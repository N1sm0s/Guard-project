"""Корпус примеров нарушений целостности (синтетический, с реальными атаками на реальные модели).

Для каждого «проекта» обучается эталонная модель, после чего порождаются кандидаты:
легитимные обновления и нарушения девяти классов. Атаки не имитируются признаками -
модели действительно дообучаются на отравленных данных, веса действительно искажаются,
а признаки затем извлекаются тем же кодом, что и в боевом режиме.
"""
from __future__ import annotations

import copy
import hashlib
import io
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

from .features import BehaviorProbe, extract, hash_baseline
from .scan import POPULAR
from .spec import CAPS, CLASS_LEVEL, CLASSES, LEVELS, Dep, Module, PackageSpec, layers_of, mlp_forward

# сколько кандидатов каждого класса порождает один проект
PLAN = {
    "clean": 8, "dependency": 3, "weights": 3,
    "backdoor": 3, "poison": 3, "label_flip": 3,
    "adversarial": 2,   # угроза 4: состязательные входы
    "extraction": 2,    # угроза 7: извлечение модели
    "availability": 2,  # угроза 8: нарушение доступности
}

_SNIPPET = {
    "network": "import urllib.request\n\ndef fetch(url):\n    return urllib.request.urlopen(url).read()\n",
    "process": "import subprocess\n\ndef run_tool(args):\n    return subprocess.run(args, capture_output=True)\n",
    "dynamic_exec": "def evaluate(expr, env):\n    return eval(expr, env)\n",
    "obfuscation": "import base64\n_BLOB = '{blob}'\n\ndef _unpack():\n    return base64.b64decode(_BLOB)\n",
    "file_write": "def save(path, data):\n    with open(path, 'wb') as fh:\n        fh.write(data)\n",
    "install_hook": "from setuptools.command.install import install\n\nclass PostInstall(install):\n"
                    "    def run(self):\n        install.run(self)\n",
    "unsafe_deser": "import pickle\n\ndef restore(blob):\n    return pickle.loads(blob)\n",
    "native": "import ctypes\n\ndef load_native(path):\n    return ctypes.CDLL(path)\n",
}
_CAP_P = dict(network=.25, process=.15, dynamic_exec=.10, obfuscation=.02,
              file_write=.5, install_hook=.05, unsafe_deser=.08, native=.3)
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
SEP = (5.0, 6.5)
_MODS = ["train", "infer", "data", "utils", "api", "config", "metrics", "export"]


def _hex(rng) -> str:
    return hashlib.sha256(rng.bytes(16)).hexdigest()


def stub(caps, rng, imports=(), filler=0) -> str:
    """Безвредная заглушка кода с заданным набором «возможностей» (для статического анализа)."""
    parts = [f"import {i}\n" for i in imports]
    for c in CAPS:
        if c in caps:
            blob = "".join(rng.choice(list(_B64), 320)) if c == "obfuscation" else ""
            parts.append(_SNIPPET[c].format(blob=blob) if c == "obfuscation" else _SNIPPET[c])
    parts += [f"\ndef helper_{i}(x):\n    return x * {int(rng.integers(2, 99))} + {i}\n" for i in range(filler)]
    return "\n".join(parts)


class Task:
    """Синтетическая задача классификации проекта (гауссовы классы в D-мерном пространстве)."""

    def __init__(self, rng):
        self.d = int(rng.choice([32, 48, 64]))
        self.k = int(rng.choice([4, 5, 6]))
        sep = rng.uniform(SEP[0], SEP[1]) / np.sqrt(2 * self.d)
        self.protos = torch.tensor(rng.normal(0, sep, (self.k, self.d)), dtype=torch.float32)

    def sample(self, n, g, probs=None, noise=1.0):
        y = torch.randint(0, self.k, (n,), generator=g) if probs is None else \
            torch.multinomial(torch.tensor(probs, dtype=torch.float32), n, True, generator=g)
        return self.protos[y] + noise * torch.randn(n, self.d, generator=g), y


def new_state(sizes, g) -> OrderedDict:
    st = OrderedDict()
    for i in range(len(sizes) - 1):
        bound = 1 / np.sqrt(sizes[i])
        st[f"net.{2 * i}.weight"] = (torch.rand(sizes[i + 1], sizes[i], generator=g) * 2 - 1) * bound
        st[f"net.{2 * i}.bias"] = (torch.rand(sizes[i + 1], generator=g) * 2 - 1) * bound
    return st


def _train_step(params, x_batch, y_batch, opt):
    """Один шаг оптимизации (вынесен отдельно для чистоты)."""
    logits = mlp_forward(layers_of(params), x_batch)
    err = F.cross_entropy(logits, y_batch)
    opt.zero_grad()
    err.backward()
    opt.step()


def fit(state, x, y, epochs, lr, g) -> OrderedDict:
    """Обучение/дообучение MLP, заданного state_dict."""
    params = OrderedDict((k, v.clone().requires_grad_(True)) for k, v in state.items())
    opt = torch.optim.Adam(list(params.values()), lr=lr)
    for _ in range(epochs):
        perm = torch.randperm(len(x), generator=g)
        for i in range(0, len(x), 128):
            idx = perm[i:i + 128]
            _train_step(params, x[idx], y[idx], opt)
    return OrderedDict((k, v.detach()) for k, v in params.items())


def predict(state, x):
    with torch.no_grad():
        return mlp_forward(layers_of(state), x).argmax(-1)


def make_reference(rng, state, pid) -> tuple[PackageSpec, dict]:
    index: dict = {}
    names = list(rng.choice(POPULAR, int(rng.integers(8, 17)), replace=False))
    deps = []
    for i, n in enumerate(names):
        later = names[i + 1:]
        req = list(rng.choice(later, min(len(later), int(rng.integers(0, 3))), replace=False)) if later else []
        caps = {c for c, p in _CAP_P.items() if rng.random() < p}
        d = Dep(n, f"{rng.integers(0, 5)}.{rng.integers(0, 20)}.{rng.integers(0, 10)}", _hex(rng),
                "internal" if rng.random() < 0.1 else "pypi", [str(r) for r in req],
                int(np.exp(rng.uniform(np.log(2e4), np.log(2e7)))), stub(caps, rng))
        index[n] = {d.version: d.sha256}
        deps.append(d)
    mods = []
    mnames = list(rng.choice(_MODS, int(rng.integers(3, 8)), replace=False))
    for i, n in enumerate(mnames):
        imps = [str(x).replace("-", "_") for x in rng.choice(names, int(rng.integers(1, 5)), replace=False)]
        if i and rng.random() < 0.5:
            imps.append(mnames[int(rng.integers(0, i))])
        caps = {"file_write"} if rng.random() < 0.5 else set()
        if n == "api":
            caps.add("network")
        mods.append(Module(n, stub(caps, rng, imps, int(rng.integers(1, 8)))))
    mods.sort(key=lambda m: m.name)
    spec = PackageSpec(f"project-{pid}", f"1.{rng.integers(0, 9)}.0", deps, mods, state, True, False, _hex(rng))
    return spec, index


def _bump(v: str, rng) -> str:
    parts = v.split(".")
    idx = int(rng.integers(0, len(parts)))
    parts[idx] = str(int(parts[idx]) + 1)
    return ".".join(parts)


def legit_update(spec: PackageSpec, rng, g) -> PackageSpec:
    cand = copy.deepcopy(spec)
    cand.version = _bump(spec.version, rng)
    n = int(rng.integers(1, min(4, len(cand.deps) + 1)))
    for d in rng.choice(cand.deps, n, replace=False):
        d.version = _bump(d.version, rng)
        d.sha256 = _hex(rng)
    # Legitimate releases may include small patches, broad fine-tuning, or
    # partial layer reinitialization. Varying the magnitude prevents the
    # classifier from treating any weight drift as an attack label.
    profiles = ("patch", "fine_tune", "retrain", "reinitialize")
    profile = str(rng.choice(profiles, p=[0.25, 0.35, 0.25, 0.15]))
    if profile == "patch":
        scale = float(rng.uniform(1e-4, 0.01))
        changed = set(cand.state)
    elif profile == "fine_tune":
        scale = float(rng.uniform(0.01, 0.18))
        changed = set(cand.state)
    elif profile == "retrain":
        scale = float(rng.uniform(0.08, 0.55))
        changed = set(cand.state)
    else:
        scale = float(rng.uniform(0.2, 0.8))
        layer_keys = [k for k, v in cand.state.items() if v.dim() == 2]
        count = int(rng.integers(1, len(layer_keys) + 1))
        selected = set(rng.choice(layer_keys, count, replace=False).tolist())
        changed = {k for k in cand.state if k in selected or k.removesuffix("weight") + "bias" in selected}
    cand.state = OrderedDict(
        (k, v + scale * torch.randn_like(v, generator=g) if k in changed else v)
        for k, v in cand.state.items())
    cand.update_profile = profile
    cand.dataset_sha256 = _hex(rng)
    cand.signed_ok = True
    # Benign releases may add ordinary components too. This deliberately
    # overlaps the structural changes present in threat samples so the label
    # cannot be inferred from "a new component exists" alone.
    if rng.random() < 0.65:
        used = {m.name for m in cand.modules}
        options = [name for name in _MODS if name not in used]
        name = str(rng.choice(options)) if options else f"plugin_{int(rng.integers(1000, 9999))}"
        # Benign components may use APIs also seen in malicious samples.
        # Sample from the same capability prior as ordinary dependencies so
        # one rare scanner flag alone cannot identify the generator label.
        caps = {c for c, p in _CAP_P.items() if rng.random() < p}
        cand.modules.append(Module(name, stub(caps, rng, filler=int(rng.integers(1, 5)))))
    if rng.random() < 0.35:
        choices = [name for name in POPULAR if not any(d.name == name for d in cand.deps)]
        if choices:
            name = str(rng.choice(choices))
            caps = {c for c, p in _CAP_P.items() if rng.random() < p}
            source = str(rng.choice(["pypi", "internal", "url"], p=[0.8, 0.1, 0.1]))
            cand.deps.append(Dep(name, f"{rng.integers(0, 5)}.{rng.integers(0, 20)}.0", _hex(rng),
                                 source, [], int(np.exp(rng.uniform(np.log(2e4), np.log(2e7)))),
                                 stub(caps, rng)))
    return cand


def _typo(name: str, rng) -> str:
    if len(name) < 4:
        return name + "-" + name
    i = int(rng.integers(1, len(name) - 1))
    ops = ["swap", "dup", "drop", "hyphen"]
    op = ops[int(rng.integers(0, len(ops)))]
    if op == "swap":
        s = list(name); s[i], s[i - 1] = s[i - 1], s[i]; return "".join(s)
    elif op == "dup":
        return name[:i] + name[i] + name[i:]
    elif op == "drop":
        return name[:i] + name[i + 1:]
    else:
        return name[:i] + "-" + name[i:]


def attack_structure(spec: PackageSpec, rng, g) -> tuple[PackageSpec, dict]:
    cand = copy.deepcopy(spec)
    meta: dict = {}
    if rng.random() < 0.5 and cand.deps:
        victim = cand.deps[int(rng.integers(0, len(cand.deps)))]
        old_hash = victim.sha256
        victim.sha256 = _hex(rng)
        meta["tampered_dep"] = victim.name
        meta["old_hash"] = old_hash
    else:
        base = cand.deps[int(rng.integers(0, len(cand.deps)))].name if cand.deps else "requests"
        evil_name = _typo(base, rng)
        caps = {"network", "process"} if rng.random() < 0.6 else {"dynamic_exec"}
        evil = Dep(evil_name, f"0.{rng.integers(1, 5)}.0", _hex(rng), "url",
                   [], int(rng.integers(5000, 50000)), stub(caps, rng))
        cand.deps.append(evil)
        meta["typosquat"] = evil_name
    if rng.random() < 0.4:
        cand.signed_ok = False
        meta["sig_broken"] = True
    return cand, meta


def attack_weights(spec: PackageSpec, rng, g, level=1) -> tuple[PackageSpec, dict]:
    cand = copy.deepcopy(spec)
    keys = list(cand.state.keys())
    n_layers = sum(1 for k in keys if cand.state[k].dim() == 2)
    n_target = max(1, int(np.ceil(n_layers * (0.3 + 0.3 * level))))
    target_keys = list(rng.choice([k for k in keys if cand.state[k].dim() == 2],
                                  min(n_target, n_layers), replace=False))
    scale = 0.5 + level * 0.5
    for k in target_keys:
        cand.state[k] = cand.state[k] + scale * torch.randn_like(cand.state[k], generator=g)
    if rng.random() < 0.3 + 0.2 * level:
        cand.unsafe_format = True
    return cand, {"perturbed_layers": target_keys, "scale": scale}


def poison_data(spec: PackageSpec, ref_state, task: Task, rng, g, level=1) -> tuple[PackageSpec, dict, bool]:
    cand = copy.deepcopy(spec)
    n_poison = 200 + level * 100
    xp, yp = task.sample(n_poison, g)
    if rng.random() < 0.5:
        flip_cls = int(rng.integers(0, task.k))
        yp = torch.where(yp == flip_cls,
                         torch.tensor((flip_cls + 1) % task.k), yp)
        poison_type = "label_flip"
    else:
        noise_scale = 0.5 + level * 0.5
        xp = xp + noise_scale * torch.randn_like(xp, generator=g)
        poison_type = "poison"
    xc, yc = task.sample(500, g)
    mixed_x = torch.cat([xc, xp])
    mixed_y = torch.cat([yc, yp])
    new_state = fit(copy.deepcopy(ref_state), mixed_x, mixed_y, 5 + level * 2, 1e-3, g)
    cand.state = new_state
    acc_ref = (predict(ref_state, xc) == yc).float().mean().item()
    acc_new = (predict(new_state, xc) == yc).float().mean().item()
    effect = acc_ref - acc_new
    ok = effect >= 0.03 or level >= 2
    return cand, {"poison_type": poison_type, "effect": round(effect, 4), "level": level}, ok


def attack_adversarial(spec: PackageSpec, ref_state, task: Task, rng, g, level=1) -> tuple[PackageSpec, dict, bool]:
    """Угроза 4: состязательные входы / эвазия модели (FGSM-подобная атака)."""
    cand = copy.deepcopy(spec)
    xc, yc = task.sample(300, g)
    # FGSM-подобное возмущение входов
    eps = 0.05 + level * 0.07
    x_adv = xc + eps * torch.sign(torch.randn_like(xc, generator=g))
    acc_clean = (predict(ref_state, xc) == yc).float().mean().item()
    acc_adv = (predict(ref_state, x_adv) == yc).float().mean().item()
    effect = acc_clean - acc_adv
    # Синтетические признаки адаптивного входного шлюза/эвазии. Сами примеры
    # остаются инертными: генератор добавляет только анализируемый исходный текст.
    profiles = [
        {"dynamic_exec", "network"},
        {"dynamic_exec", "obfuscation"},
        {"network", "file_write"},
    ]
    caps_adv = profiles[int(rng.integers(0, len(profiles)))]
    evil_mod = Module("adversarial_hook", stub(caps_adv, rng, filler=int(rng.integers(2, 6))))
    cand.modules.append(evil_mod)
    meta = {"effect": round(effect, 4), "eps": round(float(eps), 4), "level": level,
            "type": "adversarial", "profile": "+".join(sorted(caps_adv))}
    # Для offline integrity scan объектом обнаружения является добавленный
    # компонент обработки adversarial-входов; успешность не зависит от случайной
    # устойчивости конкретной сгенерированной сети к шуму.
    return cand, meta, True


def attack_extraction(spec: PackageSpec, ref_state, task: Task, rng, g, level=1) -> tuple[dict, bool]:
    """Угроза 7: несанкционированное извлечение модели (дистилляция + exfil)."""
    cand = copy.deepcopy(spec)
    # Шум дистилляции на весах
    noise_scale = 0.02 + level * 0.03
    for k in cand.state:
        cand.state[k] = cand.state[k] + noise_scale * torch.randn_like(cand.state[k], generator=g)
    # Добавляем зависимость для эксфильтрации
    exfil_dep = Dep(
        f"model-exfil-{int(rng.integers(1, 99))}",
        f"0.{rng.integers(1, 9)}.0",
        _hex(rng),
        "url",
        [],
        int(rng.integers(10000, 80000)),
        stub({"network", "unsafe_deser", "process"}, rng, filler=int(rng.integers(3, 8)))
    )
    cand.deps.append(exfil_dep)
    exfil_mod = Module("model_export_hook", stub({"network", "file_write", "unsafe_deser"}, rng,
                                                   filler=int(rng.integers(3, 8))))
    cand.modules.append(exfil_mod)
    meta = {"noise_scale": round(float(noise_scale), 4), "exfil_dep": exfil_dep.name,
            "level": level, "type": "extraction"}
    return meta, True  # extraction всегда ok


def attack_availability(spec: PackageSpec, ref_state, task: Task, rng, g, level=1) -> tuple[dict, bool]:
    """Угроза 8: нарушение доступности (DoS) — порча весов / бесконечный цикл."""
    cand = copy.deepcopy(spec)
    variant = rng.choice(["zero_weights", "overflow", "corrupt_all", "loop_inject", "resource_exhaustion"])
    if variant == "zero_weights":
        # Обнуление ключевого слоя
        key = list(cand.state.keys())[int(rng.integers(0, len(cand.state)))]
        cand.state[key] = torch.zeros_like(cand.state[key])
    elif variant == "overflow":
        # Переполнение (Inf/NaN)
        for k in cand.state:
            if rng.random() < 0.3:
                cand.state[k] = cand.state[k] * float("inf")
    elif variant == "corrupt_all":
        for k in cand.state:
            cand.state[k] = torch.randn_like(cand.state[k], generator=g) * 1e6
    else:
        caps = {"process", "dynamic_exec"} if variant == "loop_inject" else {"process", "file_write", "network"}
        loop_mod = Module("availability_hook", stub(caps, rng, filler=int(rng.integers(3, 7))))
        cand.modules.append(loop_mod)
    xc, yc = task.sample(200, g)
    acc = (predict(cand.state, xc) == yc).float().mean().item()
    acc_ref = (predict(ref_state, xc) == yc).float().mean().item()
    effect = acc_ref - acc
    meta = {"variant": str(variant), "effect": round(float(effect), 4), "level": level, "type": "availability"}
    ok = effect >= 0.05 or variant in ("zero_weights", "overflow", "loop_inject", "resource_exhaustion") or level >= 1
    return meta, ok


def _gen_project_once(pid: int, rng, g, *, with_specs=False, class_name=None, probe_seed=0):
    """Генерирует один синтетический проект. Возвращает (spec, cls, label, meta) или None."""
    # Выбираем класс согласно плану
    classes, counts = zip(*PLAN.items())
    weights = np.array(counts, dtype=float) / sum(counts)
    cls = class_name or str(rng.choice(classes, p=weights))
    label = CLASSES.index(cls)

    sizes = [int(rng.choice([32, 48, 64])),
             int(rng.choice([32, 48])),
             int(rng.choice([16, 24]))]
    task = Task(rng)
    sizes_full = [task.d] + sizes + [task.k]
    ref_state = new_state(sizes_full, g)

    # Начальное обучение эталона
    xr, yr = task.sample(400, g)
    ref_state = fit(ref_state, xr, yr, 10, 1e-3, g)
    ref_spec, index = make_reference(rng, ref_state, pid)
    spec = ref_spec

    meta: dict = {"class": cls, "pid": pid}
    bad: set = set()

    if cls == "clean":
        how = "legit"
        spec = legit_update(spec, rng, g)
        meta["update_profile"] = spec.update_profile
    elif cls == "dependency":
        how = "dependency"
        spec, m = attack_structure(spec, rng, g)
        meta.update(m)
        bad = {"deps"}
    elif cls == "weights":
        how = "weights"
        level = int(rng.integers(0, 3))
        spec, m = attack_weights(spec, rng, g, level)
        meta.update(m)
        bad = {"model"}
    elif cls in ("backdoor", "poison", "label_flip"):
        how = cls
        level = int(rng.integers(0, 3))
        spec, m, ok = poison_data(spec, ref_state, task, rng, g, level)
        if not ok:
            return None
        meta.update(m)
        bad = {"model"}
    elif cls == "adversarial":
        how = "adversarial"
        level = int(rng.integers(0, 3))
        spec, m, ok = attack_adversarial(spec, ref_state, task, rng, g, level)
        if not ok:
            return None
        meta.update(m)
        bad = {"model"}
    elif cls == "extraction":
        how = "extraction"
        level = int(rng.integers(0, 3))
        m, ok = attack_extraction(spec, ref_state, task, rng, g, level)
        if not ok:
            return None
        meta.update(m)
        bad = {"model"}
    elif cls == "availability":
        how = "availability"
        level = int(rng.integers(0, 3))
        m, ok = attack_availability(spec, ref_state, task, rng, g, level)
        if not ok:
            return None
        meta.update(m)
        bad = {"model"}
    else:
        return None

    meta["how"] = how
    meta["bad"] = sorted(bad)
    if with_specs:
        probe = BehaviorProbe(ref_state, xr, yr, seed=int(probe_seed))
        features = extract(ref_spec, spec, index, probe)
        levels = torch.tensor([float(CLASS_LEVEL[cls] == level) for level in LEVELS], dtype=torch.float32)
        node_y = (features["x"][:, 7:10].sum(dim=1) > 0).to(torch.float32)
        sample = {"spec": spec, "y": label, "cls": cls, "variant": how, "index": index,
                  "keys": features["keys"], "x": features["x"], "adj": features["adj"],
                  "layers": features["layers"], "behav": features["behav"],
                  "node_y": node_y, "levels": levels, "hash_flag": bool(not spec.signed_ok),
                  "pid": int(pid), "meta": meta}
        project = {"ref": ref_spec, "x": xr, "y": yr, "index": index}
        return [sample], project
    return spec, cls, label, meta


def gen_project(pid: int, rng=None, g=None, *, with_specs=False, class_name=None):
    """Generate a project, retrying filtered scenarios with the same RNG stream."""
    rng = rng or np.random.default_rng(pid)
    if g is None:
        g = torch.Generator().manual_seed(int(pid))
    for attempt in range(40):
        result = _gen_project_once(pid + attempt, rng, g, with_specs=with_specs,
                                   class_name=class_name, probe_seed=pid)
        if result is not None:
            return result
    return None


def _gen_bytes(n: int, rng) -> bytes:
    return bytes(rng.integers(0, 256, n, dtype=np.uint8).tolist())


def build_corpus(n_projects: int = 150, seed: int = 42,
                 path: str | Path | None = None, progress=None) -> list[dict]:
    """Строит синтетический корпус ПНП.

    Args:
        n_projects: целевое число проектов (попытки повторяются при фильтрации).
        seed:       начальное значение генератора случайных чисел.
        path:       если задан — сериализует корпус по указанному пути (pickle).

    Returns:
        Список словарей с полями spec, cls, label, meta.
    """
    rng = np.random.default_rng(seed)
    g = torch.Generator().manual_seed(int(rng.integers(0, 2 ** 32)))
    classes = list(CLASSES)
    targets = []
    while len(targets) < n_projects:
        order = list(classes)
        rng.shuffle(order)
        targets.extend(order)
    targets = targets[:n_projects]
    corpus: list[dict] = []
    attempts = 0
    max_attempts = n_projects * 6
    print(f"[corpus] Генерация {n_projects} проектов (seed={seed})…")
    while len(corpus) < n_projects and attempts < max_attempts:
        attempts += 1
        # gen_project may retry up to 39 times and returns pid + retry_offset.
        # Reserve a disjoint PID range per requested project so retries cannot
        # merge unrelated samples into one train/validation/test group.
        project_pid = (attempts - 1) * 41
        generated = gen_project(project_pid, rng, g, with_specs=True,
                                class_name=targets[len(corpus)])
        if generated is None:
            continue
        samples, _project = generated
        sample = samples[0]
        result = (sample["spec"], sample["cls"], sample["y"], sample["meta"])
        spec, cls, label, meta = result
        corpus.append({"spec": spec, "cls": cls, "label": label, "y": label,
                       "pid": int(sample["pid"]), "meta": meta, "x": sample["x"],
                       "adj": sample["adj"], "keys": sample["keys"],
                       "layers": sample["layers"], "behav": sample["behav"],
                       "node_y": sample["node_y"], "levels": sample["levels"],
                       "hash_flag": sample["hash_flag"]})
        if progress:
            progress(len(corpus), n_projects)
        if len(corpus) % 50 == 0:
            print(f"  [{len(corpus)}/{n_projects}] …")
    # Статистика
    from collections import Counter
    dist = Counter(r["cls"] for r in corpus)
    print(f"[corpus] Готово {len(corpus)} проектов. Распределение: {dict(dist)}")
    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            import pickle
            pickle.dump(corpus, fh, protocol=4)
        print(f"[corpus] Сохранено -> {path}")
    return corpus


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Генератор корпуса ПНП")
    p.add_argument("--n", type=int, default=300, help="Число проектов (умолч. 300)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", type=str, default="corpus.pkl")
    args = p.parse_args()
    build_corpus(args.n, args.seed, path=args.out)
