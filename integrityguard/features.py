"""Подсистема сбора признаков: три уровня целостности.

Все признаки вычисляются для пары (эталон, кандидат): нарушение формализуется
как отклонение кандидата от эталонного состояния графа компонентов.
"""
from __future__ import annotations

import hashlib
import math

import torch

from .scan import POPULAR, scan_code, typosquat_score
from .spec import CAPS, PackageSpec, layers_of, mlp_forward

TrustedIndex = dict  # имя пакета -> {версия: sha256}

NODE_TYPES = ["root", "dep", "module", "model", "layer", "data"]
STRUCT_DIM = 44
PARAM_DIM = 28
BEHAV_DIM = 32


# ----------------------------------------------------------------------------
# 1. Структурный уровень: граф компонентов
# ----------------------------------------------------------------------------
def _ver(v: str) -> tuple[int, int, int]:
    parts = []
    for p in (v.split(".") + ["0", "0", "0"])[:3]:
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def build_graph(ref: PackageSpec, cand: PackageSpec, index: TrustedIndex, layer_delta: list[tuple[float, float]]):
    """Граф отклонений: узлы — компоненты (объединение эталона и кандидата), рёбра — зависимости.

    Возвращает (x[N,F], adj[N,N], keys[N]); adj[i,j]=1 — компонент i зависит от j.
    """
    known = frozenset(index) | frozenset(POPULAR)
    keys: list[str] = ["root"]
    feats: list[list[float]] = []
    edges: list[tuple[str, str]] = []

    def blank(t: str) -> list[float]:
        f = [0.0] * STRUCT_DIM
        f[NODE_TYPES.index(t)] = 1.0
        return f

    def status(f, old, new):
        f[6 + (2 if old is None else 3 if new is None else 0 if old == new else 1)] = 1.0

    def caps_feats(f, code_new: str, code_old: str | None):
        cn = scan_code(code_new)[0]
        co = scan_code(code_old)[0] if code_old is not None else frozenset()
        for i, c in enumerate(CAPS):
            f[20 + i] = float(c in cn)
            f[28 + i] = float(c in cn and c not in co and code_old is not None)
        if code_old is None:                       # новый компонент: все возможности «новые»
            for i, c in enumerate(CAPS):
                f[28 + i] = float(c in cn)

    root = blank("root")
    root[16] = float(not cand.signed_ok)
    status(root, ref.version, cand.version)
    feats.append(root)

    # --- зависимости
    names = list(dict.fromkeys([d.name for d in ref.deps] + [d.name for d in cand.deps]))
    required = {r for d in cand.deps for r in d.requires}
    for n in names:
        o, c = ref.dep(n), cand.dep(n)
        cur = c or o
        f = blank("dep")
        status(f, o and (o.version, o.sha256), c and (c.version, c.sha256))
        if o and c:
            vo, vn = _ver(o.version), _ver(c.version)
            f[10] = min(abs(vn[0] - vo[0]), 5) / 5
            f[11] = min(abs(vn[1] - vo[1]), 5) / 5 if vn[0] == vo[0] else 0.0
            f[12] = min(abs(vn[2] - vo[2]), 5) / 5 if vn[:2] == vo[:2] else 0.0
            f[13] = float(vn < vo)
            f[18] = float(o.source != c.source)
            f[36] = max(-3.0, min(3.0, math.log((c.size + 1) / (o.size + 1))))
            f[43] = float(_h(o.code) != _h(c.code))
        if c:
            in_idx = n in index
            f[14] = float(in_idx and index[n].get(c.version) != c.sha256)   # хеш не совпал с доверенным
            f[15] = float(not in_idx)
            f[17] = float(c.source not in ("pypi", "internal"))
            f[19] = typosquat_score(n, known) if not in_idx else 0.0
            caps_feats(f, c.code, o.code if o else None)
            for r in c.requires:
                edges.append((f"dep:{n}", f"dep:{r}"))
            if n not in required:
                edges.append(("root", f"dep:{n}"))
        keys.append(f"dep:{n}")
        feats.append(f)

    # --- собственные модули
    mods_o = {m.name: m for m in ref.modules}
    mods_c = {m.name: m for m in cand.modules}
    dep_import = {d.name.replace("-", "_"): d.name for d in cand.deps}
    for n in dict.fromkeys(list(mods_o) + list(mods_c)):
        o, c = mods_o.get(n), mods_c.get(n)
        f = blank("module")
        status(f, o and _h(o.code), c and _h(c.code))
        if c:
            caps_feats(f, c.code, o.code if o else None)
            f[43] = float(o is not None and _h(o.code) != _h(c.code))
            if o:
                f[36] = max(-3.0, min(3.0, math.log((len(c.code) + 1) / (len(o.code) + 1))))
            for imp in scan_code(c.code)[1]:
                if imp in dep_import:
                    edges.append((f"mod:{n}", f"dep:{dep_import[imp]}"))
                elif imp in mods_c and imp != n:
                    edges.append((f"mod:{n}", f"mod:{imp}"))
            edges.append(("root", f"mod:{n}"))
        keys.append(f"mod:{n}")
        feats.append(f)

    # --- модель, её слои, обучающие данные
    m = blank("model")
    m[16] = float(not cand.signed_ok)
    m[39] = float(cand.unsafe_format)
    changed = any(rel > -7.9 for rel, _ in layer_delta)
    m[6 + int(changed)] = 1.0
    keys.append("model")
    feats.append(m)
    edges.append(("root", "model"))
    for i, (rel, same) in enumerate(layer_delta):
        f = blank("layer")
        f[6 + int(same < 1.0)] = 1.0
        f[40], f[41] = rel / 8 + 1, same
        keys.append(f"layer:{i}")
        feats.append(f)
        edges.append(("model", f"layer:{i}"))
        if i:
            edges.append((f"layer:{i - 1}", f"layer:{i}"))
    d = blank("data")
    d[42] = float(ref.dataset_sha256 != cand.dataset_sha256)
    d[6 + int(d[42])] = 1.0
    keys.append("data")
    feats.append(d)
    edges.append(("model", "data"))

    pos = {k: i for i, k in enumerate(keys)}
    n = len(keys)
    adj = torch.zeros(n, n)
    for a, b in edges:
        if a in pos and b in pos:
            adj[pos[a], pos[b]] = 1.0
    x = torch.tensor(feats)
    # глубина от корня и входящая степень
    depth = [-1] * n
    depth[0], frontier = 0, [0]
    while frontier:
        nxt = []
        for i in frontier:
            for j in torch.nonzero(adj[i]).flatten().tolist():
                if depth[j] < 0:
                    depth[j] = depth[i] + 1
                    nxt.append(j)
        frontier = nxt
    x[:, 37] = torch.tensor([min(dp if dp >= 0 else 6, 6) / 6 for dp in depth])
    x[:, 38] = torch.clamp(adj.sum(0), max=8) / 8
    return x, adj, keys


# ----------------------------------------------------------------------------
# 2. Параметрический уровень: статистические и спектральные портреты слоёв
# ----------------------------------------------------------------------------
def _moments(t: torch.Tensor):
    mu, sd = t.mean(), t.std() + 1e-12
    z = (t - mu) / sd
    return mu, sd, (z ** 3).mean(), (z ** 4).mean()


def _spectral(m: torch.Tensor):
    s = torch.linalg.svdvals(m)
    e = s ** 2
    tot = e.sum() + 1e-20
    p = e / tot
    ent = -(p * torch.log(p + 1e-20)).sum() / math.log(len(s)) if len(s) > 1 else torch.tensor(0.0)
    return s[0], (e[0] / tot), (tot / (e[0] + 1e-20)) / len(s), ent


def layer_portrait(w, b, w0=None, b0=None, pos: float = 0.0) -> list[float]:
    """Портрет слоя: распределение весов, спектр и отклонение от эталонного слоя."""
    f = [0.0] * PARAM_DIM
    mu, sd, sk, ku = _moments(w.flatten())
    s1, top, srank, ent = _spectral(w)
    fro = w.norm()
    f[0:10] = [float(mu / sd), float(torch.log10(sd + 1e-12)), float(sk.clamp(-5, 5)), float(torch.log1p(ku)),
               float(torch.log1p(w.abs().max() / sd)), float(torch.log10(fro + 1e-12)), float(top), float(srank),
               float(ent), float((w.abs() < 0.01 * sd).float().mean())]
    f[26] = pos
    if w0 is None or w0.shape != w.shape:
        f[10] = 1.0                                   # форма слоя изменилась / слоя не было
        f[11] = 0.25
        return f
    d = w - w0
    dn, n0 = d.norm(), w0.norm() + 1e-12
    rel = float(torch.log10(dn / n0 + 1e-8).clamp(-8, 2))
    f[11] = rel / 8 + 1
    f[13] = float((d == 0).float().mean())
    if dn == 0:
        f[12] = 1.0
        return f
    sd0 = w0.std() + 1e-12
    _, _, _, kd = _moments(d.flatten())
    ds1, dtop, dsrank, dent = _spectral(d)
    rows, cols = d.norm(dim=1), d.norm(dim=0)
    db = (b - b0).norm() / (b0.norm() + 1e-6) if b0 is not None and b0.shape == b.shape else torch.tensor(0.0)
    s10 = torch.linalg.svdvals(w0)[0]
    f[12] = float(torch.nn.functional.cosine_similarity(w.flatten(), w0.flatten(), dim=0))
    f[14:26] = [float(torch.log1p(kd)), float(torch.log1p(d.abs().max() / sd0)), float(dtop), float(dsrank),
                float(d.abs().sum() / (dn * math.sqrt(d.numel()))), float(torch.log(rows.max() / (rows.mean() + 1e-12))),
                float(torch.log(cols.max() / (cols.mean() + 1e-12))), float(torch.log1p(db)),
                float(torch.log(s1 / s10)), float(torch.log(sd / sd0)), float((mu - w0.mean()) / sd0), float(dent)]
    return f


def weight_portraits(ref_state, cand_state):
    """Портреты всех слоёв кандидата: (тензор [L,P], [(rel, доля неизменных) для графа])."""
    lr, lc = layers_of(ref_state), layers_of(cand_state)
    rows = []
    for i, (w, b) in enumerate(lc):
        w0, b0 = lr[i] if i < len(lr) else (None, None)
        rows.append(layer_portrait(w, b, w0, b0, i / max(len(lc) - 1, 1)))
    p = torch.tensor(rows)
    rel = p[:, 11]
    p[:, 27] = rel - rel.median()     # локализация: насколько слой выделяется на фоне остальных
    delta = [((float(r) - 1) * 8, float(u)) for r, u in zip(rel, p[:, 13])]
    return p, delta


# ----------------------------------------------------------------------------
# 3. Поведенческий уровень: отклик на контрольные и триггерные входы
# ----------------------------------------------------------------------------
def _trigger_search(layers, x, y, n_cls, steps=40, lr=0.1, lam=0.1):
    """Обратная реконструкция триггера: для каждого класса ищется минимальное (L1)
    универсальное возмущение, переводящее контрольные входы в этот класс.
    У модели с бэкдором для целевого класса такое возмущение аномально мало и эффективно.
    """
    delta = torch.zeros(n_cls, x.shape[1], requires_grad=True)
    opt = torch.optim.Adam([delta], lr=lr)
    tgt = torch.arange(n_cls)[:, None].expand(n_cls, x.shape[0])
    for _ in range(steps):
        logits = mlp_forward(layers, x[None] + delta[:, None, :])
        loss = torch.nn.functional.cross_entropy(logits.reshape(-1, n_cls), tgt.reshape(-1)) \
            + lam * delta.abs().sum(1).mean()
        opt.zero_grad()
        loss.backward()
        opt.step()
    delta = delta.detach()
    with torch.no_grad():
        pred = mlp_forward(layers, x[None] + delta[:, None, :]).argmax(-1)
        other = (y[None] != torch.arange(n_cls)[:, None]).float()
        asr = ((pred == tgt).float() * other).sum(1) / other.sum(1).clamp(min=1)
    return delta, asr, delta.abs().sum(1) / x.abs().sum(1).mean()


def _asr(layers, x, y, delta, cls):
    with torch.no_grad():
        m = y != cls
        return float((mlp_forward(layers, x[m] + delta).argmax(-1) == cls).float().mean()) if m.any() else 0.0


class BehaviorProbe:
    """Контрольный набор защитника + кэш откликов эталонной модели."""

    def __init__(self, ref_state, x: torch.Tensor, y: torch.Tensor, seed: int = 0):
        self.x, self.y = x.float(), y.long()
        self.layers = layers_of(ref_state)
        self.ok = bool(self.layers) and x.dim() == 2 and len(x) == len(y) and len(x) >= 8 \
            and self.layers[0][0].shape[1] == x.shape[1]
        if not self.ok:
            return
        self.n_cls = self.layers[-1][0].shape[0]
        if int(self.y.min()) < 0 or int(self.y.max()) >= self.n_cls:
            self.ok = False                              # метки контрольного набора не соответствуют модели
            return
        g = torch.Generator().manual_seed(seed)
        self.noise = 0.5 * x.std() * torch.randn(x.shape, generator=g)
        self.sub = slice(0, min(256, len(x)))
        self.ref = self._stats(self.layers)

    def _stats(self, layers):
        x, y, k = self.x, self.y, self.n_cls
        with torch.no_grad():
            logp = torch.log_softmax(mlp_forward(layers, x), -1)
            pred = logp.argmax(-1)
            flip = float((mlp_forward(layers, x + self.noise).argmax(-1) != pred).float().mean())
        p = logp.exp()
        conf = torch.zeros(k, k)
        conf.index_put_((y, pred), torch.ones(len(y)), accumulate=True)
        delta, asr, norm = _trigger_search(layers, x[self.sub], y[self.sub], k)
        return dict(logp=logp, pred=pred, acc=float((pred == y).float().mean()),
                    rec=conf.diag() / conf.sum(1).clamp(min=1), conf=conf / conf.sum(1, keepdim=True).clamp(min=1),
                    cnt=conf, confd=float(p.max(-1).values.mean()), ent=float(-(p * logp).sum(-1).mean()),
                    flip=flip, delta=delta, asr=asr, norm=norm, eff=asr / (norm + 0.05))

    def features(self, cand_state) -> torch.Tensor:
        f = torch.zeros(BEHAV_DIM)
        layers = layers_of(cand_state)
        if not self.ok or not layers or layers[0][0].shape[1] != self.x.shape[1] \
                or layers[-1][0].shape[0] != self.n_cls:
            f[0] = 1.0                                 # поведенческий контроль невозможен
            return f
        r, c, k = self.ref, self._stats(layers), self.n_cls
        off = ~torch.eye(k, dtype=torch.bool)
        dr = c["rec"] - r["rec"]
        errs = c["cnt"][off]
        share = torch.bincount(c["pred"], minlength=k).float() / len(self.y)
        true_share = torch.bincount(self.y, minlength=k).float() / len(self.y)
        eff = c["eff"]
        top = int(eff.argmax())           # класс с самым «дешёвым» универсальным возмущением
        mad = (eff - eff.median()).abs().median() + 1e-3
        transfer = _asr(self.layers, self.x[self.sub], self.y[self.sub], c["delta"][top], top)
        f[1:] = torch.tensor([
            c["acc"], r["acc"], c["acc"] - r["acc"],
            float(dr.min()), float(dr.mean()), float(dr.max()), float(dr.std()),
            float((c["pred"] == r["pred"]).float().mean()),
            float(torch.log1p((r["logp"].exp() * (r["logp"] - c["logp"])).sum(-1).mean().clamp(min=0))),
            c["confd"], c["confd"] - r["confd"], c["ent"], c["ent"] - r["ent"],
            float(c["conf"][off].max()), float((c["conf"] - r["conf"])[off].max()),
            float(errs.max() / errs.sum().clamp(min=1)),
            float((share - true_share).max()),
            c["flip"], c["flip"] - r["flip"],
            float(c["asr"].max()), float(c["asr"].topk(min(2, k)).values[-1]), float(c["asr"].mean()),
            float(c["norm"][top]), float(eff.max()), float(torch.log1p((eff.max() - eff.median()) / mad)),
            float(r["asr"].max()), float(r["eff"].max()), float(c["asr"].max() - r["asr"].max()),
            float(torch.log((eff.max() + 0.05) / (r["eff"].max() + 0.05))),
            transfer, float(c["asr"].max()) - transfer,
        ])
        return f


# ----------------------------------------------------------------------------
# Сборка образца для детектора
# ----------------------------------------------------------------------------
def extract(ref: PackageSpec, cand: PackageSpec, index: TrustedIndex, probe: BehaviorProbe | None) -> dict:
    """Полный вектор наблюдения: граф, портреты слоёв, поведенческие признаки."""
    layers, delta = weight_portraits(ref.state, cand.state)
    layers = torch.nan_to_num(layers, nan=0.0, posinf=8.0, neginf=-8.0)
    x, adj, keys = build_graph(ref, cand, index, delta)
    x = torch.nan_to_num(x, nan=0.0, posinf=8.0, neginf=-8.0)
    if probe is None:
        behav = torch.zeros(BEHAV_DIM)
        behav[0] = 1.0
    else:
        behav = torch.nan_to_num(probe.features(cand.state), nan=0.0, posinf=8.0, neginf=-8.0)
    return {"x": x, "adj": adj, "keys": keys, "layers": layers, "behav": behav}


def hash_baseline(ref: PackageSpec, cand: PackageSpec, index: TrustedIndex) -> bool:
    """Базовый метод сравнения: контроль подписи и хешей (сигнатурно-хешевый). True = нарушение."""
    if not cand.signed_ok or cand.unsafe_format:
        return True
    return any(d.name not in index or index[d.name].get(d.version) != d.sha256 for d in cand.deps)
