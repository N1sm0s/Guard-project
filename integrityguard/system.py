"""Модель системы защиты информации: сбор признаков -> нейросетевой анализ -> решение -> реагирование.

Встраивается в три точки жизненного цикла: сборка (CI), поставка (перед развёртыванием),
эксплуатация (периодический контроль развёрнутого пакета).
"""
from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import torch

from .collect import fingerprint, load_control, load_package, sign_package
from .features import BehaviorProbe, extract, hash_baseline
from .model import collate, load_detector
from .spec import CLASS_RU, CLASSES, LEVELS, layers_of

ALLOW, REVIEW, BLOCK = "ALLOW", "REVIEW", "BLOCK"
EXIT_CODE = {ALLOW: 0, BLOCK: 1, REVIEW: 2}


def opaque_source_anomalies(ref, cand, *, min_chars=16, min_size=1024, min_ratio=0.01):
    """Find new/changed .py modules that decode as mostly non-UTF-8 bytes.

    This deterministic guard covers binary payloads disguised with a Python
    extension. It intentionally requests review instead of asserting malware.
    """
    old = {m.name: m.code for m in ref.modules}
    found = []
    for module in cand.modules:
        if module.code == old.get(module.name):
            continue
        replacement_count = module.code.count("\ufffd")
        size = len(module.code)
        ratio = replacement_count / max(size, 1)
        if size >= min_size and replacement_count >= min_chars and ratio >= min_ratio:
            found.append({"module": module.name, "replacement_chars": replacement_count,
                          "text_chars": size, "replacement_ratio": round(ratio, 4)})
    return found

# рекомендуемые действия реагирования (сценарии для SOC/SOAR)
PLAYBOOK = {
    "dependency": ["остановить сборку/поставку", "зафиксировать версии зависимостей по lock-файлу эталона",
                   "проверить указанный компонент и источник его загрузки", "сменить учётные данные сборочного узла"],
    "weights": ["запретить развёртывание артефакта модели", "восстановить веса из доверенного хранилища",
                "проверить журнал доступа к хранилищу моделей и ключ подписи"],
    "backdoor": ["запретить развёртывание модели", "провести аудит обучающих данных последнего цикла",
                 "переобучить модель на проверенных данных"],
    "poison": ["запретить развёртывание модели", "проверить источники и целостность обучающих данных",
               "откатиться к эталонной версии модели"],
    "label_flip": ["запретить развёртывание модели", "перепроверить разметку обучающих данных",
                   "откатиться к эталонной версии модели"],
    "adversarial": ["изолировать модель от внешних входных данных",
                    "провести аудит препроцессора входных данных",
                    "включить adversarial robustness проверки в pipeline"],
    "extraction":  ["ограничить API-доступ к модели",
                    "включить rate limiting на inference endpoint",
                    "проверить журналы API-запросов на признаки систематического зондирования"],
    "availability": ["откатить модель к предыдущей версии",
                     "проверить целостность весов модели",
                     "восстановить модель из доверенного хранилища"],
}


class IntegrityGuard:
    def __init__(self, registry, model_path, key: bytes | None = None):
        self.registry = Path(registry)
        self.registry.mkdir(parents=True, exist_ok=True)
        self.model, ck = load_detector(model_path)
        self.threshold, self.block_threshold = ck["threshold"], ck["block_threshold"]
        keyfile = self.registry / "signing.key"
        self.key = key or (os.environ["IG_SIGNING_KEY"].encode() if "IG_SIGNING_KEY" in os.environ
                           else keyfile.read_bytes() if keyfile.exists() else None)
        self._probes: dict = {}

    # ---------------------------------------------------------------- эталоны
    def _base(self, name) -> Path:
        return self.registry / "baselines" / name

    def register_baseline(self, pkg_dir, control=None, index=None, note="initial") -> str:
        """Регистрация доверенного (эталонного) состояния пакета."""
        spec = load_package(pkg_dir, self.key)
        if spec.unsafe_format:
            raise ValueError("модель пакета сериализована небезопасным pickle — такой пакет нельзя сделать эталоном")
        if not layers_of(spec.state):
            raise ValueError("в model.pt не найдено полносвязных слоёв (поддерживаются модели Linear+ReLU, state_dict)")
        if self.key is not None and not spec.signed_ok:
            raise ValueError("подпись пакета отсутствует или неверна — подпишите пакет ключом реестра перед регистрацией")
        if control:
            probe = BehaviorProbe(spec.state, *load_control(control))
            if not probe.ok:
                raise ValueError("контрольный набор не подходит к модели: проверьте размерность X, число примеров (≥ 8) "
                                 "и диапазон меток y")
        base = self._base(spec.name)
        src, dst = Path(pkg_dir).resolve(), (base / "package").resolve()
        if src != dst:                                   # эталон не копируется сам в себя
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        if control and Path(control).resolve() != (base / "control.npz").resolve():
            shutil.copy(control, base / "control.npz")
        # эталон доверен по определению: его зависимости попадают в доверенный индекс
        cur = self.index()
        for d in spec.deps:
            cur.setdefault(d.name, {})[d.version] = d.sha256
        (self.registry / "trusted_index.json").write_text(json.dumps(cur, indent=1), encoding="utf-8")
        if index:
            self.merge_index(index)
        self._history(spec.name, {"event": "baseline", "version": spec.version, "note": note,
                                  "fingerprint": fingerprint(pkg_dir)})
        self._probes.pop(spec.name, None)
        return spec.name

    def sign(self, pkg_dir) -> None:
        """Подпись пакета ключом реестра (ключ создаётся при первом обращении)."""
        if self.key is None:
            self.key = os.urandom(32).hex().encode()
            (self.registry / "signing.key").write_bytes(self.key)
        load_package(pkg_dir, self.key)                  # проверка, что это корректный пакет
        sign_package(pkg_dir, self.key)

    def merge_index(self, index_path) -> None:
        cur = self.index()
        for n, vers in json.loads(Path(index_path).read_text(encoding="utf-8-sig")).items():
            cur.setdefault(n, {}).update(vers)
        (self.registry / "trusted_index.json").write_text(json.dumps(cur, indent=1), encoding="utf-8")

    def index(self) -> dict:
        p = self.registry / "trusted_index.json"
        return json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else {}

    def _history(self, name, rec) -> None:
        base = self._base(name)
        base.mkdir(parents=True, exist_ok=True)
        with open(base / "history.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"time": _now(), **rec}, ensure_ascii=False) + "\n")

    # ---------------------------------------------------------------- проверка
    def check(self, pkg_dir, stage="build", index_path=None, strict=False) -> dict:
        """Проверка кандидата относительно зарегистрированного эталона. Возвращает вердикт (dict)."""
        t0 = time.perf_counter()
        cand = load_package(pkg_dir, self.key)
        base = self._base(cand.name)
        if not (base / "package").exists():
            raise ValueError(f"для пакета «{cand.name}» не зарегистрирован эталон — добавьте его на вкладке "
                             f"«Эталоны и версии» (или командой baseline)")
        ref = load_package(base / "package", self.key)
        no_key = self.key is None
        if no_key:                                       # подпись проверить нечем — не считаем её нарушенной
            cand.signed_ok = ref.signed_ok = True
        index = json.loads(Path(index_path).read_text(encoding="utf-8-sig")) if index_path else self.index()
        ev = {"time": _now(), "stage": stage, "package": cand.name, "version": cand.version,
              "baseline_version": ref.version, "fingerprint": fingerprint(pkg_dir), "rules": [],
              "hash_control": bool(hash_baseline(ref, cand, index))}
        if no_key:
            ev["rules"].append("ключ подписи не задан: подпись пакета не проверялась")
        bad_weights = [k for k, v in cand.state.items() if v.is_floating_point() and not torch.isfinite(v).all()]
        if not cand.unsafe_format and (bad_weights or not layers_of(cand.state)):
            # правило политики: модель, которую нельзя проанализировать, не допускается
            why = f"веса содержат NaN/Inf ({', '.join(bad_weights[:3])})" if bad_weights \
                else "в model.pt нет поддерживаемых слоёв (Linear+ReLU, state_dict)"
            ev.update(verdict=BLOCK, score=1.0, risk_score=100,
                  threat="weights", threat_ru=CLASS_RU["weights"], suspects=[
                {"component": "model", "score": 1.0}], actions=PLAYBOOK["weights"])
            ev["rules"].append(why)
            ev["timing_ms"] = {"total": round(1000 * (time.perf_counter() - t0), 1)}
            return ev
        if cand.unsafe_format:
            # правило политики: небезопасная сериализация модели блокируется без загрузки файла
            ev.update(verdict=BLOCK, score=1.0, risk_score=100,
                      threat="dependency", threat_ru=CLASS_RU["dependency"],
                      suspects=[{"component": "model", "score": 1.0}], actions=PLAYBOOK["dependency"])
            ev["rules"].append("модель сериализована небезопасным pickle (возможно исполнение кода при загрузке)")
            ev["timing_ms"] = {"total": round(1000 * (time.perf_counter() - t0), 1)}
            return ev
        if fingerprint(pkg_dir) == fingerprint(base / "package"):
            # Exact byte-for-byte trusted baseline is a deterministic identity match;
            # the learned classifier must not override this provenance check.
            ev.update(verdict=ALLOW, score=0.0, risk_score=0, threat="clean",
                      threat_ru=CLASS_RU["clean"], threshold=self.threshold,
                      block_threshold=self.block_threshold, probabilities={}, levels={},
                      suspects=[], layer_anomaly=[], actions=[], baseline_match=True,
                      timing_ms={"total": round(1000 * (time.perf_counter() - t0), 1)})
            return ev
        source_anomalies = opaque_source_anomalies(ref, cand)
        if source_anomalies:
            names = ", ".join(item["module"] for item in source_anomalies[:5])
            ev["rules"].append(
                "новый или изменённый .py содержит много не-UTF-8 байтов; требуется проверка формата/встроенного бинарного файла"
                f" ({names})")
        if cand.name not in self._probes:
            ctrl = base / "control.npz"
            self._probes[cand.name] = BehaviorProbe(ref.state, *load_control(ctrl)) if ctrl.exists() else None
        probe = self._probes[cand.name]
        sample = extract(ref, cand, index, probe)
        t1 = time.perf_counter()
        with torch.no_grad():
            out = self.model(collate([sample]))
        probs = torch.softmax(out["logits"][0], -1)
        t2 = time.perf_counter()
        score = float(1 - probs[0])
        if score != score:                               # NaN на выходе сети — не допускать
            score = 1.0
            ev["rules"].append("сеть вернула неопределённую оценку — пакет заблокирован")
        top = int(probs[1:].argmax()) + 1
        neural_top = top
        neural_verdict = BLOCK if score >= self.block_threshold else REVIEW if score >= self.threshold else ALLOW
        verdict = neural_verdict
        if source_anomalies and verdict == ALLOW:
            # This is a package-format anomaly, not a calibrated neural class.
            top = CLASSES.index("dependency")
            verdict = REVIEW
        if strict and verdict == REVIEW:
            verdict = BLOCK
        nodes = torch.sigmoid(out["node_logits"][0])
        order = nodes.argsort(descending=True)[:3].tolist()
        if probe is None:
            ev["rules"].append("контрольный набор не зарегистрирован: поведенческий уровень не проверялся")
        elif sample["behav"][0] > 0:
            ev["rules"].append("вход/выход модели не соответствует контрольному набору: поведенческий уровень не проверялся")
        risk_score = _risk_score(score, self.threshold, self.block_threshold)
        if source_anomalies:
            risk_score = max(risk_score, 70 if verdict == BLOCK else 30 if verdict == REVIEW else 0)
        ev.update(verdict=verdict, neural_verdict=neural_verdict,
                  neural_threat=CLASSES[neural_top],
                  policy_finding="opaque_source_format" if source_anomalies else None,
                  source_anomalies=source_anomalies, score=round(score, 4),
                  risk_score=risk_score,
                  threshold=self.threshold,
                  block_threshold=self.block_threshold,
                  threat=CLASSES[top] if verdict != ALLOW else "clean",
                  threat_ru=CLASS_RU[CLASSES[top]] if verdict != ALLOW else CLASS_RU["clean"],
                  probabilities={c: round(float(p), 4) for c, p in zip(CLASSES, probs)},
                  levels={lv: round(float(torch.sigmoid(v)), 4) for lv, v in zip(LEVELS, out["levels"][0])},
                  suspects=[{"component": sample["keys"][i], "score": round(float(nodes[i]), 4)} for i in order]
                  if verdict != ALLOW else [],
                  layer_anomaly=[round(float(e), 4) for e in out["layer_err"][0]],
                  actions=PLAYBOOK[CLASSES[top]] if verdict != ALLOW else [],
                  timing_ms={"collect": round(1000 * (t1 - t0), 1), "analyze": round(1000 * (t2 - t1), 2),
                             "total": round(1000 * (t2 - t0), 1)})
        return ev

    # ---------------------------------------------------------------- реагирование
    def respond(self, ev: dict, pkg_dir=None, promote=False) -> int:
        """Журналирование события для SIEM/SOC, обновление эталона при допуске. Возвращает код возврата."""
        with open(self.registry / "events.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        self._history(ev["package"], {"event": "check", "stage": ev["stage"], "version": ev["version"],
                                      "verdict": ev["verdict"], "threat": ev["threat"], "score": ev["score"],
                                      "fingerprint": ev["fingerprint"]})
        if promote and ev["verdict"] == ALLOW and pkg_dir:
            self.register_baseline(pkg_dir, note=f"promoted {ev['version']}")   # контрольный набор сохраняется
        return EXIT_CODE[ev["verdict"]]

    def monitor(self, pkg_dir, interval=30.0, once=False, on_event=None, on_error=None) -> None:
        """Эксплуатация: контроль развёрнутого пакета; полная проверка — при изменении отпечатка."""
        last = None
        while True:
            fp = fingerprint(pkg_dir)
            if fp != last:
                try:
                    ev = self.check(pkg_dir, stage="runtime")
                    self.respond(ev)
                    if on_event:
                        on_event(ev)
                except (ValueError, OSError) as e:       # повреждённый пакет не должен останавливать наблюдение
                    if once or on_error is None:
                        raise
                    on_error(e)
                last = fp
            if once:
                return
            time.sleep(interval)


def _risk_score(score: float, thr: float, block_thr: float) -> int:
    """Нормирует score (0–1) в Risk Score 0–100 с учётом порогов REVIEW/BLOCK.

    0–29  → зелёная зона (ALLOW)
    30–69 → жёлтая зона (REVIEW)
    70–100 → красная зона (BLOCK)
    """
    if score <= 0:
        return 0
    if score >= 1:
        return 100
    if score < thr:
        # зелёная зона: линейно 0 → 29
        return max(0, round(score / thr * 29))
    if score < block_thr:
        # жёлтая зона: линейно 30 → 69
        t = (score - thr) / max(block_thr - thr, 1e-6)
        return 30 + round(t * 39)
    # красная зона: линейно 70 → 99 (100 — только при score=1.0)
    t = (score - block_thr) / max(1.0 - block_thr, 1e-6)
    return 70 + round(t * 29)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def format_event(ev: dict) -> str:
    mark = {ALLOW: "ДОПУСК", REVIEW: "НА ПРОВЕРКУ", BLOCK: "БЛОКИРОВКА"}[ev["verdict"]]
    rs = ev.get("risk_score", round(ev["score"] * 100))
    lines = [f"[{mark}] {ev['package']} {ev['baseline_version']} -> {ev['version']}  (стадия: {ev['stage']})",
             f"  оценка риска: {rs}/100; оценка нарушения: {ev['score']:.3f}; заключение: {ev['threat_ru']}"]
    if "levels" in ev:
        lines.append("  уровни: " + ", ".join(f"{k} {v:.2f}" for k, v in ev["levels"].items()))
    if ev.get("suspects"):
        lines.append("  подозрительные компоненты: " + ", ".join(f"{s['component']} ({s['score']:.2f})" for s in ev["suspects"]))
    lines += [f"  ! {r}" for r in ev["rules"]]
    lines += [f"  - {a}" for a in ev.get("actions", [])]
    lines.append(f"  контроль подписи/хешей: {'нарушение' if ev['hash_control'] else 'норма'}; "
                 f"время проверки: {ev['timing_ms']['total']:.0f} мс")
    return "\n".join(lines)
