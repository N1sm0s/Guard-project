"""Модель системы защиты информации: сбор признаков -> нейросетевой анализ -> решение -> реагирование.

Встраивается в три точки жизненного цикла: сборка (CI), поставка (перед развёртыванием),
эксплуатация (периодический контроль развёрнутого пакета).
"""
from __future__ import annotations

import json
import hashlib
import math
import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import torch

from .collect import fingerprint, load_control, load_package, sign_package
from .features import BehaviorProbe, extract, hash_baseline
from .evidence import EvidenceStore
from .model import collate, load_detector
from .spec import CLASS_RU, CLASSES, LEVELS, layers_of
from .threat_intel import lookup_pypi_dependencies

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
    def __init__(self, registry, model_path, key: bytes | None = None, public_intel_enabled=True):
        self.registry = Path(registry)
        self.registry.mkdir(parents=True, exist_ok=True)
        self.model_path = Path(model_path).resolve()
        self.model, ck = load_detector(model_path)
        self.threshold, self.block_threshold = ck["threshold"], ck["block_threshold"]
        self.model_sha256 = EvidenceStore.sha256_file(self.model_path)
        self.evidence = EvidenceStore(self.registry / "evidence.sqlite")
        self.evidence.register_model(self.model_sha256, self.model_path, ck)
        self.evidence.backfill_jsonl(self.registry / "events.jsonl",
                                     self.registry / "events.archive.jsonl")
        keyfile = self.registry / "signing.key"
        self.key = key or (os.environ["IG_SIGNING_KEY"].encode() if "IG_SIGNING_KEY" in os.environ
                           else keyfile.read_bytes() if keyfile.exists() else None)
        self._probes: dict = {}
        self.public_intel_enabled = bool(public_intel_enabled)

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

    def _public_intel(self, dependencies) -> dict:
        """Look up OSV only for manifest dependencies explicitly sourced from PyPI."""
        if not self.public_intel_enabled:
            return {}
        try:
            return lookup_pypi_dependencies(dependencies, self.registry / "public_intel" / "osv-cache.json")
        except Exception as error:  # public intel must not make deterministic package checks unavailable
            return {"source": "OSV", "source_url": "https://osv.dev/", "status": "unavailable",
                    "queried": 0, "eligible": 0, "skipped_non_pypi_or_invalid": 0,
                    "known_vulnerable_dependencies": 0, "findings": [], "coverage_complete": False,
                    "limitations": [str(error)[:300]]}

    @staticmethod
    def _apply_public_intel(ev: dict, intel: dict) -> dict:
        """Attach advisory evidence; keep it separate from the model score."""
        ev["public_intel"] = intel
        vulnerable = intel.get("findings", [])
        if not vulnerable:
            if intel.get("status") in {"partial", "unavailable"}:
                ev.setdefault("rules", []).append(
                    f"проверка публичных сведений OSV неполная ({intel.get('status')}); отсутствие результатов не подтверждает безопасность")
            return ev
        ids = list(dict.fromkeys(vuln.get("id", "")
                                 for dependency in vulnerable
                                 for vuln in dependency.get("vulnerabilities", []) if vuln.get("id")))
        ev.setdefault("policy_findings", []).append("known_vulnerable_dependency")
        ev.setdefault("rules", []).append(
            f"OSV: найдено {len(vulnerable)} уязвимых зависимостей; идентификаторы: {', '.join(ids[:12])}"
            + (" …" if len(ids) > 12 else ""))
        ev.setdefault("actions", []).insert(0,
            "проверьте затронутые версии зависимостей и обновите их по исправленным версиям из источников рекомендаций")
        if ev.get("verdict") == ALLOW:
            ev["verdict"] = REVIEW
            ev["threat"] = "dependency"
            ev["threat_ru"] = CLASS_RU["dependency"]
        return ev

    @staticmethod
    def _rotate_log(path: Path, max_bytes=5_000_000, keep_lines=5000) -> None:
        """Если журнал разросся — старые записи сами переносятся в архив рядом (ничего не теряется),
        а в рабочем файле остаются последние keep_lines записей, чтобы чтение и отображение в
        интерфейсе оставались быстрыми. Ротация — не критичная операция: при ошибке просто пропускаем."""
        try:
            if not path.exists() or path.stat().st_size < max_bytes:
                return
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) <= keep_lines:
                return
            archive = path.with_name(f"{path.stem}.archive.jsonl")
            with open(archive, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines[:-keep_lines]) + "\n")
            path.write_text("\n".join(lines[-keep_lines:]) + "\n", encoding="utf-8")
        except OSError:
            pass

    def _history(self, name, rec) -> None:
        from .journal import append_record
        base = self._base(name)
        base.mkdir(parents=True, exist_ok=True)
        hist = base / "history.jsonl"
        append_record(hist, {"time": _now(), **rec}, self._rotate_log)

    # ------------------------------------------------- признаки для онлайн-дообучения
    def extract_features(self, pkg_dir, index_path=None) -> dict | None:
        """Пересобирает признаки (граф, веса, поведение) кандидата относительно его эталона.

        Используется для онлайн-дообучения (online_learn.maybe_queue) — чтобы сохранить
        признаки карантинного пакета для возможного последующего дообучения на
        подтверждённом человеком образце. Возвращает None, если для пакета нет
        зарегистрированного эталона (дообучаться не на чём).
        """
        cand = load_package(pkg_dir, self.key)
        base = self._base(cand.name)
        if not (base / "package").exists():
            return None
        ref = load_package(base / "package", self.key)
        index = json.loads(Path(index_path).read_text(encoding="utf-8-sig")) if index_path else self.index()
        if cand.name not in self._probes:
            ctrl = base / "control.npz"
            self._probes[cand.name] = BehaviorProbe(ref.state, *load_control(ctrl)) if ctrl.exists() else None
        probe = self._probes[cand.name]
        return extract(ref, cand, index, probe)

    # ---------------------------------------------------------------- проверка
    def check(self, pkg_dir, stage="build", index_path=None, strict=False) -> dict:
        """Проверка кандидата относительно зарегистрированного эталона. Возвращает вердикт (dict)."""
        t0 = time.perf_counter()
        cand = load_package(pkg_dir, self.key)
        intel = self._public_intel(cand.deps)
        base = self._base(cand.name)
        if not (base / "package").exists():
            ev = self.assess_unbaselined(pkg_dir, stage, intel)
            if strict and ev["verdict"] == REVIEW:
                ev["verdict"] = BLOCK
                ev["rules"].append("строгий режим: пакет без доверенного эталона не допускается")
            return ev
        ref = load_package(base / "package", self.key)
        no_key = self.key is None
        if no_key:                                       # подпись проверить нечем — не считаем её нарушенной
            cand.signed_ok = ref.signed_ok = True
        index = json.loads(Path(index_path).read_text(encoding="utf-8-sig")) if index_path else self.index()
        ev = {"time": _now(), "stage": stage, "package": cand.name, "version": cand.version,
              "baseline_version": ref.version, "fingerprint": fingerprint(pkg_dir), "rules": [],
              "hash_control": bool(hash_baseline(ref, cand, index)), "public_intel": intel}
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
            return self._apply_public_intel(ev, intel)
        if cand.unsafe_format:
            # правило политики: небезопасная сериализация модели блокируется без загрузки файла
            ev.update(verdict=BLOCK, score=1.0, risk_score=100,
                      threat="dependency", threat_ru=CLASS_RU["dependency"],
                      suspects=[{"component": "model", "score": 1.0}], actions=PLAYBOOK["dependency"])
            ev["rules"].append("модель сериализована небезопасным pickle (возможно исполнение кода при загрузке)")
            ev["timing_ms"] = {"total": round(1000 * (time.perf_counter() - t0), 1)}
            return self._apply_public_intel(ev, intel)
        if fingerprint(pkg_dir) == fingerprint(base / "package"):
            # Exact byte-for-byte trusted baseline is a deterministic identity match;
            # the learned classifier must not override this provenance check.
            ev.update(verdict=ALLOW, score=0.0, risk_score=0, threat="clean",
                      threat_ru=CLASS_RU["clean"], threshold=self.threshold,
                      block_threshold=self.block_threshold, probabilities={}, levels={},
                      suspects=[], layer_anomaly=[], actions=[], baseline_match=True,
                      timing_ms={"total": round(1000 * (time.perf_counter() - t0), 1)})
            return self._apply_public_intel(ev, intel)
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
        return self._apply_public_intel(ev, intel)

    def assess_unbaselined(self, pkg_dir, stage="deploy", public_intel=None) -> dict:
        """Record an explicit, unscored result when no trusted reference exists.

        First sighting and a locally generated signature are not trust anchors.
        Objective format checks are recorded as facts, while the pairwise
        detector and risk score remain unavailable until a reference is found.
        """
        t0 = time.perf_counter()
        cand = load_package(pkg_dir, self.key)
        intel = public_intel if public_intel is not None else self._public_intel(cand.deps)
        rules: list[str] = ["доверенный эталон не найден; сравнение целостности и числовая оценка не выполнялись"]
        facts = {"manifest_parsed": True, "signature_verified": bool(cand.signed_ok) if self.key else None,
                 "model_pickle_safe": not cand.unsafe_format,
                 "supported_linear_layers": bool(layers_of(cand.state)) if not cand.unsafe_format else False,
                 "dependency_count": len(cand.deps), "module_count": len(cand.modules)}
        verdict, threat, threat_ru, action = (REVIEW, "reference_required",
                                              "нет доверенного эталона для сравнения",
                                              "получить и одобрить доверенную версию пакета")
        if cand.unsafe_format:
            rules.append("файл модели использует небезопасный pickle или не прошёл статическую проверку формата")
            verdict, threat, threat_ru = BLOCK, "weights", CLASS_RU["weights"]
            action = "не загружать модель до получения проверенной сборки"
        else:
            bad_weights = [name for name, value in cand.state.items()
                           if value.is_floating_point() and not torch.isfinite(value).all()]
            if bad_weights:
                facts["nonfinite_weights"] = bad_weights[:20]
                rules.append("обнаружены не конечные значения весов (NaN/Inf): " + ", ".join(bad_weights[:5]))
                verdict, threat, threat_ru = BLOCK, "weights", CLASS_RU["weights"]
                action = "не запускать пакет; получить проверенную сборку модели"
            elif not facts["supported_linear_layers"]:
                rules.append("модель не относится к поддерживаемому формату Linear+ReLU; сравнение недоступно")
            if self.key:
                rules.append("подпись проверена ключом реестра" if cand.signed_ok else
                             "подпись отсутствует или не прошла проверку ключом реестра")
            else:
                rules.append("ключ проверки подписи не настроен; криптографическое происхождение не проверено")
        event = {"time": _now(), "stage": stage, "package": cand.name, "version": cand.version,
                "baseline_version": None, "fingerprint": fingerprint(pkg_dir), "rules": rules,
                "hash_control": None, "analysis_mode": "reference_missing",
                "assessment_complete": False, "comparison_performed": False,
                "objective_facts": facts, "model_score": None, "verdict": verdict,
                "score": None, "risk_score": None, "threat": threat,
                "threat_ru": threat_ru, "threshold": None, "block_threshold": None,
                "probabilities": {}, "levels": {}, "suspects": [],
                "layer_anomaly": [], "actions": [action],
                "timing_ms": {"collect": round(1000 * (time.perf_counter() - t0), 1),
                              "analyze": 0.0, "total": round(1000 * (time.perf_counter() - t0), 1)}}
        event["objective_facts"]["public_intel_status"] = intel.get("status", "not_checked")
        event["objective_facts"]["public_intel_queried"] = intel.get("queried", 0)
        event["objective_facts"]["public_intel_coverage_complete"] = intel.get("coverage_complete")
        return self._apply_public_intel(event, intel)

    def assessment_error(self, pkg_dir, error, stage="deploy") -> dict:
        """Journal an attempted package assessment that could not parse its manifest/files."""
        path = Path(pkg_dir)
        try:
            fp = fingerprint(path)
        except OSError:
            fp = ""
        message = str(error).replace("\n", " ")[:500]
        return {"time": _now(), "stage": stage, "package": path.name, "version": "?",
                "baseline_version": None, "fingerprint": fp, "rules": [
                    f"проверка пакета не завершена: {message}"],
                "hash_control": None, "analysis_mode": "intake_validation_error",
                "assessment_complete": False, "model_score": None, "verdict": REVIEW,
                "comparison_performed": False, "score": None, "risk_score": None, "threat": "reference_required",
                "threat_ru": "проверка пакета не завершена", "threshold": None,
                "block_threshold": None, "probabilities": {}, "levels": {}, "suspects": [],
                "layer_anomaly": [], "actions": ["проверьте комплектность и читаемость файлов пакета",
                                                     "повторно поместите исправленный пакет во входящую папку"],
                "timing_ms": {"collect": 0.0, "analyze": 0.0, "total": 0.0}}

    # ---------------------------------------------------------------- реагирование
    def respond(self, ev: dict, pkg_dir=None, promote=False) -> int:
        """Журналирование события для SIEM/SOC, обновление эталона при допуске. Возвращает код возврата."""
        ev.setdefault("event_id", uuid.uuid4().hex)
        if getattr(self, "model_sha256", None):
            ev.setdefault("model_sha256", self.model_sha256)
        events = self.registry / "events.jsonl"
        from .journal import append_record
        append_record(events, ev, self._rotate_log)
        evidence = getattr(self, "evidence", None)
        if evidence is not None:
            evidence.record_event(ev)
        self._history(ev["package"], {"event": "check", "stage": ev["stage"], "version": ev["version"],
                                      "verdict": ev["verdict"], "threat": ev["threat"], "score": ev["score"],
                                      "fingerprint": ev["fingerprint"], "event_id": ev.get("event_id")})
        if promote and ev["verdict"] == ALLOW and pkg_dir:
            self.register_baseline(pkg_dir, note=f"promoted {ev['version']}")   # контрольный набор сохраняется
        return EXIT_CODE[ev["verdict"]]

    def monitor(self, pkg_dir, interval=30.0, once=False, on_event=None, on_error=None,
                stop_event=None) -> None:
        """Monitor a deployed package with bounded polling, durable checkpoints and retries.

        A new process rechecks the current package snapshot. Its deterministic event ID
        makes a crash after journal persistence but before checkpoint persistence safe:
        replay is deduplicated by the shared journal.
        """
        try:
            interval = float(interval)
        except (TypeError, ValueError):
            interval = 30.0
        if not math.isfinite(interval):
            interval = 30.0
        interval = min(3600.0, max(2.0, interval))
        package = Path(pkg_dir).resolve()
        monitor_key = hashlib.sha256(str(package).encode("utf-8")).hexdigest()
        state_path = self.registry / "monitor_state" / f"{monitor_key}.json"
        last = None
        failures = 0

        def report_error(error):
            if on_error:
                try:
                    on_error(error)
                except Exception:
                    pass

        while stop_event is None or not stop_event.is_set():
            try:
                fp = fingerprint(package)
                if fp != last:
                    ev = self.check(package, stage="runtime")
                    if fingerprint(package) != fp:
                        raise OSError("пакет изменился во время проверки; результат не сохранён, будет повтор")
                    event_id = "runtime-" + hashlib.sha256(
                        f"{package}\0{fp}".encode("utf-8")).hexdigest()
                    ev["event_id"] = event_id
                    self.respond(ev)
                    last = fp
                    failures = 0
                    try:
                        state_path.parent.mkdir(parents=True, exist_ok=True)
                        temporary = state_path.with_suffix(".tmp")
                        with temporary.open("w", encoding="utf-8") as stream:
                            json.dump({"fingerprint": fp, "event_id": event_id,
                                       "checked_at": _now()}, stream)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(temporary, state_path)
                    except OSError as state_error:
                        report_error(state_error)
                    if on_event:
                        try:
                            on_event(ev)
                        except Exception as callback_error:  # UI/report callback must not end monitoring
                            report_error(callback_error)
            except Exception as error:
                try:
                    event = self.assessment_error(package, error, "runtime")
                    event["event_id"] = "runtime-error-" + hashlib.sha256(
                        f"{package}\0{type(error).__name__}\0{error}".encode("utf-8", "replace")).hexdigest()
                    self.respond(event)
                except Exception as journal_error:
                    report_error(journal_error)
                failures += 1
                report_error(error)
                if once:
                    raise

            if once:
                return
            if stop_event is not None and stop_event.is_set():
                return
            delay = interval
            if failures:
                retry_delay = min(60.0, 2.0 ** min(failures, 6))
                delay = min(interval, retry_delay)
            if stop_event is not None and callable(getattr(stop_event, "wait", None)):
                stop_event.wait(delay)
            else:
                time.sleep(delay)


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
    baseline = ev.get("baseline_version") or "без эталона"
    lines = [f"[{mark}] {ev['package']} {baseline} -> {ev['version']}  (стадия: {ev['stage']})",
             f"  заключение: {ev['threat_ru']}"]
    if isinstance(ev.get("risk_score"), (int, float)) and isinstance(ev.get("score"), (int, float)):
        lines.append(f"  балл риска модели: {ev['risk_score']}/100; оценка нарушения: {ev['score']:.3f}")
    elif ev.get("analysis_mode") == "reference_missing":
        lines.append("  сравнительная оценка не выполнена: доверенный эталон отсутствует; балл не рассчитывался")
    elif ev.get("analysis_mode") == "intake_validation_error":
        lines.append("  оценка не завершена из-за ошибки проверки пакета; балл не рассчитывался")
    if "levels" in ev:
        lines.append("  уровни: " + ", ".join(f"{k} {v:.2f}" for k, v in ev["levels"].items()))
    if ev.get("suspects"):
        lines.append("  подозрительные компоненты: " + ", ".join(f"{s['component']} ({s['score']:.2f})" for s in ev["suspects"]))
    intel = ev.get("public_intel") or {}
    if intel:
        lines.append(f"  OSV: {intel.get('status', 'неизвестно')}; проверено "
                     f"{intel.get('queried', 0)} из {intel.get('eligible', 0)} PyPI-зависимостей; "
                     f"совпадений: {intel.get('known_vulnerable_dependencies', 0)} "
                     "(отсутствие совпадений не подтверждает безопасность)")
    lines += [f"  ! {r}" for r in ev["rules"]]
    lines += [f"  - {a}" for a in ev.get("actions", [])]
    integrity = ("не оценивался без эталона" if ev.get("hash_control") is None else
                 "нарушение" if ev["hash_control"] else "норма")
    lines.append(f"  контроль подписи/хешей: {integrity}; "
                 f"время проверки: {ev['timing_ms']['total']:.0f} мс")
    return "\n".join(lines)
