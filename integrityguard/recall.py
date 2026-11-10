"""Полнота обнаружения (Recall) — отдельная функция системы.

Полнота = доля пакетов с нарушением, которые детектор не допустил (вердикт «на проверку» или «блокировка»).
Считается по классам угроз, по уровням целостности и в целом; для сравнения — то же для контроля подписи и хешей.
Модуль не зависит от обучения и интерфейса: ему нужны только пары «разметка — результат проверки».
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .spec import CLASS_LEVEL, CLASSES, LEVELS

THREATS = CLASSES[1:]


def _rate(hit: int, n: int):
    return hit / n if n else None


def recall_table(results) -> dict:
    """Полнота по набору результатов.

    results — список словарей: {"class": истинный класс, "detected": bool, "named": заключение детектора,
    "hash": bool — сработал ли контроль подписи и хешей}.
    """
    per_class = {}
    for c in THREATS:
        rows = [r for r in results if r["class"] == c]
        n = len(rows)
        det = sum(bool(r["detected"]) for r in rows)
        per_class[c] = {"n": n, "detected": det, "missed": n - det, "recall": _rate(det, n),
                        "named": _rate(sum(r.get("named") == c for r in rows), n),
                        "hash_recall": _rate(sum(bool(r.get("hash")) for r in rows), n)}
    per_level = {}
    for lv in LEVELS:
        cs = [c for c in THREATS if CLASS_LEVEL[c] == lv]
        n, det = sum(per_class[c]["n"] for c in cs), sum(per_class[c]["detected"] for c in cs)
        per_level[lv] = {"n": n, "detected": det, "missed": n - det, "recall": _rate(det, n)}
    bad = [r for r in results if r["class"] != "clean"]
    clean = [r for r in results if r["class"] == "clean"]
    det = sum(bool(r["detected"]) for r in bad)
    return {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "per_class": per_class, "per_level": per_level,
            "overall": {"n": len(bad), "detected": det, "missed": len(bad) - det, "recall": _rate(det, len(bad)),
                        "hash_recall": _rate(sum(bool(r.get("hash")) for r in bad), len(bad))},
            "clean": {"n": len(clean), "false_alarms": sum(bool(r["detected"]) for r in clean)}}


def result_of(label: dict, ev: dict) -> dict:
    """Пара «разметка демо-пакета — событие проверки» в виде строки для recall_table."""
    return {"class": label["class"], "detected": ev["verdict"] != "ALLOW", "named": ev.get("threat"),
            "hash": bool(ev.get("hash_control"))}


def measure_recall(guard, demo_dir, labels, progress=None) -> dict:
    """Расчёт полноты на размеченном наборе пакетов. В журнал событий проверки не пишутся."""
    demo_dir, results = Path(demo_dir), []
    for i, lb in enumerate(labels):
        cand = demo_dir / lb["project"] / "candidates" / lb["candidate"]
        side = Path(f"{cand}.index.json")
        ev = guard.check(cand, "build", str(side) if side.exists() else None)
        results.append(result_of(lb, ev))
        if progress:
            progress((i + 1, len(labels)))
    return recall_table(results)


def from_metrics(metrics: dict) -> dict:
    """Полнота на тестовой выборке из metrics.json (результат обучения) в том же виде, что и recall_table."""
    h, hb = metrics["hybrid"], metrics["hash_baseline"]["per_class_detected"]
    per_class = {}
    for c in THREATS:
        pc = h["per_class"][c]
        det = round(pc["detected"] * pc["n"])
        per_class[c] = {"n": pc["n"], "detected": det, "missed": pc["n"] - det, "recall": pc["detected"],
                        "named": pc["recall"], "hash_recall": hb.get(c)}
    per_level = {}
    for lv in LEVELS:
        cs = [c for c in THREATS if CLASS_LEVEL[c] == lv]
        n, det = sum(per_class[c]["n"] for c in cs), sum(per_class[c]["detected"] for c in cs)
        per_level[lv] = {"n": n, "detected": det, "missed": n - det, "recall": _rate(det, n)}
    n, det = sum(v["n"] for v in per_class.values()), sum(v["detected"] for v in per_class.values())
    hash_det = sum((v["hash_recall"] or 0) * v["n"] for v in per_class.values())
    return {"per_class": per_class, "per_level": per_level,
            "overall": {"n": n, "detected": det, "missed": n - det, "recall": _rate(det, n), "hash_recall": _rate(hash_det, n)}}


def save(path, table: dict) -> None:
    Path(path).write_text(json.dumps(table, ensure_ascii=False, indent=1), encoding="utf-8")


def load(path):
    try:
        t = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return t if isinstance(t, dict) and "per_class" in t and "overall" in t else None
    except (OSError, ValueError):
        return None


def class_metric_values(table: dict, metric: str, classes=THREATS) -> list:
    """Return aligned class metrics; missing classes in older reports are undefined, not zero."""
    per_class = table.get("per_class", {}) if isinstance(table, dict) else {}
    values = []
    for class_name in classes:
        row = per_class.get(class_name, {}) if isinstance(per_class, dict) else {}
        value = row.get(metric) if isinstance(row, dict) else None
        values.append(value if isinstance(value, (int, float)) and value == value else None)
    return values
