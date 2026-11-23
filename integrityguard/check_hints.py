"""Explainable advisory hints for a network snapshot check (not a verdict, never blocks).

Each hint names the observed feature, its value, why it matters and that it is advice.
Thresholds are fixed rules for explanation only; they do not change any score or decision.
"""
from __future__ import annotations

_RULES = (
    ("port_scan_suspected_count", lambda v: v >= 1,
     "Похоже на перебор портов: с одного источника много подключений к разным портам."),
    ("unattributed_endpoint_share", lambda v: v >= 0.5,
     "Большая доля соединений не привязана к известному процессу."),
    ("new_remote_endpoint_count", lambda v: v >= 10,
     "Много новых внешних адресов по сравнению с эталоном."),
    ("packet_rate_zscore", lambda v: abs(v) >= 3,
     "Интенсивность пакетов заметно отличается от обычной."),
    ("byte_rate_zscore", lambda v: abs(v) >= 3,
     "Объём данных заметно отличается от обычного."),
    ("non_https_endpoint_share", lambda v: v >= 0.5,
     "Большая доля соединений без шифрования (не HTTPS)."),
    ("suspicious_port_match_count", lambda v: v >= 1,
     "Есть соединения на порты, которые часто используют в атаках."),
    ("blocked_state_ratio", lambda v: v >= 0.3,
     "Много заблокированных или неудачных соединений."),
)

ADVICE_NOTE = "Это подсказка для ручной проверки, не вердикт и не основание для блокировки."


def hints(features: dict | None) -> list[dict]:
    """Return explanations for every rule that fires on the given feature values."""
    if not isinstance(features, dict):
        return []
    found = []
    for name, fires, reason in _RULES:
        value = features.get(name)
        if isinstance(value, (int, float)) and fires(value):
            found.append({"feature": name, "value": round(float(value), 3), "reason": reason})
    return found
