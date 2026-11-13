"""Local assistant for live IntegrityGuard network and application telemetry."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _ollama_executable() -> Path | None:
    candidates = []
    configured = os.environ.get("OLLAMA_EXE")
    if configured:
        candidates.append(Path(configured))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe")
    from shutil import which
    on_path = which("ollama")
    if on_path:
        candidates.append(Path(on_path))
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def ensure_ollama_server(base_url: str = "http://127.0.0.1:11434", timeout: int = 20) -> bool:
    """Start Ollama on demand, bound to loopback only."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} \
            or parsed.port not in (None, 11434):
        raise ValueError("Разрешён только локальный Ollama API на порту 11434")

    def ready() -> bool:
        try:
            with urllib.request.urlopen(base_url.rstrip("/") + "/api/tags", timeout=1) as response:
                return response.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    if ready():
        return True
    executable = _ollama_executable()
    if executable is None:
        return False
    environment = os.environ.copy()
    if not environment.get("OLLAMA_MODELS"):
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                environment["OLLAMA_MODELS"] = winreg.QueryValueEx(key, "OLLAMA_MODELS")[0]
        except (ImportError, OSError):
            pass
    environment["OLLAMA_HOST"] = "127.0.0.1:11434"
    creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        subprocess.Popen([str(executable), "serve"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, env=environment, creationflags=creationflags)
    except OSError as exc:
        raise RuntimeError(f"Не удалось запустить локальную службу Ollama: {exc}") from exc
    deadline = time.monotonic() + max(1, min(timeout, 30))
    while time.monotonic() < deadline:
        if ready():
            return True
        time.sleep(0.25)
    return False


def list_ollama_models(base_url: str = "http://127.0.0.1:11434", timeout: int = 2) -> list[str]:
    if not ensure_ollama_server(base_url, timeout=20):
        raise RuntimeError("Локальная служба Ollama не отвечает. Проверьте установку Ollama.")
    request = urllib.request.Request(base_url.rstrip("/") + "/api/tags", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(256 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Локальная служба Ollama не отвечает на 127.0.0.1:11434") from exc
    if len(raw) > 256 * 1024:
        raise RuntimeError("Список локальных моделей превышает допустимый размер")
    try:
        result = json.loads(raw.decode("utf-8"))
        models = result["models"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError("Ollama вернула список моделей в неизвестном формате") from exc
    if not isinstance(models, list):
        raise RuntimeError("Ollama вернула некорректный список моделей")
    return sorted({item["name"] for item in models if isinstance(item, dict)
                   and isinstance(item.get("name"), str) and 0 < len(item["name"]) <= 128})


def _route_question(query: str) -> str | None:
    """Map explicit user requests to fixed read-only functions."""
    q = query.lower().replace("ё", "е")
    if any(term in q for term in (
        "трафик", "траффик", "соединени", "сетевую активность", "сетевой активности",
        "поток сети", "состояние сети", "есть ли атака", "сетевая атака", "сетевой атак",
        "подозрительн", "отбрасывать атак", "блокировать трафик", "рекомендацию по атаке")):
        return "network_assessment"
    if any(term in q for term in ("готовность дообуч", "подтвержденных примеров", "сколько примеров",
                                   "кандидат готов", "можно ли обуч", "готов ли детектор")):
        return "training_readiness"
    if any(term in q for term in ("последние события", "покажи события", "последние инциденты")):
        return "recent_events"
    if any(term in q for term in ("состояние мониторинга", "состояние очереди", "очередь входящих",
                                   "мониторинг сейчас", "сколько событий", "состояние журнала")):
        return "monitoring_status"
    return None


def is_supported_operational_question(query: str) -> bool:
    return _route_question(query) is not None


def _format_read_only_tool_answer(name: str, result: dict) -> str:
    if name == "monitoring_status":
        mode = "включён" if result.get("automatic_monitoring") else "выключен"
        queue = result.get("incoming_queue")
        queue_text = f"{queue}" if type(queue) is int else "недоступна"
        counts = result.get("event_counts_in_latest_500_records", {})
        count_text = ", ".join(f"{key}: {counts.get(key, 'н/д')}" for key in ("ALLOW", "REVIEW", "BLOCK"))
        lines = [f"Автоматический мониторинг: {mode}.", f"Очередь пакетов: {queue_text}.",
                 f"Событий в выборке журнала (не более 500): {result.get('events_observed', 'н/д')}; {count_text}.",
                 f"Файл детектора доступен: {'да' if result.get('detector_file_available') else 'нет'}.",
                 "Качество детектора на независимых реальных инцидентах не подтверждено."]
        if not result.get("event_log_complete", False):
            lines.append("Журнал прочитан не полностью; счётчики ограничены доступной частью.")
        if result.get("last_event_time"):
            lines.append(f"Время последнего события: {result['last_event_time']}.")
        return "\n".join(lines)
    if name == "training_readiness":
        return "\n".join([
            f"Подтверждённые примеры для бинарного детектора пакетов: {result.get('confirmed_samples', 'н/д')}.",
            f"Безопасные: {result.get('benign_samples', 'н/д')}; атакующие: {result.get('attack_samples', 'н/д')}.",
            f"Минимум для кандидата: {result.get('minimum_total', 'н/д')} всего и {result.get('minimum_per_class', 'н/д')} на метку.",
            f"Кандидат готов: {'да' if result.get('binary_detector_candidate_ready') else 'нет'}.",
            f"Ожидают проверки: {result.get('pending_review_count', 'н/д')}.",
        ])
    if name == "recent_events":
        events = result.get("events", [])
        return "Последние события (разрешённые безопасные поля):\n" + json.dumps(
            events, ensure_ascii=False, indent=2, sort_keys=True)
    return "Неизвестная read-only функция."


def _tool_record(name: str, status: str, result: object) -> dict:
    canonical = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {"name": name, "status": status,
            "result_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def answer_with_ollama(query: str, model: str, base_url: str = "http://127.0.0.1:11434",
                       timeout: int = 180, tool_context: dict | None = None) -> dict:
    """Assess live telemetry or return a deterministic read-only app status; never reads documents."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} \
            or parsed.port not in (None, 11434):
        raise ValueError("Разрешён только локальный Ollama API на порту 11434")
    model = model.strip()
    if not model or len(model) > 120 or any(ch.isspace() for ch in model):
        raise ValueError("Укажите имя установленной локальной модели без пробелов")
    if not isinstance(query, str) or not query.strip() or len(query) > 2000:
        raise ValueError("Запрос должен содержать от 1 до 2000 символов")
    if not isinstance(tool_context, dict):
        raise PermissionError("Не задан контекст полномочий локального пользователя")

    routed = _route_question(query)
    if routed is None:
        return {"answer": ("Помощник работает с текущей сетевой телеметрией и функциями IntegrityGuard. "
                           "Спросите о трафике, соединениях, мониторинге, событиях журнала или готовности детектора."),
                "insufficient_evidence": True, "model": "IntegrityGuard operational scope",
                "tool_results": [], "tool_calls": []}

    from .copilot_tools import execute_tool
    if routed == "network_assessment":
        from .network_ai import assess_network_with_ollama
        network = execute_tool("network_status", {}, tool_context)
        app_state = execute_tool("monitoring_status", {}, tool_context)
        assessment = assess_network_with_ollama(network, app_state, model, base_url, timeout)
        data = {"network_telemetry": network, "application_functions": app_state,
                "ai_assessment": assessment,
                "policy_note": "Модель выдаёт рекомендацию; трафик не блокировался."}
        calls = [
            _tool_record("network_status", "ok", network),
            _tool_record("monitoring_status", "ok", app_state),
            _tool_record("network_assessment", "advisory", assessment),
        ]
        labels = {"ALLOW": "явная атака не установлена", "REVIEW": "нужна проверка",
                  "BLOCK": "рекомендация к проверке оператором"}
        answer = (f"Рекомендация локальной модели: {assessment['decision']} — "
                  f"{labels[assessment['decision']]}. {assessment['summary']}\n"
                  "Решение основано на сетевых метаданных и не является правилом firewall.")
        return {"answer": answer, "insufficient_evidence": assessment["insufficient_evidence"],
                "model": f"IntegrityGuard network advisor ({assessment['model']})",
                "tool_results": [{"citation_id": "tool_result_network_assessment", "data": data}],
                "tool_calls": calls}

    arguments = {"limit": 5} if routed == "recent_events" else {}
    try:
        result = execute_tool(routed, arguments, tool_context)
        status = "ok"
    except PermissionError:
        result, status = {"error": "FORBIDDEN"}, "denied"
    except (ValueError, TypeError):
        result, status = {"error": "INVALID_ARGUMENT"}, "denied"
    except (OSError, RuntimeError):
        result, status = {"error": "INTERNAL"}, "error"
    return {"answer": _format_read_only_tool_answer(routed, result) if status == "ok"
            else "Read-only функция не выполнена; проверьте доступ к состоянию приложения.",
            "insufficient_evidence": status != "ok", "model": f"IntegrityGuard tool: {routed}",
            "tool_results": [{"citation_id": f"tool_result_{routed}", "data": result}],
            "tool_calls": [_tool_record(routed, status, result)]}


def telemetry_digest(snapshot: dict, app_state: dict, assessment: dict | None) -> str:
    body = json.dumps({"snapshot": snapshot, "app_state": app_state, "assessment": assessment},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
