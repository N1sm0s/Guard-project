"""Create a readable, Unicode-safe PDF report for an IntegrityGuard event."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .spec import CLASS_RU, LEVEL_RU

_VERDICT_RU = {"ALLOW": "ДОПУСК", "REVIEW": "ТРЕБУЕТ ПРОВЕРКИ", "BLOCK": "БЛОКИРОВКА"}
_COLORS = {
    "ink": (25, 37, 59), "muted": (96, 108, 128), "line": (221, 228, 238),
    "pale": (241, 245, 251), "blue": (47, 111, 235), "green": (22, 163, 94),
    "amber": (207, 137, 12), "red": (211, 57, 68), "track": (231, 236, 243),
    "white": (255, 255, 255),
}
_VERDICT_COLOR = {"ALLOW": _COLORS["green"], "REVIEW": _COLORS["amber"], "BLOCK": _COLORS["red"]}


def _find_font(name: str) -> str | None:
    windows_names = {"Arial": "arial", "Arial-Bold": "arialbd",
                     "SegoeUI": "segoeui", "SegoeUI-Bold": "segoeuib"}
    candidates = [
        f"/usr/share/fonts/truetype/dejavu/{name}.ttf",
        f"/usr/share/fonts/dejavu/{name}.ttf",
        f"C:/Windows/Fonts/{windows_names.get(name, name)}.ttf",
        os.path.join(os.path.dirname(__file__), "..", "assets", "fonts", f"{name}.ttf"),
    ]
    return next((str(Path(p)) for p in candidates if Path(p).is_file()), None)


def _register_unicode_font(pdf) -> str:
    for family, regular_name, bold_name in (
        ("DejaVu", "DejaVuSans", "DejaVuSans-Bold"),
        ("Arial", "Arial", "Arial-Bold"),
        ("SegoeUI", "SegoeUI", "SegoeUI-Bold"),
    ):
        regular, bold = _find_font(regular_name), _find_font(bold_name)
        if regular:
            pdf.add_font(family, "", regular)
            pdf.add_font(family, "B", bold or regular)
            return family
    raise RuntimeError("Для PDF не найден Unicode-шрифт. Установите Arial или DejaVu Sans.")


def _format_event_time(value) -> str:
    """Render event time in the computer's local timezone and show its UTC offset."""
    if not value:
        return "не указано"
    try:
        checked_at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
        local_time = checked_at.astimezone()
        offset = local_time.strftime("%z")
        offset = f"UTC{offset[:3]}:{offset[3:]}" if len(offset) == 5 else "локальное время"
        return f"{local_time.strftime('%d.%m.%Y %H:%M:%S')} ({offset})"
    except (TypeError, ValueError):
        return str(value)


def generate(ev: dict[str, Any], out_path: str | Path) -> Path:
    """Create a polished PDF report and write it to any caller-selected path."""
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError as exc:
        raise ImportError("Для экспорта в PDF установите пакет: pip install fpdf2") from exc

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    class ReportPDF(FPDF):
        def footer(self):
            self.set_y(-13)
            self.set_draw_color(*_COLORS["line"])
            self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
            self.set_y(-11)
            self.set_font(font_family, "", 7.5)
            self.set_text_color(*_COLORS["muted"])
            self.cell(0, 6, f"IntegrityGuard  |  Страница {self.page_no()}/{{nb}}", align="C")

    pdf = ReportPDF(orientation="P", unit="mm", format="A4")
    font_family = _register_unicode_font(pdf)
    pdf.alias_nb_pages()
    pdf.set_margins(16, 15, 16)
    pdf.set_auto_page_break(True, margin=18)
    pdf.add_page()
    page_w = pdf.w - pdf.l_margin - pdf.r_margin
    x0 = pdf.l_margin

    def font(size=9, bold=False):
        pdf.set_font(font_family, "B" if bold else "", size)

    def section(title):
        pdf.ln(2)
        font(10, True)
        pdf.set_fill_color(*_COLORS["pale"])
        pdf.set_text_color(*_COLORS["ink"])
        pdf.cell(page_w, 7, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    def kv_row(label, value, y, value_bold=False):
        font(8.5, True)
        pdf.set_text_color(*_COLORS["muted"])
        pdf.set_xy(x0, y)
        pdf.cell(45, 5.5, label)
        font(9, value_bold)
        pdf.set_text_color(*_COLORS["ink"])
        pdf.set_xy(x0 + 46, y)
        pdf.multi_cell(page_w - 46, 5.5, str(value))
        return max(y + 6, pdf.get_y())

    def bar_row(label, value, color, *, max_value=1.0, decimals=2, label_w=83):
        value = float(value) if isinstance(value, (int, float)) else 0.0
        value = min(max(value, 0.0), max_value)
        y = pdf.get_y()
        font(8.1)
        pdf.set_text_color(*_COLORS["ink"])
        pdf.set_xy(x0, y)
        pdf.multi_cell(label_w, 4.3, str(label))
        text_h = pdf.get_y() - y
        row_h = max(6.2, text_h)
        bar_x = x0 + label_w + 2
        value_w = 13
        bar_w = page_w - label_w - value_w - 4
        bar_y = y + (row_h - 3.2) / 2
        pdf.set_fill_color(*_COLORS["track"])
        pdf.rect(bar_x, bar_y, bar_w, 3.2, style="F")
        if value > 0:
            pdf.set_fill_color(*color)
            pdf.rect(bar_x, bar_y, bar_w * value / max_value, 3.2, style="F")
        font(8)
        pdf.set_text_color(*_COLORS["ink"])
        pdf.set_xy(bar_x + bar_w + 1, y + (row_h - 5) / 2)
        display = f"{value:.{decimals}f}" if decimals else f"{value:.0%}"
        pdf.cell(value_w, 5, display, align="R")
        pdf.set_y(y + row_h + 1)

    # Header and verdict
    font(17, True)
    pdf.set_text_color(*_COLORS["ink"])
    pdf.cell(page_w, 9, "IntegrityGuard", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    font(9)
    pdf.set_text_color(*_COLORS["muted"])
    pdf.cell(page_w, 6, "Отчёт о проверке целостности программной модели",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_draw_color(*_COLORS["blue"])
    pdf.set_line_width(0.9)
    pdf.line(x0, pdf.get_y(), x0 + page_w, pdf.get_y())
    pdf.ln(4)

    verdict = ev.get("verdict", "ALLOW")
    pdf.set_fill_color(*_VERDICT_COLOR.get(verdict, _COLORS["muted"]))
    pdf.set_text_color(*_COLORS["white"])
    font(13, True)
    pdf.cell(page_w, 12, f"  {_VERDICT_RU.get(verdict, verdict)}", fill=True,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*_COLORS["ink"])
    pdf.ln(2)

    # Summary
    section("Сводка проверки")
    risk = ev.get("risk_score")
    if risk is None and isinstance(ev.get("score"), (int, float)):
        risk = round(float(ev["score"]) * 100)
    risk_label = f"{risk} из 100" if risk is not None else "не рассчитывался"
    score = ev.get("score")
    score_label = f"{float(score):.4f}" if isinstance(score, (int, float)) else "не рассчитывалась"
    stage_names = {"build": "сборка", "deploy": "поставка", "runtime": "эксплуатация"}
    time_label = _format_event_time(ev.get("time"))
    rows = [
        ("Пакет", f"{ev.get('package', '?')}  |  версия {ev.get('version', '?')}"),
        ("Доверенный эталон", ev.get("baseline_version") or "не зарегистрирован"),
        ("Этап контроля", stage_names.get(ev.get("stage"), ev.get("stage", "не указан"))),
        ("Время события", time_label),
        ("Балл риска модели", risk_label),
        ("Оценка нарушения", score_label),
        ("Метод оценки", "Сравнение не выполнено: нет эталона" if ev.get("analysis_mode") == "reference_missing"
         else "Оценка не завершена" if ev.get("analysis_mode") in {"intake_validation_error", "wheel_validation_error"}
         else ("Статический анализ wheel и сравнение с точным эталоном"
               if ev.get("analysis_mode") == "wheel_static" and ev.get("comparison_performed")
               else "Статический анализ wheel; доверенный эталон не найден"
               if ev.get("analysis_mode") == "wheel_static"
               else "Нейросетевое сравнение с эталоном")),
        ("Класс", ev.get("threat_ru") or CLASS_RU.get(ev.get("threat", "clean"), ev.get("threat", "?"))),
    ]
    y = pdf.get_y()
    for label, value in rows:
        y = kv_row(label, value, y, value_bold=(label == "Балл риска модели"))
    pdf.set_y(y)
    font(7.5)
    pdf.set_text_color(*_COLORS["muted"])
    score_note = ("Без доверенного эталона числовая оценка не рассчитывается."
                  if ev.get("analysis_mode") == "reference_missing" else
                  "Проверка не завершена; числовая оценка не рассчитывалась."
                  if ev.get("analysis_mode") in {"intake_validation_error", "wheel_validation_error"} else
                  "Для wheel выполнен статический анализ; нейросетевой балл не рассчитывался."
                  if ev.get("analysis_mode") == "wheel_static" else
                  "Балл риска - индикатор модели, не вероятность подтверждённой атаки.")
    pdf.cell(page_w, 4.5, score_note,
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if isinstance(ev.get("objective_facts"), dict) and ev["objective_facts"]:
        section("Проверяемые факты")
        fact_names = {"manifest_parsed": "Манифест прочитан", "signature_verified": "Подпись подтверждена",
                      "model_pickle_safe": "Формат модели безопасен", "supported_linear_layers": "Формат слоёв поддерживается",
                      "dependency_count": "Зависимостей", "module_count": "Модулей", "nonfinite_weights": "Неконечные веса"}
        y = pdf.get_y()
        for key, value in ev["objective_facts"].items():
            display = "не проверено" if value is None else "да" if value is True else "нет" if value is False else value
            y = kv_row(fact_names.get(key, key), display, y)
        pdf.set_y(y)

    intel = ev.get("public_intel") or {}
    if intel:
        section("Публичные сведения об уязвимостях")
        font(8.5)
        pdf.set_text_color(*_COLORS["ink"])
        coverage = (f"Источник: OSV; статус запроса: {intel.get('status', 'неизвестно')}; "
                    f"проверено {intel.get('queried', 0)} из {intel.get('eligible', 0)} публичных PyPI-зависимостей. "
                    "Совпадение указывает на опубликованную рекомендацию для версии зависимости, "
                    "а отсутствие совпадений не подтверждает безопасность.")
        pdf.multi_cell(page_w, 5, coverage)
        for dependency in intel.get("findings", []):
            for vulnerability in dependency.get("vulnerabilities", []):
                identifier = vulnerability.get("id", "OSV record")
                label = f"{dependency.get('name')} {dependency.get('version')} — {identifier}"
                summary = vulnerability.get("summary") or "Описание отсутствует в ответе источника."
                url = vulnerability.get("url", "")
                pdf.multi_cell(page_w, 5, f"- {label}: {summary}")
                if url:
                    pdf.set_text_color(*_COLORS["blue"])
                    pdf.multi_cell(page_w, 4.5, url)
                    pdf.set_text_color(*_COLORS["ink"])
        for issue in intel.get("limitations", [])[:5]:
            pdf.multi_cell(page_w, 4.5, f"Ограничение запроса: {issue}")

    # Integrity levels
    if isinstance(ev.get("levels"), dict) and ev["levels"]:
        section("Оценка уровней целостности")
        colors = {"structural": _COLORS["blue"], "parametric": _COLORS["amber"],
                  "behavioral": _COLORS["green"]}
        for level, value in ev["levels"].items():
            bar_row(LEVEL_RU.get(level, level), value, colors.get(level, _COLORS["blue"]))

    # Component findings
    if ev.get("suspects"):
        section("Компоненты, требующие внимания")
        for suspect in ev["suspects"]:
            bar_row(suspect.get("component", "компонент"), suspect.get("score", 0), _COLORS["red"])

    if ev.get("rules"):
        section("Сработавшие правила")
        for rule in ev["rules"]:
            font(8.5)
            pdf.set_text_color(*_COLORS["ink"])
            pdf.multi_cell(page_w, 5, f"- {rule}")

    if ev.get("actions"):
        section("Рекомендуемые действия")
        for i, action in enumerate(ev["actions"], 1):
            font(8.5)
            pdf.set_text_color(*_COLORS["ink"])
            pdf.multi_cell(page_w, 5, f"{i}. {action}")

    if isinstance(ev.get("probabilities"), dict) and ev["probabilities"]:
        section("Оценки классификатора по классам")
        font(7.5)
        pdf.set_text_color(*_COLORS["muted"])
        pdf.multi_cell(page_w, 4.5, "Это оценки модели. Они сами по себе не подтверждают факт атаки.")
        for cls, probability in ev["probabilities"].items():
            bar_row(CLASS_RU.get(cls, cls), probability, _COLORS["blue"], decimals=3, label_w=83)

    # Hash signal is independent evidence, so explain it without overriding the verdict.
    section("Подпись и контрольные хеши")
    hash_value = ev.get("hash_control")
    hash_changed = bool(hash_value)
    if hash_value is None:
        message, color = "Сравнение подписи и контрольных хешей невозможно: доверенный эталон отсутствует.", _COLORS["muted"]
    elif hash_changed:
        message = "Хеш отличается от эталона. Этот сигнал сам по себе не является вердиктом модели."
        if verdict == "ALLOW":
            message += " Проверка модели завершилась допуском; проверьте, что обновление было ожидаемым."
        color = _COLORS["amber"]
    else:
        message, color = "Расхождений по подписи/хешам не обнаружено.", _COLORS["green"]
    font(8.5, True)
    pdf.set_text_color(*color)
    pdf.multi_cell(page_w, 5, message)

    if isinstance(ev.get("timing_ms"), dict) and ev["timing_ms"]:
        section("Время обработки")
        timing_names = {"collect": "Сбор признаков", "analyze": "Анализ модели", "total": "Всего"}
        for key, value in ev["timing_ms"].items():
            y = pdf.get_y()
            kv_row(timing_names.get(str(key), str(key)), f"{value} мс", y)

    fingerprint = str(ev.get("fingerprint", "не указан"))
    font(7.5)
    pdf.set_text_color(*_COLORS["muted"])
    pdf.ln(2)
    pdf.multi_cell(page_w, 4.2, f"Отпечаток проверенного пакета (SHA-256): {fingerprint}")
    pdf.output(str(out_path))
    return out_path


def select_period_events(events: list[dict[str, Any]], start_date: str, end_date: str) -> list[dict[str, Any]]:
    """Select events by inclusive UTC calendar days."""
    try:
        from datetime import date, timedelta
        start_day = date.fromisoformat(str(start_date))
        end_day = date.fromisoformat(str(end_date))
    except (TypeError, ValueError) as exc:
        raise ValueError("Даты периода должны иметь формат YYYY-MM-DD") from exc
    if end_day < start_day:
        raise ValueError("Конец периода не может быть раньше его начала")
    lower = datetime.combine(start_day, datetime.min.time(), timezone.utc)
    upper = datetime.combine(end_day + timedelta(days=1), datetime.min.time(), timezone.utc)

    def parsed_time(event):
        value = event.get("time")
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

    return [event for event in events if isinstance(event, dict)
            and (dt := parsed_time(event)) is not None and lower <= dt < upper]


def generate_period(events: list[dict[str, Any]], out_path: str | Path,
                    start_date: str, end_date: str) -> Path:
    """Create a period summary from stored events; date limits are inclusive UTC days."""
    try:
        from fpdf import FPDF, XPos, YPos
    except ImportError as exc:
        raise ImportError("Для экспорта в PDF установите пакет: pip install fpdf2") from exc

    from datetime import date
    start_day = date.fromisoformat(str(start_date))
    end_day = date.fromisoformat(str(end_date))
    selected = select_period_events(events, start_date, end_date)

    def parsed_time(event):
        value = event.get("time")
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    family = _register_unicode_font(pdf)
    pdf.set_margins(12, 13, 12)
    pdf.set_auto_page_break(True, margin=16)
    pdf.alias_nb_pages()

    def font(size=9, bold=False):
        pdf.set_font(family, "B" if bold else "", size)

    def heading(title):
        font(10, True)
        pdf.set_fill_color(*_COLORS["pale"])
        pdf.set_text_color(*_COLORS["ink"])
        pdf.cell(0, 7, f"  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    pdf.add_page()
    font(17, True)
    pdf.set_text_color(*_COLORS["ink"])
    pdf.cell(0, 9, "IntegrityGuard — сводный отчёт по событиям",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    font(9)
    pdf.set_text_color(*_COLORS["muted"])
    pdf.cell(0, 6, f"Период UTC: {start_day.isoformat()} — {end_day.isoformat()}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_draw_color(*_COLORS["blue"])
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)

    counts = {v: sum(e.get("verdict") == v for e in selected) for v in ("ALLOW", "REVIEW", "BLOCK")}
    unscored = sum(e.get("score") is None for e in selected)
    incomplete = sum(e.get("assessment_complete") is False for e in selected)
    vulnerable = sum(bool((e.get("public_intel") or {}).get("findings")) for e in selected)
    heading("Итоги периода")
    font(9)
    pdf.set_text_color(*_COLORS["ink"])
    summary = (f"Событий: {len(selected)}    |    Допуск: {counts['ALLOW']}    |    "
               f"Проверка: {counts['REVIEW']}    |    Блокировка: {counts['BLOCK']}    |    "
               f"Без числовой оценки: {unscored}    |    Неполных проверок: {incomplete}    |    "
               f"Событий с находками публичных источников: {vulnerable}")
    pdf.multi_cell(0, 6, summary)
    pdf.ln(2)
    heading("События")
    widths = [37, 53, 24, 28, 38, 22, 52]
    headers = ["Время UTC", "Пакет", "Версия", "Вердикт", "Класс / основание", "Риск", "Режим оценки"]

    def table_header():
        font(8, True)
        pdf.set_fill_color(*_COLORS["ink"])
        pdf.set_text_color(*_COLORS["white"])
        for title, width in zip(headers, widths):
            pdf.cell(width, 8, title, border=0, fill=True, align="L")
        pdf.ln()

    table_header()
    font(7.5)
    for event in sorted(selected, key=lambda item: str(item.get("time", ""))):
        if pdf.get_y() > pdf.h - 23:
            pdf.add_page()
            table_header()
            font(7.5)
        when = parsed_time(event)
        values = [when.strftime("%Y-%m-%d %H:%M:%S") if when else "—",
                  str(event.get("package") or "—"), str(event.get("version") or "—"),
                  _VERDICT_RU.get(event.get("verdict"), str(event.get("verdict") or "—")),
                  str(event.get("threat_ru") or event.get("threat") or event.get("analysis_mode") or "—"),
                  "—" if event.get("risk_score") is None else str(event.get("risk_score")),
                  str(event.get("analysis_mode") or ("comparison" if event.get("comparison_performed") else "—"))]
        bg = _COLORS["pale"] if pdf.page_no() % 2 else _COLORS["white"]
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*_COLORS["ink"])
        for value, width in zip(values, widths):
            text = value if len(value) <= 34 else value[:31] + "…"
            pdf.cell(width, 7, text, border="B", fill=True)
        pdf.ln()

    if not selected:
        font(9)
        pdf.set_text_color(*_COLORS["muted"])
        pdf.cell(0, 8, "За выбранный период событий нет.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def footer():
        pdf.set_y(-12)
        pdf.set_draw_color(*_COLORS["line"])
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.set_y(-10)
        font(7)
        pdf.set_text_color(*_COLORS["muted"])
        pdf.cell(0, 5, f"IntegrityGuard  |  UTC  |  Страница {pdf.page_no()}/{{nb}}", align="C")

    for page in range(1, pdf.page_no() + 1):
        pdf.page = page
        footer()
    pdf.output(str(out_path))
    return out_path
