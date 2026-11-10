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
    risk = ev.get("risk_score", round(float(ev.get("score", 0)) * 100))
    stage_names = {"build": "сборка", "deploy": "поставка", "runtime": "эксплуатация"}
    time_label = _format_event_time(ev.get("time"))
    rows = [
        ("Пакет", f"{ev.get('package', '?')}  |  версия {ev.get('version', '?')}"),
        ("Доверенный эталон", ev.get("baseline_version", "не указан")),
        ("Этап контроля", stage_names.get(ev.get("stage"), ev.get("stage", "не указан"))),
        ("Время события", time_label),
        ("Баллы риска", f"{risk} из 100"),
        ("Оценка модели", f"{float(ev.get('score', 0)):.4f}"),
        ("Класс", CLASS_RU.get(ev.get("threat", "clean"), ev.get("threat", "?"))),
    ]
    y = pdf.get_y()
    for label, value in rows:
        y = kv_row(label, value, y, value_bold=(label == "Баллы риска"))
    pdf.set_y(y)
    font(7.5)
    pdf.set_text_color(*_COLORS["muted"])
    pdf.cell(page_w, 4.5, "Балл риска - индикатор модели, не вероятность подтверждённой атаки.",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

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
    hash_changed = bool(ev.get("hash_control", False))
    if hash_changed:
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
