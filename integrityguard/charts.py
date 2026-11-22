"""Графики интерфейса в тёмной теме. Рисуются средствами Qt, без внешних библиотек.

Каждый график сам закрашивает свой фон и сам показывает причину, если построить его не удалось, —
пустого прямоугольника вместо графика не бывает.
"""
from __future__ import annotations

import traceback
from datetime import datetime, timedelta

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

SURFACE, GRID, INK, MUTED, ACCENT, SECOND = "#12151c", "#222733", "#e9ebef", "#8a8f99", "#2bb7ab", "#e8793a"
STATUS = {"ALLOW": ("Допуск", "#1f9d63"), "REVIEW": ("На проверку", "#d99a1c"), "BLOCK": ("Блокировка", "#e5484d")}


class TrainingHistoryChart(QWidget):
    """Recorded losses and development recall confidence bound; no interpolated data."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.epochs = []
        self.train_loss = []
        self.dev_loss = []
        self.dev_recall_ci_lower = []
        self.best_dev_recall_ci_lower = []
        self.setMinimumHeight(210)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_history(self, rows):
        valid = [row for row in rows if isinstance(row, dict)
                 and row.get("event") == "epoch"
                 and isinstance(row.get("epoch"), int)
                 and isinstance(row.get("train_loss"), (int, float))
                 and isinstance(row.get("development_nll"), (int, float))]
        self.epochs = [row["epoch"] for row in valid]
        self.train_loss = [float(row["train_loss"]) for row in valid]
        self.dev_loss = [float(row["development_nll"]) for row in valid]
        self.dev_recall_ci_lower = [
            float(row.get("development_min_recall_ci95_lower") or 0.0) for row in valid]
        self.best_dev_recall_ci_lower = [
            float(row.get("best_development_min_recall_ci95_lower") or 0.0) for row in valid]
        self.update()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor(SURFACE))
        left, right, top, bottom = 54, self.width() - 48, 28, self.height() - 36
        plot = QRectF(left, top, max(1, right - left), max(1, bottom - top))
        if len(self.epochs) < 2:
            p.setPen(QColor(MUTED))
            p.drawText(plot, Qt.AlignCenter, "Кривые появятся после записи минимум двух эпох реального обучения")
            p.end()
            return
        vals = self.train_loss + self.dev_loss
        vmax = max(max(vals), 1e-6)
        vmin = min(0.0, min(vals))
        span = max(vmax - vmin, 1e-6)
        p.setFont(QFont("Segoe UI", 8))
        for i in range(5):
            y = plot.bottom() - plot.height() * i / 4
            p.setPen(QPen(QColor(GRID), 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QColor(MUTED))
            p.drawText(QRectF(0, y - 8, left - 8, 16), Qt.AlignRight | Qt.AlignVCenter,
                       f"{vmin + span * i / 4:.3g}")
        colors = (QColor(ACCENT), QColor(SECOND))
        for data, color in ((self.train_loss, colors[0]), (self.dev_loss, colors[1])):
            path = QPainterPath()
            for index, value in enumerate(data):
                x = plot.left() + plot.width() * index / max(1, len(data) - 1)
                y = plot.bottom() - plot.height() * (value - vmin) / span
                point = QPointF(x, y)
                if index == 0:
                    path.moveTo(point)
                else:
                    path.lineTo(point)
            p.setPen(QPen(color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            p.drawPath(path)
        p.setPen(colors[0]); p.drawText(QRectF(plot.left(), 4, 96, 18), Qt.AlignLeft, "Train loss")
        p.setPen(colors[1]); p.drawText(QRectF(plot.left() + 98, 4, 100, 18), Qt.AlignLeft,
                                        "Development NLL")
        recall_color = QColor("#7db7ff")
        best_color = QColor("#d6b4ff")
        for data, color, pen_style in (
                (self.dev_recall_ci_lower, recall_color, Qt.SolidLine),
                (self.best_dev_recall_ci_lower, best_color, Qt.DashLine)):
            if not any(self.dev_recall_ci_lower):
                break
            path = QPainterPath()
            for index, value in enumerate(data):
                x = plot.left() + plot.width() * index / max(1, len(data) - 1)
                y = plot.bottom() - plot.height() * min(max(value, 0.0), 1.0)
                point = QPointF(x, y)
                if index == 0:
                    path.moveTo(point)
                else:
                    path.lineTo(point)
            p.setPen(QPen(color, 2 if pen_style == Qt.SolidLine else 1.5, pen_style,
                          Qt.RoundCap, Qt.RoundJoin))
            p.drawPath(path)
        p.setPen(recall_color)
        p.drawText(QRectF(plot.left() + 202, 4, 108, 18), Qt.AlignLeft, "Dev recall CI-L")
        p.setPen(best_color)
        p.drawText(QRectF(plot.left() + 312, 4, 92, 18), Qt.AlignLeft, "Best so far")
        p.setPen(QColor(MUTED))
        for i in range(5):
            y = plot.bottom() - plot.height() * i / 4
            p.drawText(QRectF(plot.right() + 4, y - 8, 42, 16), Qt.AlignLeft | Qt.AlignVCenter,
                       f"{i * 25}%")
        p.drawText(QRectF(plot.right() + 2, plot.top() - 18, 48, 16), Qt.AlignLeft | Qt.AlignVCenter,
                   "CI-L")
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(plot.left(), plot.bottom() + 5, plot.width() / 2, 18), Qt.AlignLeft,
                   f"эпоха {self.epochs[0]}")
        p.drawText(QRectF(plot.center().x(), plot.bottom() + 5, plot.width() / 2, 18), Qt.AlignRight,
                   f"эпоха {self.epochs[-1]}")
        p.end()


def _steps(vmax: float) -> int:
    """Число делений шкалы, при котором подписи — целые числа."""
    if vmax <= 5:
        return max(int(vmax), 1)
    return 4 if vmax % 4 == 0 and vmax % 5 != 0 or vmax % 20 == 0 else 5


def _nice(v: float) -> float:
    """Округление максимума шкалы вверх до «красивого» числа."""
    if not v == v or v <= 0:
        return 1.0
    p = 10 ** len(str(int(v))) / 10
    for m in (1, 2, 2.5, 4, 5, 10):
        if v <= m * p and (p >= 10 or m == int(m)):
            return float(m * p)
    return float(v)


def _local(iso: str) -> datetime:
    """Время события (UTC, ISO) -> местное время без зоны."""
    t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    return (t.astimezone() if t.tzinfo else t).replace(tzinfo=None)


class Chart(QWidget):
    """Основа: фон, поле графика, сетка, подписи осей, легенда, подсказка при наведении."""
    M_LEFT, M_RIGHT, M_TOP, M_BOTTOM = 46, 14, 28, 26

    def __init__(self, height=220):
        super().__init__()
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMouseTracking(True)
        self.empty_text = "Данных пока нет"
        self._hits: list[tuple[QRectF, str]] = []

    # --- рисование
    def paintEvent(self, _):
        p = QPainter(self)
        try:
            p.setRenderHint(QPainter.Antialiasing)
            p.fillRect(self.rect(), QColor(SURFACE))
            f = QFont(self.font())
            f.setPointSizeF(8.5)
            p.setFont(f)
            self._hits = []
            if self.draw(p) is False:
                self.message(p, self.empty_text)
        except Exception as e:  # noqa: BLE001 — ошибка в данных не должна оставлять пустое место
            traceback.print_exc()
            p.fillRect(self.rect(), QColor(SURFACE))
            self.message(p, f"Не удалось построить график: {type(e).__name__}: {e}")
        finally:
            p.end()

    def draw(self, p) -> bool | None:
        """Рисует график. Возвращает False, если данных нет."""
        raise NotImplementedError

    def message(self, p, text):
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(self.rect()).adjusted(16, 8, -16, -8), Qt.AlignCenter | Qt.TextWordWrap, text)

    def plot(self) -> QRectF:
        return QRectF(self.M_LEFT, self.M_TOP, max(self.width() - self.M_LEFT - self.M_RIGHT, 10),
                      max(self.height() - self.M_TOP - self.M_BOTTOM, 10))

    def y_grid(self, p, r, vmax, fmt="{:.0f}", steps=4):
        for i in range(steps + 1):
            y = r.bottom() - r.height() * i / steps
            p.setPen(QPen(QColor(GRID), 1))
            p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
            p.setPen(QColor(MUTED))
            p.drawText(QRectF(0, y - 9, self.M_LEFT - 8, 18), Qt.AlignRight | Qt.AlignVCenter, fmt.format(vmax * i / steps))

    def legend(self, p, items):
        x = float(self.M_LEFT)
        for name, color in items:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(color))
            p.drawRoundedRect(QRectF(x, 8, 10, 10), 3, 3)
            p.setPen(QColor(MUTED))
            w = p.fontMetrics().horizontalAdvance(name)
            p.drawText(QRectF(x + 15, 3, w + 6, 20), Qt.AlignVCenter, name)
            x += w + 36

    # --- подсказки
    def mouseMoveEvent(self, e):
        pos = e.position()
        for rect, text in self._hits:
            if rect.contains(pos):
                QToolTip.showText(e.globalPosition().toPoint(), text, self)
                return
        QToolTip.hideText()


class VerdictBars(Chart):
    """Поток входящих пакетов: число проверок по интервалам времени с разбивкой по вердиктам."""

    def __init__(self):
        super().__init__()
        self.buckets: list[tuple[str, dict]] = []

    def set_events(self, events):
        times = []
        for ev in events:
            try:
                if ev["verdict"] in STATUS:
                    times.append((_local(ev["time"]), ev["verdict"]))
            except (KeyError, ValueError, TypeError, OSError):
                continue                                  # запись журнала без времени пропускается
        self.buckets = []
        if times:
            t0, t1 = min(t for t, _ in times), max(t for t, _ in times)
            span = max((t1 - t0).total_seconds(), 1.0)
            step = next((s for s in (10, 60, 300, 900, 3600, 6 * 3600, 86400) if span / s <= 24), 7 * 86400)
            base = datetime(t0.year, t0.month, t0.day)
            start = base + timedelta(seconds=int((t0 - base).total_seconds() // step) * step)
            n = int((t1 - start).total_seconds() // step) + 1
            fmt = "%H:%M:%S" if step < 60 else "%H:%M" if step < 86400 else "%d.%m"
            counts = [dict.fromkeys(STATUS, 0) for _ in range(n)]
            for t, v in times:
                counts[min(int((t - start).total_seconds() // step), n - 1)][v] += 1
            self.buckets = [((start + timedelta(seconds=i * step)).strftime(fmt), c) for i, c in enumerate(counts)]
        self.update()

    def draw(self, p):
        if not self.buckets:
            return False
        r = self.plot()
        vmax = _nice(max(sum(c.values()) for _, c in self.buckets))
        self.y_grid(p, r, vmax, steps=_steps(vmax))
        self.legend(p, list(STATUS.values()))
        n = len(self.buckets)
        slot = r.width() / n
        bw = min(38.0, slot * 0.62)
        every = max(1, int(n * 64 / r.width()) + 1)
        for i, (lab, c) in enumerate(self.buckets):
            x = r.left() + slot * i + (slot - bw) / 2
            y = r.bottom()
            for key, (name, color) in STATUS.items():
                if not c[key]:
                    continue
                h = r.height() * c[key] / vmax
                seg = QRectF(x, y - h + 1, bw, max(h - 2, 2))        # зазор 2 px между сегментами
                p.setPen(Qt.NoPen)
                p.setBrush(QColor(color))
                p.drawRoundedRect(seg, 3, 3)
                self._hits.append((seg.adjusted(-2, -2, 2, 2), f"{lab} — {name.lower()}: {c[key]}"))
                y -= h
            if i % every == 0:
                p.setPen(QColor(MUTED))
                p.drawText(QRectF(x - 34, r.bottom() + 4, bw + 68, 18), Qt.AlignHCenter, lab)


class ScoreDots(Chart):
    """Оценка нарушения для каждого проверенного пакета по порядку поступления."""

    def __init__(self):
        super().__init__()
        self.events, self.thr, self.block = [], None, None

    def set_events(self, events):
        self.events = [e for e in events if isinstance(e.get("score"), (int, float)) and e.get("verdict") in STATUS][-120:]
        last = next((e for e in reversed(events) if "threshold" in e and "block_threshold" in e), None)
        self.thr, self.block = (last["threshold"], last["block_threshold"]) if last else (None, None)
        self.update()

    def draw(self, p):
        if not self.events:
            return False
        r = self.plot()
        self.y_grid(p, r, 1.0, "{:.2f}")
        self.legend(p, list(STATUS.values()))
        for val, name, dy in ((self.thr, "порог проверки", -17), (self.block, "порог блокировки", 3)):
            if isinstance(val, (int, float)) and 0 <= val <= 1:
                y = r.bottom() - r.height() * val
                p.setPen(QPen(QColor(MUTED), 1, Qt.DashLine))
                p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
                p.drawText(QRectF(r.right() - 170, y + dy, 166, 16), Qt.AlignRight, f"{name} {val:.2f}")
        n = len(self.events)
        for i, ev in enumerate(self.events):
            s = ev["score"] if ev["score"] == ev["score"] else 1.0
            x = r.left() + r.width() * (i + 0.5) / n
            y = r.bottom() - r.height() * min(max(s, 0), 1)
            name, color = STATUS[ev["verdict"]]
            p.setPen(QPen(QColor(SURFACE), 2))                      # кольцо цвета фона вокруг точки
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(x, y), 5, 5)
            self._hits.append((QRectF(x - 8, y - 8, 16, 16),
                               f"{ev.get('package', '')} {ev.get('version', '')}\n{name}, оценка {s:.3f}"))
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight,
                   f"последние {n} проверок, слева направо по времени")


class HBars(Chart):
    """Горизонтальные столбцы: число пакетов по заключениям."""
    M_LEFT, M_TOP, M_BOTTOM = 150, 8, 8

    def __init__(self):
        super().__init__()
        self.rows: list[tuple[str, int]] = []

    def set_rows(self, rows):
        self.rows = rows
        self.update()

    def draw(self, p):
        if not self.rows or not any(v for _, v in self.rows):
            return False
        r = self.plot()
        vmax = max(v for _, v in self.rows)
        slot = r.height() / len(self.rows)
        bh = min(18.0, slot * 0.6)
        for i, (name, v) in enumerate(self.rows):
            y = r.top() + slot * i + (slot - bh) / 2
            p.setPen(QColor(INK))
            p.drawText(QRectF(0, y - 3, self.M_LEFT - 10, bh + 6), Qt.AlignRight | Qt.AlignVCenter, name)
            w = max(r.width() - 44, 10) * v / vmax
            bar = QRectF(r.left(), y, max(w, 2), bh)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(ACCENT if v else GRID))
            p.drawRoundedRect(bar, 3, 3)
            p.setPen(QColor(MUTED))
            p.drawText(QRectF(bar.right() + 8, y - 3, 60, bh + 6), Qt.AlignVCenter, str(v))
            self._hits.append((QRectF(0, y - 3, self.width(), bh + 6), f"{name}: {v}"))


class LiveLine(Chart):
    """Бегущий график одного показателя (последние N секунд)."""

    def __init__(self, unit="пак./с", capacity=120):
        super().__init__(190)
        self.unit, self.capacity, self.values = unit, capacity, []
        self._hover = None

    def push(self, v: float):
        self.values = (self.values + [max(float(v), 0.0)])[-self.capacity:]
        self.update()

    def mouseMoveEvent(self, e):
        r = self.plot()
        x = e.position().x()
        if self.values and r.left() <= x <= r.right():
            i = round((x - r.left()) / r.width() * (self.capacity - 1)) - (self.capacity - len(self.values))
            if 0 <= i < len(self.values):
                self._hover = i
                QToolTip.showText(e.globalPosition().toPoint(),
                                  f"{self.values[i]:.0f} {self.unit}\n{len(self.values) - 1 - i} с назад", self)
                return self.update()
        self._hover = None
        QToolTip.hideText()
        self.update()

    def leaveEvent(self, _):
        self._hover = None
        self.update()

    def draw(self, p):
        if len(self.values) < 2:
            return False
        r = self.plot()
        vmax = _nice(max(max(self.values), 1))
        self.y_grid(p, r, vmax, steps=_steps(vmax))
        off = self.capacity - len(self.values)
        pts = [QPointF(r.left() + r.width() * (off + i) / (self.capacity - 1), r.bottom() - r.height() * v / vmax)
               for i, v in enumerate(self.values)]
        area = QPainterPath(QPointF(pts[0].x(), r.bottom()))
        for q in pts:
            area.lineTo(q)
        area.lineTo(QPointF(pts[-1].x(), r.bottom()))
        fill = QColor(ACCENT)
        fill.setAlpha(40)
        p.fillPath(area, fill)
        line = QPainterPath(pts[0])
        for q in pts[1:]:
            line.lineTo(q)
        p.setPen(QPen(QColor(ACCENT), 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.setBrush(Qt.NoBrush)
        p.drawPath(line)
        if self._hover is not None and self._hover < len(pts):
            q = pts[self._hover]
            p.setPen(QPen(QColor(MUTED), 1))
            p.drawLine(QPointF(q.x(), r.top()), QPointF(q.x(), r.bottom()))
            p.setPen(QPen(QColor(SURFACE), 2))
            p.setBrush(QColor(ACCENT))
            p.drawEllipse(q, 5, 5)
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignLeft, f"−{self.capacity} с")
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight, "сейчас")
        p.drawText(QRectF(self.M_LEFT, 3, r.width(), 20), Qt.AlignVCenter, self.unit)


class GroupBars(Chart):
    """Сгруппированные столбцы долей (0…1): сравнение методов по категориям."""
    M_TOP, M_BOTTOM = 48, 30

    def __init__(self):
        super().__init__(280)
        self.cats: list[str] = []
        self.series: list[tuple[str, str, list]] = []

    def set_data(self, cats, series):
        self.cats, self.series = list(cats), [(n, c, list(v)) for n, c, v in series]
        self.update()

    def draw(self, p):
        if not self.cats or not self.series:
            return False
        r = self.plot()
        self.y_grid(p, r, 1.0, "{:.1f}", steps=5)
        self.legend(p, [(n, c) for n, c, _ in self.series])
        slot = r.width() / len(self.cats)
        k = len(self.series)
        bw = min(34.0, slot * 0.72 / k)
        for i, cat in enumerate(self.cats):
            x0 = r.left() + slot * i + (slot - bw * k - 2 * (k - 1)) / 2
            for j, (name, color, vals) in enumerate(self.series):
                v = vals[i] if i < len(vals) and isinstance(vals[i], (int, float)) and vals[i] == vals[i] else None
                if v is None:
                    p.setPen(QColor(MUTED))
                    p.drawText(QRectF(x0 + j * (bw + 2) - 8, r.top() + 2, bw + 16, 14), Qt.AlignHCenter, "—")
                    continue
                h = r.height() * min(max(v, 0), 1)
                bar = QRectF(x0 + j * (bw + 2), r.bottom() - h, bw, max(h, 1.5))
                p.setPen(Qt.NoPen)
                p.setBrush(QColor(color))
                p.drawRoundedRect(bar, 3, 3)
                p.setPen(QColor(INK if v else MUTED))
                p.drawText(QRectF(bar.left() - 12, bar.top() - 16, bw + 24, 14), Qt.AlignHCenter, f"{v:.2f}")
                self._hits.append((bar.adjusted(-2, -18, 2, 0), f"{cat} — {name}: {v:.3f}"))
            p.setPen(QColor(MUTED))
            p.drawText(QRectF(r.left() + slot * i, r.bottom() + 6, slot, 18), Qt.AlignHCenter, cat)


class Heatmap(Chart):
    """Матрица ошибок: строки — истинный класс, столбцы — заключение детектора."""
    M_LEFT, M_RIGHT, M_TOP, M_BOTTOM = 96, 14, 8, 46

    def __init__(self):
        super().__init__(280)
        self.labels: list[str] = []
        self.matrix: list[list] = []

    def set_data(self, labels, matrix):
        self.labels, self.matrix = list(labels), [list(row) for row in matrix]
        self.update()

    def draw(self, p):
        n = len(self.labels)
        if not n or len(self.matrix) != n or any(len(row) != n for row in self.matrix):
            return False
        fm = p.fontMetrics()
        tilt = max(fm.horizontalAdvance(t) for t in self.labels) > self.plot().width() / n - 6
        self.M_BOTTOM = 78 if tilt else 46                # узкие столбцы — подписи под наклоном
        r = self.plot()
        cw, ch = r.width() / n, r.height() / n
        lo, hi = QColor("#1c2330"), QColor(ACCENT)
        for i, row in enumerate(self.matrix):
            total = sum(row) or 1
            p.setPen(QColor(MUTED))
            p.drawText(QRectF(0, r.top() + ch * i, self.M_LEFT - 8, ch), Qt.AlignRight | Qt.AlignVCenter, self.labels[i])
            for j, v in enumerate(row):
                t = min(max(v / total, 0), 1) ** 0.5
                c = QColor(*(round(lo.getRgb()[q] + (hi.getRgb()[q] - lo.getRgb()[q]) * t) for q in range(3)))
                cell = QRectF(r.left() + cw * j + 1, r.top() + ch * i + 1, cw - 2, ch - 2)
                p.setPen(Qt.NoPen)
                p.setBrush(c)
                p.drawRoundedRect(cell, 4, 4)
                p.setPen(QColor(INK if v else "#5d6675"))
                p.drawText(cell, Qt.AlignCenter, str(v))
                self._hits.append((cell, f"истинный класс: {self.labels[i]}\nзаключение: {self.labels[j]}\n"
                                         f"образцов: {v} ({100 * v / total:.1f}% строки)"))
        p.setPen(QColor(MUTED))
        for j, lab in enumerate(self.labels):
            if tilt:
                p.save()
                p.translate(r.left() + cw * (j + 0.5) + 4, r.bottom() + 8)
                p.rotate(-40)
                p.drawText(QRectF(-80, -8, 80, 16), Qt.AlignRight | Qt.AlignVCenter, lab)
                p.restore()
            else:
                p.drawText(QRectF(r.left() + cw * j - 10, r.bottom() + 4, cw + 20, 18), Qt.AlignHCenter, lab)
        p.drawText(QRectF(0, self.height() - 22, self.width(), 18), Qt.AlignHCenter,
                   "строки — истинный класс, столбцы — заключение")


class NNScoreStream(Chart):
    """Потоковый график оценок P(attack) последних N завершённых потоков.

    Пороговые превышения отмечаются для обзора. Они не являются подтверждёнными
    атаками и не запускают блокировку. Пунктир — порог кандидата.
    """

    def __init__(self, capacity=200):
        super().__init__(200)
        self.capacity = capacity
        self.flows: list[dict] = []
        self.threshold: float | None = None
        self._hover_i: int | None = None

    def push_flows(self, flows: list[dict], threshold: float | None = None):
        self.flows = (self.flows + [f for f in flows if isinstance(f.get("score"), (int, float))])[-self.capacity:]
        if threshold is not None:
            self.threshold = float(threshold)
        self.update()

    def set_flows(self, flows: list[dict], threshold: float | None = None):
        """Replace the displayed window with the current live inference window."""
        self.flows = [f for f in flows if isinstance(f, dict)
                      and isinstance(f.get("score"), (int, float))][-self.capacity:]
        if threshold is not None:
            self.threshold = float(threshold)
        self.update()

    def mouseMoveEvent(self, e):
        r = self.plot()
        x = e.position().x()
        if self.flows and r.left() <= x <= r.right():
            i = round((x - r.left()) / r.width() * (len(self.flows) - 1))
            if 0 <= i < len(self.flows):
                self._hover_i = i
                f = self.flows[i]
                udp_tag = " [UDP]" if f.get("is_udp") else ""
                completion = f.get("completion_reason")
                completion_tag = "\nЗавершение: тайм-аут бездействия 1 с" \
                    if completion == "udp_idle_timeout_1s" else ""
                QToolTip.showText(e.globalPosition().toPoint(),
                                  f"Поток #{i + 1}{udp_tag}\nP(атака) = {f['score']:.4f}\n"
                                  f"Статус кандидата: {f.get('verdict', '?')}{completion_tag}",
                                  self)
                return self.update()
        self._hover_i = None
        QToolTip.hideText()
        self.update()

    def leaveEvent(self, _):
        self._hover_i = None
        self.update()

    def draw(self, p):
        if not self.flows:
            return False
        r = self.plot()
        self.y_grid(p, r, 1.0, "{:.2f}")
        if self.threshold is not None and 0 <= self.threshold <= 1:
            y_thr = r.bottom() - r.height() * self.threshold
            p.setPen(QPen(QColor(ACCENT), 1, Qt.DashLine))
            p.drawLine(QPointF(r.left(), y_thr), QPointF(r.right(), y_thr))
            p.setPen(QColor(ACCENT))
            p.drawText(QRectF(r.right() - 130, y_thr - 16, 126, 14), Qt.AlignRight, f"порог {self.threshold:.4f}")
        n = len(self.flows)
        COLORS = {"ALLOW": "#1f9d63", "REVIEW": "#d99a1c", "BLOCK": "#e5484d"}
        UDP_RING = "#4dd0c4"
        for i, f in enumerate(self.flows):
            s = min(max(float(f["score"]), 0.0), 1.0)
            x = r.left() + r.width() * i / max(n - 1, 1)
            y = r.bottom() - r.height() * s
            color = COLORS.get(f.get("verdict", "ALLOW"), MUTED)
            radius = 6 if i == self._hover_i else 4
            if f.get("is_udp"):
                p.setPen(QPen(QColor(UDP_RING), 1.5))
            else:
                p.setPen(QPen(QColor(SURFACE), 1.5))
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(x, y), radius, radius)
        self.legend(p, [("выше порога — обзор", "#d99a1c"),
                        ("ниже порога", "#1f9d63"), ("UDP-кольцо", UDP_RING)])
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight, f"последние {n} потоков →")


class BenignUDPHistogram(Chart):
    """Гистограмма оценок P(attack) для наблюдаемых UDP-потоков.

    Локальные метки неизвестны; график не считает ложные срабатывания.
    """

    def __init__(self, bins: int = 40):
        super().__init__(180)
        self.bins = bins
        self.scores: list[float] = []
        self.threshold: float | None = None

    def set_scores(self, scores: list[float], threshold: float | None = None):
        self.scores = [float(s) for s in scores if isinstance(s, (int, float))]
        if threshold is not None:
            self.threshold = float(threshold)
        self.update()

    def draw(self, p):
        if not self.scores:
            return False
        r = self.plot()
        counts = [0] * self.bins
        for s in self.scores:
            bi = min(int(s * self.bins), self.bins - 1)
            counts[bi] += 1
        vmax = max(counts) or 1
        self.y_grid(p, r, vmax, steps=4)
        bw = r.width() / self.bins
        for i, cnt in enumerate(counts):
            x = r.left() + bw * i
            h = r.height() * cnt / vmax
            bar = QRectF(x + 1, r.bottom() - h, bw - 2, max(h, 1))
            is_tail = (self.threshold is not None and (i + 1) / self.bins > self.threshold)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(SECOND if is_tail else "#1f9d63"))
            p.drawRoundedRect(bar, 2, 2)
        if self.threshold is not None:
            thr_x = r.left() + r.width() * self.threshold
            p.setPen(QPen(QColor("#e5484d"), 1.5, Qt.DashLine))
            p.drawLine(QPointF(thr_x, r.top()), QPointF(thr_x, r.bottom()))
            p.setPen(QColor("#e5484d"))
            p.drawText(QRectF(thr_x + 4, r.top() + 2, 80, 14), Qt.AlignLeft, f"порог {self.threshold:.4f}")
        above = sum(1 for s in self.scores if self.threshold is not None and s > self.threshold)
        total = len(self.scores)
        pct = above / total * 100 if total else 0
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignLeft,
                   f"UDP потоков: {total}")
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight,
                   f"выше порога: {above} ({pct:.1f}%)")
        self.legend(p, [("ниже порога", "#1f9d63"), ("выше порога", SECOND)])
