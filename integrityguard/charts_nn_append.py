

class NNScoreStream(Chart):
    """Потоковый график P(attack) для последних N сетевых потоков нейросети.

    Каждая точка — один поток; цвет по вердикту (BLOCK=красный, REVIEW=оранжевый, ALLOW=зелёный).
    Горизонтальная пунктирная линия — порог классификатора.
    """

    def __init__(self, capacity=200):
        super().__init__(200)
        self.capacity = capacity
        # список dict: {"score": float, "is_udp": bool, "verdict": "ALLOW"|"REVIEW"|"BLOCK"}
        self.flows: list[dict] = []
        self.threshold: float | None = None
        self._hover_i: int | None = None

    def push_flows(self, flows: list[dict], threshold: float | None = None):
        """Добавить новые потоки (список dict со score/verdict/is_udp); хранить последние capacity."""
        self.flows = (self.flows + [f for f in flows if isinstance(f.get("score"), (int, float))])[-self.capacity:]
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
                QToolTip.showText(e.globalPosition().toPoint(),
                                  f"Поток #{i + 1}{udp_tag}\nP(атака) = {f['score']:.4f}\nВердикт: {f.get('verdict', '?')}",
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
        # порог
        if self.threshold is not None and 0 <= self.threshold <= 1:
            y_thr = r.bottom() - r.height() * self.threshold
            p.setPen(QPen(QColor(ACCENT), 1, Qt.DashLine))
            p.drawLine(QPointF(r.left(), y_thr), QPointF(r.right(), y_thr))
            p.setPen(QColor(ACCENT))
            p.drawText(QRectF(r.right() - 130, y_thr - 16, 126, 14), Qt.AlignRight, f"порог {self.threshold:.4f}")
        # точки потоков
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
        # легенда
        self.legend(p, [("BLOCK", "#e5484d"), ("REVIEW", "#d99a1c"), ("ALLOW", "#1f9d63"), ("UDP-кольцо", UDP_RING)])
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight, f"последние {n} потоков →")


class BenignUDPHistogram(Chart):
    """Гистограмма распределения P(attack) для доброкачественных UDP-потоков.

    Показывает, насколько хорошо модель держит benign-UDP вдали от порога (хвост слева).
    Вертикальная красная линия — порог; зелёная область — потоки ниже порога.
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
        # посчитать бины
        counts = [0] * self.bins
        for s in self.scores:
            bi = min(int(s * self.bins), self.bins - 1)
            counts[bi] += 1
        vmax = max(counts) or 1
        self.y_grid(p, r, vmax, steps=4)
        bw = r.width() / self.bins
        thr_x = r.left() + r.width() * (self.threshold or 0.5)
        for i, cnt in enumerate(counts):
            x = r.left() + bw * i
            h = r.height() * cnt / vmax
            bar = QRectF(x + 1, r.bottom() - h, bw - 2, max(h, 1))
            # зелёный — до порога, оранжевый — после (хвост)
            is_tail = (self.threshold is not None and (i + 1) / self.bins > self.threshold)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(SECOND if is_tail else "#1f9d63"))
            p.drawRoundedRect(bar, 2, 2)
        # линия порога
        if self.threshold is not None:
            p.setPen(QPen(QColor("#e5484d"), 1.5, Qt.DashLine))
            p.drawLine(QPointF(thr_x, r.top()), QPointF(thr_x, r.bottom()))
            p.setPen(QColor("#e5484d"))
            p.drawText(QRectF(thr_x + 4, r.top() + 2, 80, 14), Qt.AlignLeft, f"порог {self.threshold:.4f}")
        # статистика
        above = sum(1 for s in self.scores if self.threshold is not None and s > self.threshold)
        total = len(self.scores)
        pct = above / total * 100 if total else 0
        p.setPen(QColor(MUTED))
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignLeft,
                   f"UDP benign: {total} потоков")
        p.drawText(QRectF(r.left(), r.bottom() + 4, r.width(), 18), Qt.AlignRight,
                   f"выше порога: {above} ({pct:.1f}%)")
        self.legend(p, [("ниже порога", "#1f9d63"), ("выше порога (ложные тревоги)", SECOND)])
