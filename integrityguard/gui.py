"""Графический интерфейс IntegrityGuard (PySide6)."""
from __future__ import annotations

import json
import getpass
import hashlib
import ipaddress
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from collections import deque
from pathlib import Path

from PySide6.QtCore import QDate, QMetaObject, QSettings, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
                               QDateEdit, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QStackedWidget,
                               QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .charts import ACCENT, SECOND, BenignUDPHistogram, GroupBars, HBars, Heatmap, LiveLine, NNScoreStream, ScoreDots, TrainingHistoryChart, VerdictBars
from . import online_learn
from . import recall as R
from .network_telemetry import NetworkTelemetry
from .network_classifier import assess_network_with_classifier
from .paths import APP_ROOT as ROOT, DATA_ROOT as DATA, RESOURCE_ROOT

# Сетевая flow-модель использует опубликованные метки реальных захватов.
# Локальные прогнозы и неизвестные потоки не превращаются в обучающие метки.
NETWORK_CLASSIFIER_CHECKPOINT = DATA / "models" / "candidates" / "network_classifier_candidate.pt"
from .spec import CLASS_LEVEL, CLASS_RU, CLASSES, LEVEL_RU, LEVELS

VERDICT = {"ALLOW": ("ДОПУСК", "#1f9d63"), "REVIEW": ("НА ПРОВЕРКУ", "#d99a1c"), "BLOCK": ("БЛОКИРОВКА", "#e5484d")}
THREAT_SHORT = {"clean": "норма", "dependency": "зависимости", "weights": "веса", "backdoor": "бэкдор",
                "poison": "отравление данных", "label_flip": "подмена меток",
                "adversarial": "состяз. входы", "extraction": "извлечение", "availability": "доступность",
                "reference_required": "нет эталона"}
THREAT_TINY = {"clean": "норма", "dependency": "зависим.", "weights": "веса", "backdoor": "бэкдор",
               "poison": "отравл.", "label_flip": "метки",
               "adversarial": "состяз.", "extraction": "извлеч.", "availability": "доступн.",
               "reference_required": "нет эталона"}
STAGE_RU = {"build": "сборка", "deploy": "поставка", "runtime": "эксплуатация"}
NOTE_COLOR = {"error": "#e5484d", "warn": "#d99a1c", "info": "#2bb7ab", "ok": "#1f9d63"}
RETRAIN_RECALL_THRESHOLD = 0.85  # ниже этой полноты на тестовой выборке — советуем переобучить детектор


def _threat_detail(threat, suspects=None):
    """Текст и подсказка для столбца «Тип угрозы»: вместо короткого слова — полное описание класса
    нарушения (CLASS_RU), а если у события есть локализация (suspects) — во всплывающей подсказке
    перечисляются конкретные подозрительные компоненты пакета, по которым принято решение."""
    text = CLASS_RU.get(threat, THREAT_SHORT.get(threat, str(threat) if threat else "—"))
    tip = ""
    if suspects:
        parts = [f"{_component_ru(s['component'])} ({s['score']:.2f})" for s in suspects[:5]]
        tip = "Подозрительные компоненты: " + ", ".join(parts)
    return text, tip

QSS = """
* { font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", "DejaVu Sans", sans-serif; font-size: 10pt; color: #e9ebef; }
QMainWindow, QWidget#page, QScrollArea, QScrollArea > QWidget > QWidget { background: #0a0c10; }
QWidget#side { background: #0d1016; border-right: 1px solid #1b1f28; }
QLabel#brand { font-size: 15pt; font-weight: 700; color: #f4f6f8; letter-spacing: 0.2px; }
QLabel#sub, QLabel[muted="true"] { color: #8a8f99; }
QLabel#navSection { color: #5c6168; font-size: 8pt; font-weight: 700; letter-spacing: 1.1px; padding: 14px 10px 4px; }
QLabel#h1 { font-size: 18pt; font-weight: 650; color: #f3f5f8; }
QLabel#h2 { font-size: 11.5pt; font-weight: 650; color: #e9ebef; }
QPushButton#nav { text-align: left; min-height: 24px; padding: 9px 13px; border: 1px solid transparent; border-radius: 7px; color: #9aa0ab; background: transparent; }
QPushButton#nav:hover { background: #141820; color: #eef0f3; }
QPushButton#nav:checked { background: #122a28; border-left: 3px solid #2bb7ab; color: #e9ebef; font-weight: 650; padding-left: 11px; }
QPushButton#nav:focus { border-color: #2bb7ab; }
QFrame#card { background: #12151c; border: 1px solid #202531; border-radius: 10px; }
QFrame#tile { background: transparent; border: none; border-bottom: 2px solid #202531; border-radius: 0px; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit { background: #10131a; border: 1px solid #252b38; border-radius: 7px; padding: 8px 10px; selection-background-color: #1c5e57; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus, QDateEdit:focus { border-color: #2bb7ab; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background: #12151c; border: 1px solid #252b38; selection-background-color: #122a28; }
QPushButton { background: #171b24; border: 1px solid #2a3140; border-radius: 7px; padding: 8px 15px; }
QPushButton:hover { background: #1d222d; border-color: #363e4f; }
QPushButton:focus { border-color: #2bb7ab; }
QPushButton:disabled { color: #5c6168; background: #121620; border-color: #1e2330; }
QPushButton#primary { background: #1f9d8f; border-color: #1f9d8f; color: #061211; font-weight: 650; }
QPushButton#primary:hover { background: #27b3a4; border-color: #27b3a4; }
QPushButton#primary:disabled { background: #163733; border-color: #163733; color: #6a8f8a; }
QTableWidget { background: #12151c; border: 1px solid #202531; border-radius: 9px; gridline-color: transparent; alternate-background-color: #151821; selection-background-color: #122a28; }
QTableWidget::item { padding: 7px 8px; border: none; }
QTableWidget::item:selected { background: #17413c; color: #ffffff; }
QHeaderView::section { background: #141720; color: #8a8f99; border: none; border-bottom: 1px solid #242a36; padding: 9px 8px; font-weight: 650; }
QTableCornerButton::section { background: #141720; border: none; }
QPlainTextEdit { background: #0d1016; border: 1px solid #202531; border-radius: 9px; padding: 9px; font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace; font-size: 9pt; }
QProgressBar { background: #10131a; border: 1px solid #202531; border-radius: 6px; height: 12px; text-align: center; font-size: 8pt; }
QProgressBar::chunk { background: #2bb7ab; border-radius: 5px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #262c38; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #323a49; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #262c38; border-radius: 4px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #323a49; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #2e3544; background: #10131a; }
QCheckBox::indicator:checked { background: #2bb7ab; border-color: #2bb7ab; }
QDialog, QMessageBox, QMenu { background-color: #12151c; }
QMenu::item { padding: 8px 26px 8px 12px; }
QMenu::item:selected { background: #122a28; }
QMessageBox QLabel { color: #e9ebef; font-size: 10pt; background: transparent; }
QMessageBox QPushButton { min-width: 84px; }
QFrame#banner { background: #111820; border: none; border-bottom: 1px solid #202531; }
QPushButton#flat { background: transparent; border: none; padding: 5px 10px; color: #8a8f99; }
QPushButton#flat:hover { color: #eef0f3; background: #141820; }
QLabel { background: transparent; }
QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button { width: 18px; border: none; background: transparent; }
QToolTip { background: #171b24; color: #eef0f3; border: 1px solid #2a3140; padding: 5px; }
"""


# ---------------------------------------------------------------- вспомогательные элементы
class Worker(QThread):
    """Фоновая задача: fn(progress) -> результат."""
    done = Signal(object)
    fail = Signal(str)
    progress = Signal(object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn(self.progress.emit))
        except (ValueError, FileNotFoundError, PermissionError) as e:   # ожидаемые ошибки — без трассировки
            self.fail.emit(str(e)[:1].upper() + str(e)[1:])
        except Exception as e:  # noqa: BLE001 — показать пользователю любую ошибку
            traceback.print_exc()
            self.fail.emit(f"{type(e).__name__}: {e}\n\n{traceback.format_exc(limit=3)}")


def label(text="", name=None, muted=False, wrap=False):
    w = QLabel(text)
    if name:
        w.setObjectName(name)
    if muted:
        w.setProperty("muted", True)
    w.setWordWrap(wrap)
    return w


def card(*widgets, title=None):
    f = QFrame(objectName="card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(18, 16, 18, 16)
    lay.setSpacing(10)
    if title:
        lay.addWidget(label(title, "h2"))
    for w in widgets:
        lay.addLayout(w) if not isinstance(w, QWidget) else lay.addWidget(w)
    return f


def tile(name_widget, value_widget, *extra_widgets):
    """Плоская KPI-плитка: без скругления, с нижней цветной линией — отличается от card()
    по силуэту, чтобы числовые метрики не выглядели как обычный контентный блок."""
    f = QFrame(objectName="tile")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(16, 14, 16, 12)
    lay.setSpacing(6)
    lay.addWidget(name_widget)
    lay.addWidget(value_widget)
    for w in extra_widgets:
        lay.addWidget(w)
    return f


def table(headers, stretch=0):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.setSelectionMode(QTableWidget.SingleSelection)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.ResizeToContents)
    h.setSectionResizeMode(stretch, QHeaderView.Stretch)
    h.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return t


def add_row(t, values, color=None, color_col=None, tips=None):
    r = t.rowCount()
    t.insertRow(r)
    for c, v in enumerate(values):
        it = QTableWidgetItem(str(v))
        if color and c == color_col:
            it.setForeground(QColor(color))
            f = it.font()
            f.setBold(True)
            it.setFont(f)
        if tips and tips.get(c):
            it.setToolTip(tips[c])
        t.setItem(r, c, it)


class PathEdit(QWidget):
    """Поле пути с кнопкой «Обзор»."""
    picked = Signal()

    def __init__(self, placeholder, folder=True, filt=""):
        super().__init__()
        self.folder, self.filt = folder, filt
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.edit = QLineEdit(placeholderText=placeholder)
        btn = QPushButton("Обзор…")
        btn.clicked.connect(self.browse)
        lay.addWidget(self.edit, 1)
        lay.addWidget(btn)

    def browse(self):
        start = self.edit.text() or str(DATA if DATA.exists() else ROOT)
        p = QFileDialog.getExistingDirectory(self, "Выберите каталог", start) if self.folder \
            else QFileDialog.getOpenFileName(self, "Выберите файл", start, self.filt)[0]
        if p:
            self.edit.setText(p)
            self.picked.emit()

    def text(self):
        return self.edit.text().strip()

    def setText(self, s):
        self.edit.setText(str(s))


class Page(QScrollArea):
    def __init__(self, title, subtitle):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        body = QWidget(objectName="page")
        self.lay = QVBoxLayout(body)
        self.lay.setContentsMargins(30, 26, 30, 26)
        self.lay.setSpacing(16)
        self.lay.addWidget(label(title, "h1"))
        self.lay.addWidget(label(subtitle, muted=True, wrap=True))
        self.setWidget(body)


# ---------------------------------------------------------------- главное окно
class MainWindow(QMainWindow):
    def __init__(self):
        startup_started = time.perf_counter()
        super().__init__()
        self.setWindowTitle("IntegrityGuard — контроль целостности нейросетевых программ")
        self.resize(1280, 820)
        self.setMinimumSize(900, 600)
        icon = RESOURCE_ROOT / "assets" / "integrityguard.ico"
        self._icon_path = icon
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self.settings = QSettings(str(DATA / "settings.ini"), QSettings.IniFormat)
        self.settings.remove("copilot_model")
        self.settings.remove("network_autoblock_enabled")
        self._guard = None
        self._workers: list[Worker] = []
        self._last_ev: dict | None = None
        self._monitor_latest_identity = None
        self._candidate_busy = False
        self._network_telemetry = NetworkTelemetry()
        self._network_capture_busy = False
        self._network_flow_busy = False
        self._network_flow_telemetry = NetworkTelemetry()
        self._network_capture_next = time.monotonic() + 10
        self._packet_capture_busy = False
        self._packet_capture_next = time.monotonic() + 15
        self._nn_monitor_flows = deque(maxlen=200)
        self._nn_monitor_status = "Ожидание первого захвата Pktmon."
        self._auto_note_text = "Обновляется само при появлении новых событий."

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QWidget(objectName="side")
        side.setFixedWidth(246)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(15, 22, 15, 18)
        sl.setSpacing(5)
        sl.addWidget(label("IntegrityGuard", "brand"))
        sl.addWidget(label("контроль целостности ПНП", "sub"))
        sl.addSpacing(16)
        self.stack = QStackedWidget()
        self.nav = QButtonGroup(self)
        self.banner = QFrame(objectName="banner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(0, 0, 10, 0)
        self.banner_mark = QFrame()
        self.banner_mark.setFixedWidth(5)
        self.banner_text = label("", wrap=True)
        self.banner_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.banner_text.setContentsMargins(14, 10, 8, 10)
        close = QPushButton("Скрыть", objectName="flat")
        close.clicked.connect(self.banner.hide)
        bl.addWidget(self.banner_mark)
        bl.addWidget(self.banner_text, 1)
        bl.addWidget(close, 0, Qt.AlignTop)
        self.banner.hide()
        self.banner_timer = QTimer(self, singleShot=True)
        self.banner_timer.timeout.connect(self.banner.hide)
        # Keep operational pages alive at startup (the incoming-package flow,
        # settings state, and continuous network monitor depend on their widgets).
        # Build analysis/history pages only when the user opens them.
        self._page_factories = [self._page_check, self._page_monitor, self._page_baselines,
                                self._page_events, self._page_recall, self._page_train,
                                self._page_settings, self._page_nn]
        self._page_loaded = set()
        # The live monitor refreshes the event table even when its tab is not
        # selected, so its widgets are also required from the start.
        eager_pages = {0, 1, 3, 6, 7}
        for i, name in enumerate(("Проверка пакета", "Мониторинг", "Эталоны и версии",
                                  "Журнал событий", "Полнота обнаружения", "Обучение и оценка",
                                  "Настройки", "Нейросеть сети")):
            if i in (0, 2, 4, 6, 7):
                section_names = {0: "РАБОЧЕЕ МЕСТО", 2: "УПРАВЛЕНИЕ", 4: "КАЧЕСТВО МОДЕЛИ",
                                 6: "СИСТЕМА", 7: "НЕЙРОСЕТЬ"}
                sl.addWidget(label(section_names[i], "navSection"))
            b = QPushButton(name, objectName="nav", checkable=True)
            b.setCursor(Qt.PointingHandCursor)
            self.nav.addButton(b, i)
            sl.addWidget(b)
            page = self._build_page(i) if i in eager_pages else QWidget()
            self.stack.addWidget(page)
        sl.addStretch(1)
        self.status = label("", "sub", wrap=True)
        sl.addWidget(self.status)
        self.nav.idClicked.connect(self._goto)
        # Start on the operational overview, as in analyst consoles, while preserving
        # the established page IDs used by existing navigation actions.
        self.nav.button(1).setChecked(True)
        self.stack.setCurrentIndex(1)
        right = QWidget(objectName="page")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        rl.addWidget(self.banner)
        rl.addWidget(self.stack, 1)
        root.addWidget(side)
        root.addWidget(right, 1)
        self.setCentralWidget(central)
        self._refresh_status()
        self.net_timer.start(1000)                        # график сети и журнал обновляются всё время работы
        # --- автоматический режим
        self.incoming, self.processed = DATA / "incoming", DATA / "processed"
        self._load_monitor()
        self._seen: dict[str, tuple] = {}                 # каталог -> «подпись» содержимого на прошлом проходе
        self._done: dict[str, tuple] = {}                 # уже обработанные (если не удалось переместить)
        self._auto_busy = False
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self._auto_tick)
        if self.auto_on():
            QTimer.singleShot(300, self._auto_start)
        else:
            self._set_auto_note("Автоматический режим выключен (включается в настройках).")
        self._quitting = False
        self._setup_tray()
        # --- автоочистка устаревших обработанных пакетов во входящих (allow/review/block)
        self.cleanup_timer = QTimer(self)
        self.cleanup_timer.timeout.connect(self._cleanup_processed)
        self.cleanup_timer.start(3600_000)                 # раз в час — сканирование папки не бесплатно
        QTimer.singleShot(5000, self._cleanup_processed)    # и один раз вскоре после запуска
        self._recover_release_if_needed()
        self.candidate_timer = QTimer(self)
        self.candidate_timer.timeout.connect(self._maybe_run_scheduled_candidate)
        self.candidate_timer.start(15 * 60_000)
        QTimer.singleShot(60_000, self._maybe_run_scheduled_candidate)
        print(f"[startup] MainWindow initialized in {(time.perf_counter() - startup_started) * 1000:.0f} ms",
              file=sys.stderr)

    # ------------------------------------------------------------ значок в трее (фоновая работа)
    def _setup_tray(self):
        """Значок в трее: программа продолжает проверять входящие пакеты и при закрытом окне."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = None
            return
        ic = QIcon(str(self._icon_path)) if self._icon_path.exists() else self.windowIcon()
        self.tray = QSystemTrayIcon(ic, self)
        self.tray.setToolTip("IntegrityGuard — контроль целостности ПНП")
        menu = QMenu()
        act_open = QAction("Открыть окно", self)
        act_open.triggered.connect(self._tray_open)
        self._tray_auto = QAction("Автоматический режим", self, checkable=True)
        self._tray_auto.setChecked(self.auto_on())
        self._tray_auto.triggered.connect(self._tray_toggle_auto)
        act_quit = QAction("Выход", self)
        act_quit.triggered.connect(self._tray_quit)
        menu.addAction(act_open)
        menu.addAction(self._tray_auto)
        menu.addSeparator()
        menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: self._tray_open() if reason == QSystemTrayIcon.Trigger else None)
        self.tray.show()

    def _tray_open(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_toggle_auto(self, checked):
        if hasattr(self, "s_auto"):
            self.s_auto.setChecked(checked)
            self._save_settings()
        else:
            self.settings.setValue("auto", "true" if checked else "false")
            self.settings.sync()

    def _tray_quit(self):
        self._quitting = True
        self._exit_cancelled = False
        self.close()
        if self._exit_cancelled:                      # не закрываемся молча: сообщаем, почему выход отменён
            self.notify("Выход отменён: фоновая задача продолжается.", "info")

    def notify(self, text, kind="error"):
        """Сообщение пользователю — полосой над страницей, без всплывающих окон."""
        text = str(text).strip()
        if kind == "error":
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "ошибка:", text, flush=True)
            text = text.split("\n\nTraceback")[0]
        self.banner_mark.setStyleSheet(f"background: {NOTE_COLOR.get(kind, NOTE_COLOR['info'])};")
        self.banner_text.setText(text)
        self.banner.show()
        self.banner_timer.stop()
        if kind != "error":
            self.banner_timer.start(12000)

    # ------------------------------------------------------------ автоматический режим
    def auto_on(self) -> bool:
        return str(self.settings.value("auto", "true")).lower() != "false"

    def _auto_start(self):
        """При запуске: всё, что нужно для работы, готовится без участия пользователя."""
        try:
            self.incoming.mkdir(parents=True, exist_ok=True)
            hint = self.incoming / "КАК ПОЛЬЗОВАТЬСЯ.txt"
            if not hint.exists():
                hint.write_text("Скопируйте сюда каталог пакета (manifest.json и model.pt) или реальный PyPI wheel (*.whl).\n"
                                "IntegrityGuard проверит его сам и переложит в data/processed/<вердикт>/.\n"
                                "Без доверенного эталона сравнительная оценка не выполняется; пакет остаётся на проверке.\n"
                                "Эталон регистрируется отдельно на вкладке «Эталоны и версии».\n", encoding="utf-8-sig")
        except OSError as e:
            self.notify(f"Не удалось создать папку входящих пакетов {self.incoming}: {e}")
        self.auto_timer.start(3000)
        self._auto_status()
        from .intake import recover_archived
        recovery = self.run_bg(lambda _: recover_archived(self.incoming, self.processed),
                               lambda _: None, silent=True)
        recovery.finished.connect(self._auto_prepare)

    def _auto_prepare(self):
        """Finish startup recovery without injecting synthetic demo data into the operational registry."""
        model_ready = Path(self.cfg("model")).is_file()
        status = ("Экспериментальный детектор загружен; его качество на реальных пакетах не подтверждено. "
                  "Синтетические демонстрации не запускаются автоматически. "
                  "Пакеты без доверенного эталона будут зарегистрированы без числовой оценки."
                  if model_ready else
                  "Файл модели не найден. Автоматическое синтетическое обучение отключено; "
                  "для сравнения нужен проверенный детектор и зарегистрированный эталон.")
        self._auto_status(status)
        self._refresh_status()

    def _page_index(self, name):
        return [b.text() for b in self.nav.buttons()].index(name)

    def _build_page(self, index):
        started = time.perf_counter()
        page = self._page_factories[index]()
        self._page_loaded.add(index)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if elapsed_ms >= 100:
            print(f"[startup] page {index} built in {elapsed_ms:.0f} ms", file=sys.stderr)
        return page

    def _auto_status(self, last=""):
        self._set_auto_note(f"Автоматический режим включён. Папка входящих пакетов: {self.incoming}"
                            + (f"\n{last}" if last else ""))

    def _set_auto_note(self, text):
        self._auto_note_text = text
        if hasattr(self, "e_auto_note"):
            self.e_auto_note.setText(text)

    def _auto_tick(self):
        """Наблюдение за папкой входящих: новый пакет проверяется, как только его копирование завершилось."""
        if self._auto_busy or self._workers or not self.incoming.exists():
            return
        try:
            candidates = sorted(p for p in self.incoming.iterdir()
                                if p.is_dir() or (p.is_file() and p.suffix.lower() == ".whl"))
        except OSError:
            return
        for d in candidates:
            try:
                if d.is_file():
                    st = d.stat()
                    sig = (1, st.st_size, st.st_mtime_ns)
                else:
                    stats = [f.stat() for f in d.rglob("*") if f.is_file()]
                    sig = (len(stats), sum(s.st_size for s in stats), max((s.st_mtime_ns for s in stats), default=0))
            except OSError:
                self._seen.pop(str(d), None)
                continue
            prev = self._seen.get(str(d))
            self._seen[str(d)] = sig
            is_package = (d.suffix.lower() == ".whl") if d.is_file() else (d / "manifest.json").is_file()
            if prev != sig or not is_package or self._done.get(str(d)) == sig:
                continue                                  # ещё копируется, не пакет или уже обработан
            self._auto_busy = True
            self._done[str(d)] = sig

            # показываем прогресс-карточку мониторинга
            pkg_name = d.stem if d.is_file() else d.name
            self._mon_log_lines = []
            if hasattr(self, "_mon_progress_card"):
                self._mon_progress_bar.setValue(5)
                self._mon_progress_pkg.setText(f"⏳ {pkg_name}")
                self._mon_progress_log.setText("⏳ Инициализация…")
                self._mon_progress_card.setVisible(True)

            def _on_progress(step, text, _d=d):
                self._mon_log_lines.append(text)
                QMetaObject.invokeMethod(self, "_update_mon_log", Qt.QueuedConnection)

            w = self.run_bg(lambda _, d=d, cb=_on_progress: self._auto_process(d, progress_cb=cb),
                            self._auto_done, silent=True)
            w.fail.connect(lambda _, path=str(d): self._done.pop(path, None))
            w.finished.connect(lambda: setattr(self, "_auto_busy", False))
            return

    def _auto_process(self, d: Path, progress_cb=None) -> dict:
        from .intake import process_incoming
        analyze = (lambda path: self._analyze_incoming(path, progress_cb=progress_cb)) if progress_cb else self._analyze_incoming
        return process_incoming(d, self.processed, analyze, self._publish_incoming)

    def _publish_incoming(self, result):
        if "verdict" in result:
            if str(result.get("analysis_mode", "")).startswith("wheel_"):
                from .wheel_scan import persist_wheel_event
                persist_wheel_event(result, Path(self.cfg("registry")))
            else:
                self.guard().respond(result)

    def _analyze_incoming(self, d: Path, progress_cb=None):
        """Проверить входящий пакет против доверенного эталона или осторожно оценить без него."""
        if d.is_file() and d.suffix.lower() == ".whl":
            from .wheel_scan import assess_wheel
            event = assess_wheel(d, Path(self.cfg("registry")))
            return event, event["verdict"].lower()
        from .collect import load_package
        g = self.guard()
        try:
            spec = load_package(d, g.key)
            if not (g._base(spec.name) / "package").exists():
                res = g.assess_unbaselined(d, "deploy")
                dest = res["verdict"].lower()
            else:
                res = g.check(d, "deploy", self._index_for(d), progress_cb=progress_cb)
                res = self._apply_policy(res)
                dest = res["verdict"].lower()
        except (ValueError, OSError) as e:
            res = g.assessment_error(d, e, "deploy")
            res["auto"] = "error"
            dest = "error"
            return res, dest
        if dest in ("review", "block"):
            try:
                res.setdefault("event_id", uuid.uuid4().hex)
                res.setdefault("model_sha256", g.model_sha256)
                feats = g.extract_features(d, self._index_for(d))
                if feats is not None:
                    online_learn.maybe_queue(DATA, res, feats,
                                             evidence_db=g.registry / "evidence.sqlite")
            except Exception:
                pass                                       # аудит-выборка — вспомогательная функция, не должна мешать основной проверке
        return res, dest

    def _cleanup_processed(self):
        """Автоочистка: обработанные пакеты (allow/review/block) во входящих не копятся вечно —
        устаревшие по сроку хранения удаляются сами, без участия пользователя. Срок задаётся в
        настройках («Хранить обработанные пакеты»); 0 — автоочистка выключена."""
        if self._workers:                                 # не мешаем текущей фоновой задаче — попробуем на следующем проходе
            return
        try:
            days = int(self.settings.value("processed_retention_days", 30))
        except (TypeError, ValueError):
            days = 30
        if days <= 0 or not self.processed.exists():
            return

        def job(_):
            cutoff = time.time() - days * 86400
            removed = 0
            for verdict_dir in self.processed.iterdir():
                if not verdict_dir.is_dir():
                    continue
                for pkg_dir in verdict_dir.iterdir():
                    try:
                        if pkg_dir.is_dir() and pkg_dir.stat().st_mtime < cutoff:
                            shutil.rmtree(pkg_dir, ignore_errors=True)
                            removed += 1
                        elif pkg_dir.is_file() and pkg_dir.suffix.lower() == ".whl" \
                                and pkg_dir.stat().st_mtime < cutoff:
                            pkg_dir.unlink(missing_ok=True)
                            removed += 1
                    except OSError:
                        continue
            return removed

        def done(removed):
            if removed:
                self._auto_status(f"Автоочистка: удалено устаревших обработанных пакетов — {removed} "
                                  f"(старше {days} дн.).")

        self.run_bg(job, done, silent=True)

    @Slot()
    def _update_mon_log(self):
        """Обновить прогресс-карточку мониторинга из фонового потока (через QueuedConnection)."""
        lines = getattr(self, "_mon_log_lines", [])
        total_steps = 6
        step = len(lines)
        pct = min(10 + int(step / total_steps * 85), 95)
        if hasattr(self, "_mon_progress_bar"):
            self._mon_progress_bar.setValue(pct)
        icons = {1: "📦", 2: "🔍", 3: "📋", 4: "🔬", 5: "⚖️", 6: "🧠"}
        log_html = "<br>".join(
            f"<span style='color:#8a8f99'>{icons.get(i + 1, '•')}</span> {ln}"
            for i, ln in enumerate(lines)
        )
        if hasattr(self, "_mon_progress_log"):
            self._mon_progress_log.setText(log_html or "⏳ Инициализация…")

    def _auto_done(self, res: dict):
        if res.get("incoming_path") and not res.get("moved_to"):
            path = res["incoming_path"]
            retry_after = max(0, int(res.get("retry_after", 0) or 0))
            if retry_after:
                self._done[path] = self._seen.get(path)
                QTimer.singleShot(retry_after * 1000, lambda path=path: self._retry_incoming(path))
            else:
                self._done.pop(path, None)
        if res.get("auto") == "baseline":
            last = (f"Последнее событие: пакет «{res['package']}» {res['version']} встречен впервые и зарегистрирован как эталон"
                    + ("" if res["control"] else " (без контрольного набора — поведенческий уровень не проверяется)") + ".")
        elif res.get("verdict") in VERDICT:
            self._show_event(res)
            if res.get("analysis_mode") == "reference_missing":
                last = f"Пакет «{res['package']}» обработан; эталон не найден, числовая оценка не выполнялась."
            elif res.get("analysis_mode") == "intake_validation_error":
                last = f"Последнее событие: «{res['package']}» отправлен в error — оценка не завершена."
            else:
                last = (f"Последнее событие: «{res['package']}» {res['version']} — "
                        f"{VERDICT[res['verdict']][0].lower()}, {res['threat_ru']}.")
        elif res.get("auto") == "error":
            last = f"Последнее событие: «{res['package']}» не обработан — {res['error']}"
        if res.get("retry_after"):
            last += (f" Перенос не завершён: {res.get('move_error', 'ошибка доступа')}. "
                     f"Задание сохранено; повтор через {res['retry_after']} с.")
        self._auto_status(last)
        self._refresh_status()
        # завершаем прогресс-карточку мониторинга
        if hasattr(self, "_mon_progress_bar"):
            self._mon_progress_bar.setValue(100)
            QTimer.singleShot(3000, lambda: (
                self._mon_progress_card.setVisible(False)
                if hasattr(self, "_mon_progress_card") else None
            ))
        self._refresh_views()

    def _retry_incoming(self, path):
        """Wake a persisted intake retry when its backoff expires."""
        self._done.pop(path, None)
        self._auto_tick()

    def _refresh_views(self):
        name = self.nav.button(self.stack.currentIndex()).text()
        if name == "Мониторинг":
            self._load_monitor()
        elif name == "Эталоны и версии":
            self._load_baselines()
        elif name == "Журнал событий":
            self._load_events()

    # ------------------------------------------------------------ настройки и ядро
    def cfg(self, key):
        defaults = {"registry": DATA / "registry", "model": RESOURCE_ROOT / "models" / "detector.pt", "key": ""}
        v = str(self.settings.value(key, "") or "").strip()
        try:
            if key in ("registry", "model", "key") and v:
                configured = Path(v).expanduser()
                if not configured.is_absolute():
                    if key == "registry":
                        parts = configured.parts
                        if parts and parts[0].lower() == "data":
                            configured = Path(*parts[1:])
                        configured = DATA / configured
                    else:
                        configured = RESOURCE_ROOT / configured
                v = str(configured.resolve())
            if key == "model" and not (v and Path(v).is_file()):
                v = ""                                    # сохранённый детектор пропал — берётся поставляемый
            elif key == "key" and not (v and Path(v).is_file() and Path(v).stat().st_size >= 8
                                       and Path(v).suffix.lower() not in (".log", ".ini", ".json", ".pt")):
                return ""                                 # файл ключа не найден или это заведомо не ключ
        except OSError:
            v = ""
        return v or str(defaults[key])

    def guard(self):
        """Ядро системы защиты (загружается при первом обращении)."""
        if self._guard is None:
            from .system import IntegrityGuard
            model = Path(self.cfg("model"))
            if not model.exists():
                raise FileNotFoundError(f"Файл модели детектора не найден: {model}\nОбучите детектор на вкладке «Обучение и оценка».")
            key = Path(self.cfg("key")).read_bytes().strip() if self.cfg("key") else None
            self._guard = IntegrityGuard(self.cfg("registry"), model, key)
        return self._guard

    def _refresh_status(self):
        ok = Path(self.cfg("model")).exists()
        n = len(self._baseline_names())
        self.status.setText(f"Детектор: {'загружен; качество на реальных данных не подтверждено' if ok else 'не обучен'}\n"
                            f"Эталонов в реестре: {n}\n"
                            f"Авторежим: {'включён' if self.auto_on() else 'выключен'}")

    def _baseline_names(self):
        d = Path(self.cfg("registry")) / "baselines"
        try:
            return sorted(p.name for p in d.iterdir() if (p / "package").exists()) if d.exists() else []
        except OSError:
            return []

    def _goto(self, i):
        if i not in self._page_loaded:
            previous = self.stack.widget(i)
            page = self._build_page(i)
            self.stack.removeWidget(previous)
            previous.deleteLater()
            self.stack.insertWidget(i, page)
        self.stack.setCurrentIndex(i)
        name = self.nav.button(i).text()
        if name == "Мониторинг":
            self._load_monitor()
        elif name == "Эталоны и версии":
            self._load_baselines()
        elif name == "Журнал событий":
            self._load_events()
        elif name == "Полнота обнаружения":
            self._load_recall()

    def closeEvent(self, e):
        # Закрытие окна крестиком и команда «Выход» в трее завершают приложение.
        # Не оставляем скрытый фоновый процесс после того, как пользователь закрыл окно.
        if not self._confirm_exit_with_background_work():
            self._exit_cancelled = True
            return e.ignore()
        self._exit_cancelled = False
        self.shutdown_background()
        e.accept()

    def _confirm_exit_with_background_work(self) -> bool:
        if not any(w.isRunning() for w in self._workers):
            return True
        box = QMessageBox(QMessageBox.Question, "IntegrityGuard", "Идёт фоновая задача (проверка или обучение). "
                          "Прервать её и закрыть программу?", QMessageBox.Yes | QMessageBox.No, self)
        box.button(QMessageBox.Yes).setText("Прервать и закрыть")
        box.button(QMessageBox.No).setText("Не закрывать")
        return box.exec() == QMessageBox.Yes

    def shutdown_background(self, grace_ms: int = 8000):
        """Cancel background work and end this app's capture processes. Safe to call twice.

        1. Set the capture stop flag; running captures stop their own Pktmon session.
        2. Wait up to grace_ms for workers; terminate only those still running after that.
        3. Stop a Pktmon session only if its owner marker names this process.
        4. End the elevated helper tree started by this app (best effort; see stop_elevated_helper).
        """
        if getattr(self, "_shutdown_done", False):
            return
        self._shutdown_done = True
        from .pktmon_capture import request_capture_stop, stop_own_capture_session
        from .pktmon_segment import stop_elevated_helper
        request_capture_stop()
        busy = [w for w in self._workers if w.isRunning()]
        deadline = time.monotonic() + grace_ms / 1000
        for w in busy:
            w.wait(max(0, int((deadline - time.monotonic()) * 1000)))
        for w in busy:
            if w.isRunning():
                w.terminate()
                w.wait(2000)
        stopped, reason = stop_own_capture_session()
        if not stopped:
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "выход:", reason, flush=True)
        for note in stop_elevated_helper():
            print(time.strftime("%Y-%m-%d %H:%M:%S"), "выход:", note, flush=True)

    def _read_events(self):
        f = Path(self.cfg("registry")) / "events.jsonl"
        out = []
        try:
            lines = f.read_text(encoding="utf-8-sig", errors="replace").splitlines() if f.exists() else []
        except OSError:
            lines = []                                    # журнал занят другой программой — прочтём в следующий раз
        for line in lines:
            try:
                ev = json.loads(line)
                if isinstance(ev, dict) and ev.get("verdict") in VERDICT and "time" in ev \
                        and (isinstance(ev.get("score"), (int, float)) or
                             ev.get("analysis_mode") in {"reference_missing", "intake_validation_error",
                                                         "wheel_static", "wheel_validation_error"}):
                    out.append(ev)
            except json.JSONDecodeError:
                continue                                  # повреждённая строка журнала пропускается
        return out

    # ------------------------------------------------------------ страница «Мониторинг»
    def _page_monitor(self):
        p = Page("Мониторинг", "Поток пакетов, поступающих на проверку, и сетевая активность компьютера. "
                               "Страница обновляется сама.")
        self.mon_state = label("", muted=True, wrap=True)
        self.mon_state.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.lay.addWidget(card(self.mon_state))
        self.mon_refresh = label("Обновление данных мониторинга ожидается…", muted=True)
        p.lay.addWidget(self.mon_refresh)

        # --- прогресс автоматической проверки входящего пакета ---
        self._mon_progress_bar = QProgressBar()
        self._mon_progress_bar.setRange(0, 100)
        self._mon_progress_bar.setValue(0)
        self._mon_progress_bar.setTextVisible(False)
        self._mon_progress_bar.setFixedHeight(6)
        self._mon_progress_bar.setStyleSheet(
            "QProgressBar { background: #1e2229; border-radius: 3px; }"
            "QProgressBar::chunk { background: #2bb7ab; border-radius: 3px; }")
        self._mon_progress_pkg = label("", wrap=False)
        self._mon_progress_pkg.setStyleSheet("font-weight: 600;")
        self._mon_progress_log = label("", wrap=True, muted=True)
        self._mon_progress_log.setTextFormat(Qt.RichText)
        self._mon_progress_card = card(self._mon_progress_bar, self._mon_progress_pkg,
                                       self._mon_progress_log, title="Проверка входящего пакета")
        self._mon_progress_card.setVisible(False)
        p.lay.addWidget(self._mon_progress_card)

        tiles = QGridLayout()
        tiles.setHorizontalSpacing(12)
        tiles.setVerticalSpacing(12)
        self.tiles = {}
        for key, name, color in (("total", "Проверено пакетов", "#e6e9ef"), ("ALLOW", "Допущено", VERDICT["ALLOW"][1]),
                                 ("REVIEW", "На проверку", VERDICT["REVIEW"][1]), ("BLOCK", "Заблокировано", VERDICT["BLOCK"][1]),
                                 ("queue", "Ждут во входящих", "#e6e9ef")):
            val = label("0")
            val.setStyleSheet(f"font-size: 21pt; font-weight: 650; color: {color};")
            val.setMinimumHeight(34)
            self.tiles[key] = val
            t = tile(label(name, muted=True, wrap=True), val)
            t.setMinimumWidth(0)
            tile_index = len(self.tiles) - 1
            tiles.addWidget(t, tile_index // 3, tile_index % 3)
        for column in range(3):
            tiles.setColumnStretch(column, 1)
        p.lay.addLayout(tiles)
        self.ch_flow, self.ch_score, self.ch_threat = VerdictBars(), ScoreDots(), HBars()
        self.ch_flow.empty_text = self.ch_threat.empty_text = \
            "Проверок пока не было. График появится после первой проверки пакета."
        self.ch_score.empty_text = "Числовых сравнительных оценок пока нет. Для них нужен доверенный эталон."
        p.lay.addWidget(card(self.ch_flow, title="Входящие пакеты: число проверок по времени"))
        row = QHBoxLayout()
        row.setSpacing(14)
        row.addWidget(card(self.ch_score, title="Оценка нарушения по пакетам"), 3)
        row.addWidget(card(self.ch_threat, title="Типы угроз по детектору"), 2)
        p.lay.addLayout(row)
        self.mon_table = table(["Время", "Пакет", "Версия", "Стадия", "Вердикт", "Тип угрозы", "Оценка"], 1)
        self.mon_table.setMinimumHeight(250)
        p.lay.addWidget(card(self.mon_table, title="Последние проверки"))

        self.audit_note = label("", muted=True, wrap=True)
        self.audit_table = table(["Время", "Пакет", "Вердикт", "Тип угрозы", "Оценка"], 1)
        self.audit_table.setMinimumHeight(160)
        attack_btn = QPushButton("Разметить: угроза")
        attack_btn.clicked.connect(lambda: self._audit_confirm(True))
        clean_btn = QPushButton("Разметить: ложное срабатывание")
        clean_btn.clicked.connect(lambda: self._audit_confirm(False))
        audit_btns = QHBoxLayout()
        audit_btns.addWidget(attack_btn)
        audit_btns.addWidget(clean_btn)
        audit_btns.addStretch(1)
        p.lay.addWidget(card(self.audit_note, self.audit_table, audit_btns,
                             title="Самообучение: аудит карантина (нужно подтверждение человека)"))

        self.ch_net = LiveLine("пак./с")
        self.ch_net.empty_text = "Идёт сбор данных о сети…"
        self.ch_net_out = LiveLine("пак./с")
        self.ch_net_out.empty_text = "Идёт сбор данных о сети…"
        net_pkt_row = QHBoxLayout()
        net_pkt_row.addWidget(card(self.ch_net, title="Входящие пакеты"), 1)
        net_pkt_row.addWidget(card(self.ch_net_out, title="Исходящие пакеты"), 1)
        p.lay.addLayout(net_pkt_row)
        self.ch_net_kb_in = LiveLine("КБ/с")
        self.ch_net_kb_in.empty_text = "Идёт сбор данных о сети…"
        self.ch_net_kb_out = LiveLine("КБ/с")
        self.ch_net_kb_out.empty_text = "Идёт сбор данных о сети…"
        net_kb_row = QHBoxLayout()
        net_kb_row.addWidget(card(self.ch_net_kb_in, title="Входящий трафик"), 1)
        net_kb_row.addWidget(card(self.ch_net_kb_out, title="Исходящий трафик"), 1)
        p.lay.addLayout(net_kb_row)
        self.net_note = label("", muted=True)
        self.net_card = card(self.net_note, title="Сетевая активность")
        p.lay.addWidget(self.net_card)
        self.net_capture_note = label(
            "Сетевые счётчики и метаданные соединений собираются автоматически, пока открыта программа. "
            "Полезная нагрузка пакетов не захватывается; сохранение снимка не блокирует трафик.",
            muted=True, wrap=True)
        self.net_capture_note.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.lay.addWidget(card(self.net_capture_note, title="Сбор сетевых наблюдений"))
        self._network_baseline_path = DATA / "online" / "network_behavior_baseline.json"
        from .network_behavior_baseline import load_profile
        self._network_baseline_profile = load_profile(self._network_baseline_path)
        now_utc = datetime.now(timezone.utc)
        self.baseline_start = QLineEdit((now_utc - timedelta(minutes=20)).replace(
            second=0, microsecond=0).isoformat(timespec="seconds"))
        self.baseline_start.setPlaceholderText("Начало UTC: 2026-11-24T08:00:00+00:00")
        self.baseline_end = QLineEdit(now_utc.replace(second=0, microsecond=0).isoformat(timespec="seconds"))
        self.baseline_end.setPlaceholderText("Конец UTC: 2026-11-24T08:20:00+00:00")
        self._baseline_window_auto = True
        self.baseline_start.textEdited.connect(self._freeze_network_baseline_window)
        self.baseline_end.textEdited.connect(self._freeze_network_baseline_window)
        self.baseline_confirm = QCheckBox(
            "Я выбрал этот интервал как локальную точку сравнения; безопасность трафика не подтверждена")
        self.baseline_button = QPushButton("Сформировать профиль поведения")
        self.baseline_button.setObjectName("primary")
        self.baseline_button.clicked.connect(self._create_network_baseline)
        self.baseline_status = label("", muted=True, wrap=True)
        self.baseline_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.baseline_progress = QProgressBar()
        self.baseline_progress.setRange(0, 100)
        self.baseline_progress.setValue(0)
        self.baseline_progress.setFormat("Проверка журнала: %p%")
        self.baseline_progress.setVisible(False)
        self.baseline_readiness = QProgressBar()
        self.baseline_readiness.setRange(0, 30)
        self.baseline_readiness.setValue(0)
        self.baseline_readiness.setFormat("%v / 30 записей в интервале · полнота не проверена")
        self.baseline_readiness_note = label("", muted=True, wrap=True)
        self.baseline_start.editingFinished.connect(self._refresh_network_baseline_readiness)
        self.baseline_end.editingFinished.connect(self._refresh_network_baseline_readiness)
        baseline_times = QHBoxLayout()
        baseline_times.addWidget(label("Начало (UTC)", muted=True))
        baseline_times.addWidget(self.baseline_start, 1)
        baseline_times.addWidget(label("Конец (UTC)", muted=True))
        baseline_times.addWidget(self.baseline_end, 1)
        self._render_network_baseline_status()
        p.lay.addWidget(card(baseline_times, self.baseline_confirm, self.baseline_button,
                             self.baseline_readiness, self.baseline_readiness_note, self.baseline_progress,
                             self.baseline_status,
                             title="Эталон поведения этой сети · только справочные отклонения"))
        self._refresh_network_baseline_readiness()
        self.net_flow_note = label(
            "Собственная модель анализирует текущие сокеты во время работы приложения. "
            "Проверка обновляется примерно раз в секунду. Модель формирует рекомендацию, не меняя Firewall.",
            muted=True, wrap=True)
        p.lay.addWidget(card(self.net_flow_note, title="Непрерывный мониторинг сокетов собственной моделью"))
        self.packet_flow_note = label(
            "Захват заголовков Pktmon не выполнялся. При повышенных правах программа собирает "
            "короткие сегменты раз в минуту; исходный захват удаляется после расчёта агрегатов. "
            "Экспериментальная модель не блокирует трафик.", muted=True, wrap=True)
        p.lay.addWidget(card(self.packet_flow_note,
                             title="Мониторинг потоков по заголовкам пакетов (экспериментальный сенсор)"))

        self.firewall_ip = QLineEdit()
        self.firewall_ip.setPlaceholderText("Удалённый IPv4 или IPv6")
        self.firewall_status = label("Действие подтверждает оператор.", wrap=True)
        firewall_row = QHBoxLayout()
        firewall_row.addWidget(self.firewall_ip, 1)
        self.firewall_buttons = []
        for action, title in (("Block", "Заблокировать IP"), ("Unblock", "Снять блокировку")):
            button = QPushButton(title)
            button.clicked.connect(lambda checked=False, value=action: self._change_network_block(value))
            self.firewall_buttons.append(button)
            firewall_row.addWidget(button)
        p.lay.addWidget(card(firewall_row, self.firewall_status, title="Windows Firewall"))
        p.lay.addStretch(1)
        self.net_timer = QTimer(self)
        self.net_timer.timeout.connect(self._net_tick)
        self._net_prev = None
        self._mon_sig = None
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            self._psutil = None
            self.ch_net.empty_text = "Для графика сети нужна библиотека psutil — запустите install.bat ещё раз."
        return p

    def _queue(self) -> int:
        """Сколько пакетов лежит в папке входящих и ещё не обработано."""
        try:
            return sum(1 for d in self.incoming.iterdir()
                       if (d.is_dir() and (d / "manifest.json").is_file())
                       or (d.is_file() and d.suffix.lower() == ".whl"))
        except (OSError, AttributeError):
            return 0

    def _load_monitor(self):
        evs = self._read_events()
        latest_identity = ((evs[-1].get("time"), evs[-1].get("package"), evs[-1].get("version"))
                           if evs else None)
        if latest_identity != self._monitor_latest_identity:
            previous_latest = self._monitor_latest_identity
            self._monitor_latest_identity = latest_identity
            follows_latest = (self._last_ev is None or
                              (previous_latest is not None and
                               (self._last_ev.get("time"), self._last_ev.get("package"),
                                self._last_ev.get("version")) == previous_latest))
            if evs and follows_latest:
                self._show_event(evs[-1], external_refresh=True)
        self.tiles["total"].setText(str(len(evs)))
        for key in ("ALLOW", "REVIEW", "BLOCK"):
            self.tiles[key].setText(str(sum(e["verdict"] == key for e in evs)))
        self.tiles["queue"].setText(str(self._queue()))
        self.ch_flow.set_events(evs)
        self.ch_score.set_events(evs)
        threat_rows = [(THREAT_SHORT[c], sum(e.get("threat") == c for e in evs)) for c in CLASSES]
        threat_rows.append((THREAT_SHORT["reference_required"], sum(e.get("threat") == "reference_required" for e in evs)))
        self.ch_threat.set_rows(threat_rows)
        self.mon_table.setSortingEnabled(False)           # на время перестройки — иначе Qt путает порядок вставки
        self.mon_table.setRowCount(0)
        for ev in evs[-12:][::-1]:
            text, color = VERDICT[ev["verdict"]]
            threat_text, threat_tip = _threat_detail(ev.get("threat"), ev.get("suspects"))
            add_row(self.mon_table, [_when(ev["time"]), ev.get("package", ""), ev.get("version", ""),
                                     STAGE_RU.get(ev.get("stage"), ev.get("stage", "")), text, threat_text,
                                     _num(ev.get("score"))],
                    color, 4, tips={5: threat_tip})
        self.mon_table.setSortingEnabled(True)             # удобно сортировать по столбцу кликом на заголовок
        mode = (f"Автоматический режим включён: пакеты из папки {getattr(self, 'incoming', '')} проверяются сами."
                if self.auto_on() else "Автоматический режим выключен: проверки запускаются вручную, "
                                      "счётчики изменятся после следующей проверки.")
        last = f" Последняя проверка: {_when(evs[-1]['time'])}." if evs else " Проверок ещё не было."
        self.mon_state.setText(mode + last + f" Обновление панели: {time.strftime('%H:%M:%S')}.")
        self._load_audit()

    def _monitor_signature(self):
        registry = Path(self.cfg("registry")) / "events.jsonl"
        try:
            stat = registry.stat()
            event_signature = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            event_signature = (None, None)

        incoming = getattr(self, "incoming", DATA / "incoming")
        queue_signature = []
        try:
            for entry in sorted(incoming.iterdir(), key=lambda item: item.name.lower()):
                try:
                    item_stat = entry.stat()
                    item_signature = [entry.name, entry.is_dir(), item_stat.st_mtime_ns, item_stat.st_size]
                    if entry.is_dir():
                        manifest = entry / "manifest.json"
                        manifest_stat = manifest.stat()
                        item_signature.extend((manifest_stat.st_mtime_ns, manifest_stat.st_size))
                    queue_signature.append(tuple(item_signature))
                except OSError:
                    queue_signature.append((entry.name, "unavailable"))
        except OSError:
            pass
        return event_signature, tuple(queue_signature)

    def _load_audit(self):
        """Карантинные пакеты, случайно отобранные на аудит человеком (см. online_learn.AUDIT_RATE),
        и сколько уже подтверждённых образцов ждут дообучения."""
        pending = online_learn.list_pending(DATA)
        self.audit_table.setSortingEnabled(False)
        self.audit_table.setRowCount(0)
        for item in pending[:20]:
            text, color = VERDICT.get(item.get("verdict", ""), ("?", "#e6e9ef"))
            add_row(self.audit_table, [_when(item["time"]), item.get("package", ""), text,
                                       item.get("threat_ru", ""), _num(item.get("score"))],
                    color, 2)
            self.audit_table.item(self.audit_table.rowCount() - 1, 0).setData(Qt.UserRole, item["id"])
        self.audit_table.setSortingEnabled(True)
        confirmed_n = online_learn.confirmed_count(DATA)
        self.audit_note.setText(
            f"Ждут подтверждения: {len(pending)}. Подтверждённых образцов для дообучения: {confirmed_n}. "
            "Для учебной метки нужны документ, обоснование и согласованные решения двух учётных записей. "
            "Карантинные пакеты случайно отбираются на аудит. Подтверждённые примеры создают отдельного "
            "кандидата по расписанию: минимум 20 примеров, не менее 5 на каждый бинарный класс, "
            "не чаще раза в сутки; обучение ограничено 500 примерами и 3 эпохами, "
            "использует отдельный процесс, до 4 CPU-потоков и доступную CUDA. "
            "Рабочая модель не меняется до независимой оценки.")

    def _audit_confirm(self, is_attack: bool):
        row = self.audit_table.currentRow()
        if row < 0:
            self.notify("Сначала выберите строку в таблице аудита.", "error")
            return
        item_id = self.audit_table.item(row, 0).data(Qt.UserRole)
        if not item_id:
            return
        evidence_path, _ = QFileDialog.getOpenFileName(self, "Выберите документ, подтверждающий метку")
        if not evidence_path:
            return
        rationale, accepted = QInputDialog.getMultiLineText(
            self, "Обоснование разметки", "Какие факты связывают документ, пакет и выбранную метку? Требуется проверка второй учётной записью.")
        if not accepted:
            return
        try:
            result = online_learn.confirm(DATA, item_id, is_attack, evidence_path=evidence_path, rationale=rationale)
            if result and result.get("review_status"):
                self.notify("Решение сохранено. Нужна согласованная независимая проверка; в обучение пример не добавлен.", "info")
        except (ValueError, OSError) as error:
            self.notify(str(error), "error")
            return
        self._load_audit()
        self._maybe_run_scheduled_candidate()

    def _maybe_run_scheduled_candidate(self):
        """Check persisted cadence and evidence balance; start at most one bounded worker."""
        if self._candidate_busy or self._workers:
            return
        state = online_learn.claim_candidate_schedule(DATA)
        if not state.get("claimed"):
            return
        self._candidate_busy = True

        def done(message):
            if message:
                self.notify(message, "info")
            self._load_audit()
            self._refresh_candidate_options()

        worker = self.run_bg(self._finetune_online, done, silent=True)
        worker.finished.connect(lambda: setattr(self, "_candidate_busy", False))

    def _finetune_online(self, _progress=None) -> str:
        """Scheduled bounded candidate training; never changes the active detector."""
        model_path = Path(self.cfg("model"))
        try:
            from .training_process import run_training_process
            result = run_training_process(DATA, model_path)
            candidate = result["candidate"]
            if not candidate:
                online_learn.finish_candidate_schedule(DATA, "insufficient_data")
                return "Кандидат не создан: не выполнены требования к подтверждённым данным."
            online_learn.finish_candidate_schedule(DATA, "candidate_created", candidate["candidate_id"])
            return (f"Создан кандидат {candidate['candidate_id']} на {candidate['training_sample_count']} "
                    "подтверждённых примерах. Он ожидает независимой оценки; рабочая модель не изменена.")
        except Exception:
            online_learn.finish_candidate_schedule(DATA, "training_failed")
            raise

    def _net_tick(self):
        """Раз в секунду: обновление графиков при изменении журнала и новая точка графика сети."""
        if hasattr(self, "label_coverage_table"):
            registry_path = DATA / "label_registry.sqlite"
            try:
                signature = registry_path.stat().st_mtime_ns if registry_path.exists() else None
                if signature != getattr(self, "_label_registry_signature", None):
                    self._load_label_coverage()
                    self._label_registry_signature = signature
            except OSError:
                pass
        try:
            sig = self._monitor_signature()
        except (OSError, AttributeError):
            sig = None
        if sig != self._mon_sig:                          # журнал или очередь изменились — перерисовать
            self._mon_sig = sig
            self._load_monitor()
            self._load_events(keep_selection=True)        # «Журнал событий» тоже обновляется сам, без кнопки
        if hasattr(self, "mon_refresh"):
            self.mon_refresh.setText(f"Данные мониторинга проверены {time.strftime('%H:%M:%S')}.")
        self._maybe_capture_packet_segment()
        if self._psutil is None:
            if hasattr(self, "net_capture_note"):
                self.net_capture_note.setText("Сетевой сенсор psutil недоступен; живые снимки не сохраняются.")
            return
        try:
            io, now = self._psutil.net_io_counters(), time.monotonic()
        except Exception as e:  # noqa: BLE001 — счётчики сети недоступны на этом компьютере
            self._psutil = None
            self.ch_net.empty_text = f"Счётчики сети недоступны: {e}"
            self.ch_net.update()
            return
        if self._net_prev:
            p0, b0, ps0, bs0, t0 = self._net_prev
            dt = max(now - t0, 1e-3)
            rate_in = max(io.packets_recv - p0, 0) / dt
            rate_out = max(io.packets_sent - ps0, 0) / dt
            kb_in = max(io.bytes_recv - b0, 0) / dt / 1024
            kb_out = max(io.bytes_sent - bs0, 0) / dt / 1024
            self.ch_net.push(rate_in)
            self.ch_net_out.push(rate_out)
            self.ch_net_kb_in.push(kb_in)
            self.ch_net_kb_out.push(kb_out)
            self.net_note.setText(
                f"Сейчас: вход {rate_in:.0f} пак./с ({kb_in:.1f} КБ/с), "
                f"выход {rate_out:.0f} пак./с ({kb_out:.1f} КБ/с). "
                f"Обновление раз в секунду, окно 2 минуты.")
        self._net_prev = (io.packets_recv, io.bytes_recv, io.packets_sent, io.bytes_sent, now)
        self._maybe_live_flow_assessment()
        self._maybe_capture_network_snapshot(now)

    def _maybe_capture_packet_segment(self):
        """Collect a short, payload-free Pktmon segment without blocking the GUI."""
        if self._packet_capture_busy:
            return
        now = time.monotonic()
        if now < self._packet_capture_next:
            return
        # Keep Pktmon segments close to contiguous; a 10 s sample once per
        # minute observed only ~17% of traffic and missed most short flows.
        self._packet_capture_next = now + 30
        self._packet_capture_busy = True

        def work(_progress):
            runtime_path = DATA / "online" / "network_runtime_metrics.sqlite"
            from .network_runtime_evidence import record_packet_capture_segment, record_captured_flows
            from .pktmon_capture import capture_header_segment
            try:
                # P2.5: optional split mode. The app itself never needs administrator rights;
                # the elevated helper is started through a UAC prompt. Off by default.
                if str(self.settings.value("pktmon_helper", "0") or "0").strip() == "1":
                    from .pktmon_segment import capture_via_helper, helper_command
                    program, script = helper_command()
                    capture = capture_via_helper(30, DATA, program, script)
                else:
                    capture = capture_header_segment(duration_seconds=30)
            except Exception as error:  # noqa: BLE001 — persist the sensor failure for diagnosis
                capture = {"status": "capture_exception",
                           "reason": f"{type(error).__name__}: {error}"[:400]}
            segment_hash = None
            try:
                segment_hash = record_packet_capture_segment(
                    runtime_path,
                    observed_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    capture=capture,
                )
                if segment_hash and capture.get("flows"):
                    capture["evidence_journal"] = record_captured_flows(
                        runtime_path, segment_hash=segment_hash,
                        observed_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        flows=capture.get("flows", []),
                    )
            except (OSError, ValueError, TypeError):
                capture["evidence_journal"] = {"stored_flow_count": 0, "status": "write_failed"}
            assessment = None
            if capture.get("status") in ("ok", "parsed_best_effort"):
                from .network_flow_model import assess_completed_packet_flows
                candidate_path = (Path(__file__).resolve().parents[1] / "models"
                                  / "network_flow_v3_candidate.pt")
                assessment = assess_completed_packet_flows(capture.get("flows", []), candidate_path)
            if assessment and assessment.get("status") == "recommendation_candidate":
                try:
                    from .network_runtime_evidence import record_flow_inference, runtime_summary
                    runtime_path = DATA / "online" / "network_runtime_metrics.sqlite"
                    record_flow_inference(
                        runtime_path,
                        observed_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        inference_ms=assessment["inference_latency_ms"],
                        flows_scored=assessment["scored_flows"],
                        capture_status=capture.get("status", "unknown"),
                        packets_seen=(capture.get("counts") or {}).get("packets"),
                        drop_counters_available=bool(capture.get("drop_counters_available")),
                        candidate_sha256=assessment["checkpoint_sha256"],
                        feature_version=assessment["feature_version"],
                        dataset_manifest_sha256=assessment["dataset_manifest_sha256"],
                        threshold=assessment["threshold"],
                        capture_segment_hash=segment_hash,
                    )
                    assessment["runtime_summary"] = runtime_summary(runtime_path)
                except (OSError, ValueError, KeyError, TypeError):
                    assessment["runtime_summary"] = {"sample_count": 0}
            return capture, assessment

        def done(result):
            capture, assessment = result
            status = capture.get("status")
            observed = time.strftime("%H:%M:%S")
            if status in ("ok", "parsed_best_effort") and assessment \
                    and assessment.get("status") == "recommendation_candidate":
                scored = assessment.get("flow_scores") or []
                self._nn_monitor_flows.extend(scored)
                self._nn_monitor_status = (
                    f"Последний Pktmon-сегмент {observed}: оценено {len(scored)} полных потоков; "
                    f"в видимом окне {len(self._nn_monitor_flows)}. Положительная оценка — кандидат для обзора, "
                    "локальные метки неизвестны.")
            elif status in ("ok", "parsed_best_effort"):
                self._nn_monitor_status = (
                    f"Последний Pktmon-сегмент {observed} сохранён, но оценка потока недоступна: "
                    f"{(assessment or {}).get('reason', (assessment or {}).get('status', 'unknown'))}.")
            else:
                reason = str(capture.get("reason", status or "неизвестная ошибка"))
                self._nn_monitor_status = f"Pktmon недоступен ({observed}): {reason}"
            if hasattr(self, "nn_monitor_status_label"):
                self.nn_monitor_status_label.setText(self._nn_monitor_status)
            if hasattr(self, "nn_score_stream"):
                self._refresh_nn_monitor()
            if status in ("ok", "parsed_best_effort"):
                counts = capture.get("counts", {})
                journal = capture.get("evidence_journal") or {}
                text = (f"Pktmon · разобрано IP-пакетов {counts.get('parsed', 0)} из "
                        f"{counts.get('packets', 0)}, не-IP кадров {counts.get('non_ip_frames', 0)}, "
                        f"неразобранных/обрезанных {counts.get('unsupported_or_truncated', 0)}. "
                        f"Полных потоков: {capture.get('complete_flow_count', 0)}; "
                        f"в локальном журнале потоков: {journal.get('stored_flow_count', 0)} "
                        f"(метки неизвестны). ")
                if assessment and assessment.get("status") == "recommendation_candidate":
                    text += (f"Flow-модель на {assessment.get('dataset_family', 'публичных метках')} "
                             f"оценила {assessment['scored_flows']} полных потоков; "
                             f"выше порога {assessment['threshold']:.4f}: "
                             f"{assessment['attack_candidates_at_threshold']}; inference "
                             f"{assessment['inference_latency_ms']:.2f} мс. "
                             "Используются опубликованные авторами набора метки. "
                             "Целевая сеть не оценена, Firewall не меняется.")
                else:
                    text += "Оценка модели пропущена: нет совместимого кандидата или полных потоков."
                if status == "parsed_best_effort":
                    text += " Захват неполный; результаты только диагностические."
                self.packet_flow_note.setText(text)
            else:
                self.packet_flow_note.setText(
                    f"Захват пакетов недоступен · {capture.get('reason', status)}. "
                    "Сокетный мониторинг и системные счётчики продолжают работать.")
            self._packet_capture_busy = False

        def failed(message):
            self.packet_flow_note.setText(f"Захват заголовков не выполнен: {message}")
            self._packet_capture_busy = False

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: setattr(self, "_packet_capture_busy", False))
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _maybe_live_flow_assessment(self):
        if self._psutil is None or self._network_flow_busy:
            return
        self._network_flow_busy = True

        def work(_progress):
            snapshot = self._network_flow_telemetry.sample(self._psutil)
            from .network_flow_model import assess
            return snapshot, assess(snapshot)

        def done(result):
            snapshot, assessment = result
            if assessment.get("status") == "recommendation":
                self.net_flow_note.setText(
                    f"Живой опрос · {snapshot['observed_at_utc']} · "
                    f"активных соединений {snapshot['active_connection_count']}, "
                    f"удалённых узлов {snapshot['remote_endpoint_count']}. "
                    f"Модель обработала {assessment['scored_connections']} сокетов, "
                    f"кандидатов {assessment['attack_candidates']}, "
                    f"средняя оценка атаки {assessment['mean_attack_probability']:.1%}. "
                    "Опрос выполняется раз в секунду, пока программа открыта. "
                    "Это рекомендация; правила Firewall не меняются.")
            else:
                reason = assessment.get("reason", assessment.get("status"))
                if assessment.get("status") == "unavailable":
                    self.net_flow_note.setText(
                        f"Живой опрос сокетов · {snapshot['observed_at_utc']} · "
                        f"сокетная модель не загружена: {reason}. Это не оценка потоков пакетов: "
                        "per-flow кандидат проверяется отдельно только на полных потоках Pktmon.")
                else:
                    self.net_flow_note.setText(
                        f"Живой опрос · {snapshot['observed_at_utc']} · "
                        f"модель не вынесла оценку: {reason}")
            self._network_flow_busy = False

        def failed(message):
            self.net_flow_note.setText(f"Живой опрос сокетов не выполнен: {message}")
            self._network_flow_busy = False

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: setattr(self, "_network_flow_busy", False))
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _maybe_capture_network_snapshot(self, now: float | None = None):
        if self._network_capture_busy or self._psutil is None:
            return
        now = time.monotonic() if now is None else now
        if now < self._network_capture_next:
            return
        self._network_capture_busy = True
        self._network_capture_next = now + 20

        def work(_progress):
            snapshot = self._network_telemetry.sample(self._psutil)
            from .network_evidence import NetworkEventLog
            event_log = NetworkEventLog(DATA / "online" / "network_events.sqlite")
            event_id = event_log.capture(snapshot, source="gui_periodic")
            baseline_advisory = None
            from .network_behavior_baseline import compare_snapshot
            profile = self._network_baseline_profile
            if profile is not None:
                try:
                    baseline_advisory = compare_snapshot(snapshot, profile)
                except ValueError as error:
                    baseline_advisory = {"status": "unavailable", "reason": str(error)}
            try:
                classifier = assess_network_with_classifier(
                    snapshot, {}, NETWORK_CLASSIFIER_CHECKPOINT)
            except Exception as error:  # noqa: BLE001 — model scoring cannot stop capture
                classifier = {"status": "error", "reason": type(error).__name__}
            return snapshot, event_id, classifier, baseline_advisory

        def done(result):
            snapshot, event_id, classifier, baseline_advisory = result
            if self._baseline_window_auto:
                end_utc = datetime.now(timezone.utc).replace(microsecond=0)
                self.baseline_end.setText(end_utc.isoformat(timespec="seconds"))
                self.baseline_start.setText((end_utc - timedelta(minutes=20)).isoformat(timespec="seconds"))
            note = (f"Снимок сохранён · {snapshot['observed_at_utc']} · "
                    f"активных соединений: {snapshot.get('active_connection_count', 0)} · "
                    f"удалённых узлов: {snapshot.get('remote_endpoint_count', 0)} · id {event_id}. ")
            if classifier.get("status") == "error":
                note += "Собственный классификатор недоступен; сетевые данные сохранены для разметки."
            else:
                note += (f"Собственная модель: {classifier.get('decision', 'REVIEW')}. "
                         f"{classifier.get('summary', 'Недостаточно данных для вывода.')} "
                         "Это рекомендация модели; Firewall не меняется.")
            if baseline_advisory:
                if baseline_advisory.get("status") == "unavailable":
                    note += f" Профиль поведения не сравнен: {baseline_advisory['reason']}"
                elif baseline_advisory.get("status") == "advisory_deviation":
                    details = "; ".join(
                        f"{item['feature']}: {item['value']:.2f} "
                        f"(обычный диапазон {item['baseline_p05']:.2f}–{item['baseline_p95']:.2f})"
                        for item in baseline_advisory["deviations"][:3])
                    more = max(0, len(baseline_advisory["deviations"]) - 3)
                    note += f" Отклонение от выбранного профиля: {details}"
                    if more:
                        note += f" и ещё {more}."
                    note += " Только для обзора; это не метка и не решение модели."
                else:
                    note += " Параметры снимка в диапазонах выбранного профиля поведения. Это не подтверждение безопасности."
            self.net_capture_note.setText(note)
            self._refresh_network_baseline_readiness()
            self._network_capture_busy = False
            self._check_nn()

        def failed(message):
            self.net_capture_note.setText(f"Снимок сети не сохранён: {message}")
            self._network_capture_busy = False

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: setattr(self, "_network_capture_busy", False))
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _render_network_baseline_status(self):
        profile = getattr(self, "_network_baseline_profile", None)
        if not profile:
            self.baseline_status.setText(
                "Профиль не создан. Выберите фактический период журнала; минимум 30 снимков за 10 минут, "
                "не менее 90% полных телеметрических записей, разрыв между полными снимками не более 120 секунд."
            )
            return
        window = profile.get("window", {})
        digest = profile.get("profile_sha256", "")
        self.baseline_status.setText(
            f"Профиль загружен · контрольная сумма совпадает · {profile.get('event_count', 0)} реальных снимков · "
            f"полнота телеметрии {profile.get('telemetry_coverage', 0):.1%} · "
            f"неполных исключено: {len(profile.get('excluded_events', []))} · "
            f"{window.get('start_utc', '—')} — {window.get('end_utc', '—')} · "
            f"SHA-256 {digest[:16]}… · это контрольная сумма, не удостоверение подлинности; "
            "профиль не используется для меток, обучения или блокировки."
        )

    def _freeze_network_baseline_window(self):
        """Stop rolling the suggested window as soon as the operator edits either time."""
        self._baseline_window_auto = False
        self.baseline_readiness_note.setText(
            "Интервал задан вручную. Индикатор ниже показывает только предварительное число записей; "
            "целостность и полнота проверяются при формировании профиля."
        )

    def _refresh_network_baseline_readiness(self):
        """Show raw interval volume only; trust/completeness is checked on profile creation."""
        try:
            start = datetime.fromisoformat(self.baseline_start.text().strip().replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.baseline_end.text().strip().replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None:
                raise ValueError("Добавьте часовой пояс к обеим датам, например +00:00.")
            start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
            if end <= start:
                raise ValueError("Конец интервала должен быть позже начала.")
            db_path = DATA / "online" / "network_events.sqlite"
            if not db_path.is_file():
                count = 0
            else:
                with sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True,
                                     timeout=1) as db:
                    count = db.execute(
                        "SELECT COUNT(*) FROM events WHERE captured_at_utc>=? AND captured_at_utc<=?",
                        (start.isoformat(), end.isoformat())).fetchone()[0]
            self.baseline_readiness.setValue(min(30, count))
            duration = (end - start).total_seconds()
            if duration < 600:
                prefix = "Последние 20 минут сдвигаются автоматически до ручной правки дат. " if self._baseline_window_auto else ""
                self.baseline_readiness_note.setText(
                    f"{prefix}В журнале {count} записей по времени записи. Интервал короче минимальных 10 минут; "
                    "состав и целостность снимков ещё не проверялись."
                )
            elif count < 30:
                prefix = "Последние 20 минут сдвигаются автоматически до ручной правки дат. " if self._baseline_window_auto else ""
                self.baseline_readiness_note.setText(
                    f"{prefix}Пока {count} записей по времени записи; нужно минимум 30 полных снимков. "
                    "Программа проверит хеши, полноту и разрывы только при формировании профиля."
                )
            else:
                prefix = "Последние 20 минут сдвигаются автоматически до ручной правки дат. " if self._baseline_window_auto else ""
                self.baseline_readiness_note.setText(
                    f"{prefix}В интервале {count} записей по времени записи. Это предварительный счётчик: "
                    "хеши, полнота телеметрии и разрывы проверяются при формировании профиля."
                )
        except (ValueError, OSError, sqlite3.Error) as error:
            self.baseline_readiness.setValue(0)
            self.baseline_readiness_note.setText(f"Не удалось оценить объём интервала: {error}")

    def _create_network_baseline(self):
        if not self.baseline_confirm.isChecked():
            self.notify("Подтвердите репрезентативность выбранного периода. Это не присваивает метки безопасности.",
                        "warn")
            return
        try:
            from .network_behavior_baseline import build_profile, save_profile
            start = datetime.fromisoformat(self.baseline_start.text().strip().replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.baseline_end.text().strip().replace("Z", "+00:00"))
            if start.tzinfo is None or end.tzinfo is None:
                raise ValueError("Укажите часовой пояс; например, +00:00 для UTC.")
        except (ValueError, TypeError) as error:
            self.notify(str(error), "error")
            return
        # Freeze precisely the interval the operator attested to before the worker
        # starts; later live captures must not change the dates shown in the UI.
        self._baseline_window_auto = False
        self.baseline_start.setEnabled(False)
        self.baseline_end.setEnabled(False)
        self.baseline_confirm.setEnabled(False)
        self.baseline_button.setEnabled(False)
        self.baseline_progress.setValue(0)
        self.baseline_progress.setVisible(True)
        self.baseline_status.setText("Проверяю журнал снимков, целостность SHA-256 и покрытие интервала…")

        def work(progress):
            profile = build_profile(DATA / "online" / "network_events.sqlite", start, end,
                                    operator_selected=True, progress=progress)
            save_profile(profile, self._network_baseline_path)
            return profile

        def done(profile):
            self._network_baseline_profile = profile
            self._baseline_window_auto = False
            self.baseline_confirm.setChecked(False)
            self._render_network_baseline_status()
            self.baseline_progress.setVisible(False)
            self.baseline_start.setEnabled(True)
            self.baseline_end.setEnabled(True)
            self.baseline_confirm.setEnabled(True)
            self.baseline_button.setEnabled(True)
            self.notify("Профиль поведения сохранён отдельно. Он формирует только advisory-отклонения.", "ok")

        def failed(message):
            self.baseline_start.setEnabled(True)
            self.baseline_end.setEnabled(True)
            self.baseline_confirm.setEnabled(True)
            self.baseline_button.setEnabled(True)
            self.baseline_progress.setVisible(False)
            self._render_network_baseline_status()
            self.notify(f"Профиль не создан: {message}", "error")

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.progress.connect(lambda value: self._network_baseline_progress(value))
        worker.finished.connect(lambda: self.baseline_button.setEnabled(True))
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _network_baseline_progress(self, value):
        if not isinstance(value, dict):
            return
        percent = max(0, min(100, int(value.get("percent", 0))))
        self.baseline_progress.setValue(percent)
        self.baseline_status.setText(
            f"Проверяю целостность записей журнала: "
            f"{value.get('records_processed', 0)} из {value.get('records_total', 0)}…"
        )

    def _change_network_block(self, action):
        try:
            address = ipaddress.ip_address(self.firewall_ip.text().strip())
            if address.is_unspecified or address.is_loopback or address.is_multicast or getattr(address, 'scope_id', None):
                raise ValueError
        except ValueError:
            self.firewall_status.setText("Укажите один удалённый IP-адрес.")
            return
        if sys.platform != "win32":
            self.firewall_status.setText("Управление Windows Firewall доступно в Windows.")
            return
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            self.firewall_status.setText("Для изменения правил запустите IntegrityGuard от имени администратора.")
            return
        address = str(address)
        title = "Заблокировать" if action == "Block" else "Разблокировать"
        if QMessageBox.question(self, "Windows Firewall", f"{title} входящий и исходящий трафик для {address}?") != QMessageBox.StandardButton.Yes:
            return
        for button in self.firewall_buttons:
            button.setEnabled(False)
        self.firewall_status.setText("Изменяю правила Windows Firewall…")

        def work(_progress):
            from .security_audit import SecurityAudit
            audit = SecurityAudit(DATA / "security_audit.sqlite")
            request = f"{action} {address} {uuid.uuid4()}"
            principal = getpass.getuser()
            audit.append(principal=principal, question=request, answer="requested", model="operator",
                         status="answered", source_hashes=[], tool_calls=[
                             {"name": f"firewall_{action.lower()}", "status": "requested",
                              "result_sha256": hashlib.sha256(request.encode()).hexdigest()}])
            try:
                system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
                powershell = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
                subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File",
                                str(RESOURCE_ROOT / "tools/network-block.ps1"), "-Action", action,
                                "-Address", address], check=True, capture_output=True,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=60)
            except (OSError, subprocess.SubprocessError) as error:
                result = type(error).__name__
                message = f"Windows Firewall вернул ошибку ({result}). Проверьте правила для {address}."
                status = "error"
            else:
                result, status = "success", "answered"
                message = f"{address}: {'правила блокировки добавлены' if action == 'Block' else 'правила IntegrityGuard сняты'}."
            audit.append(principal=principal, question=request, answer=result, model="operator", status=status,
                         source_hashes=[], tool_calls=[{"name": f"firewall_{action.lower()}", "status": result,
                         "result_sha256": hashlib.sha256(f"{request} {result}".encode()).hexdigest()}])
            return message

        worker = self.run_bg(work, self.firewall_status.setText)
        worker.fail.connect(self.firewall_status.setText)
        worker.finished.connect(lambda: [button.setEnabled(True) for button in self.firewall_buttons])

    def run_bg(self, fn, done, button=None, progress=None, silent=False):
        w = Worker(fn, self)
        if button:
            button.setEnabled(False)

        def finish():
            if button:
                button.setEnabled(True)
            self._workers.remove(w)
        w.done.connect(done)
        w.fail.connect(lambda msg: self.notify(msg, "error"))
        if progress:
            w.progress.connect(progress)
        w.finished.connect(finish)
        self._workers.append(w)
        w.start()
        return w

    # ------------------------------------------------------------ страница «Проверка»
    def _page_check(self):
        p = Page("Проверка пакета", "Результат относится к последнему сетевому снимку. Прогноз модели — рекомендация, "
                                    "а не подтверждённая метка и не действие блокировки.")
        # ---- строка статуса анализа + кнопка повтора ----
        self._check_status_lbl = label("Загружаем последнее событие из БД\u2026", muted=True, wrap=True)
        self.check_btn = QPushButton("\u27f3  Повторить оценку", objectName="primary")
        self.check_btn.setMinimumWidth(180)
        self.check_btn.clicked.connect(lambda: self._check_nn(force=True))
        status_row = QHBoxLayout()
        status_row.addWidget(self._check_status_lbl, 1)
        status_row.addWidget(self.check_btn)
        p.lay.addWidget(card(status_row))

        # Контекст проверяемого события остаётся видимым над вердиктом.
        self.check_context_package = label("Ожидание события", "h2", wrap=True)
        self.check_context_version = label("Версия: —", muted=True, wrap=True)
        self.check_context_reference = label("Эталон: не определён", muted=True, wrap=True)
        self.check_context_time = label("Время события: —", muted=True, wrap=True)
        context = QGridLayout()
        context.addWidget(self.check_context_package, 0, 0, 1, 2)
        context.addWidget(self.check_context_version, 1, 0)
        context.addWidget(self.check_context_reference, 1, 1)
        context.addWidget(self.check_context_time, 2, 0, 1, 2)
        p.lay.addWidget(card(context, title="Объект проверки"))

        # --- прогресс-бар и живой лог (скрыты до запуска проверки)
        self._check_progress_bar = QProgressBar()
        self._check_progress_bar.setRange(0, 100)
        self._check_progress_bar.setValue(0)
        self._check_progress_bar.setTextVisible(False)
        self._check_progress_bar.setFixedHeight(6)
        self._check_progress_bar.setStyleSheet(
            "QProgressBar { background: #1e2229; border-radius: 3px; }"
            "QProgressBar::chunk { background: #2bb7ab; border-radius: 3px; }")
        self._check_progress_bar.setVisible(False)
        self._check_log = label("", wrap=True, muted=True)
        self._check_log.setTextFormat(Qt.RichText)
        self._check_log.setVisible(False)
        # --- карточка прогресса (скрыта пока не запущена проверка)
        self._check_progress_card = card(self._check_progress_bar, self._check_log, title="Ход анализа")
        self._check_progress_card.setVisible(False)
        p.lay.addWidget(self._check_progress_card)

        # результат
        self.badge = label("—", wrap=False)
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setMinimumSize(190, 54)
        self.badge.setMaximumHeight(54)
        self._set_badge(None)
        self.risk_badge = label("—", wrap=False)
        self.risk_badge.setAlignment(Qt.AlignCenter)
        self.risk_badge.setMinimumSize(80, 54)
        self.risk_badge.setMaximumHeight(54)
        self.risk_badge.setStyleSheet("background: #171b24; color: #8a8f99; border-radius: 9px; "
                                      "font-size: 11pt; font-weight: 700; padding: 6px 12px;")
        self.res_title = label("Проверка ещё не выполнялась", "h2", wrap=True)
        self.res_sub = label("Выберите пакет и нажмите «Проверить».", muted=True, wrap=True)
        self.res_sub.setMinimumHeight(40)
        self.res_sub.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.pdf_btn = QPushButton("↓ PDF-отчёт")
        self.pdf_btn.setEnabled(False)
        self.pdf_btn.setToolTip("Экспорт отчёта о последней проверке в PDF")
        self.pdf_btn.clicked.connect(self._export_pdf)
        head = QHBoxLayout()
        head.setSpacing(18)
        head.addWidget(self.badge, 0, Qt.AlignTop)
        risk_col = QVBoxLayout()
        risk_col.setSpacing(2)
        risk_col.addWidget(label("Риск", muted=True))
        risk_col.addWidget(self.risk_badge)
        head.addLayout(risk_col)
        head.setAlignment(risk_col, Qt.AlignTop)
        col = QVBoxLayout()
        col.addWidget(self.res_title)
        col.addWidget(self.res_sub)
        col.addWidget(self.pdf_btn)
        head.addLayout(col, 1)
        self.level_bars = {}
        lv = QGridLayout()
        lv.setHorizontalSpacing(12)
        for i, name in enumerate(LEVELS):
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            val = label("—", muted=True)
            val.setMinimumWidth(44)
            lv.addWidget(label(f"{LEVEL_RU[name].capitalize()} уровень"), i, 0)
            lv.addWidget(bar, i, 1)
            lv.addWidget(val, i, 2)
            self.level_bars[name] = (bar, val)
        lv.setColumnStretch(1, 1)
        self.suspects = table(["Подозрительный компонент", "Оценка"])
        self.suspects.setMaximumHeight(150)
        self.actions = label("", wrap=True)
        self.actions.setTextFormat(Qt.RichText)
        two = QHBoxLayout()
        two.setSpacing(14)
        lv_caption = label("Эвристическая оценка по признакам снимка, не вероятность атаки: "
                           "чем выше значение, тем ближе к норме. Низкое значение — повод проверить вручную.",
                           muted=True, wrap=True)
        lv.addWidget(lv_caption, len(LEVELS), 0, 1, 3)
        lv_card = card(lv, title="Оценки признаков целостности")
        lv_card.layout().addStretch(1)
        two.addWidget(lv_card, 1)
        self.loc_card = card(self.suspects, title="Затронутые компоненты")
        two.addWidget(self.loc_card, 1)
        self.result_card = card(head)
        p.lay.addWidget(self.result_card)
        # Подсказки по признакам: объяснения для ручной проверки, не вердикт
        self.hints_lbl = label("", wrap=True)
        self.hints_lbl.setTextFormat(Qt.RichText)
        self.check_details_toggle = QPushButton("＋  Показать доказательства и технические детали")
        self.check_details_toggle.setCheckable(True)
        self.check_details = QWidget()
        details_layout = QVBoxLayout(self.check_details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.addLayout(two)
        details_layout.addWidget(card(self.hints_lbl, title="Подсказки по признакам (не вердикт)"))
        self.check_details.setVisible(False)
        self.check_details_toggle.toggled.connect(
            lambda expanded: (self.check_details.setVisible(expanded),
                              self.check_details_toggle.setText(
                                  "−  Скрыть доказательства и технические детали" if expanded else
                                  "＋  Показать доказательства и технические детали")))
        p.lay.addWidget(self.check_details_toggle)
        p.lay.addWidget(self.check_details)
        p.lay.addWidget(card(self.actions, title="Рекомендуемое действие"))
        # Решение оператора: записывается в журнал аудита, блокировка трафика этим не выполняется
        self.dec_btns = {}
        dec_row = QHBoxLayout()
        dec_row.setSpacing(10)
        for key, text, tip in (
            ("allow", "Допустить", "Записать решение «допустить» в журнал аудита"),
            ("hold", "Оставить на проверке", "Записать решение «оставить на проверке»"),
            ("block", "Отметить как блокировку", "Записывается решение оператора. Блокировка трафика этим не выполняется."),
        ):
            btn = QPushButton(text)
            btn.setEnabled(False)
            btn.setToolTip(tip)
            btn.clicked.connect(lambda _=False, k=key: self._record_operator_decision(k))
            self.dec_btns[key] = btn
            dec_row.addWidget(btn)
        dec_row.addStretch(1)
        self.dec_status = label("Решение оператора станет доступно после проверки.", muted=True, wrap=True)
        dec_col = QVBoxLayout()
        dec_col.addLayout(dec_row)
        dec_col.addWidget(self.dec_status)
        p.lay.addWidget(card(dec_col, title="Решение оператора"))
        p.lay.addStretch(1)
        # Автоматически запустить анализ после инициализации страницы
        self._check_busy = False
        self._check_last_event_id = None
        self._check_inflight_event_id = None
        QTimer.singleShot(300, self._check_nn)
        return p


    def _show_event_nn(self, ev):
        """Displays neural network analysis result on Package Check page."""
        self._set_check_context(ev)
        self._set_badge(ev.get("verdict"))
        rs = ev.get("risk_score")
        rs_color = "#8a8f99" if rs is None else "#e5484d" if rs >= 70 else "#d99a1c" if rs >= 30 else "#1f9d63"
        self.risk_badge.setText("\u043d/\u0434" if rs is None else str(rs))
        self.risk_badge.setStyleSheet(
            f"background: {rs_color}22; color: {rs_color}; border: 2px solid {rs_color}; "
            f"border-radius: 9px; font-size: 14pt; font-weight: 700; padding: 4px 10px;")
        verdict = ev.get("verdict", "REVIEW")
        # Вердикт показан только крупной плашкой (badge); здесь — причина простым языком.
        if rs is None:
            self.res_title.setText("Оценка риска не рассчитана")
            self.res_sub.setText("Классификатор не готов для текущей версии признаков. Проверьте событие вручную.")
        else:
            self.res_title.setText(f"Риск {rs} из 100")
            self.res_sub.setText(ev.get("threat_ru", ""))
        self.pdf_btn.setEnabled(True)
        self.pdf_btn.setToolTip("Сохранить отчёт о последней проверке в PDF")
        levels = ev.get("levels", {})
        for name, (bar, val) in self.level_bars.items():
            v = levels.get(name)
            bar.setValue(int(round(100 * v)) if v is not None else 0)
            val.setText(f"{v:.0%}" if v is not None else "\u2014")
            if v is not None:
                # Эвристическая оценка по признакам снимка: высокое = ближе к норме (зелёный).
                color = "#1f9d63" if v >= 0.7 else "#d99a1c" if v >= 0.4 else "#e5484d"
                bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}")
        nn_result = ev.get("_nn_result", {})
        probs = nn_result.get("class_probabilities") or {}
        if probs:
            p_allow, p_block = probs.get("ALLOW", 0), probs.get("BLOCK", 0)
            probabilities_html = (f"<b>Вероятность угрозы:</b> {p_block:.1%} &nbsp;|&nbsp; "
                                  f"<b>Вероятность безопасности:</b> {p_allow:.1%}<br>")
        else:
            probabilities_html = "<b>Вероятности:</b> не рассчитаны.<br>"
        decision_word = {"ALLOW": "допустить", "BLOCK": "заблокировать",
                         "REVIEW": "проверить вручную"}.get(nn_result.get("decision"), "проверить вручную")
        actions_html = probabilities_html + f"<b>Предложение классификатора:</b> {decision_word}"
        if probs:
            actions_html += f"<br>{nn_result.get('summary', '')}"
        # Полная техническая формулировка доступна в подсказке, не на основном экране.
        self.actions.setToolTip(nn_result.get("summary", ""))
        from .check_hints import ADVICE_NOTE, hints as _hints
        found = _hints(ev.get("_hint_features"))
        muted_note = f"<br><span style='color:#8a8f99'>{ADVICE_NOTE}</span>"
        if found:
            items = "".join(f"<li>{h['reason']} <span style='color:#8a8f99'>({h['feature']} = {h['value']})</span></li>"
                            for h in found)
            self.hints_lbl.setText(f"<ul>{items}</ul>{muted_note}")
        else:
            self.hints_lbl.setText(f"Явных признаков по правилам не найдено.{muted_note}")
        if verdict == "BLOCK":
            actions_html += "<br><br>\u26d4 <b>Рекомендуется заблокировать</b> данный сетевой снимок."
        elif verdict == "ALLOW":
            actions_html += "<br><br>\u2705 <b>Трафик выглядит безопасным.</b> Дополнительных действий не требуется."
        else:
            actions_html += "<br><br>\u26a0\ufe0f <b>Рекомендуется ручная проверка</b> данного события."
        self.actions.setText(actions_html)
        self._last_ev = ev
    def _record_operator_decision(self, key: str):
        """Writes the operator's choice to the audit chain. It does not block or change traffic."""
        import getpass
        from .check_audit import append_check
        event_id = getattr(self, "_current_event_id", None)
        if not event_id:
            return
        names = {"allow": "допустить", "hold": "оставить на проверке", "block": "отметить как блокировку"}
        try:
            operator = getpass.getuser()
        except Exception:  # noqa: BLE001 — a missing login name must not break the page
            operator = "неизвестен"
        try:
            append_check(DATA / "audit" / "network_check_audit.jsonl", {
                "kind": "operator_decision", "event_id": str(event_id),
                "operator": operator, "decision": key,
                "note": "решение записано; блокировка трафика этим не выполняется",
            })
            self.dec_status.setText(f"Записано: {names[key]} · оператор {operator}. Блокировка не выполнена.")
        except OSError as error:
            self.dec_status.setText(f"Решение не записано: {error}")

    def _set_badge(self, verdict):
        text, color = VERDICT.get(verdict, ("—", "#2a2f3a"))
        self.badge.setText(text)
        self.badge.setStyleSheet(f"background: {color}; color: white; border-radius: 9px; font-size: 13pt; "
                                 f"font-weight: 700; padding: 6px 18px;")

    def _index_for(self, pkg):
        side = Path(f"{pkg}.index.json")       # необязательный доверенный индекс рядом с пакетом
        return str(side) if side.exists() else None

    def _check_load_events(self):
        """Fetches latest event snapshot from DB. Returns (event_id, snap_json) or (None, None)."""
        import sqlite3
        import pathlib
        db_path = DATA / "online" / "network_events.sqlite"
        if not db_path.exists():
            return None, None
        try:
            con = sqlite3.connect(str(db_path))
            row = con.execute(
                "SELECT event_id, snapshot_json FROM events ORDER BY captured_at_utc DESC LIMIT 1"
            ).fetchone()
            con.close()
            if row:
                return row[0], row[1]
        except Exception:
            pass
        return None, None

    def _check_nn(self, force: bool = False):
        """Automatically score each newly captured network snapshot; manual refresh is optional."""
        if self._check_busy:
            return
        import json as _json
        event_id, snap_json = self._check_load_events()
        if not event_id or not snap_json:
            self._check_status_lbl.setText("\u26a0\ufe0f Нет событий в БД для анализа.")
            return
        if not force and event_id == self._check_last_event_id:
            return
        self._check_busy = True
        self._current_event_id = None
        for decision_button in self.dec_btns.values():
            decision_button.setEnabled(False)
        self._check_inflight_event_id = event_id
        self._check_status_lbl.setText(f"\U0001f9e0 Анализируем событие {str(event_id)[:20]}\u2026")

        self._check_log_lines = []
        self._check_progress_bar.setValue(0)
        self._check_progress_bar.setVisible(True)
        self._check_log.setVisible(True)
        self._check_log.setText("\u23f3 Анализ запущен\u2026")
        self._check_progress_card.setVisible(True)

        def _log(text):
            self._check_log_lines.append(text)
            QMetaObject.invokeMethod(self, "_update_check_log", Qt.QueuedConnection)

        def job(_):
            import json as _json2
            from .network_classifier import assess_network_with_classifier, extract_features
            from pathlib import Path as _Path
            try:
                snapshot = _json2.loads(snap_json) if isinstance(snap_json, str) else snap_json
            except Exception:
                snapshot = {}
            _log("\U0001f4e6 Извлечение признаков снимка\u2026")
            features = extract_features(snapshot)
            _log(f"\U0001f50d Признаков извлечено: {len(features)}")
            checkpoint_path = NETWORK_CLASSIFIER_CHECKPOINT
            _log("\U0001f9e0 Запуск нейросети\u2026")
            result = assess_network_with_classifier(snapshot, {}, checkpoint_path)
            probs = result.get("class_probabilities", {})
            p_block = probs.get("BLOCK")
            decision = result.get("decision", "REVIEW")
            probability_text = f"p_угрозы={p_block:.1%}" if p_block is not None else "оценка модели отсутствует"
            _log(f"\u2696\ufe0f Предложение: {decision}  ({probability_text})")
            # Structural: аномалии структуры сетевых соединений
            structural_score = 1.0 - min(1.0,
                features.get("port_scan_suspected_count", 0) * 0.4 +
                features.get("unattributed_endpoint_share", 0) * 0.4 +
                min(features.get("new_remote_endpoint_count", 0) / 20.0, 1.0) * 0.2
            )
            # Parametric: параметры трафика
            pz = abs(features.get("packet_rate_zscore", 0.0))
            bz = abs(features.get("byte_rate_zscore", 0.0))
            non_https = features.get("non_https_endpoint_share", 0)
            parametric_score = 1.0 - min(1.0,
                min(pz / 5.0, 1.0) * 0.3 +
                min(bz / 5.0, 1.0) * 0.3 +
                non_https * 0.4
            )
            # Behavioral: поведенческие аномалии
            suspicious = features.get("suspicious_port_match_count", 0)
            blocked_ratio = features.get("blocked_state_ratio", 0)
            behavioral_score = 1.0 - min(1.0,
                min(suspicious / 5.0, 1.0) * 0.5 +
                min(blocked_ratio, 1.0) * 0.3 +
                (p_block or 0.0) * 0.2
            )
            risk_score = round(p_block * 100) if p_block is not None else None
            _log(f"\U0001f4ca Уровни: структурный={structural_score:.0%} параметрический={parametric_score:.0%} поведенческий={behavioral_score:.0%}")
            verdict = "BLOCK" if decision == "BLOCK" else "ALLOW" if decision == "ALLOW" else "REVIEW"
            return {
                "verdict": verdict, "decision": decision, "risk_score": risk_score,
                "package": "Сетевой снимок", "version": str(event_id)[:12],
                "baseline_version": None, "threat_ru": result.get("summary", "")[:180],
                "hash_control": None, "analysis_mode": "nn_only",
                "score": p_block, "threshold": 0.1, "block_threshold": 0.9,
                "timing_ms": {"total": 0}, "rules": [], "public_intel": {},
                "levels": {
                    "structural": structural_score,
                    "parametric": parametric_score,
                    "behavioral": behavioral_score,
                },
                "_nn_result": result,
                "_hint_features": features,
            }

        def on_audit(res_ev):
            # Добавляем в очередь аудита для самообучения (REVIEW/BLOCK с вероятностью AUDIT_RATE)
            network_result = res_ev.get("_nn_result") or {}
            features = network_result.get("features")
            if not isinstance(features, dict):
                return res_ev
            try:
                online_learn.maybe_queue_network(
                    DATA, event_id, snap_json,
                    res_ev.get("decision", "REVIEW"),
                    features,
                )
            except Exception as error:  # noqa: BLE001 — surface queue failures in the analysis log
                _log(f"Не удалось сохранить снимок в очередь аудита: {type(error).__name__}: {error}")
            return res_ev

        def on_done(ev):
            self._check_last_event_id = event_id
            self._current_event_id = event_id
            for btn in self.dec_btns.values():
                btn.setEnabled(True)
            self._check_progress_bar.setValue(100)
            verdict = ev.get("verdict", "REVIEW")
            rs = ev.get("risk_score", 0)
            risk_text = f"риск {rs} из 100" if rs is not None else "оценка риска не рассчитана"
            self._check_status_lbl.setText(f"\u2705 Анализ завершён · {risk_text}")
            self._show_event_nn(ev)
            # Каждая проверка пишется в цепочку аудита: что показано и воздержался ли классификатор.
            try:
                from .check_audit import append_check
                nn = ev.get("_nn_result") or {}
                append_check(DATA / "audit" / "network_check_audit.jsonl", {
                    "kind": "check",
                    "event_id": str(event_id),
                    "classifier_status": "scored" if nn.get("class_probabilities") else "abstained",
                    "classifier_decision": nn.get("decision"),
                    "verdict_shown": ev.get("verdict"),
                    "risk_score": ev.get("risk_score"),
                    "levels": ev.get("levels"),
                })
            except OSError as error:
                self._check_status_lbl.setText(f"Аудит не записан: {error}")
            QTimer.singleShot(4000, lambda: self._check_progress_card.setVisible(False))

        worker = self.run_bg(job, lambda ev: on_done(on_audit(ev)), self.check_btn)
        worker.finished.connect(lambda: setattr(self, "_check_busy", False))

    @Slot()
    @Slot()
    def _update_check_log(self):
        """Updates progress log text in GUI thread."""
        lines = getattr(self, "_check_log_lines", [])
        total_steps = 5
        step = len(lines)
        pct = min(10 + int(step / total_steps * 85), 95)
        self._check_progress_bar.setValue(pct)
        log_html = "<br>".join(
            f"<span style='color:#8a8f99'>&bull;</span> {ln}"
            for ln in lines
        )
        self._check_log.setText(log_html or "⏳ Инициализация…")

    def _toggle_advanced(self):
        """Stub kept for compatibility."""
        pass

    def _sync_watch(self, text):
        pass

    def _watch_tick(self):
        pass


    def _show_event(self, ev, external_refresh=False):
        self._set_check_context(ev)
        self._set_badge(ev["verdict"])
        rs = ev.get("risk_score")
        if rs is None and isinstance(ev.get("score"), (int, float)):
            rs = round(ev["score"] * 100)
        rs_color = "#8a8f99" if rs is None else "#e5484d" if rs >= 70 else "#d99a1c" if rs >= 30 else "#1f9d63"
        self.risk_badge.setText("—" if rs is None else f"{rs}")
        self.risk_badge.setStyleSheet(
            f"background: {rs_color}22; color: {rs_color}; border: 2px solid {rs_color}; "
            f"border-radius: 9px; font-size: 14pt; font-weight: 700; padding: 4px 10px;")
        self.pdf_btn.setEnabled(True)
        self._last_ev = ev
        baseline = ev.get("baseline_version") or "эталон отсутствует"
        self.res_title.setText(f"{ev['package']}  {baseline} → {ev['version']}:  {ev['threat_ru']}")
        hc = ("не оценивался: нет эталона" if ev.get("hash_control") is None else
              "нарушение" if ev["hash_control"] else "норма")
        if ev.get("analysis_mode") == "reference_missing":
            score_text = "Сравнительная оценка не выполнена: нет доверенного эталона; балл не рассчитывался."
        elif ev.get("analysis_mode") == "intake_validation_error":
            score_text = "Оценка не завершена из-за ошибки проверки; балл не рассчитывался."
        elif isinstance(ev.get("score"), (int, float)) and isinstance(ev.get("threshold"), (int, float)) \
                and isinstance(ev.get("block_threshold"), (int, float)):
            score_text = (f"Оценка нарушения {ev['score']:.3f} (порог проверки {ev['threshold']:.2f}, "
                          f"блокировки {ev['block_threshold']:.2f}).")
        elif isinstance(ev.get("score"), (int, float)):
            score_text = f"Оценка нарушения {ev['score']:.3f}."
        else:
            score_text = "Числовая оценка не рассчитана."
        risk_text = f"Балл риска модели: {rs}/100." if rs is not None else "Балл риска модели не рассчитывался."
        intel = ev.get("public_intel") or {}
        intel_text = ""
        if intel:
            intel_text = (f"\nПубличные сведения OSV: {intel.get('status', 'неизвестно')}; "
                          f"проверено {intel.get('queried', 0)} из {intel.get('eligible', 0)} публичных PyPI-зависимостей; "
                          f"известно уязвимых: {intel.get('known_vulnerable_dependencies', 0)}. "
                          "Отсутствие совпадений не подтверждает безопасность.")
        self.res_sub.setText(f"{risk_text}  {score_text}  "
                             f"Контроль подписи и хешей: {hc}.  "
                             f"Время проверки: {ev['timing_ms']['total']:.0f} мс."
                             + intel_text + "".join(f"\n⚠ {r}" for r in ev["rules"]))
        for name, (bar, val) in self.level_bars.items():
            v = ev.get("levels", {}).get(name)
            bar.setValue(int(round(100 * v)) if v is not None else 0)
            val.setText(f"{v:.2f}" if v is not None else "—")
            # Для этой страницы высокий эвристический балл означает ближе к норме.
            color = "#1f9d63" if v is not None and v >= 0.7 else (
                "#d99a1c" if v is not None and v >= 0.4 else "#e5484d")
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}")
        self.suspects.setRowCount(0)
        suspects = ev.get("suspects") or []
        for s in suspects:
            add_row(self.suspects, [_component_ru(s["component"]), f"{s['score']:.2f}"])
        if not suspects:
            self.suspects.setRowCount(1)
            self.suspects.setSpan(0, 0, 1, 2)
            message = ("В записи проверки нет данных локализации."
                       if ev.get("analysis_mode") != "reference_missing"
                       else "Локализация недоступна без доверенного эталона.")
            self.suspects.setItem(0, 0, QTableWidgetItem(message))
        if hasattr(self, "loc_card"):
            # Пустую локализацию не показываем: блок появляется только при наличии данных.
            self.loc_card.setVisible(bool(suspects) or ev.get("analysis_mode") == "reference_missing")
        acts = ev.get("actions", [])
        self.actions.setText("<br>".join(f"•&nbsp; {a}" for a in acts) if acts else
                             "<span style='color:#8a8f99'>Действия не требуются: пакет допущен.</span>")
        self._refresh_status()
        if ev.get("verdict") == "BLOCK" and not external_refresh:
            self._auto_block_report(ev)
            self._notify_block(ev)

    def _set_check_context(self, ev):
        """Keep package identity and reference availability visible with the verdict."""
        package = str(ev.get("package") or "Неизвестный пакет")
        version = str(ev.get("version") or "не указана")
        baseline = ev.get("baseline_version")
        mode = ev.get("analysis_mode")
        if mode == "reference_missing" or not baseline:
            reference = "Эталон: отсутствует — сравнительная оценка не выполнена"
        elif mode == "intake_validation_error":
            reference = f"Эталон: {baseline} · проверка не завершена"
        else:
            reference = f"Эталон: {baseline}"
        self.check_context_package.setText(package)
        self.check_context_version.setText(f"Версия объекта: {version}")
        self.check_context_reference.setText(reference)
        self.check_context_reference.setStyleSheet(
            "color: #d99a1c;" if "отсутствует" in reference or "не завершена" in reference else "")
        self.check_context_time.setText(f"Время события: {_when(ev.get('time', ''))}")

    def _auto_block_report(self, ev):
        """При блокировке PDF-отчёт — готовая доказательная база для расследования — сохраняется сам,
        в data/reports/, без отдельного нажатия «PDF-отчёт»."""
        reports_dir = DATA / "reports"

        def job(_):
            from .report import generate
            reports_dir.mkdir(parents=True, exist_ok=True)
            stamp = ev["time"][:19].replace(":", "-").replace("T", "_") if ev.get("time") else time.strftime("%Y%m%d_%H%M%S")
            out = reports_dir / f"block_{ev.get('package', 'package')}_{ev.get('version', '0')}_{stamp}.pdf"
            generate(ev, out)
            return str(out)

        def done(out_path):
            self.notify(f"Пакет заблокирован — отчёт для расследования сохранён сам: {out_path}", "ok")

        self.run_bg(job, done, silent=True)

    def _notify_block(self, ev):
        """Уведомление в трее о блокировке — виден даже если окно программы свёрнуто."""
        tray = getattr(self, "tray", None)
        if tray and tray.isVisible() and QSystemTrayIcon.supportsMessages():
            tray.showMessage("IntegrityGuard: пакет заблокирован",
                             f"{ev.get('package', '?')} {ev.get('version', '')}: {ev.get('threat_ru', '')}",
                             QSystemTrayIcon.Critical, 8000)

    def _export_pdf(self):
        """Экспорт PDF-отчёта по последней проверке."""
        if not self._last_ev:
            self.notify("Сначала выполните проверку пакета.", "warn")
            return
        from PySide6.QtWidgets import QFileDialog
        pkg = self._last_ev.get("package", "report")
        ver = self._last_ev.get("version", "0")
        default = str(DATA / f"report_{pkg}_{ver}.pdf")
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить PDF-отчёт", default, "PDF (*.pdf)")
        if not path:
            return

        def job(_):
            from .report import generate
            return generate(self._last_ev, path)

        def done(out_path):
            self.notify(f"PDF-отчёт сохранён: {out_path}", "ok")

        self.run_bg(job, done, self.pdf_btn)

    def _open_incoming(self):
        self.incoming.mkdir(parents=True, exist_ok=True)
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.incoming)))

    # ------------------------------------------------------------ страница «Эталоны»
    def _page_baselines(self):
        p = Page("Эталоны и версии", "Эталон — доверенное состояние пакета, с которым сравниваются кандидаты. "
                                     "История показывает все проверки и смены версий модели.")
        # ---- главный блок: один осознанный клик — регистрация; подпись, SBOM и таблицы дальше сами ----
        self.b_pkg = PathEdit("Каталог доверенного пакета")
        self.b_ctrl = PathEdit("Контрольный набор .npz (X, y) — нужен для поведенческого уровня", False, "NumPy (*.npz)")
        self.b_idx = PathEdit("Доверенный индекс зависимостей .json (необязательно)", False, "JSON (*.json)")
        btn = QPushButton("Зарегистрировать эталон", objectName="primary")
        btn.setMinimumHeight(40)
        btn.clicked.connect(lambda: self._register(btn))
        g = QGridLayout()
        g.setVerticalSpacing(10)
        g.setHorizontalSpacing(12)
        for i, (name, w) in enumerate((("Пакет", self.b_pkg), ("Контрольный набор", self.b_ctrl), ("Индекс", self.b_idx))):
            g.addWidget(label(name, muted=True), i, 0)
            g.addWidget(w, i, 1)
        self.b_note = label("После регистрации пакет сам подписывается ключом реестра и для него сам "
                            "создаётся SBOM — дополнительно нажимать для этого ничего не нужно.",
                            muted=True, wrap=True)
        hero = QVBoxLayout()
        hero.addLayout(g)
        hero.addWidget(btn, 0, Qt.AlignLeft)
        hero.addWidget(self.b_note)
        p.lay.addWidget(card(hero, title="Новый эталон"))

        # ---- дополнительные параметры: ручная подпись и SBOM по своему пути — скрыты по умолчанию ----
        sign = QPushButton("Подписать пакет ключом реестра")
        sign.setToolTip("Обычно не нужно — подпись создаётся сама после регистрации. "
                        "Пригодится, если нужно подписать пакет повторно вручную.")
        sign.clicked.connect(lambda: self._sign(sign))
        self.sbom_btn = QPushButton("↓ SBOM в свой файл…")
        self.sbom_btn.setToolTip("Обычно не нужно — SBOM сохраняется сам после регистрации. "
                                 "Пригодится, чтобы сохранить его в другое место вручную.")
        self.sbom_btn.clicked.connect(lambda: self._export_sbom(self.sbom_btn))
        b_adv_row = QHBoxLayout()
        b_adv_row.addWidget(sign)
        b_adv_row.addWidget(self.sbom_btn)
        b_adv_row.addStretch(1)
        b_adv_body = QWidget()
        b_adv_lay = QVBoxLayout(b_adv_body)
        b_adv_lay.setContentsMargins(0, 8, 0, 0)
        b_adv_lay.addLayout(b_adv_row)
        b_adv_body.hide()
        self._b_adv_body = b_adv_body
        self.b_adv_toggle = QPushButton("▸  Дополнительные параметры (ручная подпись, SBOM в свой файл)",
                                        objectName="flat")
        self.b_adv_toggle.setCursor(Qt.PointingHandCursor)
        self.b_adv_toggle.clicked.connect(self._toggle_b_adv)
        p.lay.addWidget(card(self.b_adv_toggle, b_adv_body))

        p.lay.addWidget(self._build_wheel_accept_card())

        self.b_table = table(["Пакет", "Версия эталона", "Зависимостей", "Контрольный набор", "Проверок"])
        self.b_table.setMinimumHeight(150)
        self.b_table.itemSelectionChanged.connect(self._load_history)
        self.b_table.itemSelectionChanged.connect(
            lambda: self.b_del_btn.setEnabled(self.b_table.currentRow() >= 0))
        self.h_table = table(["Время (UTC)", "Событие", "Версия", "Вердикт", "Тип угрозы", "Оценка"], 1)
        self.h_table.setMinimumHeight(240)
        b_head = QHBoxLayout()
        b_head.addWidget(label("Зарегистрированные эталоны", "h2"), 1)
        self.b_del_btn = QPushButton("Удалить эталон")
        self.b_del_btn.setToolTip("Удаляет выбранный эталон из реестра (подпись, SBOM и историю версий — "
                                  "сам пакет на диске, из которого он был зарегистрирован, не трогается). "
                                  "Полезно, если эталон был зарегистрирован по ошибке.")
        self.b_del_btn.setEnabled(False)
        self.b_del_btn.clicked.connect(self._delete_baseline)
        b_head.addWidget(self.b_del_btn)
        b_head_w = QWidget()
        b_head_w.setLayout(b_head)
        p.lay.addWidget(card(b_head_w, self.b_table))
        p.lay.addWidget(card(self.h_table, title="История версий и проверок"))
        p.lay.addStretch(1)
        return p

    def _delete_baseline(self):
        """Удаляет из реестра эталон, выбранный в таблице — например, если он был зарегистрирован по
        ошибке. Требует подтверждения: действие нельзя отменить."""
        r = self.b_table.currentRow()
        if r < 0:
            return
        name = self.b_table.item(r, 0).text()
        box = QMessageBox(QMessageBox.Question, "IntegrityGuard",
                          f"Удалить эталон «{name}» из реестра? История проверок по нему будет потеряна. "
                          "Пакет на диске, из которого он был зарегистрирован, не затрагивается.",
                          QMessageBox.Yes | QMessageBox.No, self)
        box.button(QMessageBox.Yes).setText("Удалить")
        box.button(QMessageBox.No).setText("Отмена")
        if box.exec() != QMessageBox.Yes:
            return
        shutil.rmtree(Path(self.cfg("registry")) / "baselines" / name, ignore_errors=True)
        self.settings.sync()
        self.notify(f"Эталон «{name}» удалён из реестра.", "ok")
        self._refresh_views()

    def _toggle_b_adv(self):
        """Разворачивает/сворачивает ручные подпись и SBOM — по умолчанию скрыты, так как после регистрации
        эталона и то, и другое программа делает сама."""
        show = not self._b_adv_body.isVisible()
        self._b_adv_body.setVisible(show)
        self.b_adv_toggle.setText(("▾  " if show else "▸  ") + "Дополнительные параметры (ручная подпись, SBOM в свой файл)")

    def _register(self, btn):
        """Один осознанный клик: при необходимости пакет сначала сам подписывается ключом реестра (без этого
        регистрация эталона не разрешена политикой безопасности), затем регистрируется как эталон, и для
        него сам сохраняется SBOM — отдельных кликов «Подписать» и «SBOM» для этого не нужно."""
        pkg, ctrl, idx = self.b_pkg.text(), self.b_ctrl.text() or None, self.b_idx.text() or None
        if not pkg or not (Path(pkg) / "manifest.json").exists():
            self.notify("Укажите каталог доверенного пакета, содержащий manifest.json.", "warn")
            return

        def job(_):
            from .collect import load_package
            from .sbom import export_sbom, sbom_summary
            g = self.guard()
            signed_now = False
            spec = load_package(pkg, g.key)
            if g.key is None or not spec.signed_ok:
                g.sign(pkg)                               # подпись нужна до регистрации — делаем её сами
                signed_now = True
            name = g.register_baseline(pkg, ctrl, idx)
            sbom_dir = DATA / "sbom"
            sbom_dir.mkdir(parents=True, exist_ok=True)
            sbom_path = sbom_dir / f"{name}.json"
            sbom = export_sbom(load_package(pkg, None), pkg, str(sbom_path))
            return name, signed_now, str(sbom_path), sbom_summary(sbom)

        def done(res):
            name, signed_now, sbom_path, summary = res
            self._load_baselines()
            self._refresh_status()
            prefix = "Пакет подписан ключом реестра. " if signed_now else ""
            self.notify(f"Эталон пакета «{name}» зарегистрирован. {prefix}SBOM сохранён: {sbom_path}\n{summary}", "ok")

        self.run_bg(job, done, btn)

    # ------------------------------------------------------------ принятие wheel-эталона (P1)
    def _build_wheel_accept_card(self):
        self._wheel_proposal = None
        self.w_file = PathEdit("Файл wheel (.whl) — реальный файл с PyPI", False, "Wheel (*.whl)")
        self.w_source = QLineEdit()
        self.w_source.setPlaceholderText("Страница пакета на PyPI, например https://pypi.org/project/имя/")
        self.w_prov = QLineEdit()
        self.w_prov.setPlaceholderText("Основание: ссылка на запись PyPI или другой реестр")
        self.w_operator = QLineEdit()
        self.w_operator.setPlaceholderText("Ваше имя или логин — попадает в журнал решений")
        self.w_check = QPushButton("Проверить по PyPI", objectName="primary")
        self.w_check.setMinimumHeight(36)
        self.w_check.clicked.connect(lambda: self._wheel_propose(self.w_check))
        self.w_result = label("Проверка не выполнялась. Пока файл не проверен, доверие не выдаётся.",
                              muted=True, wrap=True)
        self.w_result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.w_replace = QCheckBox("Заменить эталон другой версии этого пакета")
        self.w_replace.hide()
        self.w_accept = QPushButton("Принять эталон", objectName="primary")
        self.w_accept.setEnabled(False)
        self.w_accept.clicked.connect(lambda: self._wheel_decide("accept", self.w_accept))
        self.w_reject = QPushButton("Отклонить")
        self.w_reject.setEnabled(False)
        self.w_reject.clicked.connect(lambda: self._wheel_decide("reject", self.w_reject))
        self.w_file.picked.connect(self._wheel_reset)
        self.w_source.textChanged.connect(self._wheel_reset)
        self.w_prov.textChanged.connect(self._wheel_reset)
        g = QGridLayout()
        g.setVerticalSpacing(10)
        g.setHorizontalSpacing(12)
        for i, (name, w) in enumerate((("Файл", self.w_file), ("Источник", self.w_source),
                                       ("Основание", self.w_prov), ("Оператор", self.w_operator))):
            g.addWidget(label(name, muted=True), i, 0)
            g.addWidget(w, i, 1)
        buttons = QHBoxLayout()
        buttons.addWidget(self.w_check)
        buttons.addStretch(1)
        buttons.addWidget(self.w_reject)
        buttons.addWidget(self.w_accept)
        body = QVBoxLayout()
        body.addLayout(g)
        body.addLayout(buttons)
        body.addWidget(self.w_result)
        body.addWidget(self.w_replace)
        note = label("Эталон принимается только если PyPI подтвердил точный файл по SHA-256. "
                     "Решение и причины отказа записываются в журнал с цепочкой хешей.", muted=True, wrap=True)
        body.addWidget(note)
        return card(body, title="Принять wheel-эталон по PyPI")

    def _wheel_reset(self, *_):
        self._wheel_proposal = None
        self.w_accept.setEnabled(False)
        self.w_reject.setEnabled(False)
        self.w_replace.hide()
        self.w_replace.setChecked(False)
        self.w_result.setText("Проверка не выполнялась или входные данные изменились. Нужна новая проверка.")

    def _wheel_propose(self, btn):
        wheel = self.w_file.text().strip()
        source, prov = self.w_source.text().strip(), self.w_prov.text().strip()
        if not wheel or not wheel.lower().endswith(".whl"):
            self.notify("Выберите файл wheel (.whl).", "warn")
            return
        if not source or not prov:
            self.notify("Укажите источник (страница PyPI) и основание.", "warn")
            return
        registry = Path(self.cfg("registry"))

        def job(_):
            from .baseline_acceptance import propose
            return propose(wheel, registry, source_url=source, provenance_ref=prov)

        def done(proposal):
            self._wheel_proposal = proposal
            self._wheel_show(proposal)

        self.run_bg(job, done, btn)

    def _wheel_show(self, p):
        lines = [f"Пакет: {p['name']} {p['version']}",
                 f"SHA-256 файла: {p['artifact_sha256']}"]
        verification = p.get("verification")
        if verification:
            lines.append(f"PyPI подтвердил точный файл (метаданные SHA-256 {verification['metadata_sha256'][:16]}…, "
                         f"загружен {verification.get('uploaded_at') or 'дата не указана'}).")
        for reason in p.get("reasons", []):
            lines.append("Причина: " + reason)
        if p.get("replaces_versions"):
            lines.append("Заменит эталоны версий: " + ", ".join(p["replaces_versions"]))
        lines.append(p.get("meaning", ""))
        self.w_result.setText("\n".join(line for line in lines if line))
        self.w_accept.setEnabled(bool(p.get("can_accept")))
        self.w_reject.setEnabled(True)
        self.w_replace.setVisible(bool(p.get("replaces_versions")))
        self.w_replace.setChecked(False)
        self.w_accept.setToolTip("" if p.get("can_accept") else "Эталон нельзя принять: см. причины выше")

    def _wheel_decide(self, decision, btn):
        p = self._wheel_proposal
        wheel = self.w_file.text().strip()
        operator = self.w_operator.text().strip()
        if p is None:
            self.notify("Сначала выполните проверку по PyPI.", "warn")
            return
        if not operator:
            self.notify("Укажите оператора: кто принимает решение.", "warn")
            return
        replace = self.w_replace.isChecked()
        registry = Path(self.cfg("registry"))

        def job(_):
            from .baseline_acceptance import accept
            return accept(p, wheel, registry, operator=operator, decision=decision,
                          replace_existing=replace)

        def done(manifest):
            self._wheel_reset()
            if decision == "accept" and manifest:
                self._load_baselines()
                self.notify(f"Эталон принят: {manifest['name']} {manifest['version']}. "
                            "Решение записано в журнал.", "ok")
            else:
                self.notify("Решение «отклонить» записано в журнал. Эталон не создан.", "info")

        self.run_bg(job, done, btn)

    def _sign(self, btn):
        pkg = self.b_pkg.text()
        if not pkg:
            self.notify("Укажите каталог пакета.", "warn")
            return
        self.run_bg(lambda _: self.guard().sign(pkg),
                    lambda _: self.notify("Пакет подписан ключом реестра.", "ok"), btn)

    def _export_sbom(self, btn):
        """Экспорт SBOM для выбранного эталонного пакета."""
        from PySide6.QtWidgets import QFileDialog
        pkg_path = self.b_pkg.text()
        if not pkg_path or not (Path(pkg_path) / "manifest.json").exists():
            self.notify("Укажите каталог пакета в поле «Пакет».", "warn")
            return
        default = str(DATA / "sbom_export.json")
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить SBOM", default, "JSON (*.json)")
        if not path:
            return

        def job(_):
            from .collect import load_package
            from .sbom import export_sbom, sbom_summary
            spec = load_package(pkg_path, None)
            sbom = export_sbom(spec, pkg_path, path)
            return sbom_summary(sbom)

        def done(summary):
            self.notify(f"SBOM сохранён: {path}\n{summary}", "ok")

        self.run_bg(job, done, btn)

    def _history(self, name):
        f = Path(self.cfg("registry")) / "baselines" / name / "history.jsonl"
        out = []
        for line in (f.read_text(encoding="utf-8", errors="replace").splitlines() if f.exists() else []):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def _load_baselines(self):
        self.b_table.setSortingEnabled(False)             # на время перестройки — иначе Qt путает порядок вставки
        self.b_table.setRowCount(0)
        for name in self._baseline_names():
            base = Path(self.cfg("registry")) / "baselines" / name
            try:
                man = json.loads((base / "package" / "manifest.json").read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            checks = sum(1 for h in self._history(name) if h.get("event") == "check")
            add_row(self.b_table, [name, man["version"], len(man.get("dependencies", [])),
                                   "есть" if (base / "control.npz").exists() else "нет", checks])
        self.b_table.setSortingEnabled(True)               # удобно сортировать по столбцу кликом на заголовок
        if self.b_table.rowCount():
            self.b_table.selectRow(0)
        else:
            self.h_table.setRowCount(0)
            self.b_del_btn.setEnabled(False)

    def _load_history(self):
        self.h_table.setSortingEnabled(False)
        self.h_table.setRowCount(0)
        r = self.b_table.currentRow()
        if r < 0:
            self.h_table.setSortingEnabled(True)
            return
        for h in reversed(self._history(self.b_table.item(r, 0).text())):
            if h.get("event") == "check" and h.get("verdict") in VERDICT:
                text, color = VERDICT[h["verdict"]]
                threat_text, _ = _threat_detail(h["threat"])
                add_row(self.h_table, [h["time"][:19].replace("T", " "), f"проверка ({STAGE_RU.get(h.get('stage'), h.get('stage', ''))})", h["version"], text,
                                       threat_text, _num(h.get("score"))], color, 3)
            else:
                add_row(self.h_table, [h.get("time", "")[:19].replace("T", " "), f"эталон ({h.get('note', '')})",
                                       h.get("version", ""), "", "", ""])
        self.h_table.setSortingEnabled(True)               # удобно сортировать по столбцу кликом на заголовок

    # ------------------------------------------------------------ страница «Журнал»
    def _page_events(self):
        p = Page("Журнал событий", "События, признаки и подтверждённые метки связаны в evidence.sqlite. "
                                   "events.jsonl остаётся совместимым источником для SIEM/SOC.")
        self.e_table = table(["Время (UTC)", "Пакет", "Версия", "Стадия", "Вердикт", "Тип угрозы", "Оценка", "Хеш-контроль"], 1)
        self.e_table.setMinimumHeight(330)
        self.e_table.itemSelectionChanged.connect(self._event_detail)
        self.e_detail = QPlainTextEdit(readOnly=True)
        self.e_detail.setMinimumHeight(220)
        self.e_path = label("", muted=True)
        self.e_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.e_auto_note = label(self._auto_note_text, muted=True)
        self.e_filter = QLineEdit(placeholderText="Фильтр по имени пакета…")
        self.e_filter.setClearButtonEnabled(True)
        self.e_filter.setMaximumWidth(260)
        self.e_filter.textChanged.connect(lambda _: self._load_events(keep_selection=True))
        self.e_period_from = QDateEdit(calendarPopup=True, displayFormat="dd.MM.yyyy")
        self.e_period_from.setDate(QDate.currentDate().addDays(-30))
        self.e_period_from.setToolTip("Начало периода, включительно (дата UTC)")
        self.e_period_to = QDateEdit(calendarPopup=True, displayFormat="dd.MM.yyyy")
        self.e_period_to.setDate(QDate.currentDate())
        self.e_period_to.setToolTip("Конец периода, включительно (дата UTC)")
        self.e_period_btn = QPushButton("PDF за период")
        self.e_period_btn.clicked.connect(self._export_period_pdf)
        row = QHBoxLayout()
        row.addWidget(self.e_path, 1)
        row.addWidget(self.e_filter)
        row.addWidget(label("UTC с"))
        row.addWidget(self.e_period_from)
        row.addWidget(label("по"))
        row.addWidget(self.e_period_to)
        row.addWidget(self.e_period_btn)
        row.addWidget(self.e_auto_note)
        self.ev_verdict_chart = VerdictBars()
        self.ev_verdict_chart.empty_text = "Нет событий с меткой времени в текущей выборке."
        self.ev_threat_chart = HBars()
        self.ev_threat_chart.empty_text = "Событий в текущей выборке пока нет."
        two = QHBoxLayout()
        two.addWidget(card(self.ev_verdict_chart, title="Вердикты во времени (текущая выборка)"), 3)
        two.addWidget(card(self.ev_threat_chart, title="По типу угрозы (текущая выборка)"), 2)
        p.lay.addLayout(two)
        p.lay.addWidget(card(row, self.e_table))
        p.lay.addWidget(card(self.e_detail, title="Событие целиком (JSON)"))
        p.lay.addStretch(1)
        return p

    def _export_period_pdf(self):
        start_date = self.e_period_from.date().toString("yyyy-MM-dd")
        end_date = self.e_period_to.date().toString("yyyy-MM-dd")
        if end_date < start_date:
            self.notify("Конец периода не может быть раньше его начала.", "error")
            return
        default = str(DATA / f"events_{start_date}_{end_date}.pdf")
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить сводный отчёт", default, "PDF (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        registry = Path(self.cfg("registry"))

        def job(_):
            from .evidence import EvidenceStore
            from .report import generate_period
            store = EvidenceStore(registry / "evidence.sqlite")
            store.backfill_jsonl(registry / "events.jsonl", registry / "events.archive.jsonl")
            return generate_period(store.read_events(), path, start_date, end_date)

        self.run_bg(job, lambda out: self.notify(f"Сводный PDF за период сохранён: {out}", "ok"),
                    self.e_period_btn)

    def _load_events(self, keep_selection=False):
        """keep_selection=True — для автообновления и для фильтра: не сбивать просмотр уже выбранного
        события, когда в журнал само дописывается новая строка или меняется текст фильтра.

        Событие каждой строки хранится в данных её первой ячейки (Qt.UserRole) — так выбор и детали
        остаются верными независимо от порядка строк после сортировки кликом на заголовок столбца."""
        prev_time = None
        if keep_selection:
            it = self.e_table.item(self.e_table.currentRow(), 0) if self.e_table.currentRow() >= 0 else None
            if it:
                prev_time = (it.data(Qt.UserRole) or {}).get("time")
        f = Path(self.cfg("registry")) / "events.jsonl"
        self.e_path.setText(f"Файл журнала: {f}")
        self.events = self._read_events()[-500:][::-1]
        needle = self.e_filter.text().strip().lower()
        shown = [ev for ev in self.events if not needle or needle in ev.get("package", "").lower()]
        self.ev_verdict_chart.set_events(shown)
        threat_counts: dict[str, int] = {}
        for ev in shown:
            key = _threat_detail(ev.get("threat"))[0]
            threat_counts[key] = threat_counts.get(key, 0) + 1
        self.ev_threat_chart.set_rows(sorted(threat_counts.items(), key=lambda kv: -kv[1])[:12])
        self.e_table.setSortingEnabled(False)              # на время перестройки — иначе Qt путает порядок вставки
        self.e_table.setRowCount(0)
        for ev in shown:
            text, color = VERDICT[ev["verdict"]]
            threat_text, threat_tip = _threat_detail(ev.get("threat"), ev.get("suspects"))
            add_row(self.e_table, [ev["time"][:19].replace("T", " "), ev["package"], ev["version"],
                                   STAGE_RU.get(ev.get("stage"), ev.get("stage", "")), text,
                                   threat_text, _num(ev.get("score")),
                                   ("не оценивался" if ev.get("hash_control") is None else
                                    "нарушение" if ev.get("hash_control") else "норма")], color, 4, tips={5: threat_tip})
            self.e_table.item(self.e_table.rowCount() - 1, 0).setData(Qt.UserRole, ev)
        self.e_table.setSortingEnabled(True)               # удобно сортировать по столбцу кликом на заголовок
        if not shown:
            self.e_detail.setPlainText("Событий пока нет." if not self.events else
                                       "Ничего не найдено по фильтру.")
            return
        target = next((row for row in range(self.e_table.rowCount())
                      if (self.e_table.item(row, 0).data(Qt.UserRole) or {}).get("time") == prev_time), 0)
        self.e_table.selectRow(target)

    def _event_detail(self):
        r = self.e_table.currentRow()
        it = self.e_table.item(r, 0) if r >= 0 else None
        ev = it.data(Qt.UserRole) if it else None
        self.e_detail.setPlainText(json.dumps(ev, ensure_ascii=False, indent=2) if ev else "")

    # ------------------------------------------------------------ страница «Полнота обнаружения»
    def _page_recall(self):
        p = Page("Полнота обнаружения", "Метрики показываются только для независимой реальной выборки с проверенными "
                 "метками. Синтетические пакеты и показатели в эксплуатационной оценке отключены.")
        self.r_retrain_text = label("", wrap=True)
        retrain_btn = QPushButton("Открыть «Обучение и оценка»")
        retrain_btn.clicked.connect(lambda: self.nav.button(self._page_index("Обучение и оценка")).click())
        rw_row = QHBoxLayout()
        rw_row.addWidget(self.r_retrain_text, 1)
        rw_row.addWidget(retrain_btn)
        self.r_retrain_banner = card(rw_row)
        self.r_retrain_banner.hide()
        p.lay.addWidget(self.r_retrain_banner)
        self.r_btn = QPushButton("Нужна независимая реальная выборка", objectName="primary")
        self.r_btn.clicked.connect(self._measure_recall)
        self.r_btn.setEnabled(False)
        self.r_bar = QProgressBar()
        self.r_bar.setTextVisible(False)
        self.r_bar.setRange(0, 100)
        self.r_note = label("", muted=True, wrap=True)
        row = QHBoxLayout()
        row.addWidget(self.r_btn)
        row.addWidget(self.r_bar, 1)
        p.lay.addWidget(card(row, self.r_note, title="Расчёт"))
        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        self.r_tiles = {}
        for key, name in (("test", "Полнота: реальная контрольная выборка"),
                          ("hash", "Контроль подписи и хешей")):
            val = label("—")
            val.setStyleSheet("font-size: 22pt; font-weight: 600;")
            sub = label("", muted=True)
            self.r_tiles[key] = (val, sub)
            tiles.addWidget(tile(label(name, muted=True), val, sub), 1)
        p.lay.addLayout(tiles)
        self.ch_recall = GroupBars()
        self.ch_recall.empty_text = "Метрики появятся после независимой проверки на реальных пакетах."
        p.lay.addWidget(card(self.ch_recall, title="Полнота по классам угроз"))
        self.r_class = table(["Класс угрозы", "Уровень", "Образцов", "Полнота", "Контроль подписи/хешей"])
        self.r_class.setFixedHeight(214)
        p.lay.addWidget(card(self.r_class, title="По классам угроз"))
        self.r_level = table(["Уровень целостности", "Образцов", "Полнота"])
        self.r_level.setFixedHeight(154)
        p.lay.addWidget(card(self.r_level, title="По уровням целостности"))
        self.r_method = table(["Метод обнаружения", "Полнота на тестовой выборке"])
        self.r_method.setFixedHeight(214)
        p.lay.addWidget(card(self.r_method, title="По методам (гибридная сеть, её отдельные ветви и контроль хешей)"))
        p.lay.addStretch(1)
        return p

    def _measure_recall(self):
        self.notify("Расчёт отключён до подключения независимой реальной выборки с проверенными метками. "
                    "Синтетические пакеты для метрик не используются.", "warn")

    def _load_recall(self):
        raw, test = {}, None
        try:
            metrics_path = Path(self.cfg("model")).parent / "metrics.json"
            raw = json.loads(metrics_path.read_text(encoding="utf-8-sig")) if metrics_path.is_file() else {}
            if raw.get("dataset_kind") == "real_independent":
                test = R.from_metrics(raw)
        except (OSError, ValueError, KeyError, TypeError):
            raw, test = {}, None

        self.r_method.setSortingEnabled(False)
        self.r_method.setRowCount(0)
        for name, key in (("Гибридный детектор", "hybrid"), ("Только граф", "only_graph"),
                          ("Автокодировщик весов", "only_autoencoder"),
                          ("Поведенческий классификатор", "only_behavior"),
                          ("Контроль подписи и хешей", "hash_baseline")):
            score = (raw.get(key) or {}).get("binary", {}).get("recall") if test else None
            if isinstance(score, (int, float)):
                add_row(self.r_method, [name, f"{100 * score:.1f} %"])
        self.r_method.setSortingEnabled(True)

        pct = lambda value: f"{100 * value:.1f} %" if isinstance(value, (int, float)) else "—"
        overall = (test or {}).get("overall")
        self.r_tiles["test"][0].setText(pct(overall.get("recall")) if overall else "—")
        self.r_tiles["test"][1].setText(
            f"{overall['detected']} из {overall['n']} реальных образцов" if overall else
            "независимая размеченная выборка не подключена")
        self.r_tiles["hash"][0].setText(pct(overall.get("hash_recall")) if overall else "—")
        self.r_tiles["hash"][1].setText("на тех же независимых данных" if overall else "не измерено")

        if overall and isinstance(overall.get("recall"), (int, float)) \
                and overall["recall"] < RETRAIN_RECALL_THRESHOLD:
            self.r_retrain_text.setText(
                f"Полнота на независимых реальных данных — {100 * overall['recall']:.1f} %, "
                f"ниже порога {100 * RETRAIN_RECALL_THRESHOLD:.0f} %. Требуется анализ корпуса и модели.")
            self.r_retrain_banner.show()
        else:
            self.r_retrain_banner.hide()

        self.r_class.setSortingEnabled(False)
        self.r_class.setRowCount(0)
        for cls in R.THREATS:
            row = (test or {}).get("per_class", {}).get(cls)
            add_row(self.r_class, [CLASS_RU[cls], LEVEL_RU[CLASS_LEVEL[cls]],
                                   row.get("n", "—") if row else "—",
                                   pct(row.get("recall")) if row else "—",
                                   pct(row.get("hash_recall")) if row else "—"])
        self.r_class.setSortingEnabled(True)

        self.r_level.setSortingEnabled(False)
        self.r_level.setRowCount(0)
        for level in LEVELS:
            row = (test or {}).get("per_level", {}).get(level)
            add_row(self.r_level, [LEVEL_RU[level], row.get("n", "—") if row else "—",
                                   pct(row.get("recall")) if row else "—"])
        self.r_level.setSortingEnabled(True)

        short = dict(THREAT_SHORT, poison="отравление")
        series = []
        if test:
            series = [("Детектор, независимая реальная выборка", ACCENT,
                       [test["per_class"][cls]["recall"] for cls in R.THREATS]),
                      ("Подпись и хеши", SECOND,
                       [test["per_class"][cls]["hash_recall"] for cls in R.THREATS])]
        self.ch_recall.set_data([short[cls] for cls in R.THREATS] if series else [], series)
        self.r_btn.setText("Независимая реальная выборка подключена" if test else
                           "Нужна независимая реальная выборка")
        self.r_note.setText("Показаны только метрики с dataset_kind=real_independent. Синтетические наборы, "
                            "демо-метрики и рассчитанные по ним показатели не загружаются. "
                            + ("Метрики относятся к указанному набору и не заменяют проверку происхождения разметки."
                               if test else "Качество детектора на реальных угрозах пока не измерено."))

    # ------------------------------------------------------------ страница «Обучение»
    def _page_train(self):
        p = Page("Обучение и оценка", "Эксплуатационное обучение приостановлено до подключения реального корпуса "
                                      "с подтверждённой разметкой и независимым тестовым разделом.")
        self.t_projects = QSpinBox(minimum=10, maximum=1000, value=60, singleStep=10)
        self.t_epochs = QSpinBox(minimum=10, maximum=300, value=70, singleStep=10)
        self.t_fpr = QDoubleSpinBox(minimum=0.005, maximum=0.2, value=0.02, singleStep=0.005, decimals=3)
        for control in (self.t_projects, self.t_epochs, self.t_fpr):
            control.setEnabled(False)
        self.t_abl = QCheckBox("Сравнить с отдельными ветвями (абляция)")
        self.t_abl.setChecked(True)
        self.t_btn = QPushButton("Сформировать корпус и обучить", objectName="primary")
        self.t_btn.clicked.connect(self._train)
        self.t_bar = QProgressBar()
        self.t_bar.setRange(0, 100)
        self.t_bar.setTextVisible(False)
        self.t_note = label("Автоматическое обучение отключено: сейчас доступны только синтетические примеры. "
                            "Нужен проверенный реальный корпус с подтверждённой разметкой.", muted=True, wrap=True)
        self.t_btn.setEnabled(False)
        self.t_abl.setEnabled(False)
        g = QGridLayout()
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(10)
        for i, (name, w) in enumerate((("Проектов в корпусе", self.t_projects), ("Эпох обучения", self.t_epochs),
                                       ("Допустимая доля ложных срабатываний", self.t_fpr))):
            g.addWidget(label(name, muted=True), 0, 2 * i)
            g.addWidget(w, 0, 2 * i + 1)
        g.setColumnStretch(6, 1)
        row = QHBoxLayout()
        row.addWidget(self.t_btn)
        row.addWidget(self.t_abl)
        row.addStretch(1)
        p.lay.addWidget(card(g, row, self.t_bar, self.t_note, title="Новый цикл обучения"))
        self.label_coverage_note = label("", muted=True, wrap=True)
        self.label_coverage_chart = HBars()
        self.label_coverage_chart.empty_text = "Карточек свидетельств пока не импортировано."
        self.label_coverage_table = table(["Класс", "Предложено", "Подтверждено", "Оценка качества"], 0)
        self.label_coverage_table.setMinimumHeight(310)
        p.lay.addWidget(card(self.label_coverage_note, self.label_coverage_chart, self.label_coverage_table,
                             title="Покрытие классов реальными свидетельствами"))
        self._load_label_coverage()
        self.t_log = QPlainTextEdit(readOnly=True)
        self.t_log.setFixedHeight(150)
        self.t_log_card = card(self.t_log, title="Ход обучения")
        self.t_log_card.hide()
        p.lay.addWidget(self.t_log_card)
        self.m_caption = label("", muted=True, wrap=True)
        self.m_table = table(["Метод", "Accuracy", "Precision", "F1", "Ложные срабатывания", "AUC"])
        self.m_table.setFixedHeight(214)
        self.ch_conf = Heatmap()
        self.m_files = label("", muted=True, wrap=True)
        self.m_files.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.lay.addWidget(card(self.m_caption, self.m_table, title="Показатели текущего детектора (тестовая выборка)"))
        self.m_img_card = QWidget()
        row = QHBoxLayout(self.m_img_card)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        row.addWidget(card(self.ch_conf, title="Матрица ошибок гибридного детектора"), 3)
        to_recall = QPushButton("Открыть страницу «Полнота обнаружения»")
        to_recall.clicked.connect(lambda: self.nav.button(self._page_index("Полнота обнаружения")).click())
        side = card(label("Полнота обнаружения (Recall) по классам угроз и уровням целостности рассчитывается и "
                          "показывается отдельно — на странице «Полнота обнаружения».", muted=True, wrap=True), to_recall,
                    title="Полнота")
        side.layout().addStretch(1)
        row.addWidget(side, 2)
        p.lay.addWidget(self.m_img_card)
        p.lay.addWidget(self.m_files)
        self.candidate_eval_box = QComboBox()
        self.candidate_eval_manifest = PathEdit("Манифест независимой реальной выборки", folder=False,
                                                filt="JSON (*.json)")
        self.candidate_eval_btn = QPushButton("Оценить кандидата")
        self.candidate_eval_btn.clicked.connect(self._evaluate_selected_candidate)
        self.candidate_promote_btn = QPushButton("Активировать допущенного кандидата", objectName="primary")
        self.candidate_promote_btn.setToolTip("Перед заменой активной модели оценка запускается повторно; создаётся резервная копия.")
        self.candidate_promote_btn.clicked.connect(self._promote_selected_candidate)
        self.candidate_rollback_btn = QPushButton("Откатить последнюю активацию")
        self.candidate_rollback_btn.clicked.connect(self._rollback_active_candidate)
        self.candidate_eval_note = label("Нужны реальные данные с подтверждёнными метками, "
                                         "источниками и без пересечения с обучающими примерами. "
                                         "Оценка не активирует кандидата.", muted=True, wrap=True)
        self._refresh_candidate_options()
        candidate_row = QHBoxLayout()
        candidate_row.addWidget(self.candidate_eval_box, 1)
        candidate_row.addWidget(self.candidate_eval_btn)
        candidate_actions = QHBoxLayout()
        candidate_actions.addWidget(self.candidate_promote_btn)
        candidate_actions.addWidget(self.candidate_rollback_btn)
        candidate_actions.addStretch(1)
        p.lay.addWidget(card(candidate_row, self.candidate_eval_manifest, self.candidate_eval_note,
                             candidate_actions,
                             title="Независимая оценка кандидата"))
        p.lay.addStretch(1)
        self._load_metrics()
        return p

    def _load_label_coverage(self):
        from .label_registry import LabelRegistry
        try:
            coverage = LabelRegistry(DATA / "label_registry.sqlite").coverage()
        except Exception as error:
            self.label_coverage_table.setRowCount(0)
            self.label_coverage_chart.set_rows([])
            self.label_coverage_note.setText(f"Не удалось прочитать реестр разметки: {error}")
            return
        self.label_coverage_chart.set_rows([(CLASS_RU[name], coverage["classes"][name]["proposed_cases"])
                                            for name in CLASSES])
        self.label_coverage_table.setSortingEnabled(False)
        self.label_coverage_table.setRowCount(0)
        for name in CLASSES:
            row = coverage["classes"][name]
            add_row(self.label_coverage_table, [CLASS_RU[name], str(row["proposed_cases"]),
                                              str(row["verified_cases"]), "не оценена"])
        self.label_coverage_note.setText(
            f"Карточек: {coverage['cases']}; инцидентов: {coverage['incidents']}. "
            "Предложенная метка не является подтверждённой. Свидетельства инцидента "
            "не заменяют проверенные артефакты и обучающие признаки.")

    def _refresh_candidate_options(self):
        if not hasattr(self, "candidate_eval_box"):
            return
        selected = self.candidate_eval_box.currentData()
        self.candidate_eval_box.clear()
        candidates = DATA / "models" / "candidates"
        manifests = sorted(candidates.glob("*/candidate.json")) if candidates.exists() else []
        for manifest in manifests:
            status = "unknown"
            try:
                item = json.loads(manifest.read_text(encoding="utf-8"))
                candidate_id = str(item.get("candidate_id", manifest.parent.name))
                status = str(item.get("status", status))
            except (OSError, ValueError):
                candidate_id = manifest.parent.name
            self.candidate_eval_box.addItem(f"{candidate_id} · {status}", candidate_id)
        index = self.candidate_eval_box.findData(selected)
        if index >= 0:
            self.candidate_eval_box.setCurrentIndex(index)
        self.candidate_eval_btn.setEnabled(self.candidate_eval_box.count() > 0)
        index = self.candidate_eval_box.currentIndex()
        candidate_status = self.candidate_eval_box.itemText(index).split(" · ", 1)[-1] if index >= 0 else ""
        self.candidate_promote_btn.setEnabled(candidate_status == "release_eligible")
        release_state = DATA / "models" / "release_state.json"
        rollback_allowed = False
        try:
            state = json.loads(release_state.read_text(encoding="utf-8"))
            rollback_allowed = state.get("action") == "promote" and state.get("status") == "committed"
        except (OSError, ValueError):
            pass
        self.candidate_rollback_btn.setEnabled(rollback_allowed)

    def _evaluate_selected_candidate(self):
        candidate_id = self.candidate_eval_box.currentData()
        evaluation_manifest = self.candidate_eval_manifest.text()
        if not candidate_id or not evaluation_manifest:
            self.notify("Выберите кандидата и манифест независимой оценки.", "error")
            return

        def job(_):
            from .candidate_eval import evaluate_candidate
            return evaluate_candidate(DATA, str(candidate_id), evaluation_manifest)

        def done(result):
            status = "КРИТЕРИИ ВЫПОЛНЕНЫ" if result["release_eligible"] else "КРИТЕРИИ НЕ ВЫПОЛНЕНЫ"
            metrics = result["candidate_metrics"]
            self.candidate_eval_note.setText(
                f"{status}. N={result['n']}; Recall={metrics['recall']:.3f}; "
                f"FPR={metrics['fpr']:.3f}; верхняя 95% граница FPR="
                f"{result['decision']['candidate_fpr_upper_95']:.3f}. Рабочая модель не изменена.")
            self._refresh_candidate_options()

        self.run_bg(job, done, self.candidate_eval_btn)

    def _promote_selected_candidate(self):
        candidate_id = self.candidate_eval_box.currentData()
        if not candidate_id:
            return

        def job(_):
            from .release import promote_candidate
            return promote_candidate(DATA, str(candidate_id), self.cfg("model"))

        def done(state):
            self._guard = None
            self.candidate_eval_note.setText(
                f"Кандидат {state['candidate_id']} активирован после повторной независимой оценки. "
                f"Резервная копия: {state['backup_path']}")
            self._refresh_candidate_options()
            self.notify("Новая модель активирована; резервная копия готова для отката.", "ok")

        self.run_bg(job, done, self.candidate_promote_btn)

    def _rollback_active_candidate(self):
        def job(_):
            from .release import rollback_candidate
            return rollback_candidate(DATA, self.cfg("model"))

        def done(state):
            self._guard = None
            self._refresh_candidate_options()
            self.candidate_eval_note.setText(
                f"Предыдущая модель восстановлена. Текущий SHA-256: {state['candidate_sha256']}")
            self.notify("Откат модели завершён и подтверждён по SHA-256.", "ok")

        self.run_bg(job, done, self.candidate_rollback_btn)

    def _recover_release_if_needed(self):
        # Recovery verifies hashes and may read large checkpoints; keep it off the UI thread
        # so a stale/interrupted release journal cannot make the window appear frozen.
        def recover(_progress):
            from .release import recover_release
            return recover_release(DATA, self.cfg("model"))

        def recovered(result):
            if isinstance(result, dict) and result.get("error"):
                self.notify(f"Не удалось проверить незавершённую операцию выпуска: {result['error']}", "error")
                return
            state = result
            if state and state.get("status") == "needs_review":
                self.notify("После сбоя модель не совпала с ожидаемыми хешами выпуска. Выпуск остановлен; "
                            "проверьте резервные копии и журнал релизов.", "error")
            elif state and state.get("recovered_after_crash"):
                self.notify(f"Восстановлено состояние операции выпуска: {state['status']}.", "info")

        def failed(message):
            self.notify(f"Не удалось проверить незавершённую операцию выпуска: {message}", "error")

        worker = Worker(recover, self)
        worker.done.connect(recovered)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        self._workers.append(worker)
        worker.start()

    def _load_metrics(self):
        d = Path(self.cfg("model")).parent
        self.m_table.setSortingEnabled(False)
        self.m_table.setRowCount(0)
        f = d / "metrics.json"
        if not f.exists():
            self.m_caption.setText("Показатели появятся после обучения детектора.")
            self.m_img_card.hide()
            self.m_files.setText("")
            self.m_table.setSortingEnabled(True)
            return
        try:
            r = json.loads(f.read_text(encoding="utf-8-sig"))
            s = r["split"]
            r["hybrid"]["binary"], r["hash_baseline"]["binary"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            self.m_caption.setText("Файл metrics.json рядом с детектором повреждён.")
            self.m_img_card.hide()
            self.m_table.setSortingEnabled(True)
            return
        if r.get("dataset_kind") != "real_independent":
            self.m_caption.setText("Поставляемая модель обучена на синтетическом корпусе. Эти метрики не являются "
                                   "оценкой качества на реальных угрозах; независимая реальная выборка отсутствует.")
            self.m_img_card.hide()
            self.m_files.setText("Синтетический отчёт хранится рядом с моделью только для отладки.")
            self.m_table.setSortingEnabled(True)
            return
        self.m_caption.setText(f"Независимая реальная выборка: проектов {s['projects']}; образцов: обучение {s['train']}, "
                               f"валидация {s['val']}, тест {s['test']}.")
        rows = [("Гибридный детектор", r["hybrid"]["binary"]), ("Только граф (GNN)", r.get("only_graph", {}).get("binary")),
                ("Только автокодировщик весов", r.get("only_autoencoder", {}).get("binary")),
                ("Только поведенческий классификатор", r.get("only_behavior", {}).get("binary")),
                ("Контроль подписи и хешей", r["hash_baseline"]["binary"])]
        for name, m in rows:
            if m:
                add_row(self.m_table, [name] + [_num(m.get(k)) for k in ("accuracy", "precision", "f1", "fpr", "auc")])
        self.m_table.setSortingEnabled(True)
        self.ch_conf.set_data([THREAT_TINY[c] for c in CLASSES], r["hybrid"].get("confusion") or [])
        self.m_img_card.show()
        self.m_files.setText(f"Отчёт для печати (report.md, metrics.png, metrics.json) лежит в папке {d}")
        if hasattr(self, "r_class"):
            self._load_recall()

    def _train(self):
        self.notify("Обучение не запущено: синтетические примеры не используются для эксплуатационной модели. "
                    "Сначала требуется корпус реальных пакетов с проверенной разметкой и происхождением.", "warn")

    # ------------------------------------------------------------ страница «Настройки»
    def _page_nn(self):
        p = Page("Нейросеть трафика", "Модель использует опубликованные метки реальных сетевых наборов. "
                                      "Локальные прогнозы не считаются разметкой и не запускают дообучение.")
        self.nn_training_chart = TrainingHistoryChart()
        self.nn_training_status = label("История эпох пока не записана. График появится только при реальном запуске обучения.",
                                         muted=True, wrap=True)
        self.nn_training_progress = QProgressBar()
        self.nn_training_progress.setRange(0, 100)
        self.nn_training_progress.setValue(0)
        self.nn_training_progress.setFormat("нет активного обучения")
        self.nn_training_scheme = QComboBox()
        self.nn_training_scheme.addItem("Последняя схема", None)
        self.nn_training_scheme.currentIndexChanged.connect(self._refresh_nn_training_chart)
        p.lay.addWidget(card(self.nn_training_progress, self.nn_training_scheme, self.nn_training_chart,
                             self.nn_training_status,
                             label("Train loss и Development NLL показаны по левой шкале; нижняя CI полноты "
                                   "на каждом dev-захвате — по правой. Все значения взяты из завершённых эпох. "
                                   "Dev-метрики служат только для выбора кандидата и не являются независимым тестом.",
                                   muted=True, wrap=True),
                             title="Ход обучения нейросети"))
        self._nn_training_history_path = DATA / "network-training-history.jsonl"
        self._poll_nn_training_history()
        self._nn_training_timer = QTimer(self)
        self._nn_training_timer.setInterval(2000)
        self._nn_training_timer.timeout.connect(self._poll_nn_training_history)
        self._nn_training_timer.start()
        from .network_flow_model import source_labeled_candidate_status
        candidate = source_labeled_candidate_status(
            RESOURCE_ROOT / "models" / "network_flow_v3_candidate.pt")
        if candidate.get("status") != "available":
            p.lay.addWidget(card(label(
                "Модель недоступна: " + candidate.get("reason", "не прошла проверку происхождения данных."),
                muted=True, wrap=True), title="Состояние модели"))
            p.lay.addStretch(1)
            return p

        self._nn_candidate_sha256 = candidate.get("checkpoint_sha256")

        metrics = candidate.get("independent_test_metrics") or {}
        per_capture = candidate.get("per_capture_metrics") or {}
        test_counts = metrics.get("combined_counts") or {
            "attack": int(metrics.get("n_attack", 0) or 0),
            "benign": int(metrics.get("n_benign", 0) or 0),
        }
        train_captures = ", ".join(candidate.get("train_captures") or [])
        test_captures = ", ".join(candidate.get("independent_test_captures") or [])
        threshold = float(candidate.get("threshold") or 0.5)
        summary = [
            f"Источник меток: опубликованные авторами CTU-13; семейство набора: {candidate.get('dataset_family', 'не указано')}.",
            f"Разбиение: обучение {train_captures}; валидация {candidate.get('validation_capture')}; независимый тест {test_captures}.",
        ]
        if metrics:
            summary.append(
                f"Независимый тест при пороге {threshold:.5f}: полнота атак "
                f"{float(metrics.get('attack_recall') or 0):.1%}, ложные срабатывания "
                f"{float(metrics.get('benign_false_positive_rate') or 0):.3%}, "
                f"точность положительных прогнозов {float(metrics.get('attack_precision') or 0):.1%} "
                "совокупно; release-критерии считаются отдельно для каждого захвата.")
        summary.append(
            "Кандидат предназначен для рекомендаций. На целевой сети качество не измерено; "
            "правила Firewall не меняются.")
        p.lay.addWidget(card(label(" ".join(summary), muted=True, wrap=True),
                             title="Модель и происхождение меток"))

        # --- Production мониторинг нейросети (вверху страницы) ---
        self.nn_score_stream = NNScoreStream(capacity=200)
        self.nn_score_stream.empty_text = "Ожидание оценки полных потоков Pktmon…"
        self.nn_udp_hist = BenignUDPHistogram(bins=40)
        self.nn_udp_hist.empty_text = (
            "Нет UDP-потоков, закрытых 1-секундным тайм-аутом бездействия в текущих захватах.")
        self.nn_monitor_status_label = label(self._nn_monitor_status, muted=True, wrap=True)

        nn_stats_row = QHBoxLayout()
        self.nn_stat_total = label("—", "h2")
        self.nn_stat_attack = label("—", "h2")
        self.nn_stat_udp_fp = label("—", "h2")
        self.nn_stat_p999 = label("—", "h2")
        for stat_val, stat_name in (
            (self.nn_stat_total, "потоков всего"),
            (self.nn_stat_attack, "выше порога"),
            (self.nn_stat_udp_fp, "UDP выше порога"),
            (self.nn_stat_p999, "UDP p99.9 P(attack)"),
        ):
            stat_val.setAlignment(Qt.AlignCenter)
            stat_name_lbl = label(stat_name, muted=True)
            stat_name_lbl.setAlignment(Qt.AlignCenter)
            col = QVBoxLayout()
            col.addWidget(stat_val)
            col.addWidget(stat_name_lbl)
            nn_stats_row.addLayout(col)

        p.lay.addWidget(card(
            nn_stats_row,
            self.nn_score_stream,
            self.nn_monitor_status_label,
            label("Каждая точка — оценка полного потока Pktmon. Бирюзовое кольцо = UDP. "
                  "Выше порога означает рекомендацию для обзора; прогноз не является подтверждённой меткой.",
                  muted=True, wrap=True),
            title="Оценка P(attack) по потокам"))

        p.lay.addWidget(card(
            self.nn_udp_hist,
            label("UDP-поток учитывается после наблюдаемой секунды бездействия до остановки сегмента Pktmon. "
                  "Это правило завершения потока для оценки, а не подтверждённая метка; истинный класс неизвестен.",
                  muted=True, wrap=True),
            title="Распределение P(attack) для UDP-потоков"))

        # таймер обновления мониторинга (каждые 5 секунд)
        self._nn_journal_path = DATA / "online" / "network_runtime_metrics.sqlite"
        try:
            self._nn_journal_mtime_ns = self._nn_journal_path.stat().st_mtime_ns
        except OSError:
            self._nn_journal_mtime_ns = None
        self._nn_journal_busy = False
        self._nn_journal_retry_after = 0.0
        self._nn_monitor_timer = QTimer(self)
        self._nn_monitor_timer.setInterval(5000)
        self._nn_monitor_timer.timeout.connect(self._poll_nn_monitor_journal)
        self._nn_monitor_timer.start()
        self._nn_monitor_threshold = float(threshold)
        self._nn_monitor_status = "Проверяю целостность локального журнала Pktmon в фоне…"
        self._refresh_nn_monitor()

        train_ids = set(candidate.get("train_captures") or [])
        validation_id = candidate.get("validation_capture")
        test_ids = set(candidate.get("independent_test_captures") or [])
        source_test_ready = bool(metrics.get("n", 0) and test_ids
                                 and not (train_ids & test_ids)
                                 and validation_id not in test_ids)
        target_eval = candidate.get("target_network_evaluation")
        from .network_statistics import (
            MIN_BENIGN_SUPPORT_ZERO_FP, MIN_RELEASE_ATTACK_SUPPORT,
            RELEASE_FPR_CI_CEILING,
            hash_locked_target_evaluation,
        )
        target_test_ready = hash_locked_target_evaluation(
            target_eval, candidate.get("checkpoint_sha256"))
        # Full hash-chain walks are performed after the window appears.
        runtime = {"sample_count": 0, "p95_inference_ms": None,
                   "target_load_tested": False, "drop_counters_observed": False,
                   "candidate_provenance_by_sha256": {},
                   "candidate_linked_complete_flows_by_sha256": {},
                   "candidate_linked_segment_counts_by_sha256": {},
                   "capture_integrity_valid": False,
                   "captured_flow_integrity_valid": False,
                   "candidate_capture_link_integrity_valid": False}
        runtime_sample_count = int(runtime.get("sample_count", 0) or 0)
        active_checkpoint_hash = str(candidate.get("checkpoint_sha256") or "")
        runtime_candidate_samples = int((runtime.get("candidate_provenance_by_sha256") or {}).get(
            active_checkpoint_hash, 0) or 0)
        runtime_complete_flows = int((runtime.get("candidate_linked_complete_flows_by_sha256") or {}).get(
            active_checkpoint_hash, 0) or 0)
        runtime_linked_segments = int((runtime.get("candidate_linked_segment_counts_by_sha256") or {}).get(
            active_checkpoint_hash, 0) or 0)
        runtime_flow_ready = (
            runtime_candidate_samples > 0
            and runtime_complete_flows > 0
            and runtime.get("capture_integrity_valid") is True
            and runtime.get("captured_flow_integrity_valid") is True
            and runtime.get("candidate_capture_link_integrity_valid") is True
        )
        capture_quality_rows = []
        for capture, capture_data in per_capture.items():
            selected = (capture_data or {}).get("validation_selected_threshold") or {}
            from .network_statistics import confusion_metrics
            computed = confusion_metrics(selected)
            recall_ci = computed["attack_recall_ci95_wilson"] if computed else []
            fpr_ci = computed["benign_false_positive_rate_ci95_wilson"] if computed else []
            passed = (computed is not None
                      and float(recall_ci[0]) >= 0.80
                      and float(fpr_ci[1]) <= RELEASE_FPR_CI_CEILING)
            capture_quality_rows.append((capture, computed or {}, recall_ci, fpr_ci, passed))
        capture_quality_ready = bool(capture_quality_rows) and all(row[4] for row in capture_quality_rows)
        target_metrics = candidate.get("target_network_metrics") or (
            target_eval.get("metrics", {}) if isinstance(target_eval, dict) else {})
        from .network_statistics import confusion_metrics
        target_computed = confusion_metrics(target_metrics)
        target_attack_n = target_computed["n_attack"] if target_computed else 0
        target_benign_n = target_computed["n_benign"] if target_computed else 0
        target_fpr_ci = (target_computed["benign_false_positive_rate_ci95_wilson"]
                         if target_computed else [])
        target_fpr_ready = (target_test_ready
                            and target_attack_n >= MIN_RELEASE_ATTACK_SUPPORT
                            and target_benign_n >= MIN_BENIGN_SUPPORT_ZERO_FP
                            and len(target_fpr_ci) == 2
                            and float(target_fpr_ci[1]) <= RELEASE_FPR_CI_CEILING)
        sensor_validation = candidate.get("target_sensor_validation") or {}
        packet_drop_rate = sensor_validation.get("packet_drop_rate")
        sensor_completeness_ready = (sensor_validation.get("validated") is True
                                     and packet_drop_rate is not None
                                     and float(packet_drop_rate) <= 0.001)
        operational_performance = candidate.get("operational_performance") or {}
        inference_latency_ms = operational_performance.get("p95_inference_latency_ms")
        latency_ready = (inference_latency_ms is not None
                         and float(inference_latency_ms) <= 100.0
                         and operational_performance.get("target_load_tested") is True)
        firewall_validation = candidate.get("firewall_validation") or {}
        firewall_ready = (firewall_validation.get("passed") is True
                          and firewall_validation.get("audit_verified") is True
                          and firewall_validation.get("rollback_verified") is True)
        gates = [
            ("Происхождение корпуса и SHA-256 checkpoint/manifest проверены", True),
            ("Обученный checkpoint доступен", bool(train_ids)),
            ("Есть отдельные validation и test захваты", source_test_ready),
            ("Per-flow модель подключена к Pktmon; есть успешный реальный сегмент",
             runtime_flow_ready),
            ("По каждому test-захвату нижняя CI recall ≥80%, верхняя CI FPR ≤0,25%",
             capture_quality_ready),
            ("Проведён отдельный размеченный test на целевой сети", target_test_ready),
            ("Целевая выборка: ≥100 атак и достаточная benign-поддержка для верхней CI FPR ≤0,25%",
             target_fpr_ready),
            ("Измерены потери сенсора; packet-drop rate ≤0,1%", sensor_completeness_ready),
            ("P95 inference ≤100 мс на целевой нагрузке", latency_ready),
            ("Путь блокировки, аудит действий и откат прошли проверку", firewall_ready),
        ]
        completed_gates = sum(1 for _name, passed in gates if passed)
        self._nn_gate_count_without_runtime = completed_gates
        readiness_percent = round(completed_gates * 100 / len(gates))
        self.nn_readiness_bar = QProgressBar()
        self.nn_readiness_bar.setRange(0, 100)
        self.nn_readiness_bar.setValue(readiness_percent)
        self.nn_readiness_bar.setFormat(f"{readiness_percent}% · {completed_gates} из {len(gates)} этапов")
        self.nn_readiness_bar.setToolTip(
            "Доля закрытых технических этапов допуска. Это не точность, не вероятность обнаружения "
            "и не процент знаний модели.")
        gate_lines = [f"{'✓' if passed else '○'}  {name}" for name, passed in gates]
        if not runtime_flow_ready:
            gate_lines.append(
                f"Pktmon-путь: {runtime_candidate_samples} inference-записей с provenance кандидата, "
                f"{runtime_complete_flows} полных потоков из {runtime_linked_segments} связанных сегментов, "
                "связанных с inference кандидата; "
                "этап требует валидные цепочки и прямую связь этих записей.")
        if not capture_quality_ready and capture_quality_rows:
            for capture, selected, recall_ci, fpr_ci, passed in capture_quality_rows:
                if len(recall_ci) == 2 and len(fpr_ci) == 2:
                    gate_lines.append(
                        f"   Захват {capture}: recall {float(selected.get('attack_recall') or 0):.1%} "
                        f"(95% CI {float(recall_ci[0]):.1%}–{float(recall_ci[1]):.1%}); "
                        f"FPR {float(selected.get('benign_false_positive_rate') or 0):.3%} "
                        f"(верхняя 95% CI {float(fpr_ci[1]):.3%})")
        gate_lines.extend((
            "Порог стабильности заранее задан для каждого захвата: нижняя 95% CI полноты ≥80%, "
            "верхняя двусторонняя 95% Wilson CI ложных срабатываний ≤0,25%.",
            "Для target-test требуется не менее 100 атак и достаточная benign-поддержка; неизвестные потоки "
            "остаются без метки и не входят в оценку. CI пересчитываются из TP/FP/FN/TN. Для FPR ≤0,25% "
            "при нуле ложных срабатываний нужно минимум 1 533 benign-потока (95% Wilson); при FP нужно больше.",
        ))
        gate_status = label("\n".join(gate_lines), muted=True, wrap=True)
        self._nn_gate_status = gate_status
        self._nn_runtime_status_label = label(
            "Проверка runtime-журналов выполняется в фоне; результат появится здесь.",
            muted=True, wrap=True)
        observed_p95 = runtime.get("p95_inference_ms")
        if observed_p95 is None:
            gate_lines.append("Runtime inference: журнал Pktmon проверяется; итог появится после проверки цепочки.")
        else:
            gate_lines.append(
                f"Runtime inference: наблюдаемый P95 {observed_p95:.3f} мс "
                f"по {runtime_sample_count} реальным сегментам; это не целевой нагрузочный тест.")
        gate_lines.append(
            "Target-test принимается только при наличии SHA-256 захвата и набора меток, "
            "зафиксированных до оценки этой контрольной точкой.")
        gate_lines.append(
            "Потери сенсора: счётчики Pktmon собираются отдельно; оценка packet-drop rate пока не подтверждена.")
        gate_status.setText("\n".join(gate_lines))
        p.lay.addWidget(card(self.nn_readiness_bar, gate_status, self._nn_runtime_status_label,
                             label("Обучение текущего checkpoint завершено. Прогресс показывает "
                                   "10 равновесных этапов допуска, а не точность или знания модели. "
                                   "Live-прогнозы не используются как метки.",
                                   muted=True, wrap=True),
                             title="Готовность к релизу сетевой модели"))

        class_rows = []
        if test_counts:
            class_rows = [("Атака — метка набора", int(test_counts.get("attack", 0))),
                          ("Норма — метка набора", int(test_counts.get("benign", 0)))]
        class_chart = HBars()
        class_chart.empty_text = "Нет размеченных примеров независимого теста."
        class_chart.set_rows(class_rows)
        p.lay.addWidget(card(class_chart,
                             label(f"Всего в тесте: {int(test_counts.get('attack', 0)) + int(test_counts.get('benign', 0)):,}. "
                                   "Показаны опубликованные метки CTU-13; неизвестные и фоновые метки исключены. "
                                   "Это source-test, не оценка вашей целевой сети.", muted=True, wrap=True),
                             title="Независимый тест CTU-13"))

        capture_rows = []
        for capture in sorted(per_capture):
            selected = (per_capture[capture] or {}).get("validation_selected_threshold") or {}
            if selected:
                capture_rows.append((f"Захват {capture}: полнота атак",
                                     round(float(selected.get("attack_recall") or 0) * 100)))
        if capture_rows:
            capture_chart = HBars()
            capture_chart.set_rows(capture_rows)
            p.lay.addWidget(card(capture_chart,
                                 label("Разброс между независимыми захватами показывает, что результат зависит от сценария.",
                                       muted=True, wrap=True),
                                 title="Проверка по отдельным захватам"))

        p.lay.addStretch(1)
        self._start_nn_runtime_restore()
        return p

    def _start_nn_runtime_restore(self):
        """Verify append-only runtime journals off the UI thread and restore chart state."""
        if getattr(self, "_nn_runtime_restore_started", False):
            return
        self._nn_runtime_restore_started = True
        self._nn_journal_busy = True
        db_path = DATA / "online" / "network_runtime_metrics.sqlite"
        checkpoint_path = RESOURCE_ROOT / "models" / "network_flow_v3_candidate.pt"
        candidate_hash = str(getattr(self, "_nn_candidate_sha256", "") or "")

        def work(_progress):
            from .network_runtime_evidence import recent_captured_flows, runtime_summary
            summary = runtime_summary(db_path)
            recent = recent_captured_flows(db_path, verified_summary=summary)
            scores = []
            if recent.get("flows"):
                from .network_flow_model import assess_completed_packet_flows
                restored = assess_completed_packet_flows(recent["flows"], checkpoint_path)
                if restored.get("status") == "recommendation_candidate":
                    scores = restored.get("flow_scores") or []
            return summary, scores

        def done(result):
            summary, scores = result
            if scores:
                self._nn_monitor_flows.extend(scores[-200:])
                self._nn_monitor_status = (
                    f"Восстановлены и заново оценены последние {len(self._nn_monitor_flows)} "
                    "завершённых потоков; локальные метки остаются неизвестными.")
            elif summary.get("integrity_valid") is not True:
                self._nn_monitor_status = "Журнал Pktmon не прошёл проверку целостности; оценки не восстановлены."
            else:
                self._nn_monitor_status = "Журнал проверен; завершённых потоков для восстановления нет."
            self._refresh_nn_monitor()

            candidate_samples = int((summary.get("candidate_provenance_by_sha256") or {}).get(
                candidate_hash, 0) or 0)
            complete_flows = int((summary.get("candidate_linked_complete_flows_by_sha256") or {}).get(
                candidate_hash, 0) or 0)
            linked_segments = int((summary.get("candidate_linked_segment_counts_by_sha256") or {}).get(
                candidate_hash, 0) or 0)
            gate_ready = (candidate_samples > 0 and complete_flows > 0
                          and summary.get("capture_integrity_valid") is True
                          and summary.get("captured_flow_integrity_valid") is True
                          and summary.get("candidate_capture_link_integrity_valid") is True)
            ready_count = self._nn_gate_count_without_runtime + int(gate_ready)
            percent = round(ready_count * 100 / 10)
            self.nn_readiness_bar.setValue(percent)
            self.nn_readiness_bar.setFormat(f"{percent}% · {ready_count} из 10 этапов")
            p95 = summary.get("p95_inference_ms")
            p95_text = f"P95 инференса: {p95:.3f} мс." if p95 is not None else "P95 инференса: нет измерений."
            self._nn_runtime_status_label.setText(
                f"Runtime-журналы проверены. Связанных с кандидатом записей: {candidate_samples}; "
                f"полных потоков: {complete_flows}; сегментов: {linked_segments}. {p95_text} "
                "Это не подтверждает целевую нагрузку.")
            self._nn_gate_status.setText(
                self._nn_gate_status.text() + "\n"
                + ("✓" if gate_ready else "○")
                + f" Pktmon runtime evidence: {candidate_samples} записей, {complete_flows} полных потоков, "
                f"{linked_segments} сегментов; целостность {'подтверждена' if gate_ready else 'не подтверждена'}.")

        def failed(message):
            self._nn_monitor_status = f"Проверка runtime-журнала не завершена: {message[:180]}"
            self._refresh_nn_monitor()
            self._nn_runtime_status_label.setText(self._nn_monitor_status)

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: setattr(self, "_nn_journal_busy", False))
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        self._workers.append(worker)
        worker.start()

    def _refresh_nn_monitor(self):
        """Refresh live scores from Pktmon inference results held in this window."""
        thr = getattr(self, "_nn_monitor_threshold", 0.5)
        recent_flows = list(getattr(self, "_nn_monitor_flows", ()))
        self.nn_score_stream.set_flows(recent_flows, thr)
        udp_scores = [float(f["score"]) for f in recent_flows if f.get("is_udp")]
        self.nn_udp_hist.set_scores(udp_scores, thr)
        threshold_hits = sum(1 for f in recent_flows if float(f.get("score", 0)) >= thr)
        udp_hits = sum(1 for f in recent_flows if f.get("is_udp") and float(f.get("score", 0)) >= thr)
        if udp_scores:
            sorted_udp = sorted(udp_scores)
            p999_idx = min(int(len(sorted_udp) * 0.999), len(sorted_udp) - 1)
            self.nn_stat_p999.setText(f"{sorted_udp[p999_idx]:.4f}")
        else:
            self.nn_stat_p999.setText("—")
        self.nn_stat_total.setText(str(len(recent_flows)))
        self.nn_stat_attack.setText(str(threshold_hits))
        self.nn_stat_udp_fp.setText(str(udp_hits))
        if hasattr(self, "nn_monitor_status_label"):
            self.nn_monitor_status_label.setText(getattr(self, "_nn_monitor_status", ""))

    def _poll_nn_training_history(self):
        """Render only recorded training events; never invent progress between epochs."""
        path = getattr(self, "_nn_training_history_path", None)
        if path is None or not path.is_file():
            self.nn_training_chart.set_history([])
            self.nn_training_progress.setValue(0)
            self.nn_training_progress.setFormat("нет активного обучения")
            self.nn_training_status.setText("История обучения ещё не записана. Кривые появятся после первого запуска.")
            return
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - 2_000_000), os.SEEK_SET)
                if stream.tell():
                    stream.readline()
                raw_lines = stream.read().decode("utf-8", errors="replace").splitlines()
            events = []
            for line in raw_lines[-5000:]:
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue  # writer may be between append and newline
            events = [event for event in events if isinstance(event, dict) and event.get("run_id")]
            if not events:
                return
            run_id = events[-1]["run_id"]
            run_events = [event for event in events if event.get("run_id") == run_id]
            epoch_events = [event for event in run_events if event.get("event") == "epoch"]
            scheme = epoch_events[-1].get("scheme") if epoch_events else None
            schemes = list(dict.fromkeys(event.get("scheme") for event in epoch_events if event.get("scheme")))
            selected_scheme = self.nn_training_scheme.currentData()
            self.nn_training_scheme.blockSignals(True)
            current_scheme_items = [self.nn_training_scheme.itemData(i)
                                    for i in range(self.nn_training_scheme.count())]
            if current_scheme_items != [None, *schemes]:
                self.nn_training_scheme.clear()
                self.nn_training_scheme.addItem("Последняя схема", None)
                for item in schemes:
                    self.nn_training_scheme.addItem(str(item), item)
                selected_index = self.nn_training_scheme.findData(selected_scheme)
                if selected_index >= 0:
                    self.nn_training_scheme.setCurrentIndex(selected_index)
                elif self.nn_training_scheme.count():
                    self.nn_training_scheme.setCurrentIndex(0)
            self.nn_training_scheme.blockSignals(False)
            selected_scheme = self.nn_training_scheme.currentData() or scheme
            scheme_events = [event for event in epoch_events if event.get("scheme") == selected_scheme]
            self._nn_training_events = epoch_events
            self._nn_training_chart_scheme = selected_scheme
            self.nn_training_chart.set_history(scheme_events)
            latest = run_events[-1]
            context = (f"Run {run_id[:10]} · train захваты {', '.join(latest.get('train_captures', []))} · "
                       f"development захваты {', '.join(latest.get('development_captures', []))}.")
            timestamp = latest.get("timestamp_utc")
            age_seconds = None
            if timestamp:
                try:
                    written_at = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                    age_seconds = max(0.0, (datetime.now(timezone.utc) - written_at).total_seconds())
                except ValueError:
                    pass
            if latest.get("event") == "run_completed":
                checks = latest.get("checkpoint_sha256_by_scheme") or {}
                self.nn_training_progress.setValue(100)
                self.nn_training_progress.setFormat("обучение завершено · все эпохи записаны")
                hashes = ", ".join(f"{key}: {value[:12]}…" for key, value in checks.items())
                selected_epoch_event = None
                if scheme_events:
                    best_epoch = int(scheme_events[-1].get("best_epoch") or 0)
                    selected_epoch_event = next((event for event in scheme_events
                                                 if int(event.get("epoch") or 0) == best_epoch), None)
                selected_ci = (float(scheme_events[-1].get("best_development_min_recall_ci95_lower") or 0.0)
                               if scheme_events else 0.0)
                selected_threshold = (selected_epoch_event.get("development_threshold")
                                      if selected_epoch_event else None)
                dev_ceiling = float((latest.get("training_config") or {}).get("dev_fpr_ci_ceiling") or 0.0)
                self.nn_training_status.setText(
                    f"Завершено. {context} Для {selected_scheme}: лучшая minimum dev recall CI-L "
                    f"{selected_ci:.2%}; threshold {float(selected_threshold or 0.0):.6g}; "
                    f"dev upper FPR CI ceiling {dev_ceiling:.2%}. Checkpoint SHA-256: {hashes or 'нет'}; "
                    f"manifest SHA-256: {str(latest.get('manifest_sha256') or 'нет')[:12]}…; "
                    f"время: {latest.get('timestamp_utc', 'не записано')}.")
            elif age_seconds is not None and age_seconds > 120:
                self.nn_training_progress.setFormat("нет свежих событий обучения")
                self.nn_training_status.setText(
                    f"История не обновлялась {age_seconds / 60:.1f} мин; факт завершения или остановки процесса "
                    f"не подтверждён. Последний записанный шаг и захваты: {context}")
            elif epoch_events:
                current = epoch_events[-1]
                total = max(1, int(current.get("total_epochs") or 1))
                epoch = min(total, int(current.get("epoch") or 0))
                self.nn_training_progress.setValue(round(epoch * 100 / total))
                self.nn_training_progress.setFormat(f"{current.get('scheme', 'схема')} · эпоха {epoch}/{total}")
                self.nn_training_status.setText(
                    f"Выполняется. {context} Train loss {float(current['train_loss']):.5f}; "
                    f"Development NLL {float(current['development_nll']):.5f}; "
                    f"минимальная dev recall CI-L "
                    f"{float(current.get('development_min_recall_ci95_lower') or 0.0):.2%}; "
                    f"лучший результат по критерию {float(current.get('best_development_min_recall_ci95_lower') or 0.0):.2%}; "
                    f"dev threshold {float(current.get('development_threshold') or 0.0):.6g}; "
                    f"dev FPR CI ceiling {float((latest.get('training_config') or {}).get('dev_fpr_ci_ceiling') or 0.0):.2%}; "
                    f"NLL {float(current['best_development_nll']):.5f} на выбранной эпохе "
                    f"{int(current['best_epoch'])}; ожидание остановки {int(current['patience_used'])}; "
                    f"обновлено {current.get('timestamp_utc', 'время не записано')}.")
            else:
                self.nn_training_progress.setValue(0)
                self.nn_training_progress.setFormat("подготовка обучающего запуска")
                self.nn_training_status.setText(f"Запуск зарегистрирован; первая эпоха ещё не завершена. {context}")
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
            self.nn_training_status.setText(f"Не удалось прочитать журнал обучения: {type(error).__name__}")

    def _refresh_nn_training_chart(self):
        events = getattr(self, "_nn_training_events", [])
        scheme = self.nn_training_scheme.currentData() or getattr(self, "_nn_training_chart_scheme", None)
        self.nn_training_chart.set_history([event for event in events if event.get("scheme") == scheme])

    def _poll_nn_monitor_journal(self):
        """Reload newly committed, integrity-checked flow scores without blocking the UI."""
        self._refresh_nn_monitor()
        if getattr(self, "_nn_journal_busy", False):
            return
        if time.monotonic() < getattr(self, "_nn_journal_retry_after", 0.0):
            return
        journal = getattr(self, "_nn_journal_path", DATA / "online" / "network_runtime_metrics.sqlite")
        try:
            mtime_ns = journal.stat().st_mtime_ns
        except OSError:
            return
        if mtime_ns == getattr(self, "_nn_journal_mtime_ns", None):
            return
        self._nn_journal_mtime_ns = mtime_ns
        self._nn_journal_busy = True

        def work(_progress):
            from .network_runtime_evidence import recent_captured_flows
            from .network_flow_model import assess_completed_packet_flows
            recent = recent_captured_flows(journal, limit=200)
            if recent.get("status") != "ok" or not recent.get("flows"):
                return {"status": recent.get("status", "empty"), "flow_scores": []}
            return assess_completed_packet_flows(
                recent["flows"], RESOURCE_ROOT / "models" / "network_flow_v3_candidate.pt")

        def done(result):
            self._nn_journal_busy = False
            if result.get("status") == "recommendation_candidate":
                scores = result.get("flow_scores") or []
                self._nn_monitor_flows = deque(scores, maxlen=200)
                self._nn_monitor_status = (
                    f"Панель обновлена {time.strftime('%H:%M:%S')}: из проверенного журнала заново оценены "
                    f"{len(scores)} последних полных потоков. Метки локальных потоков неизвестны; "
                    "оценки не являются подтверждёнными классами.")
            elif result.get("status") in ("integrity_unverified", "unreadable"):
                # Retry after a short pause; preserve the last visible values.
                self._nn_journal_retry_after = time.monotonic() + 15.0
                self._nn_monitor_status = (
                    "Динамическое обновление журнала приостановлено: целостность новых записей "
                    "не подтверждена. Показаны последние ранее проверенные оценки.")
            self._refresh_nn_monitor()

        def failed(message):
            self._nn_journal_busy = False
            self._nn_journal_retry_after = time.monotonic() + 15.0
            self._nn_monitor_status = f"Не удалось обновить оценки из журнала: {message[:240]}"
            self._refresh_nn_monitor()

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)
        worker.finished.connect(lambda: setattr(self, "_nn_journal_busy", False))
        self._workers.append(worker)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        worker.start()

    def _page_settings(self):
        p = Page("Настройки", "Параметры сгруппированы по назначению. Изменения применяются после сохранения.")
        self.s_reg = PathEdit("Каталог реестра (эталоны, журнал событий)")
        self.s_model = PathEdit("Файл детектора detector.pt", False, "Модель (*.pt)")
        self.s_key = PathEdit("Файл ключа подписи (пусто — registry/signing.key или переменная IG_SIGNING_KEY)", False)
        self.s_reg.setText(self.cfg("registry"))
        self.s_model.setText(self.cfg("model"))
        self.s_key.setText(self.cfg("key"))
        g = QGridLayout()
        g.setVerticalSpacing(10)
        g.setHorizontalSpacing(12)
        for i, (name, w) in enumerate((("Реестр", self.s_reg), ("Детектор", self.s_model), ("Ключ подписи", self.s_key))):
            g.addWidget(label(name, muted=True), i, 0)
            g.addWidget(w, i, 1)
        btn = QPushButton("Сохранить источники", objectName="primary")
        btn.clicked.connect(self._save_settings)
        self.s_note = label("Файлы проверяются при сохранении.", muted=True)
        row = QHBoxLayout()
        row.addWidget(btn)
        row.addWidget(self.s_note, 1)
        p.lay.addWidget(card(g, row, title="Источники проверки"))

        ops = QGridLayout()
        ops.setVerticalSpacing(10)
        ops.setHorizontalSpacing(12)
        self.s_auto = QCheckBox("Автоматически проверять реальные пакеты из папки входящих")
        self.s_auto.setChecked(str(self.settings.value("auto", "true")).lower() != "false")
        ops.addWidget(self.s_auto, 0, 0, 1, 2)
        self.s_autostart = QCheckBox("Запускать автоматически при входе в Windows (в трее, без открытия окна)")
        self.s_autostart.setChecked(self._autostart_enabled())
        if sys.platform != "win32" or not QSystemTrayIcon.isSystemTrayAvailable():
            self.s_autostart.setEnabled(False)
            self.s_autostart.setToolTip("Доступно только в Windows со значком в трее.")
        ops.addWidget(self.s_autostart, 1, 0, 1, 2)
        self.s_retention = QSpinBox(minimum=0, maximum=3650, suffix=" дн.")
        self.s_retention.setToolTip("Через сколько дней автоматически удалять уже обработанные пакеты "
                                    "(allow/review/block) из data/processed. 0 — не удалять (хранить всегда).")
        try:
            self.s_retention.setValue(int(self.settings.value("processed_retention_days", 30)))
        except (TypeError, ValueError):
            self.s_retention.setValue(30)
        ops.addWidget(label("Срок хранения обработанных пакетов", muted=True), 2, 0)
        ops.addWidget(self.s_retention, 2, 1)
        ops_btn = QPushButton("Сохранить работу приложения", objectName="primary")
        ops_btn.clicked.connect(self._save_settings)
        self.s_ops_note = label("Настройки автоматизации и хранения.", muted=True)
        ops_row = QHBoxLayout()
        ops_row.addWidget(ops_btn)
        ops_row.addWidget(self.s_ops_note, 1)
        p.lay.addWidget(card(ops, ops_row, title="Автоматизация и хранение"))

        # --- политики блокировки
        pg = QGridLayout()
        pg.setVerticalSpacing(10)
        pg.setHorizontalSpacing(12)
        self.s_policy_block = QSpinBox()
        self.s_policy_block.setRange(0, 100)
        self.s_policy_block.setSuffix(" / 100")
        self.s_policy_block.setToolTip(
            "Пакеты с Risk Score ≥ этого значения принудительно блокируются, даже если нейросеть дала REVIEW. "
            "0 — политика отключена (используются только пороги детектора).")
        try:
            self.s_policy_block.setValue(int(self.settings.value("policy_block_score", 0)))
        except (TypeError, ValueError):
            self.s_policy_block.setValue(0)
        self.s_policy_strict_stage = QCheckBox("Строгий режим для стадии «Поставка» (deploy): REVIEW → BLOCK")
        self.s_policy_strict_stage.setChecked(
            str(self.settings.value("policy_strict_deploy", "false")).lower() == "true")
        pg.addWidget(label("Принудительная блокировка при Risk Score ≥", muted=True), 0, 0)
        pg.addWidget(self.s_policy_block, 0, 1)
        pg.addWidget(label("(0 — отключено)", muted=True), 0, 2)
        pg.addWidget(self.s_policy_strict_stage, 1, 1, 1, 2)
        pg.addWidget(label("Эти правила влияют на вердикт проверки пакета. Сетевой трафик ими не блокируется.",
                           muted=True, wrap=True), 2, 0, 1, 3)
        pbtn = QPushButton("Сохранить политику", objectName="primary")
        pbtn.clicked.connect(self._save_policy)
        self.s_policy_note = label("", muted=True)
        prow = QHBoxLayout()
        prow.addWidget(pbtn)
        prow.addWidget(self.s_policy_note, 1)
        p.lay.addWidget(card(pg, prow, title="Политика вердиктов для пакетов"))
        info = label(
            "<b>Встраивание в конвейер сборки и поставки.</b> Та же проверка доступна из командной строки:<br>"
            "<code>python -m integrityguard check --package &lt;каталог&gt; --strict</code><br>"
            "Код возврата: 0 — допуск, 1 — блокировка, 2 — на проверку. Шаг конвейера с ненулевым кодом останавливает сборку.<br><br>"
            "<b>Подключение к мониторингу безопасности.</b> Каждая проверка добавляет строку JSON в файл "
            "<code>events.jsonl</code> в каталоге реестра.", wrap=True)
        info.setTextFormat(Qt.RichText)
        ci_btn = QPushButton("Сгенерировать workflow для GitHub Actions")
        ci_btn.setToolTip("Создаёт .github/workflows/integrityguard.yml с готовой командой check --strict — "
                          "не нужно переносить её из подсказки выше вручную.")
        ci_btn.clicked.connect(self._generate_ci_workflow)
        self.ci_note = label("", muted=True, wrap=True)
        ci_row = QHBoxLayout()
        ci_row.addWidget(ci_btn)
        ci_row.addStretch(1)
        p.lay.addWidget(card(info, ci_row, self.ci_note, title="Интеграция"))
        p.lay.addStretch(1)
        return p

    def _generate_ci_workflow(self):
        """Готовый workflow для GitHub Actions: та же команда «check --strict», что и в подсказке выше, —
        конвейер сам остановится при вердикте БЛОКИРОВКА, переносить команду вручную не нужно."""
        reg, model = self.cfg("registry"), self.cfg("model")

        def rel(p):
            try:
                return str(Path(p).resolve().relative_to(ROOT)).replace("\\", "/")
            except ValueError:
                return str(p)                             # путь вне репозитория — оставляем как есть

        reg_rel, model_rel = rel(reg), rel(model)
        yml = f"""name: IntegrityGuard

on:
  push:
  pull_request:

jobs:
  check-package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Установка зависимостей
        run: pip install -r requirements.txt

      # Реестр эталонов ({reg_rel}) и обученный детектор ({model_rel}) должны быть доступны по этим
      # путям на этом шаге — в составе репозитория или восстановлены отдельным шагом (например,
      # actions/download-artifact) до команды ниже.
      - name: Проверка целостности пакета
        run: >
          python -m integrityguard check
          --package <путь к каталогу пакета-кандидата>
          --registry {reg_rel}
          --model {model_rel}
          --stage deploy
          --strict
        # Код возврата: 0 — допуск, 1 — блокировка, 2 — на проверку.
        # Ненулевой код сам останавливает сборку — дополнительно настраивать ничего не нужно.
"""
        out = ROOT / ".github" / "workflows" / "integrityguard.yml"
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(yml, encoding="utf-8")
        except OSError as e:
            self.notify(f"Не удалось сохранить workflow: {e}", "error")
            return
        self.ci_note.setText(f"Сохранено: {out}. Осталось подставить путь к каталогу пакета-кандидата своего конвейера.")
        self.notify(f"Файл workflow сохранён: {out}", "ok")

    # ------------------------------------------------------------ автозапуск при входе в Windows
    _AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    _AUTOSTART_NAME = "IntegrityGuard"

    def _autostart_command(self) -> str:
        """Команда запуска в трее: тот же способ, которым запущена текущая программа."""
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}" --tray'
        pyw = Path(sys.executable).with_name("pythonw.exe")
        script = ROOT / "IntegrityGuard.pyw"
        return f'"{pyw if pyw.exists() else sys.executable}" "{script}" --tray'

    def _autostart_enabled(self) -> bool:
        if sys.platform != "win32":
            return False
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._AUTOSTART_KEY) as k:
                winreg.QueryValueEx(k, self._AUTOSTART_NAME)
                return True
        except OSError:
            return False

    def _set_autostart(self, enable: bool) -> None:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if enable:
                winreg.SetValueEx(k, self._AUTOSTART_NAME, 0, winreg.REG_SZ, self._autostart_command())
            else:
                try:
                    winreg.DeleteValue(k, self._AUTOSTART_NAME)
                except FileNotFoundError:
                    pass

    def _save_settings(self):
        if self.s_model.text() and not Path(self.s_model.text()).is_file():
            self.notify("Файл детектора не найден.", "warn")
            return
        if self.s_key.text() and not Path(self.s_key.text()).is_file():
            self.notify("Файл ключа подписи не найден.", "warn")
            return
        for key, w in (("registry", self.s_reg), ("model", self.s_model), ("key", self.s_key)):
            if w.text() or key == "key":
                self.settings.setValue(key, w.text())
        self.settings.setValue("auto", "true" if self.s_auto.isChecked() else "false")
        self.settings.setValue("processed_retention_days", self.s_retention.value())
        self.settings.sync()
        if hasattr(self, "s_autostart") and self.s_autostart.isEnabled():
            try:
                self._set_autostart(self.s_autostart.isChecked())
            except OSError as e:
                self.notify(f"Не удалось изменить автозапуск при входе в Windows: {e}", "warn")
        if hasattr(self, "_tray_auto"):
            self._tray_auto.setChecked(self.s_auto.isChecked())
        if self.s_auto.isChecked():
            self._auto_start()
        else:
            self.auto_timer.stop()
            self._set_auto_note("Автоматический режим выключен (включается в настройках).")
        self._guard = None
        self._refresh_status()
        self._load_metrics()
        self._load_monitor()
        self.s_note.setText("Сохранено.")
        if hasattr(self, "s_ops_note"):
            self.s_ops_note.setText("Настройки сохранены и применены.")


    def _save_policy(self):
        score = self.s_policy_block.value()
        strict_deploy = self.s_policy_strict_stage.isChecked()
        self.settings.setValue("policy_block_score", score)
        self.settings.setValue("policy_strict_deploy", "true" if strict_deploy else "false")
        self.settings.sync()
        msg = []
        if score > 0:
            msg.append(f"Пакеты с Risk Score ≥ {score} будут блокироваться.")
        else:
            msg.append("Принудительная блокировка по Risk Score отключена.")
        if strict_deploy:
            msg.append("Стадия «Поставка»: REVIEW → BLOCK.")
        self.s_policy_note.setText("  ".join(msg))

    def _apply_policy(self, ev: dict) -> dict:
        """Применяет настроенные политики к событию проверки (может изменить verdict)."""
        changed = False
        score = self.s_policy_block.value() if hasattr(self, "s_policy_block") else 0
        risk = ev.get("risk_score")
        if score > 0 and isinstance(risk, (int, float)) and risk >= score and ev.get("verdict") != "BLOCK":
            ev = dict(ev, verdict="BLOCK")
            ev.setdefault("rules", [])
            if isinstance(ev["rules"], list):
                ev["rules"] = list(ev["rules"]) + [
                    f"Принудительная блокировка: Risk Score {ev['risk_score']} ≥ порога политики {score}"]
            changed = True
        strict_deploy = (hasattr(self, "s_policy_strict_stage") and
                         self.s_policy_strict_stage.isChecked())
        if strict_deploy and ev.get("stage") == "deploy" and ev.get("verdict") == "REVIEW":
            ev = dict(ev, verdict="BLOCK")
            ev.setdefault("rules", [])
            if isinstance(ev["rules"], list):
                ev["rules"] = list(ev["rules"]) + ["Строгий режим поставки: REVIEW → BLOCK"]
            changed = True
        return ev


def _num(v) -> str:
    return f"{v:.3f}" if isinstance(v, (int, float)) and v == v else "—"


def _when(iso) -> str:
    """Время события журнала (UTC) в местном времени."""
    try:
        from .charts import _local
        return _local(iso).strftime("%d.%m %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(iso)[:19].replace("T", " ")


def dark_palette() -> QPalette:
    """Тёмная палитра приложения: по ней рисуются и стандартные окна (сообщения, подсказки)."""
    pal = QPalette()
    for role, color in (("Window", "#0a0c10"), ("WindowText", "#e9ebef"), ("Base", "#0a0c10"), ("AlternateBase", "#151821"),
                        ("Text", "#e9ebef"), ("Button", "#171b24"), ("ButtonText", "#e9ebef"), ("BrightText", "#ffffff"),
                        ("ToolTipBase", "#171b24"), ("ToolTipText", "#e9ebef"), ("Highlight", "#2bb7ab"),
                        ("HighlightedText", "#06120f"), ("PlaceholderText", "#5c6168"), ("Link", "#4dd0c4"),
                        ("Light", "#202531"), ("Midlight", "#1b1f28"), ("Mid", "#151821"), ("Dark", "#07080b"),
                        ("Shadow", "#000000")):
        pal.setColor(getattr(QPalette, role), QColor(color))
    for role in ("WindowText", "Text", "ButtonText"):
        pal.setColor(QPalette.Disabled, getattr(QPalette, role), QColor("#4a4f57"))
    return pal


def _component_ru(key: str) -> str:
    kind, _, name = key.partition(":")
    return {"dep": f"зависимость {name}", "mod": f"модуль {name}.py", "layer": f"слой модели № {name}",
            "model": "модель (веса в целом)", "root": "пакет", "data": "обучающие данные"}.get(kind, key)


def main(start_minimized=False):
    DATA.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":                       # отдельный значок на панели задач Windows
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("zss.integrityguard")
        except Exception:
            pass
    app = QApplication(sys.argv)
    from .instance import ApplicationInstance
    instance = ApplicationInstance()
    if not instance.acquire():
        return
    app.aboutToQuit.connect(instance.close)
    app.setQuitOnLastWindowClosed(True)                # закрытие главного окна завершает процесс
    app.aboutToQuit.connect(lambda: w.shutdown_background())   # w is bound below, before app.exec()
    app.setStyle("Fusion")
    try:                                              # тёмные заголовки окон и системных диалогов (Qt 6.8+)
        app.styleHints().setColorScheme(Qt.ColorScheme.Dark)
    except (AttributeError, TypeError):
        pass
    app.setPalette(dark_palette())
    app.setStyleSheet(QSS)
    app.setFont(QFont("Segoe UI", 10))
    w = MainWindow()
    instance.bind(w)
    if start_minimized and getattr(w, "tray", None):   # запуск из автозагрузки Windows: сразу в трей
        w.hide()
    else:
        w.show()
    code = app.exec()
    # Capture work was stopped above. QThread and non-daemon threading workers cannot be
    # joined safely at interpreter exit, so end the process hard once cleanup is done.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError, AttributeError):
            pass
    os._exit(code)


if __name__ == "__main__":
    main()

