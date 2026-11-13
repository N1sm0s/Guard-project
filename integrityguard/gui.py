"""Графический интерфейс IntegrityGuard (PySide6)."""
from __future__ import annotations

import json
import getpass
import hashlib
import ipaddress
import os
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path

from PySide6.QtCore import QDate, QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
                               QDateEdit, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QStackedWidget,
                               QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .charts import ACCENT, SECOND, GroupBars, HBars, Heatmap, LiveLine, ScoreDots, VerdictBars
from . import online_learn
from . import recall as R
from .copilot import answer_with_ollama, list_ollama_models
from .network_ai import NetworkTelemetry, assess_network_with_ollama, telemetry_digest
from .paths import APP_ROOT as ROOT, DATA_ROOT as DATA, RESOURCE_ROOT
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
        super().__init__()
        self.setWindowTitle("IntegrityGuard — контроль целостности нейросетевых программ")
        self.resize(1280, 820)
        self.setMinimumSize(900, 600)
        icon = RESOURCE_ROOT / "assets" / "integrityguard.ico"
        self._icon_path = icon
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self.settings = QSettings(str(DATA / "settings.ini"), QSettings.IniFormat)
        self._guard = None
        self._workers: list[Worker] = []
        self._last_ev: dict | None = None
        self._candidate_busy = False
        self._copilot_worker: Worker | None = None
        self._network_telemetry = NetworkTelemetry()
        self._network_ai_busy = False
        self._network_ai_next = time.monotonic() + 10

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
        pages = [("Проверка пакета", self._page_check()), ("Мониторинг", self._page_monitor()),
                 ("Эталоны и версии", self._page_baselines()),
                 ("Журнал событий", self._page_events()), ("Полнота обнаружения", self._page_recall()),
                 ("Обучение и оценка", self._page_train()),
                 ("Настройки", self._page_settings()), ("ИИ-помощник", self._page_copilot())]
        for i, (name, page) in enumerate(pages):
            if i in (0, 2, 4, 6, 7):
                section_names = {0: "РАБОЧЕЕ МЕСТО", 2: "УПРАВЛЕНИЕ", 4: "КАЧЕСТВО МОДЕЛИ",
                                 6: "СИСТЕМА", 7: "ПОМОЩНИК"}
                sl.addWidget(label(section_names[i], "navSection"))
            b = QPushButton(name, objectName="nav", checkable=True)
            b.setCursor(Qt.PointingHandCursor)
            self.nav.addButton(b, i)
            sl.addWidget(b)
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
            self.auto_note.setText("Автоматический режим выключен (включается в настройках).")
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
        self.close()

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

    def _auto_status(self, last=""):
        self.auto_note.setText(f"Автоматический режим включён. Папка входящих пакетов: {self.incoming}"
                               + (f"\n{last}" if last else ""))

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
            w = self.run_bg(lambda _, d=d: self._auto_process(d), self._auto_done, silent=True)
            w.fail.connect(lambda _, path=str(d): self._done.pop(path, None))
            w.finished.connect(lambda: setattr(self, "_auto_busy", False))
            return

    def _auto_process(self, d: Path) -> dict:
        from .intake import process_incoming
        return process_incoming(d, self.processed, self._analyze_incoming, self._publish_incoming)

    def _publish_incoming(self, result):
        if "verdict" in result:
            if str(result.get("analysis_mode", "")).startswith("wheel_"):
                from .wheel_scan import persist_wheel_event
                persist_wheel_event(result, Path(self.cfg("registry")))
            else:
                self.guard().respond(result)

    def _analyze_incoming(self, d: Path):
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
                res = g.check(d, "deploy", self._index_for(d))
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
        elif name == "ИИ-помощник":
            self._copilot_refresh_models()

    def closeEvent(self, e):
        if getattr(self, "tray", None) and self.tray.isVisible() and not self._quitting:
            # окно скрывается в трей, фоновая проверка входящих пакетов не прерывается
            e.ignore()
            self.hide()
            if not self.settings.value("tray_hint_shown", False, type=bool):
                self.tray.showMessage(
                    "IntegrityGuard",
                    "Программа продолжает работать в фоне — значок в трее. "
                    "Проверка входящих пакетов не прерывается. Выход — через меню значка.",
                    QSystemTrayIcon.Information, 6000)
                self.settings.setValue("tray_hint_shown", True)
                self.settings.sync()
            return
        busy = [w for w in self._workers if w.isRunning()]
        if self._copilot_worker is not None and self._copilot_worker.isRunning():
            busy.append(self._copilot_worker)
        if busy:
            box = QMessageBox(QMessageBox.Question, "IntegrityGuard", "Идёт фоновая задача (проверка или обучение). "
                              "Прервать её и закрыть программу?", QMessageBox.Yes | QMessageBox.No, self)
            box.button(QMessageBox.Yes).setText("Прервать и закрыть")
            box.button(QMessageBox.No).setText("Не закрывать")
            if box.exec() != QMessageBox.Yes:
                return e.ignore()
        for w in busy:
            w.terminate()
            w.wait(2000)
        e.accept()

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
        self.net_note = label("", muted=True)
        self.net_card = card(self.ch_net, self.net_note, title="Входящие сетевые пакеты")
        p.lay.addWidget(self.net_card)
        self.net_ai_note = label(
            "Локальная ИИ-оценка запустится автоматически по текущим сетевым метаданным и состоянию IntegrityGuard. "
            "Оценка рекомендательная: пакетный payload не собирается, правила firewall модель не меняет.",
            muted=True, wrap=True)
        self.net_ai_note.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.lay.addWidget(card(self.net_ai_note, title="ИИ-оценка сетевого трафика и функций программы"))
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
                if self.auto_on() else "Автоматический режим выключен: проверки запускаются вручную.")
        last = f" Последняя проверка: {_when(evs[-1]['time'])}." if evs else " Проверок ещё не было."
        self.mon_state.setText(mode + last)
        self._load_audit()

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
        f = Path(self.cfg("registry")) / "events.jsonl"
        try:
            sig = (f.stat().st_mtime if f.exists() else 0, self._queue())
        except OSError:
            sig = None
        if sig != self._mon_sig:                          # журнал или очередь изменились — перерисовать
            self._mon_sig = sig
            self._load_monitor()
            self._load_events(keep_selection=True)        # «Журнал событий» тоже обновляется сам, без кнопки
        if self._psutil is None:
            if hasattr(self, "net_ai_note"):
                self.net_ai_note.setText("Сетевой сенсор psutil недоступен; модель не получает телеметрию и не выносит рекомендацию.")
            return
        try:
            io, now = self._psutil.net_io_counters(), time.monotonic()
        except Exception as e:  # noqa: BLE001 — счётчики сети недоступны на этом компьютере
            self._psutil = None
            self.ch_net.empty_text = f"Счётчики сети недоступны: {e}"
            self.ch_net.update()
            return
        if self._net_prev:
            p0, b0, t0 = self._net_prev
            dt = max(now - t0, 1e-3)
            rate = max(io.packets_recv - p0, 0) / dt
            self.ch_net.push(rate)
            self.net_note.setText(f"Сейчас: {rate:.0f} пак./с, {max(io.bytes_recv - b0, 0) / dt / 1024:.1f} КБ/с. "
                                  f"Обновление раз в секунду, окно 2 минуты.")
        self._net_prev = (io.packets_recv, io.bytes_recv, now)
        self._maybe_network_ai_assessment(now)

    def _maybe_network_ai_assessment(self, now: float | None = None):
        if getattr(self, "_network_ai_paused", False) or self._network_ai_busy:
            return
        now = time.monotonic() if now is None else now
        if now < self._network_ai_next:
            return
        # A slow local model cannot start overlapping scans. If a scan is still
        # running, the next one is scheduled only after it completes.
        self._network_ai_busy = True
        self._network_ai_next = now + 60
        model = str(self.settings.value("copilot_model", "qwen3.5:4b")).strip() or "qwen3.5:4b"
        self.net_ai_note.setText("Ollama анализирует живые счётчики интерфейсов, текущие соединения и состояние функций IntegrityGuard…")

        def work(_progress):
            from .copilot_audit import CopilotAudit
            from .copilot_tools import execute_tool

            context = self._copilot_tool_context()
            audit = CopilotAudit(DATA / "copilot_audit.sqlite")
            snapshot = app_state = None
            try:
                context["network_snapshot"] = self._network_telemetry.sample(self._psutil)
                snapshot = execute_tool("network_status", {}, context)
                app_state = execute_tool("monitoring_status", {}, context)
                assessment = assess_network_with_ollama(snapshot, app_state, model)
                digest = telemetry_digest(snapshot, app_state, assessment)
                assessment_json = json.dumps(assessment, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                audit.append(
                    principal=getpass.getuser(),
                    question="periodic_network_assessment",
                    answer=assessment_json,
                    model=assessment["model"],
                    status="insufficient_evidence" if assessment["insufficient_evidence"] else "answered",
                    source_hashes=[digest],
                    tool_calls=[{"name": "network_ai_assessment", "status": assessment["decision"],
                                 "result_sha256": hashlib.sha256(assessment_json.encode("utf-8")).hexdigest()}],
                )
                return snapshot, app_state, assessment
            except Exception as error:
                hashes = [telemetry_digest(snapshot, app_state, None)] if snapshot is not None and app_state is not None else []
                audit.append(
                    principal=getpass.getuser(), question="periodic_network_assessment",
                    answer=f"{type(error).__name__}: local network assessment failed",
                    model=model, status="error", source_hashes=hashes,
                    tool_calls=[{"name": "network_ai_assessment", "status": "error",
                                 "result_sha256": hashlib.sha256(type(error).__name__.encode("utf-8")).hexdigest()}],
                )
                raise

        def done(result):
            snapshot, app_state, assessment = result
            labels = {"ALLOW": "ЯВНАЯ АТАКА НЕ УСТАНОВЛЕНА", "REVIEW": "НУЖНА ПРОВЕРКА",
                      "BLOCK": "РЕКОМЕНДАЦИЯ: БЛОКИРОВАТЬ"}
            note = (f"{labels[assessment['decision']]} · модель {assessment['model']} · "
                    f"соединений: {snapshot['active_connection_count']}, удалённых endpoint: "
                    f"{snapshot['remote_endpoint_count']} · {snapshot['observed_at_utc']}\n"
                    f"{assessment['summary']}\n"
                    "Эта оценка Ollama не применяет правила Windows Firewall. "
                    "Сенсор видит счётчики и метаданные соединений, не payload пакетов.")
            if assessment["model_decision"] != assessment["decision"]:
                note += f"\nИсходная оценка Ollama: {assessment['model_decision']}."
            if assessment["evidence_ids"]:
                note += "\nОснования оценки (ID): " + ", ".join(assessment["evidence_ids"])
            intel = snapshot.get("threat_intelligence", {})
            if isinstance(intel, dict):
                match_count = len(intel.get("matches", []))
                note += (f"\nПубличный источник {intel.get('source', 'DShield')}: "
                         f"{match_count} совпадений, статус {intel.get('status', 'unknown')}; "
                         f"снимок {intel.get('checked_at_utc') or 'не получен'}. "
                         "Совпадение даёт контекст и само по себе не доказывает атаку.")
            if not snapshot["connection_table_query_succeeded"] or not snapshot["interface_counters_available"]:
                note += " Системный запрос телеметрии неполон или недоступен."
            self.net_ai_note.setText(note)
            self._network_ai_busy = False
            self._network_ai_next = time.monotonic() + 60

        def failed(message):
            self.net_ai_note.setText(
                f"ИИ-оценка сейчас недоступна: {message}. Сбор счётчиков продолжает работать; рекомендация не вынесена.")
            self._network_ai_busy = False
            self._network_ai_next = time.monotonic() + 300

        worker = Worker(work, self)
        worker.done.connect(done)
        worker.fail.connect(failed)

        def finish():
            self._network_ai_busy = False
            if worker in self._workers:
                self._workers.remove(worker)

        worker.finished.connect(finish)
        self._workers.append(worker)
        worker.start()

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
            from .copilot_audit import CopilotAudit
            audit = CopilotAudit(DATA / "copilot_audit.sqlite")
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

    def _copilot_tool_context(self) -> dict:
        from .copilot_tools import COPILOT_READ_CAPABILITIES
        return {"principal": getpass.getuser(), "data_root": DATA, "incoming": self.incoming,
                "processed": self.processed, "registry": Path(self.cfg("registry")),
                "detector": Path(self.cfg("model")), "auto_enabled": self.auto_on(),
                "network_intel_enabled": True,
                "capabilities": sorted(COPILOT_READ_CAPABILITIES)}

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
        p = Page("Проверка пакета", "Кандидат сравнивается с зарегистрированным эталоном на трёх уровнях целостности: "
                                    "структурном (граф зависимостей), параметрическом (веса) и поведенческом (отклик модели).")
        self.auto_note = label("", muted=True, wrap=True)
        self.auto_note.setTextInteractionFlags(Qt.TextSelectableByMouse)
        open_btn = QPushButton("Открыть папку входящих")
        open_btn.clicked.connect(self._open_incoming)
        arow = QHBoxLayout()
        arow.addWidget(self.auto_note, 1)
        arow.addWidget(open_btn)
        p.lay.addWidget(card(arow))
        # ---- главный блок: ровно 1-2 клика и больше ничего делать не нужно ----
        self.pkg = PathEdit("Каталог пакета-кандидата (manifest.json, model.pt, src/)")
        self.pkg.picked.connect(self._check)
        self.pkg.edit.textChanged.connect(self._sync_watch)
        self.watch_note = label("", muted=True, wrap=True)
        hero = QVBoxLayout()
        hero.addWidget(label("Что проверить?", "h2"))
        hero.addWidget(label("Укажите каталог своего пакета — проверка начнётся сама, без лишних кнопок.",
                              muted=True, wrap=True))
        hero.addWidget(self.pkg)
        hero.addWidget(self.watch_note)
        p.lay.addWidget(card(hero))

        # ---- дополнительные параметры: скрыты по умолчанию, чтобы не пугать при первом запуске ----
        self.stage = QComboBox()
        for code, name in (("build", "Сборка"), ("deploy", "Поставка"), ("runtime", "Эксплуатация")):
            self.stage.addItem(name, code)
        self.strict = QCheckBox("Строгий режим («на проверку» = блокировка)")
        self.promote = QCheckBox("При допуске сделать новым эталоном")
        self.check_btn = QPushButton("Проверить", objectName="primary")
        self.check_btn.setMinimumWidth(150)
        self.check_btn.clicked.connect(self._check)
        g = QGridLayout()
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(10)
        g.addWidget(label("Стадия", muted=True), 0, 0)
        g.addWidget(self.stage, 0, 1)
        g.addWidget(self.strict, 0, 2)
        g.addWidget(self.promote, 0, 3)
        g.setColumnStretch(2, 1)
        row = QHBoxLayout()
        row.addWidget(self.check_btn)
        row.addStretch(1)
        adv_body = QWidget()
        adv_lay = QVBoxLayout(adv_body)
        adv_lay.setContentsMargins(0, 8, 0, 0)
        adv_lay.setSpacing(10)
        adv_lay.addLayout(g)
        adv_lay.addLayout(row)
        adv_body.hide()
        self._adv_body = adv_body
        self.adv_toggle = QPushButton("▸  Дополнительные параметры (стадия и политика проверки)",
                                      objectName="flat")
        self.adv_toggle.setCursor(Qt.PointingHandCursor)
        self.adv_toggle.clicked.connect(self._toggle_advanced)
        p.lay.addWidget(card(self.adv_toggle, adv_body))

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
        lv_card = card(lv, title="Оценки по уровням целостности")
        lv_card.layout().addStretch(1)
        two.addWidget(lv_card, 1)
        two.addWidget(card(self.suspects, title="Локализация"), 1)
        self.result_card = card(head)
        p.lay.addWidget(self.result_card)
        p.lay.addLayout(two)
        p.lay.addWidget(card(self.actions, title="Рекомендуемые действия реагирования"))
        p.lay.addStretch(1)
        self._watch_seen = None
        self._watch_fingerprint = None
        self._watch_last_fingerprint_at = 0.0
        self._watch_timer = QTimer(self)
        self._watch_timer.timeout.connect(self._watch_tick)
        saved_pkg = self.settings.value("watch_pkg", "")
        if saved_pkg:
            self.pkg.setText(saved_pkg)                    # восстановление после перезапуска: наблюдение пойдёт само
        else:
            self._sync_watch("")
        return p

    def _set_badge(self, verdict):
        text, color = VERDICT.get(verdict, ("—", "#2a2f3a"))
        self.badge.setText(text)
        self.badge.setStyleSheet(f"background: {color}; color: white; border-radius: 9px; font-size: 13pt; "
                                 f"font-weight: 700; padding: 6px 18px;")

    def _index_for(self, pkg):
        side = Path(f"{pkg}.index.json")       # необязательный доверенный индекс рядом с пакетом
        return str(side) if side.exists() else None

    def _check(self):
        pkg = self.pkg.text()
        if not pkg or not (Path(pkg) / "manifest.json").exists():
            self.notify("Укажите каталог реального пакета с manifest.json, используя кнопку «Обзор…».", "warn")
            return
        stage, strict, promote = self.stage.currentData(), self.strict.isChecked(), self.promote.isChecked()

        def job(_):
            g = self.guard()
            from .collect import fingerprint
            try:
                before = fingerprint(pkg)
                ev = g.check(pkg, stage, self._index_for(pkg), strict)
                if fingerprint(pkg) != before:
                    ev = g.assessment_error(pkg, "пакет изменился во время проверки; результат сравнения не сохранён",
                                            stage)
            except (ValueError, OSError) as error:
                ev = g.assessment_error(pkg, error, stage)
            ev = self._apply_policy(ev)
            g.respond(ev, pkg, promote)
            return ev
        self.run_bg(job, lambda ev: (self._show_event(ev), self._refresh_views()), self.check_btn)

    def _toggle_advanced(self):
        """Разворачивает/сворачивает блок дополнительных параметров — скрыт по умолчанию, чтобы при первом
        запуске на странице было видно только главное: куда указать пакет и кнопку «показать на примере»."""
        show = not self._adv_body.isVisible()
        self._adv_body.setVisible(show)
        self.adv_toggle.setText(("▾  " if show else "▸  ") + "Дополнительные параметры (стадия и политика проверки)")

    # ------------------------------------------------------------ автопроверка каталога (без кнопок и галочек)
    def _sync_watch(self, text):
        """Как только указан каталог пакета, он сам проверяется и сам наблюдается — без отдельного включения.

        Путь запоминается, а дальше ничего выбирать и нажимать не нужно: проверка идёт сама при появлении
        пути и повторяется сама при каждом изменении файлов в нём. Чтобы остановить наблюдение — очистите поле."""
        self.settings.setValue("watch_pkg", text)
        self.settings.sync()
        pkg = text.strip()
        if not pkg:
            self._watch_timer.stop()
            self._watch_seen = None
            self._watch_fingerprint = None
            self._watch_last_fingerprint_at = 0.0
            self.watch_note.setText("Автопроверка: укажите каталог реального пакета кнопкой «Обзор…» "
                                    "или поместите его во входящую папку.")
            return
        if not (Path(pkg) / "manifest.json").exists():
            self._watch_timer.stop()
            self._watch_seen = None
            self._watch_fingerprint = None
            self._watch_last_fingerprint_at = 0.0
            self.watch_note.setText(f"Автопроверка приостановлена: в «{pkg}» нет manifest.json.")
            return
        self._watch_seen = None
        self._watch_fingerprint = None
        self._watch_last_fingerprint_at = 0.0
        if not self._watch_timer.isActive():
            self._watch_timer.start(4000)
        QTimer.singleShot(150, self._watch_tick)
        self.watch_note.setText(f"Автопроверка включена: «{pkg}» проверяется сам при каждом изменении, "
                                "без выбора и без кнопок.")

    def _watch_tick(self):
        """Наблюдение за выбранным каталогом: изменение файлов запускает проверку само, без участия пользователя."""
        pkg = self.pkg.text()
        p = Path(pkg) if pkg else None
        if self._workers or not p or not (p / "manifest.json").exists():
            return
        path_key = str(p.resolve())
        previous = self._watch_seen
        full_hash_due = time.monotonic() - self._watch_last_fingerprint_at >= 60.0

        def inspect(_):
            try:
                from .collect import fingerprint
                files = [item for item in p.rglob("*") if item.is_file()]
                stats = [item.stat() for item in files]
                signature = (len(stats), sum(stat.st_size for stat in stats),
                             max((stat.st_mtime_ns for stat in stats), default=0))
                changed = signature != previous
                digest = fingerprint(p) if changed or full_hash_due or self._watch_fingerprint is None else None
                return signature, digest, None
            except (OSError, ValueError) as error:
                return None, None, str(error)

        def inspected(result):
            signature, digest, error = result
            if str(Path(self.pkg.text()).resolve()) != path_key:
                return
            if error:
                self.watch_note.setText(f"Автопроверка: не удалось прочитать пакет; будет повтор: {error}")
                return
            self._watch_seen = signature
            if digest is None:
                return
            self._watch_last_fingerprint_at = time.monotonic()
            if digest != self._watch_fingerprint:
                self._watch_fingerprint = digest
                self._check()

        self.run_bg(inspect, inspected, silent=True)

    def _show_event(self, ev):
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
            color = "#e5484d" if (v or 0) >= 0.5 else "#2bb7ab"
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}")
        self.suspects.setRowCount(0)
        for s in ev.get("suspects", []):
            add_row(self.suspects, [_component_ru(s["component"]), f"{s['score']:.2f}"])
        acts = ev.get("actions", [])
        self.actions.setText("<br>".join(f"•&nbsp; {a}" for a in acts) if acts else
                             "<span style='color:#8a8f99'>Действия не требуются: пакет допущен.</span>")
        self._refresh_status()
        if ev.get("verdict") == "BLOCK":
            self._auto_block_report(ev)
            self._notify_block(ev)

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
        self.e_auto_note = label("Обновляется само при появлении новых событий.", muted=True)
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
        self.label_coverage_table = table(["Класс", "Предложено", "Подтверждено", "Оценка качества"], 0)
        self.label_coverage_table.setMinimumHeight(310)
        p.lay.addWidget(card(self.label_coverage_note, self.label_coverage_table,
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
            self.label_coverage_note.setText(f"Не удалось прочитать реестр разметки: {error}")
            return
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
        try:
            from .release import recover_release
            state = recover_release(DATA, self.cfg("model"))
        except Exception as error:
            self.notify(f"Не удалось проверить незавершённую операцию выпуска: {error}", "error")
            return
        if state and state.get("status") == "needs_review":
            self.notify("После сбоя модель не совпала с ожидаемыми хешами выпуска. Выпуск остановлен; "
                        "проверьте резервные копии и журнал релизов.", "error")
        elif state and state.get("recovered_after_crash"):
            self.notify(f"Восстановлено состояние операции выпуска: {state['status']}.", "info")

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
    def _page_copilot(self):
        p = Page("ИИ-помощник сети", "Локальная модель анализирует текущую сетевую телеметрию и read-only состояние функций IntegrityGuard. Документы и файлы помощником не читаются.")
        self.cp_status = label(
            "Ollama получает только агрегированные сетевые счётчики, метаданные соединений и безопасную сводку приложения. Пакеты не захватываются; firewall не меняется.",
            muted=True, wrap=True)
        self.cp_status.setObjectName("copilot_status")
        p.lay.addWidget(card(self.cp_status, title="Состояние помощника"))

        self.cp_question = QLineEdit(placeholderText="Например: оцени текущий трафик и проверь состояние IntegrityGuard")
        self.cp_question.returnPressed.connect(self._copilot_search)
        self.cp_model = QComboBox()
        self.cp_model.setEditable(True)
        self.cp_model.setInsertPolicy(QComboBox.NoInsert)
        self.cp_model.lineEdit().setPlaceholderText("Локальная модель Ollama, например qwen3.5:4b")
        self.cp_model.setEditText(str(self.settings.value("copilot_model", "qwen3.5:4b")))
        self.cp_search = QPushButton("Оценить сеть / состояние приложения", objectName="primary")
        self.cp_search.clicked.connect(self._copilot_search)
        self.cp_refresh = QPushButton("Обновить модели")
        self.cp_refresh.clicked.connect(self._copilot_refresh_models)
        self.cp_results = QPlainTextEdit(readOnly=True)
        self.cp_results.setPlaceholderText("Рекомендация по живым сетевым метаданным или данные read-only функций IntegrityGuard появятся здесь.")
        self.cp_results.setMinimumHeight(300)
        model_row = QHBoxLayout()
        model_row.addWidget(self.cp_model, 1)
        model_row.addWidget(self.cp_refresh)
        p.lay.addWidget(card(self.cp_question, model_row, self.cp_search, title="Сетевой запрос"))
        p.lay.addWidget(card(self.cp_results, title="Результат мониторинга"))
        p.lay.addStretch(1)
        return p

    def _copilot_search(self):
        if self._copilot_worker is not None and self._copilot_worker.isRunning():
            return
        query = self.cp_question.text().strip()
        if not query:
            self.notify("Введите запрос о сети или состоянии IntegrityGuard.", "warn")
            return
        self.cp_results.setPlainText("Получаю текущую сетевую телеметрию и read-only состояние функций IntegrityGuard.")
        model = self.cp_model.currentText().strip()
        if model:
            self.settings.setValue("copilot_model", model)
            self.settings.sync()

        from .copilot_audit import CopilotAudit
        principal = getpass.getuser()
        tool_context = self._copilot_tool_context()
        audit = CopilotAudit(DATA / "copilot_audit.sqlite")

        def work(_progress):
            try:
                try:
                    answer = answer_with_ollama(query, model, tool_context=tool_context) if model else None
                    warning = None
                except Exception as error:
                    answer = None
                    warning = f"{type(error).__name__}: {str(error)[:400]}"
                if answer is None:
                    warning = warning or "Не выбрана локальная модель Ollama."
                    output, status, audit_model, calls = warning, "error", "unconfigured", []
                else:
                    output = answer["answer"]
                    status = "insufficient_evidence" if answer["insufficient_evidence"] else "answered"
                    audit_model = answer["model"]
                    calls = answer.get("tool_calls", [])
                audit.append(principal=principal, question=query, answer=output, model=audit_model,
                             status=status, source_hashes=[], tool_calls=calls)
                return answer, warning
            except Exception as error:
                audit.append(principal=principal, question=query,
                             answer=f"{type(error).__name__}: {str(error)[:500]}",
                             model=model or "unconfigured", status="error",
                             source_hashes=[], tool_calls=[])
                raise

        def done(result):
            answer, warning = result
            blocks = []
            if warning:
                blocks.append(warning)
            if answer is not None:
                if answer["insufficient_evidence"]:
                    blocks.append("Запрос вне поддерживаемого сетевого/операционного охвата или данных недостаточно.")
                blocks.append(f"ИИ ({answer['model']}):\n{answer['answer']}")
                for item in answer.get("tool_results", []):
                    blocks.append(f"\nДанные IntegrityGuard [{item['citation_id']}] (read-only):\n"
                                  f"{json.dumps(item['data'], ensure_ascii=False, indent=2)}")
            blocks.append("\nПомощник не читает пользовательские документы и содержимое файлов. "
                          "Захвата packet payload нет; вывод модели не меняет Windows Firewall. "
                          "Хеши запросов и вызовов записываются в локальный hash-chain аудит.")
            self.cp_results.setPlainText("\n\n".join(blocks))

        worker = Worker(work, self)
        self._copilot_worker = worker
        self.cp_search.setEnabled(False)
        worker.done.connect(done)
        worker.fail.connect(lambda msg: self.notify(msg, "error"))

        def finish():
            self.cp_search.setEnabled(True)
            self._copilot_worker = None
            if worker in self._workers:
                self._workers.remove(worker)

        worker.finished.connect(finish)
        self._workers.append(worker)
        worker.start()

    def _copilot_refresh_models(self):
        if self._copilot_worker is not None and self._copilot_worker.isRunning():
            return
        selected = self.cp_model.currentText().strip()
        self.cp_refresh.setEnabled(False)

        def done(names):
            self.cp_model.clear()
            self.cp_model.addItems(names)
            if selected:
                self.cp_model.setEditText(selected)
            elif names:
                preferred = next((n for n in names if n.startswith("qwen3.5:4b")), names[0])
                self.cp_model.setCurrentText(preferred)
            self.cp_status.setText(
                f"Ollama отвечает на локальном адресе. Найдено моделей: {len(names)}. "
                "Модель получает только телеметрию сети и read-only состояние приложения.")

        worker = Worker(lambda _progress: list_ollama_models(), self)
        self._copilot_worker = worker
        worker.done.connect(done)
        worker.fail.connect(lambda msg: self.cp_status.setText(
            f"Ollama пока не обнаружена: {msg}. Проверка сети недоступна до запуска локальной модели."))

        def finish():
            self.cp_refresh.setEnabled(True)
            self._copilot_worker = None
            if worker in self._workers:
                self._workers.remove(worker)

        worker.finished.connect(finish)
        self._workers.append(worker)
        worker.start()

    # ------------------------------------------------------------ страница «Настройки»
    def _page_settings(self):
        p = Page("Настройки", "Пути к реестру эталонов, модели детектора и ключу подписи пакетов.")
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
        self.s_auto = QCheckBox("Автоматически проверять реальные пакеты из папки входящих")
        self.s_auto.setChecked(str(self.settings.value("auto", "true")).lower() != "false")
        g.addWidget(self.s_auto, 3, 1)
        self.s_autostart = QCheckBox("Запускать автоматически при входе в Windows (в трее, без открытия окна)")
        self.s_autostart.setChecked(self._autostart_enabled())
        if sys.platform != "win32" or not QSystemTrayIcon.isSystemTrayAvailable():
            self.s_autostart.setEnabled(False)
            self.s_autostart.setToolTip("Доступно только в Windows со значком в трее.")
        g.addWidget(self.s_autostart, 4, 1)
        self.s_retention = QSpinBox(minimum=0, maximum=3650, suffix=" дн.")
        self.s_retention.setToolTip("Через сколько дней автоматически удалять уже обработанные пакеты "
                                    "(allow/review/block) из data/processed. 0 — не удалять (хранить всегда).")
        try:
            self.s_retention.setValue(int(self.settings.value("processed_retention_days", 30)))
        except (TypeError, ValueError):
            self.s_retention.setValue(30)
        g.addWidget(label("Хранить обработанные пакеты во входящих", muted=True), 5, 0)
        g.addWidget(self.s_retention, 5, 1)
        btn = QPushButton("Сохранить", objectName="primary")
        btn.clicked.connect(self._save_settings)
        self.s_note = label("", muted=True)
        row = QHBoxLayout()
        row.addWidget(btn)
        row.addWidget(self.s_note, 1)
        p.lay.addWidget(card(g, row))

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
        pbtn = QPushButton("Сохранить политику", objectName="primary")
        pbtn.clicked.connect(self._save_policy)
        self.s_policy_note = label("", muted=True)
        prow = QHBoxLayout()
        prow.addWidget(pbtn)
        prow.addWidget(self.s_policy_note, 1)
        p.lay.addWidget(card(pg, prow, title="Политики блокировки"))
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
            self.auto_note.setText("Автоматический режим выключен (включается в настройках).")
        self._guard = None
        self._refresh_status()
        self._load_metrics()
        self._load_monitor()
        self.s_note.setText("Сохранено.")


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
    app.setQuitOnLastWindowClosed(False)               # окно скрывается в трей, а не завершает программу
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
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

