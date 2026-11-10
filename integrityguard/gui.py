"""Графический интерфейс IntegrityGuard (PySide6)."""
from __future__ import annotations

import json
import shutil
import sys
import time
import traceback
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import (QApplication, QButtonGroup, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QStackedWidget,
                               QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .charts import ACCENT, SECOND, GroupBars, HBars, Heatmap, LiveLine, ScoreDots, VerdictBars
from . import recall as R
from .paths import APP_ROOT as ROOT, DATA_ROOT as DATA, RESOURCE_ROOT
from .spec import CLASS_LEVEL, CLASS_RU, CLASSES, LEVEL_RU, LEVELS

VERDICT = {"ALLOW": ("ДОПУСК", "#1f9d63"), "REVIEW": ("НА ПРОВЕРКУ", "#d99a1c"), "BLOCK": ("БЛОКИРОВКА", "#e5484d")}
THREAT_SHORT = {"clean": "норма", "dependency": "зависимости", "weights": "веса", "backdoor": "бэкдор",
                "poison": "отравление данных", "label_flip": "подмена меток",
                "adversarial": "состяз. входы", "extraction": "извлечение", "availability": "доступность"}
THREAT_TINY = {"clean": "норма", "dependency": "зависим.", "weights": "веса", "backdoor": "бэкдор",
               "poison": "отравл.", "label_flip": "метки",
               "adversarial": "состяз.", "extraction": "извлеч.", "availability": "доступн."}
STAGE_RU = {"build": "сборка", "deploy": "поставка", "runtime": "эксплуатация"}
NOTE_COLOR = {"error": "#e5484d", "warn": "#d99a1c", "info": "#3b82f6", "ok": "#1f9d63"}

QSS = """
* { font-family: "Segoe UI", "Inter", "DejaVu Sans", sans-serif; font-size: 10.5pt; color: #e6e9ef; }
QMainWindow, QWidget#page, QScrollArea, QScrollArea > QWidget > QWidget { background: #0f1218; }
QWidget#side { background: #151a22; border-right: 1px solid #232a36; }
QLabel#brand { font-size: 14pt; font-weight: 700; }
QLabel#sub, QLabel[muted="true"] { color: #8b94a5; }
QLabel#h1 { font-size: 17pt; font-weight: 600; }
QLabel#h2 { font-size: 11.5pt; font-weight: 600; }
QPushButton#nav { text-align: left; padding: 11px 16px; border: none; border-radius: 8px; color: #aab2c0; background: transparent; }
QPushButton#nav:hover { background: #1c222d; color: #e6e9ef; }
QPushButton#nav:checked { background: #1f2a3d; color: #ffffff; font-weight: 600; }
QFrame#card { background: #171c25; border: 1px solid #252d3a; border-radius: 12px; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox { background: #0f1218; border: 1px solid #2a3342; border-radius: 8px; padding: 7px 10px; selection-background-color: #3b82f6; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border-color: #3b82f6; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView { background: #171c25; border: 1px solid #2a3342; selection-background-color: #1f2a3d; }
QPushButton { background: #222a37; border: 1px solid #2f394a; border-radius: 8px; padding: 8px 16px; }
QPushButton:hover { background: #2a3443; }
QPushButton:disabled { color: #5d6675; background: #1a202a; }
QPushButton#primary { background: #3b82f6; border-color: #3b82f6; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #5293f7; }
QPushButton#primary:disabled { background: #25436f; border-color: #25436f; color: #8fa6c9; }
QTableWidget { background: #171c25; border: 1px solid #252d3a; border-radius: 10px; gridline-color: transparent; alternate-background-color: #1a202a; }
QTableWidget::item { padding: 6px 8px; border: none; }
QTableWidget::item:selected { background: #1f2a3d; }
QHeaderView::section { background: #171c25; color: #8b94a5; border: none; border-bottom: 1px solid #252d3a; padding: 8px; font-weight: 600; }
QTableCornerButton::section { background: #171c25; border: none; }
QPlainTextEdit { background: #0b0e13; border: 1px solid #252d3a; border-radius: 10px; padding: 8px; font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace; font-size: 9.5pt; }
QProgressBar { background: #0f1218; border: 1px solid #252d3a; border-radius: 6px; height: 12px; text-align: center; font-size: 8pt; }
QProgressBar::chunk { background: #3b82f6; border-radius: 5px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #2a3342; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2a3342; border-radius: 4px; min-width: 30px; }
QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #3a4558; background: #0f1218; }
QCheckBox::indicator:checked { background: #3b82f6; border-color: #3b82f6; }
QDialog, QMessageBox { background-color: #171c25; }
QMessageBox QLabel { color: #e6e9ef; font-size: 10.5pt; background: transparent; }
QMessageBox QPushButton { min-width: 84px; }
QFrame#banner { background: #1a202a; border: none; border-bottom: 1px solid #252d3a; }
QPushButton#flat { background: transparent; border: none; padding: 4px 10px; color: #8b94a5; }
QPushButton#flat:hover { color: #e6e9ef; background: #222a37; }
QLabel { background: transparent; }
QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button, QDoubleSpinBox::down-button { width: 18px; border: none; background: transparent; }
QToolTip { background: #171c25; color: #e6e9ef; border: 1px solid #2a3342; }
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


def add_row(t, values, color=None, color_col=None):
    r = t.rowCount()
    t.insertRow(r)
    for c, v in enumerate(values):
        it = QTableWidgetItem(str(v))
        if color and c == color_col:
            it.setForeground(QColor(color))
            f = it.font()
            f.setBold(True)
            it.setFont(f)
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
        self.lay.setContentsMargins(28, 24, 28, 24)
        self.lay.setSpacing(14)
        self.lay.addWidget(label(title, "h1"))
        self.lay.addWidget(label(subtitle, muted=True, wrap=True))
        self.setWidget(body)


# ---------------------------------------------------------------- главное окно
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IntegrityGuard — контроль целостности нейросетевых программ")
        self.resize(1240, 800)
        self.setMinimumSize(1000, 640)
        icon = RESOURCE_ROOT / "assets" / "integrityguard.ico"
        self._icon_path = icon
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self.settings = QSettings(str(DATA / "settings.ini"), QSettings.IniFormat)
        self._guard = None
        self._workers: list[Worker] = []
        self._last_ev: dict | None = None

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QWidget(objectName="side")
        side.setFixedWidth(232)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 20, 14, 16)
        sl.setSpacing(4)
        sl.addWidget(label("IntegrityGuard", "brand"))
        sl.addWidget(label("контроль целостности ПНП", "sub"))
        sl.addSpacing(18)
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
                 ("Настройки", self._page_settings())]
        for i, (name, page) in enumerate(pages):
            b = QPushButton(name, objectName="nav", checkable=True)
            b.setCursor(Qt.PointingHandCursor)
            self.nav.addButton(b, i)
            sl.addWidget(b)
            self.stack.addWidget(page)
        sl.addStretch(1)
        self.status = label("", "sub", wrap=True)
        sl.addWidget(self.status)
        self.nav.idClicked.connect(self._goto)
        self.nav.button(0).setChecked(True)
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
        self._refresh_demo()
        self.net_timer.start(1000)                        # график сети и журнал обновляются всё время работы
        # --- автоматический режим
        self.incoming, self.processed = DATA / "incoming", DATA / "processed"
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
                hint.write_text("Скопируйте сюда каталог пакета (с manifest.json и model.pt).\n"
                                "IntegrityGuard проверит его сам и переложит в data/processed/<вердикт>/.\n"
                                "Первый пакет с новым именем становится эталоном.\n", encoding="utf-8-sig")
        except OSError as e:
            self.notify(f"Не удалось создать папку входящих пакетов {self.incoming}: {e}")
        self.auto_timer.start(3000)
        self._auto_status()
        self._auto_prepare()

    def _demo_ready(self) -> bool:
        """Демо-набор на месте: есть разметка, сами пакеты и их эталон в реестре."""
        if not self.demo_labels:
            return False
        lb = self.demo_labels[0]
        cand = self._demo_dir() / lb["project"] / "candidates" / lb["candidate"] / "manifest.json"
        return cand.exists() and str(self.settings.value("demo_baseline", "")) in self._baseline_names()

    def _auto_prepare(self):
        """Следующий недостающий шаг подготовки: детектор -> демо-набор -> его проверка."""
        if self._workers:
            return
        if not Path(self.cfg("model")).is_file():         # детектора нет — обучаем с параметрами по умолчанию
            self.nav.button(self._page_index("Обучение и оценка")).click()
            self._train()
        elif not self._demo_ready():                      # первый запуск — демо-набор и его проверка
            self._make_demo(then_check=True)
        elif not self._read_events():
            self._check_all()

    def _page_index(self, name):
        return [b.text() for b in self.nav.buttons()].index(name)

    def _auto_status(self, last=""):
        self.auto_note.setText(f"Автоматический режим включён. Папка входящих пакетов: {self.incoming}"
                               + (f"\n{last}" if last else ""))

    def _auto_tick(self):
        """Наблюдение за папкой входящих: новый пакет проверяется, как только его копирование завершилось."""
        if self._auto_busy or self._workers or not self.incoming.exists():
            return
        for d in sorted(p for p in self.incoming.iterdir() if p.is_dir()):
            files = [f for f in d.rglob("*") if f.is_file()]
            sig = (len(files), sum(f.stat().st_size for f in files), max((f.stat().st_mtime for f in files), default=0))
            prev = self._seen.get(str(d))
            self._seen[str(d)] = sig
            if prev != sig or not (d / "manifest.json").exists() or self._done.get(str(d)) == sig:
                continue                                  # ещё копируется, не пакет или уже обработан
            self._auto_busy = True
            self._done[str(d)] = sig
            w = self.run_bg(lambda _, d=d: self._auto_process(d), self._auto_done, silent=True)
            w.finished.connect(lambda: setattr(self, "_auto_busy", False))
            return

    def _auto_process(self, d: Path) -> dict:
        """Обработка входящего пакета: эталон при первом появлении, иначе проверка и раскладка по вердикту."""
        from .collect import load_package
        g = self.guard()
        try:
            spec = load_package(d, g.key)
            if not (g._base(spec.name) / "package").exists():
                if g.key is None or not spec.signed_ok:
                    g.sign(d)                             # первый пакет подписывается ключом реестра
                ctrl = next((c for c in (d / "control.npz", d.parent / f"{d.name}.control.npz") if c.exists()), None)
                g.register_baseline(d, ctrl, note="auto: первое появление")
                res = {"auto": "baseline", "package": spec.name, "version": spec.version, "control": bool(ctrl)}
                dest = "baseline"
            else:
                res = g.check(d, "deploy", self._index_for(d))
                res = self._apply_policy(res)
                g.respond(res)
                dest = res["verdict"].lower()
        except (ValueError, OSError) as e:
            res, dest = {"auto": "error", "package": d.name, "error": str(e)}, "error"
        target = self.processed / dest / f"{d.name}_{time.strftime('%Y%m%d_%H%M%S')}"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(d), str(target))
            side = Path(f"{d}.index.json")
            if side.exists():
                shutil.move(str(side), f"{target}.index.json")
            res["moved_to"] = str(target)
        except OSError:
            res["moved_to"] = ""                          # не удалось переместить — пакет остаётся во входящих
        return res

    def _auto_done(self, res: dict):
        if res.get("auto") == "baseline":
            last = (f"Последнее событие: пакет «{res['package']}» {res['version']} встречен впервые и зарегистрирован как эталон"
                    + ("" if res["control"] else " (без контрольного набора — поведенческий уровень не проверяется)") + ".")
        elif res.get("auto") == "error":
            last = f"Последнее событие: «{res['package']}» не обработан — {res['error']}"
        else:
            self._show_event(res)
            last = (f"Последнее событие: «{res['package']}» {res['version']} — {VERDICT[res['verdict']][0].lower()}, "
                    f"{res['threat_ru']}.")
        self._auto_status(last)
        self._refresh_status()
        self._refresh_views()

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
                    base = DATA if getattr(sys, "frozen", False) and key == "registry" else RESOURCE_ROOT
                    configured = base / configured
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
        self.status.setText(f"Детектор: {'готов' if ok else 'не обучен'}\nЭталонов в реестре: {n}\n"
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
                        and isinstance(ev.get("score"), (int, float)):
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
        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        self.tiles = {}
        for key, name, color in (("total", "Проверено пакетов", "#e6e9ef"), ("ALLOW", "Допущено", VERDICT["ALLOW"][1]),
                                 ("REVIEW", "На проверку", VERDICT["REVIEW"][1]), ("BLOCK", "Заблокировано", VERDICT["BLOCK"][1]),
                                 ("queue", "Ждут во входящих", "#e6e9ef")):
            val = label("0")
            val.setStyleSheet(f"font-size: 22pt; font-weight: 600; color: {color};")
            self.tiles[key] = val
            tiles.addWidget(card(label(name, muted=True), val), 1)
        p.lay.addLayout(tiles)
        self.ch_flow, self.ch_score, self.ch_threat = VerdictBars(), ScoreDots(), HBars()
        self.ch_flow.empty_text = self.ch_score.empty_text = self.ch_threat.empty_text = \
            "Проверок пока не было. График появится после первой проверки пакета."
        p.lay.addWidget(card(self.ch_flow, title="Входящие пакеты: число проверок по времени"))
        row = QHBoxLayout()
        row.setSpacing(14)
        row.addWidget(card(self.ch_score, title="Оценка нарушения по пакетам"), 3)
        row.addWidget(card(self.ch_threat, title="Заключения детектора"), 2)
        p.lay.addLayout(row)
        self.mon_table = table(["Время", "Пакет", "Версия", "Стадия", "Вердикт", "Заключение", "Оценка"], 1)
        self.mon_table.setMinimumHeight(250)
        p.lay.addWidget(card(self.mon_table, title="Последние проверки"))
        self.ch_net = LiveLine("пак./с")
        self.ch_net.empty_text = "Идёт сбор данных о сети…"
        self.net_note = label("", muted=True)
        self.net_card = card(self.ch_net, self.net_note, title="Входящие сетевые пакеты")
        p.lay.addWidget(self.net_card)
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
            return sum(1 for d in self.incoming.iterdir() if d.is_dir() and (d / "manifest.json").exists())
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
        self.ch_threat.set_rows([(THREAT_SHORT[c], sum(e.get("threat") == c for e in evs)) for c in CLASSES])
        self.mon_table.setRowCount(0)
        for ev in evs[-12:][::-1]:
            text, color = VERDICT[ev["verdict"]]
            add_row(self.mon_table, [_when(ev["time"]), ev.get("package", ""), ev.get("version", ""),
                                     STAGE_RU.get(ev.get("stage"), ev.get("stage", "")), text, THREAT_SHORT.get(ev.get("threat"), "—"), f"{ev['score']:.3f}"], color, 4)
        mode = (f"Автоматический режим включён: пакеты из папки {getattr(self, 'incoming', '')} проверяются сами."
                if self.auto_on() else "Автоматический режим выключен: проверки запускаются вручную.")
        last = f" Последняя проверка: {_when(evs[-1]['time'])}." if evs else " Проверок ещё не было."
        self.mon_state.setText(mode + last)

    def _net_tick(self):
        """Раз в секунду: обновление графиков при изменении журнала и новая точка графика сети."""
        f = Path(self.cfg("registry")) / "events.jsonl"
        try:
            sig = (f.stat().st_mtime if f.exists() else 0, self._queue())
        except OSError:
            sig = None
        if sig != self._mon_sig:                          # журнал или очередь изменились — перерисовать
            self._mon_sig = sig
            self._load_monitor()
        if self._psutil is None:
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
        self.demo_try_btn = QPushButton("▶  Показать на примере", objectName="primary")
        self.demo_try_btn.setMinimumHeight(40)
        self.demo_try_btn.clicked.connect(self._try_demo)
        or_row = QHBoxLayout()
        or_row.addWidget(label("———  или  ———", muted=True), 0, Qt.AlignCenter)
        hero = QVBoxLayout()
        hero.addWidget(label("Что проверить?", "h2"))
        hero.addWidget(label("Укажите каталог своего пакета — проверка начнётся сама, без лишних кнопок.",
                              muted=True, wrap=True))
        hero.addWidget(self.pkg)
        hero.addWidget(self.watch_note)
        hero.addLayout(or_row)
        hero.addWidget(self.demo_try_btn, 0, Qt.AlignLeft)
        p.lay.addWidget(card(hero))

        # ---- дополнительные параметры: скрыты по умолчанию, чтобы не пугать при первом запуске ----
        self.demo_box = QComboBox()
        self.demo_box.currentIndexChanged.connect(self._pick_demo)
        self.demo_btn = QPushButton("Создать демонстрационные пакеты")
        self.demo_btn.clicked.connect(lambda: self._make_demo())
        self.stage = QComboBox()
        for code, name in (("build", "Сборка"), ("deploy", "Поставка"), ("runtime", "Эксплуатация")):
            self.stage.addItem(name, code)
        self.strict = QCheckBox("Строгий режим («на проверку» = блокировка)")
        self.promote = QCheckBox("При допуске сделать новым эталоном")
        self.check_btn = QPushButton("Проверить", objectName="primary")
        self.check_btn.setMinimumWidth(150)
        self.check_btn.clicked.connect(self._check)
        self.all_btn = QPushButton("Проверить все демо-пакеты")
        self.all_btn.clicked.connect(self._check_all)
        g = QGridLayout()
        g.setHorizontalSpacing(12)
        g.setVerticalSpacing(10)
        g.addWidget(label("Демо-пакет", muted=True), 0, 0)
        g.addWidget(self.demo_box, 0, 1, 1, 2)
        g.addWidget(self.demo_btn, 0, 3)
        g.addWidget(label("Стадия", muted=True), 1, 0)
        g.addWidget(self.stage, 1, 1)
        g.addWidget(self.strict, 1, 2)
        g.addWidget(self.promote, 1, 3)
        g.setColumnStretch(2, 1)
        row = QHBoxLayout()
        row.addWidget(self.check_btn)
        row.addWidget(self.all_btn)
        row.addStretch(1)
        adv_body = QWidget()
        adv_lay = QVBoxLayout(adv_body)
        adv_lay.setContentsMargins(0, 8, 0, 0)
        adv_lay.setSpacing(10)
        adv_lay.addLayout(g)
        adv_lay.addLayout(row)
        adv_body.hide()
        self._adv_body = adv_body
        self.adv_toggle = QPushButton("▸  Дополнительные параметры (стадия, строгий режим, ручной запуск)",
                                      objectName="flat")
        self.adv_toggle.setCursor(Qt.PointingHandCursor)
        self.adv_toggle.clicked.connect(self._toggle_advanced)
        p.lay.addWidget(card(self.adv_toggle, adv_body))

        # результат
        self.badge = label("—", wrap=False)
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setMinimumSize(190, 54)
        self._set_badge(None)
        self.risk_badge = label("—", wrap=False)
        self.risk_badge.setAlignment(Qt.AlignCenter)
        self.risk_badge.setMinimumSize(80, 54)
        self.risk_badge.setStyleSheet("background: #2a3342; color: #8b94a5; border-radius: 10px; "
                                      "font-size: 11pt; font-weight: 700; padding: 6px 12px;")
        self.res_title = label("Проверка ещё не выполнялась", "h2", wrap=True)
        self.res_sub = label("Выберите пакет и нажмите «Проверить».", muted=True, wrap=True)
        self.res_sub.setMinimumHeight(40)
        self.res_sub.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.pdf_btn = QPushButton("⬇ PDF-отчёт")
        self.pdf_btn.setEnabled(False)
        self.pdf_btn.setToolTip("Экспорт отчёта о последней проверке в PDF")
        self.pdf_btn.clicked.connect(self._export_pdf)
        head = QHBoxLayout()
        head.setSpacing(18)
        head.addWidget(self.badge)
        risk_col = QVBoxLayout()
        risk_col.setSpacing(2)
        risk_col.addWidget(label("Риск", muted=True))
        risk_col.addWidget(self.risk_badge)
        head.addLayout(risk_col)
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
        self.batch = table(["Пакет", "Разметка", "Вердикт", "Заключение", "Оценка", "Время, мс"])
        self.batch_card = card(self.batch, title="Пакетная проверка демо-набора")
        self.batch.setMinimumHeight(330)
        self.batch_card.hide()
        p.lay.addWidget(self.batch_card)
        p.lay.addStretch(1)
        self._watch_seen = None
        self._watch_timer = QTimer(self)
        self._watch_timer.timeout.connect(self._watch_tick)
        saved_pkg = self.settings.value("watch_pkg", "")
        if saved_pkg:
            self.pkg.setText(saved_pkg)                    # восстановление после перезапуска: наблюдение пойдёт само
        else:
            self._sync_watch("")
        return p

    def _set_badge(self, verdict):
        text, color = VERDICT.get(verdict, ("—", "#3a4558"))
        self.badge.setText(text)
        self.badge.setStyleSheet(f"background: {color}; color: white; border-radius: 10px; font-size: 13pt; "
                                 f"font-weight: 700; padding: 6px 18px;")

    def _index_for(self, pkg):
        side = Path(f"{pkg}.index.json")       # снимок доверенного индекса рядом с пакетом (демо-корпус)
        return str(side) if side.exists() else None

    def _check(self):
        pkg = self.pkg.text()
        if not pkg or not (Path(pkg) / "manifest.json").exists():
            self.notify("Укажите каталог пакета, содержащий manifest.json, — кнопкой «Обзор…» или выбором демо-пакета.", "warn")
            return
        stage, strict, promote = self.stage.currentData(), self.strict.isChecked(), self.promote.isChecked()

        def job(_):
            g = self.guard()
            ev = g.check(pkg, stage, self._index_for(pkg), strict)
            ev = self._apply_policy(ev)
            g.respond(ev, pkg, promote)
            return ev
        self.run_bg(job, lambda ev: (self._show_event(ev), self._refresh_views()), self.check_btn)

    def _toggle_advanced(self):
        """Разворачивает/сворачивает блок дополнительных параметров — скрыт по умолчанию, чтобы при первом
        запуске на странице было видно только главное: куда указать пакет и кнопку «показать на примере»."""
        show = not self._adv_body.isVisible()
        self._adv_body.setVisible(show)
        self.adv_toggle.setText(("▾  " if show else "▸  ") + "Дополнительные параметры (стадия, строгий режим, ручной запуск)")

    def _try_demo(self):
        """Кнопка «Показать на примере»: один клик — и всё остальное программа делает сама.

        Если демонстрационных пакетов ещё нет, они создаются в фоне; как только готовы (или если уже были),
        первый пример подставляется в поле «Пакет», и его результат сразу показывается в карточке — без
        выбора демо-пакета вручную и без отдельного нажатия «Проверить»."""
        if self.demo_labels:
            self._select_first_demo()
        else:
            w = self._make_demo(then_check=False)
            w.done.connect(lambda _: QTimer.singleShot(50, self._select_first_demo))

    def _select_first_demo(self):
        if self.demo_box.count() <= 1:
            return
        if self.demo_box.currentIndex() != 1:
            self.demo_box.setCurrentIndex(1)               # вызовет _pick_demo -> подставит путь
        else:
            self.pkg.setText(self.demo_box.itemData(1))
        self._show_demo_result_when_free()

    def _show_demo_result_when_free(self):
        """Результат примера должен появиться сразу, даже если в этот момент в фоне идёт другая задача
        (например, автоматическая проверка всего демо-набора сразу после первого создания пакетов)."""
        if self._workers:
            QTimer.singleShot(200, self._show_demo_result_when_free)
        else:
            self._check()

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
            self.watch_note.setText("Автопроверка: укажите каталог пакета (кнопкой «Обзор…» или выбором "
                                    "демо-пакета) — дальше он будет проверяться сам, без кнопок.")
            return
        if not (Path(pkg) / "manifest.json").exists():
            self._watch_timer.stop()
            self.watch_note.setText(f"Автопроверка приостановлена: в «{pkg}» нет manifest.json.")
            return
        self._watch_seen = None                           # первая проверка — почти сразу, дальше — по таймеру
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
        try:
            files = [f for f in p.rglob("*") if f.is_file()]
            sig = (len(files), sum(f.stat().st_size for f in files), max((f.stat().st_mtime for f in files), default=0))
        except OSError:
            return
        if sig == self._watch_seen:
            return
        self._watch_seen = sig
        self._check()

    def _show_event(self, ev):
        self._set_badge(ev["verdict"])
        rs = ev.get("risk_score", round(ev.get("score", 0) * 100))
        rs_color = "#e5484d" if rs >= 70 else "#d99a1c" if rs >= 30 else "#1f9d63"
        self.risk_badge.setText(f"{rs}")
        self.risk_badge.setStyleSheet(
            f"background: {rs_color}22; color: {rs_color}; border: 2px solid {rs_color}; "
            f"border-radius: 10px; font-size: 14pt; font-weight: 700; padding: 4px 10px;")
        self.pdf_btn.setEnabled(True)
        self._last_ev = ev
        self.res_title.setText(f"{ev['package']}  {ev['baseline_version']} → {ev['version']}:  {ev['threat_ru']}")
        hc = "нарушение" if ev["hash_control"] else "норма"
        self.res_sub.setText(f"Оценка риска: {rs}/100.  Оценка нарушения {ev['score']:.3f} (порог проверки "
                             f"{ev.get('threshold', 0):.2f}, блокировки {ev.get('block_threshold', 0):.2f}).  "
                             f"Контроль подписи и хешей: {hc}.  "
                             f"Время проверки: {ev['timing_ms']['total']:.0f} мс."
                             + "".join(f"\n⚠ {r}" for r in ev["rules"]))
        for name, (bar, val) in self.level_bars.items():
            v = ev.get("levels", {}).get(name)
            bar.setValue(int(round(100 * v)) if v is not None else 0)
            val.setText(f"{v:.2f}" if v is not None else "—")
            color = "#e5484d" if (v or 0) >= 0.5 else "#3b82f6"
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 5px; }}")
        self.suspects.setRowCount(0)
        for s in ev.get("suspects", []):
            add_row(self.suspects, [_component_ru(s["component"]), f"{s['score']:.2f}"])
        acts = ev.get("actions", [])
        self.actions.setText("<br>".join(f"•&nbsp; {a}" for a in acts) if acts else
                             "<span style='color:#8b94a5'>Действия не требуются: пакет допущен.</span>")
        self._refresh_status()

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

    # --- демонстрационные пакеты
    def _demo_dir(self):
        return DATA / "demo_packages"

    def _refresh_demo(self):
        self.demo_box.blockSignals(True)
        self.demo_box.clear()
        lab = self._demo_dir() / "labels.json"
        try:
            self.demo_labels = json.loads(lab.read_text(encoding="utf-8-sig")) if lab.exists() else []
        except (OSError, ValueError):
            self.demo_labels = []                         # разметка повреждена — набор будет создан заново
        self.demo_box.addItem("— выберите пример —" if self.demo_labels else "демо-пакеты ещё не созданы", "")
        for lb in self.demo_labels:
            path = self._demo_dir() / lb["project"] / "candidates" / lb["candidate"]
            self.demo_box.addItem(f"{lb['candidate']}   ·   {THREAT_SHORT[lb['class']]}", str(path))
        self.demo_box.blockSignals(False)
        self.all_btn.setEnabled(bool(self.demo_labels))
        self.demo_btn.setText("Пересоздать демонстрационные пакеты" if self.demo_labels else "Создать демонстрационные пакеты")

    def _pick_demo(self, _):
        if self.demo_box.currentData():
            self.pkg.setText(self.demo_box.currentData())
            if not self._workers:
                self._check()                             # выбор примера сразу запускает проверку

    def _open_incoming(self):
        self.incoming.mkdir(parents=True, exist_ok=True)
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.incoming)))

    def _make_demo(self, then_check=False):
        def job(_):
            from .collect import export_corpus
            d = self._demo_dir()
            g = self.guard()                              # сначала убедиться, что детектор загружается
            old_names = self.settings.value("demo_baselines", [])
            if isinstance(old_names, str):
                old_names = [old_names]
            if not old_names and self.settings.value("demo_baseline", ""):
                old_names = [str(self.settings.value("demo_baseline"))]
            for old in old_names:                         # эталоны прежнего демо-набора больше не нужны
                shutil.rmtree(Path(self.cfg("registry")) / "baselines" / str(old), ignore_errors=True)
            shutil.rmtree(d, ignore_errors=True)
            if g.key is None:                             # ключа ещё нет — заводим ключ реестра
                g.key = b"demo-signing-key"
                (Path(self.cfg("registry")) / "signing.key").write_bytes(g.key)
            export_corpus(d, len(CLASSES), seed=int(time.time()) % 100000, key=g.key,
                          class_names=CLASSES)         # по одному пакету каждого класса
            names = []
            for project in sorted(d.glob("project_*")):
                names.append(g.register_baseline(project / "reference", project / "control.npz"))
            self.settings.setValue("demo_baselines", names)
            self.settings.setValue("demo_baseline", names[0] if names else "")
            return True
        self.demo_btn.setText("Создание пакетов…")
        self.notify("Создаются демонстрационные пакеты: обучается учебная модель и проводятся атаки на неё. "
                    "Это занимает 10–30 секунд.", "info")

        def done(_):
            self._refresh_demo()
            self._refresh_status()
            self.banner.hide()
            if then_check or self.auto_on():
                QTimer.singleShot(0, self._check_all)     # созданный набор сразу проверяется
        w = self.run_bg(job, done, self.demo_btn)
        w.fail.connect(lambda _: self._refresh_demo())
        return w

    def _check_all(self):
        labels = list(self.demo_labels)
        if not labels:
            return

        def job(progress):
            g = self.guard()
            for lb in labels:
                c = self._demo_dir() / lb["project"] / "candidates" / lb["candidate"]
                ev = g.check(c, "build", self._index_for(c))
                g.respond(ev)
                progress((lb, ev))
            return len(labels)
        self.batch.setRowCount(0)
        self.batch_card.show()
        self._batch_ok = 0
        pairs = []

        def step(item):
            lb, ev = item
            pairs.append(R.result_of(lb, ev))
            hit = (ev["verdict"] != "ALLOW") == (lb["class"] != "clean")
            self._batch_ok += hit
            text, color = VERDICT[ev["verdict"]]
            add_row(self.batch, [lb["candidate"], THREAT_SHORT[lb["class"]], text, THREAT_SHORT[ev["threat"]],
                                 f"{ev['score']:.3f}", f"{ev['timing_ms']['total']:.0f}"], color, 2)
            self.batch.scrollToBottom()
        self.check_btn.setEnabled(False)
        w = self.run_bg(job, lambda n: self.batch_card.findChild(QLabel).setText(
            f"Пакетная проверка демо-набора: верных решений {self._batch_ok} из {n}"), self.all_btn, step)
        def finished():
            self.check_btn.setEnabled(True)
            if len(pairs) == len(labels):                 # набор проверен целиком — полнота пересчитана
                self._store_recall(R.recall_table(pairs))
            self._refresh_views()
        w.finished.connect(finished)

    # ------------------------------------------------------------ страница «Эталоны»
    def _page_baselines(self):
        p = Page("Эталоны и версии", "Эталон — доверенное состояние пакета, с которым сравниваются кандидаты. "
                                     "История показывает все проверки и смены версий модели.")
        self.b_pkg = PathEdit("Каталог доверенного пакета")
        self.b_ctrl = PathEdit("Контрольный набор .npz (X, y) — нужен для поведенческого уровня", False, "NumPy (*.npz)")
        self.b_idx = PathEdit("Доверенный индекс зависимостей .json (необязательно)", False, "JSON (*.json)")
        btn = QPushButton("Зарегистрировать эталон", objectName="primary")
        btn.clicked.connect(lambda: self._register(btn))
        g = QGridLayout()
        g.setVerticalSpacing(10)
        g.setHorizontalSpacing(12)
        for i, (name, w) in enumerate((("Пакет", self.b_pkg), ("Контрольный набор", self.b_ctrl), ("Индекс", self.b_idx))):
            g.addWidget(label(name, muted=True), i, 0)
            g.addWidget(w, i, 1)
        sign = QPushButton("Подписать пакет ключом реестра")
        sign.setToolTip("Создаёт файл подписи manifest.sig. Нужно, если пакет ещё не подписан.")
        sign.clicked.connect(lambda: self._sign(sign))
        self.sbom_btn = QPushButton("⬇ SBOM")
        self.sbom_btn.setToolTip(
            "Экспорт инвентаря компонентов пакета (Software Bill of Materials) в формате CycloneDX JSON.")
        self.sbom_btn.clicked.connect(lambda: self._export_sbom(self.sbom_btn))
        row = QHBoxLayout()
        row.addWidget(btn)
        row.addWidget(sign)
        row.addWidget(self.sbom_btn)
        row.addStretch(1)
        p.lay.addWidget(card(g, row, title="Новый эталон"))
        self.b_table = table(["Пакет", "Версия эталона", "Зависимостей", "Контрольный набор", "Проверок"])
        self.b_table.setMinimumHeight(150)
        self.b_table.itemSelectionChanged.connect(self._load_history)
        self.h_table = table(["Время (UTC)", "Событие", "Версия", "Вердикт", "Заключение", "Оценка"], 1)
        self.h_table.setMinimumHeight(240)
        p.lay.addWidget(card(self.b_table, title="Зарегистрированные эталоны"))
        p.lay.addWidget(card(self.h_table, title="История версий и проверок"))
        p.lay.addStretch(1)
        return p

    def _register(self, btn):
        pkg, ctrl, idx = self.b_pkg.text(), self.b_ctrl.text() or None, self.b_idx.text() or None
        if not pkg or not (Path(pkg) / "manifest.json").exists():
            self.notify("Укажите каталог доверенного пакета, содержащий manifest.json.", "warn")
            return
        self.run_bg(lambda _: self.guard().register_baseline(pkg, ctrl, idx),
                    lambda name: (self._load_baselines(), self._refresh_status(),
                                  self.notify(f"Эталон пакета «{name}» зарегистрирован.", "ok")), btn)

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
        if self.b_table.rowCount():
            self.b_table.selectRow(0)
        else:
            self.h_table.setRowCount(0)

    def _load_history(self):
        self.h_table.setRowCount(0)
        r = self.b_table.currentRow()
        if r < 0:
            return
        for h in reversed(self._history(self.b_table.item(r, 0).text())):
            if h.get("event") == "check" and h.get("verdict") in VERDICT:
                text, color = VERDICT[h["verdict"]]
                add_row(self.h_table, [h["time"][:19].replace("T", " "), f"проверка ({STAGE_RU.get(h.get('stage'), h.get('stage', ''))})", h["version"], text,
                                       THREAT_SHORT[h["threat"]], f"{h['score']:.3f}"], color, 3)
            else:
                add_row(self.h_table, [h.get("time", "")[:19].replace("T", " "), f"эталон ({h.get('note', '')})",
                                       h.get("version", ""), "", "", ""])

    # ------------------------------------------------------------ страница «Журнал»
    def _page_events(self):
        p = Page("Журнал событий", "Все проверки записываются в events.jsonl в каталоге реестра — этот файл "
                                   "можно подключить к SIEM/SOC как источник событий.")
        self.e_table = table(["Время (UTC)", "Пакет", "Версия", "Стадия", "Вердикт", "Заключение", "Оценка", "Хеш-контроль"], 1)
        self.e_table.setMinimumHeight(330)
        self.e_table.itemSelectionChanged.connect(self._event_detail)
        self.e_detail = QPlainTextEdit(readOnly=True)
        self.e_detail.setMinimumHeight(220)
        self.e_path = label("", muted=True)
        self.e_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        btn = QPushButton("Обновить")
        btn.clicked.connect(self._load_events)
        row = QHBoxLayout()
        row.addWidget(self.e_path, 1)
        row.addWidget(btn)
        p.lay.addWidget(card(row, self.e_table))
        p.lay.addWidget(card(self.e_detail, title="Событие целиком (JSON)"))
        p.lay.addStretch(1)
        return p

    def _load_events(self):
        f = Path(self.cfg("registry")) / "events.jsonl"
        self.e_path.setText(f"Файл журнала: {f}")
        self.events = self._read_events()[-500:][::-1]
        self.e_table.setRowCount(0)
        for ev in self.events:
            text, color = VERDICT[ev["verdict"]]
            add_row(self.e_table, [ev["time"][:19].replace("T", " "), ev["package"], ev["version"],
                                   STAGE_RU.get(ev.get("stage"), ev.get("stage", "")), text,
                                   THREAT_SHORT.get(ev.get("threat"), "—"), f"{ev['score']:.3f}",
                                   "нарушение" if ev.get("hash_control") else "норма"], color, 4)
        self.e_detail.setPlainText("" if self.events else "Событий пока нет.")
        if self.events:
            self.e_table.selectRow(0)

    def _event_detail(self):
        r = self.e_table.currentRow()
        if 0 <= r < len(self.events):
            self.e_detail.setPlainText(json.dumps(self.events[r], ensure_ascii=False, indent=2))

    # ------------------------------------------------------------ страница «Полнота обнаружения»
    def _page_recall(self):
        p = Page("Полнота обнаружения", "Полнота (Recall) — доля пакетов с нарушением целостности, которые система не "
                 "допустила. Считается отдельно от обучения: на тестовой выборке детектора и на демо-наборе пакетов.")
        self.r_btn = QPushButton("Рассчитать полноту на демо-наборе", objectName="primary")
        self.r_btn.clicked.connect(self._measure_recall)
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
        for key, name in (("test", "Полнота: тестовая выборка"), ("demo", "Полнота: демо-набор"),
                          ("missed", "Пропущено нарушений (демо)"), ("hash", "Полнота контроля хешей (тест)")):
            val = label("—")
            val.setStyleSheet("font-size: 22pt; font-weight: 600;")
            sub = label("", muted=True)
            self.r_tiles[key] = (val, sub)
            tiles.addWidget(card(label(name, muted=True), val, sub), 1)
        p.lay.addLayout(tiles)
        self.ch_recall = GroupBars()
        self.ch_recall.empty_text = "Полнота появится после обучения детектора или расчёта на демо-наборе."
        p.lay.addWidget(card(self.ch_recall, title="Полнота по классам угроз"))
        self.r_class = table(["Класс угрозы", "Уровень", "Тест: образцов", "Тест: полнота", "Тест: хеши",
                              "Демо: обнаружено", "Демо: полнота"])
        self.r_class.setFixedHeight(214)
        p.lay.addWidget(card(self.r_class, title="По классам угроз"))
        self.r_level = table(["Уровень целостности", "Тест: образцов", "Тест: полнота", "Демо: образцов", "Демо: обнаружено",
                              "Демо: полнота"])
        self.r_level.setFixedHeight(154)
        p.lay.addWidget(card(self.r_level, title="По уровням целостности"))
        self.r_method = table(["Метод обнаружения", "Полнота на тестовой выборке"])
        self.r_method.setFixedHeight(214)
        p.lay.addWidget(card(self.r_method, title="По методам (гибридная сеть, её отдельные ветви и контроль хешей)"))
        p.lay.addStretch(1)
        return p

    def _recall_file(self):
        return DATA / "recall.json"

    def _store_recall(self, tab):
        try:
            R.save(self._recall_file(), tab)
        except OSError as e:
            self.notify(f"Не удалось сохранить расчёт полноты: {e}")
        self._load_recall()

    def _measure_recall(self):
        if not self._demo_ready():
            self.notify("Демо-набор ещё не создан: создайте его на странице «Проверка пакета» "
                        "(в автоматическом режиме он создаётся сам).", "warn")
            return
        labels = list(self.demo_labels)
        self.r_bar.setRange(0, len(labels))
        self.r_bar.setValue(0)
        self.r_note.setText("Идёт расчёт: каждый пакет демо-набора проверяется заново…")

        def done(tab):
            self.r_bar.setValue(len(labels))
            self._store_recall(tab)
        self.run_bg(lambda progress: R.measure_recall(self.guard(), self._demo_dir(), labels, progress), done, self.r_btn,
                    lambda m: self.r_bar.setValue(m[0]))

    def _load_recall(self):
        test, raw = None, {}
        try:
            f = Path(self.cfg("model")).parent / "metrics.json"
            raw = json.loads(f.read_text(encoding="utf-8-sig")) if f.exists() else {}
            test = R.from_metrics(raw) if raw else None
        except (OSError, ValueError, KeyError, TypeError):
            test, raw = None, {}                          # показателей обучения нет или файл повреждён
        self.r_method.setRowCount(0)
        for name, key in (("Гибридный детектор", "hybrid"), ("Только граф (GNN)", "only_graph"),
                          ("Только автокодировщик весов", "only_autoencoder"),
                          ("Только поведенческий классификатор", "only_behavior"), ("Контроль подписи и хешей", "hash_baseline")):
            v = (raw.get(key) or {}).get("binary", {}).get("recall") if isinstance(raw, dict) else None
            if isinstance(v, (int, float)):
                add_row(self.r_method, [name, f"{100 * v:.1f} %"])
        demo = R.load(self._recall_file())
        pct = lambda v: f"{100 * v:.1f} %" if isinstance(v, (int, float)) else "—"  # noqa: E731
        num = lambda t, k: t[k] if t else "—"  # noqa: E731

        def tile(key, value, sub):
            self.r_tiles[key][0].setText(value)
            self.r_tiles[key][1].setText(sub)
        to, do = (test or {}).get("overall"), (demo or {}).get("overall")
        tile("test", pct(to["recall"]) if to else "—", f"{to['detected']} из {to['n']} нарушений" if to else "детектор не обучен")
        tile("demo", pct(do["recall"]) if do else "—", f"{do['detected']} из {do['n']} нарушений" if do else "расчёт не выполнялся")
        tile("missed", str(do["missed"]) if do else "—",
             f"ложных тревог на чистых: {demo['clean']['false_alarms']} из {demo['clean']['n']}" if demo and "clean" in demo else "")
        tile("hash", pct(to["hash_recall"]) if to else "—", "подпись и хеши без нейросети" if to else "")
        self.r_class.setRowCount(0)
        for c in R.THREATS:
            t, d = (test or {}).get("per_class", {}).get(c), (demo or {}).get("per_class", {}).get(c)
            add_row(self.r_class, [CLASS_RU[c], LEVEL_RU[CLASS_LEVEL[c]], num(t, "n"), pct(t["recall"]) if t else "—",
                                   pct(t["hash_recall"]) if t else "—",
                                   f"{d['detected']} из {d['n']}" if d else "—", pct(d["recall"]) if d else "—"])
        self.r_level.setRowCount(0)
        for lv in LEVELS:
            t, d = (test or {}).get("per_level", {}).get(lv), (demo or {}).get("per_level", {}).get(lv)
            add_row(self.r_level, [LEVEL_RU[lv], num(t, "n"), pct(t["recall"]) if t else "—", num(d, "n"),
                                   f"{d['detected']} из {d['n']}" if d else "—", pct(d["recall"]) if d else "—"])
        short = dict(THREAT_SHORT, poison="отравление")
        series = []
        if test:
            series += [("Гибридный детектор, тест", ACCENT, [test["per_class"][c]["recall"] for c in R.THREATS]),
                       ("Контроль подписи и хешей, тест", SECOND, [test["per_class"][c]["hash_recall"] for c in R.THREATS])]
        if demo:
            series.append(("Гибридный детектор, демо-набор", "#1f9d63", R.class_metric_values(demo, "recall")))
        self.ch_recall.set_data([short[c] for c in R.THREATS] if series else [], series)
        self.r_note.setText((f"Последний расчёт на демо-наборе: {_when(demo['time'])}. " if demo and demo.get("time") else
                             "На демо-наборе расчёт ещё не выполнялся. ")
                            + "Демо-набор мал (по 3 пакета на класс), поэтому основная оценка — тестовая выборка.")

    # ------------------------------------------------------------ страница «Обучение»
    def _page_train(self):
        p = Page("Обучение и оценка", "Формирование корпуса примеров нарушений (реальные атаки на учебные модели), "
                                      "обучение гибридной сети и расчёт показателей Accuracy, Precision, F1. Полнота — на отдельной странице.")
        self.t_projects = QSpinBox(minimum=10, maximum=1000, value=60, singleStep=10)
        self.t_epochs = QSpinBox(minimum=10, maximum=300, value=70, singleStep=10)
        self.t_fpr = QDoubleSpinBox(minimum=0.005, maximum=0.2, value=0.02, singleStep=0.005, decimals=3)
        self.t_abl = QCheckBox("Сравнить с отдельными ветвями (абляция)")
        self.t_abl.setChecked(True)
        self.t_btn = QPushButton("Сформировать корпус и обучить", objectName="primary")
        self.t_btn.clicked.connect(self._train)
        self.t_bar = QProgressBar()
        self.t_bar.setRange(0, 100)
        self.t_bar.setTextVisible(False)
        self.t_note = label("Около 2 секунд на проект; 60 проектов ≈ 1400 образцов.", muted=True)
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
        p.lay.addStretch(1)
        self._load_metrics()
        return p

    def _load_metrics(self):
        d = Path(self.cfg("model")).parent
        self.m_table.setRowCount(0)
        f = d / "metrics.json"
        if not f.exists():
            self.m_caption.setText("Показатели появятся после обучения детектора.")
            self.m_img_card.hide()
            self.m_files.setText("")
            return
        try:
            r = json.loads(f.read_text(encoding="utf-8-sig"))
            s = r["split"]
            r["hybrid"]["binary"], r["hash_baseline"]["binary"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            self.m_caption.setText("Файл metrics.json рядом с детектором повреждён.")
            self.m_img_card.hide()
            return
        self.m_caption.setText(f"Проектов {s['projects']}; образцов: обучение {s['train']}, валидация {s['val']}, тест {s['test']}. "
                               f"Эталоны тестовой выборки в обучении не участвовали. Корпус синтетический.")
        rows = [("Гибридный детектор", r["hybrid"]["binary"]), ("Только граф (GNN)", r.get("only_graph", {}).get("binary")),
                ("Только автокодировщик весов", r.get("only_autoencoder", {}).get("binary")),
                ("Только поведенческий классификатор", r.get("only_behavior", {}).get("binary")),
                ("Контроль подписи и хешей", r["hash_baseline"]["binary"])]
        for name, m in rows:
            if m:
                add_row(self.m_table, [name] + [_num(m.get(k)) for k in ("accuracy", "precision", "f1", "fpr", "auc")])
        self.ch_conf.set_data([THREAT_TINY[c] for c in CLASSES], r["hybrid"].get("confusion") or [])
        self.m_img_card.show()
        self.m_files.setText(f"Отчёт для печати (report.md, metrics.png, metrics.json) лежит в папке {d}")
        if hasattr(self, "r_class"):
            self._load_recall()

    def _train(self):
        n, epochs, fpr, abl = self.t_projects.value(), self.t_epochs.value(), self.t_fpr.value(), self.t_abl.isChecked()
        out = DATA / "runs" / time.strftime("%Y%m%d_%H%M%S")

        def job(progress):
            import torch
            from .corpus import build_corpus
            from .train import run_experiment
            samples = build_corpus(n, int(time.time()) % 100000,
                                   progress=lambda i, total: progress((i, total)))
            out.mkdir(parents=True, exist_ok=True)
            torch.save(samples, out / "corpus.pt")
            progress("corpus_done")
            run_experiment(samples, out, epochs, fpr, 0, abl, log=progress)
            return out
        self.t_log.clear()
        self.t_log_card.show()
        self.t_bar.setRange(0, n)
        self.t_bar.setValue(0)
        self.t_note.setText("Формирование корпуса: обучаются эталонные модели и проводятся атаки…")

        def step(msg):
            if isinstance(msg, tuple):
                self.t_bar.setValue(msg[0])
                self.t_note.setText(f"Формирование корпуса: проект {msg[0]} из {msg[1]}")
            elif msg == "corpus_done":
                self.t_bar.setRange(0, 0)               # неопределённый прогресс на время обучения
                self.t_note.setText("Обучение детектора…")
            else:
                self.t_log.appendPlainText(str(msg))

        def done(path):
            self.t_bar.setRange(0, 100)
            self.t_bar.setValue(100)
            self.t_note.setText(f"Готово. Детектор и отчёт сохранены в {path}")
            self.settings.setValue("model", str(path / "detector.pt"))
            self.s_model.setText(path / "detector.pt")
            self._guard = None
            self._load_metrics()
            self._refresh_status()
            if self.auto_on() and not self._demo_ready():
                self.nav.button(0).click()
                self._make_demo(then_check=True)
        w = self.run_bg(job, done, self.t_btn, step)
        w.fail.connect(lambda _: (self.t_bar.setRange(0, 100), self.t_note.setText("Обучение прервано ошибкой.")))

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
        self.s_auto = QCheckBox("Автоматический режим: проверять пакеты из папки входящих, готовить демо-набор и обучение без запросов")
        self.s_auto.setChecked(str(self.settings.value("auto", "true")).lower() != "false")
        g.addWidget(self.s_auto, 3, 1)
        self.s_autostart = QCheckBox("Запускать автоматически при входе в Windows (в трее, без открытия окна)")
        self.s_autostart.setChecked(self._autostart_enabled())
        if sys.platform != "win32" or not QSystemTrayIcon.isSystemTrayAvailable():
            self.s_autostart.setEnabled(False)
            self.s_autostart.setToolTip("Доступно только в Windows со значком в трее.")
        g.addWidget(self.s_autostart, 4, 1)
        btn = QPushButton("Сохранить", objectName="primary")
        btn.clicked.connect(self._save_settings)
        self.s_note = label("", muted=True)
        row = QHBoxLayout()
        row.addWidget(btn)
        row.addWidget(self.s_note, 1)
        p.lay.addWidget(card(g, row))

        # --- политики блокировки
        from PySide6.QtWidgets import QSpinBox, QDoubleSpinBox
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
        p.lay.addWidget(card(info, title="Интеграция"))
        p.lay.addStretch(1)
        return p

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
        if score > 0 and ev.get("risk_score", 0) >= score and ev.get("verdict") != "BLOCK":
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
    for role, color in (("Window", "#0f1218"), ("WindowText", "#e6e9ef"), ("Base", "#0f1218"), ("AlternateBase", "#1a202a"),
                        ("Text", "#e6e9ef"), ("Button", "#222a37"), ("ButtonText", "#e6e9ef"), ("BrightText", "#ffffff"),
                        ("ToolTipBase", "#171c25"), ("ToolTipText", "#e6e9ef"), ("Highlight", "#3b82f6"),
                        ("HighlightedText", "#ffffff"), ("PlaceholderText", "#6b7485"), ("Link", "#6ea8fe"),
                        ("Light", "#2a3342"), ("Midlight", "#232a36"), ("Mid", "#1a202a"), ("Dark", "#0b0e13"),
                        ("Shadow", "#000000")):
        pal.setColor(getattr(QPalette, role), QColor(color))
    for role in ("WindowText", "Text", "ButtonText"):
        pal.setColor(QPalette.Disabled, getattr(QPalette, role), QColor("#5d6675"))
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
    if start_minimized and getattr(w, "tray", None):   # запуск из автозагрузки Windows: сразу в трей
        w.hide()
    else:
        w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

