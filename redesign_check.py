path = 'integrityguard/gui.py'
src = open(path, encoding='utf-8').read()

# ============================================================
# Replace _page_check - no combo, no button, auto-analyze
# ============================================================
OLD_PAGE_CHECK = '''    def _page_check(self):
        p = Page("Проверка пакета", "Нейросеть анализирует сетевой снимок события и выставляет оценку "
                                    "по трём уровням целостности: структурному, параметрическому и поведенческому.")
        # ---- блок выбора события для анализа ----
        self._check_event_combo = QComboBox()
        self._check_event_combo.setMinimumWidth(500)
        self._check_event_combo.setPlaceholderText("Выберите событие для анализа\\u2026")
        refresh_btn = QPushButton("\\u27f3")
        refresh_btn.setToolTip("Обновить список событий")
        refresh_btn.setMaximumWidth(36)
        refresh_btn.clicked.connect(self._check_load_events)
        event_row = QHBoxLayout()
        event_row.addWidget(self._check_event_combo, 1)
        event_row.addWidget(refresh_btn)
        hero = QVBoxLayout()
        hero.addWidget(label("Что проверить?", "h2"))
        hero.addWidget(label("Выберите сетевое событие из истории \\u2014 нейросеть сама оценит все уровни целостности.",
                              muted=True, wrap=True))
        hero.addLayout(event_row)
        p.lay.addWidget(card(hero))

        # ---- кнопка запуска анализа ----
        self.check_btn = QPushButton("Анализировать нейросетью", objectName="primary")
        self.check_btn.setMinimumWidth(220)
        self.check_btn.clicked.connect(self._check_nn)
        btn_row = QHBoxLayout()
        btn_row.addWidget(self.check_btn)
        btn_row.addStretch(1)
        p.lay.addWidget(card(btn_row))'''

NEW_PAGE_CHECK = '''    def _page_check(self):
        p = Page("Проверка пакета", "Нейросеть автоматически анализирует последний сетевой снимок "
                                    "и выставляет оценку по трём уровням целостности: структурному, параметрическому и поведенческому.")
        # ---- строка статуса анализа + кнопка повтора ----
        self._check_status_lbl = label("Загружаем последнее событие из БД\\u2026", muted=True, wrap=True)
        self.check_btn = QPushButton("\\u27f3  Обновить анализ", objectName="primary")
        self.check_btn.setMinimumWidth(180)
        self.check_btn.clicked.connect(self._check_nn)
        status_row = QHBoxLayout()
        status_row.addWidget(self._check_status_lbl, 1)
        status_row.addWidget(self.check_btn)
        p.lay.addWidget(card(status_row))'''

if OLD_PAGE_CHECK in src:
    src = src.replace(OLD_PAGE_CHECK, NEW_PAGE_CHECK)
    print("OK: _page_check replaced")
else:
    print("FAIL: _page_check not found")

# ============================================================
# Replace QTimer.singleShot call at end of _page_check
# ============================================================
OLD_TIMER = '        # Загрузить список событий после инициализации\n        QTimer.singleShot(200, self._check_load_events)\n        return p'
NEW_TIMER = '        # Автоматически запустить анализ после инициализации страницы\n        QTimer.singleShot(300, self._check_nn)\n        return p'

if OLD_TIMER in src:
    src = src.replace(OLD_TIMER, NEW_TIMER)
    print("OK: QTimer replaced")
else:
    print("FAIL: QTimer not found")

# ============================================================
# Replace _check_load_events - now fetches single latest event
# and calls _check_nn directly (kept as internal helper)
# ============================================================
OLD_LOAD = '''    def _check_load_events(self):
        """Loads last 50 events from DB into combo for selection."""
        import sqlite3
        import pathlib
        db_path = pathlib.Path("F:\\\\New\\\\integrityguard\\\\data\\\\online\\\\network_events.sqlite")
        rows = []
        if db_path.exists():
            try:
                con = sqlite3.connect(str(db_path))
                cur = con.execute(
                    "SELECT event_id, captured_at_utc, '', snapshot_json FROM events ORDER BY captured_at_utc DESC LIMIT 50"
                )
                rows = cur.fetchall()
                con.close()
            except Exception:
                pass
        self._check_event_combo.clear()
        self._check_events_data = {}
        if not rows:
            self._check_event_combo.addItem("\\u2014 нет событий в БД \\u2014")
            return
        for row in rows:
            eid, ts, proc, snap_json = row
            ts_short = str(ts)[:19] if ts else "?"
            label_txt = ts_short
            self._check_event_combo.addItem(label_txt, eid)
            self._check_events_data[eid] = snap_json
        self._check_event_combo.setCurrentIndex(0)'''

NEW_LOAD = '''    def _check_load_events(self):
        """Fetches latest event snapshot from DB. Returns (event_id, snap_json) or (None, None)."""
        import sqlite3
        import pathlib
        db_path = pathlib.Path("F:\\\\New\\\\integrityguard\\\\data\\\\online\\\\network_events.sqlite")
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
        return None, None'''

if OLD_LOAD in src:
    src = src.replace(OLD_LOAD, NEW_LOAD)
    print("OK: _check_load_events replaced")
else:
    print("FAIL: _check_load_events not found")

# ============================================================
# Replace _check_nn - now fully automatic, no combo needed
# ============================================================
OLD_NN_HEAD = '''    def _check_nn(self):
        """Analyzes selected event with neural network, shows 3 integrity levels."""
        import json as _json
        idx = self._check_event_combo.currentIndex()
        event_id = self._check_event_combo.itemData(idx)
        if not event_id:
            self.notify("Выберите событие из списка для анализа.", "warn")
            return
        snap_json = getattr(self, "_check_events_data", {}).get(event_id)
        if not snap_json:
            self.notify("Не удалось получить данные снимка для этого события.", "warn")
            return'''

NEW_NN_HEAD = '''    def _check_nn(self):
        """Fetches latest DB event and analyzes it with neural network, shows 3 integrity levels."""
        import json as _json
        event_id, snap_json = self._check_load_events()
        if not event_id or not snap_json:
            self._check_status_lbl.setText("\\u26a0\\ufe0f Нет событий в БД для анализа.")
            return
        self._check_status_lbl.setText(f"\\U0001f9e0 Анализируем событие {str(event_id)[:20]}\\u2026")'''

if OLD_NN_HEAD in src:
    src = src.replace(OLD_NN_HEAD, NEW_NN_HEAD)
    print("OK: _check_nn head replaced")
else:
    print("FAIL: _check_nn head not found")

# Fix on_done to also update status label
OLD_ON_DONE = '''        def on_done(ev):
            self._check_progress_bar.setValue(100)
            self._show_event_nn(ev)
            QTimer.singleShot(4000, lambda: self._check_progress_card.setVisible(False))'''

NEW_ON_DONE = '''        def on_done(ev):
            self._check_progress_bar.setValue(100)
            verdict = ev.get("verdict", "REVIEW")
            rs = ev.get("risk_score", 0)
            decision_ru = {"ALLOW": "ДОПУСТИТЬ", "BLOCK": "ЗАБЛОКИРОВАТЬ", "REVIEW": "НА ПРОВЕРКУ"}.get(verdict, verdict)
            self._check_status_lbl.setText(f"\\u2705 Анализ завершён: {decision_ru}  (риск {rs}/100)")
            self._show_event_nn(ev)
            QTimer.singleShot(4000, lambda: self._check_progress_card.setVisible(False))'''

if OLD_ON_DONE in src:
    src = src.replace(OLD_ON_DONE, NEW_ON_DONE)
    print("OK: on_done updated")
else:
    print("FAIL: on_done not found")

open(path, 'w', encoding='utf-8').write(src)
print("All done.")
