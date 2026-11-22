# -*- coding: utf-8 -*-
"""Patch script: redesign 'Package Check' page to use neural network."""
import re

PATCH_FILE = r"F:\New\integrityguard\integrityguard\gui.py"
DB_PATH = r"F:\\New\\integrityguard\\data\\online\\network_events.sqlite"
CP_PATH = r"F:\\New\\integrityguard\\data\\online\\network_classifier.pt"

with open(PATCH_FILE, encoding="utf-8") as f:
    src = f.read()

errors = []

# ==============================================================================
# 1. Replace hero block (PathEdit -> ComboBox)
# ==============================================================================
old1 = (
    '    def _page_check(self):\n'
    '        p = Page("Проверка пакета", "Кандидат сравнивается с зарегистрированным эталоном на трёх уровнях целостности: "\n'
    '                                    "структурном (граф зависимостей), параметрическом (веса) и поведенческом (отклик модели).")\n'
    '        self.auto_note = label("", muted=True, wrap=True)\n'
    '        self.auto_note.setTextInteractionFlags(Qt.TextSelectableByMouse)\n'
    '        open_btn = QPushButton("Открыть папку входящих")\n'
    '        open_btn.clicked.connect(self._open_incoming)\n'
    '        arow = QHBoxLayout()\n'
    '        arow.addWidget(self.auto_note, 1)\n'
    '        arow.addWidget(open_btn)\n'
    '        p.lay.addWidget(card(arow))\n'
    '        # ---- главный блок: ровно 1-2 клика и больше ничего делать не нужно ----\n'
    '        self.pkg = PathEdit("Каталог пакета-кандидата (manifest.json, model.pt, src/)")\n'
    '        self.pkg.picked.connect(self._check)\n'
    '        self.pkg.edit.textChanged.connect(self._sync_watch)\n'
    '        self.watch_note = label("", muted=True, wrap=True)\n'
    '        hero = QVBoxLayout()\n'
    '        hero.addWidget(label("Что проверить?", "h2"))\n'
    '        hero.addWidget(label("Укажите каталог своего пакета — проверка начнётся сама, без лишних кнопок.",\n'
    '                              muted=True, wrap=True))\n'
    '        hero.addWidget(self.pkg)\n'
    '        hero.addWidget(self.watch_note)\n'
    '        p.lay.addWidget(card(hero))'
)
new1 = (
    '    def _page_check(self):\n'
    '        p = Page("Проверка пакета", "Нейросеть анализирует сетевой снимок события и выставляет оценку "\n'
    '                                    "по трём уровням целостности: структурному, параметрическому и поведенческому.")\n'
    '        # ---- блок выбора события для анализа ----\n'
    '        self._check_event_combo = QComboBox()\n'
    '        self._check_event_combo.setMinimumWidth(500)\n'
    '        self._check_event_combo.setPlaceholderText("Выберите событие для анализа\\u2026")\n'
    '        refresh_btn = QPushButton("\\u27f3")\n'
    '        refresh_btn.setToolTip("Обновить список событий")\n'
    '        refresh_btn.setMaximumWidth(36)\n'
    '        refresh_btn.clicked.connect(self._check_load_events)\n'
    '        event_row = QHBoxLayout()\n'
    '        event_row.addWidget(self._check_event_combo, 1)\n'
    '        event_row.addWidget(refresh_btn)\n'
    '        hero = QVBoxLayout()\n'
    '        hero.addWidget(label("Что проверить?", "h2"))\n'
    '        hero.addWidget(label("Выберите сетевое событие из истории \\u2014 нейросеть сама оценит все уровни целостности.",\n'
    '                              muted=True, wrap=True))\n'
    '        hero.addLayout(event_row)\n'
    '        p.lay.addWidget(card(hero))'
)
if old1 in src:
    src = src.replace(old1, new1, 1)
    print("OK #1: hero block replaced")
else:
    errors.append("FAIL #1: hero block not found")

# ==============================================================================
# 2. Replace advanced params block
# ==============================================================================
old2 = (
    '        # ---- дополнительные параметры: скрыты по умолчанию, чтобы не пугать при первом запуске ----\n'
    '        self.stage = QComboBox()\n'
    '        for code, name in (("build", "Сборка"), ("deploy", "Поставка"), ("runtime", "Эксплуатация")):\n'
    '            self.stage.addItem(name, code)\n'
    '        self.strict = QCheckBox("Строгий режим (\u00abна проверку\u00bb = блокировка)")\n'
    '        self.promote = QCheckBox("При допуске сделать новым эталоном")\n'
    '        self.check_btn = QPushButton("Проверить", objectName="primary")\n'
    '        self.check_btn.setMinimumWidth(150)\n'
    '        self.check_btn.clicked.connect(self._check)\n'
    '        g = QGridLayout()\n'
    '        g.setHorizontalSpacing(12)\n'
    '        g.setVerticalSpacing(10)\n'
    '        g.addWidget(label("Стадия", muted=True), 0, 0)\n'
    '        g.addWidget(self.stage, 0, 1)\n'
    '        g.addWidget(self.strict, 0, 2)\n'
    '        g.addWidget(self.promote, 0, 3)\n'
    '        g.setColumnStretch(2, 1)\n'
    '        row = QHBoxLayout()\n'
    '        row.addWidget(self.check_btn)\n'
    '        row.addStretch(1)\n'
    '        adv_body = QWidget()\n'
    '        adv_lay = QVBoxLayout(adv_body)\n'
    '        adv_lay.setContentsMargins(0, 8, 0, 0)\n'
    '        adv_lay.setSpacing(10)\n'
    '        adv_lay.addLayout(g)\n'
    '        adv_lay.addLayout(row)\n'
    '        adv_body.hide()\n'
    '        self._adv_body = adv_body'
)
new2 = (
    '        # ---- кнопка запуска анализа ----\n'
    '        self.check_btn = QPushButton("Анализировать нейросетью", objectName="primary")\n'
    '        self.check_btn.setMinimumWidth(220)\n'
    '        self.check_btn.clicked.connect(self._check_nn)\n'
    '        btn_row = QHBoxLayout()\n'
    '        btn_row.addWidget(self.check_btn)\n'
    '        btn_row.addStretch(1)\n'
    '        p.lay.addWidget(card(btn_row))'
)
if old2 in src:
    src = src.replace(old2, new2, 1)
    print("OK #2: advanced params replaced")
else:
    errors.append("FAIL #2: advanced params not found")

# ==============================================================================
# 3. Remove adv_toggle
# ==============================================================================
old3 = (
    '        self.adv_toggle = QPushButton("\u25b8  Дополнительные параметры (стадия и политика проверки)",\n'
    '                                      objectName="flat")\n'
    '        self.adv_toggle.setCursor(Qt.PointingHandCursor)\n'
    '        self.adv_toggle.clicked.connect(self._toggle_advanced)\n'
    '        p.lay.addWidget(card(self.adv_toggle, adv_body))\n'
    '\n'
    '        # --- карточка прогресса (скрыта пока не запущена проверка)\n'
    '        self._check_progress_card = card(self._check_progress_bar, self._check_log, title="Ход проверки")\n'
    '        self._check_progress_card.setVisible(False)\n'
    '        p.lay.addWidget(self._check_progress_card)'
)
new3 = (
    '        # --- карточка прогресса (скрыта пока не запущена проверка)\n'
    '        self._check_progress_card = card(self._check_progress_bar, self._check_log, title="Ход анализа")\n'
    '        self._check_progress_card.setVisible(False)\n'
    '        p.lay.addWidget(self._check_progress_card)'
)
if old3 in src:
    src = src.replace(old3, new3, 1)
    print("OK #3: adv_toggle removed")
else:
    errors.append("FAIL #3: adv_toggle not found")

# ==============================================================================
# 4. Replace tail of _page_check
# ==============================================================================
old4 = (
    '        self._watch_seen = None\n'
    '        self._watch_fingerprint = None\n'
    '        self._watch_last_fingerprint_at = 0.0\n'
    '        self._watch_timer = QTimer(self)\n'
    '        self._watch_timer.timeout.connect(self._watch_tick)\n'
    '        saved_pkg = self.settings.value("watch_pkg", "")\n'
    '        if saved_pkg:\n'
    '            self.pkg.setText(saved_pkg)                    # восстановление после перезапуска: наблюдение пойдёт само\n'
    '        else:\n'
    '            self._sync_watch("")\n'
    '        return p'
)
new4 = (
    '        # Загрузить список событий после инициализации\n'
    '        QTimer.singleShot(200, self._check_load_events)\n'
    '        return p'
)
if old4 in src:
    src = src.replace(old4, new4, 1)
    print("OK #4: watch_timer tail replaced")
else:
    errors.append("FAIL #4: tail not found")

# ==============================================================================
# 5. Replace _check() with _check_load_events() + _check_nn()
# ==============================================================================
old5 = (
    '    def _check(self):\n'
    '        pkg = self.pkg.text()\n'
    '        if not pkg or not (Path(pkg) / "manifest.json").exists():\n'
    '            self.notify("Укажите каталог реального пакета с manifest.json, используя кнопку \u00abОбзор\u2026\u00bb.", "warn")\n'
    '            return\n'
    '        stage, strict, promote = self.stage.currentData(), self.strict.isChecked(), self.promote.isChecked()\n'
    '\n'
    '        # --- живой лог прогресса\n'
    '        self._check_log_lines = []\n'
    '        self._check_progress_bar.setValue(0)\n'
    '        self._check_progress_bar.setVisible(True)\n'
    '        self._check_log.setVisible(True)\n'
    '        self._check_log.setText("\u23f3 Проверка запущена\u2026")\n'
    '        self._check_progress_card.setVisible(True)\n'
    '\n'
    '        def _on_progress(step, text):\n'
    '            """Вызывается из фонового потока — обновляем GUI через сигнал."""\n'
    '            self._check_log_lines.append(text)\n'
    '            QMetaObject.invokeMethod(self, "_update_check_log", Qt.QueuedConnection)\n'
    '\n'
    '        def job(_):\n'
    '            g = self.guard()\n'
    '            from .collect import fingerprint\n'
    '            try:\n'
    '                before = fingerprint(pkg)\n'
    '                ev = g.check(pkg, stage, self._index_for(pkg), strict, progress_cb=_on_progress)\n'
    '                if fingerprint(pkg) != before:\n'
    '                    ev = g.assessment_error(pkg, "пакет изменился во время проверки; результат сравнения не сохранён",\n'
    '                                            stage)\n'
    '            except (ValueError, OSError) as error:\n'
    '                ev = g.assessment_error(pkg, error, stage)\n'
    '            ev = self._apply_policy(ev)\n'
    '            g.respond(ev, pkg, promote)\n'
    '            return ev\n'
    '\n'
    '        def on_done(ev):\n'
    '            self._check_progress_bar.setValue(100)\n'
    '            self._show_event(ev)\n'
    '            self._refresh_views()\n'
    '            # скрываем прогресс через 4 сек после завершения\n'
    '            QTimer.singleShot(4000, lambda: self._check_progress_card.setVisible(False))\n'
    '\n'
    '        self.run_bg(job, on_done, self.check_btn)'
)

new5 = (
    '    def _check_load_events(self):\n'
    '        """Loads last 50 events from DB into combo for selection."""\n'
    '        import sqlite3\n'
    '        import pathlib\n'
    '        db_path = pathlib.Path("' + DB_PATH + '")\n'
    '        rows = []\n'
    '        if db_path.exists():\n'
    '            try:\n'
    '                con = sqlite3.connect(str(db_path))\n'
    '                cur = con.execute(\n'
    '                    "SELECT id, timestamp, process_name, snapshot FROM events ORDER BY timestamp DESC LIMIT 50"\n'
    '                )\n'
    '                rows = cur.fetchall()\n'
    '                con.close()\n'
    '            except Exception:\n'
    '                pass\n'
    '        self._check_event_combo.clear()\n'
    '        self._check_events_data = {}\n'
    '        if not rows:\n'
    '            self._check_event_combo.addItem("\\u2014 нет событий в БД \\u2014")\n'
    '            return\n'
    '        for row in rows:\n'
    '            eid, ts, proc, snap_json = row\n'
    '            ts_short = str(ts)[:19] if ts else "?"\n'
    '            proc_short = (proc or "unknown")[:30]\n'
    '            label_txt = f"{ts_short}  {proc_short}"\n'
    '            self._check_event_combo.addItem(label_txt, eid)\n'
    '            self._check_events_data[eid] = snap_json\n'
    '        self._check_event_combo.setCurrentIndex(0)\n'
    '\n'
    '    def _check_nn(self):\n'
    '        """Analyzes selected event with neural network, shows 3 integrity levels."""\n'
    '        import json as _json\n'
    '        idx = self._check_event_combo.currentIndex()\n'
    '        event_id = self._check_event_combo.itemData(idx)\n'
    '        if not event_id:\n'
    '            self.notify("Выберите событие из списка для анализа.", "warn")\n'
    '            return\n'
    '        snap_json = getattr(self, "_check_events_data", {}).get(event_id)\n'
    '        if not snap_json:\n'
    '            self.notify("Не удалось получить данные снимка для этого события.", "warn")\n'
    '            return\n'
    '\n'
    '        self._check_log_lines = []\n'
    '        self._check_progress_bar.setValue(0)\n'
    '        self._check_progress_bar.setVisible(True)\n'
    '        self._check_log.setVisible(True)\n'
    '        self._check_log.setText("\\u23f3 Анализ запущен\\u2026")\n'
    '        self._check_progress_card.setVisible(True)\n'
    '\n'
    '        def _log(text):\n'
    '            self._check_log_lines.append(text)\n'
    '            QMetaObject.invokeMethod(self, "_update_check_log", Qt.QueuedConnection)\n'
    '\n'
    '        def job(_):\n'
    '            import json as _json2\n'
    '            from .network_classifier import assess_network_with_classifier, extract_features\n'
    '            from pathlib import Path as _Path\n'
    '            try:\n'
    '                snapshot = _json2.loads(snap_json) if isinstance(snap_json, str) else snap_json\n'
    '            except Exception:\n'
    '                snapshot = {}\n'
    '            _log("\\U0001f4e6 Извлечение признаков снимка\\u2026")\n'
    '            features = extract_features(snapshot)\n'
    '            _log(f"\\U0001f50d Признаков извлечено: {len(features)}")\n'
    '            checkpoint_path = _Path("' + CP_PATH + '")\n'
    '            _log("\\U0001f9e0 Запуск нейросети\\u2026")\n'
    '            result = assess_network_with_classifier(snapshot, {}, checkpoint_path)\n'
    '            probs = result.get("class_probabilities", {})\n'
    '            p_block = probs.get("BLOCK", 0.5)\n'
    '            decision = result.get("decision", "REVIEW")\n'
    '            _log(f"\\u2696\\ufe0f Решение: {decision}  (p_угрозы={p_block:.1%})")\n'
    '            # Structural: аномалии структуры сетевых соединений\n'
    '            structural_score = 1.0 - min(1.0,\n'
    '                features.get("port_scan_suspected_count", 0) * 0.4 +\n'
    '                features.get("unattributed_endpoint_share", 0) * 0.4 +\n'
    '                min(features.get("new_remote_endpoint_count", 0) / 20.0, 1.0) * 0.2\n'
    '            )\n'
    '            # Parametric: параметры трафика\n'
    '            pz = abs(features.get("packet_rate_zscore", 0.0))\n'
    '            bz = abs(features.get("byte_rate_zscore", 0.0))\n'
    '            non_https = features.get("non_https_endpoint_share", 0)\n'
    '            parametric_score = 1.0 - min(1.0,\n'
    '                min(pz / 5.0, 1.0) * 0.3 +\n'
    '                min(bz / 5.0, 1.0) * 0.3 +\n'
    '                non_https * 0.4\n'
    '            )\n'
    '            # Behavioral: поведенческие аномалии\n'
    '            suspicious = features.get("suspicious_port_match_count", 0)\n'
    '            blocked_ratio = features.get("blocked_state_ratio", 0)\n'
    '            behavioral_score = 1.0 - min(1.0,\n'
    '                min(suspicious / 5.0, 1.0) * 0.5 +\n'
    '                min(blocked_ratio, 1.0) * 0.3 +\n'
    '                p_block * 0.2\n'
    '            )\n'
    '            risk_score = round(p_block * 100)\n'
    '            _log(f"\\U0001f4ca Уровни: структурный={structural_score:.0%} параметрический={parametric_score:.0%} поведенческий={behavioral_score:.0%}")\n'
    '            verdict = "BLOCK" if decision == "BLOCK" else "ALLOW" if decision == "ALLOW" else "REVIEW"\n'
    '            return {\n'
    '                "verdict": verdict, "decision": decision, "risk_score": risk_score,\n'
    '                "package": "Сетевой снимок", "version": str(event_id)[:12],\n'
    '                "baseline_version": None, "threat_ru": result.get("summary", "")[:180],\n'
    '                "hash_control": None, "analysis_mode": "nn_only",\n'
    '                "score": p_block, "threshold": 0.1, "block_threshold": 0.9,\n'
    '                "timing_ms": {"total": 0}, "rules": [], "public_intel": {},\n'
    '                "levels": {\n'
    '                    "structural": structural_score,\n'
    '                    "parametric": parametric_score,\n'
    '                    "behavioral": behavioral_score,\n'
    '                },\n'
    '                "_nn_result": result,\n'
    '            }\n'
    '\n'
    '        def on_done(ev):\n'
    '            self._check_progress_bar.setValue(100)\n'
    '            self._show_event_nn(ev)\n'
    '            QTimer.singleShot(4000, lambda: self._check_progress_card.setVisible(False))\n'
    '\n'
    '        self.run_bg(job, on_done, self.check_btn)'
)

if old5 in src:
    src = src.replace(old5, new5, 1)
    print("OK #5: _check() replaced with _check_load_events() + _check_nn()")
else:
    errors.append("FAIL #5: _check() not found")

# ==============================================================================
# 6. Update _update_check_log
# ==============================================================================
old6 = (
    '    @Slot()\n'
    '    def _update_check_log(self):\n'
    '        """Обновляет текст лога прогресса в GUI-потоке."""\n'
    '        lines = getattr(self, "_check_log_lines", [])\n'
    '        total_steps = 6\n'
    '        step = len(lines)\n'
    '        pct = min(10 + int(step / total_steps * 85), 95)\n'
    '        self._check_progress_bar.setValue(pct)\n'
    '        icons = {1: "\\U0001f4e6", 2: "\\U0001f50d", 3: "\\U0001f4cb", 4: "\\U0001f52c", 5: "\\u2696\\ufe0f", 6: "\\U0001f9e0"}\n'
    '        log_html = "<br>".join(\n'
    '            f"<span style=\'color:#8a8f99\'>{icons.get(i+1,\'\\u2022\')}</span> {ln}"\n'
    '            for i, ln in enumerate(lines)\n'
    '        )\n'
    '        self._check_log.setText(log_html or "\\u23f3 Инициализация\\u2026")'
)
new6 = (
    '    @Slot()\n'
    '    def _update_check_log(self):\n'
    '        """Updates progress log text in GUI thread."""\n'
    '        lines = getattr(self, "_check_log_lines", [])\n'
    '        total_steps = 5\n'
    '        step = len(lines)\n'
    '        pct = min(10 + int(step / total_steps * 85), 95)\n'
    '        self._check_progress_bar.setValue(pct)\n'
    '        log_html = "<br>".join(\n'
    '            f"<span style=\'color:#8a8f99\'>&bull;</span> {ln}"\n'
    '            for ln in lines\n'
    '        )\n'
    '        self._check_log.setText(log_html or "\\u23f3 Инициализация\\u2026")'
)
if old6 in src:
    src = src.replace(old6, new6, 1)
    print("OK #6: _update_check_log updated")
else:
    errors.append("FAIL #6: _update_check_log not found")

# ==============================================================================
# 7. Replace _toggle_advanced with stub
# ==============================================================================
old7 = (
    '    def _toggle_advanced(self):\n'
    '        """Разворачивает/сворачивает блок дополнительных параметров — скрыт по умолчанию, чтобы при первом\n'
    '        запуске на странице было видно только главное: куда указать пакет и кнопку «показать на примере»."""\n'
    '        show = not self._adv_body.isVisible()\n'
    '        self._adv_body.setVisible(show)\n'
    '        self.adv_toggle.setText(("\\u25be  " if show else "\\u25b8  ") + "Дополнительные параметры (стадия и политика проверки)")'
)
new7 = (
    '    def _toggle_advanced(self):\n'
    '        """Stub kept for compatibility."""\n'
    '        pass'
)
if old7 in src:
    src = src.replace(old7, new7, 1)
    print("OK #7: _toggle_advanced stubbed")
else:
    errors.append("FAIL #7: _toggle_advanced not found")

# ==============================================================================
# 8. Stub out _sync_watch and _watch_tick
# ==============================================================================
old8_start = "    # ------------------------------------------------------------ автопроверка каталога (без кнопок и галочек)\n    def _sync_watch"
if old8_start in src:
    pos = src.find(old8_start)
    pos_tick = src.find("    def _watch_tick(self):", pos)
    if pos_tick != -1:
        pos_after_tick = src.find("\n    def ", pos_tick + 10)
        if pos_after_tick != -1:
            stub8 = (
                '    # ---- auto-watch removed: page now uses neural network ----\n'
                '    def _sync_watch(self, text):\n'
                '        pass\n'
                '\n'
                '    def _watch_tick(self):\n'
                '        pass\n'
                '\n'
            )
            src = src[:pos] + stub8 + src[pos_after_tick:]
            print("OK #8: _sync_watch and _watch_tick stubbed")
        else:
            errors.append("FAIL #8: cannot find end of _watch_tick")
    else:
        errors.append("FAIL #8: _watch_tick not found")
else:
    errors.append("FAIL #8: _sync_watch not found")

# ==============================================================================
# 9. Add _show_event_nn() before _set_badge
# ==============================================================================
show_event_nn = (
    '\n'
    '    def _show_event_nn(self, ev):\n'
    '        """Displays neural network analysis result on Package Check page."""\n'
    '        self._set_badge(ev.get("verdict"))\n'
    '        rs = ev.get("risk_score")\n'
    '        rs_color = "#8a8f99" if rs is None else "#e5484d" if rs >= 70 else "#d99a1c" if rs >= 30 else "#1f9d63"\n'
    '        self.risk_badge.setText("\\u2014" if rs is None else str(rs))\n'
    '        self.risk_badge.setStyleSheet(\n'
    '            f"background: {rs_color}22; color: {rs_color}; border: 2px solid {rs_color}; "\n'
    '            f"border-radius: 9px; font-size: 14pt; font-weight: 700; padding: 4px 10px;")\n'
    '        verdict = ev.get("verdict", "REVIEW")\n'
    '        decision_ru = {"ALLOW": "ДОПУСТИТЬ", "BLOCK": "ЗАБЛОКИРОВАТЬ", "REVIEW": "НА ПРОВЕРКУ"}.get(verdict, verdict)\n'
    '        self.res_title.setText(f"Нейросеть: {decision_ru}  (риск {rs}/100)")\n'
    '        self.res_sub.setText(ev.get("threat_ru", ""))\n'
    '        self.pdf_btn.setEnabled(False)\n'
    '        levels = ev.get("levels", {})\n'
    '        for name, (bar, val) in self.level_bars.items():\n'
    '            v = levels.get(name)\n'
    '            bar.setValue(int(round(100 * v)) if v is not None else 0)\n'
    '            val.setText(f"{v:.0%}" if v is not None else "\\u2014")\n'
    '            if v is not None:\n'
    '                color = "#1f9d63" if v >= 0.7 else "#d99a1c" if v >= 0.4 else "#e5484d"\n'
    '                bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; border-radius: 3px; }}")\n'
    '        nn_result = ev.get("_nn_result", {})\n'
    '        probs = nn_result.get("class_probabilities", {})\n'
    '        p_allow = probs.get("ALLOW", 0)\n'
    '        p_block = probs.get("BLOCK", 0)\n'
    '        actions_html = (\n'
    '            f"<b>Вероятность угрозы:</b> {p_block:.1%} &nbsp;|&nbsp; "\n'
    '            f"<b>Вероятность безопасности:</b> {p_allow:.1%}<br>"\n'
    '            f"<b>Решение нейросети:</b> {nn_result.get(\'decision\', \'?\')}<br>"\n'
    '            f"{nn_result.get(\'summary\', \'\')}"\n'
    '        )\n'
    '        if verdict == "BLOCK":\n'
    '            actions_html += "<br><br>\\u26d4 <b>Рекомендуется заблокировать</b> данный сетевой снимок."\n'
    '        elif verdict == "ALLOW":\n'
    '            actions_html += "<br><br>\\u2705 <b>Трафик выглядит безопасным.</b> Дополнительных действий не требуется."\n'
    '        else:\n'
    '            actions_html += "<br><br>\\u26a0\\ufe0f <b>Рекомендуется ручная проверка</b> данного события."\n'
    '        self.actions.setText(actions_html)\n'
    '        self._last_ev = ev\n'
)

marker9 = "    def _set_badge(self, verdict):"
if marker9 in src:
    pos = src.find(marker9)
    src = src[:pos] + show_event_nn + src[pos:]
    print("OK #9: _show_event_nn() added")
else:
    errors.append("FAIL #9: _set_badge marker not found")

# ==============================================================================
# Save
# ==============================================================================
with open(PATCH_FILE, "w", encoding="utf-8") as f:
    f.write(src)

if errors:
    print("\n=== ERRORS ===")
    for e in errors:
        print(e)
else:
    print("\n=== ALL DONE: gui.py patched successfully ===")
