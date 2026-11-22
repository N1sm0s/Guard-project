"""
Patch gui.py: label ALL flows in an event, not just the first one.
"""
import re

path = r"F:\New\integrityguard\integrityguard\gui.py"

with open(path, encoding="utf-8") as f:
    src = f.read()

# Find and replace the _lbl_submit method's flow_id logic
old_block = '''            # flow_id — из первого endpoint или генерируем
            try:
                snap = json.loads(snap_json or "{}")
                eps = snap.get("remote_endpoints") or []
                flow_id = eps[0].get("id", str(uuid.uuid4())[:12]) if eps else str(uuid.uuid4())[:12]
            except Exception:
                flow_id = str(uuid.uuid4())[:12]
            result = reviews.propose_simple(
                event_id=event_id,
                flow_id=flow_id,
                snapshot_sha256=sha256 or hashlib.sha256(snap_json.encode()).hexdigest(),
                is_malicious=is_malicious,
                rationale=rationale,
            )
            verdict_str = "BLOCK" if is_malicious else "ALLOW"
            color = "#e5484d" if is_malicious else "#1f9d63"
            self.lbl_note.setText(f"<span style='color:{color}'>Метка {verdict_str} сохранена "
                                   f"(id={result.get('id', '?')})</span>")
            self.lbl_note.setTextFormat(Qt.RichText)
            self.lbl_rationale.clear()
            self._lbl_load_events()   # обновляем счётчик меток в таблице'''

new_block = '''            # Помечаем ВСЕ flows события (требуется для попадания в обучение)
            try:
                snap = json.loads(snap_json or "{}")
                eps = snap.get("remote_endpoints") or []
                flow_ids = [ep.get("id") for ep in eps if isinstance(ep, dict) and ep.get("id")]
            except Exception:
                flow_ids = []
            if not flow_ids:
                flow_ids = [str(uuid.uuid4())[:12]]
            snap_sha = sha256 or hashlib.sha256(snap_json.encode()).hexdigest()
            labeled_count = 0
            last_result = None
            for flow_id in flow_ids:
                try:
                    last_result = reviews.propose_simple(
                        event_id=event_id,
                        flow_id=flow_id,
                        snapshot_sha256=snap_sha,
                        is_malicious=is_malicious,
                        rationale=rationale,
                    )
                    labeled_count += 1
                except Exception:
                    pass
            verdict_str = "BLOCK" if is_malicious else "ALLOW"
            color = "#e5484d" if is_malicious else "#1f9d63"
            self.lbl_note.setText(f"<span style='color:{color}'>Метка {verdict_str} сохранена "
                                   f"({labeled_count}/{len(flow_ids)} flows)</span>")
            self.lbl_note.setTextFormat(Qt.RichText)
            self.lbl_rationale.clear()
            self._lbl_load_events()   # обновляем счётчик меток в таблице'''

if old_block in src:
    new_src = src.replace(old_block, new_block)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_src)
    print("SUCCESS: gui.py patched - now labels ALL flows per event")
else:
    print("ERROR: target block not found in gui.py!")
    # Show context
    idx = src.find("flow_id = eps[0].get")
    if idx >= 0:
        print("Found similar line at char", idx)
        print(repr(src[idx-200:idx+300]))
    else:
        print("'flow_id = eps[0].get' not found either")
