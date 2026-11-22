# -*- coding: utf-8 -*-
"""Fix remaining 2 blocks that failed in patch_page_check.py"""

PATCH_FILE = r"F:\New\integrityguard\integrityguard\gui.py"

with open(PATCH_FILE, encoding="utf-8") as f:
    src = f.read()

errors = []

# ==============================================================================
# Fix #6: _update_check_log — find dynamically and replace
# ==============================================================================
marker6 = "    def _update_check_log(self):"
pos6 = src.find(marker6)
if pos6 == -1:
    errors.append("FAIL #6: _update_check_log not found")
else:
    # Find end of method (next def at same indent)
    pos6_end = src.find("\n    def ", pos6 + 10)
    if pos6_end == -1:
        errors.append("FAIL #6: cannot find end")
    else:
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
            '        self._check_log.setText(log_html or "\u23f3 \u0418\u043d\u0438\u0446\u0438\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u044f\u2026")\n'
        )
        src = src[:pos6] + new6 + src[pos6_end:]
        print("OK #6: _update_check_log replaced")

# ==============================================================================
# Fix #7: _toggle_advanced — find and stub
# ==============================================================================
marker7 = "    def _toggle_advanced(self):"
pos7 = src.find(marker7)
if pos7 == -1:
    errors.append("FAIL #7: _toggle_advanced not found")
else:
    pos7_end = src.find("\n    def ", pos7 + 10)
    if pos7_end == -1:
        errors.append("FAIL #7: cannot find end")
    else:
        new7 = (
            '    def _toggle_advanced(self):\n'
            '        """Stub kept for compatibility."""\n'
            '        pass\n'
        )
        src = src[:pos7] + new7 + src[pos7_end:]
        print("OK #7: _toggle_advanced stubbed")

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
    print("\n=== ALL DONE ===")
