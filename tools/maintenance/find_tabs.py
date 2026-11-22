import re
with open('F:/New/integrityguard/integrityguard/gui.py', encoding='utf-8') as f:
    lines = f.readlines()

patterns = ['QTabWidget', 'addTab', 'tab_', 'Tab(', 'sidebar', 'nav_btn', 'stacked', 'QStackedWidget', 'NetworkTab', 'def _build']
for i, line in enumerate(lines, 1):
    for p in patterns:
        if p.lower() in line.lower():
            print(f"{i}: {line.rstrip()}")
            break
