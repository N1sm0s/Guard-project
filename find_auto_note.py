src = open('integrityguard/gui.py', encoding='utf-8').read()
lines = src.splitlines()
for i, line in enumerate(lines):
    if 'auto_note' in line:
        print(f"{i+1}: {line}")
