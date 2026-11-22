with open('F:/New/integrityguard/integrityguard/gui.py', encoding='utf-8') as f:
    lines = f.readlines()

# Find _page_train method
start = None
for i, line in enumerate(lines, 1):
    if '_page_train' in line and 'def ' in line:
        start = i
        break

if start:
    print(f"_page_train starts at line {start}")
    for i, line in enumerate(lines[start-1:start+120], start):
        print(f"{i}: {line.rstrip()}")
