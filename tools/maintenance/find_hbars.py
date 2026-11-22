with open('F:/New/integrityguard/integrityguard/charts.py', encoding='utf-8') as f:
    lines = f.readlines()

# Find HBars and LiveLine classes
targets = ['class HBars', 'class LiveLine', 'def set_rows', 'def append', 'def set_data']
for i, line in enumerate(lines, 1):
    for t in targets:
        if t in line:
            print(f"{i}: {line.rstrip()}")
            # print next 15 lines for context
            for j in range(1, 16):
                if i-1+j < len(lines):
                    print(f"  {i+j}: {lines[i-1+j].rstrip()}")
            print()
            break
