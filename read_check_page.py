path = 'integrityguard/gui.py'
lines = open(path, encoding='utf-8').read().splitlines()
for i in range(1355, 1700):
    print(f"{i+1}: {lines[i]}")
