src = open('integrityguard/gui.py', encoding='utf-8').read()
lines = src.splitlines()
for i in range(355, 380):
    print(f"{i+1}: {lines[i]}")
