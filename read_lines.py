import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
lines = open(r'F:\New\integrityguard\integrityguard\gui.py', encoding='utf-8').readlines()
for i, l in enumerate(lines[1355:1700], start=1356):
    print(i, l, end='')
