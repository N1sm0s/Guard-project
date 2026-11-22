import ast, sys

files = [
    'integrityguard/charts.py',
    'integrityguard/gui.py',
]
ok = True
for f in files:
    try:
        src = open(f, encoding='utf-8').read()
        ast.parse(src)
        print(f'OK: {f}')
    except SyntaxError as e:
        print(f'SYNTAX ERROR in {f}: {e}')
        ok = False
sys.exit(0 if ok else 1)
