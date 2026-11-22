import ast, sys
path = 'F:/New/integrityguard/integrityguard/gui.py'
with open(path, encoding='utf-8') as f:
    src = f.read()
try:
    ast.parse(src)
    print("OK: syntax valid")
except SyntaxError as e:
    print(f"SYNTAX ERROR at line {e.lineno}: {e.msg}")
    sys.exit(1)
