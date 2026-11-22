# -*- coding: utf-8 -*-
"""Helper to find the correct GUI entry point."""
import subprocess, sys, os

# Try common entry points
entries = [
    [r"F:\New\integrityguard\.venv\Scripts\pythonw.exe", "-c",
     "from integrityguard.gui import main; main()"],
    [r"F:\New\integrityguard\.venv\Scripts\pythonw.exe", "-m", "integrityguard.gui"],
]

os.chdir(r"F:\New\integrityguard")
sys.path.insert(0, r"F:\New\integrityguard")

# Just check what's available
import importlib.util
spec = importlib.util.find_spec("integrityguard.gui")
if spec:
    print(f"Found gui module at: {spec.origin}")
else:
    print("gui module NOT found")

# Check for main() in gui
try:
    import integrityguard.gui as g
    has_main = hasattr(g, 'main')
    print(f"Has main(): {has_main}")
    fns = [x for x in dir(g) if not x.startswith('_')]
    print(f"Top-level names: {fns[:20]}")
except Exception as e:
    print(f"Import error: {e}")
