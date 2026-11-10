"""Prefer the Qt wheel's colocated runtime DLLs over colliding package DLLs."""
import os
import sys

if sys.platform == "win32" and getattr(sys, "frozen", False):
    qt_runtime = os.path.join(sys._MEIPASS, "PySide6")
    if os.path.isdir(qt_runtime):
        os.environ["PATH"] = qt_runtime + os.pathsep + os.environ.get("PATH", "")
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(qt_runtime)
