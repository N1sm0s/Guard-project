"""Application, bundled-resource, and writable-data locations."""
from __future__ import annotations

import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
APP_ROOT = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", APP_ROOT)).resolve() if FROZEN else APP_ROOT

if FROZEN:
    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    DATA_ROOT = local_app_data / "IntegrityGuard" / "data"
else:
    DATA_ROOT = APP_ROOT / "data"
