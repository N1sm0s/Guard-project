"""Application, bundled-resource, and writable-data locations."""
from __future__ import annotations

import os
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
APP_ROOT = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", APP_ROOT)).resolve() if FROZEN else APP_ROOT

local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
data_location = local_app_data / "IntegrityGuard" / "data-location.txt"
if data_location.is_file():
    configured_data = Path(data_location.read_text(encoding="utf-8-sig").strip())
    if not configured_data.is_absolute() or not configured_data.is_dir():
        raise RuntimeError(f"Каталог данных IntegrityGuard недоступен: {configured_data}")
    DATA_ROOT = configured_data.resolve()
elif FROZEN:
    DATA_ROOT = local_app_data / "IntegrityGuard" / "data"
else:
    DATA_ROOT = APP_ROOT / "data"
