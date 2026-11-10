# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path


a = Analysis(
    ['IntegrityGuard.pyw'],
    pathex=[],
    binaries=[],
    datas=[('models/detector.pt', 'models'), ('assets', 'assets')],
    hiddenimports=['fpdf'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['pyinstaller_runtime.py'],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# Do not bundle unrelated VC runtime / ICU DLLs discovered from the host's
# Codex runtime (for example Poppler/libheif). Their exports can shadow the
# versions expected by the PySide6 wheel and prevent QtCore from loading.
_pyside_prefixes = (
    str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'PySide6').lower(),
    str(Path(sys.prefix) / 'Lib' / 'site-packages' / 'shiboken6').lower(),
)
_runtime_names = {'icuuc.dll', 'msvcp140.dll', 'vcruntime140.dll'}
a.binaries = [entry for entry in a.binaries
              if not (Path(entry[0]).name.lower() in _runtime_names
                      and not str(entry[1]).lower().startswith(_pyside_prefixes))]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IntegrityGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/integrityguard.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IntegrityGuard',
)
