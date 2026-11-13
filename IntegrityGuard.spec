# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path

# Resolve native dependencies only from this interpreter, its packages and
# Windows. Host tools (Codex, Git, image codecs) may inject incompatible DLLs
# into PATH. PyInstaller hooks add each package's own DLL directories.
if sys.platform == 'win32':
    _windows = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    os.environ['PATH'] = os.pathsep.join(str(p) for p in (
        Path(sys.prefix) / 'Scripts', Path(sys.base_prefix),
        Path(sys.base_prefix) / 'DLLs', _windows / 'System32', _windows,
    ))


a = Analysis(
    ['IntegrityGuard.pyw'],
    pathex=[],
    binaries=[],
    datas=[('models/detector.pt', 'models'), ('assets', 'assets'), ('tools/network-block.ps1', 'tools')],
    hiddenimports=['fpdf'],
    hookspath=[],
    # Training reports save PNG via Agg; no interactive matplotlib UI is used.
    hooksconfig={'matplotlib': {'backends': ['Agg']}},
    runtime_hooks=['pyinstaller_runtime.py'],
    # The GUI only ever imports PySide6.QtCore/QtGui/QtWidgets/QtNetwork
    # (see gui.py, charts.py, instance.py); PDF reports are rendered with
    # fpdf2, not Qt. QtQml/QtQuick/QtPdf/QtOpenGL* are pulled in only by
    # PySide6's own PyInstaller hook, never actually used, and together with
    # their native Qt6*.dll backends add ~25 MB that nothing in this app
    # reaches at runtime.
    excludes=['PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtQuickWidgets',
              'PySide6.QtQuick3D', 'PySide6.QtPdf', 'PySide6.QtPdfWidgets',
              'PySide6.QtOpenGL', 'PySide6.QtOpenGLWidgets',
              'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineWidgets',
              'PySide6.QtWebEngineQuick', 'PySide6.QtWebChannel',
              # Developer-only entry points; retain torch's runtime helpers,
              # distributed imports and source files needed by introspection.
              'pytest', '_pytest', 'IPython', 'notebook', 'sphinx',
              'torch.utils.benchmark', 'torch.utils.bottleneck',
              'matplotlib.testing', 'numpy.f2py'],
    # NOTE: torch.distributed/torch.onnx/torch.testing were tried as excludes
    # too and reverted -- torch's own __init__ imports torch.distributed
    # unconditionally even for single-process CPU use, so excluding it broke
    # startup ("No module named 'torch.distributed'"). Verified by rebuilding
    # and running the packaged exe's --selftest-gui, not just by inspection.
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
# Qt's software-OpenGL fallback rasterizer (opengl32sw.dll, ~20 MB) is only
# loaded when a machine has no usable GPU/driver OpenGL at all -- practically
# never for a desktop security tool. torch/bin/protoc.exe (~3 MB) is a
# protobuf code-generator torch ships for *building* torch itself; nothing
# in this app's runtime invokes it. Pillow's AVIF codec plugin (~7.5 MB) is
# never used: the app only reads/writes PNG/ICO assets and PDF charts.
_unused_binary_names = {'opengl32sw.dll'}
_unused_binary_prefixes = ('_avif.',)
a.binaries = [entry for entry in a.binaries
              if Path(entry[0]).name.lower() not in _unused_binary_names
              and not Path(entry[0]).name.lower().startswith(_unused_binary_prefixes)
              and Path(entry[0]).name.lower() != 'protoc.exe']
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
