"""Entry point for the project-owned isolated Python training environment."""
import sys
import os
from pathlib import Path

# A frozen parent may pass a DLL search directory containing CPU-only torch.
# Reset it in the child before importing torch; never alter the GUI process.
if os.name == 'nt':
    import ctypes
    ctypes.windll.kernel32.SetDllDirectoryW(None)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrityguard.training_process import worker_main

if __name__ == '__main__':
    raise SystemExit(worker_main())
