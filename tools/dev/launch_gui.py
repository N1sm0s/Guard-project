"""Developer entry point for launching the GUI from a source checkout."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from integrityguard.gui import main

main()
