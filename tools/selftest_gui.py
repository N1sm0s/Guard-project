"""Run the GUI self-test from a source checkout."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from integrityguard.gui_selftest import run

    sys.exit(run())
