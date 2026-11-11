"""Real-only GUI smoke check; it must not create or load synthetic packages."""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path


def run() -> int:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        from . import gui
    except Exception as error:  # noqa: BLE001
        print(f"GUI startup import failed: {error}")
        return 1

    app = QApplication.instance() or QApplication([])
    old_data = gui.DATA
    with tempfile.TemporaryDirectory(prefix="integrityguard-real-only-gui-") as temp:
        gui.DATA = Path(temp)
        window = None
        try:
            window = gui.MainWindow()
            window.show()
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.02)
            assert not hasattr(window, "demo_labels")
            assert not hasattr(window, "demo_try_btn")
            assert not hasattr(window, "demo_btn")
            assert not hasattr(window, "all_btn")
            assert not window.r_btn.isEnabled()
            assert window.incoming.is_dir()
            assert not any(item.is_dir() for item in window.incoming.iterdir())
            window._quitting = True
            window.auto_timer.stop()
            window.net_timer.stop()
            window.cleanup_timer.stop()
            window.candidate_timer.stop()
            window._watch_timer.stop()
            for worker in list(window._workers):
                if worker.isRunning():
                    worker.wait(3000)
            window.close()
            app.processEvents()
            print("GUI starts; real-package intake is ready; synthetic demo actions are disabled; incoming queue is empty.")
            return 0
        except Exception as error:  # noqa: BLE001
            print(f"GUI smoke check failed: {error}")
            if window is not None:
                window._quitting = True
                window.close()
            return 1
        finally:
            gui.DATA = old_data
