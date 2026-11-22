"""Coordinate GUI launches within one user session."""
import os
from pathlib import Path

from PySide6.QtCore import QLockFile
from PySide6.QtNetwork import QLocalServer, QLocalSocket


class ApplicationInstance:
    def __init__(self, directory=None, server_name="IntegrityGuard.GUI.v1"):
        directory = Path(directory or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "IntegrityGuard")
        directory.mkdir(parents=True, exist_ok=True)
        self.lock = QLockFile(str(directory / "gui.lock"))
        # Allow Qt to remove a lock left by a process that exited abnormally.
        # With 0, QLockFile disables stale-lock cleanup; a dead PID then makes
        # every scheduled restart silently return from main() as a duplicate.
        self.lock.setStaleLockTime(30_000)
        self.server_name = server_name
        self.server = QLocalServer()

    def acquire(self):
        if self.lock.tryLock(0):
            QLocalServer.removeServer(self.server_name)
            if not self.server.listen(self.server_name):
                self.lock.unlock()
                raise RuntimeError(self.server.errorString())
            return True
        socket = QLocalSocket()
        socket.connectToServer(self.server_name)
        if socket.waitForConnected(2000):
            socket.disconnectFromServer()
        return False

    def bind(self, window):
        def activate():
            while self.server.hasPendingConnections():
                connection = self.server.nextPendingConnection()
                connection.close()
                connection.deleteLater()
            window.showNormal()
            window.raise_()
            window.activateWindow()

        self.server.newConnection.connect(activate)

    def close(self):
        self.server.close()
        self.lock.unlock()
