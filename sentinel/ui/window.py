"""window.py — Ventana principal de SENTINEL (Command Center embebido)."""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QMainWindow
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtWebEngineWidgets import QWebEngineView

from sentinel import __product__
from sentinel.ui.bridge import Bridge
from sentinel.ui.scan_worker import ScanWorker

_INDEX = (Path(__file__).resolve().parent.parent.parent
          / "assets" / "command_center" / "index.html")


class SentinelWindow(QMainWindow):
    def __init__(self, scan_interval: int = 60):
        super().__init__()
        self.setWindowTitle(f"{__product__} — ELVIS SYSTEMS")
        self.resize(1280, 820)

        self.view = QWebEngineView(self)
        try:
            self.view.page().setBackgroundColor(QColor("#05100c"))
        except Exception:
            pass
        self.setCentralWidget(self.view)

        # Puente Python <-> JS
        self.bridge = Bridge(self)
        self.channel = QWebChannel()
        self.channel.registerObject("pyBridge", self.bridge)
        self.view.page().setWebChannel(self.channel)

        # Motor de vigilancia en hilo aparte
        self.worker = ScanWorker(interval=scan_interval)
        self.worker.result.connect(self.bridge.push_scan)  # cruza al hilo principal

        self.view.setUrl(QUrl.fromLocalFile(str(_INDEX.absolute())))
        self.worker.start()

    def request_scan(self) -> None:
        self.worker.trigger()

    def closeEvent(self, event):
        try:
            self.worker.stop()
            self.worker.wait(2000)
        except Exception:
            pass
        super().closeEvent(event)
