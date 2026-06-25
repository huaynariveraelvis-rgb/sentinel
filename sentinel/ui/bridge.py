"""bridge.py — Puente Python <-> JavaScript (QWebChannel).

Se registra como `pyBridge` (mismo nombre que espera el frontend heredado).
Expone:
  - senal `scan_result(str)`  -> empuja el reporte de vigilancia (JSON) a la UI
  - slot  `request_scan()`    -> la UI pide un barrido inmediato
  - controles de ventana (minimizar/maximizar/cerrar/fullscreen)
Los metodos que el frontend invoca con optional-chaining y que aun no aplican
a SENTINEL se dejan como stubs inofensivos.
"""
from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


class Bridge(QObject):
    scan_result = pyqtSignal(str)
    theme_changed = pyqtSignal(str)

    def __init__(self, window):
        super().__init__()
        self._window = window

    # ---- Seguridad ----
    @pyqtSlot(str)
    def push_scan(self, json_str: str) -> None:
        """Recibe el reporte del worker (otro hilo) y lo reemite al JS.
        Al ser un slot, Qt encola la llamada al hilo principal -> QWebChannel
        entrega siempre desde el hilo correcto."""
        self.scan_result.emit(json_str)

    @pyqtSlot()
    def request_scan(self) -> None:
        self._window.request_scan()

    @pyqtSlot()
    def request_theme(self) -> None:
        self.theme_changed.emit("guardian")

    # ---- Controles de ventana ----
    @pyqtSlot()
    def minimize(self) -> None:
        self._window.showMinimized()

    @pyqtSlot()
    def toggle_max(self) -> None:
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()

    @pyqtSlot()
    def close_win(self) -> None:
        self._window.close()

    @pyqtSlot()
    def toggle_fullscreen(self) -> None:
        if self._window.isFullScreen():
            self._window.showNormal()
        else:
            self._window.showFullScreen()

    @pyqtSlot()
    def start_move(self) -> None:
        # Arrastre de ventana sin marco — se cableara al pulir el frame.
        pass

    # ---- Stubs inofensivos (heredados del frontend) ----
    @pyqtSlot()
    def stop(self) -> None: ...
    @pyqtSlot()
    def toggle_mute(self) -> None: ...
    @pyqtSlot(str)
    def on_text_command(self, text: str) -> None: ...
    @pyqtSlot()
    def open_settings(self) -> None: ...
    @pyqtSlot()
    def open_terminal(self) -> None: ...
    @pyqtSlot()
    def open_folder(self) -> None: ...
