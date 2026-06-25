"""scan_worker.py — Ejecuta el motor de vigilancia en un hilo aparte.

Corre full_scan() periodicamente (y bajo demanda) sin bloquear la UI,
emitiendo el reporte como JSON via la senal `result`.
"""
from __future__ import annotations

import json
import threading

from PyQt6.QtCore import QThread, pyqtSignal

from sentinel.core.monitor import full_scan


class ScanWorker(QThread):
    result = pyqtSignal(str)   # reporte completo en JSON

    def __init__(self, interval: int = 60, parent=None):
        super().__init__(parent)
        self.interval = max(10, int(interval))
        self._stop = threading.Event()
        self._scan_now = threading.Event()

    def trigger(self) -> None:
        """Pide un escaneo inmediato (desde la UI)."""
        self._scan_now.set()

    def stop(self) -> None:
        self._stop.set()
        self._scan_now.set()  # despierta el sleep

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                report = full_scan()
                self.result.emit(json.dumps(report, ensure_ascii=False))
            except Exception as e:  # nunca matar el hilo por un fallo de barrido
                self.result.emit(json.dumps({"error": str(e), "findings": [],
                                             "counts": {}, "max_severity": "INFO"}))
            # Espera el intervalo, pero responde al stop / scan-now al instante.
            self._scan_now.wait(timeout=self.interval)
            self._scan_now.clear()
