"""scan_worker.py — Ejecuta los motores de SENTINEL en un hilo aparte.

- Vigilancia (procesos/red/arranque): rapida, cada `interval` segundos.
- Blindaje (hardening de Windows): lenta (~10s), se cachea y refresca cada
  `hardening_every` segundos; se fusiona en cada reporte para que el panel
  siempre muestre el estado completo.
No bloquea la UI: emite el reporte como JSON via la senal `result`.
"""
from __future__ import annotations

import json
import time
import threading

from PyQt6.QtCore import QThread, pyqtSignal

from sentinel.core.monitor import full_scan


class ScanWorker(QThread):
    result = pyqtSignal(str)

    def __init__(self, interval: int = 60, hardening_every: int = 300,
                 voice_enabled: bool = False, alert_severity: str = "ALTA",
                 parent=None):
        super().__init__(parent)
        self.interval = max(10, int(interval))
        self.hardening_every = max(60, int(hardening_every))
        self.voice_enabled = bool(voice_enabled)
        self.alert_severity = alert_severity
        self._stop = threading.Event()
        self._scan_now = threading.Event()
        self._hard_checks: list = []
        self._hard_findings: list = []
        self._hard_score: int | None = None
        self._hard_last: float = 0.0
        self._hard_running: bool = False
        # Persistencia avanzada (tareas, servicios, WMI, USB): tambien lenta,
        # se refresca en el mismo ciclo que el blindaje.
        self._deep_findings: list = []
        self._spoken: set = set()   # amenazas ya avisadas por voz

    def trigger(self) -> None:
        self._scan_now.set()

    def fix_command_for(self, key: str) -> str:
        for c in self._hard_checks:
            if getattr(c, "key", None) == key:
                return getattr(c, "fix_command", "") or ""
        return ""

    def force_hardening_refresh(self) -> None:
        self._hard_last = 0.0
        self._scan_now.set()

    def stop(self) -> None:
        self._stop.set()
        self._scan_now.set()

    def _kick_hardening_if_due(self) -> None:
        """Lanza el blindaje en SU PROPIO hilo (es lento ~10s) para no bloquear
        el bucle de vigilancia. Al terminar, cachea y dispara un re-escaneo
        para emitir un reporte ya enriquecido con el blindaje."""
        now = time.monotonic()
        if self._hard_running:
            return
        if self._hard_last and (now - self._hard_last) < self.hardening_every:
            return
        self._hard_running = True

        def _job():
            try:
                from sentinel.core.hardening import scan_hardening, hardening_score
                checks, findings = scan_hardening()
                self._hard_checks = checks
                self._hard_findings = findings
                self._hard_score = hardening_score(checks)
                self._hard_last = time.monotonic()
            except Exception:
                pass
            try:
                from sentinel.core.persistence import scan_persistence
                self._deep_findings = scan_persistence()
            except Exception:
                pass
            finally:
                self._hard_running = False
                if not self._stop.is_set():
                    self.trigger()   # reemite incluyendo el blindaje

        threading.Thread(target=_job, daemon=True).start()

    def _alert_threshold(self) -> int:
        from sentinel.core.monitor import Severity
        return {"CRITICA": Severity.CRITICAL, "ALTA": Severity.HIGH,
                "MEDIA": Severity.MEDIUM}.get(self.alert_severity, Severity.HIGH)

    def _maybe_alert(self, report: dict) -> None:
        """Avisa por voz una sola vez por amenaza nueva (>= umbral)."""
        if not self.voice_enabled:
            return
        thr = self._alert_threshold()
        for f in report.get("findings", []):
            if f.get("severity", 0) < thr:
                continue
            key = (f.get("category"), f.get("title"))
            if key in self._spoken:
                continue
            self._spoken.add(key)
            try:
                from sentinel.core.voice import speak
                from sentinel.core.brain import alert_phrase
                speak(alert_phrase(f))
            except Exception:
                pass
            break  # un aviso por ciclo, no saturar

    def _emit_report(self) -> None:
        from sentinel.core.brain import heuristic_summary
        report = full_scan(
            extra_findings=list(self._hard_findings) + list(self._deep_findings),
            hardening=self._hard_checks,
            hardening_score=self._hard_score,
        )
        report["summary"] = heuristic_summary(report)
        self._maybe_alert(report)
        self.result.emit(json.dumps(report, ensure_ascii=False))

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                # Barrido rapido de vigilancia -> la UI muestra datos al instante.
                self._emit_report()
                # El blindaje se refresca en su propio hilo (no bloquea).
                self._kick_hardening_if_due()
            except Exception as e:
                self.result.emit(json.dumps(
                    {"error": str(e), "findings": [], "counts": {},
                     "max_severity": "INFO"}))
            self._scan_now.wait(timeout=self.interval)
            self._scan_now.clear()
