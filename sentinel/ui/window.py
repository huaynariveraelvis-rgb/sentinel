"""window.py — Ventana principal de SENTINEL (Command Center embebido)."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QMainWindow, QFileDialog
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtWebEngineWidgets import QWebEngineView

from sentinel import __product__
from sentinel.ui.bridge import Bridge
from sentinel.ui.scan_worker import ScanWorker

_INDEX = (Path(__file__).resolve().parent.parent.parent
          / "assets" / "command_center" / "index.html")


class SentinelWindow(QMainWindow):
    def __init__(self, scan_interval: int | None = None):
        super().__init__()
        self.setWindowTitle(f"{__product__} — ELVIS SYSTEMS")
        self.resize(1280, 820)

        from sentinel.core.config import load_settings
        self.settings = load_settings()
        scan_cfg = self.settings.get("scan", {})
        voice_cfg = self.settings.get("voice", {})
        interval = scan_interval or scan_cfg.get("auto_interval_seconds", 60)
        self._last_report_json = None   # para dar contexto al chat

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
        self.worker = ScanWorker(
            interval=interval,
            voice_enabled=bool(voice_cfg.get("enabled", False)),
            alert_severity=voice_cfg.get("alert_on_severity", "ALTA"),
        )
        self.worker.result.connect(self.bridge.push_scan)  # cruza al hilo principal

        self.view.loadFinished.connect(self._on_load_finished)
        self.view.setUrl(QUrl.fromLocalFile(str(_INDEX.absolute())))
        self.worker.start()

    def _on_load_finished(self, ok: bool) -> None:
        """Inyecta el estado de licencia en la pagina (badge MODO PRUEBA)."""
        if not ok:
            return
        try:
            from sentinel.core.license import license_status
            st = license_status()
            licensed = bool(st.get("licensed"))
            name = st.get("customer", "") or ""
            js = (f"document.body.classList.toggle('trial', {str(not licensed).lower()});"
                  f"window.__sentinelLicense={{licensed:{str(licensed).lower()},"
                  f"customer:{json.dumps(name)}}};")
            self.view.page().runJavaScript(js)
        except Exception:
            pass

    def request_scan(self) -> None:
        self.worker.trigger()

    def chat(self, message: str) -> None:
        """Responde un mensaje del usuario via el cerebro (Gemini), en un hilo."""
        ai_cfg = self.settings.get("ai", {})
        api_key = ai_cfg.get("gemini_api_key", "") if ai_cfg.get("enabled") else ""
        voice_cfg = self.settings.get("voice", {})
        speak_back = bool(voice_cfg.get("enabled"))
        last = self._last_report_json

        def _run():
            from sentinel.core.brain import chat as brain_chat, context_from_report
            ctx = ""
            if last:
                try:
                    ctx = context_from_report(json.loads(last))
                except Exception:
                    ctx = ""
            reply = brain_chat(message, api_key, ctx)
            self.bridge.chat_reply.emit(reply)
            if speak_back and api_key:
                try:
                    from sentinel.core.voice import speak
                    speak(reply)
                except Exception:
                    pass

        threading.Thread(target=_run, daemon=True).start()

    def apply_fix(self, key: str) -> None:
        """Aplica un blindaje en un hilo (el UAC bloquea) y reporta resultado."""
        cmd = self.worker.fix_command_for(key)

        def _run():
            from sentinel.core.fixer import apply_fix as run_fix
            ok, msg = run_fix(cmd)
            self.bridge.fix_result.emit(json.dumps(
                {"ok": ok, "msg": msg, "key": key}, ensure_ascii=False))
            if ok:
                self.worker.force_hardening_refresh()

        threading.Thread(target=_run, daemon=True).start()

    def pick_and_analyze(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Analizar archivo")
        if path:
            self.analyze(path)

    def analyze(self, target: str) -> None:
        """Analiza un archivo o URL bajo demanda, en un hilo."""
        def _run():
            from sentinel.core.analysis import analyze_target
            try:
                res = analyze_target(target)
            except Exception as e:
                res = {"ok": False, "target": target, "error": str(e)}
            self.bridge.analysis_result.emit(json.dumps(res, ensure_ascii=False))

        threading.Thread(target=_run, daemon=True).start()

    def quarantine_file(self, path: str) -> None:
        from sentinel.core.analysis import quarantine
        res = quarantine(path)
        self.bridge.fix_result.emit(json.dumps(
            {"ok": res.get("ok"), "msg": res.get("message") or res.get("error", ""),
             "key": "quarantine"}, ensure_ascii=False))
        self.worker.trigger()

    def closeEvent(self, event):
        try:
            self.worker.stop()
            self.worker.wait(2000)
        except Exception:
            pass
        super().closeEvent(event)
