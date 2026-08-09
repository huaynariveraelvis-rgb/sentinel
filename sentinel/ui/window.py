"""window.py — Ventana principal de SENTINEL (Command Center embebido)."""
from __future__ import annotations

import os
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
        # La voz en vivo (Gemini) maneja el audio; los avisos TTS del worker se
        # dejan solo si NO hay voz en vivo (sin clave de IA), para no solaparse.
        ai_cfg = self.settings.get("ai", {})
        live_voice = bool(voice_cfg.get("enabled") and ai_cfg.get("enabled")
                          and ai_cfg.get("gemini_api_key"))
        self.worker = ScanWorker(
            interval=interval,
            voice_enabled=bool(voice_cfg.get("enabled", False)) and not live_voice,
            alert_severity=voice_cfg.get("alert_on_severity", "ALTA"),
        )
        self.worker.result.connect(self.bridge.push_scan)  # cruza al hilo principal

        self.voice = None          # asistente de voz en vivo (se crea tras cargar)
        self._voice_started = False

        self.view.loadFinished.connect(self._on_load_finished)
        self.view.setUrl(QUrl.fromLocalFile(str(_INDEX.absolute())))
        self.worker.start()

        # Tecla Insert = mutear/despertar la voz (como JARVIS).
        try:
            from PyQt6.QtGui import QShortcut, QKeySequence
            from PyQt6.QtCore import Qt as _Qt
            sc = QShortcut(QKeySequence(_Qt.Key.Key_Insert), self)
            sc.activated.connect(self.toggle_voice_mute)
        except Exception:
            pass

    def _start_voice(self) -> None:
        """Arranca la voz en vivo si está habilitada y hay clave."""
        if self._voice_started:
            return
        ai = self.settings.get("ai", {})
        voice_cfg = self.settings.get("voice", {})
        key = ai.get("gemini_api_key", "")
        if not (voice_cfg.get("enabled") and ai.get("enabled") and key):
            return
        try:
            from sentinel.core.voice_live import VoiceAssistant
            from sentinel.core.brain import context_from_report
            import json as _json

            def _ctx():
                if self._last_report_json:
                    try:
                        return context_from_report(_json.loads(self._last_report_json))
                    except Exception:
                        return ""
                return ""

            self.voice = VoiceAssistant(
                key,
                get_context=_ctx,
                voice_name=voice_cfg.get("voice_name", "Charon"),
                on_state=lambda s: self.bridge.voice_state.emit(s),
                on_user_text=lambda t: self.bridge.voice_user.emit(t),
                on_bot_text=lambda t: self.bridge.voice_bot.emit(t),
                on_level=lambda v: self.bridge.voice_level.emit(float(v)),
            )
            self.voice.start()
            self._voice_started = True
        except Exception as e:
            print(f"[SENTINEL] no se pudo iniciar la voz: {e}")

    def toggle_voice_mute(self) -> None:
        if self.voice:
            muted = self.voice.toggle_mute()
            self.bridge.voice_state.emit("MUTED" if muted else "LISTENING")

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
        # Arranca la voz en vivo (si está habilitada) una vez la página está lista.
        self._start_voice()

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
                    speak(reply, api_key)
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

    def run_command(self, command: str) -> None:
        """Ejecuta un comando en este equipo y devuelve su salida a la UI.

        Corre en un hilo para no congelar la interfaz. `execute_locally` deja
        constancia en el registro de acciones.
        """
        command = (command or "").strip()

        def _run():
            from sentinel.net.commands import execute_locally
            code, out, err = execute_locally(command, timeout=60)
            self.bridge.command_result.emit(json.dumps(
                {"command": command, "exit_code": code,
                 "stdout": out, "stderr": err}, ensure_ascii=False))

        threading.Thread(target=_run, daemon=True).start()

    def generate_report(self, label: str, pdf: bool = False) -> None:
        """Genera el informe tecnico del ultimo barrido y lo abre.

        Corre en un hilo: escribir el HTML y lanzar el navegador para el PDF
        tarda segundos y bloquearia la interfaz.
        """
        last = self._last_report_json
        label = (label or "EQUIPO").strip()[:40]

        def _run():
            payload = {"ok": False, "msg": "", "html": "", "pdf": ""}
            try:
                if not last:
                    payload["msg"] = "Todavia no hay un barrido completo."
                    raise RuntimeError(payload["msg"])
                report = json.loads(last)
                from sentinel.core import report_html, evidence
                from sentinel.core.audit_log import read as leer_acciones
                ruta = report_html.save_report(
                    report, label,
                    checks=report.get("hardening") or [],
                    hist=evidence.history(label, limit=12),
                    cmp_=evidence.compare(label),
                    dr=evidence.drift(report, label),
                    acciones=leer_acciones(25))
                payload.update(ok=True, html=str(ruta),
                               msg=f"Informe generado: {ruta.name}")
                if pdf:
                    p = report_html.to_pdf(ruta)
                    if p:
                        payload["pdf"] = str(p)
                        payload["msg"] = f"Informe PDF generado: {p.name}"
                    else:
                        payload["msg"] = ("Informe HTML generado. No se encontro "
                                          "Chrome ni Edge para el PDF.")
                # Abre lo que se haya producido, para que el usuario lo vea.
                destino = payload["pdf"] or payload["html"]
                try:
                    os.startfile(destino)  # noqa: S606 - apertura local pedida
                except Exception:
                    pass
            except Exception as e:
                if not payload["msg"]:
                    payload["msg"] = f"No se pudo generar el informe: {e}"
            self.bridge.report_result.emit(
                json.dumps(payload, ensure_ascii=False))

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
            if self.voice:
                self.voice.stop()
        except Exception:
            pass
        try:
            self.worker.stop()
            self.worker.wait(2000)
        except Exception:
            pass
        super().closeEvent(event)
