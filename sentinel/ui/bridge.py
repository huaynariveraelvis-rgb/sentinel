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
    fix_result = pyqtSignal(str)     # resultado de aplicar un blindaje (JSON)
    analysis_result = pyqtSignal(str)  # resultado de analizar archivo/URL (JSON)
    report_result = pyqtSignal(str)    # resultado de generar el informe (JSON)
    command_result = pyqtSignal(str)   # salida de un comando de la terminal (JSON)
    chat_reply = pyqtSignal(str)     # respuesta conversacional del cerebro
    voice_state = pyqtSignal(str)    # estado de voz: LISTENING/THINKING/SPEAKING
    voice_user = pyqtSignal(str)     # transcripción de lo que dijo el usuario
    voice_bot = pyqtSignal(str)      # texto que va hablando SENTINEL
    voice_level = pyqtSignal(float)  # nivel de audio 0..1 (anima el orbe)

    def __init__(self, window):
        super().__init__()
        self._window = window

    # ---- Seguridad ----
    @pyqtSlot(str)
    def push_scan(self, json_str: str) -> None:
        """Recibe el reporte del worker (otro hilo) y lo reemite al JS.
        Al ser un slot, Qt encola la llamada al hilo principal -> QWebChannel
        entrega siempre desde el hilo correcto."""
        self._window._last_report_json = json_str
        self.scan_result.emit(json_str)

    @pyqtSlot()
    def request_scan(self) -> None:
        self._window.request_scan()

    @pyqtSlot(str)
    def apply_fix(self, key: str) -> None:
        """Aplica el blindaje identificado por `key` (con UAC)."""
        self._window.apply_fix(key)

    @pyqtSlot(str)
    def run_command(self, command: str) -> None:
        """Ejecuta un comando en ESTE equipo (la terminal de la consola).
        Es un terminal local: corre donde corre SENTINEL, con el permiso del
        usuario que lo opera, y queda registrado."""
        self._window.run_command(command)

    @pyqtSlot(str, bool)
    def generate_report(self, label: str, pdf: bool) -> None:
        """Genera el informe tecnico del ultimo barrido y lo abre."""
        self._window.generate_report(label, pdf)

    @pyqtSlot(str)
    def analyze_path(self, path: str) -> None:
        """Analiza un archivo o URL bajo demanda."""
        self._window.analyze(path)

    @pyqtSlot()
    def open_file(self) -> None:
        """Abre un dialogo para elegir un archivo a analizar."""
        self._window.pick_and_analyze()

    @pyqtSlot(str)
    def quarantine(self, path: str) -> None:
        """Pone un archivo en cuarentena (reversible)."""
        self._window.quarantine_file(path)

    @pyqtSlot()
    def request_theme(self) -> None:
        self.theme_changed.emit("guardian")

    @pyqtSlot(result=str)
    def app_config(self) -> str:
        """Config que el frontend necesita al arrancar: rol del equipo y datos
        de la Consola de Flota (nube). El token de administrador SOLO se entrega
        si este equipo es 'root' — un equipo normal nunca podra comandar el
        parque aunque abran la app."""
        import json
        from sentinel.core import config
        s = config.load_settings()
        role = str(s.get("role", "agent")).lower()
        cloud = s.get("cloud", {}) or {}
        return json.dumps({
            "role": role,
            "cloud_url": str(cloud.get("url", "")),
            "admin_token": str(cloud.get("admin_token", "")) if role == "root" else "",
        })

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
    def toggle_mute(self) -> None:
        self._window.toggle_voice_mute()
    @pyqtSlot(str)
    def on_text_command(self, text: str) -> None:
        """Mensaje de chat del usuario -> cerebro conversacional."""
        self._window.chat(text)
    @pyqtSlot()
    def open_settings(self) -> None: ...
    @pyqtSlot()
    def open_terminal(self) -> None: ...
    @pyqtSlot()
    def open_folder(self) -> None: ...
