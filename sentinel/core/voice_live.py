"""voice_live.py — Voz en tiempo real de SENTINEL (escucha + habla, tipo JARVIS).

Usa la API Live de Gemini (audio nativo): captura el micrófono con
sounddevice, lo transmite a Gemini, y reproduce la respuesta hablada. Corre
en su propio hilo con un loop asyncio para no tocar el hilo de la GUI.

Persona: guardián de ciberseguridad (SENTINEL), con el contexto de los
hallazgos actuales del equipo inyectado en el system prompt.

Modelo "siempre escuchando + mute": el micrófono está abierto siempre; al
silenciar (mute) se deja de enviar audio. La detección de fin de habla (VAD)
la hace el propio Gemini.

Callbacks (todos opcionales, se llaman desde el hilo de voz -> la GUI debe
reenviar a su hilo con señales Qt):
  on_state(str)      -> "LISTENING" | "THINKING" | "SPEAKING"
  on_user_text(str)  -> transcripción de lo que dijo el usuario
  on_bot_text(str)   -> texto que va hablando SENTINEL (streaming)
  on_level(float)    -> nivel de audio 0..1 (para animar el orbe)
"""
from __future__ import annotations

import asyncio
import threading

LIVE_MODEL = "models/gemini-2.5-flash-native-audio-preview-12-2025"
SEND_RATE = 16000
RECV_RATE = 24000
CHANNELS = 1
CHUNK = 256        # ~16ms mic
PLAY_CHUNK = 480   # ~20ms playback

_PERSONA = (
    "Eres SENTINEL, un guardián de ciberseguridad creado por ELVIS SYSTEMS "
    "Industrias. Hablás en español, natural, directo y con confianza, tuteando "
    "al usuario. Tu misión es PROTEGER su PC: explicás riesgos en lenguaje "
    "claro, recomendás qué hacer y respondés dudas de seguridad. Sé conciso y "
    "conversacional (es voz, no texto). No inventes. Eres defensivo: no ayudás "
    "a atacar equipos de terceros. Si te preguntan quién sos: SENTINEL, de "
    "ELVIS SYSTEMS.\n\n"
    "PODÉS ACTUAR, no solo aconsejar: tenés herramientas para cerrar puertos "
    "(close_port), activar el firewall (enable_firewall), aplicar blindajes "
    "(fix_hardening: defender/firewall/uac/rdp/smb1), analizar archivos/URLs "
    "(analyze_target), neutralizar procesos maliciosos o arranques sospechosos "
    "(neutralize_threat) y revisar el estado (security_report/scan_now). Cuando el "
    "usuario te pida hacer algo (ej. 'cerrá el puerto 445', 'activá el "
    "firewall'), USÁ la herramienta correspondiente y confirmá con el resultado "
    "REAL que devuelve (cada acción del sistema pide permiso de administrador). "
    "Si una acción falla o el usuario cancela el permiso, decílo con honestidad."
)


class VoiceAssistant:
    def __init__(self, api_key: str, *, get_context=None, voice_name: str = "Charon",
                 on_state=None, on_user_text=None, on_bot_text=None, on_level=None):
        self.api_key = api_key
        self.get_context = get_context           # callable -> str (hallazgos)
        self.voice_name = voice_name
        self.on_state = on_state or (lambda s: None)
        self.on_user_text = on_user_text or (lambda t: None)
        self.on_bot_text = on_bot_text or (lambda t: None)
        self.on_level = on_level or (lambda v: None)

        self._muted = False
        self._speaking = False    # True mientras SENTINEL habla (mic en pausa = media-dúplex)
        self._stop = False
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._session = None
        self._out_q: asyncio.Queue | None = None
        self._in_q: asyncio.Queue | None = None
        self._turn_done: asyncio.Event | None = None

    # ---- Control desde la GUI ----
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop = False
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop = True

    def set_muted(self, muted: bool) -> None:
        self._muted = bool(muted)

    def toggle_mute(self) -> bool:
        self._muted = not self._muted
        return self._muted

    # ---- Hilo + loop asyncio ----
    def _thread_main(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
        except Exception as e:
            print(f"[SENTINEL voz] hilo terminó: {e}")

    def _build_config(self):
        from google.genai import types
        ctx = ""
        try:
            ctx = self.get_context() if self.get_context else ""
        except Exception:
            ctx = ""
        sys_prompt = _PERSONA + (("\n\nEstado actual del equipo:\n" + ctx) if ctx else "")

        from sentinel.core.agent_tools import TOOL_DECLARATIONS
        kwargs = dict(
            response_modalities=["AUDIO"],
            output_audio_transcription=types.AudioTranscriptionConfig(),
            input_audio_transcription=types.AudioTranscriptionConfig(),
            system_instruction=sys_prompt,
            tools=[{"function_declarations": TOOL_DECLARATIONS}],
        )
        try:
            kwargs["speech_config"] = types.SpeechConfig(
                voice_config=types.VoiceConfig(
                    prebuilt_voice_config=types.PrebuiltVoiceConfig(
                        voice_name=self.voice_name)))
        except Exception:
            pass
        try:
            kwargs["realtime_input_config"] = types.RealtimeInputConfig(
                automatic_activity_detection=types.AutomaticActivityDetection(
                    start_of_speech_sensitivity="START_SENSITIVITY_HIGH",
                    end_of_speech_sensitivity="END_SENSITIVITY_HIGH",
                    prefix_padding_ms=100, silence_duration_ms=400))
        except Exception:
            pass
        try:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        except Exception:
            pass
        return types.LiveConnectConfig(**kwargs)

    async def _run(self) -> None:
        from google import genai
        delay = 1.0
        while not self._stop:
            try:
                client = genai.Client(api_key=self.api_key,
                                      http_options={"api_version": "v1beta"})
                self.on_state("THINKING")
                config = self._build_config()
                async with client.aio.live.connect(model=LIVE_MODEL, config=config) as session:
                    self._session = session
                    self._out_q = asyncio.Queue(maxsize=10)
                    self._in_q = asyncio.Queue()
                    self._turn_done = asyncio.Event()
                    self.on_state("LISTENING")
                    delay = 1.0
                    await asyncio.gather(
                        self._send_loop(),
                        self._mic_loop(),
                        self._recv_loop(),
                        self._play_loop(),
                    )
            except Exception as e:
                if self._stop:
                    break
                print(f"[SENTINEL voz] reconectando tras error: {e}")
                self.on_state("THINKING")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 15.0)

    async def _send_loop(self) -> None:
        while not self._stop:
            msg = await self._out_q.get()
            try:
                await self._session.send_realtime_input(media=msg)
            except Exception:
                raise

    async def _mic_loop(self) -> None:
        import sounddevice as sd
        import numpy as np

        loop = asyncio.get_event_loop()

        def callback(indata, frames, time_info, status):
            # Media-dúplex: NO enviar mic mientras SENTINEL habla (evita que se
            # escuche a sí mismo por el parlante y alucine/se entrecorte).
            if self._stop or self._muted or self._speaking:
                return
            try:
                rms = float(np.sqrt(np.mean(indata.astype(np.float32) ** 2))) / 32768.0
                self.on_level(min(1.0, rms * 18))
            except Exception:
                pass
            data = indata.tobytes()
            def _put():
                try:
                    self._out_q.put_nowait({"data": data, "mime_type": "audio/pcm"})
                except Exception:
                    pass
            loop.call_soon_threadsafe(_put)

        with sd.InputStream(samplerate=SEND_RATE, channels=CHANNELS, dtype="int16",
                            blocksize=CHUNK, callback=callback):
            while not self._stop:
                await asyncio.sleep(0.01)

    async def _handle_tool_call(self, tool_call) -> None:
        from google.genai import types
        from sentinel.core.agent_tools import execute_tool
        responses = []
        for fc in tool_call.function_calls:
            self.on_state("THINKING")
            print(f"[SENTINEL voz] acción: {fc.name} {dict(fc.args or {})}", flush=True)
            result = await asyncio.to_thread(execute_tool, fc.name, dict(fc.args or {}))
            responses.append(types.FunctionResponse(
                name=fc.name, id=getattr(fc, "id", None), response={"result": result}))
        try:
            await self._session.send_tool_response(function_responses=responses)
        except Exception as e:
            print(f"[SENTINEL voz] send_tool_response falló: {e}", flush=True)

    async def _recv_loop(self) -> None:
        in_buf, out_buf, first = [], [], True
        while not self._stop:
            async for response in self._session.receive():
                if response.data:
                    self._speaking = True      # pausa el micrófono
                    self.on_state("SPEAKING")
                    self._in_q.put_nowait(response.data)
                if getattr(response, "tool_call", None):
                    await self._handle_tool_call(response.tool_call)
                sc = getattr(response, "server_content", None)
                if sc:
                    if sc.output_transcription and sc.output_transcription.text:
                        t = sc.output_transcription.text
                        if first:
                            self.on_bot_text("")  # limpia
                            first = False
                        out_buf.append(t)
                        self.on_bot_text("".join(out_buf))
                    if sc.input_transcription and sc.input_transcription.text:
                        in_buf.append(sc.input_transcription.text)
                    if sc.turn_complete:
                        full_in = "".join(in_buf).strip()
                        if full_in:
                            self.on_user_text(full_in)
                        in_buf, out_buf, first = [], [], True
                        if self._turn_done:
                            self._turn_done.set()

    async def _play_loop(self) -> None:
        import sounddevice as sd
        # latency 'high' + buffer = reproducción estable sin cortes ("se traba").
        stream = sd.RawOutputStream(samplerate=RECV_RATE, channels=CHANNELS,
                                    dtype="int16", blocksize=PLAY_CHUNK,
                                    latency="high")
        stream.start()
        jitter: list[bytes] = []
        JITTER = 4   # ~80ms de colchón antes de empezar a sonar
        try:
            while not self._stop:
                try:
                    chunk = await asyncio.wait_for(self._in_q.get(), timeout=0.05)
                    jitter.append(chunk)
                    if len(jitter) >= JITTER:
                        for b in jitter:
                            await asyncio.to_thread(stream.write, b)
                        jitter.clear()
                except asyncio.TimeoutError:
                    # Fin de turno: drenar lo que quede y volver a escuchar.
                    if (self._turn_done and self._turn_done.is_set()
                            and self._in_q.empty()):
                        for b in jitter:
                            await asyncio.to_thread(stream.write, b)
                        jitter.clear()
                        self._turn_done.clear()
                        self._speaking = False     # libera el micrófono
                        self.on_state("LISTENING")
        finally:
            try:
                stream.stop(); stream.close()
            except Exception:
                pass
