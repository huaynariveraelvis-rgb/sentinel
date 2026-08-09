"""voice.py — Voz de respaldo de SENTINEL (alertas y respuestas escritas).

La voz principal en conversacion es la voz EN VIVO de Gemini (voice_live.py,
voz "Charon"). Este modulo es la voz que suena cuando SENTINEL responde a algo
que escribiste o cuando avisa una amenaza. Prioridad:

  1) Gemini TTS  -> misma voz "Charon" que la voz en vivo (necesita clave +
     internet). Asi el chat escrito suena igual de bien que la voz en vivo.
  2) System.Speech (SAPI) -> voz nativa de Windows, offline, sin dependencias.
     Es la de respaldo si Gemini no esta disponible.

Habla en un hilo aparte para no bloquear la GUI y NUNCA lanza: si todo falla,
simplemente calla (mejor mudo que romper el hilo).
"""
from __future__ import annotations

import io
import subprocess
import threading

_TTS_MODEL = "gemini-2.5-flash-preview-tts"
_TTS_VOICE = "Charon"


def _pcm_to_wav(pcm: bytes, rate: int = 24000, channels: int = 1,
                width: int = 2) -> bytes:
    """Envuelve PCM crudo (16-bit LE mono, como lo entrega Gemini TTS) en un
    contenedor WAV en memoria, listo para winsound."""
    import wave
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(width)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def _gemini_key() -> str:
    """Clave de Gemini desde la config (vacia si la IA esta desactivada)."""
    try:
        from sentinel.core.config import load_settings
        ai = load_settings().get("ai", {})
        return ai.get("gemini_api_key", "") if ai.get("enabled") else ""
    except Exception:
        return ""


def _speak_gemini(text: str, api_key: str, voice: str) -> bool:
    """Habla con la voz Charon via Gemini TTS. Devuelve True si sono."""
    try:
        from google import genai
        from google.genai import types
        import winsound

        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=_TTS_MODEL,
            contents=text,
            config=types.GenerateContentConfig(
                response_modalities=["AUDIO"],
                speech_config=types.SpeechConfig(
                    voice_config=types.VoiceConfig(
                        prebuilt_voice_config=types.PrebuiltVoiceConfig(
                            voice_name=voice)))))
        pcm = resp.candidates[0].content.parts[0].inline_data.data
        if not pcm:
            return False
        wav = _pcm_to_wav(pcm)
        # SND_MEMORY: reproduce desde los bytes en memoria. La reproduccion es
        # sincrona por defecto (espera a que termine); estamos en un hilo
        # daemon, asi que no bloquea la GUI.
        winsound.PlaySound(wav, winsound.SND_MEMORY)
        return True
    except Exception:
        return False


def _escape(text: str) -> str:
    # Texto seguro dentro de comillas simples de PowerShell.
    return text.replace("'", "''")


def _speak_sapi(text: str) -> None:
    """Respaldo offline: sintesis nativa de Windows (System.Speech)."""
    safe = _escape(text)
    ps = (
        "Add-Type -AssemblyName System.Speech; "
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
        "$es = $s.GetInstalledVoices() | Where-Object { "
        "$_.VoiceInfo.Culture.Name -like 'es*' } | Select-Object -First 1; "
        "if ($es) { $s.SelectVoice($es.VoiceInfo.Name) }; "
        f"$s.Speak('{safe}')"
    )
    try:
        from sentinel.core.winproc import oculto
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", ps], capture_output=True, timeout=30,
                       **oculto())
    except Exception:
        pass


def speak(text: str, api_key: str | None = None, voice: str = _TTS_VOICE) -> None:
    """Habla `text` de forma asincrona (no bloquea).

    Usa la voz Charon (Gemini TTS) si hay clave e internet; si no, cae a la voz
    de Windows. Pasa `api_key` si ya lo tienes a mano; si no, se lee de la
    config. Nunca lanza una excepcion.
    """
    if not text:
        return

    def _run():
        key = api_key if api_key is not None else _gemini_key()
        if key and _speak_gemini(text, key, voice):
            return
        _speak_sapi(text)

    threading.Thread(target=_run, daemon=True).start()
