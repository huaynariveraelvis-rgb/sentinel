"""voice.py — Alertas habladas de SENTINEL.

Usa la sintesis de voz nativa de Windows (System.Speech, via PowerShell):
no requiere dependencias extra ni internet. Habla en un hilo aparte para no
bloquear nada. Pensado para avisos cortos de amenaza ("Alerta: ...").
"""
from __future__ import annotations

import subprocess
import threading


def _escape(text: str) -> str:
    # Texto seguro dentro de comillas simples de PowerShell.
    return text.replace("'", "''")


def speak(text: str) -> None:
    """Habla `text` de forma asincrona (no bloquea)."""
    if not text:
        return

    def _run():
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
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command", ps], capture_output=True, timeout=30)
        except (subprocess.TimeoutExpired, OSError):
            pass

    threading.Thread(target=_run, daemon=True).start()
