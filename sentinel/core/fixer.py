"""fixer.py — Aplica correcciones de blindaje con elevacion (UAC).

Las correcciones de hardening tocan ajustes del sistema, asi que SOLO se
ejecutan cuando el usuario lo pide explicitamente desde la UI, y se lanzan
elevadas (Start-Process -Verb RunAs -> prompt de UAC). SENTINEL nunca
modifica el sistema en silencio.
"""
from __future__ import annotations

import subprocess


def apply_fix(command: str) -> tuple[bool, str]:
    """Ejecuta `command` (PowerShell) como administrador. Devuelve (ok, mensaje).
    Dispara el prompt de UAC; si el usuario lo cancela, devuelve (False, ...)."""
    if not command or not command.strip():
        return False, "No hay comando de correccion para este punto."

    # Lanza una PowerShell elevada que ejecuta el comando y reporta el resultado.
    launcher = (
        "$p = Start-Process powershell -Verb RunAs -Wait -PassThru "
        "-WindowStyle Hidden -ArgumentList "
        f"'-NoProfile','-NonInteractive','-Command',\"{command}\"; "
        "exit $p.ExitCode"
    )
    try:
        from sentinel.core.winproc import oculto
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", launcher],
            capture_output=True, text=True, timeout=120, **oculto())
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"No se pudo ejecutar la correccion: {e}"

    if out.returncode == 0:
        _log(command, True, "Correccion aplicada.")
        return True, "Correccion aplicada. Re-escaneando para confirmar…"
    # 1223 = el usuario cancelo el UAC
    if out.returncode == 1223 or "cancel" in (out.stderr or "").lower():
        _log(command, False, "El usuario cancelo el permiso de administrador.")
        return False, "Cancelaste el permiso de administrador."
    _log(command, False, f"Codigo de salida {out.returncode}.")
    return False, f"La correccion no se completo (codigo {out.returncode})."


def _log(command: str, ok: bool, detail: str) -> None:
    """Deja constancia del cambio aplicado (o del intento fallido)."""
    try:
        from sentinel.core.audit_log import record
        record("correccion_blindaje", target=command[:200], ok=ok, detail=detail)
    except Exception:
        pass
