"""commands.py — Ejecucion remota de comandos (terminal remota del laboratorio).

Permite al administrador enviar un comando a un equipo del parque desde el
coordinador y recibir de vuelta su salida. Es una capacidad de administracion
remota, equivalente a PsExec, WinRM o un agente RMM.

Se construye como herramienta de administracion LEGITIMA, no como troyano. La
diferencia esta en tres propiedades, no en la funcion:

  1. AUTENTICADA — un comando solo se acepta si viene firmado con el token del
     laboratorio (ver `protocol`). Sin el token, nadie puede encolar nada.
  2. AUDITADA    — cada comando ejecutado se REGISTRA en el equipo (audit_log) y
     su resultado completo queda guardado en el coordinador. No hay ejecucion
     oculta ni silenciosa.
  3. NO ENCUBIERTA — el agente es un servicio conocido y declarado; no se
     esconde, no evade defensas, no desactiva registros.

Uso responsable: es para equipos que administras con autorizacion. La misma
funcion sobre equipos ajenos y sin permiso seria intrusion; el codigo no puede
imponer eso, pero el registro deja constancia de quien ordeno que y cuando.
"""
from __future__ import annotations

import time
import subprocess

from sentinel.core import evidence

# Tope de salida que se guarda/transmite por comando, para no cargar reportes
# gigantes (un `dir` recursivo puede producir megabytes).
_MAX_OUTPUT = 100_000


def _console_encoding() -> str:
    """Codepage con el que decodificar la salida de la consola.

    En Windows, las herramientas clasicas escriben en el codepage OEM (cp850,
    cp437...). Fuera de Windows, UTF-8.
    """
    try:
        import ctypes
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "utf-8"


# ── Lado coordinador: encolar y consultar ────────────────────────────────────

def queue(label: str, command: str, by: str = "admin") -> dict:
    """Encola un comando para que un equipo lo ejecute en su proxima conexion."""
    label = (label or "").strip()[:40]
    command = (command or "").strip()
    if not label:
        return {"ok": False, "error": "falta la etiqueta del equipo."}
    if not command:
        return {"ok": False, "error": "el comando esta vacio."}
    con = evidence._connect()
    try:
        cur = con.execute(
            "INSERT INTO commands (label, command, status, queued_by, queued_ts) "
            "VALUES (?,?,'pendiente',?,?)",
            (label, command[:4000], by[:40], time.time()))
        con.commit()
        return {"ok": True, "id": int(cur.lastrowid),
                "message": f"Comando encolado para {label} (#{cur.lastrowid})."}
    finally:
        con.close()


def pending_for(label: str) -> list[dict]:
    """Comandos pendientes de un equipo: [{id, command}, ...]."""
    con = evidence._connect()
    try:
        rows = con.execute(
            "SELECT id, command FROM commands WHERE label=? AND status='pendiente' "
            "ORDER BY queued_ts", ((label or "").strip()[:40],)).fetchall()
        return [{"id": r["id"], "command": r["command"]} for r in rows]
    finally:
        con.close()


def record_result(cmd_id: int, exit_code: int, stdout: str, stderr: str) -> None:
    """Guarda el resultado que devolvio el agente."""
    con = evidence._connect()
    try:
        con.execute(
            "UPDATE commands SET status='ejecutado', exit_code=?, stdout=?, "
            "stderr=?, done_ts=? WHERE id=? AND status='pendiente'",
            (int(exit_code), (stdout or "")[:_MAX_OUTPUT],
             (stderr or "")[:_MAX_OUTPUT], time.time(), int(cmd_id)))
        con.commit()
    finally:
        con.close()


def history(label: str | None = None, limit: int = 40) -> list[dict]:
    """Historial de comandos, para el panel y la auditoria."""
    con = evidence._connect()
    try:
        if label:
            rows = con.execute(
                "SELECT * FROM commands WHERE label=? ORDER BY queued_ts DESC "
                "LIMIT ?", (label, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM commands ORDER BY queued_ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


# ── Lado agente: ejecutar localmente ─────────────────────────────────────────

def execute_locally(command: str, timeout: int = 60) -> tuple[int, str, str]:
    """Ejecuta un comando EN ESTE equipo y devuelve (codigo, stdout, stderr).

    Deja SIEMPRE constancia en el registro de acciones (audit_log): que se
    ejecuto, cuando y con que resultado. Esa traza es lo que hace auditable la
    herramienta —cada comando remoto queda documentado en el propio equipo.
    """
    command = (command or "").strip()
    if not command:
        return 1, "", "comando vacio"
    try:
        # Se captura en BYTES y se decodifica con el codepage correcto. Las
        # herramientas de consola de Windows (ipconfig, dir...) escriben en el
        # codepage OEM, no en UTF-8: decodificar mal convertia los acentos en
        # basura ("Direcci¢n" por "Dirección").
        proc = subprocess.run(
            command, shell=True, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        enc = _console_encoding()
        code = proc.returncode
        out = (proc.stdout or b"").decode(enc, errors="replace")[:_MAX_OUTPUT]
        err = (proc.stderr or b"").decode(enc, errors="replace")[:_MAX_OUTPUT]
    except subprocess.TimeoutExpired:
        code, out, err = 124, "", f"tiempo agotado tras {timeout}s"
    except OSError as e:
        code, out, err = 1, "", f"no se pudo ejecutar: {e}"

    try:
        from sentinel.core.audit_log import record
        record("comando_remoto", target=command[:200], ok=(code == 0),
               detail=f"exit={code}")
    except Exception:
        pass
    return code, out, err
