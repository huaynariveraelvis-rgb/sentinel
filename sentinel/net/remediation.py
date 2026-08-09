"""remediation.py — Remediacion centralizada del laboratorio.

Permite al administrador APROBAR, desde el coordinador, que un equipo aplique
uno de los blindajes conocidos, y que el agente lo aplique en su proxima
conexion. Es el "control" real del laboratorio: no solo ver los problemas, sino
corregirlos desde un solo punto.

PROPIEDAD DE SEGURIDAD (lo que hace esto defendible y no un RAT)
---------------------------------------------------------------
El agente NUNCA recibe un comando. Recibe una CLAVE de una lista blanca fija de
16 blindajes (`ALLOWED`). El agente busca LOCALMENTE el comando real que
corresponde a esa clave —el mismo que ya define `hardening.py`— y lo aplica.

Consecuencia: aunque alguien comprometa el coordinador o falsifique la red, lo
peor que puede lograr es que un equipo se vuelva MAS seguro (activar el firewall,
deshabilitar SMBv1...). No existe forma de que ejecute codigo arbitrario, porque
por el canal solo viaja una clave de un catalogo cerrado, no un comando.

Ademas, cada aplicacion:
  * requiere una APROBACION explicita del administrador (no es automatica);
  * se REGISTRA localmente (audit_log) y se REPORTA de vuelta al coordinador.
No es un cambio "en silencio": es un cambio aprobado y trazado de punta a punta.
"""
from __future__ import annotations

import time

from sentinel.core import evidence

# Lista blanca: las 16 claves de blindaje que el laboratorio puede remediar.
# Es la unica cosa que el agente acepta como "accion". Cualquier otra se rechaza
# antes de tocar el sistema.
ALLOWED: frozenset[str] = frozenset({
    "defender", "defender_sig", "firewall", "uac", "autorun", "smb1", "rdp",
    "guest", "autologon", "smartscreen", "windows_update", "ps_policy",
    "lsa", "shares", "screen_lock", "bitlocker",
})


def is_allowed(key: str) -> bool:
    return key in ALLOWED


# ── Lado coordinador: aprobar y consultar ────────────────────────────────────

def approve(label: str, key: str, by: str = "admin") -> dict:
    """El administrador aprueba que `label` aplique el blindaje `key`."""
    label = (label or "").strip()[:40]
    key = (key or "").strip().lower()
    if not label:
        return {"ok": False, "error": "falta la etiqueta del equipo."}
    if not is_allowed(key):
        return {"ok": False,
                "error": f"'{key}' no esta en la lista blanca de blindajes."}
    con = evidence._connect()
    try:
        # Evita duplicar una aprobacion aun pendiente para el mismo equipo/clave.
        row = con.execute(
            "SELECT id FROM remediations WHERE label=? AND key=? AND status='pendiente'",
            (label, key)).fetchone()
        if row:
            return {"ok": True, "message": f"{key} ya estaba aprobado para {label}.",
                    "id": row["id"]}
        cur = con.execute(
            "INSERT INTO remediations (label, key, status, approved_by, approved_ts) "
            "VALUES (?,?,'pendiente',?,?)", (label, key, by[:40], time.time()))
        con.commit()
        return {"ok": True, "message": f"Aprobado: {label} aplicara '{key}'.",
                "id": int(cur.lastrowid)}
    finally:
        con.close()


def pending_for(label: str) -> list[str]:
    """Claves de blindaje aprobadas y aun no aplicadas para un equipo."""
    con = evidence._connect()
    try:
        rows = con.execute(
            "SELECT key FROM remediations WHERE label=? AND status='pendiente' "
            "ORDER BY approved_ts", ((label or "").strip()[:40],)).fetchall()
        # Solo devuelve claves de la lista blanca (defensa en profundidad: si la
        # base fuera manipulada, igual no se cuela una clave fuera de catalogo).
        return [r["key"] for r in rows if is_allowed(r["key"])]
    finally:
        con.close()


def mark(label: str, key: str, ok: bool, detail: str = "") -> None:
    """Registra el resultado de aplicar un blindaje aprobado."""
    con = evidence._connect()
    try:
        con.execute(
            "UPDATE remediations SET status=?, detail=?, done_ts=? "
            "WHERE label=? AND key=? AND status='pendiente'",
            ("aplicado" if ok else "fallido", detail[:200], time.time(),
             (label or "").strip()[:40], (key or "").strip().lower()))
        con.commit()
    finally:
        con.close()


def history(label: str | None = None, limit: int = 50) -> list[dict]:
    """Historial de remediaciones aprobadas, para el panel y la auditoria."""
    con = evidence._connect()
    try:
        if label:
            rows = con.execute(
                "SELECT * FROM remediations WHERE label=? ORDER BY approved_ts DESC "
                "LIMIT ?", (label, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM remediations ORDER BY approved_ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


# ── Lado agente: aplicar localmente ──────────────────────────────────────────

def apply_locally(key: str) -> tuple[bool, str]:
    """Aplica un blindaje EN ESTE equipo a partir de su clave.

    El comando real NUNCA llega por la red: se resuelve aqui, contra el mismo
    motor de blindaje (`hardening.py`) que usa la auditoria. Esta funcion es la
    frontera de seguridad: rechaza cualquier clave fuera de la lista blanca
    ANTES de tocar el sistema.
    """
    key = (key or "").strip().lower()
    if not is_allowed(key):
        return False, f"clave rechazada (fuera de la lista blanca): {key}"

    from sentinel.core.hardening import scan_hardening
    from sentinel.core.fixer import apply_fix

    checks, _ = scan_hardening()
    check = next((c for c in checks if c.key == key), None)
    if check is None:
        return False, f"no se encontro el control '{key}' en este equipo."
    if check.status == "ok":
        return True, f"{check.title}: ya estaba correcto, nada que aplicar."
    if not check.fix_command:
        return False, f"{check.title}: no tiene correccion automatica."

    ok, msg = apply_fix(check.fix_command)   # apply_fix ya registra en audit_log
    return ok, (f"{check.title}: {'aplicado' if ok else 'no aplicado'} — {msg}")
