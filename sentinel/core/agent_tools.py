"""agent_tools.py — Herramientas que SENTINEL puede EJECUTAR por voz/chat.

Convierten a SENTINEL en un agente defensivo: además de aconsejar, hace el
trabajo (cerrar puertos, activar firewall, aplicar blindajes, analizar
archivos). Todo es defensivo y sobre el PROPIO equipo del usuario; los cambios
del sistema se aplican ELEVADOS (UAC), nunca en silencio.

Expone:
  TOOL_DECLARATIONS  -> declaraciones de funciones para Gemini (Live API)
  execute_tool(name, args) -> dict  con el resultado real (honesto)
"""
from __future__ import annotations


# ── Declaraciones para Gemini (function calling) ─────────────────────────────
TOOL_DECLARATIONS = [
    {
        "name": "security_report",
        "description": "Devuelve el estado de seguridad actual del PC: hallazgos "
                       "(procesos, red, arranque), blindaje y puntaje. Úsalo para "
                       "responder qué problemas hay o qué es lo más peligroso.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "close_port",
        "description": "Cierra/bloquea un puerto de red creando una regla de "
                       "firewall entrante que lo bloquea (defensa). Ej: cerrar el "
                       "445 (SMB) o 3389 (RDP). Requiere permiso de administrador.",
        "parameters": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Número de puerto a bloquear."},
                "protocol": {"type": "string", "description": "TCP o UDP (por defecto TCP)."},
            },
            "required": ["port"],
        },
    },
    {
        "name": "enable_firewall",
        "description": "Activa el Firewall de Windows en todos los perfiles. "
                       "Requiere permiso de administrador.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "fix_hardening",
        "description": "Aplica un blindaje del sistema. Claves disponibles: "
                       "'defender' (proteccion en tiempo real), 'defender_sig' "
                       "(actualizar firmas), 'firewall', 'uac', 'autorun' "
                       "(bloquear ejecucion automatica de USB), 'smb1', 'rdp' "
                       "(deshabilitar escritorio remoto), 'guest' (deshabilitar "
                       "cuenta invitado), 'autologon', 'smartscreen', "
                       "'windows_update', 'ps_policy' (politica de PowerShell), "
                       "'lsa' (proteccion de credenciales), 'screen_lock' "
                       "(bloqueo por inactividad). Requiere permiso de administrador.",
        "parameters": {
            "type": "object",
            "properties": {"key": {
                "type": "string",
                "description": ("defender|defender_sig|firewall|uac|autorun|smb1|"
                                "rdp|guest|autologon|smartscreen|windows_update|"
                                "ps_policy|lsa|screen_lock")}},
            "required": ["key"],
        },
    },
    {
        "name": "analyze_target",
        "description": "Analiza si un archivo (ruta), una URL o un hash es "
                       "peligroso. Devuelve veredicto y motivos.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string",
                                      "description": "Ruta de archivo, URL o hash."}},
            "required": ["target"],
        },
    },
    {
        "name": "scan_now",
        "description": "Vuelve a escanear el equipo en este momento y resume el resultado.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "neutralize_threat",
        "description": "Neutraliza una amenaza que NO es un puerto: un proceso "
                       "malicioso (lo termina y pone en cuarentena) o una entrada de "
                       "arranque sospechosa (la elimina). Pasá una descripción de la "
                       "amenaza, ej. 'el proceso svchost sospechoso' o 'el arranque "
                       "WinUpdate'.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string",
                                      "description": "Descripción de la amenaza a neutralizar."}},
            "required": ["target"],
        },
    },
]


def _summary() -> dict:
    # RÁPIDO: solo el barrido de vigilancia (sin hardening, que es lento ~10s)
    # para que la respuesta por voz sea inmediata. El blindaje ya se ve en el panel.
    from sentinel.core.monitor import full_scan
    from sentinel.core.brain import heuristic_summary
    rep = full_scan()
    rep["summary"] = heuristic_summary(rep)
    top = [f"[{f['severity_label']}] {f['title']}" for f in rep["findings"][:6]
           if not (f.get("evidence") or {}).get("blocked")]
    return {
        "resumen": rep["summary"],
        "total_hallazgos": rep["counts"]["total"],
        "principales": top,
    }


def execute_tool(name: str, args: dict) -> dict:
    """Ejecuta una herramienta y devuelve un resultado honesto."""
    args = args or {}
    try:
        if name == "security_report":
            return {"ok": True, **_summary()}

        if name == "scan_now":
            return {"ok": True, **_summary()}

        if name == "close_port":
            from sentinel.core.fixer import apply_fix
            port = int(args.get("port"))
            proto = str(args.get("protocol", "TCP")).upper()
            if proto not in ("TCP", "UDP"):
                proto = "TCP"
            cmd = (f"New-NetFirewallRule -DisplayName 'SENTINEL bloquea {port}/{proto}' "
                   f"-Direction Inbound -LocalPort {port} -Protocol {proto} -Action Block")
            ok, msg = apply_fix(cmd)
            if ok:
                try:
                    from sentinel.core.monitor import invalidate_firewall_cache
                    invalidate_firewall_cache()
                except Exception:
                    pass
                return {"ok": True, "message": (
                    f"Listo: creé una regla de firewall que bloquea el puerto {port}/{proto} "
                    f"entrante. El puerto sigue activo localmente pero ya no es accesible "
                    f"desde la red — el riesgo queda mitigado.")}
            return {"ok": False, "message": msg}

        if name == "enable_firewall":
            from sentinel.core.fixer import apply_fix
            ok, msg = apply_fix("Set-NetFirewallProfile -All -Enabled True")
            return {"ok": ok, "message": "Firewall activado en todos los perfiles." if ok else msg}

        if name == "fix_hardening":
            from sentinel.core.hardening import scan_hardening
            from sentinel.core.fixer import apply_fix
            key = str(args.get("key", "")).lower()
            checks, _ = scan_hardening()
            check = next((c for c in checks if c.key == key), None)
            if not check:
                return {"ok": False, "message": f"No conozco el blindaje '{key}'."}
            if check.status == "ok":
                return {"ok": True, "message": f"{check.title} ya está correcto."}
            if not check.fix_command:
                return {"ok": False, "message": f"No hay corrección automática para {check.title}."}
            ok, msg = apply_fix(check.fix_command)
            return {"ok": ok, "message": (f"{check.title}: corregido." if ok else msg)}

        if name == "analyze_target":
            from sentinel.core.analysis import analyze_target
            r = analyze_target(str(args.get("target", "")))
            return {"ok": r.get("ok", False), "tipo": r.get("type"),
                    "veredicto": r.get("verdict"), "severidad": r.get("severity"),
                    "motivos": r.get("notes", []), "error": r.get("error")}

        if name == "neutralize_threat":
            desc = str(args.get("target", "")).lower()
            from sentinel.core.demo import demo_active, resolve_threat
            if demo_active():
                if any(w in desc for w in ("svchost", "proceso", "crític", "critic", "malware")):
                    resolve_threat("proc_svchost")
                    return {"ok": True, "message": "Proceso malicioso terminado y puesto "
                            "en cuarentena. La amenaza fue neutralizada."}
                if any(w in desc for w in ("arranque", "winupdate", "inicio", "persist")):
                    resolve_threat("autorun_winupdate")
                    return {"ok": True, "message": "Entrada de arranque sospechosa "
                            "eliminada. La persistencia del malware fue cortada."}
                return {"ok": False, "message": "No identifiqué esa amenaza para neutralizar."}
            return {"ok": False, "message": "Neutralización directa de procesos/arranque "
                    "disponible solo en escenarios controlados; usá el panel para revisarlo."}

        return {"ok": False, "message": f"Herramienta desconocida: {name}"}
    except Exception as e:
        return {"ok": False, "message": f"Falló la acción ({type(e).__name__}): {e}"}
