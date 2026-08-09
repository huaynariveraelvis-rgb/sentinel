"""catalog.py — Catalogo normativo de SENTINEL.

Cada regla de deteccion y cada control de blindaje del producto cita aqui su
respaldo tecnico. No es decoracion academica: es lo que permite responder
"por que esta regla existe" con una referencia verificable en vez de una
opinion.

Tres marcos, con roles distintos:

  MITRE ATT&CK  — catalogo de tecnicas REALES usadas por atacantes. Responde
                  "que ataque estoy detectando".
  CIS Benchmarks— guia de configuracion segura de Windows. Responde "por que
                  esta configuracion deberia estar de esta manera".
  NIST CSF      — funciones de un programa de seguridad (Identificar, Proteger,
                  Detectar, Responder, Recuperar). Responde "en que parte del
                  ciclo de defensa encaja esto".

La numeracion exacta de los controles CIS cambia entre versiones del
benchmark, por eso se guarda el AREA del control y no un numero fragil.
"""
from __future__ import annotations

from dataclasses import dataclass


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Technique:
    """Una tecnica del catalogo MITRE ATT&CK."""
    id: str          # T1547.001
    name: str        # nombre en espanol, legible
    tactic: str      # tactica: para que la usa el atacante

    @property
    def url(self) -> str:
        """Ficha oficial de la tecnica (citable en la bibliografia)."""
        base, _, sub = self.id.partition(".")
        if sub:
            return f"https://attack.mitre.org/techniques/{base}/{sub}/"
        return f"https://attack.mitre.org/techniques/{base}/"

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name,
                "tactic": self.tactic, "url": self.url}


ATTACK: dict[str, Technique] = {
    "T1003": Technique(
        "T1003", "Volcado de credenciales del sistema operativo",
        "Acceso a credenciales"),
    "T1021.001": Technique(
        "T1021.001", "Servicios remotos: escritorio remoto (RDP)",
        "Movimiento lateral"),
    "T1021.002": Technique(
        "T1021.002", "Servicios remotos: SMB y recursos administrativos",
        "Movimiento lateral"),
    "T1021.005": Technique(
        "T1021.005", "Servicios remotos: VNC",
        "Movimiento lateral"),
    "T1036.005": Technique(
        "T1036.005", "Suplantacion: nombre o ubicacion legitima",
        "Evasion de defensas"),
    "T1036.007": Technique(
        "T1036.007", "Suplantacion: doble extension de archivo",
        "Evasion de defensas"),
    "T1053.005": Technique(
        "T1053.005", "Ejecucion programada: tareas programadas de Windows",
        "Persistencia"),
    "T1059.001": Technique(
        "T1059.001", "Interprete de comandos: PowerShell",
        "Ejecucion"),
    "T1071": Technique(
        "T1071", "Mando y control sobre protocolo de aplicacion",
        "Mando y control"),
    "T1078": Technique(
        "T1078", "Cuentas validas",
        "Persistencia"),
    "T1091": Technique(
        "T1091", "Replicacion a traves de medios extraibles",
        "Acceso inicial"),
    "T1112": Technique(
        "T1112", "Modificacion del registro de Windows",
        "Evasion de defensas"),
    "T1136": Technique(
        "T1136", "Creacion de cuentas",
        "Persistencia"),
    "T1204.002": Technique(
        "T1204.002", "Ejecucion por el usuario: archivo malicioso",
        "Ejecucion"),
    "T1210": Technique(
        "T1210", "Explotacion de servicios expuestos en red",
        "Movimiento lateral"),
    "T1211": Technique(
        "T1211", "Evasion de defensas por explotacion",
        "Evasion de defensas"),
    "T1543.003": Technique(
        "T1543.003", "Creacion o modificacion de servicios del sistema",
        "Persistencia"),
    "T1546.003": Technique(
        "T1546.003", "Ejecucion disparada por eventos: suscripcion WMI",
        "Persistencia"),
    "T1547.001": Technique(
        "T1547.001", "Arranque automatico: claves Run y carpeta Inicio",
        "Persistencia"),
    "T1548.002": Technique(
        "T1548.002", "Elusion del Control de cuentas de usuario (UAC)",
        "Escalada de privilegios"),
    "T1552.002": Technique(
        "T1552.002", "Credenciales sin proteger en el registro",
        "Acceso a credenciales"),
    "T1562.001": Technique(
        "T1562.001", "Deterioro de defensas: deshabilitar herramientas de seguridad",
        "Evasion de defensas"),
    "T1562.004": Technique(
        "T1562.004", "Deterioro de defensas: modificar el firewall del sistema",
        "Evasion de defensas"),
    "T1566.002": Technique(
        "T1566.002", "Suplantacion de identidad mediante enlace",
        "Acceso inicial"),
}


def technique(tid: str) -> Technique | None:
    """Devuelve la ficha de una tecnica, o None si no esta catalogada."""
    return ATTACK.get(tid)


def describe(tid: str) -> dict | None:
    """Ficha serializable de una tecnica (para el reporte y la interfaz)."""
    t = ATTACK.get(tid)
    return t.to_dict() if t else None


# ── CIS Benchmarks (areas de endurecimiento de Windows) ──────────────────────

CIS: dict[str, str] = {
    "defender":       "Microsoft Defender Antivirus — proteccion en tiempo real",
    "defender_sig":   "Microsoft Defender Antivirus — actualizacion de firmas",
    "firewall":       "Windows Defender Firewall — perfiles de dominio, privado y publico",
    "uac":            "Opciones de seguridad local — Control de cuentas de usuario",
    "rdp":            "Plantillas administrativas — Servicios de Escritorio remoto",
    "smb1":           "Configuracion de red MS — cliente y servidor SMB v1",
    "autorun":        "Plantillas administrativas — Directivas de reproduccion automatica",
    "windows_update": "Plantillas administrativas — Windows Update",
    "smartscreen":    "Plantillas administrativas — Windows Defender SmartScreen",
    "guest":          "Opciones de seguridad local — Estado de la cuenta de invitado",
    "screen_lock":    "Plantillas administrativas — Personalizacion y protector de pantalla",
    "ps_policy":      "Plantillas administrativas — Windows PowerShell",
    "shares":         "Configuracion de red MS — recursos compartidos",
    "bitlocker":      "Plantillas administrativas — Cifrado de unidad BitLocker",
    "lsa":            "Opciones de seguridad local — Proteccion del proceso LSA",
    "autologon":      "Opciones de seguridad local — Inicio de sesion automatico",
}


# ── NIST Cybersecurity Framework ─────────────────────────────────────────────

NIST_IDENTIFY = "Identificar"
NIST_PROTECT = "Proteger"
NIST_DETECT = "Detectar"
NIST_RESPOND = "Responder"

NIST_FUNCTIONS = (NIST_IDENTIFY, NIST_PROTECT, NIST_DETECT, NIST_RESPOND)


# ── Utilidades de reporte ────────────────────────────────────────────────────

def coverage(findings: list) -> dict:
    """Resume que tecnicas ATT&CK aparecen en un conjunto de hallazgos.

    Sirve para el reporte del PIM: permite decir "esta auditoria evidencio
    exposicion a N tecnicas catalogadas" con la lista concreta.
    """
    seen: dict[str, int] = {}
    for f in findings or []:
        tid = (f.get("attack") or "") if isinstance(f, dict) else getattr(f, "attack", "")
        if tid:
            seen[tid] = seen.get(tid, 0) + 1
    out = []
    for tid, n in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])):
        t = ATTACK.get(tid)
        out.append({
            "id": tid,
            "name": t.name if t else tid,
            "tactic": t.tactic if t else "",
            "url": t.url if t else "",
            "hallazgos": n,
        })
    return {"total_tecnicas": len(out), "tecnicas": out}
