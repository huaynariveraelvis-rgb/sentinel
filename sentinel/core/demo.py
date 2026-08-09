"""demo.py — Modo demostración para grabar videos promocionales.

Inyecta amenazas SINTÉTICAS realistas (no toca el sistema) para que el panel
se vea cargado y el orbe en rojo. Es seguro y reversible: se activa creando el
archivo `config/demo.flag` y se apaga borrándolo (se puede togglear en vivo sin
reiniciar la app, porque el barrido lo consulta cada vez).

Las amenazas de PUERTO respetan el firewall real: si en cámara cerrás un puerto
(close_port crea una regla real), en el siguiente barrido ese puerto sintético
pasa a "protegido por firewall" — así la demo de cerrar-y-reflejar funciona.
"""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.core.config import user_config_dir
from sentinel.core.monitor import Finding, Severity, blocked_inbound_ports


# Se resuelven al usarlas: empaquetado, `__file__` cae dentro del bundle de
# solo lectura y activar el modo demo no llegaba a guardar nada.
def _flag() -> Path:
    return user_config_dir() / "demo.flag"


def _resolved_file() -> Path:
    return user_config_dir() / "demo_resolved.json"

# Puertos de riesgo "expuestos" para la demo (puerto -> (servicio, severidad)).
_DEMO_PORTS = {
    3389: ("RDP (escritorio remoto)", Severity.HIGH),
    23: ("Telnet", Severity.HIGH),
    5900: ("VNC (control remoto)", Severity.HIGH),
    1433: ("SQL Server", Severity.MEDIUM),
}


def demo_active() -> bool:
    try:
        return _flag().exists()
    except OSError:
        return False


def set_demo(on: bool) -> None:
    try:
        if on:
            _flag().write_text("demo", encoding="utf-8")
        else:
            if _flag().exists():
                _flag().unlink()
            if _resolved_file().exists():
                _resolved_file().unlink()  # limpia amenazas "resueltas" del demo
    except OSError:
        pass


def _resolved() -> set:
    try:
        if _resolved_file().exists():
            return set(json.loads(_resolved_file().read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return set()


def resolve_threat(key: str) -> None:
    """Marca una amenaza sintética como resuelta (desaparece del panel)."""
    keys = _resolved()
    keys.add(key)
    try:
        _resolved_file().write_text(json.dumps(sorted(keys)), encoding="utf-8")
    except OSError:
        pass


def demo_findings() -> list[Finding]:
    """Amenazas sintéticas para el video (no representan riesgos reales)."""
    out: list[Finding] = []
    blocked = blocked_inbound_ports()
    resolved = _resolved()

    # Puertos de riesgo (respetan el firewall real -> cerrar se refleja).
    for port, (svc, sev) in _DEMO_PORTS.items():
        if port in blocked:
            out.append(Finding(
                category="red", severity=Severity.INFO,
                title=f"Puerto {port} ({svc}) protegido por firewall",
                detail=("Sigue activo localmente, pero el firewall bloquea el acceso "
                        "entrante. Riesgo mitigado."),
                evidence={"port": port, "service": svc, "blocked": True, "demo": True},
            ))
        else:
            out.append(Finding(
                category="red", severity=sev,
                title=f"Puerto de riesgo {port} expuesto ({svc})",
                detail=(f"El puerto {port} ({svc}) está a la escucha en todas las "
                        f"interfaces y accesible desde la red. Vía de entrada típica "
                        f"de ataques; conviene cerrarlo."),
                evidence={"port": port, "service": svc, "demo": True},
            ))

    # Proceso sospechoso (suplantación) — el "wow" crítico.
    if "proc_svchost" not in resolved:
        out.append(Finding(
            category="proceso", severity=Severity.CRITICAL,
            title="'svchost.exe' corriendo fuera de System32",
            detail=("Un proceso con nombre de Windows ('svchost.exe') se ejecuta desde "
                    "C:\\Users\\Public\\Temp — patrón clásico de malware que suplanta "
                    "procesos del sistema."),
            evidence={"pid": 6624, "name": "svchost.exe",
                      "exe": r"C:\Users\Public\Temp\svchost.exe", "demo": True,
                      "demo_id": "proc_svchost"},
        ))

    # Arranque sospechoso.
    if "autorun_winupdate" not in resolved:
        out.append(Finding(
            category="arranque", severity=Severity.HIGH,
            title="Arranque sospechoso: WinUpdate",
            detail=("La entrada 'WinUpdate' (HKCU\\Run) ejecuta desde la carpeta Temp al "
                    "iniciar sesión — persistencia típica de malware."),
            evidence={"name": "WinUpdate",
                      "command": r"C:\Users\Public\Temp\update.exe", "demo": True,
                      "demo_id": "autorun_winupdate"},
        ))

    return out
