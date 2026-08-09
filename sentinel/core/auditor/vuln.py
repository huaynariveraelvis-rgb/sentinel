"""vuln.py — Deteccion de vulnerabilidades (fase 3 del Auditor).

Cruza lo enumerado contra vulnerabilidades conocidas usando las herramientas de
Kali. Sigue siendo EVALUACION: identifica el fallo y su CVE, no lo explota. Ese
es el limite del Auditor automatico; la explotacion es una fase aparte, manual y
con autorizacion propia.

Cobertura:
  * nmap NSE (categoria 'vuln' y script 'vulners') — CVEs por servicio/version
  * nuclei — deteccion por plantillas de la comunidad
  * searchsploit — correlaciona un servicio con exploits publicos conocidos

Cada CVE entra como `Finding`. La severidad se estima del propio hallazgo, y el
informe la lleva a CVSS cuando la herramienta lo aporta.
"""
from __future__ import annotations

import re
import shutil
import subprocess

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope

_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _run(tool: str, args: list[str], timeout: int) -> str:
    if shutil.which(tool) is None:
        return "__NO_INSTALADA__"
    try:
        p = subprocess.run([tool, *args], capture_output=True, text=True,
                           timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


def scan_vulns_nmap(scope: Scope, ip: str, timeout: int = 600) -> list[Finding]:
    """nmap con scripts de vulnerabilidad. Detecta, no explota."""
    scope.assert_can_run("vuln")
    scope.assert_target(ip)
    out = _run("nmap", ["-sV", "--script", "vuln,vulners", "-T4", ip], timeout)
    if out == "__NO_INSTALADA__" or not out.strip():
        return []
    cves = sorted(set(m.group(0).upper() for m in _CVE.finditer(out)))
    if not cves:
        return []
    # Heuristica de severidad: muchos CVEs o presencia de exploits marcados.
    sev = Severity.CRITICAL if "EXPLOIT" in out.upper() else (
        Severity.HIGH if len(cves) >= 3 else Severity.MEDIUM)
    return [Finding(
        category="vulnerabilidad", severity=sev,
        title=f"{len(cves)} CVE(s) potencial(es) en {ip}",
        detail=("nmap correlaciono los servicios del equipo con vulnerabilidades "
                "conocidas. Cada CVE debe verificarse manualmente antes de darlo "
                "por confirmado; es un indicio, no una explotacion."),
        evidence={"equipo": ip, "cves": cves[:40], "total": len(cves)},
        attack="T1595",
    )]


def scan_vulns_nuclei(scope: Scope, ip: str, port: int = 80,
                      timeout: int = 600) -> list[Finding]:
    """nuclei: deteccion por plantillas contra un servicio web."""
    scope.assert_can_run("vuln")
    scope.assert_target(ip)
    target = f"http://{ip}:{port}"
    out = _run("nuclei", ["-u", target, "-silent", "-nc"], timeout)
    if out == "__NO_INSTALADA__" or not out.strip():
        return []
    hits = [l.strip() for l in out.splitlines() if l.strip()]
    if not hits:
        return []
    sev = Severity.HIGH if any(x in out.lower() for x in ("critical", "high")) else Severity.MEDIUM
    return [Finding(
        category="vulnerabilidad", severity=sev,
        title=f"{len(hits)} deteccion(es) de nuclei en {ip}:{port}",
        detail=("nuclei encontro coincidencias de plantillas de vulnerabilidad "
                "en el servicio web. Revisar la severidad de cada plantilla."),
        evidence={"equipo": ip, "puerto": port, "nuclei": hits[:40]},
        attack="T1595",
    )]


def search_exploits(service: str, version: str, timeout: int = 60) -> list[Finding]:
    """searchsploit: exploits publicos conocidos para un servicio/version.

    No toca ningun objetivo — consulta la base local de Exploit-DB. Por eso no
    necesita alcance: es puramente documental para el informe.
    """
    consulta = " ".join(x for x in (service, version) if x).strip()
    if not consulta:
        return []
    out = _run("searchsploit", ["--color", "never", consulta], timeout)
    if out == "__NO_INSTALADA__" or not out.strip():
        return []
    filas = [l.strip() for l in out.splitlines()
             if "|" in l and "----" not in l and "Exploit Title" not in l]
    if not filas:
        return []
    return [Finding(
        category="vulnerabilidad", severity=Severity.MEDIUM,
        title=f"Exploits publicos para '{consulta}'",
        detail=("Existen exploits publicados para este servicio/version en "
                "Exploit-DB. Su sola existencia sube el riesgo: cualquiera puede "
                "usarlos. Confirmar si la version del objetivo es afectada."),
        evidence={"consulta": consulta, "exploits": filas[:25]},
        attack="T1595",
    )]
