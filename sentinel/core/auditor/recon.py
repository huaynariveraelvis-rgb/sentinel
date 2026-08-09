"""recon.py — Reconocimiento de red del Auditor (fase 1).

Envuelve nmap, la herramienta estandar de la industria, y convierte su salida
en los mismos `Finding` que ya usa SENTINEL. Asi el hallazgo ofensivo entra por
el mismo panel, la misma base de evidencia y el mismo informe que el defensivo.

Que hace, y nada mas que esto (fase de reconocimiento):
  * Descubre que equipos estan vivos en el alcance.
  * Lista puertos abiertos, servicios y versiones.

Que NO hace: no explota, no prueba credenciales, no deja nada en el objetivo.
Toda operacion pasa antes por el guardian de alcance (`scope.py`): una IP fuera
de la autorizacion detiene el proceso, no lo salta en silencio.

Requiere nmap instalado (viene en Kali). Sin nmap, avisa; no falla a medias.
"""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope, ScopeError

# Servicios cuya sola exposicion ya es una senal: acceso remoto, compartidos y
# bases de datos que no deberian mirar a toda la red. Mapea a MITRE ATT&CK.
_RISKY = {
    "microsoft-ds": ("SMB (445)", Severity.HIGH, "T1021.002"),
    "netbios-ssn":  ("NetBIOS/SMB (139)", Severity.HIGH, "T1021.002"),
    "ms-wbt-server": ("RDP (3389)", Severity.HIGH, "T1021.001"),
    "vnc":          ("VNC (5900)", Severity.HIGH, "T1021.005"),
    "telnet":       ("Telnet (23)", Severity.CRITICAL, "T1021"),
    "ftp":          ("FTP (21)", Severity.MEDIUM, "T1071"),
    "ssh":          ("SSH (22)", Severity.INFO, "T1021.004"),
    "mysql":        ("MySQL (3306)", Severity.HIGH, "T1210"),
    "ms-sql-s":     ("SQL Server (1433)", Severity.HIGH, "T1210"),
    "postgresql":   ("PostgreSQL (5432)", Severity.MEDIUM, "T1210"),
    "rpcbind":      ("RPC (111)", Severity.MEDIUM, "T1135"),
    "smtp":         ("SMTP (25)", Severity.INFO, "T1071"),
}


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(args: list[str], timeout: int) -> str:
    """Ejecuta nmap y devuelve su salida XML. Cadena vacia si algo sale mal."""
    if not nmap_available():
        raise ScopeError("nmap no esta instalado. En Kali: sudo apt install nmap.")
    try:
        proc = subprocess.run(["nmap", *args, "-oX", "-"],
                              capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise ScopeError(f"nmap fallo: {e}.")
    return proc.stdout or ""


def discover_hosts(scope: Scope, timeout: int = 300) -> list[str]:
    """Barrido de descubrimiento (nmap -sn) sobre los rangos autorizados.

    Aun siendo un ping-sweep sin puertos, pasa por el guardian: solo se pasan a
    nmap los rangos del alcance, y el resultado se vuelve a filtrar por si el
    rango contenia una IP excluida.
    """
    scope.assert_can_run("recon")
    xml = _run_nmap(["-sn", *scope.targets], timeout)
    vivos: list[str] = []
    for host in _iter_hosts(xml):
        ip = host["ip"]
        if ip and scope.in_scope(ip):   # excludes ya se respetan aqui
            vivos.append(ip)
    return vivos


def scan_host(scope: Scope, ip: str, timeout: int = 300) -> list[Finding]:
    """Escaneo de puertos y versiones (nmap -sV) de UN equipo autorizado."""
    scope.assert_can_run("recon")
    scope.assert_target(ip)             # barrera dura: fuera de alcance, se corta
    xml = _run_nmap(["-sV", "-T4", ip], timeout)
    return _parse_ports(xml)


def scan_scope(scope: Scope, timeout: int = 300) -> list[Finding]:
    """Reconocimiento completo: descubre y escanea todo lo autorizado."""
    findings: list[Finding] = []
    vivos = discover_hosts(scope, timeout)
    findings.append(Finding(
        category="recon", severity=Severity.INFO,
        title=f"{len(vivos)} equipo(s) vivo(s) en el alcance",
        detail=(f"El barrido de descubrimiento sobre {', '.join(scope.targets)} "
                f"encontro {len(vivos)} equipos respondiendo. Es el inventario "
                f"base del engagement."),
        evidence={"vivos": vivos[:50], "total": len(vivos)},
        attack="T1018",
    ))
    for ip in vivos:
        try:
            findings.extend(scan_host(scope, ip, timeout))
        except ScopeError:
            continue   # una IP que se cuele fuera de alcance se salta, no rompe
    return findings


# ── Parseo del XML de nmap ───────────────────────────────────────────────────

def _iter_hosts(xml: str):
    if not xml.strip():
        return
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        yield {"ip": addr, "node": host}


def _parse_ports(xml: str) -> list[Finding]:
    findings: list[Finding] = []
    for host in _iter_hosts(xml):
        ip = host["ip"]
        ports_el = host["node"].find("ports")
        if ports_el is None:
            continue
        abiertos: list[str] = []
        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            num = port.get("portid", "?")
            svc_el = port.find("service")
            svc = (svc_el.get("name") if svc_el is not None else "") or "desconocido"
            product = (svc_el.get("product") if svc_el is not None else "") or ""
            version = (svc_el.get("version") if svc_el is not None else "") or ""
            banner = " ".join(x for x in (product, version) if x).strip()
            abiertos.append(f"{num}/{svc}" + (f" ({banner})" if banner else ""))

            risky = _RISKY.get(svc)
            if risky:
                nombre, sev, attack = risky
                findings.append(Finding(
                    category="exposicion", severity=sev,
                    title=f"{nombre} expuesto en {ip}",
                    detail=(f"El equipo {ip} expone {nombre} en la red. Es un "
                            f"servicio de riesgo: superficie de acceso remoto o "
                            f"movimiento lateral. Banner: {banner or 'sin version'}."),
                    evidence={"equipo": ip, "puerto": num, "servicio": svc,
                              "version": banner},
                    attack=attack,
                ))
        if abiertos:
            findings.append(Finding(
                category="recon", severity=Severity.INFO,
                title=f"{len(abiertos)} puerto(s) abierto(s) en {ip}",
                detail=f"Servicios expuestos por {ip}, para el inventario del engagement.",
                evidence={"equipo": ip, "puertos": abiertos[:40]},
                attack="T1046",
            ))
    return findings
