"""targets.py — Deriva el mapa de objetivos (ip -> puertos) del reconocimiento.

Lo comparten el CLI (`attack.py`) y el agente conversacional (`agent.py`): a
partir de los `Finding` de recon arma {ip: [{port, svc, banner}, ...]}, para que
la enumeracion y la deteccion de vulnerabilidades solo sondeen puertos que el
reconocimiento ya encontro abiertos.
"""
from __future__ import annotations

from sentinel.core.monitor import Finding

# Puertos/servicios que disparan cada tipo de enumeracion.
WEB_SVCS = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http"}
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
SMB_SVCS = {"microsoft-ds", "netbios-ssn"}
SMB_PORTS = {445, 139}
TLS_PORTS = {443, 8443}
TLS_SVCS = {"https", "https-alt", "ssl/http"}


def parse_port_str(s: str) -> tuple[int, str, str]:
    """Interpreta '80/http (Apache 2.4)' -> (80, 'http', 'Apache 2.4')."""
    s = (s or "").strip()
    partes = s.split(" ", 1)
    izq = partes[0]
    banner = partes[1].strip().strip("()") if len(partes) > 1 else ""
    if "/" in izq:
        num, svc = izq.split("/", 1)
    else:
        num, svc = izq, ""
    try:
        port = int(num)
    except ValueError:
        port = 0
    return port, svc.lower(), banner


def add_port(lst: list[dict], port, svc: str, banner: str) -> None:
    try:
        p = int(port)
    except (ValueError, TypeError):
        return
    for e in lst:
        if e["port"] == p:
            if banner and not e.get("banner"):
                e["banner"] = banner
            return
    lst.append({"port": p, "svc": (svc or "").lower(), "banner": banner or ""})


def derive_targets(findings: list[Finding]) -> dict[str, list[dict]]:
    """{ip: [{port, svc, banner}, ...]} a partir de los hallazgos de recon."""
    hosts: dict[str, list[dict]] = {}
    for f in findings:
        ev = f.evidence or {}
        ip = ev.get("equipo")
        if not ip:
            continue
        if f.category == "exposicion" and ev.get("puerto"):
            add_port(hosts.setdefault(ip, []), ev.get("puerto"),
                     ev.get("servicio", ""), ev.get("version", ""))
        elif f.category == "recon" and ev.get("puertos"):
            lst = hosts.setdefault(ip, [])
            for s in ev["puertos"]:
                port, svc, banner = parse_port_str(s)
                add_port(lst, port, svc, banner)
    return hosts


def is_web(e: dict) -> bool:
    return e["svc"] in WEB_SVCS or e["port"] in WEB_PORTS


def is_tls(e: dict) -> bool:
    return e["svc"] in TLS_SVCS or e["port"] in TLS_PORTS


def is_smb(e: dict) -> bool:
    return e["svc"] in SMB_SVCS or e["port"] in SMB_PORTS
