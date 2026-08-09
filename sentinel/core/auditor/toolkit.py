"""toolkit.py — Arsenal del Auditor: catalogo de herramientas de Kali.

Es la "base de conocimiento" ofensiva de SENTINEL, el equivalente al catalogo
defensivo pero para el otro lado. Cada entrada declara: que hace la herramienta,
en que fase del engagement se usa, a que tecnica de MITRE ATT&CK corresponde y
si el Auditor la ORQUESTA sola o solo la RECONOCE.

Dos modos, y la diferencia es deliberada:

  * "auto"  — herramientas de EVALUACION (observan y reportan: escaneo,
    enumeracion, deteccion de vulnerabilidades). El Auditor las corre solo,
    siempre dentro del alcance. No modifican el objetivo.

  * "gated" — herramientas INTRUSIVAS (explotacion, ataque de credenciales,
    post-explotacion / C2). El Auditor las conoce, las documenta y guia su uso,
    pero NO las dispara automaticamente: las opera la persona, bajo la
    autorizacion expresa de esa fase. Automatizar el "pwn" a ciegas es lo que
    separa una auditoria de un incidente.

Todo pasa por el guardian de alcance (`scope.py`). El catalogo solo describe;
quien decide si algo puede correr es el alcance firmado.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str          # binario en Kali
    phase: str         # recon | enum | vuln | creds | exploit | postex | wireless | web
    mode: str          # "auto" (evaluacion) | "gated" (intrusiva)
    attack: str        # tecnica MITRE ATT&CK
    desc: str          # que hace, en una linea

    def installed(self) -> bool:
        return shutil.which(self.name) is not None


# ── El arsenal, por fase ──────────────────────────────────────────────────────
# Herramientas estandar de Kali. Se citan tal cual en el informe de la tesis.
ARSENAL: tuple[Tool, ...] = (
    # 1) RECONOCIMIENTO — quien esta vivo y que expone.
    Tool("nmap",        "recon", "auto", "T1046", "Descubrimiento de hosts, puertos, servicios y version"),
    Tool("masscan",     "recon", "auto", "T1046", "Escaneo de puertos masivo y muy rapido"),
    Tool("netdiscover", "recon", "auto", "T1018", "Descubrimiento de hosts por ARP en la red local"),
    Tool("arp-scan",    "recon", "auto", "T1018", "Inventario de equipos vivos por ARP"),
    Tool("fping",       "recon", "auto", "T1018", "Barrido de ping sobre un rango"),
    Tool("dnsrecon",    "recon", "auto", "T1590", "Enumeracion de registros y transferencia de zona DNS"),
    Tool("dnsenum",     "recon", "auto", "T1590", "Enumeracion de DNS y subdominios"),
    Tool("fierce",      "recon", "auto", "T1590", "Reconocimiento de DNS y hosts adyacentes"),
    Tool("theharvester","recon", "auto", "T1589", "OSINT: correos, hosts y subdominios de fuentes publicas"),
    Tool("wafw00f",     "recon", "auto", "T1590", "Deteccion de WAF frente a un sitio web"),

    # 2) ENUMERACION — detalle de cada servicio expuesto.
    Tool("whatweb",     "enum", "auto", "T1592", "Huella de tecnologias de un sitio web"),
    Tool("nikto",       "enum", "auto", "T1595", "Escaneo de vulnerabilidades y errores en servidores web"),
    Tool("gobuster",    "enum", "auto", "T1083", "Fuerza de directorios/archivos y subdominios web"),
    Tool("feroxbuster", "enum", "auto", "T1083", "Descubrimiento recursivo de contenido web"),
    Tool("ffuf",        "enum", "auto", "T1083", "Fuzzing web rapido de rutas y parametros"),
    Tool("dirb",        "enum", "auto", "T1083", "Fuerza de directorios web clasica"),
    Tool("enum4linux-ng","enum","auto", "T1087", "Enumeracion de SMB/Windows: usuarios, grupos, shares"),
    Tool("enum4linux",  "enum", "auto", "T1087", "Enumeracion de SMB/Windows (version clasica)"),
    Tool("smbmap",      "enum", "auto", "T1135", "Lista shares SMB y permisos de acceso"),
    Tool("smbclient",   "enum", "auto", "T1135", "Cliente SMB para inspeccionar recursos compartidos"),
    Tool("nbtscan",     "enum", "auto", "T1018", "Escaneo de nombres NetBIOS en la red"),
    Tool("rpcclient",   "enum", "auto", "T1087", "Consulta RPC/MSRPC para enumerar Windows"),
    Tool("snmp-check",  "enum", "auto", "T1602", "Enumeracion de dispositivos por SNMP"),
    Tool("snmpwalk",    "enum", "auto", "T1602", "Volcado de la MIB SNMP de un dispositivo"),
    Tool("onesixtyone", "enum", "auto", "T1602", "Fuerza de community strings SNMP"),
    Tool("ldapsearch",  "enum", "auto", "T1087", "Consulta LDAP/Directorio Activo"),
    Tool("showmount",   "enum", "auto", "T1135", "Lista exportaciones NFS de un servidor"),
    Tool("wpscan",      "enum", "auto", "T1595", "Auditoria de sitios WordPress"),
    Tool("sslscan",     "enum", "auto", "T1040", "Enumera cifrados y protocolos TLS de un servicio"),
    Tool("sslyze",      "enum", "auto", "T1040", "Analisis a fondo de la configuracion TLS"),
    Tool("testssl.sh",  "enum", "auto", "T1040", "Auditoria completa de TLS/SSL de un host"),

    # 3) VULNERABILIDADES — que fallos conocidos tiene lo enumerado.
    Tool("nuclei",      "vuln", "auto", "T1595", "Deteccion de vulnerabilidades por plantillas (CVE)"),
    Tool("searchsploit","vuln", "auto", "T1595", "Busca exploits publicos para un servicio/version"),
    Tool("legion",      "vuln", "auto", "T1595", "Framework de reconocimiento y escaneo semi-automatico"),
    Tool("gvm-cli",     "vuln", "auto", "T1595", "Cliente de OpenVAS/Greenbone para escaneo de vulnerabilidades"),

    # 4) CREDENCIALES — INTRUSIVA (fase 'creds', solo con autorizacion expresa).
    Tool("hydra",       "creds", "gated", "T1110", "Fuerza bruta de credenciales en servicios de red"),
    Tool("medusa",      "creds", "gated", "T1110", "Fuerza bruta de login paralela"),
    Tool("ncrack",      "creds", "gated", "T1110", "Cracking de autenticacion de red"),
    Tool("crackmapexec","creds", "gated", "T1110", "Validacion de credenciales SMB/AD a escala"),
    Tool("john",        "creds", "gated", "T1110.002", "Cracking offline de hashes de contrasena"),
    Tool("hashcat",     "creds", "gated", "T1110.002", "Cracking de hashes acelerado por GPU"),

    # 5) EXPLOTACION — INTRUSIVA (fase 'exploit'). El Auditor la reconoce; la
    #    ejecuta la persona. No hay auto-explotacion.
    Tool("msfconsole",  "exploit", "gated", "T1203", "Metasploit: framework de explotacion"),
    Tool("sqlmap",      "exploit", "gated", "T1190", "Explotacion automatizada de inyeccion SQL"),
    Tool("commix",      "exploit", "gated", "T1190", "Explotacion de inyeccion de comandos"),

    # 6) POST-EXPLOTACION / C2 — INTRUSIVA (fase 'postex'). Herramientas externas
    #    reconocidas; se despliegan y operan aparte, con su propia autorizacion.
    Tool("evil-winrm",  "postex", "gated", "T1021.006", "Shell remota WinRM tras obtener credenciales"),
    Tool("impacket-psexec", "postex", "gated", "T1021.002", "Ejecucion remota estilo PsExec (suite Impacket)"),
    Tool("sliver",      "postex", "gated", "T1071", "Framework C2 de codigo abierto"),

    # 7) WEB / PROXY — apoyo manual.
    Tool("burpsuite",   "web", "gated", "T1185", "Proxy de interceptacion para pruebas web manuales"),
    Tool("zaproxy",     "web", "auto", "T1595", "Proxy y escaner web de OWASP ZAP"),
)


def by_phase(phase: str) -> list[Tool]:
    return [t for t in ARSENAL if t.phase == phase]


def installed_tools() -> list[Tool]:
    return [t for t in ARSENAL if t.installed()]


def missing_tools(mode: str | None = None) -> list[Tool]:
    """Herramientas del catalogo que NO estan en el sistema (para avisar que
    instalar). Filtra por modo si se pide."""
    out = [t for t in ARSENAL if not t.installed()]
    return [t for t in out if t.mode == mode] if mode else out


def arsenal_status() -> dict:
    """Radiografia del arsenal disponible en este equipo, por fase.

    Sirve al arranque del Auditor: dice con que se cuenta y que falta, sin
    tocar ningun objetivo. Es 100% local.
    """
    fases: dict[str, dict] = {}
    for t in ARSENAL:
        f = fases.setdefault(t.phase, {"total": 0, "instaladas": 0, "detalle": []})
        f["total"] += 1
        ok = t.installed()
        if ok:
            f["instaladas"] += 1
        f["detalle"].append({"tool": t.name, "modo": t.mode,
                             "instalada": ok, "attack": t.attack, "que": t.desc})
    inst = installed_tools()
    return {
        "total": len(ARSENAL),
        "instaladas": len(inst),
        "evaluacion_auto": sum(1 for t in inst if t.mode == "auto"),
        "intrusivas_gated": sum(1 for t in inst if t.mode == "gated"),
        "por_fase": fases,
    }
