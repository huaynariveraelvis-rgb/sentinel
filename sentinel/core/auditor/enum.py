"""enum.py — Enumeracion de servicios (fase 2 del Auditor).

Tras el reconocimiento, se profundiza en cada servicio expuesto usando las
herramientas de Kali del catalogo (`toolkit.py`). Todas son de EVALUACION: leen
y reportan, no modifican el objetivo. Cada una corre solo si esta instalada y
solo contra equipos dentro del alcance.

Cobertura:
  * Web  — whatweb (tecnologias), nikto (fallos del servidor), gobuster (rutas)
  * SMB  — enum4linux-ng / smbmap (usuarios, grupos, shares)
  * TLS  — sslscan (protocolos y cifrados debiles)

Cada hallazgo entra como `Finding`, con su tecnica ATT&CK, al mismo panel e
informe que el resto de SENTINEL.
"""
from __future__ import annotations

import shutil
import subprocess

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope, ScopeError


def _run(tool: str, args: list[str], timeout: int) -> tuple[int, str]:
    """Corre una herramienta de Kali y devuelve (codigo, salida). No lanza:
    una herramienta ausente o que falla no debe tumbar la enumeracion entera."""
    if shutil.which(tool) is None:
        return (-1, f"__NO_INSTALADA__:{tool}")
    try:
        p = subprocess.run([tool, *args], capture_output=True, text=True,
                           timeout=timeout)
        return (p.returncode, (p.stdout or "") + (p.stderr or ""))
    except (subprocess.TimeoutExpired, OSError) as e:
        return (-2, f"__ERROR__:{e}")


def _missing(salida: str) -> bool:
    return salida.startswith("__NO_INSTALADA__") or salida.startswith("__ERROR__")


# ── Web ───────────────────────────────────────────────────────────────────────

def enum_web(scope: Scope, ip: str, port: int = 80, timeout: int = 180) -> list[Finding]:
    scope.assert_can_run("enum")
    scope.assert_target(ip)
    base = f"http://{ip}:{port}"
    findings: list[Finding] = []

    code, out = _run("whatweb", ["--color=never", "-a", "3", base], timeout)
    if not _missing(out) and out.strip():
        findings.append(Finding(
            category="enum", severity=Severity.INFO,
            title=f"Tecnologias web de {ip}:{port}",
            detail="Huella de tecnologias del sitio (servidor, framework, CMS).",
            evidence={"equipo": ip, "puerto": port, "whatweb": out.strip()[:1200]},
            attack="T1592",
        ))

    code, out = _run("nikto", ["-host", base, "-nointeractive", "-maxtime", str(timeout - 10)], timeout)
    if not _missing(out):
        hits = [l for l in out.splitlines() if l.strip().startswith("+")]
        if hits:
            findings.append(Finding(
                category="enum", severity=Severity.MEDIUM,
                title=f"{len(hits)} observacion(es) de Nikto en {ip}:{port}",
                detail=("Nikto reporto configuraciones o rutas de interes en el "
                        "servidor web. Revisar cada una: cabeceras faltantes, "
                        "archivos expuestos, versiones conocidas."),
                evidence={"equipo": ip, "puerto": port, "nikto": hits[:40]},
                attack="T1595",
            ))
    return findings


def bruteforce_dirs(scope: Scope, ip: str, port: int, wordlist: str,
                    timeout: int = 300) -> list[Finding]:
    """Descubrimiento de rutas web con gobuster. Sigue siendo evaluacion:
    consulta rutas, no ataca. Necesita una wordlist (Kali trae varias en
    /usr/share/wordlists)."""
    scope.assert_can_run("enum")
    scope.assert_target(ip)
    code, out = _run("gobuster",
                     ["dir", "-u", f"http://{ip}:{port}", "-w", wordlist,
                      "-q", "--no-color"], timeout)
    if _missing(out):
        return []
    rutas = [l.strip() for l in out.splitlines() if l.strip().startswith("/")]
    if not rutas:
        return []
    return [Finding(
        category="enum", severity=Severity.LOW,
        title=f"{len(rutas)} ruta(s) web descubierta(s) en {ip}:{port}",
        detail="Rutas y archivos accesibles en el servidor web, para el inventario.",
        evidence={"equipo": ip, "puerto": port, "rutas": rutas[:60]},
        attack="T1083",
    )]


# ── SMB / Windows ─────────────────────────────────────────────────────────────

def enum_smb(scope: Scope, ip: str, timeout: int = 200) -> list[Finding]:
    scope.assert_can_run("enum")
    scope.assert_target(ip)
    findings: list[Finding] = []

    tool = "enum4linux-ng" if shutil.which("enum4linux-ng") else "enum4linux"
    code, out = _run(tool, ["-A", ip], timeout)
    if not _missing(out) and out.strip():
        findings.append(Finding(
            category="enum", severity=Severity.MEDIUM,
            title=f"Enumeracion SMB de {ip}",
            detail=("Informacion de Windows/SMB del equipo: usuarios, grupos, "
                    "politica de contrasenas y recursos compartidos. Base para "
                    "evaluar accesos indebidos."),
            evidence={"equipo": ip, "herramienta": tool, "salida": out.strip()[:1500]},
            attack="T1087",
        ))

    code, out = _run("smbmap", ["-H", ip], timeout)
    if not _missing(out):
        shares = [l.strip() for l in out.splitlines()
                  if "READ" in l or "WRITE" in l]
        if shares:
            escribibles = [s for s in shares if "WRITE" in s]
            findings.append(Finding(
                category="exposicion",
                severity=Severity.HIGH if escribibles else Severity.MEDIUM,
                title=f"Recursos compartidos accesibles en {ip}",
                detail=(f"El equipo comparte carpetas por SMB con acceso de "
                        f"lectura{'/ESCRITURA' if escribibles else ''}. Un share "
                        f"abierto es una via directa de exfiltracion o de plantar "
                        f"archivos."),
                evidence={"equipo": ip, "shares": shares[:30],
                          "con_escritura": escribibles[:15]},
                attack="T1135",
            ))
    return findings


# ── TLS ───────────────────────────────────────────────────────────────────────

def enum_tls(scope: Scope, ip: str, port: int = 443, timeout: int = 120) -> list[Finding]:
    scope.assert_can_run("enum")
    scope.assert_target(ip)
    code, out = _run("sslscan", ["--no-colour", f"{ip}:{port}"], timeout)
    if _missing(out) or not out.strip():
        return []
    low = out.lower()
    debiles = []
    for marca in ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "rc4", "md5", "des-cbc", "export"):
        if marca in low and "enabled" in low:
            debiles.append(marca.upper())
    sev = Severity.HIGH if debiles else Severity.INFO
    return [Finding(
        category="cripto", severity=sev,
        title=f"Configuracion TLS de {ip}:{port}" + (" (debil)" if debiles else ""),
        detail=("Protocolos y cifrados que ofrece el servicio TLS. "
                + ("Se detectaron protocolos/cifrados obsoletos que deberian "
                   "deshabilitarse." if debiles else "Sin debilidades evidentes en la muestra.")),
        evidence={"equipo": ip, "puerto": port,
                  "debiles": debiles, "sslscan": out.strip()[:1200]},
        attack="T1040",
    )]
