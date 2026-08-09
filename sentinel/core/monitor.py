"""monitor.py — Motor de vigilancia en tiempo real de SENTINEL.

Vigila el equipo de forma DEFENSIVA (solo lectura del estado del propio PC):
  - Procesos: detecta binarios corriendo desde rutas sospechosas, nombres de
    procesos del sistema que no estan en System32 (posible suplantacion), y
    procesos sin ruta accesible.
  - Red: conexiones establecidas hacia IPs publicas (con el proceso dueno),
    puertos a la escucha en TODAS las interfaces (0.0.0.0) y puertos de riesgo
    expuestos (RDP/SMB/VNC/Telnet).
  - Arranque (autoruns): claves Run del registro (HKCU/HKLM) y carpetas de
    Inicio, marcando entradas que ejecutan desde rutas sospechosas.

Nada de esto ataca a terceros: es el equivalente a un antivirus/EDR mirando
su propia maquina. Devuelve `Finding`s con severidad para que la Ui y la IA
los expliquen y prioricen.
"""
from __future__ import annotations

import os
import time
import subprocess
import ipaddress
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - psutil es dependencia dura
    psutil = None


class Severity(IntEnum):
    """Niveles de severidad, ordenables (mayor = mas grave)."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "INFO",
            Severity.LOW: "BAJA",
            Severity.MEDIUM: "MEDIA",
            Severity.HIGH: "ALTA",
            Severity.CRITICAL: "CRITICA",
        }[self]


@dataclass
class Finding:
    """Un hallazgo de seguridad detectado por el motor."""
    category: str          # "proceso" | "red" | "arranque" | "blindaje"
    severity: Severity
    title: str             # resumen corto, legible
    detail: str            # explicacion en lenguaje claro
    evidence: dict = field(default_factory=dict)  # datos crudos (pid, ruta, ip...)
    attack: str = ""       # tecnica MITRE ATT&CK que evidencia (ver core.catalog)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        # Adjunta la ficha de la tecnica para que la UI y el reporte puedan
        # mostrar nombre, tactica y enlace sin volver a consultar el catalogo.
        if self.attack:
            try:
                from sentinel.core.catalog import describe
                d["attack_info"] = describe(self.attack)
            except Exception:
                d["attack_info"] = None
        return d


# --- Rutas que NO deberian albergar ejecutables en marcha normalmente ---
def _suspicious_dirs() -> list[Path]:
    # OJO: solo carpetas donde un ejecutable en marcha es genuinamente raro.
    # NO incluir ProgramData ni AppData\Roaming/Local "a secas": muchas apps
    # legitimas (Windows Defender, Spotify, Teams) viven ahi -> falsos positivos.
    env = os.environ
    candidates = [
        env.get("TEMP"),
        env.get("TMP"),
        os.path.join(env.get("LOCALAPPDATA", ""), "Temp"),
        os.path.join(env.get("USERPROFILE", ""), "Downloads"),
        os.path.join(env.get("PUBLIC", "")),
        r"C:\Windows\Temp",
    ]
    out = []
    for c in candidates:
        if c:
            try:
                out.append(Path(c).resolve())
            except (OSError, ValueError):
                pass
    return out


# Procesos del sistema que SIEMPRE viven en System32/SysWOW64. Si aparecen
# fuera de ahi, es una bandera roja clasica de malware suplantando nombres.
_SYSTEM_PROCESSES = {
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
    "winlogon.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
    "taskhostw.exe", "dwm.exe", "conhost.exe",
}

_SYSTEM_DIRS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
)

# Puertos cuya exposicion a todas las interfaces es de alto riesgo.
# (servicio, severidad, tecnica ATT&CK que habilita su exposicion)
_RISKY_PORTS = {
    23: ("Telnet", Severity.HIGH, "T1210"),
    445: ("SMB (compartir archivos)", Severity.HIGH, "T1021.002"),
    3389: ("RDP (escritorio remoto)", Severity.HIGH, "T1021.001"),
    5900: ("VNC (control remoto)", Severity.HIGH, "T1021.005"),
    135: ("RPC", Severity.MEDIUM, "T1210"),
    139: ("NetBIOS", Severity.MEDIUM, "T1021.002"),
    1433: ("SQL Server", Severity.MEDIUM, "T1210"),
    3306: ("MySQL", Severity.MEDIUM, "T1210"),
}


def _is_in_suspicious_dir(exe_path: str, susp_dirs: list[Path]) -> Path | None:
    try:
        p = Path(exe_path).resolve()
    except (OSError, ValueError):
        return None
    for d in susp_dirs:
        try:
            if p == d or d in p.parents:
                return d
        except (OSError, ValueError):
            continue
    return None


# Caché de puertos bloqueados por firewall (la consulta PowerShell es lenta).
_blocked_cache: dict = {"ports": set(), "ts": 0.0}
_BLOCKED_TTL = 20.0


def invalidate_firewall_cache() -> None:
    """Fuerza releer el firewall en el próximo barrido (tras cerrar un puerto)."""
    _blocked_cache["ts"] = 0.0


def blocked_inbound_ports() -> set:
    """Puertos con regla de firewall ENTRANTE de BLOQUEO activa = mitigados.
    Cacheado para no pegarle a PowerShell en cada barrido."""
    now = time.monotonic()
    if _blocked_cache["ts"] and (now - _blocked_cache["ts"]) < _BLOCKED_TTL:
        return _blocked_cache["ports"]
    ps = ("Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True "
          "-ErrorAction SilentlyContinue | ForEach-Object { "
          "($_ | Get-NetFirewallPortFilter).LocalPort }")
    ports: set = set()
    try:
        from sentinel.core.winproc import oculto
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=10, **oculto())
        for line in (out.stdout or "").splitlines():
            s = line.strip()
            if s.isdigit():
                ports.add(int(s))
    except (subprocess.TimeoutExpired, OSError):
        pass
    _blocked_cache["ports"] = ports
    _blocked_cache["ts"] = now
    return ports


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # si no parsea, no lo tratamos como remoto publico
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def scan_processes() -> list[Finding]:
    """Revisa todos los procesos en marcha y devuelve hallazgos."""
    findings: list[Finding] = []
    if psutil is None:
        return findings
    susp_dirs = _suspicious_dirs()

    for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            info = proc.info
            name = (info.get("name") or "").strip()
            exe = info.get("exe") or ""
            pid = info.get("pid")
            if not name:
                continue

            # 1) Proceso del sistema corriendo desde una ruta no-sistema
            if name.lower() in _SYSTEM_PROCESSES and exe:
                low = exe.lower()
                if not any(low.startswith(d) for d in _SYSTEM_DIRS):
                    findings.append(Finding(
                        category="proceso",
                        severity=Severity.CRITICAL,
                        title=f"'{name}' corriendo fuera de System32",
                        detail=(f"El proceso del sistema '{name}' deberia ejecutarse "
                                f"desde System32, pero corre desde '{exe}'. Es un patron "
                                f"clasico de malware que suplanta nombres de Windows."),
                        evidence={"pid": pid, "name": name, "exe": exe,
                                  "user": info.get("username")},
                        attack="T1036.005",
                    ))
                    continue

            # 2) Ejecutable corriendo desde carpeta sospechosa (Temp/Downloads/AppData)
            if exe:
                hit = _is_in_suspicious_dir(exe, susp_dirs)
                if hit is not None:
                    findings.append(Finding(
                        category="proceso",
                        severity=Severity.MEDIUM,
                        title=f"'{name}' se ejecuta desde una ruta inusual",
                        detail=(f"'{name}' corre desde '{exe}', dentro de una carpeta "
                                f"temporal/descargas. El software legitimo rara vez se "
                                f"ejecuta desde ahi; vale la pena revisar que es."),
                        evidence={"pid": pid, "name": name, "exe": exe,
                                  "dir": str(hit), "user": info.get("username")},
                        attack="T1204.002",
                    ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return findings


def scan_connections() -> list[Finding]:
    """Revisa conexiones de red TCP y puertos a la escucha."""
    findings: list[Finding] = []
    if psutil is None:
        return findings

    # Mapa pid -> nombre, para etiquetar conexiones con su proceso.
    names: dict[int, str] = {}
    try:
        for p in psutil.process_iter(["pid", "name"]):
            names[p.info["pid"]] = p.info.get("name") or "?"
    except Exception:
        pass

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # Sin admin no se ven todas; devolvemos un aviso informativo.
        return [Finding(
            category="red", severity=Severity.INFO,
            title="Vista de red limitada (sin privilegios)",
            detail=("Para inspeccionar todas las conexiones, SENTINEL necesita "
                    "ejecutarse como administrador."),
            evidence={},
        )]

    # Un mismo puerto suele escuchar en 0.0.0.0 (IPv4) y :: (IPv6): es el mismo
    # riesgo, no dos. Deduplicamos por (puerto, proceso).
    seen_listen: set[tuple] = set()
    blocked = blocked_inbound_ports()   # puertos ya protegidos por firewall

    for c in conns:
        try:
            proc_name = names.get(c.pid, "?") if c.pid else "sistema"

            # 1) Puertos a la escucha en TODAS las interfaces (0.0.0.0 / ::)
            if c.status == psutil.CONN_LISTEN and c.laddr:
                lip, lport = c.laddr.ip, c.laddr.port
                if lip in ("0.0.0.0", "::"):
                    key = (lport, proc_name)
                    if key in seen_listen:
                        continue
                    seen_listen.add(key)
                    is_blocked = lport in blocked
                    if lport in _RISKY_PORTS:
                        svc, sev, tech = _RISKY_PORTS[lport]
                        if is_blocked:
                            findings.append(Finding(
                                category="red", severity=Severity.INFO,
                                title=f"Puerto {lport} ({svc}) protegido por firewall",
                                detail=(f"El puerto {lport} ({svc}) sigue a la escucha "
                                        f"localmente, pero una regla de firewall BLOQUEA el "
                                        f"acceso entrante desde la red. Riesgo mitigado."),
                                evidence={"pid": c.pid, "proc": proc_name, "port": lport,
                                          "service": svc, "ip": lip, "blocked": True},
                            ))
                        else:
                            findings.append(Finding(
                                category="red", severity=sev,
                                title=f"Puerto de riesgo {lport} expuesto ({svc})",
                                detail=(f"El puerto {lport} ({svc}) esta a la escucha en TODAS "
                                        f"las interfaces ({lip}), abierto por '{proc_name}'. "
                                        f"Si no lo usas, es una via de entrada que conviene cerrar."),
                                evidence={"pid": c.pid, "proc": proc_name,
                                          "port": lport, "service": svc, "ip": lip},
                                attack=tech,
                            ))
                    elif is_blocked:
                        findings.append(Finding(
                            category="red", severity=Severity.INFO,
                            title=f"Puerto {lport} protegido por firewall",
                            detail=(f"'{proc_name}' escucha en {lport}, pero el firewall "
                                    f"bloquea el acceso entrante. Riesgo mitigado."),
                            evidence={"pid": c.pid, "proc": proc_name,
                                      "port": lport, "ip": lip, "blocked": True},
                        ))
                    else:
                        findings.append(Finding(
                            category="red", severity=Severity.LOW,
                            title=f"Puerto {lport} a la escucha en todas las interfaces",
                            detail=(f"'{proc_name}' escucha en {lip}:{lport}, accesible desde "
                                    f"la red. Revisa que sea esperado."),
                            evidence={"pid": c.pid, "proc": proc_name,
                                      "port": lport, "ip": lip},
                            attack="T1210",
                        ))

            # 2) Conexiones establecidas hacia IPs publicas
            elif c.status == psutil.CONN_ESTABLISHED and c.raddr:
                rip = c.raddr.ip
                if not _is_private_ip(rip):
                    findings.append(Finding(
                        category="red", severity=Severity.INFO,
                        title=f"Conexion saliente a {rip}:{c.raddr.port}",
                        detail=(f"'{proc_name}' tiene una conexion activa con {rip}:{c.raddr.port}. "
                                f"Normal para navegadores/apps; util para detectar trafico raro."),
                        evidence={"pid": c.pid, "proc": proc_name,
                                  "remote_ip": rip, "remote_port": c.raddr.port},
                        attack="T1071",
                    ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return findings


def scan_autoruns() -> list[Finding]:
    """Revisa entradas de arranque automatico (registro Run + carpeta Inicio)."""
    findings: list[Finding] = []
    susp_dirs = _suspicious_dirs()

    # --- Claves Run del registro ---
    try:
        import winreg
    except ImportError:
        winreg = None

    if winreg is not None:
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
        ]
        for hive, subkey, hive_name in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    cmd = str(value)
                    # extraer la ruta del ejecutable (puede ir entre comillas o con args)
                    exe = cmd.strip('"').split('"')[0] if cmd.startswith('"') else cmd.split(" ")[0]
                    hit = _is_in_suspicious_dir(exe, susp_dirs)
                    sev = Severity.HIGH if hit else Severity.INFO
                    title = (f"Arranque sospechoso: {name}" if hit
                             else f"Programa de arranque: {name}")
                    detail = (f"La entrada '{name}' ({hive_name}\\Run) ejecuta '{cmd}' al iniciar "
                              f"sesion.")
                    if hit:
                        detail += (" Apunta a una carpeta temporal/descargas — patron habitual "
                                   "de persistencia de malware.")
                    findings.append(Finding(
                        category="arranque", severity=sev, title=title, detail=detail,
                        evidence={"name": name, "command": cmd, "hive": hive_name},
                        attack="T1547.001",
                    ))
            finally:
                winreg.CloseKey(key)

    # --- Carpetas de Inicio (.lnk/.exe que arrancan con el usuario) ---
    startup_dirs = [
        os.path.join(os.environ.get("APPDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("PROGRAMDATA", ""),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for sd in startup_dirs:
        if not sd or not os.path.isdir(sd):
            continue
        try:
            entries = os.listdir(sd)
        except OSError:
            continue
        for e in entries:
            if e.lower() in ("desktop.ini",):
                continue
            findings.append(Finding(
                category="arranque", severity=Severity.INFO,
                title=f"Inicio automatico: {e}",
                detail=f"'{e}' esta en la carpeta de Inicio y arranca con el sistema.",
                evidence={"file": e, "dir": sd},
                attack="T1547.001",
            ))
    return findings


def full_scan(extra_findings: list[Finding] | None = None,
              hardening: list | None = None,
              hardening_score: int | None = None) -> dict:
    """Ejecuta los tres barridos de vigilancia y arma el reporte.

    `extra_findings` permite inyectar hallazgos de otros modulos (p. ej. el
    blindaje/hardening) para que aparezcan en el mismo panel. `hardening` y
    `hardening_score` se adjuntan al reporte para la pestana de blindaje.
    """
    procs = scan_processes()
    net = scan_connections()
    auto = scan_autoruns()
    extra = list(extra_findings or [])
    # Modo demo (para videos): amenazas sintéticas si config/demo.flag existe.
    try:
        from sentinel.core.demo import demo_active, demo_findings
        if demo_active():
            extra = extra + demo_findings()
    except Exception:
        pass
    all_findings = procs + net + auto + extra

    by_sev: dict[str, int] = {s.label: 0 for s in Severity}
    for f in all_findings:
        by_sev[f.severity.label] += 1

    # Ordenar por severidad descendente para mostrar lo grave primero.
    all_findings.sort(key=lambda f: f.severity, reverse=True)

    findings_dicts = [f.to_dict() for f in all_findings]

    # Cobertura ATT&CK: que tecnicas catalogadas evidencia esta auditoria.
    try:
        from sentinel.core.catalog import coverage
        attack_coverage = coverage(findings_dicts)
    except Exception:
        attack_coverage = {"total_tecnicas": 0, "tecnicas": []}

    report = {
        "findings": findings_dicts,
        "attack_coverage": attack_coverage,
        "counts": {
            "total": len(all_findings),
            "procesos": len(procs),
            "red": len(net),
            "arranque": len(auto),
            "blindaje": len(extra),
            "por_severidad": by_sev,
        },
        "max_severity": max((f.severity for f in all_findings),
                            default=Severity.INFO).label,
    }
    if hardening is not None:
        report["hardening"] = [c.to_dict() if hasattr(c, "to_dict") else c
                               for c in hardening]
        report["hardening_score"] = hardening_score
    return report
