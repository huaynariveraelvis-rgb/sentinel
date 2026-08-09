"""persistence.py — Superficies de persistencia avanzadas.

`monitor.py` cubre la persistencia clasica (claves Run y carpeta Inicio), que
es la mas comun pero tambien la mas facil de encontrar. Un atacante con algo
de oficio usa mecanismos mas silenciosos, y son los que se auditan aqui:

  * Tareas programadas       (ATT&CK T1053.005)
  * Servicios de Windows     (ATT&CK T1543.003)
  * Suscripciones WMI        (ATT&CK T1546.003)
  * Historial de USB         (ATT&CK T1091)

Ademas se detecta la ruta de servicio SIN COMILLAS con espacios: un fallo de
configuracion clasico que permite escalar privilegios plantando un ejecutable
en la ruta truncada.

Todo es de SOLO LECTURA. Igual que el resto del motor, se usa una sonda unica
de PowerShell para no pagar el coste de arrancar un proceso por consulta.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from sentinel.core.monitor import (
    Finding, Severity, _suspicious_dirs, _is_in_suspicious_dir,
)

_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]

# Publicadores de confianza: sus tareas y servicios no se inventarian uno a uno.
_TRUSTED = ("microsoft", "windows", "intel", "nvidia", "amd", "realtek",
            "google", "mozilla", "adobe", "dell", "hp inc", "lenovo")

_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}

# --- Tareas programadas que NO son de Microsoft y estan activas ---
try {
  $r.tasks = @(Get-ScheduledTask -ErrorAction Stop |
    Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } |
    ForEach-Object {
      $a = @($_.Actions)[0]
      @{ name  = "$($_.TaskName)"
         path  = "$($_.TaskPath)"
         autor = "$($_.Author)"
         exec  = "$($a.Execute)"
         args  = "$($a.Arguments)" }
    })
} catch {}

# --- Servicios que arrancan solos ---
try {
  $r.services = @(Get-CimInstance Win32_Service -ErrorAction Stop |
    Where-Object { $_.StartMode -ne 'Disabled' } |
    ForEach-Object {
      @{ name    = "$($_.Name)"
         display = "$($_.DisplayName)"
         bin     = "$($_.PathName)"
         start   = "$($_.StartMode)"
         account = "$($_.StartName)" }
    })
} catch {}

# --- Suscripciones WMI (persistencia sigilosa) ---
try {
  $r.wmi = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop |
    ForEach-Object { @{ filtro = "$($_.Filter)"; consumidor = "$($_.Consumer)" } })
} catch {}

# --- Historial de dispositivos de almacenamiento USB conectados ---
try {
  $r.usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop |
             ForEach-Object { "$($_.PSChildName)" })
} catch {}

$r | ConvertTo-Json -Depth 4 -Compress
"""


def probe(timeout: int = 60) -> dict:
    """Ejecuta la sonda unica de persistencia. {} si no se puede leer nada."""
    try:
        out = subprocess.run(_PS + [_PROBE], capture_output=True, text=True,
                             timeout=timeout,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (subprocess.TimeoutExpired, OSError):
        return {}
    raw = (out.stdout or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    # PowerShell colapsa las listas de un solo elemento en un objeto suelto.
    for k in ("tasks", "services", "wmi", "usb"):
        v = data.get(k)
        if v is not None and not isinstance(v, list):
            data[k] = [v]
    return data


def _trusted(text: str) -> bool:
    low = (text or "").lower()
    return any(t in low for t in _TRUSTED)


def _exe_from_command(cmd: str) -> str:
    """Extrae la ruta del ejecutable de una linea de comando de servicio."""
    c = (cmd or "").strip()
    if not c:
        return ""
    if c.startswith('"'):
        return c[1:].split('"', 1)[0]
    # Sin comillas: se corta en el primer .exe para no arrastrar los argumentos.
    low = c.lower()
    i = low.find(".exe")
    return c[:i + 4] if i != -1 else c.split(" ")[0]


def _unquoted_with_spaces(cmd: str) -> bool:
    """Ruta de servicio sin comillas y con espacios = escalada de privilegios.

    Windows intenta ejecutar cada prefijo cortado en los espacios, asi que
    'C:\\Program Files\\App\\s.exe' sin comillas intentaria primero
    'C:\\Program.exe'. Quien pueda escribir en C:\\ ejecuta codigo como SYSTEM.
    """
    c = (cmd or "").strip()
    if not c or c.startswith('"'):
        return False
    exe = _exe_from_command(c)
    if not exe.lower().endswith(".exe"):
        return False
    # Solo importa si hay espacios ANTES del ejecutable y la ruta es absoluta.
    return " " in exe and (":" in exe[:3])


# Binarios legitimos de Windows que los atacantes usan para ejecutar codigo sin
# traer un ejecutable propio ("living off the land"). Una tarea programada que
# arranca uno de estos es una senal real; una que arranca su propio .exe casi
# siempre es software normal.
_INTERPRETERS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe",
}


def scan_scheduled_tasks(data: dict) -> list[Finding]:
    """Audita las tareas programadas.

    Criterio de senal frente a ruido: se alerta de lo que tiene forma de
    persistencia (ruta temporal, interprete de comandos) y el resto se resume
    en UN solo hallazgo de inventario. Un panel con veinte avisos de tareas
    legitimas de ASUS o Zoom no lo lee nadie, y esconde el que si importa.
    """
    findings: list[Finding] = []
    susp = _suspicious_dirs()
    inventario: list[str] = []

    for t in data.get("tasks") or []:
        name = t.get("name") or "?"
        exec_ = (t.get("exec") or "").strip().strip('"')
        args = (t.get("args") or "").strip()
        autor = t.get("autor") or ""
        if not exec_:
            continue

        if _is_in_suspicious_dir(exec_, susp) is not None:
            findings.append(Finding(
                category="arranque", severity=Severity.HIGH,
                title=f"Tarea programada sospechosa: {name}",
                detail=(f"La tarea programada '{name}' ejecuta '{exec_}', dentro de "
                        f"una carpeta temporal o de descargas. Las tareas programadas "
                        f"son un mecanismo de persistencia que sobrevive a los "
                        f"reinicios y pasa desapercibido en el administrador de tareas."),
                evidence={"tarea": name, "ruta_tarea": t.get("path", ""),
                          "ejecuta": exec_, "argumentos": args, "autor": autor},
                attack="T1053.005",
            ))
            continue

        if Path(exec_).name.lower() in _INTERPRETERS:
            findings.append(Finding(
                category="arranque", severity=Severity.MEDIUM,
                title=f"Tarea programada que ejecuta un interprete: {name}",
                detail=(f"'{name}' lanza '{Path(exec_).name}' de forma automatica. "
                        f"Ejecutar un interprete de comandos desde una tarea "
                        f"programada es una tecnica habitual para correr codigo "
                        f"sin dejar un ejecutable propio. Revisa que hace."),
                evidence={"tarea": name, "ejecuta": exec_, "argumentos": args,
                          "autor": autor},
                attack="T1053.005",
            ))
            continue

        if not _trusted(autor) and not _trusted(exec_):
            inventario.append(name)

    if inventario:
        findings.append(Finding(
            category="arranque", severity=Severity.INFO,
            title=f"{len(inventario)} tarea(s) programada(s) de terceros",
            detail=("Programas que no son de Microsoft ejecutan tareas de forma "
                    "automatica. Es normal en un equipo con software instalado; "
                    "sirve como inventario para comparar contra la linea base."),
            evidence={"total": len(inventario), "tareas": inventario[:15]},
            attack="T1053.005",
        ))
    return findings


def scan_services(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    susp = _suspicious_dirs()
    for s in data.get("services") or []:
        name = s.get("name") or "?"
        display = s.get("display") or name
        cmd = s.get("bin") or ""
        exe = _exe_from_command(cmd)
        if not exe:
            continue

        hit = _is_in_suspicious_dir(exe, susp)
        if hit is not None:
            findings.append(Finding(
                category="arranque", severity=Severity.CRITICAL,
                title=f"Servicio ejecutandose desde ruta temporal: {display}",
                detail=(f"El servicio '{name}' arranca '{exe}', que esta en una "
                        f"carpeta temporal o de descargas. Un servicio corre con "
                        f"privilegios altos y arranca antes que el usuario: es "
                        f"persistencia de alto impacto."),
                evidence={"servicio": name, "binario": cmd,
                          "inicio": s.get("start", ""), "cuenta": s.get("account", "")},
                attack="T1543.003",
            ))
            continue

        if _unquoted_with_spaces(cmd):
            findings.append(Finding(
                category="arranque", severity=Severity.MEDIUM,
                title=f"Ruta de servicio sin comillas: {display}",
                detail=(f"El servicio '{name}' define su binario como {cmd} sin "
                        f"comillas y con espacios. Windows probaria primero rutas "
                        f"truncadas, asi que quien pueda escribir en esas carpetas "
                        f"podria ejecutar codigo con privilegios del servicio."),
                evidence={"servicio": name, "binario": cmd,
                          "inicio": s.get("start", ""), "cuenta": s.get("account", "")},
                attack="T1543.003",
            ))
    return findings


def scan_wmi(data: dict) -> list[Finding]:
    """Las suscripciones WMI son raras en un equipo normal y muy usadas como
    persistencia sigilosa: no aparecen en msconfig ni en el administrador."""
    findings: list[Finding] = []
    for b in data.get("wmi") or []:
        filtro = str(b.get("filtro", ""))
        consumidor = str(b.get("consumidor", ""))
        findings.append(Finding(
            category="arranque", severity=Severity.HIGH,
            title="Suscripcion WMI activa",
            detail=("Existe una suscripcion WMI que dispara una accion ante un "
                    "evento del sistema. Es un mecanismo legitimo pero poco "
                    "habitual en un equipo de uso normal, y una tecnica de "
                    "persistencia conocida: conviene identificar quien la creo."),
            evidence={"filtro": filtro, "consumidor": consumidor},
            attack="T1546.003",
        ))
    return findings


def scan_usb_history(data: dict) -> list[Finding]:
    """Inventario de memorias USB que han pasado por el equipo.

    En un laboratorio escolar este dato tiene valor propio: cuantifica el
    vector de contagio numero uno con una cifra concreta para el informe.
    """
    devices = data.get("usb") or []
    if not devices:
        return []
    muestra = [d.replace("_", " ")[:60] for d in devices[:5]]
    return [Finding(
        category="arranque", severity=Severity.INFO,
        title=f"Historial de {len(devices)} dispositivo(s) USB de almacenamiento",
        detail=("El equipo registra los dispositivos de almacenamiento USB que "
                "se le han conectado. Cuantos mas equipos y memorias comparten "
                "un ambiente, mayor es la probabilidad de contagio por medios "
                "extraibles."),
        evidence={"total": len(devices), "muestra": muestra},
        attack="T1091",
    )]


def scan_persistence(data: dict | None = None) -> list[Finding]:
    """Auditoria completa de las superficies de persistencia avanzadas."""
    d = data if data is not None else probe()
    findings: list[Finding] = []
    for fn in (scan_scheduled_tasks, scan_services, scan_wmi, scan_usb_history):
        try:
            findings.extend(fn(d))
        except Exception:
            continue  # una superficie que falla no debe tumbar el barrido
    return findings
