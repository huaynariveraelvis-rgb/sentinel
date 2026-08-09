"""hardening.py — Auditoria de endurecimiento (hardening) de Windows.

Comprueba el estado de las defensas del sistema (solo LECTURA) y recomienda
como corregir lo que este flojo. Cada chequeo devuelve un `HardeningCheck`
con estado (ok/warn/fail), explicacion, recomendacion, referencia normativa
(CIS + MITRE ATT&CK) y, cuando aplica, el comando que lo corrige (que
SENTINEL solo ejecuta con permiso explicito y como administrador).

ARQUITECTURA — sonda unica
--------------------------
La version anterior lanzaba un proceso PowerShell por control: con 5 controles
tardaba ~10 s y con 16 habria tardado casi un minuto, inaceptable para una
auditoria que se repite equipo por equipo en un laboratorio.

Ahora se lanza UN SOLO PowerShell que recoge todos los datos crudos y los
devuelve como un unico JSON. La evaluacion (decidir si cada control esta ok,
warn o fail) se hace en Python, que ademas es donde se puede probar sin
depender del sistema operativo.

Cada bloque de la sonda va dentro de su propio try/catch: si un dato no se
puede leer (sin admin, edicion de Windows sin esa caracteristica), ese control
queda como "desconocido" y los demas siguen funcionando.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, asdict

from sentinel.core.catalog import CIS, describe
from sentinel.core.monitor import Finding, Severity


@dataclass
class HardeningCheck:
    key: str
    title: str
    status: str          # "ok" | "warn" | "fail" | "unknown"
    detail: str
    recommendation: str = ""
    fix_command: str = ""   # comando PowerShell que lo corrige (requiere admin)
    attack: str = ""        # tecnica ATT&CK que este control mitiga
    cis: str = ""           # area del CIS Benchmark correspondiente
    reboot: bool = False    # la correccion requiere reiniciar para surtir efecto

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cis"] = self.cis or CIS.get(self.key, "")
        d["attack_info"] = describe(self.attack) if self.attack else None
        return d


# ── Sonda unica ──────────────────────────────────────────────────────────────

_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]

# Recoge TODOS los datos crudos en una sola pasada. Cada bloque es
# independiente: lo que falle simplemente no aparece en el JSON resultante.
_PROBE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}

# --- Defender: proteccion en tiempo real y antiguedad de firmas ---
try {
  $s = Get-MpComputerStatus -ErrorAction Stop
  $r.def_rt  = [bool]$s.RealTimeProtectionEnabled
  $r.def_av  = [bool]$s.AntivirusEnabled
  $r.def_age = [int]$s.AntivirusSignatureAge
} catch {}

# --- Firewall por perfil ---
try {
  $r.fw = @(Get-NetFirewallProfile -ErrorAction Stop |
            ForEach-Object { @{ name = "$($_.Name)"; on = [bool]$_.Enabled } })
} catch {}

# OJO: en PowerShell, [int] sobre una propiedad INEXISTENTE devuelve 0 sin
# error. Eso haria que "no configurado" se reportara como "desactivado" — un
# falso positivo grave. Por eso cada lectura numerica comprueba $null antes de
# convertir: si la propiedad no existe, la clave simplemente no se envia y el
# control queda como "desconocido".

# --- UAC ---
try {
  $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop).EnableLUA
  if ($null -ne $v) { $r.uac = [int]$v }
} catch {}

# --- RDP (1 = conexiones remotas denegadas = seguro) ---
try {
  $v = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
  if ($null -ne $v) { $r.rdp_deny = [int]$v }
} catch {}

# --- SMBv1 servidor (rapido) y driver cliente ---
try { $r.smb1_srv = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
try { $r.smb1_cli = "$((Get-Service mrxsmb10 -ErrorAction Stop).StartType)" } catch {}

# --- Reproduccion automatica de medios extraibles (vector USB) ---
try {
  $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop).NoDriveTypeAutoRun
  if ($null -ne $v) { $r.autorun_m = [int]$v }
} catch {}
try {
  $v = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop).NoDriveTypeAutoRun
  if ($null -ne $v) { $r.autorun_u = [int]$v }
} catch {}

# --- Windows Update: servicio y ultima instalacion correcta ---
try { $r.wu_start = "$((Get-Service wuauserv -ErrorAction Stop).StartType)" } catch {}
try {
  $r.wu_last = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -ErrorAction Stop).LastSuccessTime)"
} catch {}

# --- SmartScreen: clave clasica, directiva moderna y evaluacion web ---
try {
  $r.smartscreen = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction Stop).SmartScreenEnabled)"
} catch {}
try {
  $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction Stop).EnableSmartScreen
  if ($null -ne $v) { $r.smartscreen_pol = [int]$v }
} catch {}
try {
  $v = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -ErrorAction Stop).EnableWebContentEvaluation
  if ($null -ne $v) { $r.smartscreen_web = [int]$v }
} catch {}

# --- Cuenta Invitado: por SID (-501) para no depender del idioma de Windows ---
try {
  $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
  if ($g) { $r.guest_on = [bool]$g.Enabled; $r.guest_name = "$($g.Name)" }
} catch {}

# --- Bloqueo de pantalla ---
try {
  $d = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction Stop
  $r.ss_active = "$($d.ScreenSaveActive)"
  $r.ss_secure = "$($d.ScreenSaverIsSecure)"
  $t = "$($d.ScreenSaveTimeOut)"
  if ($t -match '^\d+$') { $r.ss_timeout = [int]$t }
} catch {}

# --- Politica de ejecucion de PowerShell (equipo) ---
try { $r.ps_policy = "$(Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop)" } catch {}

# --- Carpetas compartidas no administrativas ---
try {
  $r.shares = @(Get-SmbShare -ErrorAction Stop |
                Where-Object { $_.Name -notmatch '\$$' } |
                ForEach-Object { "$($_.Name)" })
} catch {}

# --- BitLocker en la unidad del sistema ---
try {
  $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $r.bl_status = "$($b.ProtectionStatus)"
} catch {}

# --- Proteccion del proceso LSA (anti volcado de credenciales) ---
try {
  $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop).RunAsPPL
  if ($null -ne $v) { $r.lsa_ppl = [int]$v }
} catch {}

# --- Inicio de sesion automatico con contrasena guardada en claro ---
try {
  $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop
  $r.autologon = "$($w.AutoAdminLogon)"
  $r.autologon_pw = [bool]($null -ne $w.DefaultPassword -and "$($w.DefaultPassword)".Length -gt 0)
} catch {}

$r | ConvertTo-Json -Depth 4 -Compress
"""


def probe(timeout: int = 45) -> dict:
    """Ejecuta la sonda unica y devuelve los datos crudos. {} si falla todo."""
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
    return data if isinstance(data, dict) else {}


def _get(d: dict, key: str, default=None):
    """Lee una clave de la sonda tratando '' y None como ausencia de dato."""
    v = d.get(key, default)
    if v is None or v == "":
        return default
    return v


# ── Evaluadores (Python puro: probables y testeables sin Windows) ────────────

def _unknown(key: str, title: str, why: str = "No se pudo leer el estado.",
             attack: str = "") -> HardeningCheck:
    return HardeningCheck(key, title, "unknown", why, attack=attack)


def eval_defender(d: dict) -> HardeningCheck:
    rt, av = _get(d, "def_rt"), _get(d, "def_av")
    if rt is None or av is None:
        return _unknown("defender", "Windows Defender", attack="T1562.001")
    if rt and av:
        return HardeningCheck("defender", "Windows Defender", "ok",
                              "Antivirus y proteccion en tiempo real activos.",
                              attack="T1562.001")
    return HardeningCheck(
        "defender", "Windows Defender", "fail",
        f"Proteccion en tiempo real {'ON' if rt else 'OFF'}, antivirus "
        f"{'ON' if av else 'OFF'}.",
        recommendation="Activa la proteccion en tiempo real de Windows Defender.",
        fix_command="Set-MpPreference -DisableRealtimeMonitoring $false",
        attack="T1562.001")


def eval_defender_signatures(d: dict) -> HardeningCheck:
    age = _get(d, "def_age")
    if age is None:
        return _unknown("defender_sig", "Firmas de antivirus actualizadas",
                        attack="T1562.001")
    age = int(age)
    if age <= 3:
        return HardeningCheck("defender_sig", "Firmas de antivirus actualizadas", "ok",
                              f"Las firmas se actualizaron hace {age} dia(s).",
                              attack="T1562.001")
    if age <= 7:
        return HardeningCheck(
            "defender_sig", "Firmas de antivirus actualizadas", "warn",
            f"Las firmas tienen {age} dias de antiguedad.",
            recommendation="Actualiza las firmas del antivirus.",
            fix_command="Update-MpSignature", attack="T1562.001")
    return HardeningCheck(
        "defender_sig", "Firmas de antivirus actualizadas", "fail",
        f"Las firmas tienen {age} dias sin actualizarse: el antivirus no "
        f"reconoce las amenazas recientes.",
        recommendation="Actualiza las firmas del antivirus.",
        fix_command="Update-MpSignature", attack="T1562.001")


def eval_firewall(d: dict) -> HardeningCheck:
    profiles = _get(d, "fw")
    if not profiles:
        return _unknown("firewall", "Firewall de Windows", attack="T1562.004")
    if isinstance(profiles, dict):
        profiles = [profiles]
    off = [str(p.get("name")) for p in profiles if not p.get("on")]
    if not off:
        return HardeningCheck("firewall", "Firewall de Windows", "ok",
                              "Firewall activo en todos los perfiles.",
                              attack="T1562.004")
    return HardeningCheck(
        "firewall", "Firewall de Windows", "fail",
        f"Firewall DESACTIVADO en: {', '.join(off)}.",
        recommendation="Activa el firewall en todos los perfiles.",
        fix_command="Set-NetFirewallProfile -All -Enabled True",
        attack="T1562.004")


def eval_uac(d: dict) -> HardeningCheck:
    v = _get(d, "uac")
    if v is None:
        return _unknown("uac", "Control de cuentas (UAC)", attack="T1548.002")
    if int(v) == 1:
        return HardeningCheck("uac", "Control de cuentas (UAC)", "ok",
                              "UAC activado: las apps piden permiso para elevar.",
                              attack="T1548.002")
    return HardeningCheck(
        "uac", "Control de cuentas (UAC)", "fail",
        "UAC DESACTIVADO: el malware puede elevar privilegios sin avisar.",
        recommendation="Reactiva UAC (requiere reinicio).",
        fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows"
                     r"\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"),
        attack="T1548.002", reboot=True)


def eval_rdp(d: dict) -> HardeningCheck:
    v = _get(d, "rdp_deny")
    if v is None:
        return _unknown("rdp", "Escritorio remoto (RDP)", attack="T1021.001")
    if int(v) == 1:
        return HardeningCheck("rdp", "Escritorio remoto (RDP)", "ok",
                              "RDP deshabilitado.", attack="T1021.001")
    return HardeningCheck(
        "rdp", "Escritorio remoto (RDP)", "warn",
        "RDP HABILITADO: es una via de ataque comun si esta expuesto.",
        recommendation="Si no usas escritorio remoto, deshabilitalo.",
        fix_command=(r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control"
                     r"\Terminal Server' -Name fDenyTSConnections -Value 1"),
        attack="T1021.001")


def eval_smb1(d: dict) -> HardeningCheck:
    srv = _get(d, "smb1_srv")
    cli = _get(d, "smb1_cli")
    if srv is None and cli is None:
        return _unknown("smb1", "SMBv1 (protocolo obsoleto)", attack="T1021.002")
    cli_on = isinstance(cli, str) and cli.lower() in ("automatic", "manual", "system")
    if srv:
        return HardeningCheck(
            "smb1", "SMBv1 (protocolo obsoleto)", "fail",
            "SMBv1 ACTIVADO en el servidor: protocolo inseguro, es el que "
            "explotaron WannaCry y EternalBlue en 2017 para propagarse solos "
            "entre equipos de una misma red.",
            recommendation="Deshabilita SMBv1.",
            fix_command="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            attack="T1021.002")
    if cli_on:
        return HardeningCheck(
            "smb1", "SMBv1 (protocolo obsoleto)", "warn",
            "El servidor SMBv1 esta apagado, pero el driver cliente sigue "
            "habilitado: el equipo aun puede conectarse por SMBv1.",
            recommendation="Deshabilita tambien el cliente SMBv1.",
            fix_command=("Disable-WindowsOptionalFeature -Online -FeatureName "
                         "SMB1Protocol -NoRestart"),
            attack="T1021.002", reboot=True)
    return HardeningCheck("smb1", "SMBv1 (protocolo obsoleto)", "ok",
                          "SMBv1 deshabilitado (correcto).", attack="T1021.002")


# NoDriveTypeAutoRun es una MASCARA de bits: marca los tipos de unidad en los
# que se DESACTIVA la reproduccion automatica. 0 = no se desactiva en ninguna;
# 255 (0xFF) = en todas. El bit 0x04 corresponde a las unidades extraibles,
# que es el que de verdad importa en un laboratorio escolar (USB).
_AUTORUN_ALL = 255
_AUTORUN_REMOVABLE = 0x04

_AUTORUN_FIX = (r"New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows"
                r"\CurrentVersion\Policies\Explorer' -Force | Out-Null; "
                r"New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows"
                r"\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun "
                r"-Value 255 -PropertyType DWord -Force | Out-Null")


def eval_autorun(d: dict) -> HardeningCheck:
    """Reproduccion automatica: el vector numero uno en un laboratorio escolar."""
    m, u = _get(d, "autorun_m"), _get(d, "autorun_u")
    values = [int(v) for v in (m, u) if v is not None]
    best = max(values) if values else 0

    if best == _AUTORUN_ALL:
        return HardeningCheck("autorun", "Reproduccion automatica de USB", "ok",
                              "Reproduccion automatica desactivada en todas las unidades.",
                              attack="T1091")

    if not best & _AUTORUN_REMOVABLE:
        # El caso grave: las unidades extraibles NO estan cubiertas.
        motivo = ("No hay ninguna directiva que la desactive"
                  if not values else
                  f"La directiva actual (valor {best}) no cubre las unidades extraibles")
        return HardeningCheck(
            "autorun", "Reproduccion automatica de USB", "fail",
            f"{motivo}: un USB infectado puede ejecutarse solo al conectarlo.",
            recommendation="Desactiva la reproduccion automatica en todas las unidades.",
            fix_command=_AUTORUN_FIX, attack="T1091")

    return HardeningCheck(
        "autorun", "Reproduccion automatica de USB", "warn",
        f"Los USB estan cubiertos, pero la directiva (valor {best} de 255) deja "
        f"otros tipos de unidad expuestos.",
        recommendation="Desactivala en todas las unidades (valor 255).",
        fix_command=_AUTORUN_FIX, attack="T1091")


def eval_windows_update(d: dict) -> HardeningCheck:
    start = _get(d, "wu_start")
    last = _get(d, "wu_last")
    if start is None:
        return _unknown("windows_update", "Actualizaciones de Windows",
                        attack="T1211")
    if str(start).lower() == "disabled":
        return HardeningCheck(
            "windows_update", "Actualizaciones de Windows", "fail",
            "El servicio de Windows Update esta DESHABILITADO: el equipo no "
            "recibe parches de seguridad.",
            recommendation="Reactiva el servicio de actualizaciones.",
            fix_command="Set-Service wuauserv -StartupType Manual",
            attack="T1211")
    detail = "El servicio de actualizaciones esta habilitado."
    if last:
        detail += f" Ultima instalacion correcta: {str(last)[:19]}."
    return HardeningCheck("windows_update", "Actualizaciones de Windows", "ok",
                          detail, attack="T1211")


def eval_smartscreen(d: dict) -> HardeningCheck:
    """SmartScreen cambio de ubicacion entre versiones de Windows, asi que se
    consultan tres fuentes: la clave clasica, la directiva moderna y la
    evaluacion de contenido web."""
    v = _get(d, "smartscreen")
    pol = _get(d, "smartscreen_pol")
    web = _get(d, "smartscreen_web")

    if v is None and pol is None:
        if web is not None and int(web) == 1:
            return HardeningCheck(
                "smartscreen", "SmartScreen", "ok",
                "La evaluacion de contenido web esta activa (SmartScreen "
                "gestionado por la Seguridad de Windows).",
                attack="T1204.002")
        return _unknown(
            "smartscreen", "SmartScreen",
            "Sin directiva explicita. Windows 11 lo trae activo por defecto; "
            "confirmalo en Seguridad de Windows, Control de aplicaciones y navegador.",
            attack="T1204.002")

    if pol is not None:
        if int(pol) == 1:
            return HardeningCheck("smartscreen", "SmartScreen", "ok",
                                  "SmartScreen activado por directiva.",
                                  attack="T1204.002")
        return HardeningCheck(
            "smartscreen", "SmartScreen", "fail",
            "SmartScreen DESACTIVADO por directiva: Windows no avisa al "
            "ejecutar archivos descargados de reputacion desconocida.",
            recommendation="Reactiva SmartScreen.",
            fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft"
                         r"\Windows\System' -Name EnableSmartScreen -Value 1"),
            attack="T1204.002")

    val = str(v).strip().lower()
    if val in ("requireadmin", "warn", "prompt", "on"):
        return HardeningCheck("smartscreen", "SmartScreen", "ok",
                              f"SmartScreen activo (modo {v}).", attack="T1204.002")
    return HardeningCheck(
        "smartscreen", "SmartScreen", "fail",
        "SmartScreen DESACTIVADO: Windows no avisa al ejecutar archivos "
        "descargados de reputacion desconocida.",
        recommendation="Reactiva SmartScreen.",
        fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows"
                     r"\CurrentVersion\Explorer' -Name SmartScreenEnabled "
                     r"-Value 'RequireAdmin'"),
        attack="T1204.002")


def eval_guest(d: dict) -> HardeningCheck:
    on = _get(d, "guest_on")
    name = _get(d, "guest_name", "Invitado")
    if on is None:
        return _unknown("guest", "Cuenta de invitado", attack="T1078")
    if not on:
        return HardeningCheck("guest", "Cuenta de invitado", "ok",
                              f"La cuenta '{name}' esta deshabilitada.",
                              attack="T1078")
    return HardeningCheck(
        "guest", "Cuenta de invitado", "fail",
        f"La cuenta '{name}' esta HABILITADA: permite acceso al equipo sin "
        f"credenciales propias y sin dejar rastro de quien fue.",
        recommendation="Deshabilita la cuenta de invitado.",
        fix_command=("Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } "
                     "| Disable-LocalUser"),
        attack="T1078")


def eval_screen_lock(d: dict) -> HardeningCheck:
    active = str(_get(d, "ss_active", "")).strip()
    secure = str(_get(d, "ss_secure", "")).strip()
    timeout = _get(d, "ss_timeout")
    if not active and timeout is None:
        return _unknown("screen_lock", "Bloqueo automatico de pantalla")
    if active == "1" and secure == "1" and timeout and int(timeout) <= 900:
        return HardeningCheck(
            "screen_lock", "Bloqueo automatico de pantalla", "ok",
            f"La sesion se bloquea tras {int(timeout) // 60} minutos de inactividad.")
    problems = []
    if active != "1":
        problems.append("no hay protector de pantalla activo")
    if secure != "1":
        problems.append("no pide contrasena al reanudar")
    if timeout and int(timeout) > 900:
        problems.append(f"el tiempo de espera es de {int(timeout) // 60} minutos")
    return HardeningCheck(
        "screen_lock", "Bloqueo automatico de pantalla", "warn",
        "La sesion queda desatendida sin bloquearse: " + ", ".join(problems) + ".",
        recommendation="Bloquea la sesion tras 10 minutos y exige contrasena al reanudar.",
        fix_command=(r"Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name "
                     r"ScreenSaveActive -Value 1; Set-ItemProperty "
                     r"'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure "
                     r"-Value 1; Set-ItemProperty 'HKCU:\Control Panel\Desktop' "
                     r"-Name ScreenSaveTimeOut -Value 600"))


def eval_ps_policy(d: dict) -> HardeningCheck:
    v = _get(d, "ps_policy")
    if v is None:
        return _unknown("ps_policy", "Politica de ejecucion de PowerShell",
                        attack="T1059.001")
    val = str(v).strip().lower()
    if val in ("unrestricted", "bypass"):
        return HardeningCheck(
            "ps_policy", "Politica de ejecucion de PowerShell", "fail",
            f"La politica es '{v}': cualquier script se ejecuta sin restriccion "
            f"ni advertencia.",
            recommendation="Usa RemoteSigned, que exige firma en los scripts descargados.",
            fix_command="Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force",
            attack="T1059.001")
    if val == "undefined":
        return HardeningCheck(
            "ps_policy", "Politica de ejecucion de PowerShell", "warn",
            "No hay politica definida a nivel de equipo; se aplica el valor por defecto.",
            recommendation="Define RemoteSigned de forma explicita.",
            fix_command="Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force",
            attack="T1059.001")
    return HardeningCheck("ps_policy", "Politica de ejecucion de PowerShell", "ok",
                          f"Politica '{v}': la ejecucion de scripts esta restringida.",
                          attack="T1059.001")


def eval_shares(d: dict) -> HardeningCheck:
    shares = _get(d, "shares")
    if shares is None:
        return _unknown("shares", "Carpetas compartidas", attack="T1021.002")
    if isinstance(shares, str):
        shares = [shares]
    shares = [s for s in shares if s]
    if not shares:
        return HardeningCheck("shares", "Carpetas compartidas", "ok",
                              "No hay carpetas compartidas fuera de las administrativas.",
                              attack="T1021.002")
    return HardeningCheck(
        "shares", "Carpetas compartidas", "warn",
        f"Hay {len(shares)} carpeta(s) compartida(s) en la red: "
        f"{', '.join(shares[:5])}. Verifica que sea intencional y con permisos "
        f"correctos.",
        recommendation="Deja de compartir lo que no se use.",
        attack="T1021.002")


def eval_bitlocker(d: dict) -> HardeningCheck:
    v = _get(d, "bl_status")
    if v is None:
        return _unknown("bitlocker", "Cifrado del disco (BitLocker)",
                        "No disponible en esta edicion de Windows o sin permisos.")
    val = str(v).strip().lower()
    if val in ("on", "1"):
        return HardeningCheck("bitlocker", "Cifrado del disco (BitLocker)", "ok",
                              "La unidad del sistema esta cifrada.")
    return HardeningCheck(
        "bitlocker", "Cifrado del disco (BitLocker)", "warn",
        "La unidad del sistema NO esta cifrada: si roban el equipo, los datos "
        "se leen sacando el disco.",
        recommendation="Activa BitLocker si la edicion de Windows lo permite.")


def eval_lsa(d: dict) -> HardeningCheck:
    # RunAsPPL: 1 = activo con bloqueo UEFI, 2 = activo sin bloqueo UEFI.
    # Ambos valores significan que la proteccion ESTA activa.
    v = _get(d, "lsa_ppl")
    if v is None or int(v) not in (1, 2):
        return HardeningCheck(
            "lsa", "Proteccion del proceso LSA", "warn",
            "La proteccion adicional del proceso que guarda las credenciales "
            "esta desactivada: facilita el robo de contrasenas en memoria.",
            recommendation="Activa la proteccion LSA (requiere reinicio).",
            fix_command=(r"New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet"
                         r"\Control\Lsa' -Name RunAsPPL -Value 1 -PropertyType "
                         r"DWord -Force | Out-Null"),
            attack="T1003", reboot=True)
    return HardeningCheck("lsa", "Proteccion del proceso LSA", "ok",
                          "El proceso de credenciales corre protegido.",
                          attack="T1003")


def eval_autologon(d: dict) -> HardeningCheck:
    on = str(_get(d, "autologon", "")).strip()
    pw = _get(d, "autologon_pw")
    if on != "1" and not pw:
        return HardeningCheck("autologon", "Inicio de sesion automatico", "ok",
                              "El equipo pide credenciales al iniciar.",
                              attack="T1552.002")
    if pw:
        return HardeningCheck(
            "autologon", "Inicio de sesion automatico", "fail",
            "El equipo inicia sesion solo y la contrasena esta guardada EN CLARO "
            "en el registro: cualquiera que use el equipo puede leerla.",
            recommendation="Desactiva el inicio automatico y borra la contrasena guardada.",
            fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT"
                         r"\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0; "
                         r"Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT"
                         r"\CurrentVersion\Winlogon' -Name DefaultPassword "
                         r"-ErrorAction SilentlyContinue"),
            attack="T1552.002")
    return HardeningCheck(
        "autologon", "Inicio de sesion automatico", "warn",
        "El equipo inicia sesion automaticamente sin pedir credenciales.",
        recommendation="Desactiva el inicio de sesion automatico.",
        fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT"
                     r"\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0"),
        attack="T1552.002")


# Orden de presentacion: primero lo que mas pesa en un laboratorio escolar.
_EVALUATORS = [
    eval_defender,
    eval_defender_signatures,
    eval_firewall,
    eval_uac,
    eval_autorun,
    eval_smb1,
    eval_rdp,
    eval_guest,
    eval_autologon,
    eval_smartscreen,
    eval_windows_update,
    eval_ps_policy,
    eval_lsa,
    eval_shares,
    eval_screen_lock,
    eval_bitlocker,
]

TOTAL_CHECKS = len(_EVALUATORS)

_STATUS_SEV = {
    "fail": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "unknown": Severity.INFO,
    "ok": Severity.INFO,
}


def evaluate(data: dict) -> list[HardeningCheck]:
    """Evalua todos los controles sobre los datos crudos de la sonda.

    Separado de `probe()` a proposito: se puede probar con datos sinteticos
    sin ejecutar PowerShell ni depender del estado real del equipo.
    """
    checks: list[HardeningCheck] = []
    for fn in _EVALUATORS:
        try:
            checks.append(fn(data or {}))
        except Exception as e:  # un control no debe tumbar la auditoria
            checks.append(HardeningCheck(
                getattr(fn, "__name__", "?").replace("eval_", ""),
                getattr(fn, "__name__", "?"), "unknown",
                f"Error al evaluar: {type(e).__name__}"))
    return checks


def scan_hardening() -> tuple[list[HardeningCheck], list[Finding]]:
    """Corre la auditoria completa. Devuelve (checks, findings) donde findings
    son solo los problemas (fail/warn) para mostrar en el panel de amenazas."""
    checks = evaluate(probe())
    findings: list[Finding] = []
    for c in checks:
        if c.status in ("fail", "warn"):
            findings.append(Finding(
                category="blindaje",
                severity=_STATUS_SEV[c.status],
                title=f"Blindaje: {c.title}",
                detail=c.detail + (f" {c.recommendation}" if c.recommendation else ""),
                evidence={"key": c.key, "status": c.status,
                          "fix_command": c.fix_command,
                          "cis": c.cis or CIS.get(c.key, ""),
                          "reboot": c.reboot},
                attack=c.attack,
            ))
    return checks, findings


def hardening_score(checks: list[HardeningCheck]) -> int:
    """Puntaje 0-100 segun cuantas defensas estan OK (ignora 'unknown')."""
    graded = [c for c in checks if c.status in ("ok", "warn", "fail")]
    if not graded:
        return 100
    pts = sum(1.0 if c.status == "ok" else 0.5 if c.status == "warn" else 0.0
              for c in graded)
    return round(100 * pts / len(graded))
