"""hardening.py — Auditoria de endurecimiento (hardening) de Windows.

Comprueba el estado de las defensas del sistema (solo LECTURA) y recomienda
como corregir lo que este flojo. Cada chequeo devuelve un `HardeningCheck`
con estado (ok/warn/fail), explicacion, recomendacion y, cuando aplica, el
comando que lo arregla (que SENTINEL solo ejecuta con permiso explicito y
como administrador).

Las consultas se hacen con PowerShell. Si un dato no se puede leer (p. ej.
sin admin), el chequeo se marca como "desconocido" sin romper el barrido.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, asdict

from sentinel.core.monitor import Finding, Severity


@dataclass
class HardeningCheck:
    key: str
    title: str
    status: str          # "ok" | "warn" | "fail" | "unknown"
    detail: str
    recommendation: str = ""
    fix_command: str = ""   # comando PowerShell que lo corrige (requiere admin)

    def to_dict(self) -> dict:
        return asdict(self)


_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


def _ps(cmd: str, timeout: int = 8) -> str | None:
    """Ejecuta un comando PowerShell y devuelve stdout (o None si falla)."""
    try:
        out = subprocess.run(_PS + [cmd], capture_output=True, text=True,
                             timeout=timeout)
        if out.returncode == 0:
            return (out.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def check_defender() -> HardeningCheck:
    raw = _ps("try { (Get-MpComputerStatus | "
              "Select-Object RealTimeProtectionEnabled,AntivirusEnabled | "
              "ConvertTo-Json) } catch { 'ERR' }")
    if not raw or raw == "ERR":
        return HardeningCheck("defender", "Windows Defender", "unknown",
                              "No se pudo leer el estado de Defender.")
    try:
        d = json.loads(raw)
        rt = bool(d.get("RealTimeProtectionEnabled"))
        av = bool(d.get("AntivirusEnabled"))
    except (ValueError, AttributeError):
        return HardeningCheck("defender", "Windows Defender", "unknown",
                              "Respuesta inesperada al consultar Defender.")
    if rt and av:
        return HardeningCheck("defender", "Windows Defender", "ok",
                              "Antivirus y proteccion en tiempo real activos.")
    return HardeningCheck(
        "defender", "Windows Defender", "fail",
        f"Proteccion en tiempo real {'ON' if rt else 'OFF'}, antivirus "
        f"{'ON' if av else 'OFF'}.",
        recommendation="Activa la proteccion en tiempo real de Windows Defender.",
        fix_command="Set-MpPreference -DisableRealtimeMonitoring $false")


def check_firewall() -> HardeningCheck:
    raw = _ps("try { (Get-NetFirewallProfile | "
              "Select-Object Name,Enabled | ConvertTo-Json) } catch { 'ERR' }")
    if not raw or raw == "ERR":
        return HardeningCheck("firewall", "Firewall de Windows", "unknown",
                              "No se pudo leer el estado del firewall.")
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        off = [p.get("Name") for p in data if not p.get("Enabled")]
    except (ValueError, AttributeError):
        return HardeningCheck("firewall", "Firewall de Windows", "unknown",
                              "Respuesta inesperada del firewall.")
    if not off:
        return HardeningCheck("firewall", "Firewall de Windows", "ok",
                              "Firewall activo en todos los perfiles.")
    return HardeningCheck(
        "firewall", "Firewall de Windows", "fail",
        f"Firewall DESACTIVADO en: {', '.join(map(str, off))}.",
        recommendation="Activa el firewall en todos los perfiles.",
        fix_command="Set-NetFirewallProfile -All -Enabled True")


def check_uac() -> HardeningCheck:
    raw = _ps(r"try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows"
              r"\CurrentVersion\Policies\System').EnableLUA } catch { 'ERR' }")
    if raw is None or raw == "ERR" or raw == "":
        return HardeningCheck("uac", "Control de cuentas (UAC)", "unknown",
                              "No se pudo leer el estado de UAC.")
    if raw.strip() == "1":
        return HardeningCheck("uac", "Control de cuentas (UAC)", "ok",
                              "UAC activado: las apps piden permiso para elevar.")
    return HardeningCheck(
        "uac", "Control de cuentas (UAC)", "fail",
        "UAC DESACTIVADO: el malware puede elevar privilegios sin avisar.",
        recommendation="Reactiva UAC (requiere reinicio).",
        fix_command=(r"Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows"
                     r"\CurrentVersion\Policies\System' -Name EnableLUA -Value 1"))


def check_rdp() -> HardeningCheck:
    raw = _ps(r"try { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control"
              r"\Terminal Server').fDenyTSConnections } catch { 'ERR' }")
    if raw is None or raw == "ERR" or raw == "":
        return HardeningCheck("rdp", "Escritorio remoto (RDP)", "unknown",
                              "No se pudo leer el estado de RDP.")
    # fDenyTSConnections = 1 -> RDP deshabilitado (seguro)
    if raw.strip() == "1":
        return HardeningCheck("rdp", "Escritorio remoto (RDP)", "ok",
                              "RDP deshabilitado.")
    return HardeningCheck(
        "rdp", "Escritorio remoto (RDP)", "warn",
        "RDP HABILITADO: es una via de ataque comun si esta expuesto.",
        recommendation="Si no usas escritorio remoto, deshabilitalo.",
        fix_command=(r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control"
                     r"\Terminal Server' -Name fDenyTSConnections -Value 1"))


def check_smb1() -> HardeningCheck:
    raw = _ps("try { (Get-WindowsOptionalFeature -Online -FeatureName "
              "SMB1Protocol).State } catch { 'ERR' }", timeout=20)
    if not raw or raw == "ERR":
        return HardeningCheck("smb1", "SMBv1 (protocolo obsoleto)", "unknown",
                              "No se pudo leer el estado de SMBv1.")
    if "Disabled" in raw:
        return HardeningCheck("smb1", "SMBv1 (protocolo obsoleto)", "ok",
                              "SMBv1 deshabilitado (correcto).")
    if "Enabled" in raw:
        return HardeningCheck(
            "smb1", "SMBv1 (protocolo obsoleto)", "fail",
            "SMBv1 ACTIVADO: protocolo inseguro (lo explotaron WannaCry/EternalBlue).",
            recommendation="Deshabilita SMBv1.",
            fix_command="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart")
    return HardeningCheck("smb1", "SMBv1 (protocolo obsoleto)", "unknown",
                          f"Estado no concluyente: {raw[:60]}")


_CHECKS = [check_defender, check_firewall, check_uac, check_rdp, check_smb1]

_STATUS_SEV = {
    "fail": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "unknown": Severity.INFO,
    "ok": Severity.INFO,
}


def scan_hardening() -> tuple[list[HardeningCheck], list[Finding]]:
    """Corre todos los chequeos. Devuelve (checks, findings) donde findings
    son solo los problemas (fail/warn) para mostrar en el panel de amenazas."""
    checks: list[HardeningCheck] = []
    findings: list[Finding] = []
    for fn in _CHECKS:
        try:
            c = fn()
        except Exception as e:  # un chequeo no debe tumbar el barrido
            c = HardeningCheck(fn.__name__, fn.__name__, "unknown", str(e))
        checks.append(c)
        if c.status in ("fail", "warn"):
            findings.append(Finding(
                category="blindaje",
                severity=_STATUS_SEV[c.status],
                title=f"Blindaje: {c.title}",
                detail=c.detail + (f" {c.recommendation}" if c.recommendation else ""),
                evidence={"key": c.key, "status": c.status,
                          "fix_command": c.fix_command},
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
