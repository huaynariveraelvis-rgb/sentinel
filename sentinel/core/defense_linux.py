"""defense_linux.py — Auditoria de endurecimiento (hardening) de Linux.

Es el gemelo de `hardening.py`, pero para el equipo Linux (Kali/Raspberry). Con
el, la MISMA Raspberry que audita el laboratorio se protege a si misma: los dos
lados, ofensivo y defensivo, sobre el mismo hardware.

Devuelve los mismos `HardeningCheck` que el motor de Windows, asi que entra por
el mismo panel, el mismo informe y el mismo puntaje de blindaje. Solo cambian
las sondas (comandos de Linux en vez de PowerShell) y las correcciones (bash
con sudo en vez de PowerShell elevado).

Principio identico al del resto de SENTINEL: la auditoria es SOLO LECTURA; las
correcciones se muestran como comando y no se ejecutan sin permiso. Lo que
necesita root para leerse y no se puede, queda como "desconocido" — nunca se
reporta un falso "correcto".
"""
from __future__ import annotations

import os
import shutil
import subprocess

from sentinel.core.hardening import HardeningCheck, hardening_score, _STATUS_SEV
from sentinel.core.monitor import Finding, Severity


def is_linux() -> bool:
    return os.name == "posix" and os.uname().sysname.lower() == "linux"


def _sh(cmd: str, timeout: int = 20) -> tuple[int, str]:
    """Corre un comando de shell y devuelve (codigo, salida). Nunca lanza."""
    try:
        p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return (p.returncode, (p.stdout or "") + (p.stderr or ""))
    except (subprocess.TimeoutExpired, OSError):
        return (-1, "")


# ── Sonda: recoge el estado crudo del sistema (solo lectura) ─────────────────

def probe(timeout: int = 30) -> dict:
    """Reune el estado de seguridad del equipo Linux. Cada lectura es
    independiente: la que falle simplemente no aparece.

    Fuera de Linux devuelve {}: `os.geteuid` y los comandos de shell no existen
    en Windows, asi que llamarla ahi por error no debe reventar."""
    if not is_linux():
        return {}
    r: dict = {"is_root": os.geteuid() == 0}

    # SSH: configuracion efectiva (sshd -T) con respaldo al archivo.
    if shutil.which("sshd") or os.path.exists("/etc/ssh/sshd_config"):
        r["ssh_installed"] = True
        _, eff = _sh("sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null")
        low = eff.lower()
        for key, marca in (("ssh_root", "permitrootlogin"),
                           ("ssh_password", "passwordauthentication"),
                           ("ssh_port", "port")):
            for line in low.splitlines():
                line = line.strip()
                if line.startswith(marca):
                    partes = line.split()
                    if len(partes) >= 2:
                        r[key] = partes[1]
                    break

    # Firewall: ufw, luego nftables, luego iptables.
    rc, ufw = _sh("ufw status 2>/dev/null")
    if "status: active" in ufw.lower():
        r["fw"] = "ufw:active"
    elif "status: inactive" in ufw.lower():
        r["fw"] = "ufw:inactive"
    else:
        _, nft = _sh("nft list ruleset 2>/dev/null | head -5")
        if nft.strip():
            r["fw"] = "nftables:rules"
        else:
            _, ipt = _sh("iptables -S 2>/dev/null")
            reglas = [l for l in ipt.splitlines() if l.startswith("-A")]
            r["fw"] = "iptables:rules" if reglas else "none"

    # Actualizaciones pendientes.
    rc, up = _sh("apt-get -s upgrade 2>/dev/null | grep -c '^Inst'")
    if rc == 0 and up.strip().isdigit():
        r["updates"] = int(up.strip())
    rc, sec = _sh("apt-get -s upgrade 2>/dev/null | grep '^Inst' | grep -ci security")
    if rc == 0 and sec.strip().isdigit():
        r["updates_security"] = int(sec.strip())

    # Permisos de /etc/shadow.
    rc, st = _sh("stat -c '%a %U' /etc/shadow 2>/dev/null")
    if st.strip():
        partes = st.split()
        r["shadow_mode"] = partes[0]
        if len(partes) > 1:
            r["shadow_owner"] = partes[1]

    # Cuentas UID 0 (deberia ser solo root).
    _, uid0 = _sh("awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null")
    r["uid0"] = [u for u in uid0.split() if u]

    # Contrasenas vacias (requiere root para leer shadow).
    if r["is_root"]:
        _, empty = _sh("awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null")
        r["empty_pw"] = [u for u in empty.split() if u]

    # Binarios SUID fuera de lo habitual.
    _, suid = _sh("find /usr /bin /sbin /opt /home /tmp /var -xdev -perm -4000 -type f 2>/dev/null",
                  timeout=timeout)
    r["suid"] = [s for s in suid.splitlines() if s.strip()]

    # Directorios del PATH escribibles por todos (secuestro de binarios).
    _, ww = _sh("for d in $(echo $PATH | tr ':' ' '); do "
                "[ -d \"$d\" ] && find \"$d\" -maxdepth 0 -perm -0002 2>/dev/null; done")
    r["ww_path"] = [d for d in ww.splitlines() if d.strip()]

    # Actualizaciones automaticas y proteccion anti-fuerza-bruta.
    _, unatt = _sh("dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'")
    r["unattended"] = unatt.strip() == "1"
    _, f2b = _sh("systemctl is-active fail2ban 2>/dev/null")
    r["fail2ban"] = f2b.strip() == "active"

    # Antivirus / anti-rootkit presentes (paralelo a Defender en Windows).
    r["av"] = [t for t in ("clamscan", "rkhunter", "chkrootkit") if shutil.which(t)]

    return r


def _get(d: dict, key: str, default=None):
    v = d.get(key, default)
    return default if v is None or v == "" else v


def _unknown(key: str, title: str, attack: str = "") -> HardeningCheck:
    return HardeningCheck(key, title, "unknown", "No se pudo leer el estado "
                          "(puede requerir root).", attack=attack)


# ── Evaluadores (Python puro, testeables sin Linux) ──────────────────────────

def eval_ssh_root(d: dict) -> HardeningCheck:
    v = _get(d, "ssh_root")
    if not _get(d, "ssh_installed"):
        return HardeningCheck("lnx_ssh_root", "SSH: acceso de root", "ok",
                              "SSH no esta instalado: sin superficie remota.",
                              attack="T1021.004")
    if v is None:
        return _unknown("lnx_ssh_root", "SSH: acceso de root", "T1021.004")
    if v in ("no", "prohibit-password", "forced-commands-only"):
        return HardeningCheck("lnx_ssh_root", "SSH: acceso de root", "ok",
                              f"Login de root por SSH restringido ({v}).",
                              attack="T1021.004", cis="CIS 5.2 SSH")
    return HardeningCheck(
        "lnx_ssh_root", "SSH: acceso de root", "fail",
        "SSH permite iniciar sesion como root directamente: un atacante que "
        "adivine la contrasena entra con control total.",
        recommendation="Prohibe el login directo de root por SSH.",
        fix_command="sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' "
                    "/etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload ssh",
        attack="T1021.004", cis="CIS 5.2 SSH")


def eval_ssh_password(d: dict) -> HardeningCheck:
    v = _get(d, "ssh_password")
    if not _get(d, "ssh_installed"):
        return HardeningCheck("lnx_ssh_pw", "SSH: autenticacion por contrasena", "ok",
                              "SSH no esta instalado.", attack="T1110")
    if v is None:
        return _unknown("lnx_ssh_pw", "SSH: autenticacion por contrasena", "T1110")
    if v == "no":
        return HardeningCheck("lnx_ssh_pw", "SSH: autenticacion por contrasena", "ok",
                              "SSH solo acepta claves: inmune a fuerza bruta de contrasena.",
                              attack="T1110", cis="CIS 5.2 SSH")
    return HardeningCheck(
        "lnx_ssh_pw", "SSH: autenticacion por contrasena", "warn",
        "SSH acepta contrasenas: queda expuesto a ataques de fuerza bruta.",
        recommendation="Usa claves SSH y desactiva la autenticacion por contrasena.",
        fix_command="sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' "
                    "/etc/ssh/sshd_config && sudo sshd -t && sudo systemctl reload ssh",
        attack="T1110", cis="CIS 5.2 SSH")


def eval_firewall(d: dict) -> HardeningCheck:
    v = _get(d, "fw")
    if v is None:
        return _unknown("lnx_firewall", "Firewall (ufw/nftables)", "T1562.004")
    if v in ("ufw:active", "nftables:rules", "iptables:rules"):
        return HardeningCheck("lnx_firewall", "Firewall (ufw/nftables)", "ok",
                              f"Firewall activo ({v.split(':')[0]}).",
                              attack="T1562.004", cis="CIS 3.5 Firewall")
    return HardeningCheck(
        "lnx_firewall", "Firewall (ufw/nftables)", "fail",
        "No hay firewall activo: todos los servicios quedan expuestos a la red.",
        recommendation="Activa ufw con politica de denegar entrantes por defecto.",
        fix_command="sudo ufw default deny incoming && sudo ufw default allow outgoing "
                    "&& sudo ufw --force enable",
        attack="T1562.004", cis="CIS 3.5 Firewall")


def eval_updates(d: dict) -> HardeningCheck:
    total = _get(d, "updates")
    sec = _get(d, "updates_security")
    if total is None:
        return _unknown("lnx_updates", "Actualizaciones de seguridad", "T1190")
    total, sec = int(total), int(sec or 0)
    if total == 0:
        return HardeningCheck("lnx_updates", "Actualizaciones de seguridad", "ok",
                              "El sistema esta al dia.", attack="T1190",
                              cis="CIS 1.9 Parcheo")
    status = "fail" if sec > 0 else "warn"
    return HardeningCheck(
        "lnx_updates", "Actualizaciones de seguridad", status,
        f"Hay {total} paquete(s) por actualizar" +
        (f", {sec} de seguridad" if sec else "") + ". Cada parche pendiente es una "
        "puerta conocida sin cerrar.",
        recommendation="Aplica las actualizaciones pendientes.",
        fix_command="sudo apt-get update && sudo apt-get -y upgrade",
        attack="T1190", cis="CIS 1.9 Parcheo")


def eval_shadow_perms(d: dict) -> HardeningCheck:
    mode = _get(d, "shadow_mode")
    if mode is None:
        return _unknown("lnx_shadow", "Permisos de /etc/shadow", "T1003.008")
    # Seguro: solo root (600/640, sin permisos para 'otros').
    try:
        otros = int(str(mode)[-1])
    except ValueError:
        return _unknown("lnx_shadow", "Permisos de /etc/shadow", "T1003.008")
    if otros == 0 and int(str(mode)) <= 640:
        return HardeningCheck("lnx_shadow", "Permisos de /etc/shadow", "ok",
                              f"/etc/shadow protegido (modo {mode}).",
                              attack="T1003.008", cis="CIS 6.1 Permisos")
    return HardeningCheck(
        "lnx_shadow", "Permisos de /etc/shadow", "fail",
        f"/etc/shadow tiene permisos {mode}: los hashes de contrasena podrian "
        f"leerse sin ser root, y romperse offline.",
        recommendation="Restringe /etc/shadow a root.",
        fix_command="sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow",
        attack="T1003.008", cis="CIS 6.1 Permisos")


def eval_uid0(d: dict) -> HardeningCheck:
    users = _get(d, "uid0", [])
    if not users:
        return _unknown("lnx_uid0", "Cuentas con UID 0", "T1078")
    extra = [u for u in users if u != "root"]
    if not extra:
        return HardeningCheck("lnx_uid0", "Cuentas con UID 0", "ok",
                              "Solo root tiene UID 0.", attack="T1078",
                              cis="CIS 6.2 Cuentas")
    return HardeningCheck(
        "lnx_uid0", "Cuentas con UID 0", "fail",
        f"Cuentas con privilegios de root ademas de root: {', '.join(extra)}. "
        f"Es una puerta trasera clasica.",
        recommendation="Revisa y elimina las cuentas UID 0 no autorizadas.",
        attack="T1078", cis="CIS 6.2 Cuentas")


def eval_empty_pw(d: dict) -> HardeningCheck:
    if not d.get("is_root"):
        return _unknown("lnx_empty_pw", "Cuentas sin contrasena", "T1078")
    users = _get(d, "empty_pw", [])
    if not users:
        return HardeningCheck("lnx_empty_pw", "Cuentas sin contrasena", "ok",
                              "Ninguna cuenta tiene contrasena vacia.",
                              attack="T1078", cis="CIS 6.2 Cuentas")
    return HardeningCheck(
        "lnx_empty_pw", "Cuentas sin contrasena", "fail",
        f"Cuentas SIN contrasena: {', '.join(users)}. Cualquiera entra sin credenciales.",
        recommendation="Asigna contrasena o bloquea esas cuentas (passwd -l).",
        attack="T1078", cis="CIS 6.2 Cuentas")


def eval_suid(d: dict) -> HardeningCheck:
    suid = _get(d, "suid", [])
    if suid == [] and "suid" not in d:
        return _unknown("lnx_suid", "Binarios SUID", "T1548.001")
    # SUID en rutas de usuario o temporales = muy sospechoso.
    sospechosos = [s for s in suid if s.startswith(("/home", "/tmp", "/var/tmp", "/dev/shm"))]
    if sospechosos:
        return HardeningCheck(
            "lnx_suid", "Binarios SUID", "fail",
            f"Binarios SUID en ubicaciones inusuales: {', '.join(sospechosos[:5])}. "
            f"Un SUID fuera del sistema suele ser una via de escalada de privilegios.",
            recommendation="Revisa cada binario y quita el bit SUID si no corresponde.",
            attack="T1548.001", cis="CIS 6.1 Permisos")
    return HardeningCheck(
        "lnx_suid", "Binarios SUID", "ok",
        f"{len(suid)} binario(s) SUID, todos en rutas del sistema.",
        attack="T1548.001", cis="CIS 6.1 Permisos")


def eval_world_writable_path(d: dict) -> HardeningCheck:
    ww = _get(d, "ww_path", [])
    if ww == [] and "ww_path" not in d:
        return _unknown("lnx_ww_path", "Directorios del PATH escribibles", "T1574")
    if not ww:
        return HardeningCheck("lnx_ww_path", "Directorios del PATH escribibles", "ok",
                              "Ningun directorio del PATH es escribible por todos.",
                              attack="T1574", cis="CIS 6.1 Permisos")
    return HardeningCheck(
        "lnx_ww_path", "Directorios del PATH escribibles", "fail",
        f"Directorios del PATH escribibles por cualquiera: {', '.join(ww)}. "
        f"Permiten plantar un binario que otro usuario ejecutaria sin saberlo.",
        recommendation="Quita el permiso de escritura para 'otros' en esas carpetas.",
        attack="T1574", cis="CIS 6.1 Permisos")


def eval_fail2ban(d: dict) -> HardeningCheck:
    active = d.get("fail2ban")
    if active:
        return HardeningCheck("lnx_fail2ban", "Proteccion anti-fuerza-bruta", "ok",
                              "fail2ban activo: bloquea IPs tras intentos fallidos.",
                              attack="T1110")
    return HardeningCheck(
        "lnx_fail2ban", "Proteccion anti-fuerza-bruta", "warn",
        "No hay fail2ban: los intentos de fuerza bruta contra SSH u otros "
        "servicios no se frenan solos.",
        recommendation="Instala y activa fail2ban.",
        fix_command="sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban",
        attack="T1110")


def eval_auto_updates(d: dict) -> HardeningCheck:
    if d.get("unattended"):
        return HardeningCheck("lnx_auto_upd", "Actualizaciones automaticas", "ok",
                              "unattended-upgrades activo: los parches de seguridad "
                              "se aplican solos.", attack="T1190")
    return HardeningCheck(
        "lnx_auto_upd", "Actualizaciones automaticas", "warn",
        "Sin actualizaciones automaticas: los parches dependen de que alguien se acuerde.",
        recommendation="Activa unattended-upgrades para parches de seguridad.",
        fix_command="sudo apt-get install -y unattended-upgrades && "
                    "sudo dpkg-reconfigure -f noninteractive unattended-upgrades",
        attack="T1190")


def eval_antivirus(d: dict) -> HardeningCheck:
    av = _get(d, "av", [])
    if av:
        return HardeningCheck("lnx_av", "Anti-malware / anti-rootkit", "ok",
                              f"Presente: {', '.join(av)}.", attack="T1059")
    return HardeningCheck(
        "lnx_av", "Anti-malware / anti-rootkit", "warn",
        "Sin herramientas de deteccion de malware/rootkits instaladas.",
        recommendation="Instala rkhunter o ClamAV para deteccion basica.",
        fix_command="sudo apt-get install -y rkhunter clamav",
        attack="T1059")


_EVALUADORES = (
    eval_ssh_root, eval_ssh_password, eval_firewall, eval_updates,
    eval_shadow_perms, eval_uid0, eval_empty_pw, eval_suid,
    eval_world_writable_path, eval_fail2ban, eval_auto_updates, eval_antivirus,
)


def evaluate(d: dict) -> list[HardeningCheck]:
    checks: list[HardeningCheck] = []
    for fn in _EVALUADORES:
        try:
            checks.append(fn(d))
        except Exception:
            continue   # un evaluador que falle no debe tumbar la auditoria
    return checks


def scan_linux_hardening() -> tuple[list[HardeningCheck], list[Finding]]:
    """Auditoria completa de endurecimiento de Linux. Misma forma que
    `hardening.scan_hardening`: (checks, findings)."""
    checks = evaluate(probe())
    findings: list[Finding] = []
    for c in checks:
        if c.status in ("fail", "warn"):
            findings.append(Finding(
                category="blindaje", severity=_STATUS_SEV[c.status],
                title=f"Blindaje: {c.title}",
                detail=c.detail + (f" {c.recommendation}" if c.recommendation else ""),
                evidence={"key": c.key, "status": c.status,
                          "fix_command": c.fix_command, "cis": c.cis,
                          "reboot": c.reboot},
                attack=c.attack,
            ))
    return checks, findings
