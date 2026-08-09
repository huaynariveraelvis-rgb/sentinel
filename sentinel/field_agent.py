"""field_agent.py — Agente + instalador todo-en-uno de SENTINEL.

Un solo ejecutable que hace de instalador profesional y de agente:

  * Doble clic (sin argumentos)  -> INSTALA en esta PC (se auto-eleva a admin,
    se copia a ProgramData, programa el reporte cada 15 min, aplica el filtro
    de contenido y confirma con un mensaje).
  * `--reportar`   -> envia una auditoria al panel (lo corre la tarea programada,
    en silencio, sin pedir admin).
  * `--desinstalar`-> revierte todo.
  * `--aplicar-filtro` / `--quitar-filtro` -> gestion del filtro (uso interno).

La configuracion (servidor + token + filtro) viaja DENTRO del .exe, asi que es
verdaderamente de un solo archivo: no hay nada mas que copiar.
"""
from __future__ import annotations

import os
import sys
import json
import time
import shutil
import socket
import ctypes
import subprocess
from pathlib import Path

APP_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SENTINEL"
EXE_NAME = "sentinel-agent.exe"
TASK = "SENTINEL Agente"
TASK_LOGON = "SENTINEL Agente Inicio"
_NW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ── Configuracion (embebida en el exe + editable en ProgramData) ─────────────

def _config() -> dict:
    paths: list[Path] = []
    if getattr(sys, "frozen", False):
        paths.append(Path(sys.executable).resolve().parent / "config.json")
        mp = getattr(sys, "_MEIPASS", None)
        if mp:
            paths.append(Path(mp) / "config.json")   # copia embebida en el exe
    else:
        paths.append(Path(__file__).resolve().parent.parent / "config.json")
    paths.insert(1 if len(paths) > 1 else 0, APP_DIR / "config.json")  # la editada gana
    for c in paths:
        try:
            if c.exists():
                return json.loads(c.read_text(encoding="utf-8"))
        except Exception:
            continue
    return {}


def _load_config() -> tuple[str, str, str]:
    d = _config()
    return (str(d.get("server", "")).strip(),
            str(d.get("token", "")).strip(),
            str(d.get("equipo", "")).strip())


def _filter_categories() -> list[str]:
    f = _config().get("filtro") or {}
    cats = f.get("categorias")
    return [str(x) for x in cats] if isinstance(cats, list) and cats else ["adultos", "juegos"]


def _filter_enabled() -> bool:
    return bool((_config().get("filtro") or {}).get("activar", True))


# ── Utilidades de Windows (admin, mensajes) ──────────────────────────────────

def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _elevate(arg: str) -> None:
    """Re-lanza este mismo ejecutable como administrador."""
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, arg, None, 1)
    except Exception:
        pass


def _msg(text: str, title: str = "SENTINEL", icon: int = 0x40) -> None:
    """Cuadro de mensaje (info=0x40, error=0x10). Cae a consola si no hay GUI."""
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, icon)
    except Exception:
        print(text)


def _this_exe() -> Path:
    return Path(sys.executable) if getattr(sys, "frozen", False) else Path(sys.argv[0])


def _log(line: str) -> None:
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        (APP_DIR / "agent.log").write_text(f"{stamp}  {line}\n", encoding="utf-8")
    except Exception:
        pass


# ── Reportar (lo corre la tarea programada, sin admin, en silencio) ──────────

def _report() -> int:
    server, token, equipo = _load_config()
    if not equipo:
        equipo = (socket.gethostname() or "PC").strip()[:40]
    if not server or not token:
        _log("FALLO: falta configuracion (server/token)")
        return 2
    from sentinel.net.agent import _send
    ok, msg = _send(server, equipo, token)
    _log(("OK: " if ok else "FALLO: ") + f"[{equipo}] {msg}")
    # Un latido de telemetria para que el panel muestre datos aunque no haya
    # un monitor en vivo corriendo.
    _send_latido(server, token, equipo)
    # Tras reportar, aplica lo que el administrador haya aprobado desde el panel.
    try:
        _poll_and_apply(server, token, equipo)
    except Exception:
        pass
    # Y ejecuta los comandos de la terminal remota (si esta habilitada).
    try:
        _poll_and_run_jobs(server, token, equipo)
    except Exception:
        pass
    return 0 if ok else 1


def _remote_terminal_enabled() -> bool:
    """La terminal remota es OPT-IN por equipo (config: terminal_remota)."""
    return bool(_config().get("terminal_remota", False))


def _poll_and_run_jobs(server: str, token: str, equipo: str) -> None:
    """Terminal remota: ejecuta los comandos que el root envio desde el panel.

    Seguridad: solo corre si el equipo lo habilito (terminal_remota); los
    comandos vienen por un canal firmado (HMAC) y cada uno queda REGISTRADO en
    audit_log via execute_locally. Es administracion remota legitima, no oculta.
    """
    if not _remote_terminal_enabled():
        return
    from sentinel.net.agent import _post_signed
    from sentinel.net.commands import execute_locally
    resp = _post_signed(server, "/jobs", {"label": equipo}, token)
    if not resp or not resp.get("jobs"):
        return
    for job in resp["jobs"]:
        cmd = str(job.get("command", ""))
        code, out, err = execute_locally(cmd)
        _log(f"COMANDO REMOTO '{cmd[:60]}': exit {code}")
        _post_signed(server, "/jobs",
                     {"label": equipo, "id": job.get("id"), "command": cmd[:200],
                      "exit_code": code, "stdout": out, "stderr": err}, token)


def _send_latido(server: str, token: str, equipo: str) -> bool:
    """Envia una muestra de rendimiento (CPU/RAM/disco/red) al panel."""
    try:
        from sentinel.net.agent import _post_signed
        from sentinel.core.metrics import sample
        r = _post_signed(server, "/latido", {"label": equipo, "metricas": sample()}, token)
        return bool(r and r.get("ok"))
    except Exception:
        return False


def _monitor(interval: int = 3) -> int:
    """Bucle de telemetria en vivo: muestrea y envia latidos sin parar.
    Es el que alimenta los graficos de rendimiento en vivo del panel."""
    server, token, equipo = _load_config()
    if not equipo:
        equipo = (socket.gethostname() or "PC").strip()[:40]
    if not server or not token:
        _log("MONITOR FALLO: falta configuracion (server/token)")
        print("  ERROR: falta server/token en la configuracion.")
        return 2
    interval = max(1, interval)
    print(f"  SENTINEL monitor  ·  equipo {equipo}")
    print(f"  Enviando telemetria en vivo a {server} cada {interval}s. Ctrl+C para detener.")
    try:
        while True:
            ok = _send_latido(server, token, equipo)
            # En modo monitor tambien atendemos la terminal remota, para que los
            # comandos del root se ejecuten en segundos (no cada 15 min).
            try:
                _poll_and_run_jobs(server, token, equipo)
            except Exception:
                pass
            print(f"  [{time.strftime('%H:%M:%S')}] latido {'OK' if ok else 'FALLO'}", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n  Monitor detenido.")
    return 0


def _run_fix_direct(command: str) -> tuple[bool, str]:
    """Ejecuta un comando de correccion DIRECTO (sin UAC). Sirve porque la tarea
    corre como SYSTEM, que ya tiene privilegios; un prompt de UAC no funcionaria
    en una tarea de fondo."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=120, creationflags=_NW)
        return out.returncode == 0, ((out.stderr or out.stdout or "").strip())[:180]
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _apply_blindaje(key: str) -> tuple[bool, str]:
    """Aplica un blindaje (o 'all' = todos los que fallan)."""
    from sentinel.core.hardening import scan_hardening
    checks, _ = scan_hardening()
    targets = [c for c in checks
               if c.status in ("fail", "warn") and c.fix_command
               and (key == "all" or c.key == key)]
    if not targets:
        return True, "nada que aplicar"
    res = []
    for c in targets:
        ok, _m = _run_fix_direct(c.fix_command)
        res.append(f"{c.key}:{'ok' if ok else 'x'}")
    return True, "aplicados: " + ", ".join(res)


# ── Aislamiento de red (contencion EDR, reversible) ──────────────────────────
_AISLA_GROUP = "SENTINEL-Aislamiento"
# Puertos de movimiento lateral / propagacion: RPC, NetBIOS, SMB, RDP, WinRM.
_AISLA_TCP = "135,139,445,593,3389,5985,5986"
_AISLA_UDP = "137,138"


def _netsh(*args):
    return subprocess.run(["netsh", "advfirewall", "firewall", *args],
                          capture_output=True, text=True, creationflags=_NW)


def _is_isolated() -> bool:
    """True si el equipo esta aislado (existe el grupo de reglas)."""
    try:
        return _netsh("show", "rule", "name=" + _AISLA_GROUP).returncode == 0
    except Exception:
        return False


def _aislar(on: bool) -> tuple[bool, str]:
    """Aisla (o reconecta) el equipo cortando los canales de propagacion en red
    (SMB/RDP/RPC/WinRM/NetBIOS) — pero MANTIENE el canal de gestion (HTTPS)
    hacia la consola, para poder reconectarlo despues. Totalmente reversible."""
    try:
        _netsh("delete", "rule", "name=" + _AISLA_GROUP)  # limpia previas
        if not on:
            return True, "aislamiento retirado (equipo reconectado)"
        r1 = _netsh("add", "rule", "name=" + _AISLA_GROUP, "dir=in",
                    "action=block", "protocol=TCP", "localport=" + _AISLA_TCP)
        r2 = _netsh("add", "rule", "name=" + _AISLA_GROUP, "dir=out",
                    "action=block", "protocol=TCP", "remoteport=" + _AISLA_TCP)
        _netsh("add", "rule", "name=" + _AISLA_GROUP, "dir=in",
               "action=block", "protocol=UDP", "localport=" + _AISLA_UDP)
        if r1.returncode != 0 or r2.returncode != 0:
            det = (r1.stderr or r2.stderr or "").strip()[:120]
            return False, "no se pudo aislar (requiere admin/SYSTEM): " + det
        return True, "equipo AISLADO: SMB/RDP/RPC/WinRM/NetBIOS cortados; gestion HTTPS intacta"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _do_action(action: str) -> tuple[bool, str]:
    """Traduce una accion aprobada en el panel a algo concreto en esta PC.
    Solo acepta acciones de la lista blanca (nunca comandos arbitrarios)."""
    try:
        if action == "filtro:on":
            from sentinel.core.webfilter import apply as fa
            r = fa(_filter_categories())
            return bool(r.get("ok")), f"{r.get('dominios', '?')} dominios"
        if action == "filtro:off":
            from sentinel.core.webfilter import remove as fr
            return bool(fr().get("ok")), "filtro quitado"
        if action.startswith("filtro:bloquear:"):
            from sentinel.core.webfilter import block_domain
            dom = action.split(":", 2)[2]
            r = block_domain(dom)
            return bool(r.get("ok")), f"bloqueado {dom}"
        if action == "blindaje:all":
            return _apply_blindaje("all")
        if action.startswith("blindaje:"):
            return _apply_blindaje(action.split(":", 1)[1])
        if action == "reiniciar":
            subprocess.run(["shutdown", "/r", "/t", "15", "/c",
                            "SENTINEL: el equipo se reiniciara"], creationflags=_NW)
            return True, "reinicio programado (15s)"
        if action == "apagar":
            subprocess.run(["shutdown", "/s", "/t", "15", "/c",
                            "SENTINEL: el equipo se apagara"], creationflags=_NW)
            return True, "apagado programado (15s)"
        if action == "aislar":
            return _aislar(True)
        if action == "desaislar":
            return _aislar(False)
        if action == "escanear":
            return True, "reporte forzado"   # el propio ciclo ya reporto
        if action.startswith("mensaje:"):
            texto = action.split(":", 1)[1][:200] or "Mensaje de SENTINEL"
            # msg * envia el aviso a TODAS las sesiones interactivas (llega al
            # usuario aunque la tarea corra como SYSTEM en sesion 0).
            subprocess.run(["msg", "*", texto], creationflags=_NW)
            return True, "mensaje enviado"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    return False, "accion desconocida"


def _poll_and_apply(server: str, token: str, label: str) -> None:
    """Pregunta al panel que acciones aprobo el admin y las aplica."""
    from sentinel.net.agent import _post_signed
    resp = _post_signed(server, "/pending", {"label": label}, token)
    if not resp or not resp.get("actions"):
        return
    for action in resp["actions"]:
        ok, detail = _do_action(action)
        _log(f"ACCION {action}: {'OK' if ok else 'FALLO'} - {detail}")
        _post_signed(server, "/result",
                     {"label": label, "action": action, "ok": ok, "detail": detail},
                     token)


# ── Filtro de contenido ──────────────────────────────────────────────────────

def _apply_filter(with_dns: bool = False) -> int:
    from sentinel.core.webfilter import apply as filter_apply
    r = filter_apply(_filter_categories(), set_dns=with_dns)
    _log("FILTRO: " + str(r))
    return 0 if r.get("ok") else 1


def _remove_filter() -> int:
    from sentinel.core.webfilter import remove as filter_remove
    return 0 if filter_remove().get("ok") else 1


# ── Instalar / desinstalar (profesional, auto-elevado) ───────────────────────

def _install() -> int:
    if not _is_admin():
        _elevate("--instalar")   # re-lanza con UAC; esta instancia termina
        return 0

    server = _load_config()[0]
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        dest = APP_DIR / EXE_NAME
        if _this_exe().resolve() != dest.resolve():
            shutil.copy2(_this_exe(), dest)
        cfg = _config()
        if cfg:
            (APP_DIR / "config.json").write_text(
                json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        _msg("No se pudo instalar el agente:\n\n" + str(e), "SENTINEL", 0x10)
        return 1

    # Tareas programadas: reporte cada 15 min y al iniciar sesion.
    # Corren como SYSTEM (/ru SYSTEM /rl HIGHEST) para poder aplicar los
    # blindajes y el filtro que se aprueben desde el panel, sin pedir permisos.
    tr = f'"{dest}" --reportar'
    subprocess.run(["schtasks", "/create", "/tn", TASK, "/tr", tr,
                    "/sc", "minute", "/mo", "15", "/ru", "SYSTEM", "/rl", "HIGHEST",
                    "/f"], capture_output=True, creationflags=_NW)
    subprocess.run(["schtasks", "/create", "/tn", TASK_LOGON, "/tr", tr,
                    "/sc", "onlogon", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"],
                   capture_output=True, creationflags=_NW)

    # Filtro de contenido.
    fmsg = ""
    if _filter_enabled():
        try:
            from sentinel.core.webfilter import apply as filter_apply
            r = filter_apply(_filter_categories())
            fmsg = (f"\n  - Filtro activo: {r.get('dominios', '?')} dominios bloqueados"
                    if r.get("ok") else "\n  - Filtro: no se pudo aplicar")
        except Exception:
            fmsg = "\n  - Filtro: no se pudo aplicar"

    # Primer reporte.
    rmsg = ""
    try:
        _report()
        rmsg = "\n  - Primer reporte enviado al panel"
    except Exception:
        pass

    _msg("SENTINEL se instalo correctamente en esta PC.\n\n"
         "Desde ahora, esta PC:\n"
         "  - Reporta su seguridad al panel cada 15 minutos" + fmsg + rmsg +
         "\n\nPanel del laboratorio:\n" + (server or "(configurar)"),
         "SENTINEL - Instalacion completada")
    return 0


def _uninstall() -> int:
    if not _is_admin():
        _elevate("--desinstalar")
        return 0
    try:
        from sentinel.core.webfilter import remove as filter_remove
        filter_remove()
    except Exception:
        pass
    subprocess.run(["schtasks", "/delete", "/tn", TASK, "/f"],
                   capture_output=True, creationflags=_NW)
    subprocess.run(["schtasks", "/delete", "/tn", TASK_LOGON, "/f"],
                   capture_output=True, creationflags=_NW)
    # Se borra la carpeta salvo el propio exe en uso (queda huerfano, inofensivo).
    try:
        for f in APP_DIR.glob("*"):
            if f.name != EXE_NAME:
                f.unlink(missing_ok=True)
    except Exception:
        pass
    _msg("SENTINEL se desinstalo de esta PC.\n\n"
         "Se quito el filtro, los reportes y la configuracion.",
         "SENTINEL - Desinstalado")
    return 0


# ── Entrada ──────────────────────────────────────────────────────────────────

def main() -> int:
    argv = [a.lower() for a in sys.argv[1:]]
    if "--reportar" in argv:
        return _report()
    if "--monitor" in argv:
        seg = 3
        for a in argv:
            if a.startswith("--intervalo="):
                try: seg = int(a.split("=", 1)[1])
                except ValueError: pass
        return _monitor(seg)
    if "--aplicar-filtro" in argv:
        return _apply_filter(with_dns=("--dns" in argv))
    if "--quitar-filtro" in argv:
        return _remove_filter()
    if "--desinstalar" in argv:
        return _uninstall()
    # Sin argumentos (doble clic) o --instalar -> instalar.
    return _install()


if __name__ == "__main__":
    raise SystemExit(main())
