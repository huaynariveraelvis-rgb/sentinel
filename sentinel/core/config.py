"""config.py — Carga la configuracion de SENTINEL.

Lee config/settings.json (no versionado). Si no existe, cae a
settings.example.json y, en ultimo caso, a valores por defecto. Asi la app
arranca siempre, con o sin configuracion del usuario.
"""
from __future__ import annotations

import sys
import json
from pathlib import Path


def _install_dir() -> Path:
    """Carpeta del producto: la del .exe instalado, o la raiz del proyecto."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def config_dir() -> Path:
    """Carpeta de configuracion QUE SE LEE (viene junto al producto).
    - Empaquetado (.exe): junto al ejecutable.
    - Desde codigo: la carpeta config/ del proyecto.

    Para escribir usa `user_config_dir()`: instalado en Archivos de programa
    esta carpeta es de solo lectura.
    """
    return _install_dir() / "config"


def _writable(d: Path) -> bool:
    """True si la carpeta se puede crear Y escribir dentro de ella.

    No basta con `mkdir`: en Archivos de programa un proceso sin elevar puede
    fallar al crear la carpeta y tambien al escribir en una que ya existe.
    Por eso se comprueba con un archivo de prueba real.
    """
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / ".escritura"
        probe.write_bytes(b"")
        probe.unlink()
        return True
    except OSError:
        return False


_STATE_DIR: Path | None = None


def state_dir() -> Path:
    """Carpeta ESCRIBIBLE donde vive todo lo que SENTINEL genera.

    El instalador deja el producto en Archivos de programa, que Windows monta
    de solo lectura para quien no es administrador. Guardar ahi la base de
    auditorias hacia que exportar un informe desde una cuenta normal del
    laboratorio muriese con "unable to open database file".

    Orden de preferencia:
      1. ProgramData  — compartido por todas las cuentas del equipo, que es
         como se usa un laboratorio: la evidencia de la PC es una sola.
      2. LocalAppData — si ProgramData no deja escribir, al menos el usuario
         que opera conserva su historial.
      3. Junto al producto — solo cuando se corre desde codigo.
    """
    global _STATE_DIR
    if _STATE_DIR is not None:
        return _STATE_DIR

    if not getattr(sys, "frozen", False):
        _STATE_DIR = _install_dir()          # en desarrollo, todo en el proyecto
        return _STATE_DIR

    import os
    for env in ("PROGRAMDATA", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if not base:
            continue
        cand = Path(base) / "SENTINEL"
        if _writable(cand):
            _STATE_DIR = cand
            _migrate_legacy_state(cand)
            return _STATE_DIR

    _STATE_DIR = _install_dir()              # ultimo recurso: que algo devuelva
    return _STATE_DIR


def _migrate_legacy_state(destino: Path) -> None:
    """Traslada la evidencia de versiones que la guardaban junto al .exe.

    Solo actua una vez y nunca pisa lo que ya existe: si el equipo ya tiene
    historial en la carpeta nueva, manda ese.
    """
    viejo = _install_dir() / "data"
    nuevo = destino / "data"
    if not viejo.is_dir() or nuevo.exists():
        return
    try:
        import shutil
        shutil.copytree(viejo, nuevo)
    except OSError:
        pass


def user_config_dir() -> Path:
    """Carpeta de configuracion ESCRIBIBLE (licencia, token del laboratorio)."""
    d = state_dir() / "config"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def os_name() -> str:
    """Nombre real del sistema operativo.

    `platform.release()` devuelve "10" tambien en Windows 11: Microsoft no
    cambio ese identificador. Lo unico que distingue las dos versiones es el
    numero de compilacion (22000 o superior es Windows 11). Sin esta
    correccion, todos los informes dirian "Windows 10" en equipos con 11.
    """
    import platform
    sistema = platform.system()
    if sistema != "Windows":
        return f"{sistema} {platform.release()}".strip()
    try:
        build = int(platform.version().split(".")[2])
    except (IndexError, ValueError):
        return f"Windows {platform.release()}"
    return f"Windows {'11' if build >= 22000 else '10'} (build {build})"


def data_dir() -> Path:
    """Carpeta de datos de SENTINEL (historial de auditorias, exportaciones).

    Cuelga de `state_dir()`, no del producto: desde codigo queda en data/ del
    proyecto y, instalado, en ProgramData\\SENTINEL\\data, que si es escribible
    para las cuentas normales del laboratorio.
    """
    d = state_dir() / "data"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def _candidate_dirs() -> list[Path]:
    # La configuracion escrita por el usuario manda sobre la que trae el producto.
    dirs = [user_config_dir(), config_dir()]
    # Plantilla empaquetada dentro del bundle (PyInstaller _internal / _MEIPASS).
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass) / "config")
    return dirs


_CONFIG_DIR = config_dir()

_DEFAULTS = {
    "product": "SENTINEL",
    "vendor": "ELVIS SYSTEMS Industrias",
    # Rol del equipo: "agent" (normal) o "root" (consola de administrador).
    # Solo un equipo "root" desbloquea la Consola de Flota (panel de la nube)
    # y recibe el token de administrador para comandar el parque.
    "role": "agent",
    "cloud": {"url": "https://sentinel-cloud-eight.vercel.app", "admin_token": ""},
    "theme": "guardian",
    "scan": {"auto_interval_seconds": 60, "watch_processes": True,
             "watch_network": True, "watch_autoruns": True},
    "ai": {"gemini_api_key": "", "enabled": False,
           # SENTINEL Rojo (Auditor conversacional): cerebro via OpenRouter.
           "openrouter_api_key": "",
           "openrouter_model": "deepseek/deepseek-chat-v3-0324"},
    "analysis": {"virustotal_api_key": ""},
    "voice": {"enabled": False, "alert_on_severity": "ALTA"},
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings() -> dict:
    for d in _candidate_dirs():
        for name in ("settings.json", "settings.example.json"):
            p = d / name
            if p.exists():
                try:
                    user = json.loads(p.read_text(encoding="utf-8"))
                    return _deep_merge(_DEFAULTS, user)
                except (ValueError, OSError):
                    continue
    return dict(_DEFAULTS)
