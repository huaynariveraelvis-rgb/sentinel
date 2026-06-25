"""config.py — Carga la configuracion de SENTINEL.

Lee config/settings.json (no versionado). Si no existe, cae a
settings.example.json y, en ultimo caso, a valores por defecto. Asi la app
arranca siempre, con o sin configuracion del usuario.
"""
from __future__ import annotations

import sys
import json
from pathlib import Path


def config_dir() -> Path:
    """Carpeta de configuracion del usuario.
    - Empaquetado (.exe): junto al ejecutable (editable tras instalar).
    - Desde codigo: la carpeta config/ del proyecto.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "config"
    return Path(__file__).resolve().parent.parent.parent / "config"


def _candidate_dirs() -> list[Path]:
    dirs = [config_dir()]
    # Plantilla empaquetada dentro del bundle (PyInstaller _internal / _MEIPASS).
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(Path(meipass) / "config")
    return dirs


_CONFIG_DIR = config_dir()

_DEFAULTS = {
    "product": "SENTINEL",
    "vendor": "ELVIS SYSTEMS Industrias",
    "theme": "guardian",
    "scan": {"auto_interval_seconds": 60, "watch_processes": True,
             "watch_network": True, "watch_autoruns": True},
    "ai": {"gemini_api_key": "", "enabled": False},
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
