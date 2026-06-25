"""config.py — Carga la configuracion de SENTINEL.

Lee config/settings.json (no versionado). Si no existe, cae a
settings.example.json y, en ultimo caso, a valores por defecto. Asi la app
arranca siempre, con o sin configuracion del usuario.
"""
from __future__ import annotations

import json
from pathlib import Path

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"

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
    for name in ("settings.json", "settings.example.json"):
        p = _CONFIG_DIR / name
        if p.exists():
            try:
                user = json.loads(p.read_text(encoding="utf-8"))
                return _deep_merge(_DEFAULTS, user)
            except (ValueError, OSError):
                continue
    return dict(_DEFAULTS)
