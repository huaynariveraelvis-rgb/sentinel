"""navigator.py — Exporta los hallazgos como capa de MITRE ATT&CK Navigator.

El ATT&CK Navigator es la herramienta oficial de MITRE para pintar un mapa de
calor de tecnicas de ataque. Este modulo toma las tecnicas que SENTINEL detecto
(cada Finding trae su ATT&CK) y genera el archivo de capa que Navigator abre,
resaltando en rojo lo mas frecuente.

Para la tesis es la imagen que un jurado recuerda: un tablero donde se ve, de un
vistazo, que tecnicas de ataque cubre el sistema — el mismo lenguaje que usan
los equipos de seguridad reales.

El resultado es un JSON estandar de capa (layer v4.5). Se sube a
https://mitre-attack.github.io/attack-navigator/ o se incrusta en el informe.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def _campo(item, nombre: str, default=""):
    if isinstance(item, dict):
        return item.get(nombre, default)
    return getattr(item, nombre, default)


def tecnicas_de(findings) -> Counter:
    """Cuenta cuantas veces aparece cada tecnica ATT&CK en los hallazgos."""
    c: Counter = Counter()
    for f in list(findings or []):
        tid = str(_campo(f, "attack", "")).strip().upper()
        if tid.startswith("T"):
            c[tid] += 1
    return c


def build_layer(findings, name: str = "SENTINEL — Cobertura ATT&CK",
                description: str = "", domain: str = "enterprise-attack") -> dict:
    """Construye la capa de Navigator a partir de los hallazgos."""
    conteo = tecnicas_de(findings)
    maximo = max(conteo.values()) if conteo else 1
    tecnicas = [{
        "techniqueID": tid,
        "score": n,
        "color": "",
        "comment": f"{n} hallazgo(s) de SENTINEL",
        "enabled": True,
        "showSubtechniques": "." in tid,
    } for tid, n in sorted(conteo.items())]

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": domain,
        "description": description or "Tecnicas detectadas por SENTINEL (rojo/azul).",
        "techniques": tecnicas,
        "gradient": {
            "colors": ["#ffe6e6", "#ff6b6b", "#c0392b"],
            "minValue": 0,
            "maxValue": maximo,
        },
        "legendItems": [
            {"label": "1 hallazgo", "color": "#ffe6e6"},
            {"label": f"{maximo} hallazgos (max)", "color": "#c0392b"},
        ],
        "sorting": 3,       # de mayor a menor score
        "hideDisabled": True,
    }


def save_layer(findings, dest: str | Path, **kw) -> Path:
    """Escribe la capa a un archivo .json y devuelve su ruta."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_layer(findings, **kw), ensure_ascii=False,
                               indent=2), encoding="utf-8")
    return dest
