"""reporting — Capa de reporte avanzado de SENTINEL.

Convierte los hallazgos crudos en el lenguaje que un informe profesional y un
jurado de tesis esperan: cobertura de marcos reconocidos (NIST CSF 2.0, CIS) y
mapa de tecnicas MITRE ATT&CK.
"""
from __future__ import annotations

from sentinel.core.reporting import frameworks, navigator

__all__ = ["frameworks", "navigator"]
