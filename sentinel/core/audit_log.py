"""audit_log.py — Registro de acciones de SENTINEL.

Una herramienta que modifica la configuracion de un equipo ajeno tiene que
poder responder tres preguntas: QUE cambio, CUANDO y SI FUNCIONO. Sin ese
registro no hay forma de revertir con criterio ni de rendir cuentas ante quien
autorizo la intervencion.

El registro es un archivo JSONL (una linea JSON por accion) que solo se
escribe al final: nunca se reescribe ni se borra desde el producto. Cada linea
es autonoma, asi que un corte de luz a mitad de escritura solo puede danar la
ultima entrada, no el historial.

Se registran las acciones que CAMBIAN algo (correcciones de blindaje,
cuarentena) y no las lecturas, que serian ruido.
"""
from __future__ import annotations

import os
import json
import time
import getpass
from pathlib import Path

from sentinel.core.config import data_dir

_LOG_NAME = "acciones.jsonl"


def log_path() -> Path:
    return data_dir() / _LOG_NAME


def _operator() -> str:
    """Quien opera el equipo. Solo el nombre de la sesion, sin datos de mas."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME", "?")


def record(action: str, target: str = "", ok: bool | None = None,
           detail: str = "", **extra) -> None:
    """Anota una accion. Nunca lanza excepcion: el registro no debe romper
    la operacion que esta registrando."""
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "accion": action,
        "objetivo": target,
        "resultado": ("ok" if ok else "fallo") if ok is not None else "-",
        "detalle": detail,
        "operador": _operator(),
    }
    if extra:
        entry.update(extra)
    try:
        with open(log_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read(limit: int = 100) -> list[dict]:
    """Ultimas acciones registradas, de la mas reciente a la mas antigua."""
    p = log_path()
    if not p.exists():
        return []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue  # una linea corrupta no invalida el resto del historial
        if len(out) >= limit:
            break
    return out
