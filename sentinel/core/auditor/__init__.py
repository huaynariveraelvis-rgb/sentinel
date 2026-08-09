"""auditor — Motor OFENSIVO de SENTINEL (modulo Auditor / red team).

A diferencia del motor defensivo (que solo observa la maquina donde corre), el
Auditor examina OTROS equipos por la red. Esa capacidad obliga a un control que
el motor defensivo no necesita: nada se toca fuera del ALCANCE autorizado.

Regla de oro del modulo, inviolable:
    ninguna sonda del Auditor se ejecuta contra una IP que no este dentro del
    alcance cargado (`scope.py`). Sin un archivo de alcance valido, el Auditor
    no escanea nada. Es el equivalente tecnico del permiso por escrito.

Corre en Linux (Kali/Raspberry). Se apoya en herramientas reconocidas del
sistema (nmap y demas); no reimplementa exploits ni C2.
"""
from __future__ import annotations

from sentinel.core.auditor.scope import Scope, load_scope, ScopeError
from sentinel.core.auditor import toolkit, recon, enum, vuln

__all__ = ["Scope", "load_scope", "ScopeError",
           "toolkit", "recon", "enum", "vuln"]
