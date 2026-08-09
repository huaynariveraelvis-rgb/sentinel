"""winproc.py — Lanzar procesos de consola sin que parpadee una ventana negra.

Windows asigna una consola a cada proceso hijo de consola (PowerShell, netsh,
ipconfig...). Desde una app grafica eso se ve como un parpadeo negro cada vez
que el motor consulta el sistema. Ocultarlo de forma fiable necesita DOS cosas
a la vez:

  * CREATE_NO_WINDOW  -> no asignar una consola nueva al hijo.
  * STARTUPINFO con SW_HIDE -> si el proceso pide ventana igual, nace oculta.

Con solo la primera hay casos (segun como se lanzo el proceso padre) en que la
ventana llega a dibujarse un instante. Por eso se usan las dos.
"""
from __future__ import annotations

import subprocess


def oculto() -> dict:
    """Argumentos para subprocess.run/Popen que evitan la ventana de consola.

    Devuelve un dict vacio de banderas en sistemas no Windows, para que el
    mismo codigo siga funcionando al portarlo.
    """
    kwargs: dict = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    si_cls = getattr(subprocess, "STARTUPINFO", None)
    if si_cls is not None:              # STARTUPINFO solo existe en Windows
        si = si_cls()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        si.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        kwargs["startupinfo"] = si
    return kwargs
