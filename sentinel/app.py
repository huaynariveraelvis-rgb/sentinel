"""app.py — Punto de entrada de la GUI de SENTINEL.

Ejecuta:  python -m sentinel
Levanta el Command Center con el orbe verde guardian y el panel de
vigilancia en vivo alimentado por el motor (procesos/red/arranque).
"""
from __future__ import annotations

import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from sentinel import __product__, __version__


def main() -> int:
    # QtWebEngine necesita contextos OpenGL compartidos ANTES de crear la app.
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(__product__)
    app.setApplicationVersion(__version__)

    # Import diferido: QApplication debe existir antes que QWebEngine.
    from sentinel.ui.window import SentinelWindow

    win = SentinelWindow(scan_interval=60)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
