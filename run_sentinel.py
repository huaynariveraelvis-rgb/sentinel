"""run_sentinel.py — Punto de entrada para el ejecutable empaquetado.

PyInstaller usa este script como entry. Equivale a `python -m sentinel`.
"""
from sentinel.app import main

if __name__ == "__main__":
    raise SystemExit(main())
