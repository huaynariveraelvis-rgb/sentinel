"""build.py — Empaqueta SENTINEL como ejecutable Windows con PyInstaller.

Uso:
  pip install pyinstaller
  python build.py

Genera dist/SENTINEL/SENTINEL.exe (modo carpeta, recomendado para apps con
QtWebEngine). El instalador (installer/installer.iss, Inno Setup) toma esa
carpeta y produce el setup final para distribuir/vender.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEP = ";" if sys.platform.startswith("win") else ":"


def main() -> int:
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "SENTINEL",
        "--windowed",                       # sin consola
        # Recursos del Command Center y plantilla de configuracion:
        "--add-data", f"{ROOT/'assets'}{SEP}assets",
        "--add-data", f"{ROOT/'config'/'settings.example.json'}{SEP}config",
        # PyQt6 WebEngine: PyInstaller trae hooks, pero aseguramos submodulos:
        "--collect-all", "PyQt6",
        # Cerebro IA conversacional (Gemini):
        "--collect-all", "google.genai",
        # icono opcional (descomenta cuando exista):
        # "--icon", str(ROOT/'assets'/'sentinel.ico'),
        str(ROOT / "run_sentinel.py"),
    ]
    print("Ejecutando:", " ".join(args))
    return subprocess.call(args)


if __name__ == "__main__":
    raise SystemExit(main())
