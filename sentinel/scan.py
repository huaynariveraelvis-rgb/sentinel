"""scan.py — Demo headless del motor de vigilancia de SENTINEL.

Ejecuta:  python -m sentinel.scan
Corre un barrido completo (procesos + red + arranque) e imprime un reporte
legible en consola. Sirve para validar el motor sin la GUI.
"""
from __future__ import annotations

import sys

from sentinel import __product__, __vendor__, __version__
from sentinel.core.monitor import full_scan, Severity


# Colores ANSI (degradan a vacio si la consola no los soporta).
_COLORS = {
    "CRITICA": "\033[97;41m",  # blanco sobre rojo
    "ALTA": "\033[91m",        # rojo
    "MEDIA": "\033[93m",       # amarillo
    "BAJA": "\033[96m",        # cyan
    "INFO": "\033[90m",        # gris
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[92m"


def _c(text: str, key: str) -> str:
    return f"{_COLORS.get(key, '')}{text}{_RESET}"


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # emojis/acentos en Windows
    except Exception:
        pass

    print()
    print(f"{_BOLD}  ╔══════════════════════════════════════════════╗{_RESET}")
    print(f"{_BOLD}  ║   🛡️  {__product__}  ·  Barrido de seguridad      ║{_RESET}")
    print(f"{_BOLD}  ╚══════════════════════════════════════════════╝{_RESET}")
    print(f"     {__vendor__}  ·  v{__version__}")
    print()
    print("  Analizando procesos, red y arranque del sistema…")
    print()

    report = full_scan()
    counts = report["counts"]
    findings = report["findings"]

    # Resumen
    bs = counts["por_severidad"]
    print(f"  {_BOLD}RESUMEN{_RESET}  ({counts['total']} hallazgos)")
    print(f"    Procesos: {counts['procesos']}   "
          f"Red: {counts['red']}   Arranque: {counts['arranque']}")
    line = "    "
    for key in ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"):
        line += _c(f"{key}:{bs.get(key, 0)}  ", key)
    print(line)
    print()

    # Detalle (lo mas grave primero; INFO se resume)
    shown = 0
    for f in findings:
        sev = f["severity_label"]
        if sev == "INFO" and shown >= 25:
            continue
        icon = {"CRITICA": "⛔", "ALTA": "🔴", "MEDIA": "🟠",
                "BAJA": "🔵", "INFO": "·"}.get(sev, "·")
        tag = _c(f"[{sev:^7}]", sev)
        print(f"  {tag} {icon} {_BOLD}{f['title']}{_RESET}")
        print(f"            {f['detail']}")
        shown += 1

    print()
    max_sev = report["max_severity"]
    if max_sev in ("CRITICA", "ALTA"):
        print(f"  {_c('⚠  SE DETECTARON RIESGOS QUE REQUIEREN ATENCION', max_sev)}")
    elif max_sev in ("MEDIA", "BAJA"):
        print(f"  {_c('Hay puntos a revisar, nada critico.', max_sev)}")
    else:
        print(f"  {_GREEN}✓ Sin riesgos relevantes detectados.{_RESET}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
