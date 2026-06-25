"""genlicense.py — Emite claves de licencia de SENTINEL (uso del FABRICANTE).

Uso:
  python -m sentinel.tools.genlicense "Nombre del cliente" [dias]

Sin `dias` -> licencia perpetua. Requiere el secreto del fabricante
(SENTINEL_LICENSE_SECRET o el valor por defecto del modulo license).
"""
import sys

from sentinel.core.license import generate_key, validate_key


def main(argv: list[str]) -> int:
    if not argv:
        print('Uso: python -m sentinel.tools.genlicense "Cliente" [dias]')
        return 2
    customer = argv[0]
    days = int(argv[1]) if len(argv) > 1 else None
    key = generate_key(customer, days)
    chk = validate_key(key)
    print(f"Cliente : {customer}")
    print(f"Vigencia: {'perpetua' if not days else str(days) + ' dias'}")
    print(f"Clave   : {key}")
    print(f"Verifica: {'OK' if chk['valid'] else 'FALLO -> ' + chk['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
