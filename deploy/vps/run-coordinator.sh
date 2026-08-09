#!/usr/bin/env bash
# run-coordinator.sh — Arranca el coordinador vinculado SOLO a una red segura.
#
# GARANTIA DE SEGURIDAD: vincula el coordinador a la IP de Tailscale y, si
# Tailscale no esta disponible, a 127.0.0.1 (solo local). NUNCA a 0.0.0.0.
# Es fisicamente imposible que este proceso quede expuesto a internet, asi que
# el servidor de la polleria no gana ninguna superficie de ataque publica.
set -euo pipefail

# Raiz del repo sentinel (dos niveles arriba de este script).
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Espera a que Tailscale entregue una IP (hasta ~30 s tras un reinicio).
HOST=""
for _ in 1 2 3 4 5 6; do
  HOST="$(tailscale ip -4 2>/dev/null | head -1 || true)"
  [ -n "$HOST" ] && break
  sleep 5
done

# Respaldo seguro: si Tailscale no respondio, escucha SOLO en localhost.
# Nunca cae a 0.0.0.0, de modo que jamas se publica al internet.
[ -n "$HOST" ] || HOST="127.0.0.1"

echo "SENTINEL coordinador -> ${HOST}:8770 (solo Tailscale/local, no publico)"
exec python3 -m sentinel.coordinator --host "$HOST" --port 8770
