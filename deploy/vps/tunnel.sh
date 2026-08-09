#!/usr/bin/env bash
# tunnel.sh — Conexion remota real via Cloudflare Tunnel (un solo comando).
#
# Arranca el coordinador y lo publica en una URL HTTPS mediante un tunel
# SALIENTE de Cloudflare. No abre ningun puerto en el VPS, asi que la polleria
# no gana exposicion. Es gratis y no requiere cuenta (tunel rapido).
#
# Uso (en el VPS):  bash ~/sentinel/deploy/vps/tunnel.sh
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "== 1/4  Token del laboratorio =="
[ -f config/lab_token.key ] || python3 -m sentinel.coordinator --generar-token >/dev/null
TOKEN="$(cat config/lab_token.key)"
echo "   TOKEN: $TOKEN"
echo

echo "== 2/4  Coordinador en 127.0.0.1:8770 =="
pkill -f 'sentinel.coordinator --host' 2>/dev/null || true
sleep 1
nohup python3 -m sentinel.coordinator --host 127.0.0.1 --port 8770 </dev/null >coord.log 2>&1 &
sleep 3
curl -s -o /dev/null -w '   coordinador local -> HTTP %{http_code}\n' http://127.0.0.1:8770/ || true
echo

echo "== 3/4  cloudflared (el tunel) =="
if ! command -v cloudflared >/dev/null 2>&1; then
  echo "   instalando cloudflared…"
  curl -L -sS -o /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i /tmp/cloudflared.deb >/dev/null
fi
echo "   cloudflared: $(cloudflared --version 2>&1 | head -1)"
echo

echo "== 4/4  Abriendo el tunel =="
pkill -f 'cloudflared tunnel' 2>/dev/null || true
sleep 1
nohup cloudflared tunnel --url http://127.0.0.1:8770 </dev/null >tunnel.log 2>&1 &
URL=""
for _ in $(seq 1 20); do
  URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' tunnel.log 2>/dev/null | head -1 || true)"
  [ -n "$URL" ] && break
  sleep 2
done

echo
echo "==================================================================="
if [ -n "$URL" ]; then
  echo "  CONEXION REMOTA LISTA"
  echo
  echo "  URL del coordinador : $URL"
  echo "  TOKEN               : $TOKEN"
  echo
  echo "  Panel (abrelo en el navegador):  $URL/"
  echo
  echo "  En cada PC del laboratorio (Windows):"
  echo "    set SENTINEL_LAB_TOKEN=$TOKEN"
  echo "    python -m sentinel.agent -s $URL -e PC-07"
else
  echo "  El tunel aun no dio la URL. Revisa:  cat ~/sentinel/tunnel.log"
fi
echo "==================================================================="
echo
curl -s -o /dev/null -w '  polleria jireh :3000 -> HTTP %{http_code} (intacta, no se toco)\n' \
  http://127.0.0.1:3000/ || true
