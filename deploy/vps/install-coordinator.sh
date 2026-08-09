#!/usr/bin/env bash
# install-coordinator.sh — Instala el coordinador de SENTINEL en el VPS de forma
# AISLADA y REVERSIBLE.
#
# Lo que este script NO toca (por diseno, para no malograr la polleria):
#   - la configuracion de Caddy
#   - los archivos de jireh-web / polleriajireh.com
#   - los puertos 80 y 443
#   - el firewall (no abre ningun puerto: usa Tailscale)
#
# Solo agrega: una carpeta de datos propia y un servicio systemd propio
# (sentinel-coord). Todo se revierte con uninstall-coordinator.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE="sentinel-coord"
UNIT="/etc/systemd/system/${SERVICE}.service"
USER_NAME="$(id -un)"

echo "== Instalador del coordinador SENTINEL =="
echo "   Carpeta del proyecto: $ROOT"
echo

# 1) Requisitos minimos (sin instalar nada del sistema).
command -v python3 >/dev/null 2>&1 || { echo "ERROR: falta python3."; exit 1; }
[ -d "$ROOT/sentinel" ] || { echo "ERROR: no encuentro el paquete 'sentinel' en $ROOT."; exit 1; }

# 2) Aviso si Tailscale no esta: el coordinador arrancara en localhost (seguro
#    pero inalcanzable por las PCs hasta que instales Tailscale).
if command -v tailscale >/dev/null 2>&1 && tailscale ip -4 >/dev/null 2>&1; then
  TS_IP="$(tailscale ip -4 | head -1)"
  echo "   Tailscale detectado. Las PCs usaran:  http://${TS_IP}:8770"
else
  echo "   AVISO: Tailscale no esta activo todavia. El coordinador arrancara en"
  echo "   127.0.0.1 (solo local). Instala Tailscale y reinicia el servicio para"
  echo "   que las PCs del laboratorio puedan alcanzarlo. Nada queda expuesto."
fi
echo

# 3) Token del laboratorio (se genera una sola vez; el mismo va en cada PC).
mkdir -p "$ROOT/config"
if [ ! -f "$ROOT/config/lab_token.key" ]; then
  python3 -c "import secrets; print(secrets.token_urlsafe(24))" > "$ROOT/config/lab_token.key"
  chmod 600 "$ROOT/config/lab_token.key"
  echo "   Token del laboratorio generado."
fi
echo "   >> TOKEN (copialo a cada PC del laboratorio):"
echo "      $(cat "$ROOT/config/lab_token.key")"
echo

# 4) Servicio systemd propio (aislado). Corre como TU usuario, no como root.
echo "   Se creara el servicio '${SERVICE}' (requiere sudo solo para esto)."
sudo tee "$UNIT" >/dev/null <<UNIT
[Unit]
Description=SENTINEL Coordinador del laboratorio (aislado)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${ROOT}
ExecStart=/usr/bin/env bash ${ROOT}/deploy/vps/run-coordinator.sh
Restart=on-failure
RestartSec=5
# Endurecimiento: el servicio no puede escalar ni escribir fuera de lo suyo.
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

chmod +x "$ROOT/deploy/vps/run-coordinator.sh"
sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE"

echo
echo "== Listo =="
sudo systemctl --no-pager --lines=5 status "$SERVICE" || true
echo
echo "Comprobaciones utiles:"
echo "  Estado del coordinador : sudo systemctl status ${SERVICE}"
echo "  IP para las PCs        : tailscale ip -4"
echo "  Panel (desde Tailscale): http://<ip-tailscale-del-vps>:8770/"
echo
echo "La polleria NO fue tocada: sin cambios en Caddy, jireh, 80/443 ni firewall."
echo "Para revertir todo: bash deploy/vps/uninstall-coordinator.sh"
