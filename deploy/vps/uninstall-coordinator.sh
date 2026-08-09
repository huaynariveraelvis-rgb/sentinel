#!/usr/bin/env bash
# uninstall-coordinator.sh — Revierte por completo la instalacion del coordinador.
# Deja el VPS exactamente como estaba: la polleria nunca fue tocada, y aqui se
# retira lo unico que se agrego (el servicio sentinel-coord).
set -euo pipefail

SERVICE="sentinel-coord"
UNIT="/etc/systemd/system/${SERVICE}.service"

echo "== Desinstalando el coordinador SENTINEL =="
sudo systemctl disable --now "$SERVICE" 2>/dev/null || true
sudo rm -f "$UNIT"
sudo systemctl daemon-reload
echo "Servicio '${SERVICE}' detenido y eliminado."
echo
echo "La polleria queda intacta (Caddy, jireh, 80/443 y firewall sin cambios)."
echo "Los datos de auditoria siguen en config/ y data/ dentro del proyecto;"
echo "borralos a mano si ya no los necesitas."
