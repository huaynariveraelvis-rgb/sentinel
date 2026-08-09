#!/usr/bin/env bash
# ==============================================================================
#  setup-kali.sh — Prepara el motor OFENSIVO de SENTINEL (Auditor) en Kali.
#
#  Que hace:
#    1. Comprueba Python 3.
#    2. Crea un entorno virtual (.venv) e instala la dependencia del Auditor
#       (psutil). NO instala la GUI (PyQt): en la Pi/Kali corre headless.
#    3. Revisa que herramientas de Kali (nmap, whatweb, nikto...) estan
#       instaladas y cuales faltan.
#    4. Deja listo el alcance.json de ejemplo si no existe.
#
#  No toca la red. No requiere root salvo para instalar herramientas ausentes.
#
#  Uso:
#    chmod +x setup-kali.sh
#    ./setup-kali.sh
# ==============================================================================
set -euo pipefail

cd "$(dirname "$0")"
echo "==> SENTINEL Auditor — preparacion en Kali"
echo "    Directorio: $(pwd)"
echo

# --- 1) Python 3 --------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "!! No se encontro python3. Instala:  sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi
echo "==> Python: $(python3 --version)"

# --- 2) Entorno virtual + dependencia ----------------------------------------
if [ ! -d ".venv" ]; then
  echo "==> Creando entorno virtual (.venv)…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "==> Instalando dependencia del Auditor (psutil)…"
pip install --quiet --upgrade pip
pip install --quiet "psutil>=7.0"
echo "    Listo."
echo

# --- 3) Herramientas de Kali --------------------------------------------------
echo "==> Revisando el arsenal (recon / enum / vuln)…"
NEED_RECON=(nmap)
NEED_ENUM=(whatweb nikto gobuster enum4linux-ng smbmap sslscan)
NEED_VULN=(nuclei searchsploit)

FALTAN=()
for t in "${NEED_RECON[@]}" "${NEED_ENUM[@]}" "${NEED_VULN[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "    [OK]    %s\n" "$t"
  else
    printf "    [falta] %s\n" "$t"
    FALTAN+=("$t")
  fi
done
echo
if [ ${#FALTAN[@]} -gt 0 ]; then
  echo "==> Herramientas ausentes (${#FALTAN[@]}). Las ausentes se saltan solas;"
  echo "    instala las que necesites con:"
  echo "      sudo apt update && sudo apt install -y ${FALTAN[*]}"
  echo "    (nuclei a veces viene por separado; searchsploit = paquete 'exploitdb')"
else
  echo "==> Arsenal completo para recon/enum/vuln."
fi
echo

# --- 4) Alcance de ejemplo ----------------------------------------------------
if [ ! -f "alcance.json" ] && [ -f "alcance.example.json" ]; then
  cp alcance.example.json alcance.json
  echo "==> Copiado alcance.example.json -> alcance.json"
  echo "    EDITALO con los datos reales de tu acta antes de escanear."
fi
echo

# --- Siguientes pasos ---------------------------------------------------------
cat <<'PASOS'
==> Preparacion terminada. Siguientes pasos:

  source .venv/bin/activate

  # 1) Ver el arsenal (no toca nada):
  python -m sentinel.attack --arsenal

  # 2) Editar el alcance con tus datos reales (acta, rango, ventana):
  nano alcance.json

  # 3) Verificar alcance + herramientas (no toca nada):
  python -m sentinel.attack --verificar --scope alcance.json

  # 4) Auditar SOLO cuando el alcance este autorizado por escrito:
  python -m sentinel.attack --scope alcance.json

Recuerda: sin un alcance valido, el Auditor no escanea nada (falla cerrado).
PASOS
