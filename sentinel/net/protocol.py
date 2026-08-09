"""protocol.py — Autenticacion y firma entre agente y coordinador.

Dos garantias, ambas con un secreto compartido (el token del laboratorio):

  1. AUTENTICIDAD  — solo quien conoce el token puede enviar un reporte valido.
  2. INTEGRIDAD    — el cuerpo va firmado con HMAC-SHA256, asi que nadie puede
                     alterar un reporte en transito sin invalidar la firma.

No es cifrado de transporte (para eso iria detras de TLS/una VPN del colegio),
pero impide que un tercero de la red inyecte reportes falsos o manipule los
datos del parque, que es el riesgo realista aqui.

El token se toma de la variable de entorno SENTINEL_LAB_TOKEN o del archivo
config/lab_token.key. Si no hay ninguno, `lab_token()` devuelve "" y tanto el
agente como el coordinador se niegan a arrancar: sin token no hay laboratorio.
"""
from __future__ import annotations

import os
import hmac
import time
import hashlib


def lab_token() -> str:
    """Token compartido del laboratorio (secreto). '' si no esta configurado."""
    env = os.environ.get("SENTINEL_LAB_TOKEN")
    if env:
        return env.strip()
    try:
        from sentinel.core.config import config_dir, user_config_dir
        # El escribible primero; el del producto acepta un token pre-instalado.
        for f in (user_config_dir() / "lab_token.key",
                  config_dir() / "lab_token.key"):
            if f.exists():
                return f.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""


def sign(body: bytes, token: str, ts: str | None = None) -> str:
    """Firma HMAC-SHA256 del cuerpo + marca de tiempo, en hex."""
    ts = ts or str(int(time.time()))
    mac = hmac.new(token.encode(), ts.encode() + b"." + body, hashlib.sha256)
    return f"{ts}.{mac.hexdigest()}"


def verify(body: bytes, signature: str, token: str,
           max_skew: int = 300) -> bool:
    """Valida la firma. Rechaza firmas viejas (>max_skew s) para acotar la
    ventana de repeticion de un reporte capturado."""
    if not token or not signature or "." not in signature:
        return False
    ts, _, mac_hex = signature.partition(".")
    if not ts.isdigit():
        return False
    if abs(time.time() - int(ts)) > max_skew:
        return False
    expected = hmac.new(token.encode(), ts.encode() + b"." + body,
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, mac_hex)


# Encabezado donde viaja la firma.
SIGNATURE_HEADER = "X-Sentinel-Signature"
