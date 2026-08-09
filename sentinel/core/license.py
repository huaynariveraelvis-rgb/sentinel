"""license.py — Licenciamiento offline de SENTINEL.

Esquema de clave firmada (sin servidor): la clave codifica un payload
(nombre del cliente + fecha de emision + opcional expiracion) y una firma
HMAC-SHA256 truncada con un secreto del fabricante. El producto valida la
firma sin internet; solo ELVIS SYSTEMS (que tiene el secreto) puede emitir
claves validas.

Formato visible:  SENT-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX  (Base32)

Nota: una licencia offline nunca es inviolable, pero frena la copia casual
y da una activacion real para vender. El secreto debe ofuscarse/rotarse en
produccion.
"""
from __future__ import annotations

import os
import csv  # noqa: F401  (reservado para registro de emisiones)
import json
import time
import hmac
import base64
import hashlib
from pathlib import Path

# El secreto del fabricante se busca, en orden:
#   1. variable de entorno SENTINEL_LICENSE_SECRET  (build y emision de claves)
#   2. archivo config/vendor.key                    (no versionado)
#   3. valor de desarrollo incrustado               (solo para probar)
#
# Tener el secreto en el codigo fuente significa que cualquiera con acceso al
# repositorio puede emitir licencias validas. Por eso el valor incrustado es
# de DESARROLLO y `licensing_is_secure()` avisa cuando esta en uso.
_DEV_SECRET = "SENTINEL-DEV-ONLY-NO-USAR-EN-PRODUCCION"


def _load_secret() -> tuple[bytes, str]:
    """Devuelve (secreto, origen)."""
    env = os.environ.get("SENTINEL_LICENSE_SECRET")
    if env:
        return env.encode(), "entorno"
    try:
        from sentinel.core.config import config_dir
        f = config_dir() / "vendor.key"
        if f.exists():
            val = f.read_text(encoding="utf-8").strip()
            if val:
                return val.encode(), "archivo"
    except Exception:
        pass
    return _DEV_SECRET.encode(), "desarrollo"


_VENDOR_SECRET, _SECRET_ORIGIN = _load_secret()


def licensing_is_secure() -> bool:
    """False si se esta usando el secreto de desarrollo incrustado."""
    return _SECRET_ORIGIN != "desarrollo"

def _license_file() -> Path:
    """Donde se ESCRIBE la licencia: carpeta escribible del equipo."""
    from sentinel.core.config import user_config_dir
    return user_config_dir() / "license.key"


def _license_sources() -> list[Path]:
    """Donde se BUSCA la licencia, en orden.

    Incluye la carpeta del producto para respetar una licencia pre-instalada
    junto al ejecutable, que en Archivos de programa solo se puede leer.
    """
    from sentinel.core.config import config_dir, user_config_dir
    return [user_config_dir() / "license.key", config_dir() / "license.key"]


_PREFIX = "SENT"


def _b32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=")


def _b32d(s: str) -> bytes:
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)


def _grouped(s: str, size: int = 5) -> str:
    return "-".join(s[i:i + size] for i in range(0, len(s), size))


def generate_key(customer: str, days: int | None = None,
                 secret: bytes = _VENDOR_SECRET) -> str:
    """Emite una clave para `customer`. `days`=None -> licencia perpetua.
    SOLO debe usarlo el fabricante (requiere el secreto)."""
    payload = {
        "c": customer.strip()[:40],
        "i": int(time.time()),
        "e": (int(time.time()) + days * 86400) if days else 0,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    body = _b32(raw)
    sig = _b32(hmac.new(secret, raw, hashlib.sha256).digest()[:10])
    return f"{_PREFIX}-" + _grouped((body + sig).upper())


def validate_key(key: str, secret: bytes = _VENDOR_SECRET) -> dict:
    """Valida una clave. Devuelve {valid, customer, expires, reason}."""
    try:
        k = (key or "").strip().upper().replace(" ", "")
        if k.startswith(_PREFIX + "-"):
            k = k[len(_PREFIX) + 1:]
        blob = k.replace("-", "")
        if len(blob) < 16:
            return {"valid": False, "reason": "Clave demasiado corta."}
        sig_part = blob[-16:]            # 10 bytes -> 16 chars Base32
        body_part = blob[:-16]
        raw = _b32d(body_part)
        expected = _b32(hmac.new(secret, raw, hashlib.sha256).digest()[:10]).upper()
        if not hmac.compare_digest(expected, sig_part):
            return {"valid": False, "reason": "Firma inválida (clave no auténtica)."}
        payload = json.loads(raw.decode())
        exp = payload.get("e", 0)
        if exp and time.time() > exp:
            return {"valid": False, "reason": "Licencia expirada.",
                    "customer": payload.get("c", "")}
        return {"valid": True, "customer": payload.get("c", ""),
                "issued": payload.get("i", 0), "expires": exp, "reason": "OK"}
    except Exception:
        return {"valid": False, "reason": "Clave malformada."}


def license_status() -> dict:
    """Estado de la licencia instalada (config/license.key)."""
    origen = next((p for p in _license_sources() if p.exists()), None)
    if origen is None:
        return {"valid": False, "reason": "Sin licencia (modo prueba).",
                "licensed": False}
    try:
        key = origen.read_text(encoding="utf-8").strip()
    except OSError:
        return {"valid": False, "reason": "No se pudo leer la licencia.",
                "licensed": False}
    res = validate_key(key)
    res["licensed"] = res.get("valid", False)
    res["secure_signing"] = licensing_is_secure()
    return res


def install_key(key: str) -> dict:
    """Guarda una clave si es valida."""
    res = validate_key(key)
    if not res.get("valid"):
        return res
    try:
        _license_file().write_text(key.strip(), encoding="utf-8")
    except OSError as e:
        return {"valid": False, "reason": f"No se pudo guardar: {e}"}
    return res
