"""signing.py — Firma digital Ed25519 de la evidencia.

Un informe de auditoria solo vale como prueba si se puede demostrar que nadie lo
altero despues de emitirlo. Este modulo firma cualquier archivo (informe, JSON
de alcance, exportacion) con una clave Ed25519 del equipo, y permite verificar
esa firma con la clave publica. Si alguien cambia un solo byte, la verificacion
falla.

Ed25519: firma moderna, rapida y corta (64 bytes), del estandar actual. Se apoya
en la libreria `cryptography`, que ya viene con SENTINEL (no suma dependencia).

La clave PRIVADA vive en la carpeta escribible del equipo y nunca se comparte.
La clave PUBLICA se incrusta junto a la firma y se puede publicar sin riesgo:
sirve para que cualquiera verifique, pero no para falsificar.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

_KEY_NAME = "signing_ed25519.key"      # 32 bytes crudos de la clave privada


def _key_path() -> Path:
    from sentinel.core.config import user_config_dir
    return user_config_dir() / _KEY_NAME


def ensure_key() -> Ed25519PrivateKey:
    """Carga la clave de firma del equipo; la crea la primera vez."""
    p = _key_path()
    if p.exists():
        try:
            return Ed25519PrivateKey.from_private_bytes(p.read_bytes())
        except (ValueError, OSError):
            pass  # clave corrupta: se regenera abajo
    key = Ed25519PrivateKey.generate()
    try:
        p.write_bytes(key.private_bytes_raw())
        try:
            p.chmod(0o600)   # solo el dueno la lee (no-op en Windows)
        except OSError:
            pass
    except OSError:
        pass
    return key


def public_key_hex(key: Ed25519PrivateKey | None = None) -> str:
    key = key or ensure_key()
    return key.public_key().public_bytes_raw().hex()


def sign_bytes(data: bytes, key: Ed25519PrivateKey | None = None) -> str:
    """Firma bytes y devuelve la firma en hexadecimal."""
    key = key or ensure_key()
    return key.sign(data).hex()


def verify_bytes(data: bytes, signature_hex: str, public_key_hex_: str) -> bool:
    """Verifica una firma. False ante cualquier problema (nunca lanza)."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex_))
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


def sign_file(path: str | Path) -> Path:
    """Firma un archivo y escribe un sidecar '<archivo>.sig' con la firma y la
    clave publica. Devuelve la ruta del sidecar."""
    path = Path(path)
    key = ensure_key()
    data = path.read_bytes()
    sig = {
        "archivo": path.name,
        "algoritmo": "Ed25519",
        "firma": sign_bytes(data, key),
        "clave_publica": public_key_hex(key),
        "firmado_en": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    dest = path.with_suffix(path.suffix + ".sig")
    dest.write_text(json.dumps(sig, ensure_ascii=False, indent=2), encoding="utf-8")
    return dest


def verify_file(path: str | Path, sig_path: str | Path | None = None) -> bool:
    """Verifica un archivo contra su sidecar de firma."""
    path = Path(path)
    sig_path = Path(sig_path) if sig_path else path.with_suffix(path.suffix + ".sig")
    try:
        meta = json.loads(Path(sig_path).read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return False
    return verify_bytes(path.read_bytes(), meta.get("firma", ""),
                        meta.get("clave_publica", ""))
