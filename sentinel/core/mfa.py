"""mfa.py — Segundo factor de autenticacion (TOTP, RFC 6238).

Agrega verificacion en dos pasos al acceso de SENTINEL: ademas del token de
administrador, se pide un codigo de 6 digitos que cambia cada 30 segundos y que
el operador obtiene de Google Authenticator, Authy o cualquier app compatible.

Es el mismo TOTP del estandar RFC 6238: un HMAC sobre el contador de tiempo,
truncado a N digitos. Se apoya en la misma familia criptografica que ya usa el
resto de SENTINEL (HMAC-SHA de `protocol.py` y `license.py`), asi que no suma
ninguna dependencia: todo sale de la libreria estandar.

Uso tipico:
    secret = generate_secret()                 # se guarda una vez por operador
    uri = provisioning_uri(secret, "Elvis", "SENTINEL")   # se pinta como QR
    ...
    if verify(secret, codigo_ingresado):       # en cada login, tras el token
        # segundo factor correcto
"""
from __future__ import annotations

import time
import hmac
import base64
import struct
import hashlib
import secrets
from urllib.parse import quote

_DIGEST = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(length: int = 20) -> str:
    """Secreto aleatorio en Base32 (lo que las apps de autenticacion esperan).

    20 bytes = 160 bits, el tamano recomendado por el RFC para SHA-1.
    """
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    """Decodifica el secreto Base32, tolerando minusculas, espacios y sin padding
    (asi el operador puede pegarlo como se lo muestre la app)."""
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def totp(secret: str, for_time: float | None = None, step: int = 30,
         digits: int = 6, algorithm: str = "SHA1", t0: int = 0) -> str:
    """Codigo TOTP para un instante dado (por defecto, ahora)."""
    if for_time is None:
        for_time = time.time()
    counter = int((for_time - t0) // step)
    key = _b32decode(secret)
    msg = struct.pack(">Q", counter)                       # contador de 8 bytes
    digestmod = _DIGEST.get(algorithm.upper(), hashlib.sha1)
    h = hmac.new(key, msg, digestmod).digest()
    # Truncamiento dinamico del RFC 4226.
    offset = h[-1] & 0x0F
    binary = ((h[offset] & 0x7F) << 24 | (h[offset + 1] & 0xFF) << 16 |
              (h[offset + 2] & 0xFF) << 8 | (h[offset + 3] & 0xFF))
    return str(binary % (10 ** digits)).zfill(digits)


def verify(secret: str, code: str, for_time: float | None = None,
           step: int = 30, digits: int = 6, algorithm: str = "SHA1",
           window: int = 1) -> bool:
    """Valida un codigo. `window=1` acepta el paso anterior y el siguiente para
    tolerar el desfase de reloj entre el telefono y el servidor.

    Comparacion en tiempo constante: no se filtra por cuanto tarda si el codigo
    es casi correcto.
    """
    if not code or not code.strip().isdigit():
        return False
    code = code.strip()
    if for_time is None:
        for_time = time.time()
    for w in range(-window, window + 1):
        candidato = totp(secret, for_time + w * step, step, digits, algorithm)
        if hmac.compare_digest(candidato, code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str = "SENTINEL",
                     digits: int = 6, step: int = 30,
                     algorithm: str = "SHA1") -> str:
    """URI otpauth:// para pintar como codigo QR y agregar a la app del telefono."""
    label = quote(f"{issuer}:{account}")
    params = (f"secret={secret}&issuer={quote(issuer)}"
              f"&digits={digits}&period={step}&algorithm={algorithm.upper()}")
    return f"otpauth://totp/{label}?{params}"
