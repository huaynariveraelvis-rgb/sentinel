"""Pruebas del segundo factor (TOTP). Ancladas a los vectores oficiales del
RFC 6238: si estos pasan, la implementacion es interoperable con Google
Authenticator, Authy y cualquier app estandar."""
import base64
import time

from sentinel.core import mfa

# Secreto del Apendice B del RFC 6238: ASCII "12345678901234567890".
_SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_vectores_oficiales_rfc6238():
    casos = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
             1234567890: "89005924", 2000000000: "69279037"}
    for t, esperado in casos.items():
        assert mfa.totp(_SECRET, for_time=t, digits=8, algorithm="SHA1") == esperado


def test_verifica_el_codigo_actual():
    s = mfa.generate_secret()
    assert mfa.verify(s, mfa.totp(s))


def test_rechaza_codigo_incorrecto():
    s = mfa.generate_secret()
    codigo = mfa.totp(s)
    malo = "000000" if codigo != "000000" else "111111"
    assert not mfa.verify(s, malo)


def test_rechaza_codigo_expirado():
    s = mfa.generate_secret()
    viejo = mfa.totp(s, for_time=time.time() - 120)   # 4 pasos atras
    assert not mfa.verify(s, viejo)


def test_tolera_desfase_de_un_paso():
    s = mfa.generate_secret()
    ahora = time.time()
    # El codigo del paso anterior sigue valido con window=1 (desfase de reloj).
    anterior = mfa.totp(s, for_time=ahora - 30)
    assert mfa.verify(s, anterior, for_time=ahora, window=1)


def test_secreto_es_base32_valido():
    s = mfa.generate_secret()
    # No debe lanzar: es Base32 decodificable.
    assert len(mfa._b32decode(s)) == 20


def test_uri_de_aprovisionamiento():
    uri = mfa.provisioning_uri("ABC234", "operador", "SENTINEL")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABC234" in uri and "issuer=SENTINEL" in uri
