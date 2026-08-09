"""Pruebas del protocolo agente/coordinador.

La firma es la unica barrera entre "solo los agentes del laboratorio reportan"
y "cualquiera en la red inyecta datos falsos". Se prueba a fondo.
"""
import time
from sentinel.net import protocol as P


TOKEN = "token-de-prueba-del-laboratorio"


def test_firma_valida_se_verifica():
    body = b'{"equipo":"PC-01"}'
    sig = P.sign(body, TOKEN)
    assert P.verify(body, sig, TOKEN) is True


def test_cuerpo_alterado_invalida_la_firma():
    sig = P.sign(b'{"score":40}', TOKEN)
    assert P.verify(b'{"score":95}', sig, TOKEN) is False


def test_token_distinto_no_verifica():
    body = b"hola"
    sig = P.sign(body, TOKEN)
    assert P.verify(body, sig, "otro-token") is False


def test_firma_vieja_se_rechaza():
    body = b"datos"
    viejo = str(int(time.time()) - 10000)
    sig = P.sign(body, TOKEN, ts=viejo)
    assert P.verify(body, sig, TOKEN) is False


def test_firma_del_futuro_tambien_se_rechaza():
    body = b"datos"
    futuro = str(int(time.time()) + 10000)
    sig = P.sign(body, TOKEN, ts=futuro)
    assert P.verify(body, sig, TOKEN) is False


def test_firma_malformada_no_revienta():
    assert P.verify(b"x", "sin-punto", TOKEN) is False
    assert P.verify(b"x", "", TOKEN) is False
    assert P.verify(b"x", "abc.def", TOKEN) is False


def test_sin_token_nunca_verifica():
    body = b"x"
    sig = P.sign(body, TOKEN)
    assert P.verify(body, sig, "") is False


def test_firma_incluye_marca_de_tiempo():
    sig = P.sign(b"x", TOKEN)
    ts, _, mac = sig.partition(".")
    assert ts.isdigit() and len(mac) == 64  # sha256 hex
