"""Pruebas de la firma Ed25519: lo que garantiza que la evidencia no se altero."""
from sentinel.core import signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_firma_y_verifica():
    key = Ed25519PrivateKey.generate()
    data = b"informe de auditoria - lab senati"
    sig = signing.sign_bytes(data, key)
    assert signing.verify_bytes(data, sig, signing.public_key_hex(key))


def test_detecta_manipulacion():
    key = Ed25519PrivateKey.generate()
    data = b"puntaje: 100"
    sig = signing.sign_bytes(data, key)
    # Cambiar un solo byte invalida la firma.
    assert not signing.verify_bytes(b"puntaje: 000", sig, signing.public_key_hex(key))


def test_otra_clave_no_valida():
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    data = b"x"
    sig = signing.sign_bytes(data, k1)
    assert not signing.verify_bytes(data, sig, signing.public_key_hex(k2))


def test_verificacion_tolera_basura():
    assert not signing.verify_bytes(b"x", "no-es-hex", "tampoco")


def test_firma_y_verifica_archivo(tmp_path, monkeypatch):
    monkeypatch.setattr(signing, "_key_path", lambda: tmp_path / "k.key")
    f = tmp_path / "informe.html"
    f.write_text("<h1>Auditoria</h1>", encoding="utf-8")
    sig_path = signing.sign_file(f)
    assert sig_path.exists()
    assert signing.verify_file(f)
    # Manipular el archivo rompe la verificacion.
    f.write_text("<h1>Alterado</h1>", encoding="utf-8")
    assert not signing.verify_file(f)
