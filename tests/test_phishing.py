"""Pruebas del filtro heuristico de phishing."""
from sentinel.core import phishing


def test_url_legitima_pasa_limpia():
    r = phishing.analyze_url("https://www.google.com/search?q=hola")
    assert r["verdict"] in ("limpio", "revisar")
    assert r["score"] <= 1


def test_suplantacion_de_marca():
    r = phishing.analyze_url("http://paypal.seguridad-login.tk/verificar")
    assert r["verdict"] in ("phishing", "sospechoso")
    assert any("paypal" in x.lower() for x in r["reasons"])


def test_ip_en_vez_de_dominio():
    r = phishing.analyze_url("http://192.168.10.5/login")
    assert r["score"] >= 3
    assert any("IP" in x for x in r["reasons"])


def test_truco_de_la_arroba():
    r = phishing.analyze_url("http://banco.com@sitiomalo.xyz/")
    assert r["score"] >= 3


def test_punycode_detectado():
    r = phishing.analyze_url("https://xn--pple-43d.com/")
    assert any("punycode" in x.lower() for x in r["reasons"])


def test_genera_finding_cuando_hay_riesgo():
    r = phishing.analyze_url("http://paypal.login-verify.tk/x")
    f = phishing.to_finding(r)
    assert f is not None and f.attack.startswith("T1566")


def test_no_genera_finding_si_esta_limpio():
    r = phishing.analyze_url("https://www.microsoft.com")
    assert phishing.to_finding(r) is None
