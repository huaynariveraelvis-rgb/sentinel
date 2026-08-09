"""Pruebas de la capa de inteligencia externa: offline-first, cache y fallback.

No se toca la red: la capa HTTP se sustituye por una funcion simulada. Lo que se
verifica es la logica que hace que el sistema NO dependa de ninguna API.
"""
import pytest

from sentinel.core import intel


@pytest.fixture(autouse=True)
def cache_temporal(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "_cache_dir", lambda: tmp_path)


def test_estado_proveedores_sin_red(monkeypatch):
    settings = {"analysis": {"virustotal_api_key": "xyz"}, "intel": {}}
    estado = {p["id"]: p for p in intel.provider_status(settings)}
    assert estado["nvd"]["listo"]                 # gratis, sin key
    assert estado["virustotal"]["listo"]          # key configurada
    assert not estado["shodan"]["listo"]          # key ausente


def test_lookup_cve_parsea_nvd(monkeypatch):
    fake = {"vulnerabilities": [{"cve": {
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        "descriptions": [{"lang": "en", "value": "RCE critica"}]}}]}
    monkeypatch.setattr(intel, "_http_get_json", lambda *a, **k: fake)
    r = intel.lookup_cve("CVE-2021-44228")
    assert r["cvss"] == 9.8 and "RCE" in r["descripcion"]


def test_cache_evita_segunda_llamada(monkeypatch):
    llamadas = {"n": 0}
    def _uno(*a, **k):
        llamadas["n"] += 1
        return {"vulnerabilities": [{"cve": {"metrics": {}, "descriptions": []}}]}
    monkeypatch.setattr(intel, "_http_get_json", _uno)
    intel.lookup_cve("CVE-2020-0001")
    intel.lookup_cve("CVE-2020-0001")          # deberia venir de cache
    assert llamadas["n"] == 1


def test_offline_degrada_sin_lanzar(monkeypatch):
    monkeypatch.setattr(intel, "_http_get_json", lambda *a, **k: None)  # sin red
    assert intel.lookup_cve("CVE-2019-0001") == {}
    assert intel.enrich("ip", "1.2.3.4", settings={"intel": {}}) == {}


def test_cache_expira(monkeypatch):
    intel.cache_set("cve", "CVE-X", {"cvss": 5})
    assert intel.cache_get("cve", "CVE-X", ttl=3600) == {"cvss": 5}
    # Con ttl=0, cualquier entrada se considera vencida.
    assert intel.cache_get("cve", "CVE-X", ttl=0) is None


def test_enrich_usa_cache_previa():
    intel.cache_set("ip", "8.8.8.8", {"reputacion": "limpia"})
    assert intel.enrich("ip", "8.8.8.8") == {"reputacion": "limpia"}
