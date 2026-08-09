"""intel.py — Enriquecimiento con inteligencia externa (APIs), offline-first.

Suma contexto a los hallazgos consultando APIs de seguridad (CVE, reputacion de
IPs, feeds de phishing). Su regla de diseno responde al "no depender de nada":

  1. OFFLINE-FIRST — el motor funciona completo sin internet. El enriquecimiento
     es un extra: si no hay red, o no hay API key, la funcion devuelve vacio y
     nada se rompe.
  2. CON CACHE — cada respuesta se guarda; una segunda consulta no vuelve a
     salir a internet, y sigue sirviendo aunque despues no haya red.
  3. CON FALLBACK — para un mismo dato (p. ej. reputacion de IP) se intentan
     varios proveedores en orden; que uno se caiga no deja sin respuesta.

PRIVACIDAD — advertencia de diseno
----------------------------------
Consultar una API sobre una IP/hash/dominio del objetivo ENVIA ese dato a un
tercero. En un engagement eso puede exceder la autorizacion. Por eso el
enriquecimiento es opt-in por proveedor y queda registrado: se sabe que se
consulto y a quien.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# ── Catalogo de proveedores (la "base de conocimiento" de APIs) ──────────────

# needs_key: requiere API key.  free: uso gratuito.  enriches: tipo de dato.
PROVIDERS: tuple[dict, ...] = (
    {"id": "nvd",        "name": "NVD (NIST)",     "enriches": "cve",
     "needs_key": False, "free": True,  "key_path": ""},
    {"id": "virustotal", "name": "VirusTotal",     "enriches": "hash|url|domain",
     "needs_key": True,  "free": True,  "key_path": "analysis.virustotal_api_key"},
    {"id": "shodan",     "name": "Shodan",         "enriches": "ip",
     "needs_key": True,  "free": False, "key_path": "intel.shodan_api_key"},
    {"id": "abuseipdb",  "name": "AbuseIPDB",      "enriches": "ip",
     "needs_key": True,  "free": True,  "key_path": "intel.abuseipdb_api_key"},
    {"id": "greynoise",  "name": "GreyNoise",      "enriches": "ip",
     "needs_key": True,  "free": True,  "key_path": "intel.greynoise_api_key"},
    {"id": "openphish",  "name": "OpenPhish",      "enriches": "domain",
     "needs_key": False, "free": True,  "key_path": ""},
    {"id": "hibp",       "name": "Have I Been Pwned", "enriches": "email",
     "needs_key": True,  "free": False, "key_path": "intel.hibp_api_key"},
)


def _dotted(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def provider_status(settings: dict | None = None) -> list[dict]:
    """Estado de cada proveedor: si esta listo para usarse (sin tocar la red).

    Un proveedor esta 'listo' si no necesita key, o si su key esta configurada.
    Es 100% local: sirve al arranque para saber con que se cuenta.
    """
    if settings is None:
        try:
            from sentinel.core.config import load_settings
            settings = load_settings()
        except Exception:
            settings = {}
    out = []
    for p in PROVIDERS:
        key = _dotted(settings, p["key_path"]) if p["key_path"] else None
        listo = (not p["needs_key"]) or bool(key)
        out.append({**{k: p[k] for k in ("id", "name", "enriches", "needs_key", "free")},
                    "listo": listo})
    return out


# ── Cache en disco (permite responder sin red tras la primera consulta) ──────

def _cache_dir() -> Path:
    try:
        from sentinel.core.config import state_dir
        d = state_dir() / "intel_cache"
    except Exception:
        d = Path(".intel_cache")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(kind: str, value: str) -> Path:
    safe = "".join(c if c.isalnum() else "_" for c in f"{kind}_{value}")[:120]
    return _cache_dir() / f"{safe}.json"


def cache_get(kind: str, value: str, ttl: int = 86400) -> dict | None:
    """Lee de cache si existe y no expiro (ttl en segundos)."""
    p = _cache_key(kind, value)
    if not p.exists():
        return None
    try:
        blob = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None
    if time.time() - blob.get("_ts", 0) >= ttl:
        return None
    return blob.get("data")


def cache_set(kind: str, value: str, data: dict) -> None:
    try:
        _cache_key(kind, value).write_text(
            json.dumps({"_ts": time.time(), "data": data}, ensure_ascii=False),
            encoding="utf-8")
    except OSError:
        pass


# ── Capa HTTP (aislada para poder probar sin red) ────────────────────────────

def _http_get_json(url: str, headers: dict | None = None,
                   timeout: int = 12) -> dict | None:
    """GET que devuelve JSON o None. Nunca lanza: sin red, devuelve None y el
    enriquecimiento degrada con elegancia."""
    try:
        import httpx
        r = httpx.get(url, headers=headers or {}, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


# ── Enriquecimiento (offline-first + cache + fallback) ───────────────────────

def lookup_cve(cve: str, ttl: int = 604800) -> dict:
    """Detalle de un CVE via NVD (gratis, sin key). {} si no hay red."""
    cve = (cve or "").strip().upper()
    if not cve.startswith("CVE-"):
        return {}
    cached = cache_get("cve", cve, ttl)
    if cached is not None:
        return cached
    data = _http_get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
    resumen: dict = {}
    try:
        vuln = (data or {}).get("vulnerabilities", [])
        if vuln:
            c = vuln[0]["cve"]
            metrics = c.get("metrics", {})
            cvss = None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics and metrics[k]:
                    cvss = metrics[k][0]["cvssData"].get("baseScore")
                    break
            resumen = {
                "cve": cve,
                "cvss": cvss,
                "descripcion": next((d["value"] for d in c.get("descriptions", [])
                                     if d.get("lang") == "en"), ""),
            }
    except (KeyError, IndexError, TypeError):
        resumen = {}
    if resumen:
        cache_set("cve", cve, resumen)
    return resumen


def enrich(kind: str, value: str, providers: list[str] | None = None,
           settings: dict | None = None, ttl: int = 86400) -> dict:
    """Enriquece un dato probando los proveedores de ese tipo, con fallback.

    Devuelve el primer resultado no vacio. Si nada responde (offline, sin keys),
    devuelve {} sin lanzar: el llamador sigue con lo que tenga.
    """
    cached = cache_get(kind, value, ttl)
    if cached is not None:
        return cached
    disponibles = [p for p in provider_status(settings)
                   if p["listo"] and kind in p["enriches"].split("|")]
    if providers:
        disponibles = [p for p in disponibles if p["id"] in providers]
    for p in disponibles:
        data = _dispatch(p["id"], kind, value)
        if data:
            cache_set(kind, value, data)
            return data
    return {}


def _dispatch(provider_id: str, kind: str, value: str) -> dict:
    """Enruta a la implementacion concreta. Los que necesitan key y aun no
    estan implementados devuelven {} (el fallback prueba el siguiente)."""
    if provider_id == "nvd" and kind == "cve":
        return lookup_cve(value)
    # Los demas proveedores se conectan aqui a medida que se implementen.
    return {}
