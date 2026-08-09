"""phishing.py — Deteccion heuristica de enlaces de phishing.

Analiza una URL y estima si es un intento de suplantacion, sin depender de
ningun servicio externo. Es la primera linea del filtro anti-phishing: rapida,
local y explicable. El sumidero DNS de la Pi (nivel de red) la complementa
bloqueando dominios ya catalogados; aqui se atrapa lo que aun no esta en
ninguna lista, razonando sobre la forma del enlace.

Cada senal suma puntos; el total decide el veredicto. Se devuelve el detalle de
por que, para que el usuario aprenda a reconocerlo, no solo para bloquear.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from sentinel.core.monitor import Finding, Severity

# TLD baratos o de registro abierto, muy usados en campanas de phishing.
_TLD_RIESGO = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "country", "kim", "loan", "men", "gdn", "review", "date", "racing", "stream",
    "rest", "fit", "cam", "surf",
}

# Marcas suplantadas con frecuencia. Si el nombre aparece en el host pero el
# dominio real no es el suyo, es un lookalike clasico.
_MARCAS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "bcp": "viabcp.com", "bbva": "bbva.pe", "interbank": "interbank.pe",
    "sunat": "sunat.gob.pe", "yape": "yape.com.pe",
}

_ACORTADORES = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
                "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyze_url(url: str) -> dict:
    """Analiza una URL. Devuelve veredicto, puntaje y razones."""
    razones: list[str] = []
    puntos = 0
    raw = (url or "").strip()
    if not raw:
        return {"url": url, "score": 0, "verdict": "vacio", "reasons": []}

    parsed = urlparse(raw if "//" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    dominio = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    # 1) Host que es una IP en vez de un dominio.
    if _IP_RE.match(host):
        puntos += 3; razones.append("El enlace usa una direccion IP en vez de un dominio.")

    # 2) Truco de la arroba: todo lo anterior a '@' se ignora, el navegador va a lo de despues.
    if "@" in raw.split("//", 1)[-1].split("/", 1)[0]:
        puntos += 3; razones.append("Contiene '@' en el host: oculta el destino real.")

    # 3) Punycode (dominios que imitan letras con caracteres unicode).
    if "xn--" in host:
        puntos += 3; razones.append("Dominio en punycode (xn--): puede imitar letras reales.")

    # 4) Sin HTTPS.
    if parsed.scheme == "http":
        puntos += 1; razones.append("No usa HTTPS.")

    # 5) Exceso de subdominios (a menudo para colar el nombre de una marca).
    if host.count(".") >= 4:
        puntos += 2; razones.append(f"Demasiados subdominios ({host.count('.')}).")

    # 6) TLD de riesgo.
    if tld in _TLD_RIESGO:
        puntos += 2; razones.append(f"Dominio de nivel superior sospechoso (.{tld}).")

    # 7) Acortador (esconde el destino).
    if dominio in _ACORTADORES:
        puntos += 1; razones.append(f"Es un acortador de enlaces ({dominio}).")

    # 8) Lookalike de marca: el nombre aparece pero el dominio real no coincide.
    for marca, real in _MARCAS.items():
        if marca in host and real and not host.endswith(real):
            puntos += 3
            razones.append(f"Suplanta a '{marca}': dice ser {marca} pero el dominio "
                           f"no es {real}.")
            break

    # 9) Muchos guiones o digitos en el dominio (generado automaticamente).
    nombre = dominio.split(".")[0] if dominio else ""
    if nombre.count("-") >= 3 or sum(c.isdigit() for c in nombre) >= 4:
        puntos += 1; razones.append("El dominio tiene forma de generado automaticamente.")

    # 10) URL muy larga (esconde la parte enganosa al final).
    if len(raw) > 100:
        puntos += 1; razones.append("El enlace es inusualmente largo.")

    if puntos >= 5:
        verdict, sev = "phishing", Severity.CRITICAL
    elif puntos >= 3:
        verdict, sev = "sospechoso", Severity.HIGH
    elif puntos >= 1:
        verdict, sev = "revisar", Severity.LOW
    else:
        verdict, sev = "limpio", Severity.INFO

    return {"url": raw, "host": host, "score": puntos, "verdict": verdict,
            "severity": sev, "reasons": razones}


def to_finding(result: dict) -> Finding | None:
    """Convierte el analisis en un Finding para el panel, si hay algo que reportar."""
    if result.get("score", 0) < 1:
        return None
    return Finding(
        category="phishing", severity=result["severity"],
        title=f"Enlace {result['verdict']}: {result.get('host') or result['url'][:40]}",
        detail="Analisis heuristico del enlace. " + " ".join(result["reasons"]),
        evidence={"url": result["url"], "puntaje": result["score"],
                  "senales": result["reasons"]},
        attack="T1566.002",   # Phishing: enlace malicioso
    )
