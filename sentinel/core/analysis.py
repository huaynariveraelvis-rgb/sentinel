"""analysis.py — Analisis bajo demanda de archivos, URLs y hashes.

El usuario arrastra/elige un archivo (o pega una URL/hash) y SENTINEL lo
evalua:
  - Archivo: tamano, SHA-256, ubicacion sospechosa, extension peligrosa y
    (si hay clave de VirusTotal) reputacion del hash.
  - URL: host por IP, TLD sospechoso, sin HTTPS, IDN/punycode y (si hay clave)
    reputacion en VirusTotal.
  - Hash (SHA-256): consulta directa de reputacion.
Tambien permite poner un archivo en CUARENTENA (mover a una carpeta aislada,
de forma reversible). Nunca borra nada por su cuenta.
"""
from __future__ import annotations

import os
import json
import time
import hashlib
import ipaddress
import shutil
from pathlib import Path
from urllib.parse import urlparse

from sentinel.core.config import load_settings, state_dir


def _quarantine_dir() -> Path:
    """Carpeta de cuarentena, en la zona escribible del equipo.

    Se calcula al usarla, no al importar: empaquetado, `__file__` apunta
    dentro del bundle de solo lectura y aislar un archivo fallaba en silencio,
    que es el peor final posible para esta funcion.
    """
    return state_dir() / "quarantine"

# Extensiones ejecutables / de riesgo frecuente en adjuntos maliciosos.
_RISKY_EXT = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".ws", ".wsf", ".hta", ".ps1", ".jar", ".msi", ".lnk", ".reg",
    ".dll", ".cpl", ".gadget",
}
_RISKY_TLD = {
    ".zip", ".mov", ".top", ".xyz", ".tk", ".gq", ".ml", ".cf", ".ga",
    ".click", ".country", ".kim", ".work", ".party", ".gdn",
}


def _sha256(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(chunk), b""):
            h.update(blk)
    return h.hexdigest()


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _vt_key() -> str:
    return (load_settings().get("analysis", {}) or {}).get("virustotal_api_key", "")


def _vt_lookup(kind: str, ident: str) -> dict | None:
    """Consulta VirusTotal v3 si hay clave y requests disponible. kind:
    'files' | 'urls' | 'domains'. Devuelve un resumen o None."""
    key = _vt_key()
    if not key:
        return None
    try:
        import requests
    except ImportError:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/{kind}/{ident}"
        r = requests.get(url, headers={"x-apikey": key}, timeout=12)
        if r.status_code != 200:
            return {"available": False, "note": f"VT HTTP {r.status_code}"}
        stats = (r.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}))
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    except Exception:
        return None


def _verdict(risk: int) -> tuple[str, str]:
    """Mapea un puntaje de riesgo a (severidad, veredicto legible)."""
    if risk >= 5:
        return "ALTA", "Peligroso — no lo abras."
    if risk >= 2:
        return "MEDIA", "Sospechoso — trátalo con cuidado."
    return "BAJA", "Sin señales claras de peligro."


def analyze_file(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "type": "archivo", "target": path,
                "error": "No es un archivo accesible."}
    size = p.stat().st_size
    sha = _sha256(str(p))
    ext = p.suffix.lower()
    risk, notes = 0, []

    if ext in _RISKY_EXT:
        risk += 2
        notes.append(f"Extensión ejecutable/de riesgo ({ext}).")
    low = str(p).lower()
    if any(d in low for d in ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp")):
        risk += 1
        notes.append("Ubicado en una carpeta temporal/descargas.")
    # Doble extension enganosa (factura.pdf.exe)
    if p.name.count(".") >= 2 and ext in _RISKY_EXT:
        risk += 2
        notes.append("Doble extensión engañosa.")

    vt = _vt_lookup("files", sha)
    if vt and vt.get("available"):
        mal = vt.get("malicious", 0)
        if mal:
            risk += 5
            notes.append(f"VirusTotal: {mal} motores lo marcan como malicioso.")
        else:
            notes.append("VirusTotal: sin detecciones.")

    sev, verdict = _verdict(risk)
    return {
        "ok": True, "type": "archivo", "target": p.name,
        "details": {
            "ruta": str(p), "tamaño": _human_size(size), "sha256": sha,
            "extensión": ext or "(sin)",
        },
        "notes": notes or ["Sin indicadores de riesgo."],
        "virustotal": vt, "severity": sev, "verdict": verdict,
        "can_quarantine": True, "path": str(p),
    }


def analyze_url(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    risk, notes = 0, []

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        risk += 2
        notes.append("La URL usa una IP en vez de un dominio (típico de phishing).")
    if parsed.scheme != "https":
        risk += 1
        notes.append("Sin HTTPS: la conexión no está cifrada.")
    if host.startswith("xn--") or "xn--" in host:
        risk += 2
        notes.append("Dominio con punycode/IDN (posible suplantación visual).")
    for tld in _RISKY_TLD:
        if host.endswith(tld):
            risk += 2
            notes.append(f"Dominio con TLD de alto abuso ({tld}).")
            break
    if host.count("-") >= 3 or len(host) > 40:
        risk += 1
        notes.append("Dominio inusualmente largo o con muchos guiones.")

    vt = _vt_lookup("domains", host) if host else None
    if vt and vt.get("available"):
        mal = vt.get("malicious", 0)
        if mal:
            risk += 5
            notes.append(f"VirusTotal: {mal} motores marcan el dominio como malicioso.")

    sev, verdict = _verdict(risk)
    return {
        "ok": True, "type": "url", "target": url,
        "details": {"host": host, "esquema": parsed.scheme},
        "notes": notes or ["Sin indicadores claros de riesgo."],
        "virustotal": vt, "severity": sev, "verdict": verdict,
        "can_quarantine": False,
    }


def analyze_hash(h: str) -> dict:
    vt = _vt_lookup("files", h)
    notes, risk = [], 0
    if vt and vt.get("available"):
        mal = vt.get("malicious", 0)
        risk = 5 if mal else 0
        notes.append(f"VirusTotal: {mal} detecciones." if mal
                     else "VirusTotal: sin detecciones.")
    else:
        notes.append("Configura una clave de VirusTotal para consultar reputación de hashes.")
    sev, verdict = _verdict(risk)
    return {"ok": True, "type": "hash", "target": h, "details": {"sha256": h},
            "notes": notes, "virustotal": vt, "severity": sev,
            "verdict": verdict, "can_quarantine": False}


def analyze_target(target: str) -> dict:
    """Punto de entrada: decide si es archivo, URL o hash y analiza."""
    t = (target or "").strip().strip('"')
    if not t:
        return {"ok": False, "target": t, "error": "Nada que analizar."}
    if os.path.isfile(t):
        return analyze_file(t)
    low = t.lower()
    if low.startswith(("http://", "https://", "www.")) or ("." in t and "/" in t):
        return analyze_url(t)
    if len(t) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in t):
        return analyze_hash(t.lower())
    if "." in t and " " not in t:   # parece dominio
        return analyze_url(t)
    return {"ok": False, "target": t,
            "error": "No reconozco eso como archivo, URL o hash."}


def quarantine(path: str) -> dict:
    """Mueve un archivo a la carpeta de cuarentena (reversible)."""
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": "El archivo ya no existe."}
    quarantine_dir = _quarantine_dir()
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    dest = quarantine_dir / f"{stamp}__{p.name}.quarantine"
    try:
        shutil.move(str(p), str(dest))
        (dest.with_suffix(dest.suffix + ".json")).write_text(
            json.dumps({"original": str(p), "quarantined_at": stamp},
                       ensure_ascii=False), encoding="utf-8")
        _log_action("cuarentena", str(p), True, f"Aislado en {dest.name}")
        return {"ok": True, "message": f"En cuarentena: {p.name}",
                "quarantined": str(dest)}
    except OSError as e:
        _log_action("cuarentena", str(p), False, str(e))
        return {"ok": False, "error": f"No se pudo mover a cuarentena: {e}"}


def _log_action(action: str, target: str, ok: bool, detail: str) -> None:
    """Deja constancia de la accion; nunca interrumpe la operacion."""
    try:
        from sentinel.core.audit_log import record
        record(action, target=target, ok=ok, detail=detail)
    except Exception:
        pass
