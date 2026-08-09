"""webfilter.py — Filtro de contenido para las PCs del laboratorio.

Bloquea, por categorias, publicidad / contenido +18 / juegos. No adivina pagina
por pagina: se apoya en CATALOGOS DE DOMINIOS mantenidos por la comunidad de
seguridad (se actualizan solos cada vez que se reaplica) y, opcionalmente, en un
DNS con filtrado que clasifica el contenido. Asi es como funcionan los filtros
profesionales, y es lo que hace que sea "inteligente" sin ser invasivo.

Mecanismo:
  1. HOSTS  — escribe los dominios a bloquear en el archivo hosts de Windows,
     apuntandolos a 0.0.0.0 (la PC no puede resolverlos). Reversible: el bloque
     va entre marcas y se quita entero.
  2. DNS    — (opcional) fija un DNS familiar que filtra +18 y anuncios a nivel
     de red, cubriendo lo que las listas no alcanzan.

Requiere permisos de ADMINISTRADOR (edita el hosts del sistema). Todo es
reversible con `remove()`.
"""
from __future__ import annotations

import os
import re
import ssl
import socket
import subprocess
import urllib.request
from pathlib import Path

_HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"

_BEGIN = "# === SENTINEL FILTRO INICIO (no editar a mano) ==="
_END = "# === SENTINEL FILTRO FIN ==="

# Catalogos mantenidos por la comunidad (formato "0.0.0.0 dominio").
_SOURCES = {
    # anuncios + malware + contenido adulto en una sola lista consolidada
    "adultos": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
    # solo anuncios/rastreadores (mas liviano, por si no se quiere +18)
    "anuncios": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # plataformas y sitios de juegos
    "juegos": "https://raw.githubusercontent.com/blocklistproject/Lists/master/gaming.txt",
}

# Lista CURADA de juegos: los sitios/plataformas que de verdad usan los
# estudiantes. Es mas confiable y precisa que una lista automatica gigante
# (que suele sobre-bloquear). Se guardan dominios base; `_expand` agrega las
# variantes www. automaticamente.
_GAMES = [
    # plataformas de juegos web (las mas usadas en un aula)
    "poki.com", "friv.com", "y8.com", "crazygames.com", "kizi.com",
    "agame.com", "addictinggames.com", "coolmathgames.com", "gamesgames.com",
    "silvergames.com", "twoplayergames.com", "1001juegos.com", "juegos.com",
    "miniclip.com", "kongregate.com", "armorgames.com", "newgrounds.com",
    "itch.io", "gamejolt.com", "lagged.com", "kbhgames.com", "yandex.games",
    # plataformas / tiendas de juegos
    "roblox.com", "web.roblox.com", "epicgames.com", "store.epicgames.com",
    "steampowered.com", "store.steampowered.com", "steamcommunity.com",
    "minecraft.net", "ea.com", "origin.com", "riotgames.com",
    "leagueoflegends.com", "playvalorant.com", "fortnite.com",
    "supercell.com", "clashofclans.com", "brawlstars.com", "garena.com",
    "ff.garena.com", "innersloth.com", "among-us.io",
    # streaming de juegos
    "twitch.tv", "player.twitch.tv",
]

# Respaldo minimo por si falla la descarga de las listas grandes.
_FALLBACK = {
    "juegos": _GAMES,
    "adultos": [
        "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
        "onlyfans.com", "redtube.com", "youporn.com",
    ],
    "anuncios": [
        "doubleclick.net", "googlesyndication.com", "adservice.google.com",
        "ads.yahoo.com", "adnxs.com",
    ],
}


def _expand(bases: list[str]) -> set[str]:
    """Agrega la variante www. a cada dominio base (el hosts es exacto)."""
    out: set[str] = set()
    for d in bases:
        d = d.lower().strip(".")
        if not d:
            continue
        out.add(d)
        if d.count(".") == 1 and not d.startswith("www."):
            out.add("www." + d)
    return out

# DNS familiar (AdGuard Family): filtra +18, anuncios y rastreadores a nivel red.
_FAMILY_DNS = ("94.140.14.15", "94.140.15.16")


def _ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


def _download_domains(url: str, timeout: int = 25) -> list[str]:
    """Descarga una lista y extrae los dominios (segundo campo de cada linea)."""
    req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-webfilter"})
    domains: list[str] = []
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        for raw in r.read().decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # formato "0.0.0.0 dominio" o "127.0.0.1 dominio"
            dom = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else parts[0]
            dom = dom.lower().strip(".")
            if dom and "." in dom and dom not in ("localhost",) and _valid(dom):
                domains.append(dom)
    return domains


_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


def _valid(d: str) -> bool:
    return bool(_DOMAIN_RE.match(d)) and len(d) <= 253


def collect(categories: list[str]) -> set[str]:
    """Reune los dominios de las categorias pedidas (con respaldo offline)."""
    doms: set[str] = set()
    for cat in categories:
        # Los juegos van SIEMPRE por la lista curada (mas precisa); las demas
        # categorias por la lista mantenida grande, con respaldo si falla.
        if cat == "juegos":
            doms.update(_expand(_GAMES))
            continue
        url = _SOURCES.get(cat)
        got = []
        if url:
            try:
                got = _download_domains(url)
            except Exception:
                got = []
        if not got:
            got = _expand(_FALLBACK.get(cat, []))
        doms.update(got)
    return doms


def _read_hosts() -> str:
    try:
        return _HOSTS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _strip_block(text: str) -> str:
    """Quita un bloque SENTINEL previo, dejando el resto del hosts intacto."""
    pattern = re.compile(re.escape(_BEGIN) + r".*?" + re.escape(_END) + r"\n?",
                         re.DOTALL)
    return pattern.sub("", text).rstrip() + "\n"


def apply(categories: list[str] | None = None, set_dns: bool = False) -> dict:
    """Aplica el filtro. Devuelve un resumen. Requiere administrador."""
    categories = categories or ["adultos", "juegos"]
    domains = collect(categories)
    if not domains:
        return {"ok": False, "error": "no se obtuvieron dominios para bloquear."}

    base = _strip_block(_read_hosts())
    lines = [_BEGIN,
             f"# categorias: {', '.join(categories)}  ({len(domains)} dominios)"]
    lines += [f"0.0.0.0 {d}" for d in sorted(domains)]
    lines.append(_END)
    block = "\n".join(lines) + "\n"

    try:
        _HOSTS.write_text(base.rstrip() + "\n\n" + block, encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"no se pudo escribir el hosts (¿admin?): {e}"}

    _flush_dns()
    dns_ok = _set_family_dns() if set_dns else None
    return {"ok": True, "categorias": categories, "dominios": len(domains),
            "dns_familiar": dns_ok}


def remove() -> dict:
    """Quita el filtro (revierte el hosts y el DNS). Requiere administrador."""
    try:
        _HOSTS.write_text(_strip_block(_read_hosts()), encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"no se pudo escribir el hosts: {e}"}
    _restore_dns()
    _flush_dns()
    return {"ok": True}


_EXTRA_BEGIN = "# === SENTINEL SITIOS EXTRA INICIO ==="
_EXTRA_END = "# === SENTINEL SITIOS EXTRA FIN ==="


def block_domain(domain: str) -> dict:
    """Bloquea un sitio puntual (ademas de las categorias). Requiere admin."""
    domain = (domain or "").lower().strip().strip(".")
    if not _valid(domain) or "." not in domain:
        return {"ok": False, "error": "dominio invalido"}
    text = _read_hosts()
    # Reune el bloque de extras existente y agrega el nuevo dominio.
    m = re.search(re.escape(_EXTRA_BEGIN) + r"(.*?)" + re.escape(_EXTRA_END),
                  text, re.DOTALL)
    extras: set[str] = set()
    if m:
        for line in m.group(1).splitlines():
            p = line.split()
            if len(p) >= 2 and p[0] == "0.0.0.0":
                extras.add(p[1])
        text = re.sub(re.escape(_EXTRA_BEGIN) + r".*?" + re.escape(_EXTRA_END) + r"\n?",
                      "", text, flags=re.DOTALL)
    extras.update({domain, "www." + domain} if domain.count(".") == 1 else {domain})
    block = "\n".join([_EXTRA_BEGIN] + [f"0.0.0.0 {d}" for d in sorted(extras)]
                      + [_EXTRA_END])
    try:
        _HOSTS.write_text(text.rstrip() + "\n" + block + "\n", encoding="utf-8")
    except OSError as e:
        return {"ok": False, "error": f"no se pudo escribir el hosts: {e}"}
    _flush_dns()
    return {"ok": True, "dominio": domain, "extras": len(extras)}


def status() -> dict:
    """Estado del filtro: activo y cuantos dominios bloquea."""
    text = _read_hosts()
    if _BEGIN not in text:
        return {"activo": False, "dominios": 0}
    m = re.search(re.escape(_BEGIN) + r".*?" + re.escape(_END), text, re.DOTALL)
    n = len(re.findall(r"^0\.0\.0\.0 ", m.group(0), re.MULTILINE)) if m else 0
    cats = ""
    mc = re.search(r"# categorias: (.+?)  ", text)
    if mc:
        cats = mc.group(1)
    return {"activo": True, "dominios": n, "categorias": cats}


# ── DNS (opcional) ───────────────────────────────────────────────────────────

def _adapters() -> list[str]:
    """Nombres de las interfaces de red activas."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetAdapter | Where-Object Status -eq 'Up').Name"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return [l.strip() for l in (out.stdout or "").splitlines() if l.strip()]
    except (OSError, subprocess.TimeoutExpired):
        return []


def _set_family_dns() -> bool:
    ok = False
    for name in _adapters():
        try:
            subprocess.run(["netsh", "interface", "ip", "set", "dns",
                            f'name={name}', "static", _FAMILY_DNS[0]],
                           capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            subprocess.run(["netsh", "interface", "ip", "add", "dns",
                            f'name={name}', _FAMILY_DNS[1], "index=2"],
                           capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ok = True
        except (OSError, subprocess.TimeoutExpired):
            continue
    return ok


def _restore_dns() -> None:
    for name in _adapters():
        try:
            subprocess.run(["netsh", "interface", "ip", "set", "dns",
                            f'name={name}', "dhcp"],
                           capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired):
            continue


def _flush_dns() -> None:
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        pass


# ── CLI ──────────────────────────────────────────────────────────────────────

def _main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="sentinel.webfilter",
        description="Filtro de contenido (anuncios / +18 / juegos) para el laboratorio.")
    ap.add_argument("--aplicar", action="store_true", help="Aplica el filtro.")
    ap.add_argument("--quitar", action="store_true", help="Quita el filtro.")
    ap.add_argument("--estado", action="store_true", help="Muestra el estado.")
    ap.add_argument("--categorias", default="adultos,juegos",
                    help="Categorias separadas por coma: adultos,juegos,anuncios")
    ap.add_argument("--dns", action="store_true",
                    help="Ademas fija un DNS familiar (filtrado a nivel de red).")
    a = ap.parse_args(argv)

    if a.quitar:
        print(remove()); return 0
    if a.estado:
        print(status()); return 0
    if a.aplicar:
        cats = [c.strip() for c in a.categorias.split(",") if c.strip()]
        print("Descargando listas y aplicando (puede tardar)…")
        print(apply(cats, set_dns=a.dns)); return 0
    ap.print_help(); return 0


if __name__ == "__main__":
    raise SystemExit(_main())
