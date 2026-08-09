"""evidence.py — Historial y evidencia de auditorias de SENTINEL.

Una herramienta de auditoria que no deja rastro documental no sirve para
auditar: sin registro no hay linea base, no hay comparacion antes/despues y
no hay nada que anexar a un informe.

Este modulo guarda cada auditoria en una base SQLite local y permite:

  * `record()`      — registrar una auditoria (equipo, puntaje, hallazgos).
  * `history()`     — ver auditorias anteriores de uno o todos los equipos.
  * `compare()`     — antes/despues de un mismo equipo (el indicador del PIM).
  * `pareto()`      — tabla de frecuencias: que falla y en cuantos equipos.
  * `export_json()` / `export_csv()` — evidencia documental.

PRIVACIDAD — decision de diseno
-------------------------------
Auditar equipos ajenos obliga a cuidar los datos. Por eso:

  * El equipo se identifica con una ETIQUETA que pone el auditor (PC-01) y
    con una huella derivada del nombre del host, no con el nombre en claro.
  * No se guardan nombres de usuario. Las rutas que los contienen se
    normalizan a %USERPROFILE% antes de escribir en disco.

Asi la evidencia se puede anexar a un informe sin exponer a nadie.
"""
from __future__ import annotations

import os
import re
import csv
import json
import time
import sqlite3
import hashlib
import platform
from pathlib import Path

from sentinel.core.config import data_dir, os_name

_DB_NAME = "auditorias.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    fecha        TEXT    NOT NULL,
    machine_id   TEXT    NOT NULL,
    label        TEXT    NOT NULL,
    so           TEXT    NOT NULL DEFAULT '',
    score        INTEGER,
    total        INTEGER NOT NULL DEFAULT 0,
    critica      INTEGER NOT NULL DEFAULT 0,
    alta         INTEGER NOT NULL DEFAULT 0,
    media        INTEGER NOT NULL DEFAULT 0,
    baja         INTEGER NOT NULL DEFAULT 0,
    info         INTEGER NOT NULL DEFAULT 0,
    payload      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_label ON audits(label, ts);

CREATE TABLE IF NOT EXISTS baselines (
    label        TEXT PRIMARY KEY,
    ts           REAL NOT NULL,
    fecha        TEXT NOT NULL,
    score        INTEGER,
    firmas       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT    NOT NULL,
    key          TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'pendiente',
    detail       TEXT    NOT NULL DEFAULT '',
    approved_by  TEXT    NOT NULL DEFAULT '',
    approved_ts  REAL    NOT NULL,
    done_ts      REAL
);
CREATE INDEX IF NOT EXISTS idx_rem_label ON remediations(label, status);

CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT    NOT NULL,
    command     TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pendiente',
    exit_code   INTEGER,
    stdout      TEXT    NOT NULL DEFAULT '',
    stderr      TEXT    NOT NULL DEFAULT '',
    queued_by   TEXT    NOT NULL DEFAULT '',
    queued_ts   REAL    NOT NULL,
    done_ts     REAL
);
CREATE INDEX IF NOT EXISTS idx_cmd_label ON commands(label, status);

CREATE TABLE IF NOT EXISTS checks (
    audit_id     INTEGER NOT NULL,
    key          TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    status       TEXT    NOT NULL,
    attack       TEXT    NOT NULL DEFAULT '',
    FOREIGN KEY(audit_id) REFERENCES audits(id)
);
CREATE INDEX IF NOT EXISTS idx_checks_key ON checks(key, status);
"""


def db_path() -> Path:
    return data_dir() / _DB_NAME


def _connect() -> sqlite3.Connection:
    # timeout=10: si otro hilo esta escribiendo, espera hasta 10 s en vez de
    # fallar al instante. Es el caso real del coordinador, donde varios agentes
    # del laboratorio pueden reportar a la vez.
    con = sqlite3.connect(str(db_path()), timeout=10)
    con.row_factory = sqlite3.Row
    # WAL permite un escritor y varios lectores sin bloquearse mutuamente:
    # sin esto, dos agentes reportando al mismo tiempo se pisaban con
    # "database is locked".
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=10000")
    except sqlite3.Error:
        pass
    con.executescript(_SCHEMA)
    return con


# ── Identidad y anonimizacion ────────────────────────────────────────────────

def machine_fingerprint() -> str:
    """Huella corta y estable del equipo, sin revelar su nombre.

    Deriva de nombre de host + procesador. Sirve para saber que dos auditorias
    son del MISMO equipo sin escribir el hostname en la evidencia.
    """
    seed = f"{platform.node()}|{platform.machine()}|{platform.processor()}"
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:12]


_USER_RE = re.compile(re.escape(os.environ.get("USERPROFILE", "\\\\__nope__")),
                      re.IGNORECASE)
_USERNAME = os.environ.get("USERNAME", "")

# El nombre de usuario solo se sustituye cuando aparece como SEGMENTO DE RUTA
# (precedido de barra y seguido de barra o fin). Sustituirlo en cualquier
# posicion romperia texto legitimo: un usuario llamado "Elvis" convertiria la
# marca "ELVIS SYSTEMS" en "%USER% SYSTEMS", y uno llamado "Admin" o "Sala"
# destrozaria frases completas del informe.
_USERNAME_RE = (
    re.compile(r"(?<=[\\/])" + re.escape(_USERNAME) + r"(?=[\\/]|\b)",
               re.IGNORECASE)
    if _USERNAME and len(_USERNAME) > 2 else None
)


def anonymize(text: str) -> str:
    """Quita el perfil y el nombre de usuario de una cadena."""
    if not isinstance(text, str) or not text:
        return text
    out = _USER_RE.sub("%USERPROFILE%", text)
    if _USERNAME_RE is not None:
        out = _USERNAME_RE.sub("%USER%", out)
    return out


def _scrub(obj):
    """Aplica anonimizacion recursivamente a un reporte completo."""
    if isinstance(obj, str):
        return anonymize(obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


# ── Registro ─────────────────────────────────────────────────────────────────

def record(report: dict, label: str, checks: list | None = None,
           machine_id: str | None = None) -> int:
    """Guarda una auditoria y devuelve su identificador.

    `label` es la etiqueta del equipo que asigna el auditor (p. ej. "PC-01").
    `machine_id` permite al coordinador guardar el reporte de un equipo REMOTO
    con la huella de ESE equipo (la que envio el agente), no la del coordinador.
    """
    label = (label or "SIN-ETIQUETA").strip()[:40]
    counts = (report or {}).get("counts", {}) or {}
    sev = counts.get("por_severidad", {}) or {}
    ts = time.time()
    clean = _scrub(report or {})
    mid = (machine_id or machine_fingerprint())[:32]

    checks_rows = []
    for c in (checks or []):
        d = c.to_dict() if hasattr(c, "to_dict") else dict(c)
        checks_rows.append((d.get("key", ""), d.get("title", ""),
                            d.get("status", ""), d.get("attack", "") or ""))

    con = _connect()
    try:
        cur = con.execute(
            "INSERT INTO audits (ts, fecha, machine_id, label, so, score, total, "
            "critica, alta, media, baja, info, payload) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
             mid, label,
             report.get("_so") or os_name(),
             report.get("hardening_score"), counts.get("total", 0),
             sev.get("CRITICA", 0), sev.get("ALTA", 0), sev.get("MEDIA", 0),
             sev.get("BAJA", 0), sev.get("INFO", 0),
             json.dumps(clean, ensure_ascii=False)))
        audit_id = int(cur.lastrowid)
        if checks_rows:
            con.executemany(
                "INSERT INTO checks (audit_id, key, title, status, attack) "
                "VALUES (?,?,?,?,?)",
                [(audit_id, *r) for r in checks_rows])
        con.commit()
        return audit_id
    finally:
        con.close()


# ── Consulta ─────────────────────────────────────────────────────────────────

def history(label: str | None = None, limit: int = 50) -> list[dict]:
    """Auditorias registradas, de la mas reciente a la mas antigua."""
    con = _connect()
    try:
        if label:
            rows = con.execute(
                "SELECT id, fecha, label, score, total, critica, alta, media "
                "FROM audits WHERE label = ? ORDER BY ts DESC LIMIT ?",
                (label, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT id, fecha, label, score, total, critica, alta, media "
                "FROM audits ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def load_last_report(label: str) -> dict | None:
    """Recupera el reporte completo de la ultima auditoria de un equipo.

    Permite regenerar un informe sin volver a escanear el equipo, util cuando
    ya se recorrio el laboratorio y solo falta la documentacion.
    """
    con = _connect()
    try:
        row = con.execute(
            "SELECT payload FROM audits WHERE label = ? ORDER BY ts DESC LIMIT 1",
            (label,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except ValueError:
            return None
    finally:
        con.close()


def latest_per_machine() -> list[dict]:
    """La auditoria mas reciente de cada equipo. Base de todos los agregados."""
    con = _connect()
    try:
        rows = con.execute(
            "SELECT a.* FROM audits a "
            "JOIN (SELECT label, MAX(ts) AS mx FROM audits GROUP BY label) m "
            "  ON a.label = m.label AND a.ts = m.mx "
            "ORDER BY a.label").fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def compare(label: str) -> dict | None:
    """Primera y ultima auditoria de un equipo: el antes/despues del PIM."""
    con = _connect()
    try:
        first = con.execute(
            "SELECT * FROM audits WHERE label = ? ORDER BY ts ASC LIMIT 1",
            (label,)).fetchone()
        last = con.execute(
            "SELECT * FROM audits WHERE label = ? ORDER BY ts DESC LIMIT 1",
            (label,)).fetchone()
        if not first or not last or first["id"] == last["id"]:
            return None
        s0 = first["score"] if first["score"] is not None else 0
        s1 = last["score"] if last["score"] is not None else 0
        return {
            "label": label,
            "antes": {"fecha": first["fecha"], "score": s0,
                      "alta": first["alta"], "media": first["media"]},
            "despues": {"fecha": last["fecha"], "score": s1,
                        "alta": last["alta"], "media": last["media"]},
            "mejora_puntos": s1 - s0,
            "mejora_pct": round(100 * (s1 - s0) / s0, 1) if s0 else None,
        }
    finally:
        con.close()


def pareto() -> dict:
    """Tabla de frecuencias para el diagrama de Pareto del Capitulo III.

    Cuenta, sobre la ULTIMA auditoria de cada equipo, en cuantos equipos falla
    cada control de blindaje. Devuelve las filas ordenadas de mayor a menor
    con el porcentaje acumulado ya calculado.
    """
    machines = latest_per_machine()
    total = len(machines)
    if not total:
        return {"equipos": 0, "filas": [], "puntaje_promedio": None}

    ids = [m["id"] for m in machines]
    con = _connect()
    try:
        q = ("SELECT key, title, attack, COUNT(*) AS n FROM checks "
             f"WHERE audit_id IN ({','.join('?' * len(ids))}) "
             "AND status IN ('fail','warn') GROUP BY key, title, attack "
             "ORDER BY n DESC, title ASC")
        rows = [dict(r) for r in con.execute(q, ids).fetchall()]
    finally:
        con.close()

    suma = sum(r["n"] for r in rows) or 1
    acumulado = 0.0
    filas = []
    for r in rows:
        pct = 100.0 * r["n"] / suma
        acumulado += pct
        filas.append({
            "control": r["title"],
            "key": r["key"],
            "attack": r["attack"],
            "equipos_afectados": r["n"],
            "porcentaje_equipos": round(100.0 * r["n"] / total, 1),
            "peso_relativo": round(pct, 1),
            "acumulado": round(acumulado, 1),
        })

    scores = [m["score"] for m in machines if m["score"] is not None]
    return {
        "equipos": total,
        "puntaje_promedio": round(sum(scores) / len(scores), 1) if scores else None,
        "filas": filas,
    }


# ── Linea base y desviacion ──────────────────────────────────────────────────

def signatures(report: dict) -> list[str]:
    """Firma estable de cada hallazgo, para comparar dos auditorias.

    Se usa categoria + titulo porque el titulo ya incorpora el dato que
    identifica al hallazgo (el puerto, el nombre de la tarea, el programa de
    arranque). Los hallazgos meramente informativos de conexiones salientes se
    excluyen: cambian en cada barrido y generarian desviaciones falsas.
    """
    out = set()
    for f in (report or {}).get("findings", []):
        titulo = f.get("title", "")
        if titulo.startswith("Conexion saliente"):
            continue  # volatil por naturaleza
        out.add(f"{f.get('category', '')}|{anonymize(titulo)}")
    return sorted(out)


def set_baseline(report: dict, label: str) -> int:
    """Fija el estado actual del equipo como referencia.

    Se toma cuando el equipo esta recien preparado y verificado. A partir de
    ahi, cualquier hallazgo nuevo es un cambio que alguien introdujo.
    """
    label = (label or "SIN-ETIQUETA").strip()[:40]
    firmas = signatures(report)
    con = _connect()
    try:
        con.execute(
            "INSERT INTO baselines (label, ts, fecha, score, firmas) "
            "VALUES (?,?,?,?,?) ON CONFLICT(label) DO UPDATE SET "
            "ts=excluded.ts, fecha=excluded.fecha, score=excluded.score, "
            "firmas=excluded.firmas",
            (label, time.time(), time.strftime("%Y-%m-%d %H:%M:%S"),
             report.get("hardening_score"),
             json.dumps(firmas, ensure_ascii=False)))
        con.commit()
        return len(firmas)
    finally:
        con.close()


def get_baseline(label: str) -> dict | None:
    con = _connect()
    try:
        row = con.execute("SELECT * FROM baselines WHERE label = ?",
                          (label,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["firmas"] = json.loads(d["firmas"])
        except ValueError:
            d["firmas"] = []
        return d
    finally:
        con.close()


def drift(report: dict, label: str) -> dict | None:
    """Compara el estado actual contra la linea base del equipo.

    Devuelve lo que APARECIO (posible cambio no autorizado) y lo que
    DESAPARECIO (normalmente, remediacion aplicada).
    """
    base = get_baseline(label)
    if not base:
        return None
    antes = set(base["firmas"])
    ahora = set(signatures(report))
    nuevos = sorted(ahora - antes)
    resueltos = sorted(antes - ahora)
    score_base = base.get("score")
    score_now = report.get("hardening_score")
    return {
        "label": label,
        "fecha_base": base["fecha"],
        "nuevos": [s.split("|", 1)[-1] for s in nuevos],
        "resueltos": [s.split("|", 1)[-1] for s in resueltos],
        "score_base": score_base,
        "score_actual": score_now,
        "score_delta": (score_now - score_base)
                       if (score_now is not None and score_base is not None) else None,
    }


# ── Exportacion ──────────────────────────────────────────────────────────────

def export_json(report: dict, label: str, dest: Path | None = None) -> Path:
    """Exporta una auditoria completa a JSON (evidencia para anexos)."""
    dest = Path(dest) if dest else data_dir() / "exportes"
    dest.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", label or "equipo")
    path = dest / f"auditoria_{safe}_{stamp}.json"
    payload = {
        "equipo": label,
        "huella": machine_fingerprint(),
        "fecha": time.strftime("%Y-%m-%d %H:%M:%S"),
        "so": os_name(),
        "puntaje_blindaje": report.get("hardening_score"),
        **_scrub(report or {}),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


def export_csv(report: dict, label: str, dest: Path | None = None) -> Path:
    """Exporta los hallazgos a CSV, abrible en Excel para los anexos del PIM."""
    dest = Path(dest) if dest else data_dir() / "exportes"
    dest.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", label or "equipo")
    path = dest / f"hallazgos_{safe}_{stamp}.csv"

    fecha = time.strftime("%Y-%m-%d %H:%M:%S")
    # utf-8-sig para que Excel en Windows respete los acentos.
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["equipo", "fecha", "categoria", "severidad", "hallazgo",
                    "detalle", "attack_id", "attack_tecnica", "cis"])
        for f in (report or {}).get("findings", []):
            ai = f.get("attack_info") or {}
            ev = f.get("evidence") or {}
            w.writerow([label, fecha, f.get("category", ""),
                        f.get("severity_label", ""),
                        anonymize(f.get("title", "")),
                        anonymize(f.get("detail", "")),
                        ai.get("id", ""), ai.get("name", ""),
                        ev.get("cis", "")])
    return path


def export_pareto_csv(dest: Path | None = None) -> Path | None:
    """Exporta la tabla de frecuencias consolidada del laboratorio."""
    data = pareto()
    if not data["filas"]:
        return None
    dest = Path(dest) if dest else data_dir() / "exportes"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"pareto_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["control", "equipos_afectados", "porcentaje_equipos",
                    "peso_relativo", "acumulado", "attack_id"])
        for r in data["filas"]:
            w.writerow([r["control"], r["equipos_afectados"],
                        r["porcentaje_equipos"], r["peso_relativo"],
                        r["acumulado"], r["attack"]])
    return path
