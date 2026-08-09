"""report_html.py — Informe tecnico de auditoria en HTML (y PDF).

Genera un informe completo y AUTOCONTENIDO de una auditoria: un solo archivo
.html sin dependencias externas, que se abre en cualquier equipo y se puede
convertir a PDF o imprimir tal cual para anexarlo a un expediente.

Contenido del informe:
  1. Portada con veredicto y puntaje
  2. Resumen ejecutivo
  3. Los 16 controles de blindaje, con estado, riesgo y remediacion
  4. Hallazgos de vigilancia con su evidencia tecnica
  5. Matriz MITRE ATT&CK por tactica
  6. Evolucion historica y desviacion respecto a la linea base
  7. Registro de cambios aplicados
  8. Anexo metodologico

El PDF se produce con Chrome/Edge en modo headless, que respeta las reglas de
impresion del propio informe. Si no hay navegador disponible se avisa y queda
el HTML, que es igualmente imprimible desde el navegador del usuario.
"""
from __future__ import annotations

import html
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from sentinel import __product__, __vendor__, __version__
from sentinel.core.config import data_dir, os_name

# ── Presentacion ─────────────────────────────────────────────────────────────

_SEV_ORDER = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"]

_SEV_CLASS = {"CRITICA": "crit", "ALTA": "alta", "MEDIA": "media",
              "BAJA": "baja", "INFO": "info"}

_STATUS_TXT = {"ok": "Correcto", "warn": "Advertencia",
               "fail": "Falla", "unknown": "No evaluado"}

_STATUS_CLASS = {"ok": "ok", "warn": "media", "fail": "alta", "unknown": "info"}

# Orden de las tacticas segun la cadena de ataque, para que la matriz se lea
# de izquierda a derecha como avanzaria un atacante real.
_TACTIC_ORDER = [
    "Acceso inicial", "Ejecucion", "Persistencia", "Escalada de privilegios",
    "Evasion de defensas", "Acceso a credenciales", "Movimiento lateral",
    "Mando y control",
]


def _e(v) -> str:
    """Escapa cualquier valor para insertarlo en el HTML sin romperlo."""
    return html.escape("" if v is None else str(v), quote=True)


def _verdict(score, counts) -> tuple[str, str, str]:
    """(clase, titulo, explicacion) segun el estado global del equipo."""
    sev = (counts or {}).get("por_severidad", {}) or {}
    if sev.get("CRITICA"):
        return ("crit", "Compromiso probable",
                "Se detectaron indicios directos de compromiso. Requiere "
                "atencion inmediata antes de seguir usando el equipo.")
    if score is None:
        return ("info", "Auditoria incompleta",
                "No se pudo completar la evaluacion del blindaje.")
    if score >= 90 and not sev.get("ALTA"):
        return ("ok", "Equipo endurecido",
                "La configuracion de seguridad es solida y no hay exposiciones "
                "de alto riesgo pendientes.")
    if score >= 70:
        return ("media", "Proteccion parcial",
                "Las defensas basicas estan activas, pero quedan controles sin "
                "aplicar que amplian la superficie de ataque.")
    if score >= 40:
        return ("alta", "Exposicion elevada",
                "Varias defensas clave estan desactivadas o mal configuradas. "
                "El equipo es vulnerable a ataques conocidos.")
    return ("crit", "Exposicion critica",
            "La mayoria de las defensas del sistema estan ausentes. El equipo "
            "no deberia usarse en red hasta remediarlo.")


_CSS = """
:root{
  --paper:#fff; --ink:#0E1518; --soft:#3A4A4C; --muted:#5E6F71;
  --rule:#CBD5D1; --rule2:#E4EAE8; --surf:#F7F9F8;
  --accent:#0B5C4E; --wash:#E8F1EE;
  --crit:#8E1E17; --alta:#B4560C; --media:#8A6B00; --baja:#3E5A60; --ok:#1A5C42;
  --serif:Constantia,Cambria,"Palatino Linotype",Georgia,serif;
  --mono:Consolas,"Cascadia Mono","DejaVu Sans Mono",monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--serif);
     font-size:15px;line-height:1.55}
.wrap{max-width:1060px;margin:0 auto;padding:0 28px 64px}

.cover{border-bottom:2px solid var(--ink);padding:36px 0 22px;margin-bottom:26px}
.brand{font-family:var(--mono);font-size:.66rem;letter-spacing:.18em;
       text-transform:uppercase;color:var(--accent);margin:0 0 14px}
h1{font-size:2.5rem;line-height:1.05;margin:0 0 6px;font-weight:400;letter-spacing:-.02em}
.sub{color:var(--muted);margin:0;font-size:1.02rem}

.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
      gap:1px;background:var(--rule2);border:1px solid var(--rule2);margin:22px 0 26px}
.meta div{background:#fff;padding:10px 12px}
.meta dt{font-family:var(--mono);font-size:.6rem;letter-spacing:.13em;
         text-transform:uppercase;color:var(--muted);margin:0 0 3px}
.meta dd{margin:0;font-size:.92rem}

.verdict{display:grid;grid-template-columns:186px 1fr;gap:24px;align-items:center;
         border:1px solid var(--rule2);border-left:5px solid var(--accent);
         padding:20px 24px;margin-bottom:30px;background:var(--surf)}
.verdict.crit{border-left-color:var(--crit)} .verdict.alta{border-left-color:var(--alta)}
.verdict.media{border-left-color:var(--media)} .verdict.ok{border-left-color:var(--ok)}
.gauge{text-align:center}
.gauge b{display:block;font-size:3.6rem;line-height:1;font-weight:400;
         font-variant-numeric:tabular-nums}
.gauge span{font-family:var(--mono);font-size:.58rem;letter-spacing:.15em;
            text-transform:uppercase;color:var(--muted);display:block;margin-top:6px}
.verdict.crit .gauge b{color:var(--crit)} .verdict.alta .gauge b{color:var(--alta)}
.verdict.media .gauge b{color:var(--media)} .verdict.ok .gauge b{color:var(--ok)}
.verdict h2{margin:0 0 6px;font-size:1.32rem;border:0;padding:0}
.verdict p{margin:0;color:var(--soft);font-size:.95rem}

.track{display:flex;gap:2px;height:12px;margin:14px 0 6px;overflow:hidden}
.track i{display:block;height:100%}
.tracklbl{display:flex;flex-wrap:wrap;gap:14px;font-family:var(--mono);
          font-size:.66rem;color:var(--muted)}
.tracklbl b{font-weight:400;color:var(--ink)}

h2{font-size:1.34rem;font-weight:400;margin:38px 0 12px;padding-bottom:7px;
   border-bottom:1px solid var(--rule);letter-spacing:-.01em}
h2 em{font-style:normal;font-family:var(--mono);font-size:.5em;letter-spacing:.1em;
      color:var(--accent);display:block;margin-bottom:5px}
h3{font-size:1.02rem;margin:24px 0 8px}
p{margin:0 0 12px;max-width:74ch}

table{border-collapse:collapse;width:100%;font-size:.85rem;margin:0 0 18px}
.tw{overflow-x:auto;border:1px solid var(--rule2);margin-bottom:18px}
.tw table{margin:0}
th{text-align:left;font-family:var(--mono);font-size:.62rem;letter-spacing:.1em;
   text-transform:uppercase;font-weight:400;color:var(--muted);padding:8px 11px;
   border-bottom:1px solid var(--rule);white-space:nowrap;vertical-align:bottom}
td{padding:8px 11px;border-bottom:1px solid var(--rule2);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tr.zebra{background:var(--surf)}
.mono{font-family:var(--mono);font-size:.78rem;font-variant-numeric:tabular-nums}
.num{font-family:var(--mono);text-align:right;font-variant-numeric:tabular-nums;
     white-space:nowrap}

.chip{font-family:var(--mono);font-size:.58rem;letter-spacing:.09em;
      text-transform:uppercase;padding:2px 7px;border:1px solid currentColor;
      white-space:nowrap;display:inline-block}
.crit{color:var(--crit)} .alta{color:var(--alta)} .media{color:var(--media)}
.baja{color:var(--baja)} .info{color:var(--muted)} .ok{color:var(--ok)}

.ev{font-family:var(--mono);font-size:.72rem;color:var(--muted);
    background:var(--surf);padding:6px 9px;margin-top:6px;
    border-left:2px solid var(--rule);word-break:break-word}

.matrix{display:grid;grid-template-columns:repeat(auto-fit,minmax(184px,1fr));
        gap:1px;background:var(--rule2);border:1px solid var(--rule2);margin-bottom:18px}
.tac{background:#fff;padding:11px}
.tac h4{margin:0 0 8px;font-family:var(--mono);font-size:.6rem;letter-spacing:.11em;
        text-transform:uppercase;color:var(--accent);font-weight:400;
        padding-bottom:5px;border-bottom:1px solid var(--rule2)}
.tec{margin-bottom:8px}
.tec b{display:block;font-family:var(--mono);font-size:.72rem;font-weight:400;
       color:var(--ink)}
.tec span{display:block;font-size:.78rem;color:var(--soft);line-height:1.32}
.tec i{font-style:normal;font-family:var(--mono);font-size:.62rem;color:var(--muted)}

.note{background:var(--wash);border-left:3px solid var(--accent);padding:12px 16px;
      margin:0 0 18px;font-size:.9rem}
.note b{color:var(--accent)}
.empty{color:var(--muted);font-style:italic}

.foot{border-top:2px solid var(--ink);margin-top:44px;padding-top:12px;
      font-family:var(--mono);font-size:.66rem;color:var(--muted);
      display:flex;flex-wrap:wrap;gap:8px 26px;justify-content:space-between}

@media print{
  @page{size:A4;margin:15mm 13mm}
  body{font-size:9.6pt}
  *{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
  .wrap{max-width:none;padding:0}
  h2{break-before:page;break-after:avoid}
  .cover+*, h2:first-of-type{break-before:auto}
  table,.verdict,.note,.tac,tr{break-inside:avoid}
  thead{display:table-header-group}
  .tw{overflow:visible}
}
"""


# ── Bloques del informe ──────────────────────────────────────────────────────

def _sev_track(counts: dict) -> str:
    """Barra de distribucion de severidad, proporcional al numero real."""
    sev = (counts or {}).get("por_severidad", {}) or {}
    total = sum(sev.get(k, 0) for k in _SEV_ORDER) or 1
    colors = {"CRITICA": "var(--crit)", "ALTA": "var(--alta)",
              "MEDIA": "var(--media)", "BAJA": "var(--baja)",
              "INFO": "var(--rule)"}
    bars, labels = [], []
    for k in _SEV_ORDER:
        n = sev.get(k, 0)
        if not n:
            continue
        bars.append(f'<i style="flex:{n};background:{colors[k]}"></i>')
        labels.append(f'<span class="{_SEV_CLASS[k]}">{k.title()} <b>{n}</b></span>')
    if not bars:
        return ""
    return (f'<div class="track">{"".join(bars)}</div>'
            f'<div class="tracklbl">{"".join(labels)}</div>')


def _controls_table(checks: list) -> str:
    if not checks:
        return '<p class="empty">No se pudo auditar el blindaje del sistema.</p>'
    orden = {"fail": 0, "warn": 1, "unknown": 2, "ok": 3}
    filas = []
    for i, c in enumerate(sorted(checks, key=lambda x: orden.get(x.get("status"), 9))):
        st = c.get("status", "unknown")
        ai = c.get("attack_info") or {}
        rem = c.get("recommendation") or ""
        if c.get("reboot"):
            rem += " Requiere reiniciar el equipo."
        filas.append(
            f'<tr class="{"zebra" if i % 2 else ""}">'
            f'<td><b>{_e(c.get("title"))}</b></td>'
            f'<td><span class="chip {_STATUS_CLASS.get(st, "info")}">'
            f'{_STATUS_TXT.get(st, st)}</span></td>'
            f'<td>{_e(c.get("detail"))}'
            + (f'<div class="ev">Remediacion: {_e(rem)}</div>' if rem else "")
            + f'</td>'
            f'<td class="mono">{_e(ai.get("id", ""))}</td>'
            f'<td style="font-size:.78rem;color:var(--muted)">{_e(c.get("cis", ""))}</td>'
            f'</tr>')
    return (
        '<div class="tw"><table><thead><tr>'
        '<th>Control</th><th>Estado</th><th>Evaluacion y remediacion</th>'
        '<th>ATT&amp;CK</th><th>Referencia CIS</th>'
        f'</tr></thead><tbody>{"".join(filas)}</tbody></table></div>')


def _findings_table(findings: list, limite_info: int = 25) -> str:
    vig = [f for f in findings if f.get("category") != "blindaje"]
    if not vig:
        return '<p class="empty">Sin hallazgos de vigilancia.</p>'
    filas, info_mostrados, ocultos = [], 0, 0
    for f in vig:
        sev = f.get("severity_label", "INFO")
        if sev == "INFO":
            if info_mostrados >= limite_info:
                ocultos += 1
                continue
            info_mostrados += 1
        ai = f.get("attack_info") or {}
        ev = {k: v for k, v in (f.get("evidence") or {}).items()
              if k not in ("fix_command", "cis", "reboot") and v not in (None, "", [])}
        ev_txt = " · ".join(f"{k}: {v}" for k, v in list(ev.items())[:6])
        filas.append(
            f'<tr>'
            f'<td><span class="chip {_SEV_CLASS.get(sev, "info")}">{sev}</span></td>'
            f'<td style="font-family:var(--mono);font-size:.72rem;color:var(--muted)">'
            f'{_e(f.get("category"))}</td>'
            f'<td><b>{_e(f.get("title"))}</b><div style="color:var(--soft)">'
            f'{_e(f.get("detail"))}</div>'
            + (f'<div class="ev">{_e(ev_txt)}</div>' if ev_txt else "")
            + f'</td>'
            f'<td class="mono">{_e(ai.get("id", ""))}</td>'
            f'</tr>')
    extra = (f'<p class="empty">Se omiten {ocultos} hallazgos informativos '
             f'adicionales de inventario.</p>' if ocultos else "")
    return ('<div class="tw"><table><thead><tr>'
            '<th>Severidad</th><th>Area</th><th>Hallazgo</th><th>ATT&amp;CK</th>'
            f'</tr></thead><tbody>{"".join(filas)}</tbody></table></div>{extra}')


def _attack_matrix(coverage: dict) -> str:
    tecnicas = (coverage or {}).get("tecnicas") or []
    if not tecnicas:
        return '<p class="empty">No se evidenciaron tecnicas catalogadas.</p>'
    por_tactica: dict[str, list] = {}
    for t in tecnicas:
        por_tactica.setdefault(t.get("tactic") or "Sin clasificar", []).append(t)
    orden = {t: i for i, t in enumerate(_TACTIC_ORDER)}
    cols = []
    for tac in sorted(por_tactica, key=lambda x: orden.get(x, 99)):
        items = "".join(
            f'<div class="tec"><b>{_e(t["id"])}</b>'
            f'<span>{_e(t["name"])}</span>'
            f'<i>{t["hallazgos"]} hallazgo(s)</i></div>'
            for t in por_tactica[tac])
        cols.append(f'<div class="tac"><h4>{_e(tac)}</h4>{items}</div>')
    return f'<div class="matrix">{"".join(cols)}</div>'


def _history_block(hist: list, cmp_: dict | None) -> str:
    partes = []
    if cmp_:
        d = cmp_["mejora_puntos"]
        signo = "+" if d > 0 else ""
        sentido = ("mejoro" if d > 0 else "empeoro" if d < 0 else "no vario")
        partes.append(
            f'<div class="note"><b>Evolucion.</b> Entre la primera auditoria '
            f'({_e(cmp_["antes"]["fecha"])}) y esta, el puntaje de blindaje '
            f'{sentido} de <b>{cmp_["antes"]["score"]}</b> a '
            f'<b>{cmp_["despues"]["score"]}</b> ({signo}{d} puntos).</div>')
    if hist and len(hist) > 1:
        filas = "".join(
            f'<tr><td class="mono">{_e(h["fecha"])}</td>'
            f'<td class="num">{_e(h["score"] if h["score"] is not None else "-")}</td>'
            f'<td class="num">{h["alta"]}</td><td class="num">{h["media"]}</td>'
            f'<td class="num">{h["total"] if "total" in h.keys() else "-"}</td></tr>'
            for h in hist[:12])
        partes.append(
            '<div class="tw"><table><thead><tr><th>Fecha</th>'
            '<th class="num">Puntaje</th><th class="num">Altas</th>'
            '<th class="num">Medias</th><th class="num">Hallazgos</th>'
            f'</tr></thead><tbody>{filas}</tbody></table></div>')
    if not partes:
        partes.append('<p class="empty">Esta es la primera auditoria registrada '
                      'del equipo; no hay historico con el que comparar.</p>')
    return "".join(partes)


def _drift_block(dr: dict | None) -> str:
    if not dr:
        return ('<p class="empty">No hay linea base fijada para este equipo. '
                'Fijala con el equipo recien preparado para poder detectar '
                'cambios posteriores.</p>')
    if not dr["nuevos"] and not dr["resueltos"]:
        return (f'<div class="note"><b>Sin desviacion.</b> El equipo se mantiene '
                f'igual que cuando se fijo la linea base '
                f'({_e(dr["fecha_base"])}).</div>')
    bloques = []
    if dr["nuevos"]:
        li = "".join(f"<li>{_e(s)}</li>" for s in dr["nuevos"][:20])
        bloques.append(f'<h3>Aparecieron ({len(dr["nuevos"])})</h3><ul>{li}</ul>')
    if dr["resueltos"]:
        li = "".join(f"<li>{_e(s)}</li>" for s in dr["resueltos"][:20])
        bloques.append(f'<h3>Se resolvieron ({len(dr["resueltos"])})</h3><ul>{li}</ul>')
    return (f'<p>Comparado con la linea base del {_e(dr["fecha_base"])}:</p>'
            + "".join(bloques))


def _actions_block(acciones: list) -> str:
    if not acciones:
        return ('<p class="empty">SENTINEL no ha aplicado ningun cambio en este '
                'equipo.</p>')
    filas = "".join(
        f'<tr><td class="mono">{_e(a.get("ts"))}</td>'
        f'<td><span class="chip {"ok" if a.get("resultado") == "ok" else "alta"}">'
        f'{_e(a.get("resultado"))}</span></td>'
        f'<td>{_e(a.get("accion"))}</td>'
        f'<td class="mono" style="font-size:.7rem">{_e((a.get("objetivo") or "")[:110])}</td>'
        f'</tr>' for a in acciones[:25])
    return ('<div class="tw"><table><thead><tr><th>Fecha</th><th>Resultado</th>'
            '<th>Accion</th><th>Detalle</th></tr></thead>'
            f'<tbody>{filas}</tbody></table></div>')


# ── Ensamblado ───────────────────────────────────────────────────────────────

def build_report(report: dict, label: str, *, checks: list | None = None,
                 hist: list | None = None, cmp_: dict | None = None,
                 dr: dict | None = None, acciones: list | None = None) -> str:
    """Devuelve el informe completo como una cadena HTML autocontenida."""
    counts = report.get("counts", {}) or {}
    sev = counts.get("por_severidad", {}) or {}
    score = report.get("hardening_score")
    checks = checks if checks is not None else (report.get("hardening") or [])
    checks = [c if isinstance(c, dict) else c.to_dict() for c in checks]

    vclass, vtitle, vtext = _verdict(score, counts)
    fecha = time.strftime("%d/%m/%Y %H:%M")

    malos = [c for c in checks if c.get("status") in ("fail", "warn")]
    oks = [c for c in checks if c.get("status") == "ok"]
    unk = [c for c in checks if c.get("status") == "unknown"]
    cov = report.get("attack_coverage", {}) or {}

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de auditoria — {_e(label)}</title>
<style>{_CSS}</style></head><body><div class="wrap">

<header class="cover">
  <p class="brand">{_e(__product__)} &middot; Informe tecnico de auditoria de seguridad</p>
  <h1>Equipo {_e(label)}</h1>
  <p class="sub">Auditoria de configuracion, exposicion y persistencia en Windows</p>
</header>

<dl class="meta">
  <div><dt>Equipo</dt><dd>{_e(label)}</dd></div>
  <div><dt>Fecha</dt><dd>{_e(fecha)}</dd></div>
  <div><dt>Sistema</dt><dd>{_e(os_name())}</dd></div>
  <div><dt>Controles auditados</dt><dd>{len(checks)}</dd></div>
  <div><dt>Hallazgos</dt><dd>{counts.get("total", 0)}</dd></div>
  <div><dt>Herramienta</dt><dd>{_e(__product__)} v{_e(__version__)}</dd></div>
</dl>

<div class="verdict {vclass}">
  <div class="gauge"><b>{score if score is not None else "—"}</b>
    <span>Puntaje de blindaje</span></div>
  <div><h2>{_e(vtitle)}</h2><p>{_e(vtext)}</p></div>
</div>

<section>
  <h2><em>01</em>Resumen ejecutivo</h2>
  <p>Se auditaron <b>{len(checks)} controles de configuracion</b> del sistema y se
  analizaron procesos, conexiones de red, mecanismos de arranque y superficies de
  persistencia. La auditoria produjo <b>{counts.get("total", 0)} hallazgos</b>, de los
  cuales <b>{sev.get("CRITICA", 0) + sev.get("ALTA", 0)}</b> son de severidad alta o
  superior.</p>
  {_sev_track(counts)}
  <p style="margin-top:16px">De los controles evaluados, <b>{len(oks)}</b> estan
  correctos, <b>{len(malos)}</b> requieren accion y <b>{len(unk)}</b> no pudieron
  evaluarse. Los controles no evaluados <b>no penalizan el puntaje</b>: reportar como
  inseguro un dato que no se pudo leer distorsionaria el resultado.</p>
  {'<div class="note"><b>Atencion inmediata.</b> ' + _e(report.get("summary", "")) +
    '</div>' if report.get("summary") and sev.get("CRITICA") else ''}
</section>

<section>
  <h2><em>02</em>Controles de blindaje</h2>
  <p>Cada control corresponde a un area de endurecimiento de los CIS Benchmarks para
  Windows y mitiga una tecnica de ataque catalogada en MITRE ATT&amp;CK. Se ordenan
  poniendo primero lo que requiere accion.</p>
  {_controls_table(checks)}
</section>

<section>
  <h2><em>03</em>Hallazgos de vigilancia</h2>
  <p>Comportamientos y exposiciones detectados en procesos, red, arranque automatico
  y persistencia avanzada. Cada hallazgo incluye la evidencia tecnica que lo sustenta.</p>
  {_findings_table(report.get("findings", []))}
</section>

<section>
  <h2><em>04</em>Matriz MITRE ATT&amp;CK</h2>
  <p>Tecnicas de ataque a las que este equipo presenta exposicion, agrupadas por la
  tactica que persigue el atacante y ordenadas segun avanzaria una intrusion real.
  Se evidenciaron <b>{cov.get("total_tecnicas", 0)} tecnicas</b>.</p>
  {_attack_matrix(cov)}
</section>

<section>
  <h2><em>05</em>Evolucion del equipo</h2>
  {_history_block(hist or [], cmp_)}
</section>

<section>
  <h2><em>06</em>Desviacion respecto a la linea base</h2>
  {_drift_block(dr)}
</section>

<section>
  <h2><em>07</em>Registro de cambios aplicados</h2>
  <p>Toda correccion que {_e(__product__)} aplica queda registrada. Ninguna se ejecuta
  sin la autorizacion explicita de administrador del usuario.</p>
  {_actions_block(acciones or [])}
</section>

<section>
  <h2><em>08</em>Anexo metodologico</h2>
  <h3>Alcance</h3>
  <p>La auditoria es <b>local y de solo lectura</b>: examina unicamente el equipo donde
  se ejecuta. No sondea la red ni otros equipos, y no incorpora ninguna capacidad
  ofensiva.</p>
  <h3>Como se obtienen los datos</h3>
  <p>El estado del sistema se recoge mediante consultas de lectura al registro de
  Windows, a la interfaz de administracion (WMI/CIM) y a los servicios de seguridad del
  propio sistema operativo. La evaluacion de cada control se realiza despues, sobre los
  datos recogidos.</p>
  <h3>Severidades</h3>
  <p><b>Critica</b>: indicio directo de compromiso. <b>Alta</b>: exposicion explotable o
  persistencia sospechosa. <b>Media</b>: configuracion debil o comportamiento inusual.
  <b>Baja</b>: superficie de ataque no justificada. <b>Informativa</b>: inventario para
  comparar contra la linea base.</p>
  <h3>Limitaciones</h3>
  <p>Esta herramienta audita configuracion y comportamiento; <b>no sustituye a un
  antivirus</b>, cuya funcion es detectar codigo malicioso conocido. Sin privilegios de
  administrador la vision de la red es parcial, y en ese caso se indica expresamente en
  lugar de reportar un estado correcto.</p>
  <h3>Marcos de referencia</h3>
  <p>MITRE ATT&amp;CK (catalogo de tecnicas de ataque), CIS Benchmarks para Windows
  (configuracion segura) y NIST Cybersecurity Framework (funciones de defensa).</p>
</section>

<footer class="foot">
  <span>{_e(__product__)} v{_e(__version__)} &middot; {_e(__vendor__)}</span>
  <span>Equipo {_e(label)} &middot; {_e(fecha)}</span>
  <span>Documento de uso interno</span>
</footer>

</div></body></html>"""


def save_report(report: dict, label: str, dest: Path | None = None,
                **kw) -> Path:
    """Escribe el informe HTML y devuelve su ruta."""
    dest = Path(dest) if dest else data_dir() / "informes"
    dest.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (label or "equipo"))
    path = dest / f"informe_{safe}_{time.strftime('%Y%m%d_%H%M%S')}.html"
    path.write_text(build_report(report, label, **kw), encoding="utf-8")
    return path


# ── Conversion a PDF ─────────────────────────────────────────────────────────

def _find_browser() -> str | None:
    """Localiza Chrome o Edge, que saben imprimir a PDF sin interfaz."""
    for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if not base:
            continue
        for rel in (r"Google\Chrome\Application\chrome.exe",
                    r"Microsoft\Edge\Application\msedge.exe"):
            p = Path(base) / rel
            if p.exists():
                return str(p)
    for name in ("chrome", "msedge", "chromium"):
        found = shutil.which(name)
        if found:
            return found
    return None


def to_pdf(html_path: Path, pdf_path: Path | None = None) -> Path | None:
    """Convierte el informe a PDF. None si no hay navegador disponible."""
    browser = _find_browser()
    if not browser:
        return None
    html_path = Path(html_path)
    pdf_path = Path(pdf_path) if pdf_path else html_path.with_suffix(".pdf")
    profile = html_path.parent / ".navegador"
    url = html_path.resolve().as_uri()
    try:
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={profile}", "--virtual-time-budget=10000",
             "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", url],
            capture_output=True, timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return pdf_path if pdf_path.exists() else None
