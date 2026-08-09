"""audit.py — Herramienta de auditoria de campo de SENTINEL.

Pensada para recorrer un parque de equipos (un laboratorio, una oficina) y
dejar evidencia documental de cada uno: ejecuta la auditoria completa, la
registra en el historial y la exporta a JSON y CSV.

Uso:
  python -m sentinel.audit --equipo PC-01        Audita y registra un equipo
  python -m sentinel.audit --equipo PC-01 --sin-exportar   Solo registra
  python -m sentinel.audit --historial           Auditorias registradas
  python -m sentinel.audit --comparar PC-01      Antes/despues de un equipo
  python -m sentinel.audit --consolidado         Tabla de frecuencias (Pareto)

La etiqueta del equipo (--equipo) la pone el auditor. Usa nombres neutros
tipo PC-01, PC-02: la evidencia no debe contener datos personales.
"""
from __future__ import annotations

import sys
import argparse

from sentinel import __product__, __vendor__, __version__
from sentinel.core import evidence
from sentinel.core.monitor import full_scan
from sentinel.core.hardening import scan_hardening, hardening_score
from sentinel.core.persistence import scan_persistence
from sentinel.core.brain import heuristic_summary

_LINE = "-" * 68


def _utf8() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _head(subtitulo: str) -> None:
    print()
    print(f"  {__product__}  ·  {subtitulo}")
    print(f"  {__vendor__}  ·  v{__version__}")
    print(f"  {_LINE}")


def _bar(score: int, width: int = 28) -> str:
    filled = round(width * max(0, min(100, score)) / 100)
    return "[" + "#" * filled + "." * (width - filled) + f"] {score:>3}/100"


# ── Auditar un equipo ────────────────────────────────────────────────────────

def cmd_auditar(label: str, exportar: bool, informe: bool = False,
                pdf: bool = False) -> int:
    _head(f"Auditoria del equipo {label}")
    print("  Recogiendo estado del sistema…")
    print("    · procesos, red y arranque")
    print("    · blindaje de Windows (16 controles)")
    print("    · persistencia avanzada (tareas, servicios, WMI, USB)")

    checks, hard_findings = scan_hardening()
    score = hardening_score(checks)
    deep_findings = scan_persistence()
    report = full_scan(extra_findings=list(hard_findings) + list(deep_findings),
                       hardening=checks, hardening_score=score)

    counts = report["counts"]
    sev = counts["por_severidad"]

    print()
    print(f"  BLINDAJE   {_bar(score)}")
    print()
    print(f"  Hallazgos  {counts['total']:>4}   "
          f"CRITICA {sev.get('CRITICA', 0)}   ALTA {sev.get('ALTA', 0)}   "
          f"MEDIA {sev.get('MEDIA', 0)}   BAJA {sev.get('BAJA', 0)}")
    print(f"  {_LINE}")

    # Controles de blindaje que no estan correctos: lo accionable.
    malos = [c for c in checks if c.status in ("fail", "warn")]
    if malos:
        print("  CONTROLES A CORREGIR")
        for c in malos:
            marca = "FALLA" if c.status == "fail" else "AVISO"
            print(f"    {marca}  {c.title}")
            print(f"           {c.detail}")
            if c.reboot:
                print("           (la correccion requiere reiniciar)")
    else:
        print("  Todos los controles de blindaje estan correctos.")

    # Hallazgos de vigilancia relevantes (fuera del blindaje): procesos, red y
    # persistencia. Se muestran de MEDIA hacia arriba para no llenar la hoja.
    vigilancia = [f for f in report["findings"]
                  if f.get("category") != "blindaje"
                  and f.get("severity", 0) >= 2
                  and not (f.get("evidence") or {}).get("blocked")]
    if vigilancia:
        print()
        print("  HALLAZGOS DE VIGILANCIA")
        for f in vigilancia[:12]:
            ai = f.get("attack_info") or {}
            print(f"    {f['severity_label']:<8} {f['title']}")
            if ai.get("id"):
                print(f"             {ai['id']} · {ai['name']}")

    desconocidos = [c for c in checks if c.status == "unknown"]
    if desconocidos:
        print()
        print("  NO EVALUADOS (no puntuan)")
        for c in desconocidos:
            print(f"    -  {c.title}: {c.detail}")

    cov = report.get("attack_coverage", {})
    if cov.get("tecnicas"):
        print()
        print(f"  TECNICAS MITRE ATT&CK EVIDENCIADAS ({cov['total_tecnicas']})")
        for t in cov["tecnicas"]:
            print(f"    {t['id']:<11} x{t['hallazgos']:<4} {t['name']}")

    print()
    print(f"  {heuristic_summary(report)}")
    print(f"  {_LINE}")

    audit_id = evidence.record(report, label, checks)
    print(f"  Registrado en el historial con el numero {audit_id}.")

    if exportar:
        j = evidence.export_json(report, label)
        c = evidence.export_csv(report, label)
        print(f"  Evidencia JSON : {j}")
        print(f"  Evidencia CSV  : {c}")

    if informe or pdf:
        _emitir_informe(report, label, [c.to_dict() for c in checks], pdf)

    # Desviacion respecto a la linea base, si el equipo tiene una fijada.
    dr = evidence.drift(report, label)
    if dr:
        print()
        print(f"  DESVIACION RESPECTO A LA LINEA BASE ({dr['fecha_base']})")
        if dr["score_delta"] is not None:
            signo = "+" if dr["score_delta"] > 0 else ""
            print(f"    Puntaje: {dr['score_base']} -> {dr['score_actual']} "
                  f"({signo}{dr['score_delta']})")
        if dr["nuevos"]:
            print(f"    APARECIERON {len(dr['nuevos'])} hallazgo(s) nuevos:")
            for s in dr["nuevos"][:10]:
                print(f"      + {s}")
        if dr["resueltos"]:
            print(f"    SE RESOLVIERON {len(dr['resueltos'])}:")
            for s in dr["resueltos"][:10]:
                print(f"      - {s}")
        if not dr["nuevos"] and not dr["resueltos"]:
            print("    Sin cambios: el equipo se mantiene como se dejo.")

    prev = evidence.compare(label)
    if prev:
        d = prev["mejora_puntos"]
        signo = "+" if d > 0 else ""
        print()
        print(f"  COMPARATIVA DE {label}")
        print(f"    Primera auditoria ({prev['antes']['fecha']}): "
              f"{prev['antes']['score']}/100")
        print(f"    Esta auditoria    ({prev['despues']['fecha']}): "
              f"{prev['despues']['score']}/100")
        print(f"    Variacion: {signo}{d} puntos")
    print()
    return 0


# ── Historial ────────────────────────────────────────────────────────────────

def cmd_historial(label: str | None) -> int:
    _head("Historial de auditorias")
    rows = evidence.history(label)
    if not rows:
        print("  Todavia no hay auditorias registradas.")
        print("  Ejecuta:  python -m sentinel.audit --equipo PC-01")
        print()
        return 0
    print(f"  {'#':>4}  {'FECHA':<20} {'EQUIPO':<12} {'PUNTAJE':>7} "
          f"{'ALTA':>5} {'MEDIA':>6}")
    print(f"  {_LINE}")
    for r in rows:
        score = r["score"] if r["score"] is not None else "-"
        print(f"  {r['id']:>4}  {r['fecha']:<20} {r['label']:<12} "
              f"{str(score):>7} {r['alta']:>5} {r['media']:>6}")
    print()
    return 0


# ── Comparativa ──────────────────────────────────────────────────────────────

def cmd_comparar(label: str) -> int:
    _head(f"Comparativa del equipo {label}")
    c = evidence.compare(label)
    if not c:
        print(f"  Hacen falta al menos dos auditorias de '{label}' para comparar.")
        print()
        return 1
    print(f"  ANTES    {c['antes']['fecha']}")
    print(f"           {_bar(c['antes']['score'])}")
    print(f"           Hallazgos ALTA {c['antes']['alta']}, "
          f"MEDIA {c['antes']['media']}")
    print()
    print(f"  DESPUES  {c['despues']['fecha']}")
    print(f"           {_bar(c['despues']['score'])}")
    print(f"           Hallazgos ALTA {c['despues']['alta']}, "
          f"MEDIA {c['despues']['media']}")
    print(f"  {_LINE}")
    d = c["mejora_puntos"]
    signo = "+" if d > 0 else ""
    pct = f" ({signo}{c['mejora_pct']}%)" if c["mejora_pct"] is not None else ""
    print(f"  VARIACION DEL PUNTAJE DE BLINDAJE: {signo}{d} puntos{pct}")
    print()
    return 0


# ── Consolidado del parque ───────────────────────────────────────────────────

def cmd_consolidado(exportar: bool) -> int:
    _head("Consolidado del parque de equipos")
    data = evidence.pareto()
    if not data["filas"]:
        print("  No hay datos suficientes. Audita al menos un equipo primero.")
        print()
        return 1

    print(f"  Equipos auditados: {data['equipos']}")
    if data["puntaje_promedio"] is not None:
        print(f"  Puntaje de blindaje promedio: {data['puntaje_promedio']}/100")
    print(f"  {_LINE}")
    print("  TABLA DE FRECUENCIAS  (base del diagrama de Pareto)")
    print()
    print(f"  {'CONTROL':<38} {'EQUIPOS':>7} {'%EQ':>6} {'ACUM':>7}")
    print(f"  {_LINE}")
    for r in data["filas"]:
        print(f"  {r['control'][:37]:<38} {r['equipos_afectados']:>7} "
              f"{r['porcentaje_equipos']:>5}% {r['acumulado']:>6}%")
    print(f"  {_LINE}")
    print("  Las primeras filas concentran la mayor parte del problema:")
    print("  son las que justifican la intervencion.")

    if exportar:
        p = evidence.export_pareto_csv()
        if p:
            print()
            print(f"  Tabla exportada: {p}")
    print()
    return 0


# ── Informe ──────────────────────────────────────────────────────────────────

def _emitir_informe(report: dict, label: str, checks: list, pdf: bool) -> None:
    """Genera el informe HTML (y el PDF si se pide) y lo anuncia."""
    from sentinel.core import report_html
    from sentinel.core.audit_log import read as leer_acciones

    ruta = report_html.save_report(
        report, label, checks=checks,
        hist=evidence.history(label, limit=12),
        cmp_=evidence.compare(label),
        dr=evidence.drift(report, label),
        acciones=leer_acciones(25))
    print(f"  Informe HTML : {ruta}")

    if pdf:
        print("  Generando PDF…")
        p = report_html.to_pdf(ruta)
        if p:
            print(f"  Informe PDF  : {p}")
        else:
            print("  No se encontro Chrome ni Edge para generar el PDF.")
            print("  Abre el HTML en tu navegador y usa Imprimir > Guardar como PDF.")


def cmd_informe(label: str, pdf: bool) -> int:
    """Genera el informe de la ultima auditoria guardada, sin volver a escanear."""
    _head(f"Informe del equipo {label}")
    report = evidence.load_last_report(label)
    if report is None:
        print(f"  No hay ninguna auditoria registrada de '{label}'.")
        print(f"  Audita primero:  python -m sentinel.audit --equipo {label}")
        print()
        return 1
    checks = report.get("hardening") or []
    print(f"  Recuperada la ultima auditoria ({len(report.get('findings', []))} "
          f"hallazgos, puntaje {report.get('hardening_score')}).")
    _emitir_informe(report, label, checks, pdf)
    print()
    return 0


# ── Linea base ───────────────────────────────────────────────────────────────

def cmd_linea_base(label: str) -> int:
    _head(f"Fijar linea base del equipo {label}")
    print("  Fotografiando el estado actual del equipo…")
    checks, hard_findings = scan_hardening()
    score = hardening_score(checks)
    deep = scan_persistence()
    report = full_scan(extra_findings=list(hard_findings) + list(deep),
                       hardening=checks, hardening_score=score)
    n = evidence.set_baseline(report, label)
    print()
    print(f"  Linea base fijada para {label}.")
    print(f"    Estado registrado : {n} elementos")
    print(f"    Puntaje de partida: {score}/100")
    print()
    print("  A partir de ahora, cada auditoria de este equipo mostrara que")
    print("  apareció y qué se resolvió respecto a este momento.")
    print()
    return 0


# ── Registro de acciones ─────────────────────────────────────────────────────

def cmd_acciones() -> int:
    from sentinel.core.audit_log import read, log_path
    _head("Registro de cambios aplicados")
    filas = read(60)
    if not filas:
        print("  SENTINEL no ha aplicado ningun cambio todavia.")
        print()
        return 0
    print(f"  {'FECHA':<20} {'RESULT':<7} ACCION")
    print(f"  {_LINE}")
    for r in filas:
        print(f"  {r.get('ts',''):<20} {r.get('resultado','-'):<7} "
              f"{r.get('accion','')}")
        obj = (r.get("objetivo") or "")[:88]
        if obj:
            print(f"  {'':<28} {obj}")
    print()
    print(f"  Archivo: {log_path()}")
    print()
    return 0


# ── Entrada ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    _utf8()
    ap = argparse.ArgumentParser(
        prog="sentinel.audit",
        description="Auditoria de campo de SENTINEL: audita, registra y exporta.")
    ap.add_argument("--equipo", "-e", metavar="ETIQUETA",
                    help="Audita este equipo y lo registra (ej. PC-01).")
    ap.add_argument("--historial", action="store_true",
                    help="Muestra las auditorias registradas.")
    ap.add_argument("--comparar", metavar="ETIQUETA",
                    help="Compara la primera y la ultima auditoria de un equipo.")
    ap.add_argument("--consolidado", action="store_true",
                    help="Tabla de frecuencias de todo el parque (Pareto).")
    ap.add_argument("--linea-base", dest="linea_base", metavar="ETIQUETA",
                    help="Fija el estado actual del equipo como referencia. "
                         "Usalo con el equipo recien preparado y verificado.")
    ap.add_argument("--acciones", action="store_true",
                    help="Muestra el registro de cambios aplicados por SENTINEL.")
    ap.add_argument("--informe", nargs="?", const="", metavar="ETIQUETA",
                    help="Genera el informe tecnico en HTML. Sin valor, lo hace "
                         "del equipo que se acaba de auditar; con una etiqueta, "
                         "lo genera de la ultima auditoria guardada de ese equipo.")
    ap.add_argument("--pdf", action="store_true",
                    help="Convierte el informe a PDF (implica --informe).")
    ap.add_argument("--sin-exportar", dest="sin_exportar", action="store_true",
                    help="No genera los archivos de evidencia.")
    args = ap.parse_args(argv)

    if args.linea_base:
        return cmd_linea_base(args.linea_base)
    if args.acciones:
        return cmd_acciones()
    # --informe con etiqueta y sin --equipo: informe de lo ya guardado.
    if args.informe and not args.equipo:
        return cmd_informe(args.informe, pdf=args.pdf)
    if args.equipo:
        return cmd_auditar(args.equipo, exportar=not args.sin_exportar,
                           informe=args.informe is not None, pdf=args.pdf)
    if args.comparar:
        return cmd_comparar(args.comparar)
    if args.consolidado:
        return cmd_consolidado(exportar=not args.sin_exportar)
    if args.historial:
        return cmd_historial(None)

    ap.print_help()
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
