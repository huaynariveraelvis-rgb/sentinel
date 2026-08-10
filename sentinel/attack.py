"""attack.py — Lanzador del motor OFENSIVO (Auditor / red team) de SENTINEL.

Es la contraparte roja de `audit.py`. En vez de blindar la maquina local, audita
OTROS equipos por la red encadenando las fases del Auditor —reconocimiento,
enumeracion y deteccion de vulnerabilidades— siempre bajo el guardian de alcance
(`core/auditor/scope.py`).

Regla de oro, heredada del modulo auditor e inviolable:
    sin un archivo de alcance valido, NO se toca nada. Cada objetivo cruza el
    guardian antes de cada sonda; una IP fuera de alcance corta la operacion.

Corre en Linux (Kali / Raspberry). Orquesta herramientas reconocidas del
sistema (nmap, whatweb, nikto, sslscan, nuclei...); no reimplementa exploits.

Uso tipico:
  python -m sentinel.attack --arsenal
      Lista el arsenal y que herramientas estan instaladas. No toca la red.

  python -m sentinel.attack --verificar --scope alcance.json
      Valida el alcance y muestra disponibilidad de herramientas. Nada se toca.

  python -m sentinel.attack --scope alcance.json
      Ejecuta las fases AUTORIZADAS por el alcance (recon + enum + vuln).

  python -m sentinel.attack --scope alcance.json --fase recon
      Ejecuta solo una fase (o varias: --fase recon,enum).

  python -m sentinel.attack --scope alcance.json --exploit-scripts
      Si el alcance autoriza 'exploit', PREPARA scripts .rc de Metasploit (con el
      'run' comentado) para que el operador los revise y ejecute a mano. No
      dispara nada.

  export OPENROUTER_API_KEY=sk-or-...
  python -m sentinel.attack --chat --scope alcance.json
      SENTINEL Rojo: le HABLAS en español ("reconoce el alcance", "audita todo")
      y el orquesta el Auditor. El cerebro (LLM via OpenRouter) decide que
      herramienta usar; el guardian de alcance sigue entre el modelo y la red.
"""
from __future__ import annotations

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

from sentinel import __product__, __vendor__, __version__
from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import load_scope, ScopeError
from sentinel.core.auditor import recon, enum, vuln, toolkit, exploit
from sentinel.core.auditor.targets import derive_targets, is_web, is_tls, is_smb

_LINE = "-" * 68


def _utf8() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _head(subtitulo: str) -> None:
    print()
    print(f"  {__product__} Auditor  ·  {subtitulo}")
    print(f"  {__vendor__}  ·  v{__version__}")
    print(f"  {_LINE}")


# ── Encabezado del alcance ────────────────────────────────────────────────────

def _print_scope(scope) -> None:
    s = scope.summary()
    print(f"  Engagement : {s['engagement']}")
    print(f"  Autoriza   : {s['autorizado_por']}  (ref {s['referencia'] or 's/n'})")
    print(f"  Operador   : {s['operador'] or 's/n'}")
    print(f"  Objetivos  : {', '.join(s['objetivos'])}")
    if s["excluidos"]:
        print(f"  Excluidos  : {', '.join(s['excluidos'])}")
    print(f"  Ventana    : {s['ventana']}")
    print(f"  Fases      : {', '.join(s['fases']) or '(ninguna)'}")
    print(f"  {_LINE}")


# ── Comando: arsenal ──────────────────────────────────────────────────────────

def cmd_arsenal() -> int:
    _head("Arsenal de herramientas (catalogo Kali)")
    fases_orden = ("recon", "enum", "vuln", "creds", "exploit",
                   "postex", "wireless", "web")
    por_fase: dict[str, list] = {}
    for t in toolkit.ARSENAL:
        por_fase.setdefault(t.phase, []).append(t)
    total = ok = 0
    for fase in fases_orden:
        tools = por_fase.get(fase)
        if not tools:
            continue
        print(f"  {fase.upper()}")
        for t in tools:
            total += 1
            hay = t.installed()
            ok += 1 if hay else 0
            marca = "OK   " if hay else "falta"
            modo = "auto " if t.mode == "auto" else "gated"
            print(f"    [{marca}] {modo} {t.name:<16} {t.attack:<11} {t.desc}")
        print()
    print(f"  {_LINE}")
    print(f"  Instaladas: {ok}/{total}. 'gated' = intrusiva, no se dispara sola.")
    print()
    return 0


# ── Comando: verificar (no toca la red) ───────────────────────────────────────

def cmd_verificar(scope_path: str | None) -> int:
    _head("Verificacion previa (no se toca ningun equipo)")
    if scope_path:
        try:
            scope = load_scope(scope_path)
        except ScopeError as e:
            print(f"  ALCANCE INVALIDO: {e}")
            print()
            return 2
        _print_scope(scope)
        abierta = scope.window_open()
        print(f"  Ventana ahora: {'ABIERTA' if abierta else 'CERRADA'}")
        pendientes = [p for p in ("recon", "enum", "vuln")
                      if p in scope.allowed_phases]
        print(f"  Fases ejecutables por este lanzador: "
              f"{', '.join(pendientes) or '(ninguna)'}")
    else:
        print("  (sin --scope: solo se comprueba el arsenal)")
        print(f"  {_LINE}")

    print()
    print(f"  nmap instalado : {'si' if recon.nmap_available() else 'NO (sudo apt install nmap)'}")
    faltan = [t.name for t in toolkit.ARSENAL
              if t.phase in ("recon", "enum", "vuln") and not t.installed()]
    if faltan:
        print(f"  Herramientas de recon/enum/vuln ausentes ({len(faltan)}):")
        print(f"    {', '.join(faltan)}")
        print("    Las ausentes simplemente se saltan; instala las que necesites.")
    else:
        print("  Todas las herramientas de recon/enum/vuln estan instaladas.")
    print()
    return 0


# ── Comando: auditar (ejecuta las fases autorizadas) ──────────────────────────

def cmd_auditar(scope_path: str, fases_pedidas: list[str] | None,
                out_dir: str, exportar: bool, exploit_scripts: bool) -> int:
    try:
        scope = load_scope(scope_path)
    except ScopeError as e:
        _head("Auditoria ofensiva")
        print(f"  ALCANCE INVALIDO: {e}")
        print("  El Auditor no opera sin una autorizacion cargada y valida.")
        print()
        return 2

    _head(f"Auditoria ofensiva — {scope.engagement}")
    _print_scope(scope)

    if not scope.window_open():
        print("  FUERA DE VENTANA: el alcance no autoriza operar en este momento.")
        print(f"  Autorizado entre {scope.window_start} y {scope.window_end}.")
        print()
        return 3

    if not scope.phase_allowed("recon"):
        print("  El alcance no autoriza 'recon'. El Auditor necesita reconocer")
        print("  para ubicar objetivos: agrega 'recon' a allowed_phases.")
        print()
        return 5

    if not recon.nmap_available():
        print("  nmap no esta instalado. En Kali: sudo apt install nmap")
        print()
        return 4

    # Que fases correr: interseccion de lo pedido con lo autorizado.
    ejecutables = [p for p in ("enum", "vuln") if scope.phase_allowed(p)]
    if fases_pedidas:
        for p in fases_pedidas:
            if p in ("enum", "vuln") and p not in scope.allowed_phases:
                print(f"  (fase '{p}' pedida pero NO autorizada en el alcance: se salta)")
        fases = [p for p in ("enum", "vuln")
                 if p in fases_pedidas and p in scope.allowed_phases]
    else:
        fases = ejecutables

    findings: list[Finding] = []

    # [1] RECONOCIMIENTO — siempre, para ubicar objetivos.
    print()
    print("  [1] RECONOCIMIENTO")
    print("      nmap: descubrimiento + puertos/servicios sobre el alcance…")
    try:
        recon_f = recon.scan_scope(scope)
    except ScopeError as e:
        print(f"      cortado por el guardian: {e}")
        print()
        return 6
    findings.extend(recon_f)
    targets = derive_targets(recon_f)
    print(f"      {len(targets)} equipo(s) con puertos abiertos en el alcance.")

    # [2] ENUMERACION
    if "enum" in fases and targets:
        print()
        print("  [2] ENUMERACION")
        for ip in sorted(targets):
            ports = targets[ip]
            for e in ports:
                if is_web(e):
                    _safe(findings, f"      web {ip}:{e['port']} (whatweb/nikto)",
                          lambda e=e, ip=ip: enum.enum_web(scope, ip, e["port"]))
                    if is_tls(e):
                        _safe(findings, f"      tls {ip}:{e['port']} (sslscan)",
                              lambda e=e, ip=ip: enum.enum_tls(scope, ip, e["port"]))
            if any(is_smb(e) for e in ports):
                _safe(findings, f"      smb {ip} (enum4linux/smbmap)",
                      lambda ip=ip: enum.enum_smb(scope, ip))

    # [3] VULNERABILIDADES
    if "vuln" in fases and targets:
        print()
        print("  [3] VULNERABILIDADES")
        for ip in sorted(targets):
            ports = targets[ip]
            _safe(findings, f"      nmap NSE vuln {ip}",
                  lambda ip=ip: vuln.scan_vulns_nmap(scope, ip))
            for e in ports:
                if is_web(e):
                    _safe(findings, f"      nuclei {ip}:{e['port']}",
                          lambda e=e, ip=ip: vuln.scan_vulns_nuclei(scope, ip, e["port"]))
                if e.get("banner"):
                    # searchsploit es documental (base local Exploit-DB): sin alcance.
                    findings.extend(vuln.search_exploits(e["svc"], e["banner"]))

    # Preparacion de explotacion (gated) — solo prepara, NO dispara.
    if exploit_scripts:
        _preparar_exploits(scope, targets, out_dir)

    _resumen(findings)

    if exportar:
        ruta = _exportar_json(scope, findings, targets, fases, out_dir)
        print(f"  Evidencia JSON: {ruta}")
    print()
    return 0


# ── Modo conversacional (SENTINEL Rojo) ───────────────────────────────────────

def _resolver_llm() -> tuple[str, str]:
    """Devuelve (api_key, modelo) desde variables de entorno o settings.json.
    La variable de entorno manda (comodo en Kali: export OPENROUTER_API_KEY=...)."""
    import os
    from sentinel.core.config import load_settings
    cfg = (load_settings().get("ai") or {})
    key = os.environ.get("OPENROUTER_API_KEY") or cfg.get("openrouter_api_key", "")
    modelo = (os.environ.get("SENTINEL_LLM_MODEL")
              or cfg.get("openrouter_model") or "google/gemini-2.5-flash")
    return key, modelo


def cmd_chat(scope_path: str | None, out_dir: str, modelo_cli: str | None,
             full: bool = False) -> int:
    from sentinel.core.auditor import agent
    scope = None
    if scope_path:
        try:
            scope = load_scope(scope_path)
        except ScopeError as e:
            _head("SENTINEL Rojo")
            print(f"  ALCANCE INVALIDO: {e}")
            print()
            return 2
    key, modelo = _resolver_llm()
    if modelo_cli:
        modelo = modelo_cli
    if not key:
        _head("SENTINEL Rojo")
        print("  Falta la clave del cerebro (OpenRouter).")
        print("  En Kali:  export OPENROUTER_API_KEY=sk-or-...")
        print("  O ponla en config/settings.json -> ai.openrouter_api_key")
        print()
        return 4
    _head("SENTINEL Rojo" + (" [OFENSIVO]" if full else "")
          + (f" — {scope.engagement}" if scope else ""))
    if scope is not None:
        _print_scope(scope)
    else:
        print("  Sin alcance previo: SENTINEL Rojo te preguntara qué auditar y a quién.")
        print(f"  {_LINE}")
    if full:
        print("  MODO OFENSIVO: la explotacion queda autorizada para esta sesion.")
        print(f"  {_LINE}")
    return agent.run_chat(scope, key, modelo, out_dir=out_dir, full_power=full)


def _safe(acc: list[Finding], etiqueta: str, fn) -> None:
    """Corre una sonda, imprime su etiqueta y acumula hallazgos. El guardian de
    alcance (ScopeError) nunca tumba la corrida: se reporta y se sigue."""
    print(f"{etiqueta}…")
    try:
        acc.extend(fn() or [])
    except ScopeError as e:
        print(f"        saltado por alcance: {e}")
    except Exception as e:   # una herramienta que revienta no debe cortar todo
        print(f"        error de herramienta (se ignora): {e}")


# ── Preparacion de explotacion (documental, con humano) ───────────────────────

def _preparar_exploits(scope, targets: dict[str, list[dict]], out_dir: str) -> None:
    print()
    print("  [*] PREPARACION DE EXPLOTACION (revision manual)")
    if not scope.phase_allowed("exploit"):
        print("      El alcance NO autoriza 'exploit'. No se genera nada.")
        return
    destino = Path(out_dir) / "exploit_scripts"
    destino.mkdir(parents=True, exist_ok=True)
    generados = 0
    for ip in sorted(targets):
        for e in targets[ip]:
            modulos = exploit.suggest_modules(e["svc"], e.get("banner", ""))
            for mod in modulos:
                try:
                    rc = exploit.build_resource_script(
                        scope, mod, ip, rport=e["port"])
                except ScopeError as ex:
                    print(f"      {ip}: {ex}")
                    continue
                nombre = f"{ip}_{e['port']}_{mod.split('/')[-1]}.rc"
                (destino / nombre).write_text(rc, encoding="utf-8")
                generados += 1
    if generados:
        print(f"      {generados} script(s) .rc generados en {destino}")
        print("      El 'run' va COMENTADO. Revisalos y ejecuta a mano:")
        print("        msfconsole -r <archivo>.rc")
    else:
        print("      Sin modulos sugeridos para los servicios encontrados.")


# ── Resumen y exportacion ─────────────────────────────────────────────────────

def _resumen(findings: list[Finding]) -> None:
    print()
    print(f"  {_LINE}")
    conteo = {s.label: 0 for s in Severity}
    for f in findings:
        conteo[f.severity.label] += 1
    print(f"  HALLAZGOS  {len(findings):>4}   "
          f"CRITICA {conteo['CRITICA']}   ALTA {conteo['ALTA']}   "
          f"MEDIA {conteo['MEDIA']}   BAJA {conteo['BAJA']}   INFO {conteo['INFO']}")
    print(f"  {_LINE}")
    relevantes = sorted(
        [f for f in findings if f.severity >= Severity.MEDIUM],
        key=lambda f: int(f.severity), reverse=True)
    if relevantes:
        for f in relevantes[:25]:
            print(f"    {f.severity.label:<8} {f.title}")
            if f.attack:
                print(f"             ATT&CK {f.attack}")
    else:
        print("    Sin hallazgos de severidad media o superior.")
    print(f"  {_LINE}")


def _exportar_json(scope, findings: list[Finding], targets: dict,
                   fases: list[str], out_dir: str) -> Path:
    destino = Path(out_dir)
    destino.mkdir(parents=True, exist_ok=True)
    conteo = {s.label: 0 for s in Severity}
    for f in findings:
        conteo[f.severity.label] += 1
    doc = {
        "producto": __product__,
        "modulo": "auditor-ofensivo",
        "version": __version__,
        "generado": datetime.now().isoformat(timespec="seconds"),
        "alcance": scope.summary(),
        "fases_ejecutadas": ["recon", *fases],
        "equipos": {ip: ports for ip, ports in targets.items()},
        "conteo_por_severidad": conteo,
        "total_hallazgos": len(findings),
        "hallazgos": [f.to_dict() for f in findings],
    }
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    seguro = "".join(c if c.isalnum() else "_" for c in scope.engagement)[:40]
    ruta = destino / f"auditoria_{seguro}_{stamp}.json"
    ruta.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return ruta


# ── Modo AUTONOMO (SENTINEL Rojo sin supervision) ────────────────────────────

def cmd_autonomo(scope_path: str | None, mision: str, out_dir: str,
                 modelo_cli: str | None, full: bool = True) -> int:
    from sentinel.core.auditor.autonomous import run_autonomous
    scope = None
    if scope_path:
        try:
            scope = load_scope(scope_path)
        except ScopeError as e:
            _head("SENTINEL Rojo AUTONOMO")
            print(f"  ALCANCE INVALIDO: {e}")
            print()
            return 2
    key, modelo = _resolver_llm()
    if modelo_cli:
        modelo = modelo_cli
    if not key:
        _head("SENTINEL Rojo AUTONOMO")
        print("  Falta la clave del cerebro (OpenRouter).")
        print("  En Kali:  export OPENROUTER_API_KEY=sk-or-...")
        print("  O ponla en config/settings.json -> ai.openrouter_api_key")
        print()
        return 4
    result = run_autonomous(
        mission=mision, scope=scope, api_key=key, model=modelo,
        out_dir=out_dir, full_power=full)
    return 0 if result.get("exito") else 1


# ── Entrada ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    _utf8()
    ap = argparse.ArgumentParser(
        prog="sentinel.attack",
        description="Motor ofensivo de SENTINEL: audita OTROS equipos por la "
                    "red, siempre dentro de un alcance autorizado.")
    ap.add_argument("--scope", "-s", metavar="ALCANCE.json",
                    help="Archivo de alcance autorizado (JSON). Sin el, no opera.")
    ap.add_argument("--fase", metavar="FASE[,FASE]",
                    help="Limita a estas fases: recon,enum,vuln (por defecto, "
                         "todas las autorizadas). recon siempre corre para ubicar "
                         "objetivos.")
    ap.add_argument("--verificar", action="store_true",
                    help="Valida el alcance y el arsenal. No toca ningun equipo.")
    ap.add_argument("--arsenal", action="store_true",
                    help="Lista el catalogo de herramientas y si estan instaladas.")
    ap.add_argument("--chat", action="store_true",
                    help="Modo conversacional (SENTINEL Rojo): le hablas y el "
                         "audita. Necesita OPENROUTER_API_KEY. --scope es "
                         "opcional: sin el, te pregunta que auditar y a quien.")
    ap.add_argument("--autonomo", action="store_true",
                    help="Modo AUTONOMO: SENTINEL Rojo opera SOLO, sin pedir "
                         "input. Le das una mision (--mision) y el hace todo: "
                         "planifica, reconoce, enumera, explota, pivotea, y al "
                         "final envia el reporte por correo. Puede correr "
                         "CUALQUIER comando en Kali. --scope es opcional.")
    ap.add_argument("--mision", metavar="TEXTO",
                    default="Auditoria ofensiva completa: descubre donde estas, "
                            "reconoce la red, enumera servicios, encuentra "
                            "vulnerabilidades, explota lo que puedas, escala "
                            "privilegios, pivotea si es posible, y al final "
                            "envia el reporte completo por correo al operador.",
                    help="Texto libre con la mision del agente autonomo. "
                         "Ej: 'sal de aqui y avisame como lo hiciste'.")
    ap.add_argument("--modelo", metavar="MODELO",
                    help="Modelo del cerebro en OpenRouter (ej. "
                         "google/gemini-2.5-flash, anthropic/claude-3.5-sonnet).")
    ap.add_argument("--full", action="store_true",
                    help="Modo OFENSIVO: pre-autoriza la explotacion en esta "
                         "sesion (no hay que decir 'autorizo'). Sigue limitado al "
                         "alcance. Solo con --chat o --autonomo.")
    ap.add_argument("--exploit-scripts", dest="exploit_scripts",
                    action="store_true",
                    help="Si el alcance autoriza 'exploit', PREPARA scripts .rc de "
                         "Metasploit (run comentado) para revision manual. No dispara.")
    ap.add_argument("--salida", "-o", default="evidencia_ofensiva",
                    metavar="DIR", help="Carpeta para la evidencia (JSON, scripts).")
    ap.add_argument("--sin-exportar", dest="sin_exportar", action="store_true",
                    help="No escribe el archivo de evidencia.")
    args = ap.parse_args(argv)

    if args.arsenal:
        return cmd_arsenal()
    if args.autonomo:
        return cmd_autonomo(args.scope, mision=args.mision, out_dir=args.salida,
                            modelo_cli=args.modelo, full=args.full)
    if args.chat:
        return cmd_chat(args.scope, out_dir=args.salida, modelo_cli=args.modelo,
                        full=args.full)
    if args.verificar:
        return cmd_verificar(args.scope)
    if args.scope:
        fases = None
        if args.fase:
            fases = [p.strip().lower() for p in args.fase.split(",") if p.strip()]
        return cmd_auditar(args.scope, fases, out_dir=args.salida,
                           exportar=not args.sin_exportar,
                           exploit_scripts=args.exploit_scripts)

    ap.print_help()
    print()
    print("  Ejemplo:  python -m sentinel.attack --verificar --scope alcance.json")
    print()
    print("  Modo autonomo (sin supervision):")
    print("    python -m sentinel.attack --autonomo --full --scope alcance.json")
    print("    python -m sentinel.attack --autonomo --full \\")
    print("        --mision 'sal de aqui y avisame como lo hiciste'")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

