"""agent.py — SENTINEL Rojo: el Auditor conversacional (le hablas, el audita).

Es la contraparte ofensiva del agente defensivo (`core/agent_tools.py`): en vez
de blindar el PC local, el cerebro (un LLM via `core/llm.py`) conversa con el
operador y ORQUESTA el Auditor —reconocer, enumerar, buscar vulnerabilidades,
preparar explotacion— llamando a herramientas.

Principio de diseno, igual que en todo SENTINEL:
    el cerebro decide QUE herramienta usar, pero CADA herramienta pasa por el
    guardian de alcance (`scope.py`). La IA no puede tocar nada fuera de lo
    autorizado, por mas que se lo pidan. El guardian esta entre el modelo y la
    red. Eso es lo que separa esta plataforma de un atacante real.

Expone:
    AuditorSession        estado de la corrida (alcance, objetivos, hallazgos)
    TOOL_SPECS            declaraciones de funciones (formato OpenAI/OpenRouter)
    execute_tool(...)     ejecuta una herramienta y devuelve un dict honesto
    run_chat(...)         bucle de conversacion en la terminal (chat de texto)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope, ScopeError
from sentinel.core.auditor import recon, enum, vuln, exploit, toolkit
from sentinel.core.auditor.targets import derive_targets, is_web, is_tls, is_smb
from sentinel.core import llm


# ── Estado de la sesion ───────────────────────────────────────────────────────

@dataclass
class AuditorSession:
    scope: Scope
    out_dir: str = "evidencia_ofensiva"
    findings: list[Finding] = field(default_factory=list)
    targets: dict[str, list[dict]] = field(default_factory=dict)

    def add_findings(self, nuevos: list[Finding]) -> None:
        self.findings.extend(nuevos)
        for ip, ports in derive_targets(nuevos).items():
            dest = self.targets.setdefault(ip, [])
            for e in ports:
                if not any(x["port"] == e["port"] for x in dest):
                    dest.append(e)


def _brief(f: Finding) -> dict:
    return {"severidad": f.severity.label, "titulo": f.title,
            "categoria": f.category, "attack": f.attack}


def _conteo(findings: list[Finding]) -> dict:
    c = {s.label: 0 for s in Severity}
    for f in findings:
        c[f.severity.label] += 1
    return c


def _ensure_host(session: AuditorSession, ip: str) -> str | None:
    """Si el equipo aun no tiene puertos conocidos, lo escanea. Devuelve un
    mensaje de error si el guardian lo rechaza, o None si quedo listo."""
    if session.targets.get(ip):
        return None
    try:
        fs = recon.scan_host(session.scope, ip)
    except ScopeError as e:
        return str(e)
    session.add_findings(fs)
    return None


# ── Herramientas (todas pasan por el guardian de alcance) ─────────────────────

def _t(name: str, desc: str, props: dict | None = None,
       required: list[str] | None = None) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object",
                       "properties": props or {},
                       "required": required or []}}}

_IP = {"ip": {"type": "string", "description": "IP del equipo objetivo (debe estar en el alcance)."}}

TOOL_SPECS = [
    _t("estado_alcance",
       "Muestra el alcance autorizado (quien autoriza, objetivos, ventana, "
       "fases) y el estado actual: equipos y hallazgos ya recogidos. No toca "
       "la red. Usalo para saber que se puede hacer antes de escanear."),
    _t("reconocer",
       "Fase 1: reconocimiento con nmap sobre TODO el alcance. Descubre equipos "
       "vivos y sus puertos/servicios abiertos. Es el punto de partida."),
    _t("escanear_equipo",
       "Escaneo de puertos y versiones (nmap -sV) de UN equipo del alcance.",
       _IP, ["ip"]),
    _t("enumerar",
       "Fase 2: enumeracion de los servicios de un equipo (web: whatweb/nikto; "
       "SMB: enum4linux/smbmap; TLS: sslscan). Solo lee, no ataca.",
       _IP, ["ip"]),
    _t("buscar_vulnerabilidades",
       "Fase 3: deteccion de vulnerabilidades de un equipo (nmap NSE 'vuln', "
       "nuclei en servicios web). Identifica CVEs; NO explota.",
       _IP, ["ip"]),
    _t("auditoria_completa",
       "Corre de una vez las fases AUTORIZADAS (recon -> enum -> vuln) sobre "
       "todo el alcance y guarda la evidencia en JSON. Usalo cuando el operador "
       "pida 'audita todo' o 'hazlo completo'."),
    _t("resumen_hallazgos",
       "Resume los hallazgos recogidos hasta ahora, ordenados por severidad. "
       "No toca la red."),
    _t("preparar_exploit",
       "Solo si el alcance autoriza la fase 'exploit': PREPARA scripts .rc de "
       "Metasploit (con el 'run' comentado) para revision manual del operador. "
       "No dispara ningun exploit.",
       _IP, ["ip"]),
    _t("arsenal",
       "Lista que herramientas de Kali estan instaladas y cuales faltan."),
]


def execute_tool(session: AuditorSession, name: str, args: dict) -> dict:
    """Ejecuta la herramienta pedida por el cerebro. Nunca lanza: devuelve un
    dict (con 'error' si el guardian rechaza o la herramienta falla)."""
    try:
        return _dispatch(session, name, args or {})
    except ScopeError as e:
        return {"error": f"BLOQUEADO POR EL ALCANCE: {e}"}
    except Exception as e:   # una herramienta rota no debe tumbar la conversacion
        return {"error": f"la herramienta '{name}' fallo: {e}"}


def _dispatch(session: AuditorSession, name: str, args: dict) -> dict:
    scope = session.scope

    if name == "estado_alcance":
        return {"alcance": scope.summary(),
                "ventana_abierta": scope.window_open(),
                "nmap_instalado": recon.nmap_available(),
                "equipos_conocidos": sorted(session.targets),
                "hallazgos_recogidos": len(session.findings)}

    if name == "arsenal":
        inst = [t.name for t in toolkit.ARSENAL if t.installed()]
        falta = [t.name for t in toolkit.ARSENAL if not t.installed()]
        return {"instaladas": inst, "faltan": falta}

    if name == "reconocer":
        if not recon.nmap_available():
            return {"error": "nmap no esta instalado (sudo apt install nmap)."}
        fs = recon.scan_scope(scope)
        session.add_findings(fs)
        return {"equipos": sorted(session.targets),
                "total_equipos": len(session.targets),
                "puertos_por_equipo": {ip: [f"{e['port']}/{e['svc']}" for e in ports]
                                       for ip, ports in session.targets.items()},
                "hallazgos_nuevos": [_brief(f) for f in fs][:40]}

    if name == "escanear_equipo":
        ip = str(args.get("ip", "")).strip()
        fs = recon.scan_host(scope, ip)
        session.add_findings(fs)
        return {"equipo": ip,
                "puertos": [f"{e['port']}/{e['svc']}"
                            for e in session.targets.get(ip, [])],
                "hallazgos": [_brief(f) for f in fs]}

    if name == "enumerar":
        ip = str(args.get("ip", "")).strip()
        err = _ensure_host(session, ip)
        if err:
            return {"error": err}
        nuevos: list[Finding] = []
        ports = session.targets.get(ip, [])
        for e in ports:
            if is_web(e):
                nuevos += enum.enum_web(scope, ip, e["port"])
                if is_tls(e):
                    nuevos += enum.enum_tls(scope, ip, e["port"])
        if any(is_smb(e) for e in ports):
            nuevos += enum.enum_smb(scope, ip)
        session.add_findings(nuevos)
        return {"equipo": ip, "hallazgos": [_brief(f) for f in nuevos] or
                "sin servicios enumerables (o herramientas no instaladas)"}

    if name == "buscar_vulnerabilidades":
        ip = str(args.get("ip", "")).strip()
        err = _ensure_host(session, ip)
        if err:
            return {"error": err}
        nuevos = list(vuln.scan_vulns_nmap(scope, ip))
        for e in session.targets.get(ip, []):
            if is_web(e):
                nuevos += vuln.scan_vulns_nuclei(scope, ip, e["port"])
            if e.get("banner"):
                nuevos += vuln.search_exploits(e["svc"], e["banner"])
        session.add_findings(nuevos)
        return {"equipo": ip, "hallazgos": [_brief(f) for f in nuevos] or
                "sin vulnerabilidades detectadas (o herramientas no instaladas)"}

    if name == "auditoria_completa":
        return _auditoria_completa(session)

    if name == "resumen_hallazgos":
        relevantes = sorted([f for f in session.findings
                             if f.severity >= Severity.MEDIUM],
                            key=lambda f: int(f.severity), reverse=True)
        return {"conteo": _conteo(session.findings),
                "total": len(session.findings),
                "relevantes": [_brief(f) for f in relevantes][:30]}

    if name == "preparar_exploit":
        ip = str(args.get("ip", "")).strip()
        if not scope.phase_allowed("exploit"):
            return {"error": "el alcance NO autoriza la fase 'exploit'. "
                             "No se prepara nada."}
        err = _ensure_host(session, ip)
        if err:
            return {"error": err}
        destino = Path(session.out_dir) / "exploit_scripts"
        destino.mkdir(parents=True, exist_ok=True)
        generados = []
        for e in session.targets.get(ip, []):
            for mod in exploit.suggest_modules(e["svc"], e.get("banner", "")):
                rc = exploit.build_resource_script(scope, mod, ip, rport=e["port"])
                archivo = destino / f"{ip}_{e['port']}_{mod.split('/')[-1]}.rc"
                archivo.write_text(rc, encoding="utf-8")
                generados.append(str(archivo))
        return {"equipo": ip, "scripts": generados or "sin modulos sugeridos",
                "nota": "REVISAR a mano; el 'run' va comentado. msfconsole -r <archivo>"}

    return {"error": f"herramienta desconocida: {name}"}


def _auditoria_completa(session: AuditorSession) -> dict:
    scope = session.scope
    if not recon.nmap_available():
        return {"error": "nmap no esta instalado (sudo apt install nmap)."}
    if not scope.phase_allowed("recon"):
        return {"error": "el alcance no autoriza 'recon'."}

    fs = recon.scan_scope(scope)
    session.add_findings(fs)
    fases = ["recon"]
    if scope.phase_allowed("enum"):
        fases.append("enum")
        for ip in sorted(session.targets):
            ports = session.targets[ip]
            nuevos: list[Finding] = []
            for e in ports:
                if is_web(e):
                    nuevos += enum.enum_web(scope, ip, e["port"])
                    if is_tls(e):
                        nuevos += enum.enum_tls(scope, ip, e["port"])
            if any(is_smb(e) for e in ports):
                nuevos += enum.enum_smb(scope, ip)
            session.add_findings(nuevos)
    if scope.phase_allowed("vuln"):
        fases.append("vuln")
        for ip in sorted(session.targets):
            nuevos = list(vuln.scan_vulns_nmap(scope, ip))
            for e in session.targets[ip]:
                if is_web(e):
                    nuevos += vuln.scan_vulns_nuclei(scope, ip, e["port"])
            session.add_findings(nuevos)

    ruta = _guardar_json(session, fases)
    return {"fases": fases, "conteo": _conteo(session.findings),
            "total_equipos": len(session.targets),
            "evidencia_json": str(ruta)}


def _guardar_json(session: AuditorSession, fases: list[str]) -> Path:
    destino = Path(session.out_dir)
    destino.mkdir(parents=True, exist_ok=True)
    doc = {
        "generado": datetime.now().isoformat(timespec="seconds"),
        "alcance": session.scope.summary(),
        "fases_ejecutadas": fases,
        "equipos": session.targets,
        "conteo_por_severidad": _conteo(session.findings),
        "total_hallazgos": len(session.findings),
        "hallazgos": [f.to_dict() for f in session.findings],
    }
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    seguro = "".join(c if c.isalnum() else "_" for c in session.scope.engagement)[:40]
    ruta = destino / f"auditoria_{seguro}_{stamp}.json"
    ruta.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


# ── Cerebro conversacional ────────────────────────────────────────────────────

def system_prompt(scope: Scope) -> str:
    s = scope.summary()
    return (
        "Eres SENTINEL Rojo, un asistente de PENTEST AUTORIZADO que audita el "
        "laboratorio de una tesis universitaria de ciberseguridad. Tu papel es "
        "el equipo rojo (ofensivo) que encuentra los huecos para que el equipo "
        "azul los tape; se mide el antes/despues.\n\n"
        "REGLAS INVIOLABLES:\n"
        "1. Operas SOLO dentro del alcance autorizado. Cada herramienta ya lo "
        "verifica; si una accion cae fuera, la herramienta la bloquea y tu lo "
        "explicas, sin insistir.\n"
        "2. La explotacion no se dispara automatica: como mucho PREPARAS scripts "
        "para revision humana. No pretendas haber explotado nada.\n"
        "3. Se honesto: reporta solo lo que las herramientas devuelven. Nunca "
        "inventes hallazgos, CVEs ni resultados.\n\n"
        "METODOLOGIA: sigue recon -> enumeracion -> vulnerabilidades. Prioriza "
        "por severidad y, cuando expliques un hallazgo, di brevemente como lo "
        "taparia el equipo azul. Responde SIEMPRE en espanol, claro y conciso.\n\n"
        f"ALCANCE ACTUAL: engagement '{s['engagement']}', autoriza "
        f"{s['autorizado_por']}, objetivos {s['objetivos']}, fases {s['fases']}, "
        f"ventana {s['ventana']}.\n"
        "Cuando el operador pida algo, usa las herramientas; no describas "
        "comandos, EJECUTALOS con las herramientas disponibles."
    )


def _extract_tool_calls(msg: dict) -> list[dict]:
    calls = msg.get("tool_calls") or []
    out = []
    for c in calls:
        fn = (c.get("function") or {})
        raw = fn.get("arguments")
        if isinstance(raw, str):
            try:
                args = json.loads(raw) if raw.strip() else {}
            except ValueError:
                args = {}
        elif isinstance(raw, dict):
            args = raw
        else:
            args = {}
        out.append({"id": c.get("id", ""), "name": fn.get("name", ""), "args": args})
    return out


def run_chat(scope: Scope, api_key: str, model: str = llm.DEFAULT_MODEL,
             out_dir: str = "evidencia_ofensiva",
             input_fn=input, print_fn=print) -> int:
    """Bucle de conversacion en la terminal. `input_fn`/`print_fn` se inyectan
    para poder probarlo sin teclado."""
    session = AuditorSession(scope=scope, out_dir=out_dir)
    messages = [{"role": "system", "content": system_prompt(scope)}]

    print_fn("")
    print_fn("  SENTINEL Rojo — asistente de auditoria. Hablame en español.")
    print_fn(f"  Cerebro: {model}   ·   Engagement: {scope.engagement}")
    print_fn("  Ejemplos: 'reconoce todo el alcance' · 'enumera el .5' · "
             "'audita todo' · 'que encontraste'")
    print_fn("  Escribe 'salir' para terminar.")
    print_fn("")

    while True:
        try:
            user = input_fn("tú> ").strip()
        except (EOFError, KeyboardInterrupt):
            print_fn("\n  Hasta luego.")
            return 0
        if not user:
            continue
        if user.lower() in ("salir", "exit", "quit", "chau", "adios"):
            print_fn("  Hasta luego.")
            return 0

        messages.append({"role": "user", "content": user})

        # El modelo puede encadenar varias herramientas antes de responder.
        for _ in range(10):
            resp = llm.complete(messages, TOOL_SPECS, api_key, model)
            if "error" in resp:
                print_fn(f"  [cerebro] {resp['error']}")
                messages.pop()   # descarta el turno del usuario que no se pudo atender
                break

            msg = resp["message"]
            messages.append(msg)
            calls = _extract_tool_calls(msg)
            if not calls:
                contenido = msg.get("content") or "(sin respuesta)"
                print_fn(f"\nSENTINEL> {contenido}\n")
                break

            for c in calls:
                print_fn(f"  · ejecutando: {c['name']}({c['args'] or ''})")
                resultado = execute_tool(session, c["name"], c["args"])
                messages.append({"role": "tool", "tool_call_id": c["id"],
                                 "name": c["name"],
                                 "content": json.dumps(resultado, ensure_ascii=False)})
        else:
            print_fn("  [aviso] demasiadas herramientas en un turno; corto aqui.")

    return 0
