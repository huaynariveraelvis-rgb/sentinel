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
from datetime import datetime, timedelta
from pathlib import Path

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope, ScopeError, build_scope
from sentinel.core.auditor import recon, enum, vuln, exploit, toolkit
from sentinel.core.auditor.targets import derive_targets, is_web, is_tls, is_smb
from sentinel.core import llm


# ── Estado de la sesion ───────────────────────────────────────────────────────

@dataclass
class AuditorSession:
    scope: Scope | None = None      # puede fijarse en la conversacion
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
    _t("configurar_alcance",
       "Fija el OBJETIVO de la auditoria con lo que diga el operador (una IP, un "
       "rango, o su red local). Llamalo en cuanto el operador diga que quiere "
       "auditar; basta con 'targets'. Puedes volver a llamarlo para cambiar de "
       "objetivo. Ninguna otra herramienta funciona sin esto. NO pidas quien "
       "autoriza ni actas: el operador ya autoriza al pedirlo.",
       {"targets": {"type": "array", "items": {"type": "string"},
                    "description": "IPs o rangos CIDR a auditar, p.ej. "
                                   "['192.168.1.10'] o ['192.168.1.0/24']. Si el "
                                   "operador dice 'mi ip'/'mi red'/'esta maquina', "
                                   "obtenlos antes con detectar_red_local."},
        "allowed_phases": {"type": "array", "items": {"type": "string"},
                           "description": "Fases: recon, enum, vuln. Omitir = las tres."},
        "engagement": {"type": "string", "description": "Nombre corto del trabajo (opcional)."},
        "excludes": {"type": "array", "items": {"type": "string"},
                     "description": "IPs a NO tocar aunque caigan en el rango (opcional)."},
        "horas_ventana": {"type": "integer",
                          "description": "Horas de ventana desde ahora. Omitir = sin limite horario."}},
       ["targets"]),
    _t("detectar_red_local",
       "Devuelve la(s) IP y subred(es) de la propia maquina Kali. Usalo cuando el "
       "operador diga 'mi ip', 'mi red', 'esta maquina', 'la red local' o similar, "
       "para saber que objetivo usar sin que el lo escriba. No toca otros equipos."),
    _t("estado_alcance",
       "Muestra el objetivo actual, la ventana, las fases y el estado: equipos y "
       "hallazgos ya recogidos. No toca la red. Si aun no hay objetivo, te dice "
       "que preguntar al operador."),
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
    # Herramientas que NO necesitan un alcance ya fijado.
    if name == "arsenal":
        inst = [t.name for t in toolkit.ARSENAL if t.installed()]
        falta = [t.name for t in toolkit.ARSENAL if not t.installed()]
        return {"instaladas": inst, "faltan": falta}

    if name == "detectar_red_local":
        return _detectar_red_local()

    if name == "configurar_alcance":
        return _configurar_alcance(session, args)

    if name == "estado_alcance":
        if session.scope is None:
            return {"sin_alcance": True,
                    "instruccion": "Todavia no hay alcance. Pregunta al operador "
                    "QUE quiere auditar, a QUE objetivo(s) (IP o rango), QUIEN lo "
                    "autoriza y que FASES; luego llama configurar_alcance."}
        return {"alcance": session.scope.summary(),
                "ventana_abierta": session.scope.window_open(),
                "nmap_instalado": recon.nmap_available(),
                "equipos_conocidos": sorted(session.targets),
                "hallazgos_recogidos": len(session.findings)}

    # De aqui en adelante hace falta un alcance fijado.
    if session.scope is None:
        return {"error": "primero define el alcance con configurar_alcance "
                         "(dime objetivo, quien autoriza y fases)."}
    scope = session.scope

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


def _detectar_red_local() -> dict:
    """IP(s) y subred(es) de la propia maquina. Para 'escanea mi ip/mi red'."""
    import subprocess
    import socket
    import ipaddress
    ips: list[str] = []
    redes: list[str] = []
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            partes = line.split()
            if "inet" in partes:
                cidr = partes[partes.index("inet") + 1]     # 192.168.56.101/24
                ip = cidr.split("/")[0]
                if ip.startswith("127."):
                    continue
                ips.append(ip)
                redes.append(str(ipaddress.ip_network(cidr, strict=False)))
    except Exception:
        pass
    if not ips:   # respaldo si no hay 'ip' (p.ej. Windows): IP de salida
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            ips.append(ip)
            redes.append(str(ipaddress.ip_network(ip + "/24", strict=False)))
        except OSError:
            pass
    return {"ips_locales": ips, "redes_locales": sorted(set(redes)),
            "nota": "usa una IP para escanear solo esta maquina, o una subred /24 "
                    "para toda la red local."}


def _configurar_alcance(session: AuditorSession, args: dict) -> dict:
    """Arma el alcance desde la conversacion, lo valida (falla cerrado) y lo fija
    en la sesion. El operador ya autoriza al pedirlo: no se le pregunta, pero
    queda un registro JSON (cadena de custodia)."""
    operador = (session.scope.operator if session.scope else None) or "operador"
    data = {
        "engagement": (args.get("engagement") or "Auditoria (definida en sesion)"),
        "authorized_by": (args.get("authorized_by") or "").strip()
                         or f"{operador} (autorizado en sesion)",
        "authorization_ref": (args.get("authorization_ref") or "").strip(),
        "operator": operador,
        "targets": args.get("targets") or [],
        "excludes": args.get("excludes") or [],
        "allowed_phases": args.get("allowed_phases") or ["recon", "enum", "vuln"],
    }
    horas = args.get("horas_ventana")
    if horas:
        try:
            ini = datetime.now()
            data["window"] = {
                "start": ini.isoformat(timespec="seconds"),
                "end": (ini + timedelta(hours=int(horas))).isoformat(timespec="seconds")}
        except (ValueError, TypeError):
            pass
    try:
        nuevo = build_scope(data)
    except ScopeError as e:
        return {"error": f"no pude fijar el alcance: {e}. Pide al operador el dato que falta."}

    # Cambiar de alcance reinicia los objetivos/hallazgos previos (son de otro trabajo).
    session.scope = nuevo
    session.targets = {}
    session.findings = []

    # Registro de lo que se autorizo en esta sesion (cadena de custodia).
    try:
        destino = Path(session.out_dir)
        destino.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        (destino / f"alcance_{stamp}.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass

    return {"alcance_fijado": nuevo.summary(),
            "ventana_abierta": nuevo.window_open(),
            "nmap_instalado": recon.nmap_available(),
            "listo_para": [f for f in ("recon", "enum", "vuln")
                           if nuevo.phase_allowed(f)]}


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

def system_prompt(scope: Scope | None) -> str:
    base = (
        "Eres SENTINEL Rojo: un PENTESTER EXPERTO y AUTONOMO (NO un chatbot) que "
        "audita el laboratorio de una tesis de ciberseguridad. Actuas como un "
        "profesional de equipo rojo con criterio propio: planificas, ejecutas y "
        "razonas sobre lo que encuentras, para que el equipo azul tape los huecos.\n\n"
        "COMO TRABAJAS (como experto, no esperando micro-ordenes):\n"
        "1. ENTIENDE la intencion real del operador aunque hable informal o con "
        "faltas de ortografia. Deduce lo que puedas; no preguntes lo obvio.\n"
        "2. PLANIFICA y ACTUA: decide que herramientas hacen falta y encadenalas "
        "TU MISMO en el mismo turno, sin pedir permiso en cada paso (ya estas "
        "autorizado dentro del alcance). Si el operador dice 'audita mi red' o "
        "'hazlo todo', usa auditoria_completa (hace recon+enum+vuln de una) en vez "
        "de muchas llamadas sueltas: es mas rapido y gasta menos.\n"
        "3. RAZONA como pentester sobre los resultados: relaciona servicio/version "
        "con el riesgo y CVEs probables (p.ej. SMB en Windows antiguo -> candidato "
        "a EternalBlue MS17-010; verificalo con buscar_vulnerabilidades). Descarta "
        "ruido, prioriza por severidad e impacto real.\n"
        "4. REPORTA como experto: que encontraste, que es lo MAS grave y por que, y "
        "en una linea como lo taparia el equipo azul. Tecnico, claro y conciso.\n\n"
        "REGLAS INVIOLABLES:\n"
        "- Operas SOLO dentro del alcance. El guardian bloquea lo demas; si algo "
        "cae fuera, lo dices y sigues.\n"
        "- No disparas explotacion automatica: como mucho PREPARAS scripts (.rc) "
        "para revision humana. Nunca finjas haber explotado ni tener una shell.\n"
        "- HONESTIDAD TOTAL: reporta solo lo que las herramientas devuelven. Jamas "
        "inventes equipos, puertos, CVEs ni resultados. Si una herramienta no esta "
        "instalada o no devolvio nada, dilo tal cual.\n"
        "- NUNCA preguntes 'quien autoriza' ni pidas actas: el operador autoriza al "
        "pedirlo. Responde SIEMPRE en espanol.\n\n"
        "INTERPRETA al operador:\n"
        "- 'escanea mi ip'/'mi red'/'esta maquina' -> llama detectar_red_local "
        "primero; 'mi ip' = la IP sola, 'mi red' = la subred /24.\n"
        "- una IP o rango directo -> fija el alcance con configurar_alcance y "
        "arranca lo que pida. Si no dice fases, asume recon+enum+vuln.\n\n")
    if scope is None:
        return base + (
            "ESTADO: aun no hay objetivo. En cuanto el operador diga que auditar, "
            "fijalo con configurar_alcance y PONTE EN MARCHA con la metodologia "
            "completa. No inventes objetivos: los da el operador.")
    s = scope.summary()
    return base + (
        f"ESTADO: objetivo ya fijado -> '{s['engagement']}', objetivos "
        f"{s['objetivos']}, fases {s['fases']}, ventana {s['ventana']}. Ponte en "
        "marcha cuando el operador lo pida; para cambiar de objetivo usa "
        "configurar_alcance.")


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


def run_chat(scope: Scope | None, api_key: str, model: str = llm.DEFAULT_MODEL,
             out_dir: str = "evidencia_ofensiva",
             input_fn=input, print_fn=print) -> int:
    """Bucle de conversacion en la terminal. `scope` puede ser None: en ese caso
    SENTINEL Rojo pregunta al operador que auditar y a quien, y arma el alcance
    con configurar_alcance. `input_fn`/`print_fn` se inyectan para pruebas."""
    session = AuditorSession(scope=scope, out_dir=out_dir)
    messages = [{"role": "system", "content": system_prompt(scope)}]

    print_fn("")
    print_fn("  SENTINEL Rojo — asistente de auditoria. Hablame en español.")
    print_fn(f"  Cerebro: {model}")
    if scope is None:
        print_fn("  Dime QUÉ quieres auditar: una IP, un rango, o 'mi red'/'mi ip'.")
        print_fn("  Ej: 'escanea mi red' · 'audita la 192.168.56.10' · "
                 "'reconoce el 10.0.0.0/24'")
    else:
        print_fn(f"  Engagement: {scope.engagement}")
        print_fn("  Ej: 'reconoce todo el alcance' · 'enumera el .5' · 'audita todo'")
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
            resp = llm.complete_resilient(messages, TOOL_SPECS, api_key, model)
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
