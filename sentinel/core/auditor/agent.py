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
from sentinel.core import llm, notify


# ── Estado de la sesion ───────────────────────────────────────────────────────

@dataclass
class AuditorSession:
    scope: Scope | None = None      # puede fijarse en la conversacion
    out_dir: str = "evidencia_ofensiva"
    findings: list[Finding] = field(default_factory=list)
    targets: dict[str, list[dict]] = field(default_factory=dict)
    progress: object = None          # callable(str): 'avance tras avance' en vivo

    def say(self, msg: str) -> None:
        """Emite una linea de avance a la terminal, si hay a donde."""
        if self.progress:
            try:
                self.progress(msg)
            except Exception:
                pass

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
                           "description": "Fases autorizadas: recon, enum, vuln, y "
                           "'exploit' SOLO si el operador autoriza explotar de forma "
                           "expresa (ej. 'con explotacion', 'quiero entrar'). Omitir "
                           "= recon+enum+vuln (sin explotacion)."},
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
    _t("explotar",
       "EJECUTA la explotacion con Metasploit contra un equipo AUTORIZADO y en "
       "alcance (solo si la fase 'exploit' esta autorizada). Corre el modulo, "
       "intenta abrir sesion (meterpreter/shell) y hace post-explotacion basica "
       "(sysinfo, getuid, hashdump). Usalo cuando el operador diga 'explota'/"
       "'entra'/'consigue shell'. Si no das 'modulo', se elige por el servicio.",
       {"ip": {"type": "string", "description": "Objetivo (en alcance)."},
        "modulo": {"type": "string", "description": "Modulo Metasploit (opcional; "
                   "si falta, se sugiere por el servicio del equipo)."}},
       ["ip"]),
    _t("avisar_por_correo",
       "Envia al operador (a SU correo configurado) un aviso con el resumen de la "
       "auditoria. Es entrega de informe/notificacion, no exfiltracion. Usalo si "
       "el operador pide 'avisame'/'mandame al correo'/'notificame'.",
       {"asunto": {"type": "string", "description": "Asunto (opcional)."}}),
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
        fs = _recon_con_avance(session)
        return {"equipos": sorted(session.targets),
                "total_equipos": len(session.targets),
                "puertos_por_equipo": {ip: [f"{e['port']}/{e['svc']}" for e in ports]
                                       for ip, ports in session.targets.items()},
                "hallazgos_nuevos": [_brief(f) for f in fs][:40]}

    if name == "escanear_equipo":
        ip = str(args.get("ip", "")).strip()
        session.say(f"  [scan] escaneando puertos y versiones de {ip}...")
        fs = recon.scan_host(scope, ip)
        session.add_findings(fs)
        riesgo = [f for f in fs if f.category == "exposicion"]
        session.say(f"          {ip}: {len(session.targets.get(ip, []))} puerto(s) abierto(s)"
                    + (f"  (!) {len(riesgo)} de riesgo" if riesgo else ""))
        return {"equipo": ip,
                "puertos": [f"{e['port']}/{e['svc']}"
                            for e in session.targets.get(ip, [])],
                "hallazgos": [_brief(f) for f in fs]}

    if name == "enumerar":
        ip = str(args.get("ip", "")).strip()
        err = _ensure_host(session, ip)
        if err:
            return {"error": err}
        nuevos = _enumerar_con_avance(session, ip)
        return {"equipo": ip, "hallazgos": [_brief(f) for f in nuevos] or
                "sin servicios enumerables (o herramientas no instaladas)"}

    if name == "buscar_vulnerabilidades":
        ip = str(args.get("ip", "")).strip()
        err = _ensure_host(session, ip)
        if err:
            return {"error": err}
        nuevos = _vulns_con_avance(session, ip)
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

    if name == "explotar":
        return _explotar(session, args)

    if name == "avisar_por_correo":
        return _avisar(session, args)

    return {"error": f"herramienta desconocida: {name}"}


def _explotar(session: AuditorSession, args: dict) -> dict:
    scope = session.scope
    ip = str(args.get("ip", "")).strip()
    if not scope.phase_allowed("exploit"):
        return {"error": "el alcance NO autoriza la fase 'exploit'. Pide al "
                         "operador que la autorice (es un candado a proposito)."}
    if not exploit.msf_available():
        return {"error": "Metasploit (msfconsole) no esta instalado. "
                         "En Kali: sudo apt install metasploit-framework."}
    err = _ensure_host(session, ip)
    if err:
        return {"error": err}

    modulo = (args.get("modulo") or "").strip()
    puerto = None
    if not modulo:
        for e in session.targets.get(ip, []):
            sugeridos = exploit.suggest_modules(e["svc"], e.get("banner", ""))
            expl = [m for m in sugeridos if m.startswith("exploit/")]
            if expl:
                modulo, puerto = expl[0], e["port"]
                break
        if not modulo:
            return {"error": f"no tengo un modulo de explotacion sugerido para los "
                             f"servicios de {ip}. Enumera/busca_vulnerabilidades "
                             f"primero, o dame un modulo Metasploit concreto."}

    session.say(f"  [exploit] {ip}: lanzando {modulo} con Metasploit...")
    try:
        hallazgo, salida = exploit.run_msf(scope, modulo, ip, rport=puerto, post=True)
    except ScopeError as e:
        return {"error": str(e)}
    if hallazgo:
        session.add_findings([hallazgo])
        estado = hallazgo.severity.label
        session.say(f"            resultado: {hallazgo.title}")
    else:
        estado = "sin sesion / no explotable"
        session.say(f"            resultado: sin sesion (no explotable con {modulo})")
    return {"equipo": ip, "modulo": modulo, "resultado": estado,
            "detalle": hallazgo.title if hallazgo else "no se abrio sesion",
            "salida_msf": (salida or "")[:1500]}


def _avisar(session: AuditorSession, args: dict) -> dict:
    from sentinel.core.config import load_settings
    cfg = (load_settings().get("notify") or {})
    if not notify.configured(cfg):
        return {"error": "el correo no esta configurado. Pon notify.smtp_host/"
                         "smtp_user/smtp_password (y email_to) en config/settings.json. "
                         "Gmail: usa una App Password."}
    conteo = _conteo(session.findings)
    eng = session.scope.engagement if session.scope else "auditoria"
    relevantes = sorted([f for f in session.findings if f.severity >= Severity.MEDIUM],
                        key=lambda f: int(f.severity), reverse=True)
    cuerpo = [f"SENTINEL Rojo — aviso de auditoria", f"Engagement: {eng}",
              f"Objetivos: {', '.join(session.scope.targets) if session.scope else '-'}",
              "",
              f"Hallazgos: {len(session.findings)}  "
              f"(CRITICA {conteo['CRITICA']}, ALTA {conteo['ALTA']}, "
              f"MEDIA {conteo['MEDIA']})", ""]
    for f in relevantes[:20]:
        cuerpo.append(f"  [{f.severity.label}] {f.title}"
                      + (f"  ({f.attack})" if f.attack else ""))
    asunto = str(args.get("asunto") or f"SENTINEL Rojo — {eng}")
    ok, msg = notify.send_email(cfg, asunto, "\n".join(cuerpo))
    session.say(f"  [aviso] {msg}")
    return {"enviado": ok, "detalle": msg}


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


# ── Fases con avance en vivo (el operador ve el progreso) ─────────────────────

def _recon_con_avance(session: AuditorSession) -> list[Finding]:
    scope = session.scope
    session.say(f"  [recon] descubriendo equipos vivos en {', '.join(scope.targets)}...")
    vivos = recon.discover_hosts(scope)
    session.say(f"          -> {len(vivos)} vivo(s)"
                + (f": {', '.join(vivos[:15])}" if vivos else ""))
    findings: list[Finding] = [Finding(
        category="recon", severity=Severity.INFO,
        title=f"{len(vivos)} equipo(s) vivo(s) en el alcance",
        detail="Inventario base del engagement.",
        evidence={"vivos": vivos[:50], "total": len(vivos)}, attack="T1018")]
    for i, ip in enumerate(vivos, 1):
        session.say(f"  [recon] [{i}/{len(vivos)}] escaneando puertos de {ip}...")
        try:
            fs = recon.scan_host(scope, ip)
        except ScopeError:
            continue
        findings += fs
        npuertos = sum(len(v) for v in derive_targets(fs).values())
        riesgo = [f for f in fs if f.category == "exposicion"]
        linea = f"          {ip}: {npuertos} puerto(s) abierto(s)"
        if riesgo:
            linea += f"  (!) {len(riesgo)} de riesgo"
        session.say(linea)
    session.add_findings(findings)
    return findings


def _enumerar_con_avance(session: AuditorSession, ip: str) -> list[Finding]:
    scope = session.scope
    session.say(f"  [enum] {ip}: enumerando servicios...")
    nuevos: list[Finding] = []
    ports = session.targets.get(ip, [])
    for e in ports:
        if is_web(e):
            session.say(f"         web {ip}:{e['port']} (whatweb/nikto)...")
            nuevos += enum.enum_web(scope, ip, e["port"])
            if is_tls(e):
                session.say(f"         tls {ip}:{e['port']} (sslscan)...")
                nuevos += enum.enum_tls(scope, ip, e["port"])
    if any(is_smb(e) for e in ports):
        session.say(f"         smb {ip} (enum4linux/smbmap)...")
        nuevos += enum.enum_smb(scope, ip)
    session.add_findings(nuevos)
    return nuevos


def _vulns_con_avance(session: AuditorSession, ip: str) -> list[Finding]:
    scope = session.scope
    session.say(f"  [vuln] {ip}: nmap NSE vuln...")
    nuevos: list[Finding] = list(vuln.scan_vulns_nmap(scope, ip))
    for e in session.targets.get(ip, []):
        if is_web(e):
            session.say(f"         nuclei {ip}:{e['port']}...")
            nuevos += vuln.scan_vulns_nuclei(scope, ip, e["port"])
        if e.get("banner"):
            nuevos += vuln.search_exploits(e["svc"], e["banner"])
    crit = [f for f in nuevos if f.severity >= Severity.HIGH]
    if crit:
        session.say(f"         (!) {len(crit)} hallazgo(s) ALTA+ en {ip}")
    session.add_findings(nuevos)
    return nuevos


def _auditoria_completa(session: AuditorSession) -> dict:
    scope = session.scope
    if not recon.nmap_available():
        return {"error": "nmap no esta instalado (sudo apt install nmap)."}
    if not scope.phase_allowed("recon"):
        return {"error": "el alcance no autoriza 'recon'."}

    session.say("")
    session.say(f"  == AUDITORIA de {', '.join(scope.targets)} ==")
    session.say("  -- Fase 1: reconocimiento --")
    _recon_con_avance(session)
    fases = ["recon"]
    if scope.phase_allowed("enum") and session.targets:
        fases.append("enum")
        session.say("  -- Fase 2: enumeracion --")
        for ip in sorted(session.targets):
            _enumerar_con_avance(session, ip)
    if scope.phase_allowed("vuln") and session.targets:
        fases.append("vuln")
        session.say("  -- Fase 3: vulnerabilidades --")
        for ip in sorted(session.targets):
            _vulns_con_avance(session, ip)

    ruta = _guardar_json(session, fases)
    session.say(f"  == Auditoria terminada. Evidencia: {ruta} ==")
    # Aviso automatico al operador si tiene el correo configurado.
    try:
        from sentinel.core.config import load_settings
        if notify.configured(load_settings().get("notify") or {}):
            _avisar(session, {"asunto": f"SENTINEL Rojo — {scope.engagement}"})
    except Exception:
        pass
    session.say("")
    return {"fases": fases, "conteo": _conteo(session.findings),
            "total_equipos": len(session.targets),
            "por_equipo": {ip: [_brief(f) for f in session.findings
                                if (f.evidence or {}).get("equipo") == ip][:10]
                           for ip in sorted(session.targets)},
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
        "COMO TRABAJAS (el operador MANDA; tu ejecutas y muestras cada paso):\n"
        "1. ENTIENDE la intencion real del operador aunque hable informal o con "
        "faltas de ortografia. Deduce lo que puedas; no preguntes lo obvio.\n"
        "2. OBEDECE PASO A PASO: haz EXACTAMENTE lo que te pide, ni mas ni menos, "
        "un paso por vez. 'escanea/reconoce el .5' -> escanear_equipo; 'enumera "
        "el .5' -> enumerar; 'busca vulns en el .10' -> buscar_vulnerabilidades; "
        "'reconoce la red' -> reconocer; 'explota/entra/consigue shell en el .5' -> "
        "explotar (requiere fase 'exploit' autorizada); 'avisame/mandame al correo' "
        "-> avisar_por_correo. Corre auditoria_completa SOLO si pide 'todo/"
        "completo/auditalo entero'. NO te adelantes a fases que no te pidieron.\n"
        "3. NARRA CADA AVANCE, como un operador humano al lado: antes de actuar di "
        "en UNA linea que vas a hacer y por que; ejecuta la herramienta (su avance "
        "se muestra en vivo); al terminar reporta el resultado de ESE paso; y "
        "ESPERA la siguiente orden.\n"
        "4. RAZONA como pentester sobre los resultados: relaciona servicio/version "
        "con el riesgo y CVEs probables (p.ej. SMB en Windows antiguo -> candidato "
        "a EternalBlue MS17-010; verificalo con buscar_vulnerabilidades). Descarta "
        "ruido, prioriza por severidad e impacto real. Sugiere el siguiente paso, "
        "pero deja que el operador decida.\n"
        "5. Al cerrar un paso o cuando te pidan 'resume/informe', REPORTA con "
        "formato PROFESIONAL de pentester:\n"
        "   - RESUMEN EJECUTIVO (1-2 lineas): postura general y lo mas critico.\n"
        "   - HALLAZGOS ordenados por severidad (CRITICA/ALTA primero), cada uno: "
        "**severidad** equipo:puerto/servicio - que es y por que importa - tecnica "
        "MITRE ATT&CK - remediacion del equipo azul.\n"
        "   - PROXIMOS PASOS recomendados.\n"
        "   Usa vinetas y **negritas**. Tecnico, claro y en espanol. No inventes "
        "severidades: usa las que traen los hallazgos.\n\n"
        "REGLAS INVIOLABLES:\n"
        "- Operas SOLO dentro del alcance. El guardian bloquea lo demas; si algo "
        "cae fuera, lo dices y sigues.\n"
        "- No disparas explotacion automatica: como mucho PREPARAS scripts (.rc) "
        "para revision humana. Nunca finjas haber explotado ni tener una shell.\n"
        "- HONESTIDAD TOTAL: reporta solo lo que las herramientas devuelven. Jamas "
        "inventes equipos, puertos, CVEs ni resultados. Si una herramienta no esta "
        "instalada o no devolvio nada, dilo tal cual.\n"
        "- NUNCA preguntes 'quien autoriza' ni pidas actas: el operador autoriza al "
        "pedirlo. Responde SIEMPRE en espanol.\n"
        "- NUNCA muestres tu razonamiento interno, deliberaciones ni texto en "
        "ingles. Nada de 'We need to...' ni 'The user says...'. Responde DIRECTO al "
        "operador: la accion y su resultado, en espanol y conciso.\n"
        "- EXPLOTACION: si (y solo si) el alcance autoriza la fase 'exploit', "
        "puedes EJECUTAR con Metasploit ('explota'/'entra'/'consigue shell' -> "
        "explotar), que abre sesion y hace post-explotacion basica sobre el "
        "objetivo AUTORIZADO y en alcance. Si la fase 'exploit' no esta autorizada, "
        "solo preparas el script (preparar_exploit) para revision manual. Nunca "
        "explotas fuera de alcance.\n"
        "- No escribes C2/implantes propios: usas Metasploit/Meterpreter (estandar). "
        "El 'correo' es un AVISO al operador con el resumen (avisar_por_correo), "
        "entrega de informe, jamas exfiltracion de datos de terceros.\n\n"
        "INTERPRETA el objetivo sin fastidiar con preguntas:\n"
        "- 'escanea mi ip'/'mi red'/'esta maquina'/'aqui'/'esto'/'donde estas'/"
        "'sal de aqui' -> el objetivo es la red local: llama detectar_red_local "
        "('mi ip' = la IP sola, 'mi red'/'aqui' = la subred /24) y fijala con "
        "configurar_alcance. NO vuelvas a preguntar el objetivo.\n"
        "- una IP o rango directo -> configurar_alcance con eso.\n"
        "- Una vez fijado el objetivo, haz SOLO la accion que te pidio (un paso), "
        "salvo que diga 'todo/completo'. Si dio objetivo pero no accion, propon el "
        "siguiente paso y espera su OK.\n\n")
    if scope is None:
        return base + (
            "ESTADO: aun no hay objetivo. Fijalo con configurar_alcance en cuanto "
            "sepas a que apuntar (detectar_red_local si dijo 'aqui'/'mi red'). "
            "Luego ejecuta SOLO lo que te pida, paso a paso.")
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
    session.progress = print_fn        # 'avance tras avance' en vivo
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
