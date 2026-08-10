"""autonomous.py — Motor AUTONOMO de SENTINEL Rojo: el pentester que piensa solo.

A diferencia del agente conversacional (`agent.py`), que espera instrucciones
entre turnos, el motor autonomo recibe UNA MISION y la ejecuta de punta a punta
sin intervencion humana. El LLM planifica, ejecuta, razona, se adapta y reporta.

La pieza clave es `ejecutar_comando`: le da al cerebro (LLM) acceso a CUALQUIER
comando del sistema (Kali Linux). Con eso puede improvisar, instalar herramientas,
escribir scripts, encadenar tecnicas no previstas — como un pentester real.

El alcance de red (`scope.py`) sigue de fondo como red de seguridad para no
tocar IPs fuera del laboratorio, pero dentro del perimetro autorizado el agente
tiene LIBERTAD TOTAL de accion.

Uso:
    python -m sentinel.attack --autonomo --scope alcance.json \\
        --mision "sal de aqui y avisame como lo hiciste"

Expone:
    AUTONOMOUS_TOOL_SPECS    herramientas del modo autonomo (function calling)
    execute_autonomous_tool  ejecuta una herramienta autonoma
    run_autonomous           bucle principal (sin input humano)
"""
from __future__ import annotations

import os
import json
import time
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sentinel.core.monitor import Finding, Severity
from sentinel.core.auditor.scope import Scope, ScopeError, build_scope
from sentinel.core.auditor import agent as chat_agent
from sentinel.core import llm, notify

# Limite de salida que se pasa al LLM (evita reventar el contexto).
_MAX_OUTPUT = 8000
# Iteraciones maximas del bucle autonomo (cada una puede invocar varias tools).
_MAX_ITERATIONS = 100
# max_tokens para el LLM en modo autonomo (necesita espacio para razonar).
_AUTONOMOUS_MAX_TOKENS = 4096


# ── Estado de la operacion autonoma ──────────────────────────────────────────

@dataclass
class AutonomousRun:
    mission: str
    session: chat_agent.AuditorSession
    api_key: str
    model: str
    bitacora: list[dict] = field(default_factory=list)
    plan: str = ""
    comandos_ejecutados: int = 0
    inicio: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def log(self, tipo: str, contenido: str, **extra) -> None:
        entrada = {"ts": datetime.now().isoformat(timespec="seconds"),
                   "tipo": tipo, "contenido": contenido, **extra}
        self.bitacora.append(entrada)

    def say(self, msg: str) -> None:
        self.session.say(msg)
        self.log("avance", msg)


# ── Herramientas autonomas ───────────────────────────────────────────────────

def _t(name: str, desc: str, props: dict | None = None,
       required: list[str] | None = None) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object",
                       "properties": props or {},
                       "required": required or []}}}


AUTONOMOUS_TOOL_SPECS = [
    _t("ejecutar_comando",
       "Ejecuta CUALQUIER comando en esta maquina Kali y devuelve la salida. "
       "Es tu herramienta principal: con ella puedes correr nmap, msfconsole, "
       "hydra, curl, python3, bash, ssh, smbclient, evil-winrm, crackmapexec, "
       "sqlmap, gobuster, john, hashcat, o CUALQUIER otro binario del sistema. "
       "Si necesitas hacer algo, ejecuta el comando. Si un comando falla, lee "
       "el stderr y adapta. No hay limites: tienes root en esta Kali.",
       {"comando": {"type": "string",
                    "description": "Comando a ejecutar (tal como lo escribirias "
                                   "en la terminal). Puede ser multi-linea con "
                                   "&& o pipes."},
        "timeout": {"type": "integer",
                    "description": "Timeout en segundos (default 120, max 600). "
                                   "Usa mas para escaneos largos o fuerza bruta."}},
       ["comando"]),

    _t("leer_archivo",
       "Lee el contenido de un archivo en esta Kali. Util para revisar "
       "resultados guardados, configs, scripts, wordlists, etc.",
       {"ruta": {"type": "string", "description": "Ruta absoluta del archivo."},
        "lineas": {"type": "integer",
                   "description": "Maximo de lineas a leer (default 200). "
                                  "Para archivos largos, lee solo lo que necesites."}},
       ["ruta"]),

    _t("escribir_archivo",
       "Crea o sobreescribe un archivo en esta Kali. Usalo para escribir "
       "scripts (Python, Bash, Ruby), payloads, resource scripts de Metasploit, "
       "configuraciones, wordlists personalizadas, o cualquier archivo que "
       "necesites para la operacion.",
       {"ruta": {"type": "string", "description": "Ruta absoluta donde escribir."},
        "contenido": {"type": "string", "description": "Contenido del archivo."},
        "ejecutable": {"type": "boolean",
                       "description": "Si true, marca el archivo como ejecutable "
                                      "(chmod +x). Util para scripts."}},
       ["ruta", "contenido"]),

    _t("instalar_herramienta",
       "Instala un paquete con apt (Debian/Kali). Usalo si necesitas una "
       "herramienta que no esta instalada: hydra, evil-winrm, gobuster, "
       "crackmapexec, john, hashcat, seclists, wordlists, o cualquier otra. "
       "Tambien puedes instalar con pip3 o gem si es una herramienta Python/Ruby.",
       {"paquete": {"type": "string",
                    "description": "Nombre del paquete (ej: 'hydra', 'evil-winrm', "
                                   "'seclists'). Para pip: 'pip3:nombre'. "
                                   "Para gem: 'gem:nombre'."},
        "forzar": {"type": "boolean",
                   "description": "Si true, reinstala aunque ya exista."}},
       ["paquete"]),

    _t("planificar",
       "Estructura tu plan de ataque ANTES de actuar. No toca la red. Es tu "
       "momento de pensar: que sabes, que no sabes, que vas a intentar, en que "
       "orden, y que esperas encontrar. El plan queda registrado en la bitacora "
       "(evidencia para la tesis). USALA al inicio y cada vez que necesites "
       "replantear la estrategia.",
       {"plan": {"type": "string",
                 "description": "Tu plan de ataque estructurado. Se lo mas "
                                "detallado que puedas: objetivo, pasos, "
                                "herramientas, alternativas si algo falla."}},
       ["plan"]),

    _t("reportar_progreso",
       "Documenta que llevas hecho, que encontraste y que sigue. Es tu "
       "bitacora de operacion: cada entrada queda en el reporte final. Usalo "
       "despues de cada fase importante (recon, enum, vuln, exploit, post-exploit, "
       "pivoting, etc.).",
       {"fase": {"type": "string",
                 "description": "Fase actual (recon/enum/vuln/exploit/post/pivot/fin)."},
        "resumen": {"type": "string",
                    "description": "Que hiciste y que encontraste en esta fase."},
        "hallazgos_clave": {"type": "array", "items": {"type": "string"},
                            "description": "Lista de hallazgos importantes de esta fase."},
        "siguiente": {"type": "string",
                      "description": "Que vas a hacer ahora basandote en lo que encontraste."}},
       ["fase", "resumen"]),

    _t("mision_cumplida",
       "Declara la mision como CUMPLIDA (o fallida si no pudiste). Detiene el "
       "bucle autonomo, guarda toda la evidencia y envia el correo al operador "
       "con el reporte completo. USALA cuando hayas logrado el objetivo o cuando "
       "hayas agotado todas las opciones.",
       {"exito": {"type": "boolean",
                  "description": "True si cumpliste la mision, False si no pudiste."},
        "reporte": {"type": "string",
                    "description": "Reporte COMPLETO para el operador: que hiciste, "
                                   "que encontraste, como entraste (o por que no pudiste), "
                                   "evidencia, recomendaciones. Este texto se envia por "
                                   "correo. Hazlo profesional y detallado."}},
       ["exito", "reporte"]),
]


# ── Ejecucion de herramientas autonomas ──────────────────────────────────────

def execute_autonomous_tool(run: AutonomousRun, name: str, args: dict) -> dict:
    """Ejecuta una herramienta autonoma. Nunca lanza."""
    try:
        return _dispatch_autonomous(run, name, args or {})
    except Exception as e:
        return {"error": f"herramienta '{name}' fallo: {type(e).__name__}: {e}"}


def _dispatch_autonomous(run: AutonomousRun, name: str, args: dict) -> dict:

    if name == "ejecutar_comando":
        return _ejecutar_comando(run, args)

    if name == "leer_archivo":
        return _leer_archivo(args)

    if name == "escribir_archivo":
        return _escribir_archivo(args)

    if name == "instalar_herramienta":
        return _instalar_herramienta(run, args)

    if name == "planificar":
        plan = str(args.get("plan", ""))
        run.plan = plan
        run.log("plan", plan)
        run.say(f"  [plan] Estrategia registrada ({len(plan)} chars)")
        return {"registrado": True, "nota": "Plan guardado en la bitacora."}

    if name == "reportar_progreso":
        fase = str(args.get("fase", ""))
        resumen = str(args.get("resumen", ""))
        hallazgos = args.get("hallazgos_clave") or []
        siguiente = str(args.get("siguiente", ""))
        run.log("progreso", resumen, fase=fase,
                hallazgos_clave=hallazgos, siguiente=siguiente)
        run.say(f"  [progreso] {fase}: {resumen[:120]}")
        return {"registrado": True}

    if name == "mision_cumplida":
        exito = bool(args.get("exito", False))
        reporte = str(args.get("reporte", ""))
        # Guardia: no permitir rendirse prematuramente.
        if run.comandos_ejecutados < _MIN_COMMANDS_BEFORE_END:
            run.say(f"  [guardia] Rechazado: solo llevas {run.comandos_ejecutados} "
                    f"comandos (minimo {_MIN_COMMANDS_BEFORE_END}). Sigue trabajando.")
            return {"error": f"No puedes terminar aun. Solo has ejecutado "
                             f"{run.comandos_ejecutados} comandos de minimo "
                             f"{_MIN_COMMANDS_BEFORE_END}. Sigue con la siguiente "
                             "fase de tu plan. Si algo fallo, busca otro camino. "
                             "NO te rindas."}
        run.log("fin", reporte, exito=exito)
        run.say(f"  [{'MISION CUMPLIDA' if exito else 'MISION FALLIDA'}]")
        return {"fin": True, "exito": exito, "reporte": reporte}

    # Si no es una herramienta autonoma, delegar al agente conversacional.
    return chat_agent.execute_tool(run.session, name, args)


def _ejecutar_comando(run: AutonomousRun, args: dict) -> dict:
    comando = str(args.get("comando", "")).strip()
    if not comando:
        return {"error": "comando vacio."}
    timeout = min(int(args.get("timeout", 120) or 120), 600)

    run.comandos_ejecutados += 1
    run.say(f"  [cmd #{run.comandos_ejecutados}] {comando[:120]}"
            + ("..." if len(comando) > 120 else ""))
    run.log("comando", comando, timeout=timeout)

    try:
        proc = subprocess.run(
            comando, shell=True, capture_output=True, text=True,
            timeout=timeout, env={**os.environ, "TERM": "dumb"})
    except subprocess.TimeoutExpired:
        run.log("timeout", f"comando excedio {timeout}s: {comando[:200]}")
        return {"error": f"timeout ({timeout}s)", "comando": comando[:200],
                "nota": "Intenta con un timeout mas largo o simplifica el comando."}
    except OSError as e:
        return {"error": f"no se pudo ejecutar: {e}"}

    stdout = (proc.stdout or "")
    stderr = (proc.stderr or "")
    truncated = False
    if len(stdout) > _MAX_OUTPUT:
        stdout = stdout[-_MAX_OUTPUT:]
        truncated = True

    run.log("resultado", f"exit={proc.returncode}",
            stdout_chars=len(proc.stdout or ""),
            stderr_chars=len(proc.stderr or ""))

    return {"exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr[-2000:] if len(stderr) > 2000 else stderr,
            "truncated": truncated}


def _leer_archivo(args: dict) -> dict:
    ruta = str(args.get("ruta", "")).strip()
    if not ruta:
        return {"error": "ruta vacia."}
    lineas_max = int(args.get("lineas", 200) or 200)
    try:
        p = Path(ruta)
        if not p.exists():
            return {"error": f"no existe: {ruta}"}
        if p.stat().st_size > 5_000_000:
            return {"error": f"archivo demasiado grande ({p.stat().st_size} bytes). "
                             "Usa ejecutar_comando con head/tail/grep para leer partes."}
        texto = p.read_text(encoding="utf-8", errors="replace")
        lineas = texto.splitlines()
        if len(lineas) > lineas_max:
            return {"contenido": "\n".join(lineas[:lineas_max]),
                    "total_lineas": len(lineas), "truncado": True,
                    "nota": f"Mostrando {lineas_max}/{len(lineas)} lineas."}
        return {"contenido": texto, "total_lineas": len(lineas)}
    except Exception as e:
        return {"error": f"no se pudo leer: {e}"}


def _escribir_archivo(args: dict) -> dict:
    ruta = str(args.get("ruta", "")).strip()
    contenido = str(args.get("contenido", ""))
    ejecutable = bool(args.get("ejecutable", False))
    if not ruta:
        return {"error": "ruta vacia."}
    try:
        p = Path(ruta)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido, encoding="utf-8")
        if ejecutable:
            p.chmod(0o755)
        return {"ok": True, "ruta": str(p.resolve()),
                "bytes": len(contenido.encode("utf-8")),
                "ejecutable": ejecutable}
    except Exception as e:
        return {"error": f"no se pudo escribir: {e}"}


def _instalar_herramienta(run: AutonomousRun, args: dict) -> dict:
    paquete = str(args.get("paquete", "")).strip()
    if not paquete:
        return {"error": "nombre de paquete vacio."}

    if paquete.startswith("pip3:"):
        nombre = paquete.split(":", 1)[1].strip()
        run.say(f"  [install] pip3 install {nombre}")
        run.log("instalar", f"pip3 install {nombre}")
        return _ejecutar_comando(run, {"comando": f"pip3 install {nombre}",
                                       "timeout": 120})

    if paquete.startswith("gem:"):
        nombre = paquete.split(":", 1)[1].strip()
        run.say(f"  [install] gem install {nombre}")
        run.log("instalar", f"gem install {nombre}")
        return _ejecutar_comando(run, {"comando": f"gem install {nombre}",
                                       "timeout": 120})

    run.say(f"  [install] apt install -y {paquete}")
    run.log("instalar", f"apt install -y {paquete}")
    return _ejecutar_comando(run, {
        "comando": f"DEBIAN_FRONTEND=noninteractive apt-get install -y {paquete}",
        "timeout": 300})


# Minimo de comandos ejecutados antes de permitir mision_cumplida.
# Evita que el agente se rinda prematuramente.
_MIN_COMMANDS_BEFORE_END = 10


# ── System prompt autonomo ───────────────────────────────────────────────────

def system_prompt_autonomous(scope: Scope | None, mission: str,
                             full_power: bool = True) -> str:
    prompt = (
        "Eres SENTINEL Rojo AUTONOMO: un HACKER ETICO EXPERTO que opera SOLO. "
        "NO eres un chatbot. NO eres un asistente. Eres un OPERADOR OFENSIVO "
        "con años de experiencia en pentesting. Te dejaron en una Kali Linux "
        "con una MISION y no paras hasta cumplirla.\n\n"

        "═══════════════════════════════════════════\n"
        "TU MISION:\n"
        f"  {mission}\n"
        "═══════════════════════════════════════════\n\n"

        "MENTALIDAD (la de un pentester real, no la de un chatbot):\n"
        "- NUNCA te rindes al primer obstaculo. Si algo falla, BUSCAS OTRO CAMINO.\n"
        "- Si el correo no funciona, usas curl a un webhook, o Python con smtplib "
        "directo, o escribes el resultado en un archivo accesible, o lo mandas por "
        "netcat. SIEMPRE hay otra forma.\n"
        "- Si un exploit falla, pruebas OTRO. Si no hay exploit conocido, buscas "
        "misconfiguraciones. Si no hay misconfiguraciones, intentas credenciales "
        "por defecto. AGOTAS las opciones.\n"
        "- Un pentester real no hace 3 comandos y se rinde. Hace 30, 50, 100 "
        "hasta encontrar el camino. TU TAMBIEN.\n"
        "- PIENSA EN VOZ ALTA sobre lo que ves: 'este servicio en esa version "
        "tiene tal CVE, voy a probar...' — razona como un profesional.\n\n"

        "FASES OBLIGATORIAS (en este orden, TODAS):\n\n"

        "FASE 1 — RECONOCIMIENTO:\n"
        "- Detecta tu IP y subred (ip addr)\n"
        "- Configura el alcance (configurar_alcance)\n"
        "- Descubre equipos vivos (nmap -sn)\n"
        "- Escanea TODOS los puertos abiertos de CADA equipo (nmap -sV -sC -A)\n"
        "- Identifica el sistema operativo, versiones de servicios, banners\n\n"

        "FASE 2 — ENUMERACION PROFUNDA (para CADA equipo encontrado):\n"
        "- Web: whatweb, nikto, gobuster/dirb para directorios ocultos\n"
        "- SMB: smbclient -L, enum4linux, crackmapexec smb\n"
        "- SSH: version, intenta credenciales comunes\n"
        "- Cada servicio que encuentres: buscale la vuelta\n"
        "- Busca credenciales por defecto, archivos expuestos, paneles de admin\n\n"

        "FASE 3 — VULNERABILIDADES:\n"
        "- nmap --script vuln contra cada equipo\n"
        "- searchsploit para cada servicio+version que encontraste\n"
        "- Busca CVEs conocidos para las versiones detectadas\n"
        "- Si hay web: prueba inyecciones SQL, LFI, RFI con herramientas\n\n"

        "FASE 4 — EXPLOTACION (la mas importante, NO la saltes):\n"
        "- Para CADA vulnerabilidad encontrada, intenta explotarla\n"
        "- Usa msfconsole con los modulos que encuentres\n"
        "- Si no hay exploit en Metasploit, busca en searchsploit y adaptalo\n"
        "- Prueba credenciales por defecto (admin/admin, root/toor, etc.)\n"
        "- Intenta fuerza bruta con hydra si encuentras SSH/FTP/SMB\n"
        "- Si un exploit falla, prueba otro. NO te rindas en el primero.\n\n"

        "FASE 5 — POST-EXPLOTACION (si entraste a un equipo):\n"
        "- Saca informacion del sistema (whoami, id, uname -a)\n"
        "- Busca credenciales (archivos de config, /etc/shadow, hashdump)\n"
        "- Intenta escalar privilegios (sudo -l, SUID, kernel exploits)\n"
        "- Busca otros equipos desde ahi (pivoting)\n"
        "- Documenta TODO lo que encuentres\n\n"

        "FASE 6 — COMUNICAR RESULTADOS:\n"
        "- Intenta avisar_por_correo. Si FALLA, no te rindas. Haz esto:\n"
        "  1. Escribe un script Python que envie el correo directo con smtplib\n"
        "  2. Si eso falla, usa curl para enviar a un servicio de notificaciones\n"
        "  3. Si eso falla, guarda el reporte completo en un archivo accesible\n"
        "  4. El punto es: BUSCA LA MANERA de comunicarte, no te rindas\n\n"

        "REGLAS DE COMBATE:\n"
        "- NO llames a mision_cumplida hasta haber ejecutado AL MENOS 10 "
        "comandos. Si lo intentas antes, el sistema te lo rechazara.\n"
        "- NO te rindas porque una herramienta fallo. SIEMPRE hay alternativa.\n"
        "- NO dejes equipos sin explorar. Si hay 3 equipos, los 3 se auditan.\n"
        "- NO hagas solo reconocimiento. EXPLOTA lo que encuentres.\n"
        "- HONESTIDAD: reporta SOLO lo que realmente paso. Jamas inventes.\n"
        "- RESPONDE SIEMPRE EN ESPAÑOL. Nada en ingles.\n"
        "- Lee la salida de CADA comando COMPLETA antes de decidir el siguiente.\n"
        "- Cuando un camino no funciona despues de 3 intentos, cambia a otro.\n"
        "  Pero NO abandones la fase: busca OTRO vector de ataque.\n\n"

        "HERRAMIENTAS:\n"
        "- ejecutar_comando: CUALQUIER comando de Kali. Es tu arma principal.\n"
        "  Usala para TODO: nmap, msfconsole -x '...', hydra, curl, python3 -c, "
        "smbclient, ssh, nikto, gobuster, sqlmap, john, hashcat, enum4linux, "
        "searchsploit, whatweb, sslscan, netcat, wget, etc.\n"
        "- escribir_archivo: crea scripts (Python, Bash, RC de Metasploit)\n"
        "- instalar_herramienta: apt/pip/gem install lo que necesites\n"
        "- planificar: estructura tu plan (obligatorio al inicio)\n"
        "- reportar_progreso: documenta cada fase\n"
        "- mision_cumplida: SOLO cuando hayas terminado TODAS las fases\n"
        "- Las herramientas predefinidas (reconocer, enumerar, etc.) son atajos "
        "pero ejecutar_comando es mas flexible. Usa lo que te convenga.\n\n"
    )

    if scope is not None:
        s = scope.summary()
        prompt += (
            f"ALCANCE DE RED (perimetro autorizado):\n"
            f"  Objetivos: {', '.join(s['objetivos'])}\n"
            f"  Excluidos: {', '.join(s['excluidos']) or 'ninguno'}\n"
            f"  Fases: {', '.join(s['fases'])}\n\n")
    else:
        prompt += (
            "NO HAY ALCANCE PREVIO. Tu primer paso es detectar donde estas "
            "(ejecutar_comando: 'ip addr') y fijar el alcance con "
            "configurar_alcance. Luego, a trabajar.\n\n")

    prompt += (
        "EMPIEZA AHORA. Planifica y ejecuta. No pares hasta terminar TODAS "
        "las fases. La mision es tuya. GO.\n")

    return prompt


# ── Bucle principal autonomo ─────────────────────────────────────────────────

def run_autonomous(mission: str, scope: Scope | None, api_key: str,
                   model: str = llm.DEFAULT_MODEL,
                   out_dir: str = "evidencia_ofensiva",
                   full_power: bool = True,
                   print_fn=print) -> dict:
    """Bucle autonomo: el LLM recibe la mision y opera solo hasta cumplirla.

    No pide input humano. Imprime avance en vivo. Al terminar genera evidencia
    JSON y envia el correo al operador si esta configurado.
    """
    session = chat_agent.AuditorSession(
        scope=scope, out_dir=out_dir, full_power=full_power)
    session.progress = print_fn

    run = AutonomousRun(
        mission=mission, session=session,
        api_key=api_key, model=model)

    # Todas las herramientas: las autonomas + las del modo conversacional.
    all_tools = AUTONOMOUS_TOOL_SPECS + chat_agent.TOOL_SPECS

    messages = [{"role": "system",
                 "content": system_prompt_autonomous(scope, mission, full_power)}]

    _LINE = "-" * 68
    print_fn("")
    print_fn(f"  {'=' * 68}")
    print_fn(f"  SENTINEL Rojo AUTONOMO")
    print_fn(f"  {'=' * 68}")
    print_fn(f"  Mision: {mission}")
    print_fn(f"  Cerebro: {model}")
    if scope:
        print_fn(f"  Alcance: {', '.join(scope.targets)}")
    else:
        print_fn(f"  Alcance: (auto-deteccion)")
    print_fn(f"  Max iteraciones: {_MAX_ITERATIONS}")
    print_fn(f"  Inicio: {run.inicio}")
    print_fn(f"  {_LINE}")
    print_fn(f"  El agente opera SOLO a partir de aqui. No se pide input.")
    print_fn(f"  Ctrl+C para detener de emergencia.")
    print_fn(f"  {_LINE}")
    print_fn("")

    reporte_final = ""
    exito = False
    fin = False

    for iteracion in range(1, _MAX_ITERATIONS + 1):
        if fin:
            break

        resp = llm.complete_resilient(
            messages, all_tools, api_key, model,
            max_tokens=_AUTONOMOUS_MAX_TOKENS, temperature=0.3)

        if "error" in resp:
            print_fn(f"  [cerebro] ERROR: {resp['error']}")
            run.log("error_llm", resp["error"])
            # Reintentar una vez despues de una pausa.
            time.sleep(5)
            resp = llm.complete_resilient(
                messages, all_tools, api_key, model,
                max_tokens=_AUTONOMOUS_MAX_TOKENS, temperature=0.3)
            if "error" in resp:
                print_fn(f"  [cerebro] ERROR persistente. Abortando.")
                run.log("abort", resp["error"])
                break

        msg = resp["message"]
        messages.append(msg)
        calls = chat_agent._extract_tool_calls(msg)

        if not calls:
            # El LLM respondio sin pedir herramientas — puede ser un avance
            # narrativo o que se estanco. Le pedimos que siga.
            contenido = msg.get("content") or ""
            if contenido:
                print_fn(f"\n  SENTINEL> {contenido[:500]}")
                if len(contenido) > 500:
                    print_fn(f"            (...{len(contenido)} chars)")
                print_fn("")
            # Inyectar un empujon para que no se detenga.
            messages.append({"role": "user",
                             "content": "Sigue. Ejecuta el siguiente paso de tu "
                                        "plan. Si ya terminaste, usa mision_cumplida."})
            continue

        for c in calls:
            nombre = c["name"]
            print_fn(f"  [{iteracion}] {nombre}"
                     + (f"({json.dumps(c['args'], ensure_ascii=False)[:200]})"
                        if c["args"] else ""))

            resultado = execute_autonomous_tool(run, nombre, c["args"])

            messages.append({"role": "tool", "tool_call_id": c["id"],
                             "name": nombre,
                             "content": json.dumps(resultado, ensure_ascii=False)})

            # Detectar fin de mision.
            if nombre == "mision_cumplida":
                fin = True
                exito = resultado.get("exito", False)
                reporte_final = resultado.get("reporte", "")
                break

    # ── Cierre ────────────────────────────────────────────────────────────────

    duracion = datetime.now().isoformat(timespec="seconds")
    print_fn("")
    print_fn(f"  {'=' * 68}")
    print_fn(f"  OPERACION AUTONOMA {'COMPLETADA' if exito else 'TERMINADA'}")
    print_fn(f"  Comandos ejecutados: {run.comandos_ejecutados}")
    print_fn(f"  Iteraciones usadas: {min(iteracion, _MAX_ITERATIONS)}")
    print_fn(f"  Hallazgos: {len(session.findings)}")
    print_fn(f"  {'=' * 68}")

    # Guardar evidencia JSON completa.
    evidencia = _guardar_evidencia(run, exito, reporte_final)
    print_fn(f"  Evidencia: {evidencia}")

    # Enviar correo al operador si esta configurado.
    _notificar(run, exito, reporte_final)

    # Imprimir reporte final.
    if reporte_final:
        print_fn("")
        print_fn(f"  {'─' * 68}")
        print_fn(f"  REPORTE DEL AGENTE:")
        print_fn(f"  {'─' * 68}")
        for linea in reporte_final.splitlines():
            print_fn(f"  {linea}")
        print_fn(f"  {'─' * 68}")

    print_fn("")
    return {"exito": exito, "reporte": reporte_final,
            "comandos_ejecutados": run.comandos_ejecutados,
            "hallazgos": len(session.findings),
            "evidencia": str(evidencia),
            "bitacora": run.bitacora}


# ── Guardar evidencia ────────────────────────────────────────────────────────

def _guardar_evidencia(run: AutonomousRun, exito: bool, reporte: str) -> Path:
    destino = Path(run.session.out_dir)
    destino.mkdir(parents=True, exist_ok=True)
    doc = {
        "producto": "SENTINEL Rojo Autonomo",
        "mision": run.mission,
        "inicio": run.inicio,
        "fin": datetime.now().isoformat(timespec="seconds"),
        "exito": exito,
        "modelo": run.model,
        "comandos_ejecutados": run.comandos_ejecutados,
        "plan": run.plan,
        "reporte": reporte,
        "alcance": (run.session.scope.summary() if run.session.scope else None),
        "hallazgos": [f.to_dict() for f in run.session.findings],
        "conteo_hallazgos": {s.label: sum(1 for f in run.session.findings
                                          if f.severity == s) for s in Severity},
        "equipos_descubiertos": sorted(run.session.targets),
        "bitacora": run.bitacora,
    }
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    ruta = destino / f"autonomo_{stamp}.json"
    ruta.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


def _notificar(run: AutonomousRun, exito: bool, reporte: str) -> None:
    """Envia el correo al operador con el reporte de la operacion."""
    try:
        from sentinel.core.config import load_settings
        cfg = (load_settings().get("notify") or {})
        if not notify.configured(cfg):
            run.say("  [aviso] Correo no configurado (notify en settings.json). "
                    "El reporte queda en el JSON de evidencia.")
            return
        estado = "CUMPLIDA" if exito else "NO CUMPLIDA"
        asunto = f"SENTINEL Rojo Autonomo — Mision {estado}"
        cuerpo = [
            "SENTINEL Rojo — Reporte de Operacion Autonoma",
            "=" * 50,
            f"Mision: {run.mission}",
            f"Estado: {estado}",
            f"Comandos ejecutados: {run.comandos_ejecutados}",
            f"Hallazgos: {len(run.session.findings)}",
            f"Modelo: {run.model}",
            f"Inicio: {run.inicio}",
            f"Fin: {datetime.now().isoformat(timespec='seconds')}",
            "",
            "REPORTE COMPLETO:",
            "-" * 50,
            reporte or "(sin reporte)",
            "",
            "BITACORA DE COMANDOS:",
            "-" * 50,
        ]
        for e in run.bitacora:
            if e["tipo"] == "comando":
                cuerpo.append(f"  [{e['ts']}] $ {e['contenido'][:200]}")
            elif e["tipo"] == "progreso":
                cuerpo.append(f"  [{e['ts']}] [{e.get('fase', '?')}] {e['contenido'][:200]}")
        ok, msg = notify.send_email(cfg, asunto, "\n".join(cuerpo))
        run.say(f"  [correo] {msg}")
    except Exception as e:
        run.say(f"  [correo] no se pudo enviar: {e}")
