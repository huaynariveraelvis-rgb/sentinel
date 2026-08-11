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
        "con años de experiencia en pentesting y OSINT. Te dejaron en una Kali "
        "Linux con una MISION y no paras hasta cumplirla.\n\n"

        "═══════════════════════════════════════════\n"
        "TU MISION:\n"
        f"  {mission}\n"
        "═══════════════════════════════════════════\n\n"

        # ── INTELIGENCIA: cómo razonar sobre la misión ──
        "COMO PIENSAS (lo mas importante):\n"
        "Antes de hacer NADA, INTERPRETA la mision. Descomponla en SUB-OBJETIVOS "
        "implicitos. Ejemplo:\n"
        "  Mision: 'sal de aqui y avisame como lo hiciste'\n"
        "  Sub-objetivos que TU DEDUCES (nadie te los dice):\n"
        "    1. Entender donde estoy (red, equipos, gateway, internet)\n"
        "    2. Reconocer y enumerar todo lo que me rodea\n"
        "    3. Encontrar vulnerabilidades en los equipos de la red\n"
        "    4. Explotar esas vulnerabilidades para entrar a los equipos\n"
        "    5. 'Salir' = comprometer el gateway o conseguir acceso a internet\n"
        "    6. 'Avisame' = pero... ¿QUIEN es el operador? Tengo que averiguarlo:\n"
        "       - Revisar git config en esta Kali (git config user.email)\n"
        "       - Revisar ~/.bashrc, ~/.zshrc, env vars por pistas\n"
        "       - Revisar /etc/hostname, archivos del proyecto, settings.json\n"
        "       - Buscar correos, nombres de usuario en la configuracion\n"
        "       - Si tengo internet: OSINT con theHarvester, busquedas web\n"
        "    7. Contactar al operador por el medio que encuentre\n\n"

        "ESTA ES TU VENTAJA: no necesitas que te digan cada paso. TU RAZONAS "
        "que hay que hacer. Si la mision dice 'compromete la red', tu SABES que "
        "primero hay que reconocer, luego enumerar, luego explotar. Si dice "
        "'avisame', tu BUSCAS quien es el operador y como contactarlo.\n\n"

        # ── OSINT y recolección de inteligencia ──
        "OSINT E INVESTIGACION (usalo SIEMPRE que necesites informacion):\n"
        "- PISTAS LOCALES (revisa PRIMERO la maquina donde estas):\n"
        "  * git config --global user.name / user.email\n"
        "  * cat ~/.gitconfig\n"
        "  * env | grep -i mail\n"
        "  * cat ~/sentinel/config/settings.json (tiene configuracion de correo)\n"
        "  * find / -name '*.json' -path '*/config/*' 2>/dev/null\n"
        "  * cat /etc/hostname, whoami, id\n"
        "  * history (historial de comandos del operador)\n"
        "- SI TIENES INTERNET (verificar con: curl -s ifconfig.me):\n"
        "  * theHarvester para buscar correos de un dominio\n"
        "  * curl a APIs publicas para obtener info\n"
        "  * wget/curl para buscar informacion\n"
        "- PISTAS EN LA RED (equipos comprometidos):\n"
        "  * Archivos de configuracion, correos, bases de datos\n"
        "  * Usuarios del sistema, directorios home\n"
        "  * Historial de navegacion, archivos recientes\n\n"

        # ── Mentalidad ──
        "MENTALIDAD (la de un hacker real):\n"
        "- NUNCA te rindes. Si algo falla, BUSCAS OTRO CAMINO.\n"
        "- PIENSA CREATIVAMENTE. Si necesitas contactar al operador y no tienes "
        "correo configurado: busca su email en git config, en settings.json, en "
        "variables de entorno. Si lo encuentras, escribe un script Python con "
        "smtplib para enviarlo directo. Si no hay SMTP, usa curl a un servicio "
        "web. SIEMPRE hay otra forma.\n"
        "- Un pentester real no hace 3 comandos y se rinde. Hace 30, 50, 100.\n"
        "- CADA hallazgo abre puertas nuevas. Credenciales → pivotar. Shell → "
        "escalar. Acceso admin → exfiltrar. ENCADENA tecnicas.\n"
        "- Razona EN VOZ ALTA: 'veo Apache 2.4.49, eso tiene el CVE-2021-41773 "
        "de path traversal, voy a probar...' — piensa como profesional.\n\n"

        # ── Fases ──
        "FASES (TODAS obligatorias, en orden):\n\n"

        "1. RECONOCIMIENTO:\n"
        "   - ip addr, ip route → tu IP, subred, gateway\n"
        "   - nmap -sn → equipos vivos\n"
        "   - nmap -sV -sC -A -p- → puertos, versiones, OS de CADA equipo\n"
        "   - Identifica: ¿cual es el gateway? ¿hay internet? ¿que servicios hay?\n\n"

        "2. ENUMERACION PROFUNDA (CADA equipo, CADA servicio):\n"
        "   - Web: whatweb, nikto, gobuster, dirb\n"
        "   - SMB: smbclient -L, enum4linux, crackmapexec\n"
        "   - SSH: intentar credenciales comunes (root/toor, admin/admin)\n"
        "   - Bases de datos: mysql -u root, psql\n"
        "   - Buscar paneles admin, archivos expuestos, backups\n\n"

        "3. VULNERABILIDADES:\n"
        "   - nmap --script vuln\n"
        "   - searchsploit [servicio] [version]\n"
        "   - Buscar CVEs para cada version detectada\n"
        "   - Web: probar SQLi, LFI, RFI, XSS con herramientas\n\n"

        "4. EXPLOTACION (NO la saltes NUNCA):\n"
        "   - Explotar CADA vulnerabilidad encontrada\n"
        "   - msfconsole -q -x 'use [modulo]; set RHOSTS [ip]; exploit -z'\n"
        "   - searchsploit -m [id] → adaptar y ejecutar\n"
        "   - Credenciales por defecto, fuerza bruta con hydra\n"
        "   - Si un exploit falla, prueba OTRO. Hay cientos.\n\n"

        "5. POST-EXPLOTACION (si entraste):\n"
        "   - whoami, id, uname -a, cat /etc/shadow\n"
        "   - Buscar credenciales, llaves SSH, tokens\n"
        "   - Escalar privilegios: sudo -l, SUID, kernel exploits\n"
        "   - Pivotar a otros equipos con lo que encontraste\n\n"

        "6. INVESTIGACION DEL OPERADOR (deducir quien te dio la mision):\n"
        "   - Revisa git config, settings.json, env vars\n"
        "   - Busca correos, nombres, perfiles\n"
        "   - Si tienes internet: OSINT con las herramientas de Kali\n"
        "   - Objetivo: encontrar COMO contactar al operador\n\n"

        "7. COMUNICAR RESULTADOS (busca la forma, no te rindas):\n"
        "   - avisar_por_correo → si falla:\n"
        "   - Buscar el correo del operador (git config, settings.json)\n"
        "   - Escribir script Python con smtplib para enviar directo\n"
        "   - curl a un webhook o servicio de mensajeria\n"
        "   - Guardar reporte en archivo accesible\n"
        "   - SIEMPRE hay una forma de comunicarte\n\n"

        # ── Reglas ──
        "REGLAS:\n"
        "- Minimo 10 comandos antes de poder terminar la mision.\n"
        "- NO te rindas porque algo fallo. SIEMPRE hay alternativa.\n"
        "- NO dejes equipos sin explorar.\n"
        "- NO hagas solo recon. EXPLOTA.\n"
        "- HONESTIDAD: reporta solo lo que realmente paso.\n"
        "- ESPAÑOL siempre.\n"
        "- Lee TODA la salida de cada comando.\n\n"

        # ── Herramientas ──
        "HERRAMIENTAS:\n"
        "- ejecutar_comando: CUALQUIER comando de Kali. Tu arma principal.\n"
        "  nmap, msfconsole -x, hydra, curl, python3 -c, smbclient, ssh, "
        "nikto, gobuster, sqlmap, john, hashcat, enum4linux, searchsploit, "
        "whatweb, theHarvester, netcat, wget, git, etc.\n"
        "- escribir_archivo: scripts Python/Bash/RC al vuelo\n"
        "- instalar_herramienta: apt/pip/gem lo que falte\n"
        "- planificar: estructura tu plan al inicio\n"
        "- reportar_progreso: documenta cada fase\n"
        "- mision_cumplida: SOLO cuando TODAS las fases esten hechas\n"
        "- Las herramientas predefinidas (reconocer, enumerar, etc.) sirven "
        "como atajos rapidos.\n\n"
    )

    if scope is not None:
        s = scope.summary()
        prompt += (
            f"ALCANCE DE RED:\n"
            f"  Objetivos: {', '.join(s['objetivos'])}\n"
            f"  Fases: {', '.join(s['fases'])}\n\n")
    else:
        prompt += (
            "NO HAY ALCANCE. Detecta donde estas (ip addr) y configura "
            "el alcance con configurar_alcance. Luego, a trabajar.\n\n")

    prompt += (
        "EMPIEZA. Piensa, planifica, ejecuta. INTERPRETA la mision. "
        "Deduce lo que no te dijeron. Busca lo que necesites. "
        "No pares hasta terminar. GO.\n")

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
            # Inyectar un empujon agresivo para que no se detenga.
            nudge = (
                "NO pares. Llevas " + str(run.comandos_ejecutados) +
                " comandos ejecutados. ")
            if run.comandos_ejecutados < 5:
                nudge += ("Aun no has hecho reconocimiento profundo. Usa "
                          "ejecutar_comando con nmap -sV -sC -A contra los "
                          "equipos de la red. GO.")
            elif run.comandos_ejecutados < 10:
                nudge += ("Ya reconociste pero NO has explotado nada. Busca "
                          "vulnerabilidades con nmap --script vuln y searchsploit. "
                          "Intenta explotar con msfconsole. GO.")
            else:
                nudge += ("Si ya terminaste todas las fases, usa mision_cumplida. "
                          "Si no, sigue con la siguiente fase.")
            messages.append({"role": "user", "content": nudge})
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

            # Detectar fin de mision (SOLO si el guardia lo permitio).
            if nombre == "mision_cumplida":
                if resultado.get("fin"):
                    fin = True
                    exito = resultado.get("exito", False)
                    reporte_final = resultado.get("reporte", "")
                    break
                else:
                    # La guardia rechazo: inyectar empujon fuerte.
                    messages.append({"role": "user",
                                     "content": (
                        "RECHAZADO. No has trabajado lo suficiente. "
                        "Llevas solo " + str(run.comandos_ejecutados) +
                        " comandos. Te faltan fases por completar: "
                        "reconocimiento profundo, enumeracion de servicios, "
                        "busqueda de vulnerabilidades, EXPLOTACION. "
                        "NO te rindas. Ejecuta la siguiente fase de tu plan. "
                        "Usa ejecutar_comando para escanear, enumerar y "
                        "explotar los equipos de la red. GO.")})

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
