"""scope.py — Alcance autorizado del engagement (la ley del Auditor).

Un pentester profesional no se distingue de un atacante por las herramientas,
sino por el ALCANCE firmado que delimita lo que puede tocar: que rango de red,
en que ventana horaria y hasta que fase. Este modulo convierte ese documento en
codigo que se hace cumplir solo.

El alcance vive en un JSON que el responsable del laboratorio autoriza. Ejemplo:

    {
      "engagement":     "Auditoria Lab SENATI - Aula 3",
      "authorized_by":  "Ing. Responsable del laboratorio",
      "authorization_ref": "ACTA-2026-014",
      "operator":       "Elvis Huayna",
      "targets":        ["192.168.1.0/24"],
      "excludes":       ["192.168.1.1", "192.168.1.10"],
      "window":         {"start": "2026-08-10T08:00:00", "end": "2026-08-10T18:00:00"},
      "allowed_phases": ["recon", "enum", "vuln"]
    }

Diseno defensivo, igual que el resto de SENTINEL:
  * Si el archivo falta o esta mal formado, el Auditor NO corre (falla cerrado).
  * `excludes` manda sobre `targets`: lo excluido nunca se toca, aunque caiga
    dentro de un rango permitido.
  * Fuera de la ventana horaria, ninguna fase se autoriza.
  * Las fases se declaran explicitamente; explotacion no esta en la lista por
    defecto y hay que autorizarla a proposito.
"""
from __future__ import annotations

import json
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


class ScopeError(Exception):
    """El alcance no existe, es invalido, o una accion se sale de el.

    Es una excepcion 'dura' a proposito: cualquier intento de operar fuera del
    alcance detiene al Auditor en vez de degradar en silencio.
    """


# Fases del engagement, de menos a mas intrusivas. El orden importa: una fase
# solo tiene sentido si las previas estan permitidas.
PHASES = ("recon", "enum", "vuln", "creds", "exploit")


@dataclass
class Scope:
    engagement: str
    authorized_by: str
    operator: str
    targets: list[str]
    allowed_phases: list[str]
    authorization_ref: str = ""
    excludes: list[str] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None

    # Redes ya parseadas (se llenan en load_scope para no repetir el trabajo).
    _nets: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)
    _excl: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)

    # ── Consultas ────────────────────────────────────────────────────────────

    def in_scope(self, ip: str) -> bool:
        """True si `ip` esta dentro del alcance y no esta excluida."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in self._excl):
            return False
        return any(addr in net for net in self._nets)

    def window_open(self, now: datetime | None = None) -> bool:
        """True si el momento actual cae dentro de la ventana autorizada.

        Sin ventana definida se asume abierta: el alcance por rango sigue
        limitando igual, pero no se restringe el horario.
        """
        if self.window_start is None or self.window_end is None:
            return True
        now = now or datetime.now()
        return self.window_start <= now <= self.window_end

    def phase_allowed(self, phase: str) -> bool:
        return phase in self.allowed_phases

    # ── Guardas (lanzan si algo se sale del alcance) ─────────────────────────

    def assert_target(self, ip: str) -> None:
        """Detiene al Auditor si `ip` no esta autorizada. Esta es la barrera
        que toda sonda cruza antes de tocar un equipo."""
        if not self.in_scope(ip):
            raise ScopeError(
                f"FUERA DE ALCANCE: {ip} no esta autorizada por '{self.engagement}'. "
                f"El Auditor no la tocara.")

    def assert_can_run(self, phase: str, now: datetime | None = None) -> None:
        """Verifica fase + ventana antes de arrancar una etapa completa."""
        if phase not in PHASES:
            raise ScopeError(f"Fase desconocida: '{phase}'.")
        if not self.phase_allowed(phase):
            raise ScopeError(
                f"Fase '{phase}' NO autorizada en este engagement. "
                f"Autorizadas: {', '.join(self.allowed_phases) or '(ninguna)'}.")
        if not self.window_open(now):
            raise ScopeError(
                "FUERA DE VENTANA: la auditoria solo esta autorizada entre "
                f"{self.window_start} y {self.window_end}.")

    def targets_only_in_scope(self, ips: list[str]) -> list[str]:
        """Filtra una lista de equipos descubiertos dejando solo los del alcance.
        Util tras un barrido de descubrimiento amplio."""
        return [ip for ip in ips if self.in_scope(ip)]

    def summary(self) -> dict:
        """Cabecera para el informe: quien autorizo, que y cuando."""
        return {
            "engagement": self.engagement,
            "autorizado_por": self.authorized_by,
            "referencia": self.authorization_ref,
            "operador": self.operator,
            "objetivos": self.targets,
            "excluidos": self.excludes,
            "ventana": (f"{self.window_start} — {self.window_end}"
                        if self.window_start else "sin restriccion horaria"),
            "fases": self.allowed_phases,
        }


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError as e:
        raise ScopeError(f"Fecha invalida en la ventana: {value!r} ({e}).")


def load_scope(path: str | Path) -> Scope:
    """Carga y valida el alcance. Lanza ScopeError si algo no cuadra.

    Falla CERRADO: ante cualquier duda, no devuelve un alcance a medias que
    pudiera permitir tocar algo no autorizado.
    """
    p = Path(path)
    if not p.is_file():
        raise ScopeError(
            f"No hay archivo de alcance en {p}. El Auditor no opera sin una "
            f"autorizacion cargada.")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise ScopeError(f"No se pudo leer el alcance: {e}.")
    return build_scope(data)


def build_scope(data: dict) -> Scope:
    """Valida y construye un Scope desde un dict (venga de un archivo o de una
    sesion conversacional). Falla CERRADO: ante cualquier duda no devuelve un
    alcance a medias que pudiera permitir tocar algo no autorizado."""
    if not isinstance(data, dict):
        raise ScopeError("El alcance debe ser un objeto JSON.")

    targets = data.get("targets") or []
    if not isinstance(targets, list) or not targets:
        raise ScopeError("El alcance no declara ningun objetivo ('targets').")

    authorized_by = (data.get("authorized_by") or "").strip()
    if not authorized_by:
        raise ScopeError(
            "El alcance no dice QUIEN autoriza ('authorized_by'). Sin un "
            "responsable identificado no hay autorizacion valida.")

    excludes = data.get("excludes") or []
    phases = data.get("allowed_phases") or []
    if not isinstance(phases, list):
        raise ScopeError("'allowed_phases' debe ser una lista.")
    for ph in phases:
        if ph not in PHASES:
            raise ScopeError(f"Fase desconocida en el alcance: '{ph}'.")

    # Parseo de redes: acepta IP suelta (host/32) o CIDR. strict=False tolera
    # que el usuario escriba 192.168.1.0/24 sin normalizar los bits del host.
    def _nets(items: list, campo: str) -> list:
        out = []
        for item in items:
            try:
                out.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError as e:
                raise ScopeError(f"'{item}' en {campo} no es una IP/CIDR valida ({e}).")
        return out

    win = data.get("window") or {}
    scope = Scope(
        engagement=(data.get("engagement") or "engagement sin nombre").strip(),
        authorized_by=authorized_by,
        operator=(data.get("operator") or "").strip(),
        authorization_ref=(data.get("authorization_ref") or "").strip(),
        targets=[str(t) for t in targets],
        excludes=[str(x) for x in excludes],
        allowed_phases=[str(p) for p in phases],
        window_start=_parse_dt(win.get("start")),
        window_end=_parse_dt(win.get("end")),
        _nets=_nets(targets, "targets"),
        _excl=_nets(excludes, "excludes"),
    )
    if scope.window_start and scope.window_end and scope.window_end < scope.window_start:
        raise ScopeError("La ventana termina antes de empezar.")
    return scope
