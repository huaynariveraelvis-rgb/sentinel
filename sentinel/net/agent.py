"""agent.py — Agente de laboratorio: audita y reporta.

Corre en cada PC del parque. Ejecuta la auditoria completa (blindaje +
vigilancia + persistencia) y ENVIA el resultado firmado al coordinador. Repite
cada cierto intervalo.

Lo que este agente NO hace, por diseno:
  * no abre ningun puerto ni escucha conexiones entrantes;
  * no acepta comandos del coordinador ni de nadie;
  * no captura pantalla ni expone un shell.

Su unica interaccion hacia afuera es una peticion HTTP de salida con el reporte.
De este modo, aunque se comprometa el coordinador, no hay forma de que ordene
nada a los equipos: el canal es de una sola via. Eso mantiene a SENTINEL como
herramienta defensiva y evita que la propia consola se vuelva el mayor riesgo
del laboratorio.

Uso (en cada equipo):
  set SENTINEL_LAB_TOKEN=<token>          (o config/lab_token.key)
  python -m sentinel.agent --servidor http://IP_DEL_COORDINADOR:8770 --equipo PC-07
  # una sola vez, sin bucle:
  python -m sentinel.agent --servidor http://IP:8770 --equipo PC-07 --una-vez
"""
from __future__ import annotations

import json
import time
import argparse
import urllib.request
import urllib.error

from sentinel import __product__, __version__
from sentinel.core import evidence
from sentinel.net import protocol, remediation, commands as cmds


def _run_audit() -> dict:
    """Auditoria completa local (la misma del modo de campo)."""
    from sentinel.core.monitor import full_scan
    from sentinel.core.hardening import scan_hardening, hardening_score
    from sentinel.core.persistence import scan_persistence
    from sentinel.core.brain import heuristic_summary

    checks, hard = scan_hardening()
    deep = scan_persistence()
    report = full_scan(extra_findings=list(hard) + list(deep),
                       hardening=checks, hardening_score=hardening_score(checks))
    report["summary"] = heuristic_summary(report)
    # Estado del filtro de contenido (anuncios/+18/juegos), para el panel.
    try:
        from sentinel.core.webfilter import status as filter_status
        report["filtro"] = filter_status()
    except Exception:
        report["filtro"] = {"activo": False, "dominios": 0}
    # Estado de aislamiento de red (contencion EDR), para el panel.
    try:
        import subprocess
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=SENTINEL-Aislamiento"],
            capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        report["aislado"] = (r.returncode == 0)
    except Exception:
        report["aislado"] = False
    return report


def _send(server: str, label: str, token: str) -> tuple[bool, str]:
    """Ejecuta la auditoria y la envia firmada. Devuelve (ok, mensaje)."""
    from sentinel.core.config import os_name
    report = _run_audit()
    payload = {
        "label": label,
        "machine_id": evidence.machine_fingerprint(),
        "so": os_name(),
        "agent_version": __version__,
        "report": report,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    signature = protocol.sign(body, token)

    url = server.rstrip("/") + "/report"
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8",
                 protocol.SIGNATURE_HEADER: signature})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        score = report.get("hardening_score")
        total = report.get("counts", {}).get("total", 0)
        return True, (f"reportado (puntaje {score}, {total} hallazgos) "
                      f"-> auditoria #{data.get('audit_id')}")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode()).get("error", "")
        except Exception:
            pass
        return False, f"el coordinador rechazo el reporte ({e.code} {detail})"
    except urllib.error.URLError as e:
        return False, f"no se pudo contactar al coordinador: {e.reason}"


def _post_signed(server: str, ruta: str, payload: dict,
                 token: str) -> dict | None:
    """Envia un cuerpo firmado a un endpoint y devuelve la respuesta JSON."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        server.rstrip("/") + ruta, data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8",
                 protocol.SIGNATURE_HEADER: protocol.sign(body, token)})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None


def _apply_pending(server: str, label: str, token: str) -> None:
    """Consulta los blindajes aprobados para este equipo y los aplica.

    Cada aplicacion pasa por `remediation.apply_locally`, que solo acepta claves
    de la lista blanca y resuelve el comando LOCALMENTE. Nunca se ejecuta nada
    recibido por la red.
    """
    resp = _post_signed(server, "/pending", {"label": label}, token)
    if not resp or not resp.get("keys"):
        return
    for key in resp["keys"]:
        ok, msg = remediation.apply_locally(key)
        print(f"  [remediacion] {key}: {'OK' if ok else 'FALLO'} — {msg}")
        _post_signed(server, "/result",
                     {"label": label, "key": key, "ok": ok, "detail": msg}, token)


def _run_pending_jobs(server: str, label: str, token: str) -> None:
    """Consulta los comandos pendientes de este equipo y los ejecuta.

    Cada comando se ejecuta localmente (queda registrado en audit_log) y su
    salida se devuelve al coordinador. El agente no ejecuta nada que no venga
    firmado con el token del laboratorio: si la firma no valida, /jobs ni
    siquiera responde con trabajos.
    """
    resp = _post_signed(server, "/jobs", {"label": label}, token)
    if not resp or not resp.get("jobs"):
        return
    for job in resp["jobs"]:
        code, out, err = cmds.execute_locally(job["command"])
        print(f"  [comando #{job['id']}] exit {code}: {job['command']}")
        _post_signed(server, "/jobresult",
                     {"id": job["id"], "exit_code": code,
                      "stdout": out, "stderr": err}, token)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel.agent",
        description="Audita este equipo y reporta al coordinador del laboratorio.")
    ap.add_argument("--servidor", "-s", required=True, metavar="URL",
                    help="URL del coordinador, ej. http://192.168.1.10:8770")
    ap.add_argument("--equipo", "-e", required=True, metavar="ETIQUETA",
                    help="Etiqueta de este equipo (ej. PC-07).")
    ap.add_argument("--intervalo", type=int, default=900,
                    help="Segundos entre reportes (por defecto 900 = 15 min).")
    ap.add_argument("--una-vez", action="store_true",
                    help="Reporta una sola vez y termina.")
    ap.add_argument("--aplicar", action="store_true",
                    help="Tras reportar, aplica los blindajes que el "
                         "administrador haya aprobado para este equipo "
                         "(requiere ejecutar como administrador).")
    ap.add_argument("--ejecutar", action="store_true",
                    help="Tras reportar, ejecuta los comandos que el "
                         "administrador haya enviado a este equipo (terminal "
                         "remota). Cada comando queda registrado.")
    args = ap.parse_args(argv)

    token = protocol.lab_token()
    if not token:
        print("  ERROR: falta el token del laboratorio.")
        print("  Define SENTINEL_LAB_TOKEN o crea config/lab_token.key con el")
        print("  MISMO secreto que usa el coordinador.")
        return 2

    interval = max(60, args.intervalo)
    print(f"  {__product__} agente v{__version__}  ·  equipo {args.equipo}")
    print(f"  Coordinador: {args.servidor}")
    def _post_actions(ok: bool):
        if not ok:
            return
        if args.aplicar:
            _apply_pending(args.servidor, args.equipo, token)
        if args.ejecutar:
            _run_pending_jobs(args.servidor, args.equipo, token)

    if args.una_vez:
        ok, msg = _send(args.servidor, args.equipo, token)
        print(f"  {'OK' if ok else 'FALLO'}: {msg}")
        _post_actions(ok)
        return 0 if ok else 1

    print(f"  Reportando cada {interval}s. Ctrl+C para detener.")
    try:
        while True:
            ok, msg = _send(args.servidor, args.equipo, token)
            print(f"  [{time.strftime('%H:%M:%S')}] {'OK' if ok else 'FALLO'}: {msg}")
            _post_actions(ok)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n  Agente detenido.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
