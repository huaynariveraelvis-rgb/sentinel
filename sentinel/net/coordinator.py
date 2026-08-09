"""coordinator.py — Panel central del laboratorio.

Recibe los reportes de auditoria de los agentes y los agrega en una vista unica
del parque: inventario, puntaje por equipo, Pareto del laboratorio y ranking de
lo mas urgente.

Es SOLO RECEPTOR. No abre conexiones hacia los equipos, no les envia comandos y
no ejecuta nada en ellos. Su unica entrada es un reporte firmado; su unica
salida es el panel. Esa asimetria es intencional: la consola centraliza la
visibilidad, no el control.

Endpoints:
  POST /report   — un agente entrega su reporte (requiere firma valida)
  GET  /status   — resumen del parque en JSON
  GET  /         — panel HTML del laboratorio

Uso:
  set SENTINEL_LAB_TOKEN=<token>          (o config/lab_token.key)
  python -m sentinel.coordinator [--host 0.0.0.0] [--port 8770]
"""
from __future__ import annotations

import json
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sentinel import __product__, __vendor__, __version__
from sentinel.core import evidence
from sentinel.net import protocol, remediation, commands as cmds

_MAX_BODY = 4 * 1024 * 1024   # 4 MB: un reporte grande no llega ni a la mitad


class _Handler(BaseHTTPRequestHandler):
    server_version = f"SENTINEL-Coordinator/{__version__}"

    # --- utilidades ---
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # silencia el log ruidoso por defecto
        pass

    # --- rutas ---
    def do_GET(self):
        if self.path.rstrip("/") in ("", "/"):
            return self._html(200, _dashboard_html())
        if self.path.startswith("/status"):
            return self._json(200, _park_summary())
        self._json(404, {"error": "no encontrado"})

    def _read_signed(self) -> dict | None:
        """Lee y valida un cuerpo firmado. Responde el error y devuelve None
        si algo falla; devuelve el JSON ya parseado si es de confianza."""
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > _MAX_BODY:
            self._json(400, {"error": "cuerpo invalido"})
            return None
        body = self.rfile.read(length)
        signature = self.headers.get(protocol.SIGNATURE_HEADER, "")
        if not protocol.verify(body, signature, self.server.lab_token):
            # Firma ausente, alterada o vencida: no es de confianza.
            self._json(401, {"error": "firma invalida"})
            return None
        try:
            return json.loads(body)
        except (ValueError, AttributeError):
            self._json(400, {"error": "json invalido"})
            return None

    def do_POST(self):
        route = self.path.split("?")[0].rstrip("/")
        if route == "/report":
            return self._post_report()
        if route == "/pending":
            return self._post_pending()
        if route == "/result":
            return self._post_result()
        if route == "/jobs":
            return self._post_jobs()
        if route == "/jobresult":
            return self._post_jobresult()
        self._json(404, {"error": "no encontrado"})

    def _post_report(self):
        data = self._read_signed()
        if data is None:
            return
        try:
            label = str(data.get("label") or "SIN-ETIQUETA")[:40]
            report = data.get("report") or {}
            machine_id = str(data.get("machine_id") or "")[:32]
            if data.get("so"):
                report["_so"] = str(data["so"])[:60]
        except AttributeError:
            return self._json(400, {"error": "json invalido"})
        checks = report.get("hardening") or []
        try:
            aid = evidence.record(report, label, checks, machine_id=machine_id)
        except Exception as e:
            return self._json(500, {"error": f"no se pudo guardar: {e}"})
        self.server.received += 1
        return self._json(200, {"ok": True, "audit_id": aid,
                                "recibidos": self.server.received})

    def _post_pending(self):
        """El agente pregunta que blindajes aprobados debe aplicar."""
        data = self._read_signed()
        if data is None:
            return
        label = str(data.get("label") or "")[:40]
        return self._json(200, {"ok": True, "label": label,
                                "keys": remediation.pending_for(label)})

    def _post_result(self):
        """El agente reporta el resultado de aplicar un blindaje aprobado."""
        data = self._read_signed()
        if data is None:
            return
        label = str(data.get("label") or "")[:40]
        key = str(data.get("key") or "")[:40]
        ok = bool(data.get("ok"))
        detail = str(data.get("detail") or "")[:200]
        remediation.mark(label, key, ok, detail)
        return self._json(200, {"ok": True})

    def _post_jobs(self):
        """El agente pregunta que comandos remotos tiene pendientes."""
        data = self._read_signed()
        if data is None:
            return
        label = str(data.get("label") or "")[:40]
        return self._json(200, {"ok": True, "jobs": cmds.pending_for(label)})

    def _post_jobresult(self):
        """El agente devuelve la salida de un comando ejecutado."""
        data = self._read_signed()
        if data is None:
            return
        try:
            cmds.record_result(int(data.get("id")), int(data.get("exit_code", 1)),
                               str(data.get("stdout", "")), str(data.get("stderr", "")))
        except (TypeError, ValueError):
            return self._json(400, {"error": "resultado invalido"})
        return self._json(200, {"ok": True})


def _park_summary() -> dict:
    """Resumen agregado del parque para el panel y el JSON de estado."""
    maquinas = evidence.latest_per_machine()
    par = evidence.pareto()
    scores = [m["score"] for m in maquinas if m["score"] is not None]
    riesgo = sorted(
        maquinas,
        key=lambda m: (m["score"] if m["score"] is not None else 999,
                       -(m["alta"] + m["critica"])))
    return {
        "producto": __product__,
        "equipos": len(maquinas),
        "puntaje_promedio": round(sum(scores) / len(scores), 1) if scores else None,
        "peor": riesgo[0]["label"] if riesgo else None,
        "maquinas": [
            {"equipo": m["label"], "fecha": m["fecha"], "puntaje": m["score"],
             "criticas": m["critica"], "altas": m["alta"], "medias": m["media"]}
            for m in riesgo],
        "pareto": par.get("filas", []),
    }


def _dashboard_html() -> str:
    """Panel del laboratorio: se auto-refresca leyendo /status."""
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{__product__} — Consola del laboratorio</title>
<style>
:root{{--bg:#070B0F;--pan:#0D141A;--ln:#1C2830;--tx:#DCE7EA;--mu:#62787F;
--ac:#2FE6A8;--crit:#FF4757;--alta:#FF8A3D;--media:#E8C547;--ok:#2FE6A8;
--mono:Consolas,"Cascadia Mono",monospace;--ui:"Segoe UI",system-ui,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font-family:var(--ui);font-size:14px}}
.top{{display:flex;align-items:center;gap:14px;padding:0 20px;height:54px;
background:var(--pan);border-bottom:1px solid var(--ln)}}
.top b{{font-family:var(--mono);letter-spacing:.22em;color:var(--ac);font-size:15px}}
.top span{{font-family:var(--mono);font-size:10px;letter-spacing:.15em;
text-transform:uppercase;color:var(--mu)}}
.wrap{{max-width:1200px;margin:0 auto;padding:20px}}
.kpi{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:12px;margin-bottom:22px}}
.card{{background:var(--pan);border:1px solid var(--ln);border-radius:3px;padding:16px}}
.card b{{display:block;font-family:var(--mono);font-size:30px;font-variant-numeric:tabular-nums}}
.card span{{font-family:var(--mono);font-size:9px;letter-spacing:.12em;
text-transform:uppercase;color:var(--mu)}}
h2{{font-family:var(--mono);font-size:11px;letter-spacing:.18em;text-transform:uppercase;
color:var(--mu);font-weight:400;margin:26px 0 10px;padding-bottom:7px;
border-bottom:1px solid var(--ln)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:.09em;
text-transform:uppercase;color:var(--mu);font-weight:400;padding:9px 11px;
border-bottom:1px solid var(--ln)}}
td{{padding:9px 11px;border-bottom:1px solid var(--ln)}}
.num{{font-family:var(--mono);text-align:right;font-variant-numeric:tabular-nums}}
.sc{{font-family:var(--mono);font-weight:600}}
.g80{{color:var(--ok)}}.g50{{color:var(--media)}}.g0{{color:var(--crit)}}
.mut{{color:var(--mu)}}.empty{{color:var(--mu);padding:22px;text-align:center;
border:1px dashed var(--ln);border-radius:3px}}
.bar{{height:7px;background:var(--ln);border-radius:4px;overflow:hidden;min-width:60px}}
.bar i{{display:block;height:100%;background:var(--ac)}}
</style></head><body>
<div class="top"><b>SENTINEL</b><span>Consola del laboratorio</span>
<span id="upd" style="margin-left:auto"></span></div>
<div class="wrap">
  <div class="kpi">
    <div class="card"><b id="kEq">—</b><span>Equipos</span></div>
    <div class="card"><b id="kProm">—</b><span>Puntaje promedio</span></div>
    <div class="card"><b id="kPeor">—</b><span>Mas expuesto</span></div>
    <div class="card"><b id="kAcc">—</b><span>Con hallazgos altos</span></div>
  </div>
  <h2>Equipos del parque</h2>
  <div id="tEquipos"><div class="empty">Esperando reportes de los agentes…</div></div>
  <h2>Controles que mas fallan (Pareto)</h2>
  <div id="tPareto"><div class="empty">Sin datos suficientes.</div></div>
</div>
<script>
function cls(s){{return s==null?'mut':s>=80?'g80':s>=50?'g50':'g0'}}
async function tick(){{
  try{{
    const r=await fetch('/status'); const d=await r.json();
    document.getElementById('kEq').textContent=d.equipos;
    document.getElementById('kProm').textContent=d.puntaje_promedio==null?'—':d.puntaje_promedio;
    document.getElementById('kPeor').textContent=d.peor||'—';
    const alto=d.maquinas.filter(m=>(m.altas+m.criticas)>0).length;
    document.getElementById('kAcc').textContent=alto;
    document.getElementById('upd').textContent='Actualizado '+new Date().toLocaleTimeString();
    if(d.maquinas.length){{
      let h='<table><thead><tr><th>Equipo</th><th>Ultima auditoria</th>'
        +'<th class=num>Puntaje</th><th class=num>Criticas</th><th class=num>Altas</th>'
        +'<th class=num>Medias</th></tr></thead><tbody>';
      for(const m of d.maquinas){{
        h+='<tr><td>'+m.equipo+'</td><td class=mut>'+m.fecha+'</td>'
          +'<td class="num sc '+cls(m.puntaje)+'">'+(m.puntaje==null?'—':m.puntaje)+'</td>'
          +'<td class=num>'+m.criticas+'</td><td class=num>'+m.altas+'</td>'
          +'<td class=num>'+m.medias+'</td></tr>';
      }}
      document.getElementById('tEquipos').innerHTML=h+'</tbody></table>';
    }}
    if(d.pareto.length){{
      let h='<table><thead><tr><th>Control</th><th class=num>Equipos</th>'
        +'<th>%</th><th class=num>ATT&CK</th></tr></thead><tbody>';
      for(const f of d.pareto){{
        h+='<tr><td>'+f.control+'</td><td class=num>'+f.equipos_afectados+'</td>'
          +'<td><div class=bar><i style="width:'+f.porcentaje_equipos+'%"></i></div></td>'
          +'<td class="num mut">'+(f.attack||'')+'</td></tr>';
      }}
      document.getElementById('tPareto').innerHTML=h+'</tbody></table>';
    }}
  }}catch(e){{document.getElementById('upd').textContent='Sin conexion';}}
}}
tick(); setInterval(tick, 5000);
</script></body></html>"""


def serve(host: str, port: int) -> int:
    token = protocol.lab_token()
    if not token:
        print("  ERROR: no hay token del laboratorio configurado.")
        print("  Define SENTINEL_LAB_TOKEN o crea config/lab_token.key con un")
        print("  secreto compartido, y usa el MISMO en cada agente.")
        return 2

    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.lab_token = token
    httpd.received = 0

    print()
    print(f"  {__product__} — Consola del laboratorio")
    print(f"  {__vendor__}  ·  v{__version__}")
    print(f"  {'-' * 58}")
    print(f"  Panel:   http://{host if host != '0.0.0.0' else 'localhost'}:{port}/")
    print(f"  Reportes en:  POST /report   (firma requerida)")
    print(f"  {'-' * 58}")
    print("  Esperando reportes de los agentes. Ctrl+C para detener.")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Coordinador detenido.")
    finally:
        httpd.server_close()
    return 0


def _cmd_generar_token() -> int:
    """Crea un token aleatorio y lo guarda en config/lab_token.key."""
    import secrets
    from sentinel.core.config import user_config_dir
    token = secrets.token_urlsafe(24)
    path = user_config_dir() / "lab_token.key"
    path.write_text(token, encoding="utf-8")
    print(f"  Token del laboratorio generado en: {path}")
    print(f"  Token: {token}")
    print("  Copia este MISMO token en cada equipo (variable SENTINEL_LAB_TOKEN")
    print("  o el mismo archivo config/lab_token.key).")
    return 0


def _cmd_aprobar(label: str, key: str) -> int:
    r = remediation.approve(label, key)
    print(f"  {r.get('message') or r.get('error')}")
    return 0 if r.get("ok") else 1


def _cmd_pendientes() -> int:
    filas = remediation.history(limit=40)
    if not filas:
        print("  No hay remediaciones aprobadas.")
        return 0
    print(f"  {'EQUIPO':<10} {'BLINDAJE':<16} {'ESTADO':<10} DETALLE")
    for f in filas:
        print(f"  {f['label']:<10} {f['key']:<16} {f['status']:<10} "
              f"{(f.get('detail') or '')[:60]}")
    return 0


def _cmd_comando(label: str, command: str) -> int:
    r = cmds.queue(label, command)
    print(f"  {r.get('message') or r.get('error')}")
    if r.get("ok"):
        print(f"  Se ejecutara cuando el agente de {label} se conecte con --ejecutar.")
        print(f"  Ver el resultado luego con:  --resultados {label}")
    return 0 if r.get("ok") else 1


def _cmd_resultados(label: str | None) -> int:
    filas = cmds.history(label, limit=20)
    if not filas:
        print("  No hay comandos registrados.")
        return 0
    for f in filas:
        estado = f["status"]
        print(f"  {'-' * 62}")
        print(f"  #{f['id']}  {f['label']}  [{estado}]  "
              f"{'exit ' + str(f['exit_code']) if f['exit_code'] is not None else ''}")
        print(f"  $ {f['command']}")
        if f.get("stdout"):
            for line in f["stdout"].rstrip().splitlines()[:40]:
                print(f"    {line}")
        if f.get("stderr"):
            for line in f["stderr"].rstrip().splitlines()[:15]:
                print(f"    [err] {line}")
    print(f"  {'-' * 62}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel.coordinator",
        description="Panel central que recibe y agrega las auditorias del parque.")
    ap.add_argument("--host", default="0.0.0.0",
                    help="Interfaz de escucha (0.0.0.0 = toda la red del laboratorio).")
    ap.add_argument("--port", type=int, default=8770, help="Puerto (por defecto 8770).")
    ap.add_argument("--generar-token", action="store_true",
                    help="Crea un token del laboratorio y termina.")
    ap.add_argument("--aprobar", nargs=2, metavar=("EQUIPO", "BLINDAJE"),
                    help="Aprueba que un equipo aplique un blindaje "
                         "(p. ej. --aprobar PC-07 firewall).")
    ap.add_argument("--pendientes", action="store_true",
                    help="Lista las remediaciones aprobadas y su estado.")
    ap.add_argument("--comando", nargs=2, metavar=("EQUIPO", "COMANDO"),
                    help="Envia un comando a un equipo (terminal remota). "
                         "Ej: --comando PC-07 \"ipconfig /all\"")
    ap.add_argument("--resultados", nargs="?", const="", metavar="EQUIPO",
                    help="Muestra la salida de los comandos ejecutados.")
    args = ap.parse_args(argv)

    if args.generar_token:
        return _cmd_generar_token()
    if args.aprobar:
        return _cmd_aprobar(args.aprobar[0], args.aprobar[1])
    if args.pendientes:
        return _cmd_pendientes()
    if args.comando:
        return _cmd_comando(args.comando[0], args.comando[1])
    if args.resultados is not None:
        return _cmd_resultados(args.resultados or None)

    try:
        return serve(args.host, args.port)
    except OSError as e:
        print(f"  No se pudo iniciar el coordinador: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
