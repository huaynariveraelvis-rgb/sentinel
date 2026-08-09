"""Pruebas de la ejecucion remota de comandos (terminal remota).

Cubren el flujo encolar -> pendiente -> ejecutar -> registrar resultado, y que
cada ejecucion deje traza en el registro de acciones. La ejecucion real se
prueba con un comando inofensivo (`echo`).
"""
import pytest

from sentinel.net import commands as C


@pytest.fixture
def base(tmp_path, monkeypatch):
    from sentinel.core import evidence
    monkeypatch.setattr(evidence, "data_dir", lambda: tmp_path)
    return tmp_path


# ── Cola de comandos (lado coordinador) ──────────────────────────────────────

def test_encolar_y_consultar_pendiente(base):
    r = C.queue("PC-07", "whoami", by="elvis")
    assert r["ok"] is True
    pend = C.pending_for("PC-07")
    assert len(pend) == 1
    assert pend[0]["command"] == "whoami"


def test_comando_vacio_se_rechaza(base):
    assert C.queue("PC-07", "   ")["ok"] is False
    assert C.pending_for("PC-07") == []


def test_sin_etiqueta_se_rechaza(base):
    assert C.queue("", "whoami")["ok"] is False


def test_pendientes_son_por_equipo(base):
    C.queue("PC-01", "hostname")
    C.queue("PC-02", "whoami")
    assert len(C.pending_for("PC-01")) == 1
    assert C.pending_for("PC-01")[0]["command"] == "hostname"


def test_registrar_resultado_saca_de_pendientes(base):
    r = C.queue("PC-01", "echo hola")
    cid = r["id"]
    C.record_result(cid, 0, "hola", "")
    assert C.pending_for("PC-01") == []
    h = C.history("PC-01")
    assert h[0]["status"] == "ejecutado"
    assert h[0]["exit_code"] == 0
    assert "hola" in h[0]["stdout"]


def test_historial_guarda_quien_encolo(base):
    C.queue("PC-05", "dir", by="admin-elvis")
    assert C.history("PC-05")[0]["queued_by"] == "admin-elvis"


def test_salida_se_recorta(base):
    r = C.queue("PC-01", "grande")
    C.record_result(r["id"], 0, "x" * 500_000, "")
    guardado = C.history("PC-01")[0]["stdout"]
    assert len(guardado) <= C._MAX_OUTPUT


# ── Ejecucion local (lado agente) ────────────────────────────────────────────

def test_ejecuta_comando_inofensivo(base):
    # 'echo' funciona con shell=True tanto en Windows (cmd) como en POSIX.
    code, out, err = C.execute_locally("echo sentinel-ok")
    assert code == 0
    assert "sentinel-ok" in out


def test_comando_vacio_no_ejecuta(base):
    code, out, err = C.execute_locally("   ")
    assert code == 1


def test_cada_ejecucion_queda_registrada(base):
    """La traza en audit_log es lo que hace auditable la terminal remota."""
    from sentinel.core.audit_log import read
    C.execute_locally("echo trazado")
    acciones = read(5)
    assert any(a["accion"] == "comando_remoto" for a in acciones)


def test_comando_que_falla_devuelve_codigo_no_cero(base):
    # Un ejecutable inexistente debe reflejarse como fallo, no como exito.
    code, out, err = C.execute_locally("comando_que_no_existe_xyz123")
    assert code != 0
