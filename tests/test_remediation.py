"""Pruebas de la remediacion centralizada.

La prueba mas importante es `test_clave_fuera_de_allowlist_se_rechaza_*`: la
frontera de seguridad de todo el sistema. Si esto falla, el canal de
remediacion podria usarse para algo que no sea un blindaje conocido.
"""
import pytest

from sentinel.net import remediation as R


# ── La frontera de seguridad ─────────────────────────────────────────────────

def test_allowlist_tiene_los_16_blindajes():
    assert len(R.ALLOWED) == 16
    assert "firewall" in R.ALLOWED and "guest" in R.ALLOWED


def test_clave_fuera_de_allowlist_se_rechaza_al_aplicar():
    """apply_locally debe rechazar cualquier clave que no sea un blindaje
    conocido ANTES de tocar el sistema. Se prueban intentos con forma de
    comando: si alguno pasara, seria ejecucion arbitraria."""
    for maligno in ("rm -rf /", "powershell -e ...", "shell", "cmd.exe",
                    "../fixer", "defender; calc", ""):
        ok, msg = R.apply_locally(maligno)
        assert ok is False
        assert "rechaz" in msg.lower() or "lista blanca" in msg.lower()


def test_apply_locally_no_importa_hardening_para_clave_invalida(monkeypatch):
    """Verifica que ni siquiera se llega a resolver un comando cuando la clave
    es invalida: el rechazo ocurre antes de tocar el motor de blindaje."""
    llamado = {"scan": False}

    def _boom(*a, **k):
        llamado["scan"] = True
        raise AssertionError("no deberia resolverse un comando para clave invalida")

    monkeypatch.setattr("sentinel.core.hardening.scan_hardening", _boom)
    ok, _ = R.apply_locally("comando_arbitrario")
    assert ok is False
    assert llamado["scan"] is False


# ── Aprobar / consultar / marcar, sobre base temporal ────────────────────────

@pytest.fixture
def base(tmp_path, monkeypatch):
    from sentinel.core import evidence
    monkeypatch.setattr(evidence, "data_dir", lambda: tmp_path)
    return tmp_path


def test_aprobar_blindaje_valido(base):
    r = R.approve("PC-07", "firewall")
    assert r["ok"] is True
    assert "firewall" in R.pending_for("PC-07")


def test_aprobar_clave_invalida_no_se_guarda(base):
    r = R.approve("PC-07", "ejecutar_todo")
    assert r["ok"] is False
    assert "lista blanca" in r["error"]
    assert R.pending_for("PC-07") == []


def test_aprobar_normaliza_mayusculas(base):
    R.approve("PC-01", "FireWall")
    assert "firewall" in R.pending_for("PC-01")


def test_no_duplica_aprobacion_pendiente(base):
    R.approve("PC-01", "guest")
    R.approve("PC-01", "guest")
    assert R.pending_for("PC-01").count("guest") == 1


def test_marcar_aplicado_saca_de_pendientes(base):
    R.approve("PC-01", "smb1")
    assert "smb1" in R.pending_for("PC-01")
    R.mark("PC-01", "smb1", True, "aplicado ok")
    assert "smb1" not in R.pending_for("PC-01")


def test_marcar_fallido_tambien_saca_de_pendientes(base):
    R.approve("PC-01", "rdp")
    R.mark("PC-01", "rdp", False, "el usuario cancelo")
    assert R.pending_for("PC-01") == []
    h = R.history("PC-01")
    assert h[0]["status"] == "fallido"


def test_pendientes_son_por_equipo(base):
    R.approve("PC-01", "firewall")
    R.approve("PC-02", "guest")
    assert R.pending_for("PC-01") == ["firewall"]
    assert R.pending_for("PC-02") == ["guest"]


def test_pending_for_filtra_claves_no_permitidas(base, monkeypatch):
    """Defensa en profundidad: aunque la base tuviera una clave fuera de
    catalogo (manipulacion directa), pending_for no la entrega."""
    from sentinel.core import evidence
    con = evidence._connect()
    con.execute("INSERT INTO remediations (label, key, status, approved_ts) "
                "VALUES ('PC-01','comando_raro','pendiente',1)")
    con.commit(); con.close()
    assert R.pending_for("PC-01") == []


def test_historial_registra_quien_aprobo(base):
    R.approve("PC-05", "uac", by="elvis")
    assert R.history("PC-05")[0]["approved_by"] == "elvis"
