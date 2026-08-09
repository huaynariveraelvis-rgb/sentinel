"""Pruebas de las rutas escribibles.

Regresion de un fallo de campo: instalado en Archivos de programa, SENTINEL
guardaba la base de auditorias junto al .exe. Windows monta esa carpeta de
solo lectura para las cuentas sin privilegios, asi que en los equipos del
laboratorio exportar un informe moria con "unable to open database file".
Los datos que el producto genera nunca deben colgar de la carpeta de
instalacion.
"""
import sqlite3

import pytest

from sentinel.core import config


@pytest.fixture(autouse=True)
def sin_cache(monkeypatch):
    """state_dir() memoriza su resultado; cada prueba parte de cero."""
    monkeypatch.setattr(config, "_STATE_DIR", None)


def _simula_instalado(monkeypatch, tmp_path, programdata):
    """Finge un .exe de PyInstaller instalado en una carpeta de solo lectura."""
    instalado = tmp_path / "Archivos de programa" / "SENTINEL"
    instalado.mkdir(parents=True)
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setattr(config.sys, "executable", str(instalado / "SENTINEL.exe"))
    monkeypatch.setenv("PROGRAMDATA", str(programdata))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    return instalado


def test_los_datos_no_cuelgan_de_la_carpeta_de_instalacion(monkeypatch, tmp_path):
    programdata = tmp_path / "ProgramData"
    instalado = _simula_instalado(monkeypatch, tmp_path, programdata)

    assert config.data_dir() == programdata / "SENTINEL" / "data"
    assert instalado not in config.data_dir().parents
    assert instalado not in config.user_config_dir().parents


def test_la_configuracion_se_sigue_leyendo_del_producto(monkeypatch, tmp_path):
    """Solo la ESCRITURA se mueve: settings.json viaja con el instalador."""
    instalado = _simula_instalado(monkeypatch, tmp_path, tmp_path / "ProgramData")
    assert config.config_dir() == instalado / "config"
    assert config.config_dir() in config._candidate_dirs()


def test_cae_a_la_carpeta_del_usuario_si_programdata_no_deja_escribir(
        monkeypatch, tmp_path):
    """En un equipo con ProgramData bloqueado, el operador no pierde su historial."""
    local = tmp_path / "LocalAppData"
    _simula_instalado(monkeypatch, tmp_path, tmp_path / "ProgramData")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(config, "_writable",
                        lambda d: str(local) in str(d))

    assert config.state_dir() == local / "SENTINEL"


def test_writable_detecta_una_carpeta_que_no_se_puede_crear(tmp_path):
    """mkdir a secas no basta: se comprueba escribiendo de verdad."""
    bloqueo = tmp_path / "archivo"
    bloqueo.write_text("no soy una carpeta")
    assert config._writable(bloqueo / "data") is False
    assert config._writable(tmp_path / "nueva") is True


def test_la_base_de_auditorias_se_puede_abrir_estando_instalado(
        monkeypatch, tmp_path):
    """Reproduce el fallo original de punta a punta.

    La carpeta de instalacion se deja imposible de usar para datos (hay un
    archivo donde iria 'data'), que es el efecto que tenia Archivos de
    programa sin permisos: mkdir fallaba y sqlite moria con
    "unable to open database file". La base debe abrirse igualmente.
    """
    from sentinel.core import evidence

    instalado = _simula_instalado(monkeypatch, tmp_path, tmp_path / "ProgramData")
    (instalado / "data").write_text("aqui no se puede escribir")

    con = evidence._connect()          # antes: OperationalError
    try:
        assert con.execute("SELECT COUNT(*) FROM audits").fetchone()[0] == 0
    finally:
        con.close()
    assert evidence.db_path().exists()


def test_migra_la_evidencia_de_una_version_anterior(monkeypatch, tmp_path):
    """Quien ya audito con la version rota no pierde su linea base."""
    programdata = tmp_path / "ProgramData"
    instalado = _simula_instalado(monkeypatch, tmp_path, programdata)
    viejo = instalado / "data"
    viejo.mkdir()
    con = sqlite3.connect(str(viejo / "auditorias.db"))
    con.execute("CREATE TABLE marca (x TEXT)")
    con.commit()
    con.close()

    assert (config.data_dir() / "auditorias.db").exists()
