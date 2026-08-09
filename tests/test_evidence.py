"""Pruebas del modulo de evidencia: anonimizacion, historial y Pareto.

La anonimizacion es la parte critica: si filtra datos personales, la evidencia
no se puede anexar a un informe ni entregar a la institucion auditada.
"""
import pytest

from sentinel.core import evidence as E
from sentinel.core.hardening import HardeningCheck


# ── Anonimizacion ────────────────────────────────────────────────────────────

def test_anonimiza_el_perfil_de_usuario(monkeypatch):
    import re
    monkeypatch.setattr(E, "_USER_RE", re.compile(re.escape(r"C:\Users\Elvis"),
                                                  re.IGNORECASE))
    out = E.anonymize(r"C:\Users\Elvis\Downloads\x.exe")
    assert out == r"%USERPROFILE%\Downloads\x.exe"
    assert "Elvis" not in out


def test_no_destroza_texto_legitimo_que_contiene_el_usuario(monkeypatch):
    """Un usuario llamado 'Elvis' no debe convertir la marca 'ELVIS SYSTEMS'
    en '%USER% SYSTEMS'. El nombre solo se sustituye dentro de una ruta."""
    import re
    monkeypatch.setattr(E, "_USERNAME_RE",
                        re.compile(r"(?<=[\\/])Elvis(?=[\\/]|\b)", re.IGNORECASE))
    assert E.anonymize("Producto de ELVIS SYSTEMS") == "Producto de ELVIS SYSTEMS"
    assert E.anonymize(r"D:\Elvis\copia") == r"D:\%USER%\copia"


def test_anonimizacion_es_recursiva_en_el_reporte(monkeypatch):
    import re
    monkeypatch.setattr(E, "_USER_RE", re.compile(re.escape(r"C:\Users\Ana"),
                                                  re.IGNORECASE))
    rep = {"findings": [{"detail": r"corre desde C:\Users\Ana\Temp",
                         "evidence": {"exe": r"C:\Users\Ana\Temp\a.exe"}}]}
    limpio = E._scrub(rep)
    assert "Ana" not in str(limpio)


def test_anonymize_tolera_valores_no_texto():
    assert E.anonymize("") == ""
    assert E.anonymize(None) is None


def test_huella_del_equipo_es_estable_y_no_revela_el_nombre():
    h1, h2 = E.machine_fingerprint(), E.machine_fingerprint()
    assert h1 == h2 and len(h1) == 12
    import platform
    assert platform.node().lower() not in h1.lower()


# ── Historial y agregados sobre una base temporal ────────────────────────────

@pytest.fixture
def base(tmp_path, monkeypatch):
    """Redirige la base de datos a una carpeta temporal de la prueba."""
    monkeypatch.setattr(E, "data_dir", lambda: tmp_path)
    return tmp_path


def _reporte(score, total=10, alta=1):
    return {"counts": {"total": total,
                       "por_severidad": {"CRITICA": 0, "ALTA": alta, "MEDIA": 2,
                                         "BAJA": 0, "INFO": 5}},
            "findings": [], "hardening_score": score}


def _checks(fallos):
    base = [("autorun", "Reproduccion automatica de USB", "T1091"),
            ("guest", "Cuenta de invitado", "T1078"),
            ("smb1", "SMBv1 (protocolo obsoleto)", "T1021.002"),
            ("firewall", "Firewall de Windows", "T1562.004")]
    return [HardeningCheck(k, t, "fail" if k in fallos else "ok", "", attack=a)
            for k, t, a in base]


def test_registra_y_recupera_una_auditoria(base):
    aid = E.record(_reporte(70), "PC-01", _checks(["guest"]))
    assert aid > 0
    hist = E.history()
    assert len(hist) == 1
    assert hist[0]["label"] == "PC-01" and hist[0]["score"] == 70


def test_historial_filtra_por_equipo(base):
    E.record(_reporte(60), "PC-01", _checks([]))
    E.record(_reporte(80), "PC-02", _checks([]))
    assert len(E.history("PC-01")) == 1
    assert len(E.history()) == 2


def test_comparar_necesita_dos_auditorias(base):
    E.record(_reporte(60), "PC-01", _checks([]))
    assert E.compare("PC-01") is None


def test_comparar_calcula_la_mejora(base):
    E.record(_reporte(60), "PC-01", _checks(["guest", "autorun"]))
    E.record(_reporte(90), "PC-01", _checks([]))
    c = E.compare("PC-01")
    assert c["antes"]["score"] == 60
    assert c["despues"]["score"] == 90
    assert c["mejora_puntos"] == 30
    assert c["mejora_pct"] == 50.0


def test_solo_cuenta_la_ultima_auditoria_de_cada_equipo(base):
    """Si un equipo se audita dos veces, el consolidado debe usar la ultima:
    de lo contrario la remediacion no se reflejaria nunca en el Pareto."""
    E.record(_reporte(40), "PC-01", _checks(["guest", "autorun"]))
    E.record(_reporte(100), "PC-01", _checks([]))
    p = E.pareto()
    assert p["equipos"] == 1
    assert p["filas"] == []


def test_pareto_ordena_por_frecuencia_y_acumula(base):
    lab = [("PC-01", ["autorun", "guest", "smb1"]), ("PC-02", ["autorun"]),
           ("PC-03", ["autorun", "guest"]), ("PC-04", ["autorun", "guest"]),
           ("PC-05", ["smb1"])]
    for label, fallos in lab:
        E.record(_reporte(60), label, _checks(fallos))

    p = E.pareto()
    assert p["equipos"] == 5
    filas = p["filas"]
    assert filas[0]["control"] == "Reproduccion automatica de USB"
    assert filas[0]["equipos_afectados"] == 4
    assert filas[0]["porcentaje_equipos"] == 80.0
    # El acumulado debe ser monotono creciente y cerrar en 100.
    acum = [f["acumulado"] for f in filas]
    assert acum == sorted(acum)
    assert acum[-1] == pytest.approx(100.0, abs=0.2)


def test_pareto_sin_datos_no_revienta(base):
    p = E.pareto()
    assert p["equipos"] == 0 and p["filas"] == []


def test_exportaciones_generan_archivos_legibles(base):
    rep = _reporte(70)
    rep["findings"] = [{"category": "blindaje", "severity_label": "ALTA",
                        "title": "Cuenta de invitado", "detail": "habilitada",
                        "attack_info": {"id": "T1078", "name": "Cuentas validas"},
                        "evidence": {"cis": "Opciones de seguridad local"}}]
    j = E.export_json(rep, "PC-01")
    c = E.export_csv(rep, "PC-01")
    assert j.exists() and c.exists()
    assert "T1078" in c.read_text(encoding="utf-8-sig")
    assert "PC-01" in j.read_text(encoding="utf-8")


# ── Linea base y desviacion ──────────────────────────────────────────────────

def _rep_con(titulos, score=75):
    return {"counts": {"total": len(titulos),
                       "por_severidad": {"CRITICA": 0, "ALTA": 0, "MEDIA": 0,
                                         "BAJA": 0, "INFO": 0}},
            "hardening_score": score,
            "findings": [{"category": "arranque", "title": t} for t in titulos]}


def test_sin_linea_base_no_hay_desviacion(base):
    assert E.drift(_rep_con(["A"]), "PC-01") is None


def test_equipo_sin_cambios_no_reporta_desviacion(base):
    rep = _rep_con(["Programa de arranque: X", "Puerto 445 expuesto"])
    E.set_baseline(rep, "PC-01")
    d = E.drift(rep, "PC-01")
    assert d["nuevos"] == [] and d["resueltos"] == []


def test_detecta_un_hallazgo_nuevo(base):
    E.set_baseline(_rep_con(["Programa de arranque: X"]), "PC-01")
    d = E.drift(_rep_con(["Programa de arranque: X",
                          "Tarea programada sospechosa: Y"]), "PC-01")
    assert d["nuevos"] == ["Tarea programada sospechosa: Y"]
    assert d["resueltos"] == []


def test_detecta_un_hallazgo_resuelto(base):
    E.set_baseline(_rep_con(["Puerto 445 expuesto", "Cuenta de invitado"]), "PC-01")
    d = E.drift(_rep_con(["Puerto 445 expuesto"]), "PC-01")
    assert d["resueltos"] == ["Cuenta de invitado"]
    assert d["nuevos"] == []


def test_desviacion_reporta_variacion_de_puntaje(base):
    E.set_baseline(_rep_con(["A"], score=60), "PC-01")
    d = E.drift(_rep_con(["A"], score=90), "PC-01")
    assert d["score_base"] == 60 and d["score_actual"] == 90
    assert d["score_delta"] == 30


def test_las_conexiones_salientes_no_cuentan_como_desviacion(base):
    """Cambian en cada barrido: incluirlas haria que todo equipo pareciera
    modificado siempre, y la funcion perderia todo su valor."""
    E.set_baseline(_rep_con(["Conexion saliente a 1.1.1.1:443"]), "PC-01")
    d = E.drift(_rep_con(["Conexion saliente a 8.8.8.8:443"]), "PC-01")
    assert d["nuevos"] == [] and d["resueltos"] == []


def test_fijar_linea_base_dos_veces_reemplaza_la_anterior(base):
    E.set_baseline(_rep_con(["A"]), "PC-01")
    E.set_baseline(_rep_con(["B"]), "PC-01")
    d = E.drift(_rep_con(["B"]), "PC-01")
    assert d["nuevos"] == [] and d["resueltos"] == []


def test_lineas_base_son_independientes_por_equipo(base):
    E.set_baseline(_rep_con(["A"]), "PC-01")
    E.set_baseline(_rep_con(["B"]), "PC-02")
    assert E.drift(_rep_con(["A"]), "PC-01")["nuevos"] == []
    assert E.drift(_rep_con(["A"]), "PC-02")["nuevos"] == ["A"]


def test_etiqueta_vacia_no_rompe_el_registro(base):
    aid = E.record(_reporte(50), "", _checks([]))
    assert aid > 0
    assert E.history()[0]["label"] == "SIN-ETIQUETA"
