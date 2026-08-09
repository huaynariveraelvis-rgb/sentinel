"""Pruebas del reporte avanzado: cobertura CSF 2.0 y capa ATT&CK Navigator."""
from sentinel.core.monitor import Finding, Severity
from sentinel.core.reporting import frameworks, navigator


def _f(category, attack, title="x"):
    return Finding(category=category, severity=Severity.HIGH, title=title,
                   detail="", evidence={}, attack=attack)


def test_csf_ubica_cada_hallazgo_en_su_funcion():
    findings = [_f("vulnerabilidad", "T1595"), _f("blindaje", "T1562"),
                _f("arranque", "T1053.005"), _f("cuarentena", "T1070")]
    cov = frameworks.csf_coverage(findings)
    d = cov["detalle"]
    assert d["ID"]["cubierta"]      # vulnerabilidad -> Identificar
    assert d["PR"]["cubierta"]      # blindaje -> Proteger
    assert d["DE"]["cubierta"]      # arranque -> Detectar
    assert d["RS"]["cubierta"]      # cuarentena -> Responder


def test_gobernar_se_cubre_con_alcance_y_registro():
    cov = frameworks.csf_coverage([], has_scope=True, has_audit_log=True)
    assert cov["detalle"]["GV"]["cubierta"]
    assert cov["marco"] == "NIST CSF 2.0"


def test_gobernar_vacio_sin_autorizacion():
    cov = frameworks.csf_coverage([_f("vulnerabilidad", "T1595")])
    assert not cov["detalle"]["GV"]["cubierta"]


def test_navigator_cuenta_tecnicas():
    findings = [_f("exposicion", "T1021.002"), _f("exposicion", "T1021.002"),
                _f("recon", "T1046")]
    layer = navigator.build_layer(findings)
    ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert ids["T1021.002"] == 2 and ids["T1046"] == 1
    assert layer["domain"] == "enterprise-attack"
    assert layer["gradient"]["maxValue"] == 2


def test_navigator_ignora_hallazgos_sin_tecnica():
    layer = navigator.build_layer([_f("x", ""), _f("x", "no-tecnica")])
    assert layer["techniques"] == []
