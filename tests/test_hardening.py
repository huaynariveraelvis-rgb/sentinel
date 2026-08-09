"""Pruebas de los evaluadores de blindaje.

Estas pruebas son posibles porque la auditoria separa RECOGER los datos
(`probe()`, que habla con PowerShell) de EVALUARLOS (`evaluate()`, Python
puro). Aqui se alimentan datos sinteticos, asi que las pruebas corren sin
depender del estado real del equipo ni de tener permisos de administrador.

El caso mas importante es `test_propiedad_ausente_no_es_desactivado`: en
PowerShell, `[int]` sobre una propiedad inexistente devuelve 0, lo que hacia
que "no configurado" se reportara como "desactivado". Ese falso positivo
habria acusado de inseguros a equipos que no lo eran.
"""
from sentinel.core import hardening as H


# ── Defender ─────────────────────────────────────────────────────────────────

def test_defender_activo_es_ok():
    c = H.eval_defender({"def_rt": True, "def_av": True})
    assert c.status == "ok"
    assert c.attack == "T1562.001"


def test_defender_apagado_falla_y_trae_correccion():
    c = H.eval_defender({"def_rt": False, "def_av": True})
    assert c.status == "fail"
    assert c.fix_command


def test_defender_sin_dato_es_desconocido():
    assert H.eval_defender({}).status == "unknown"


def test_firmas_por_antiguedad():
    assert H.eval_defender_signatures({"def_age": 0}).status == "ok"
    assert H.eval_defender_signatures({"def_age": 5}).status == "warn"
    assert H.eval_defender_signatures({"def_age": 40}).status == "fail"


# ── Firewall ─────────────────────────────────────────────────────────────────

def test_firewall_todos_los_perfiles_activos():
    d = {"fw": [{"name": "Domain", "on": True}, {"name": "Private", "on": True},
                {"name": "Public", "on": True}]}
    assert H.eval_firewall(d).status == "ok"


def test_firewall_un_perfil_apagado_falla_y_lo_nombra():
    d = {"fw": [{"name": "Domain", "on": True}, {"name": "Public", "on": False}]}
    c = H.eval_firewall(d)
    assert c.status == "fail"
    assert "Public" in c.detail


def test_firewall_perfil_unico_no_lista_se_normaliza():
    # PowerShell devuelve un objeto suelto cuando solo hay un elemento.
    c = H.eval_firewall({"fw": {"name": "Public", "on": False}})
    assert c.status == "fail"


# ── El falso positivo que motivo estas pruebas ───────────────────────────────

def test_propiedad_ausente_no_es_desactivado():
    """Si la sonda no pudo leer el dato, el control debe quedar DESCONOCIDO.

    Nunca 'fail': acusar de inseguro a un equipo por un dato que no se pudo
    leer es peor que no evaluarlo, porque contamina el puntaje del informe.
    """
    for fn in (H.eval_uac, H.eval_rdp, H.eval_defender, H.eval_firewall):
        assert fn({}).status == "unknown", fn.__name__


def test_uac_activado_y_desactivado():
    assert H.eval_uac({"uac": 1}).status == "ok"
    c = H.eval_uac({"uac": 0})
    assert c.status == "fail" and c.reboot is True


# ── AutoRun: el vector USB ───────────────────────────────────────────────────

def test_autorun_todas_las_unidades_cubiertas():
    assert H.eval_autorun({"autorun_m": 255}).status == "ok"


def test_autorun_sin_directiva_es_fallo():
    c = H.eval_autorun({})
    assert c.status == "fail"
    assert "No hay ninguna directiva" in c.detail


def test_autorun_sin_cubrir_extraibles_es_fallo():
    # 0x08 cubre unidades fijas pero NO las extraibles (0x04): el USB
    # sigue expuesto, que es justo lo que importa en un laboratorio.
    c = H.eval_autorun({"autorun_m": 0x08})
    assert c.status == "fail"


def test_autorun_cubre_extraibles_pero_no_todo_es_aviso():
    c = H.eval_autorun({"autorun_m": 0x04})
    assert c.status == "warn"


def test_autorun_toma_el_valor_mas_protector_de_las_dos_ramas():
    # Se consultan HKLM y HKCU; debe mandar el mas restrictivo.
    assert H.eval_autorun({"autorun_m": 0, "autorun_u": 255}).status == "ok"


# ── SMBv1 ────────────────────────────────────────────────────────────────────

def test_smb1_servidor_activo_es_fallo():
    c = H.eval_smb1({"smb1_srv": True})
    assert c.status == "fail"
    assert "WannaCry" in c.detail


def test_smb1_solo_cliente_es_aviso():
    assert H.eval_smb1({"smb1_srv": False, "smb1_cli": "Automatic"}).status == "warn"


def test_smb1_todo_apagado_es_ok():
    assert H.eval_smb1({"smb1_srv": False, "smb1_cli": "Disabled"}).status == "ok"


# ── Cuenta invitado y LSA ────────────────────────────────────────────────────

def test_invitado_habilitado_es_fallo():
    c = H.eval_guest({"guest_on": True, "guest_name": "Invitado"})
    assert c.status == "fail"
    assert "Invitado" in c.detail


def test_lsa_acepta_los_dos_valores_validos():
    # RunAsPPL 1 (con bloqueo UEFI) y 2 (sin el) significan ambos ACTIVO.
    assert H.eval_lsa({"lsa_ppl": 1}).status == "ok"
    assert H.eval_lsa({"lsa_ppl": 2}).status == "ok"
    assert H.eval_lsa({}).status == "warn"


# ── Autologon ────────────────────────────────────────────────────────────────

def test_autologon_con_contrasena_en_claro_es_fallo():
    c = H.eval_autologon({"autologon": "1", "autologon_pw": True})
    assert c.status == "fail"
    assert "EN CLARO" in c.detail


def test_autologon_desactivado_es_ok():
    assert H.eval_autologon({"autologon": "", "autologon_pw": False}).status == "ok"


# ── Puntaje ──────────────────────────────────────────────────────────────────

def _check(status):
    return H.HardeningCheck("k", "t", status, "d")


def test_puntaje_todo_correcto_es_cien():
    assert H.hardening_score([_check("ok")] * 5) == 100


def test_puntaje_todo_mal_es_cero():
    assert H.hardening_score([_check("fail")] * 5) == 0


def test_aviso_vale_medio_punto():
    assert H.hardening_score([_check("warn")] * 4) == 50


def test_desconocido_no_penaliza_el_puntaje():
    """Un control que no se pudo leer se excluye del calculo: si penalizara,
    un equipo sin BitLocker disponible pareceria inseguro sin serlo."""
    assert H.hardening_score([_check("ok"), _check("unknown")]) == 100


def test_puntaje_sin_controles_evaluables():
    assert H.hardening_score([_check("unknown")]) == 100
    assert H.hardening_score([]) == 100


# ── Integracion de la evaluacion completa ────────────────────────────────────

def test_evaluate_devuelve_todos_los_controles_con_datos_vacios():
    checks = H.evaluate({})
    assert len(checks) == H.TOTAL_CHECKS
    # Con datos vacios ninguno debe reventar y todos traen titulo legible.
    assert all(c.title and c.status in ("ok", "warn", "fail", "unknown")
               for c in checks)


def test_cada_control_problematico_trae_referencia_cis():
    checks = H.evaluate({"guest_on": True, "uac": 0, "smb1_srv": True})
    for c in checks:
        if c.status in ("fail", "warn"):
            assert c.to_dict()["cis"], f"{c.key} sin referencia CIS"


def test_los_hallazgos_de_blindaje_heredan_la_tecnica_attack():
    checks = H.evaluate({"guest_on": True})
    guest = next(c for c in checks if c.key == "guest")
    assert guest.to_dict()["attack_info"]["id"] == "T1078"
