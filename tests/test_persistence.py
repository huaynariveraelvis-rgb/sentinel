"""Pruebas de la deteccion de persistencia avanzada.

El foco esta en dos cosas que se equivocan facil:
  * la ruta de servicio SIN COMILLAS (hay que distinguir la vulnerable de la
    que solo parece rara), y
  * el equilibrio entre senal y ruido en las tareas programadas.
"""
from sentinel.core import persistence as P
from sentinel.core.monitor import Severity


# ── Extraccion de la ruta del ejecutable ─────────────────────────────────────

def test_extrae_ruta_entre_comillas_ignorando_argumentos():
    assert P._exe_from_command(r'"C:\Prog Files\App\s.exe" -k red') == \
        r"C:\Prog Files\App\s.exe"


def test_extrae_ruta_sin_comillas_cortando_en_exe():
    assert P._exe_from_command(r"C:\Windows\System32\svc.exe -service") == \
        r"C:\Windows\System32\svc.exe"


def test_extraccion_tolera_comando_vacio():
    assert P._exe_from_command("") == ""
    assert P._exe_from_command(None) == ""


# ── Ruta de servicio sin comillas (escalada de privilegios) ──────────────────

def test_ruta_sin_comillas_con_espacios_es_vulnerable():
    assert P._unquoted_with_spaces(r"C:\Program Files\App\svc.exe") is True


def test_ruta_entre_comillas_no_es_vulnerable():
    assert P._unquoted_with_spaces(r'"C:\Program Files\App\svc.exe"') is False


def test_ruta_sin_espacios_no_es_vulnerable():
    assert P._unquoted_with_spaces(r"C:\Windows\System32\svc.exe") is False


def test_espacios_solo_en_los_argumentos_no_es_vulnerable():
    """El riesgo esta en los espacios ANTES del .exe, no en los argumentos."""
    assert P._unquoted_with_spaces(r"C:\Win\svc.exe -a b c") is False


# ── Tareas programadas: senal frente a ruido ─────────────────────────────────

def _tarea(name, exec_, autor="Tercero"):
    return {"name": name, "path": "\\", "autor": autor, "exec": exec_, "args": ""}


def test_tarea_en_carpeta_temporal_es_alta():
    d = {"tasks": [_tarea("Raro", r"C:\Users\X\AppData\Local\Temp\a.exe")]}
    import os
    # Se apoya en las carpetas sospechosas reales del sistema.
    temp = os.environ.get("TEMP")
    if not temp:
        return
    d = {"tasks": [_tarea("Raro", os.path.join(temp, "a.exe"))]}
    fs = P.scan_scheduled_tasks(d)
    assert any(f.severity == Severity.HIGH for f in fs)
    assert all(f.attack == "T1053.005" for f in fs)


def test_tarea_que_lanza_powershell_es_media():
    fs = P.scan_scheduled_tasks({"tasks": [_tarea("X", r"C:\Windows\powershell.exe")]})
    assert len(fs) == 1
    assert fs[0].severity == Severity.MEDIUM


def test_tareas_legitimas_se_agrupan_en_un_solo_inventario():
    """Veinte avisos de tareas normales esconden el que importa: se resumen."""
    tareas = [_tarea(f"App{i}", rf"C:\Program Files\App{i}\a.exe") for i in range(20)]
    fs = P.scan_scheduled_tasks({"tasks": tareas})
    assert len(fs) == 1
    assert fs[0].severity == Severity.INFO
    assert fs[0].evidence["total"] == 20


def test_tareas_de_fabricantes_conocidos_no_generan_ruido():
    fs = P.scan_scheduled_tasks({"tasks": [
        _tarea("Update", r"C:\Program Files\Google\upd.exe", autor="Google LLC")]})
    assert fs == []


def test_sin_tareas_no_hay_hallazgos():
    assert P.scan_scheduled_tasks({}) == []


# ── Servicios ────────────────────────────────────────────────────────────────

def test_servicio_con_ruta_sin_comillas_es_media():
    d = {"services": [{"name": "svc", "display": "Servicio",
                       "bin": r"C:\Program Files\X\s.exe", "start": "Auto",
                       "account": "LocalSystem"}]}
    fs = P.scan_services(d)
    assert len(fs) == 1 and fs[0].severity == Severity.MEDIUM
    assert fs[0].attack == "T1543.003"


def test_servicio_normal_no_genera_hallazgo():
    d = {"services": [{"name": "svc", "display": "S",
                       "bin": r'"C:\Program Files\X\s.exe"', "start": "Auto",
                       "account": "LocalSystem"}]}
    assert P.scan_services(d) == []


# ── WMI y USB ────────────────────────────────────────────────────────────────

def test_suscripcion_wmi_es_alta():
    fs = P.scan_wmi({"wmi": [{"filtro": "F", "consumidor": "C"}]})
    assert len(fs) == 1
    assert fs[0].severity == Severity.HIGH and fs[0].attack == "T1546.003"


def test_sin_wmi_no_hay_hallazgo():
    assert P.scan_wmi({"wmi": []}) == []


def test_historial_usb_cuenta_dispositivos():
    fs = P.scan_usb_history({"usb": ["Disk&Ven_A", "Disk&Ven_B", "Disk&Ven_C"]})
    assert len(fs) == 1
    assert fs[0].evidence["total"] == 3
    assert fs[0].attack == "T1091"


def test_sin_usb_no_hay_hallazgo():
    assert P.scan_usb_history({"usb": []}) == []


# ── Robustez del conjunto ────────────────────────────────────────────────────

def test_scan_persistence_tolera_datos_vacios():
    assert P.scan_persistence({}) == []


def test_una_superficie_rota_no_tumba_las_demas():
    """Si un bloque de la sonda devuelve basura, el resto debe seguir."""
    d = {"services": "esto no es una lista",
         "wmi": [{"filtro": "F", "consumidor": "C"}]}
    fs = P.scan_persistence(d)
    assert any(f.attack == "T1546.003" for f in fs)
