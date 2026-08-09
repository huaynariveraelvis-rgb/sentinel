"""frameworks.py — Cobertura de marcos: NIST CSF 2.0 y CIS.

Traduce los hallazgos de SENTINEL al lenguaje de los marcos que un jurado
reconoce. Su aporte mas fuerte: hace explicita la funcion GOBERNAR del CSF 2.0
(la sexta funcion, ausente del CSF 1.1), que es justo el punto que la tesis
necesita defender.

NIST CSF 2.0 organiza la ciberseguridad en seis funciones:

    GV  Gobernar   — politica, roles, autorizacion, gestion del riesgo
    ID  Identificar— inventario de activos y vulnerabilidades
    PR  Proteger   — defensas y endurecimiento
    DE  Detectar   — vigilancia y deteccion de eventos
    RS  Responder  — contencion y respuesta a incidentes
    RC  Recuperar  — restauracion tras un incidente

Cada hallazgo se ubica en su funcion segun su naturaleza. El resultado es un
tablero de cobertura que dice, con evidencia, que funciones cubre el sistema.
"""
from __future__ import annotations

# Orden y descripcion oficiales de las funciones del CSF 2.0.
CSF_FUNCIONES = {
    "GV": ("Gobernar", "Politica, roles, autorizacion y gestion del riesgo."),
    "ID": ("Identificar", "Inventario de activos, exposiciones y vulnerabilidades."),
    "PR": ("Proteger", "Defensas, endurecimiento y controles preventivos."),
    "DE": ("Detectar", "Vigilancia continua y deteccion de eventos adversos."),
    "RS": ("Responder", "Contencion, remediacion y respuesta a incidentes."),
    "RC": ("Recuperar", "Restauracion de servicios y datos tras un incidente."),
}

# Cada categoria de hallazgo se asigna a una funcion del CSF 2.0.
_CATEGORIA_CSF = {
    "recon": "ID", "enum": "ID", "exposicion": "ID", "vulnerabilidad": "ID",
    "cripto": "ID",
    "blindaje": "PR", "phishing": "PR",
    "arranque": "DE", "proceso": "DE", "red": "DE", "deteccion": "DE",
    "cuarentena": "RS", "remediacion": "RS", "blindaje_aplicado": "RS",
    "respaldo": "RC", "recuperacion": "RC",
    "gobierno": "GV", "alcance": "GV", "auditoria": "GV",
}


def _campo(item, nombre: str, default=""):
    """Lee un atributo tanto de un Finding (objeto) como de un dict."""
    if isinstance(item, dict):
        return item.get(nombre, default)
    return getattr(item, nombre, default)


def csf_function_for(item) -> str:
    """Funcion del CSF 2.0 que corresponde a un hallazgo. 'ID' por defecto:
    un hallazgo sin categoria clara es, como minimo, algo identificado."""
    cat = str(_campo(item, "category", "")).lower()
    return _CATEGORIA_CSF.get(cat, "ID")


def csf_coverage(findings, checks=None, has_scope: bool = False,
                 has_audit_log: bool = False) -> dict:
    """Tablero de cobertura del CSF 2.0.

    `has_scope` y `has_audit_log` alimentan GOBERNAR: la existencia de un alcance
    autorizado y de un registro de acciones ES cobertura de gobierno, aunque no
    genere hallazgos. Asi la sexta funcion no aparece vacia solo porque no
    produce alertas.
    """
    cobertura = {f: {"funcion": CSF_FUNCIONES[f][0],
                     "descripcion": CSF_FUNCIONES[f][1],
                     "items": 0, "cubierta": False, "evidencia": []}
                 for f in CSF_FUNCIONES}

    for f in list(findings or []):
        fn = csf_function_for(f)
        cobertura[fn]["items"] += 1
        cobertura[fn]["cubierta"] = True
        titulo = str(_campo(f, "title", ""))
        if titulo and len(cobertura[fn]["evidencia"]) < 5:
            cobertura[fn]["evidencia"].append(titulo)

    # Los controles de endurecimiento son evidencia directa de PROTEGER.
    for c in list(checks or []):
        cobertura["PR"]["items"] += 1
        cobertura["PR"]["cubierta"] = True

    # GOBERNAR: se sostiene en la existencia de autorizacion y trazabilidad.
    if has_scope:
        cobertura["GV"]["cubierta"] = True
        cobertura["GV"]["evidencia"].append("Alcance autorizado cargado (autorizacion escrita).")
    if has_audit_log:
        cobertura["GV"]["cubierta"] = True
        cobertura["GV"]["evidencia"].append("Registro de acciones (cadena de custodia).")

    cubiertas = sum(1 for v in cobertura.values() if v["cubierta"])
    return {
        "marco": "NIST CSF 2.0",
        "funciones_cubiertas": cubiertas,
        "funciones_totales": len(CSF_FUNCIONES),
        "porcentaje": round(100 * cubiertas / len(CSF_FUNCIONES)),
        "detalle": cobertura,
    }


def cis_coverage(checks) -> dict:
    """Resumen de cobertura CIS a partir de los controles de endurecimiento.
    Cada `HardeningCheck` trae su area del CIS Benchmark en `.cis`."""
    areas: dict[str, dict] = {}
    for c in list(checks or []):
        area = (_campo(c, "cis", "") or "Sin mapear").strip() or "Sin mapear"
        estado = str(_campo(c, "status", "unknown"))
        a = areas.setdefault(area, {"ok": 0, "warn": 0, "fail": 0, "unknown": 0})
        if estado in a:
            a[estado] += 1
    total = sum(sum(v.values()) for v in areas.values())
    ok = sum(v["ok"] for v in areas.values())
    return {
        "marco": "CIS Benchmarks",
        "areas": areas,
        "controles": total,
        "conformes": ok,
        "porcentaje": round(100 * ok / total) if total else 0,
    }
