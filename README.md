# 🛡️ SENTINEL

**Guardián de seguridad con IA para Windows** — by **ELVIS SYSTEMS Industrias**.

SENTINEL es un asistente de escritorio **defensivo**: vigila tu equipo en tiempo
real, detecta comportamientos sospechosos, audita el endurecimiento de Windows y
te explica las amenazas en lenguaje claro (con voz e interfaz tipo "command
center" con orbe neural). Pensado como producto para proteger un PC — **nunca**
para atacar equipos de terceros.

> Hereda el ADN visual del proyecto *Two Twenty* (orbe, Command Center, voz),
> re-enfocado 100 % a ciberseguridad.

---

## Estado del proyecto (por fases)

| Fase | Entregable | Estado |
|------|------------|--------|
| **0** | Base + **motor de vigilancia headless** (procesos, red, arranque) | ✅ |
| 1 | GUI Command Center reskineada + panel de vigilancia en vivo | ⏳ |
| 2 | Auditoría de hardening de Windows + puntaje de seguridad | ⏳ |
| 3 | Detección inteligente + alertas por voz (Gemini) | ⏳ |
| 4 | Análisis bajo demanda (archivos / URLs / hashes + cuarentena) | ⏳ |
| 5 | Producto: instalador, licencias, docs | ⏳ |

---

## Qué hace hoy (Fase 0)

El **motor de vigilancia** (`sentinel/core/monitor.py`) hace un barrido defensivo
de **solo lectura** de tu propia máquina:

- **Procesos** — detecta binarios del sistema (`svchost.exe`, `lsass.exe`…)
  corriendo fuera de `System32` (suplantación) y ejecutables lanzados desde
  carpetas temporales / descargas.
- **Red** — puertos de riesgo expuestos a todas las interfaces (RDP 3389, SMB
  445, VNC, Telnet…), otros puertos a la escucha y conexiones salientes a IPs
  públicas (con el proceso dueño).
- **Arranque** — entradas `Run` del registro (HKCU/HKLM) y carpetas de Inicio,
  marcando las que ejecutan desde rutas sospechosas.

Cada hallazgo trae **severidad** (CRÍTICA → INFO), explicación y evidencia.

## Probar el motor

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m sentinel.scan
```

Para ver **todas** las conexiones de red, ejecútalo como administrador.

---

## Estructura

```
sentinel/
  sentinel/
    __init__.py          # marca, versión
    scan.py              # demo headless del motor (CLI)
    core/
      monitor.py         # motor de vigilancia (procesos/red/arranque)
  assets/command_center/ # frontend reskineado (orbe verde guardián)
  config/
    settings.example.json
  requirements.txt
```

---

© ELVIS SYSTEMS Industrias. Uso defensivo y educativo.
