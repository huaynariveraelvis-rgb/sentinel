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
| **1** | GUI Command Center + **panel de vigilancia en vivo** (orbe rojo ante amenaza, puntaje) | ✅ |
| **2** | **Auditoría de hardening** de Windows (Defender/Firewall/UAC/RDP/SMBv1) + botón "Blindar" | ✅ |
| **3** | **Detección inteligente** (cerebro IA, resumen en lenguaje claro) + **alertas por voz** | ✅ |
| **4** | **Análisis bajo demanda** (archivos / URLs / hashes + cuarentena) | ✅ |
| **5** | **Producto**: licencias offline, build (PyInstaller) + instalador (Inno Setup), docs | ✅ |

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

## Probar

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python -m sentinel        # GUI: Command Center + panel en vivo
python -m sentinel.scan   # solo motor, reporte por consola
```

Para ver **todas** las conexiones de red, ejecútalo como administrador.

---

## Estructura

```
sentinel/
  sentinel/
    __init__.py          # marca, versión
    __main__.py / app.py # entrada GUI
    scan.py              # demo headless del motor (CLI)
    core/
      monitor.py         # vigilancia (procesos/red/arranque)
      hardening.py       # auditoría de defensas de Windows
      fixer.py           # aplica correcciones (con UAC)
      brain.py           # resumen/priorización (IA opcional)
      voice.py           # alertas habladas (TTS de Windows)
      analysis.py        # análisis de archivos/URLs/hashes + cuarentena
      config.py          # carga de settings
      license.py         # licenciamiento offline
    ui/                  # ventana PyQt6 + bridge + worker
    tools/genlicense.py  # emisor de claves (fabricante)
  assets/command_center/ # frontend (orbe verde guardián, panel en vivo)
  installer/installer.iss# instalador Inno Setup
  build.py               # empaqueta con PyInstaller
  docs/                  # EULA + guía de usuario
```

## Empaquetar y vender

```bash
pip install pyinstaller
python build.py                       # -> dist/SENTINEL/SENTINEL.exe
iscc installer/installer.iss          # -> instalador SENTINEL_Setup.exe
```

Emitir una licencia (fabricante):

```bash
python -m sentinel.tools.genlicense "Cliente SAC"        # perpetua
python -m sentinel.tools.genlicense "Cliente SAC" 365    # 1 año
```

El cliente pega la clave en `config/license.key`. Sin licencia, corre en
**modo prueba**.

---

© ELVIS SYSTEMS Industrias. Uso defensivo y educativo.
