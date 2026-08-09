# SENTINEL

**Auditoría y remediación asistida de seguridad para Windows** — by **ELVIS SYSTEMS Industrias**.

SENTINEL es una herramienta de escritorio **defensiva**: audita cómo está
configurado un equipo Windows, vigila comportamientos anómalos en tiempo real,
le pone un **puntaje de blindaje de 0 a 100**, explica cada hallazgo en lenguaje
claro y aplica la corrección **siempre con permiso explícito de administrador**.
Nunca modifica el sistema en silencio.

Cada regla de detección y cada control de blindaje cita su respaldo:
**MITRE ATT&CK**, **CIS Benchmarks** y **NIST Cybersecurity Framework**.

> Alcance estrictamente **local y defensivo**: solo observa la máquina donde
> corre. No escanea la red ni sondea otros equipos.

---

## Capacidades

| Motor | Qué hace |
|---|---|
| **Vigilancia** | Procesos (suplantación de binarios del sistema, ejecución desde rutas temporales), red (puertos de riesgo expuestos, conexiones salientes) y arranque (claves `Run`, carpeta Inicio). |
| **Blindaje** | **16 controles** de configuración de Windows con corrección automática, y el puntaje de 0 a 100. |
| **Persistencia avanzada** | Tareas programadas, servicios, suscripciones WMI e historial de dispositivos USB. |
| **Análisis bajo demanda** | Archivos, direcciones web y hashes; cuarentena reversible. |
| **Cerebro y voz** | Resumen heurístico sin internet, explicación ampliada opcional, y asistente de voz que **ejecuta** 7 acciones reales. |
| **Evidencia** | Historial en SQLite, exportación a JSON/CSV anonimizada, comparativa antes/después y tabla de frecuencias (Pareto) del parque. |
| **Línea base** | Fotografía el estado correcto de un equipo y alerta ante cualquier desviación posterior. |
| **Consola de seguridad** | Anillo de puntaje, rejilla de los 16 controles con acción de blindaje, matriz MITRE ATT&CK por táctica y hallazgos filtrables con su evidencia. |
| **Informes** | Informe técnico de 8 secciones en HTML autocontenido, convertible a PDF con un clic. |

### Los 16 controles de blindaje

Defender · firmas actualizadas · firewall (3 perfiles) · UAC · **reproducción
automática de USB** · SMBv1 · escritorio remoto · cuenta de invitado · inicio de
sesión automático · SmartScreen · Windows Update · política de PowerShell ·
protección LSA · carpetas compartidas · bloqueo de pantalla · BitLocker.

---

## Uso

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python -m sentinel          # Panel gráfico (Command Center)
python -m sentinel.scan     # Barrido rápido por consola
```

### Auditoría de campo

Para recorrer un parque de equipos dejando evidencia documental:

```bash
python -m sentinel.audit --equipo PC-01      # Audita, registra y exporta
python -m sentinel.audit --linea-base PC-01  # Fija el estado de referencia
python -m sentinel.audit --historial         # Auditorías registradas
python -m sentinel.audit --comparar PC-01    # Antes/después de un equipo
python -m sentinel.audit --consolidado       # Tabla de frecuencias (Pareto)
python -m sentinel.audit --acciones          # Registro de cambios aplicados
```

### Informes

```bash
python -m sentinel.audit --equipo PC-01 --informe --pdf  # Audita y genera informe
python -m sentinel.audit --informe PC-01 --pdf           # Informe de lo ya guardado
```

El informe es un **HTML autocontenido** (sin dependencias externas, se abre en
cualquier equipo) con portada y veredicto, los 16 controles con su remediación,
los hallazgos con evidencia, la matriz ATT&CK por táctica, la evolución
histórica, la desviación de la línea base, el registro de cambios y un anexo
metodológico. El PDF se genera con Chrome o Edge en modo headless; si no hay
ninguno, queda el HTML y se imprime desde el navegador.

Desde la interfaz, los mismos informes se piden con los botones **Informe HTML**
e **Informe PDF** de la consola de seguridad.

---

## Consola central del laboratorio (agente + coordinador)

Gestiona la seguridad de todo un parque de equipos desde un solo punto, sin
convertir SENTINEL en una herramienta de intrusión.

### Puesta en producción

**1. En el equipo que hará de coordinador** (el del administrador):

```bash
python -m sentinel.coordinator --generar-token   # crea config/lab_token.key
python -m sentinel.coordinator                   # panel en http://IP:8770/
```

**2. En cada PC del laboratorio** — copia el MISMO token (`config/lab_token.key`
o la variable `SENTINEL_LAB_TOKEN`) y registra el agente como tarea programada:

```bash
python -m sentinel.agent --servidor http://IP_DEL_COORDINADOR:8770 --equipo PC-07
```

El panel muestra el inventario, el puntaje de cada equipo, el Pareto del parque
y el ranking de lo más expuesto, y se actualiza solo.

### Remediación centralizada

El administrador aprueba qué blindaje aplica cada equipo; el agente lo aplica en
su siguiente conexión y reporta el resultado:

```bash
python -m sentinel.coordinator --aprobar PC-07 firewall   # aprueba
python -m sentinel.coordinator --pendientes               # estado
# el agente aplica lo aprobado si corre con --aplicar (como administrador):
python -m sentinel.agent -s http://IP:8770 -e PC-07 --aplicar
```

### Propiedades de seguridad (por diseño)

- **Canal de reporte de una sola vía.** El agente solo *envía* auditorías; no
  abre puertos, no escucha, no acepta comandos, no captura pantalla.
- **Remediación con lista blanca.** Por el canal solo viaja una **clave** de los
  16 blindajes conocidos, nunca un comando. El comando real se resuelve en el
  propio equipo. Lo peor que un coordinador comprometido podría lograr es que un
  equipo se vuelva *más* seguro — no hay forma de ejecución arbitraria.
- **Autenticado y firmado.** Cada mensaje va firmado con HMAC-SHA256 usando el
  token del laboratorio; los reportes alterados o vencidos se rechazan.
- **Aprobado y trazado.** Cada remediación requiere aprobación explícita del
  administrador, se registra localmente y se reporta de vuelta. No hay cambios
  silenciosos.

> **Autorización de despliegue.** Instalar agentes en equipos de una institución
> requiere el permiso de quien los administra (área de TI o dirección). El
> permiso para *auditar* no equivale al permiso para *gestionar y remediar*.

### Terminal remota (administración)

Ejecución remota de comandos sobre los equipos del parque, al estilo de PsExec o
un RMM. Se construye como herramienta de administración legítima, no encubierta:

```bash
python -m sentinel.coordinator --comando PC-07 "ipconfig /all"   # encola
python -m sentinel.coordinator --resultados PC-07                # ve la salida
# el agente ejecuta lo pendiente cuando corre con --ejecutar:
python -m sentinel.agent -s http://IP:8770 -e PC-07 --ejecutar
```

Propiedades que la mantienen como administración y no como intrusión:

- **Autenticada.** Un comando solo se ejecuta si llega firmado con el token del
  laboratorio. Sin el token, el coordinador no entrega trabajos.
- **Auditada.** Cada comando ejecutado queda registrado en el propio equipo
  (`--acciones`) y su salida completa se guarda en el coordinador. No hay
  ejecución silenciosa.
- **No encubierta.** El agente es un servicio conocido y declarado; no se oculta,
  no evade defensas, no desactiva registros.

> Es para equipos que administras **con autorización**. El código no puede
> imponer ese permiso, pero el registro deja constancia de quién ordenó qué y
> cuándo — que es justamente la evidencia que respalda una intervención legítima.

La etiqueta del equipo la pone el auditor (`PC-01`, `PC-02`…). La evidencia
**se anonimiza**: se sustituyen las rutas de perfil y el nombre de usuario, y el
equipo se identifica por una huella derivada, nunca por su nombre real.

Para ver **todas** las conexiones de red, ejecútalo como administrador.

---

## Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
```

Las pruebas corren **sin depender del estado del equipo**: la auditoría separa
recoger los datos (`probe()`, que habla con PowerShell) de evaluarlos
(`evaluate()`, Python puro), y las pruebas alimentan datos sintéticos.

---

## Principios de diseño

1. **Solo lectura por defecto.** Vigilancia y auditoría no modifican nada.
2. **Ningún cambio en silencio.** Toda corrección se eleva y dispara el aviso de
   administrador; si el usuario cancela, se informa con honestidad.
3. **Toda acción es reversible.** La cuarentena mueve y registra, jamás borra.
4. **Funciona sin internet.** Los servicios externos son opcionales.
5. **Alcance local.** Sin ninguna función ofensiva.
6. **Evidencia en cada hallazgo.** Datos crudos adjuntos, siempre verificable.
7. **Un dato que no se pudo leer nunca es un fallo.** Queda como *desconocido* y
   se excluye del puntaje: acusar de inseguro a un equipo por una lectura fallida
   contamina el informe.

---

## Estructura

```
sentinel/
  sentinel/
    app.py / __main__.py   # entrada GUI
    scan.py                # barrido rápido por consola
    audit.py               # auditoría de campo (registro, Pareto, línea base)
    core/
      monitor.py           # vigilancia (procesos/red/arranque)
      hardening.py         # 16 controles, sonda única de PowerShell
      persistence.py       # tareas, servicios, WMI, USB
      catalog.py           # MITRE ATT&CK · CIS · NIST
      evidence.py          # historial, anonimización, Pareto, línea base
      audit_log.py         # registro de cambios aplicados
      analysis.py          # archivos/URLs/hashes + cuarentena
      fixer.py             # aplica correcciones (con UAC)
      brain.py             # resumen y priorización (IA opcional)
      voice.py / voice_live.py
      license.py           # licenciamiento offline firmado
    ui/                    # ventana PyQt6 + bridge + worker
  tests/                   # suite de pruebas
  assets/command_center/   # frontend del panel
  data/                    # historial y evidencia (no versionado)
```

---

## Empaquetar

```bash
pip install pyinstaller
python build.py                       # -> dist/SENTINEL/SENTINEL.exe
iscc installer/installer.iss          # -> instalador
```

Emitir una licencia (fabricante). El secreto de firma se toma de la variable
`SENTINEL_LICENSE_SECRET` o de `config/vendor.key`; **si falta, se usa un
secreto de desarrollo** y `licensing_is_secure()` devuelve `False`.

```bash
python -m sentinel.tools.genlicense "Cliente SAC" 365
```

---

© ELVIS SYSTEMS Industrias. Uso defensivo y educativo.
