# 🛡️ SENTINEL — Guía de usuario

**Tu guardián de seguridad con IA para Windows.** by ELVIS SYSTEMS Industrias.

---

## ¿Qué hace?

SENTINEL vigila tu PC y te avisa cuando algo es peligroso. No ataca a nadie:
solo **protege tu equipo**.

- 🔴 **El orbe se pone rojo** cuando detecta una amenaza grave.
- 📊 **Puntaje de seguridad** (0–100) siempre a la vista.
- 🗣️ **Avisos por voz** en español ante amenazas nuevas (opcional).

---

## La pantalla principal

| Zona | Qué es |
|------|--------|
| **Orbe central** | Estado general. Verde = protegido, rojo = amenaza. |
| **Panel derecho "Vigilancia en vivo"** | Puntaje + lista de hallazgos (lo grave arriba). |
| **Mensaje bajo el orbe** | Resumen en lenguaje claro de lo que pasa. |
| **Botón ↻** | Re-escanear ahora mismo. |

### Tipos de hallazgo
- **Procesos** — programas corriendo desde sitios raros o que suplantan a Windows.
- **Red** — puertos abiertos a internet (RDP, SMB…) y conexiones salientes.
- **Arranque** — programas que se inician solos.
- **Blindaje** — estado de tus defensas (Defender, Firewall, UAC, RDP, SMBv1).

---

## Acciones

### Blindar (corregir defensas)
Cuando un punto de **blindaje** está flojo, aparece un botón **🛡 Blindar**.
Al pulsarlo, SENTINEL aplica la corrección (te pedirá permiso de administrador).

### Analizar un archivo, URL o hash
- **Arrastra** un archivo a la zona de abajo, o haz clic para elegirlo.
- O **escribe** una URL o un hash en la barra y pulsa Enter.

SENTINEL te dirá si es **peligroso / sospechoso / limpio**. Si es un archivo
peligroso, puedes ponerlo en **cuarentena** (se aísla, de forma reversible).

---

## Configuración

Copia `config/settings.example.json` a `config/settings.json` y ajusta:

```json
{
  "scan":     { "auto_interval_seconds": 60 },
  "voice":    { "enabled": true, "alert_on_severity": "ALTA" },
  "ai":       { "gemini_api_key": "TU_CLAVE", "enabled": true },
  "analysis": { "virustotal_api_key": "TU_CLAVE" }
}
```

- **voice.enabled** — activa los avisos hablados.
- **ai** — explicaciones enriquecidas con Gemini (opcional, usa tu clave).
- **analysis.virustotal_api_key** — reputación de archivos/URLs (opcional).

---

## Licencia

SENTINEL funciona en **modo prueba** sin licencia (verás el sello "MODO PRUEBA").
Con una clave válida de ELVIS SYSTEMS desbloqueas la versión completa: pega tu
clave en `config/license.key`.

---

## Soporte

ELVIS SYSTEMS Industrias — soporte y ventas.
