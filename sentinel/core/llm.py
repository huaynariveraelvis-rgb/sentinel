"""llm.py — Cerebro conversacional de SENTINEL via OpenRouter (y Gemini).

Cliente minimo para chat con *function calling*, hablando el formato de OpenAI
(el que expone OpenRouter). Se usa SOLO la libreria estandar (urllib): asi el
motor corre en Kali sin instalar dependencias extra.

OpenRouter es la puerta a muchos modelos (Gemini, Claude, Llama, DeepSeek...).
Se elige el modelo por su id, p.ej. 'google/gemini-2.5-flash' o uno mas fuerte
para razonamiento de pentest. La clave se pasa por argumento (la resuelve quien
llama: variable de entorno OPENROUTER_API_KEY o config/settings.json).

Funcion principal:
    complete(messages, tools, api_key, model) -> dict
        {"message": {...}}  en exito (formato OpenAI: role/content/tool_calls)
        {"error": "..."}    si algo falla (sin conexion, clave mala, etc.)

No lanza excepciones de red: devuelve el error para que el agente lo explique.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "google/gemini-2.5-flash"


def complete(messages: list[dict], tools: list[dict] | None, api_key: str,
             model: str = DEFAULT_MODEL, timeout: int = 180,
             url: str = OPENROUTER_URL, temperature: float = 0.2,
             max_tokens: int = 1024) -> dict:
    """Una vuelta de chat. Devuelve el mensaje del asistente o un error.

    `max_tokens` se limita a proposito: sin tope, OpenRouter reserva el maximo
    del modelo (decenas de miles de tokens) y una cuenta con poco saldo recibe
    HTTP 402 aunque la respuesta real sea corta. 1024 basta para respuestas
    concisas y cabe en saldos pequenos."""
    if not api_key:
        return {"error": "falta la clave del LLM (OPENROUTER_API_KEY)."}

    body: dict = {"model": model, "messages": messages,
                  "temperature": temperature, "max_tokens": max_tokens}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    # Cabeceras opcionales que OpenRouter usa para atribucion/estadisticas.
    req.add_header("X-Title", "SENTINEL Auditor")
    req.add_header("HTTP-Referer", "https://github.com/huaynariveraelvis-rgb/sentinel")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detalle = ""
        try:
            detalle = e.read().decode("utf-8", "ignore")[:500]
        except Exception:
            pass
        return {"error": f"el LLM respondio HTTP {e.code}: {detalle or e.reason}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"error": f"sin conexion con el LLM ({e}). ¿Kali tiene internet?"}
    except ValueError as e:
        return {"error": f"respuesta no valida del LLM: {e}"}

    err = payload.get("error")
    if err:
        msg = err.get("message") if isinstance(err, dict) else str(err)
        return {"error": f"el LLM devolvio un error: {msg}"}

    choices = payload.get("choices") or []
    if not choices:
        return {"error": "el LLM no devolvio ninguna respuesta."}
    return {"message": choices[0].get("message") or {}, "raw": payload}
