"""brain.py — Cerebro de SENTINEL: resume y prioriza amenazas en lenguaje claro.

Siempre produce un resumen HEURISTICO (sin internet ni claves). Si hay una
clave de Gemini configurada y habilitada, puede generar una explicacion mas
rica/guia de remediacion. La IA es un EXTRA, nunca un requisito.
"""
from __future__ import annotations

_SEV_ORDER = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"]


def heuristic_summary(report: dict) -> str:
    """Frase corta y natural a partir del reporte (para mostrar/hablar)."""
    counts = report.get("counts", {})
    bs = counts.get("por_severidad", {})
    crit, alta, media = bs.get("CRITICA", 0), bs.get("ALTA", 0), bs.get("MEDIA", 0)

    if crit:
        return (f"Atención: {crit} amenaza{'s' if crit > 1 else ''} crítica"
                f"{'s' if crit > 1 else ''} en tu equipo. Revisá el panel ya.")
    if alta:
        # nombra la primera amenaza alta
        top = next((f for f in report.get("findings", [])
                    if f.get("severity_label") == "ALTA"), None)
        name = (top or {}).get("title", "una amenaza alta")
        extra = f" y {media} punto{'s' if media > 1 else ''} medio" if media else ""
        return f"Detecté {name.lower()}{extra}. Conviene atenderlo."
    if media:
        return f"Hay {media} punto{'s' if media > 1 else ''} de severidad media a revisar. Nada crítico."
    return "Todo en orden. No detecté amenazas relevantes."


def alert_phrase(finding: dict) -> str:
    """Aviso hablado para una amenaza nueva."""
    sev = finding.get("severity_label", "")
    title = finding.get("title", "amenaza detectada")
    pre = "Alerta crítica" if sev == "CRITICA" else "Alerta"
    return f"{pre}. {title}."


def gemini_explain(findings: list, api_key: str, max_items: int = 6) -> str | None:
    """Explicacion enriquecida via Gemini (opcional). None si no se puede."""
    if not api_key or not findings:
        return None
    try:
        from google import genai
    except ImportError:
        return None
    try:
        top = findings[:max_items]
        bullet = "\n".join(
            f"- [{f.get('severity_label')}] {f.get('title')}: {f.get('detail')}"
            for f in top)
        prompt = (
            "Eres SENTINEL, un guardián de ciberseguridad. Explica en español, "
            "claro y breve (máx 5 frases), el riesgo de estos hallazgos en el PC "
            "del usuario y qué hacer, priorizando lo más grave. Sin tecnicismos "
            "innecesarios:\n\n" + bullet)
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt)
        return (getattr(resp, "text", "") or "").strip() or None
    except Exception:
        return None
