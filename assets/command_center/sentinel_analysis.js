/* ============================================================
   SENTINEL — Tarjeta de análisis bajo demanda.
   Muestra el resultado de analizar un archivo / URL / hash y, si es
   un archivo peligroso, ofrece ponerlo en cuarentena.
   Expone window.SentinelAnalysis { show, setBridge }.
   ============================================================ */
"use strict";

(function () {
  const SEV_COLOR = { ALTA: "#ff5a78", MEDIA: "#f59e0b", BAJA: "#2fe6a8" };
  let bridge = null;
  let lastPath = null;

  function el(id) { return document.getElementById(id); }

  function show(r) {
    const card = el("analysisCard");
    if (!card) return;
    const ok = r && r.ok;
    const sev = (r && r.severity) || "BAJA";
    const color = SEV_COLOR[sev] || "#2fe6a8";

    el("anTitle").textContent = ok
      ? `${r.type.toUpperCase()} · ${r.verdict || ""}`
      : "No se pudo analizar";
    el("anTitle").style.color = color;
    el("anTarget").textContent = (r && r.target) || "";

    const body = el("anBody");
    body.innerHTML = "";
    if (!ok) {
      body.innerHTML = `<div class="an-note">${(r && r.error) || "Error desconocido."}</div>`;
    } else {
      const sevTag = document.createElement("div");
      sevTag.className = "an-sev";
      sevTag.style.background = color;
      sevTag.textContent = `RIESGO ${sev}`;
      body.appendChild(sevTag);
      const det = r.details || {};
      for (const k of Object.keys(det)) {
        const row = document.createElement("div");
        row.className = "an-row";
        row.innerHTML = `<span class="an-k">${k}</span><span class="an-v"></span>`;
        row.querySelector(".an-v").textContent = det[k];
        body.appendChild(row);
      }
      (r.notes || []).forEach((n) => {
        const d = document.createElement("div");
        d.className = "an-note"; d.textContent = "• " + n;
        body.appendChild(d);
      });
    }

    // Boton cuarentena solo para archivos
    const qBtn = el("anQuarantine");
    if (qBtn) {
      const canQ = ok && r.can_quarantine && r.path;
      qBtn.style.display = canQ ? "inline-block" : "none";
      lastPath = canQ ? r.path : null;
    }
    card.hidden = false;
  }

  window.SentinelAnalysis = {
    show,
    setBridge(b) { bridge = b; },
  };

  document.addEventListener("DOMContentLoaded", () => {
    const close = el("anClose");
    if (close) close.addEventListener("click", () => { el("analysisCard").hidden = true; });
    const q = el("anQuarantine");
    if (q) q.addEventListener("click", () => {
      if (bridge && bridge.quarantine && lastPath) {
        bridge.quarantine(lastPath);
        el("analysisCard").hidden = true;
      }
    });
  });
})();
