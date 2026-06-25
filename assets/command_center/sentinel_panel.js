/* ============================================================
   SENTINEL — Panel de vigilancia en vivo.
   Recibe los reportes del motor (via pyBridge.scan_result), calcula
   el puntaje de seguridad, pinta los hallazgos y enciende el orbe en
   rojo cuando hay una amenaza grave (ALTA/CRITICA).
   Expone window.SentinelPanel { setBridge, onScan }.
   ============================================================ */
"use strict";

(function () {
  const SEV_COLOR = {
    CRITICA: "#ff3355", ALTA: "#ff5a78", MEDIA: "#f59e0b",
    BAJA: "#2fe6a8", INFO: "#7fd9bf",
  };
  const SEV_ICON = {
    CRITICA: "⛔", ALTA: "🔴", MEDIA: "🟠", BAJA: "🔵", INFO: "·",
  };
  // Penalizacion por hallazgo para el puntaje (0–100).
  const SEV_PENALTY = { CRITICA: 25, ALTA: 15, MEDIA: 7, BAJA: 1, INFO: 0 };
  const THREAT_LEVELS = new Set(["ALTA", "CRITICA"]);

  let bridge = null;

  const $ = (id) => document.getElementById(id);

  function computeScore(findings) {
    let score = 100;
    for (const f of findings) score -= (SEV_PENALTY[f.severity_label] || 0);
    return Math.max(0, Math.min(100, score));
  }

  function scoreColor(score) {
    if (score >= 80) return "#2fe6a8";
    if (score >= 50) return "#f59e0b";
    return "#ff3355";
  }

  function render(report) {
    const findings = report.findings || [];
    const counts = report.counts || {};
    const maxSev = report.max_severity || "INFO";

    // --- Puntaje ---
    const score = computeScore(findings);
    const scoreEl = $("spScore");
    if (scoreEl) {
      scoreEl.textContent = score;
      const c = scoreColor(score);
      scoreEl.style.color = c;
      scoreEl.style.textShadow = `0 0 22px ${c}66`;
    }

    // --- Resumen ---
    const bs = (counts.por_severidad) || {};
    const sumEl = $("spSummary");
    if (sumEl) {
      const total = counts.total != null ? counts.total : findings.length;
      sumEl.innerHTML =
        `${total} hallazgos · ` +
        `<b style="color:#ff5a78">${bs.ALTA || 0} altas</b> · ` +
        `<b style="color:#f59e0b">${bs.MEDIA || 0} medias</b> · ` +
        `${bs.BAJA || 0} bajas`;
    }

    // --- Lista (lo grave primero; el backend ya ordena por severidad) ---
    const listEl = $("spList");
    if (listEl) {
      listEl.innerHTML = "";
      let shownInfo = 0;
      for (const f of findings) {
        const sev = f.severity_label;
        if (sev === "INFO" && shownInfo >= 8) continue;   // no saturar de info
        if (sev === "INFO") shownInfo++;
        const color = SEV_COLOR[sev] || "#7fd9bf";
        const item = document.createElement("div");
        item.className = "sp-item";
        item.style.setProperty("--sev", color);
        const ev = f.evidence || {};
        const canFix = ev.fix_command && ev.key;
        item.innerHTML =
          `<span class="sp-ic">${SEV_ICON[sev] || "·"}</span>` +
          `<div class="sp-body">` +
          `<div class="sp-t"></div>` +
          `<div class="sp-d"></div>` +
          `<span class="sp-sev">${sev} · ${f.category || ""}</span>` +
          (canFix ? `<button class="sp-fix" data-key="${ev.key}">🛡 Blindar</button>` : "") +
          `</div>`;
        item.querySelector(".sp-t").textContent = f.title || "";
        item.querySelector(".sp-d").textContent = f.detail || "";
        listEl.appendChild(item);
      }
    }

    // --- Orbe + alarma global ---
    const isThreat = THREAT_LEVELS.has(maxSev);
    document.body.classList.toggle("threat", isThreat);
    if (window.Orb && window.Orb.setThreat) window.Orb.setThreat(isThreat);

    // Mensaje central: usa el resumen del cerebro si viene en el reporte.
    const respEl = $("response");
    if (respEl) {
      if (report.summary) respEl.textContent = (isThreat ? "⚠ " : "") + report.summary;
      else if (isThreat) respEl.textContent = "⚠ Amenaza detectada. Revisá el panel.";
      else if (score >= 80) respEl.textContent = "SENTINEL en línea. Sistema protegido.";
      else respEl.textContent = "SENTINEL en línea. Hay puntos a revisar.";
    }
  }

  function flash(msg) {
    const respEl = $("response");
    if (respEl) respEl.textContent = msg;
  }

  window.SentinelPanel = {
    setBridge(b) {
      bridge = b;
      if (bridge && bridge.request_scan) bridge.request_scan();
    },
    onScan(json) {
      try { render(JSON.parse(json)); }
      catch (e) { console.error("SentinelPanel.onScan:", e); }
    },
    onFix(json) {
      try {
        const r = JSON.parse(json);
        flash(r.ok ? "✓ " + r.msg : "✗ " + r.msg);
      } catch (e) { console.error(e); }
    },
    onAnalysis(json) {
      try { window.SentinelAnalysis && window.SentinelAnalysis.show(JSON.parse(json)); }
      catch (e) { console.error(e); }
    },
  };

  // Botones: re-escanear + delegacion para "Blindar"
  document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("spRescan");
    if (btn) btn.addEventListener("click", () => {
      if (bridge && bridge.request_scan) bridge.request_scan();
    });
    const list = document.getElementById("spList");
    if (list) list.addEventListener("click", (e) => {
      const b = e.target.closest(".sp-fix");
      if (b && bridge && bridge.apply_fix) {
        flash("Aplicando blindaje… acepta el permiso de administrador.");
        bridge.apply_fix(b.dataset.key);
      }
    });
  });
})();
