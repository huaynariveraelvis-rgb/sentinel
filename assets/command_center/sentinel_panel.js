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
  const THREAT_LEVELS = new Set(["ALTA", "CRITICA"]);

  let bridge = null;

  const $ = (id) => document.getElementById(id);

  /* El puntaje LO CALCULA EL MOTOR (core/hardening.py) sobre los 16 controles
     de blindaje, y es el mismo numero que reporta la auditoria de consola.

     Antes el panel calculaba uno propio restando puntos por cada hallazgo.
     Eso daba dos numeros distintos para lo mismo (el motor decia 75 y el panel
     mostraba 7) y castigaba el INVENTARIO: cada puerto a la escucha restaba,
     asi que un equipo sano con muchos servicios parecia catastrofico.

     Mientras el blindaje no ha terminado su primera pasada, el reporte aun no
     trae puntaje: se muestra un guion en vez de inventar un numero. */
  function engineScore(report) {
    const s = report.hardening_score;
    return (typeof s === "number" && isFinite(s)) ? s : null;
  }

  function scoreColor(score) {
    if (score >= 80) return "#2fe6a8";
    if (score >= 50) return "#f59e0b";
    return "#ff3355";
  }

  function render(report) {
    // Las amenazas RESUELTAS (protegidas por firewall) se quitan de la lista:
    // así, al cerrar un puerto, el ítem DESAPARECE y se ve que SENTINEL actuó.
    const findings = (report.findings || []).filter(
      (f) => !(f.evidence && f.evidence.blocked));
    const maxSev = report.max_severity || "INFO";

    // --- Puntaje de blindaje (el del motor) ---
    const score = engineScore(report);
    const scoreEl = $("spScore");
    if (scoreEl) {
      scoreEl.textContent = (score === null) ? "—" : score;
      const c = (score === null) ? "#7fd9bf" : scoreColor(score);
      scoreEl.style.color = c;
      scoreEl.style.textShadow = `0 0 22px ${c}66`;
      scoreEl.title = (score === null)
        ? "Auditando el blindaje del sistema…"
        : `${score} de 100 segun los 16 controles de blindaje`;
    }

    // --- Resumen (cuenta solo lo NO resuelto) ---
    const bs = {};
    for (const f of findings) bs[f.severity_label] = (bs[f.severity_label] || 0) + 1;
    const sumEl = $("spSummary");
    if (sumEl) {
      sumEl.innerHTML =
        `${findings.length} hallazgos · ` +
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
      else if (score !== null && score >= 80) respEl.textContent = "SENTINEL en línea. Sistema protegido.";
      else respEl.textContent = "SENTINEL en línea. Hay puntos a revisar.";
    }
  }

  function flash(msg) {
    const respEl = $("response");
    if (respEl) respEl.textContent = msg;
  }

  // La consola de seguridad recibe los mismos datos que este panel. Se
  // alimenta desde aqui para no tocar el cableado del Command Center
  // heredado (app.js), que ya conecta las senales del puente a SentinelPanel.
  const console_ = () => window.SentinelConsole;

  window.SentinelPanel = {
    setBridge(b) {
      bridge = b;
      if (console_()) {
        console_().setBridge(b);
        // Senales propias de la consola: informe generado y salida de la terminal.
        if (b && b.report_result) {
          b.report_result.connect((j) => console_().onReport(j));
        }
        if (b && b.command_result) {
          b.command_result.connect((j) => console_().onCommandResult(j));
        }
      }
      if (bridge && bridge.request_scan) bridge.request_scan();
    },
    onScan(json) {
      try {
        const rep = JSON.parse(json);
        render(rep);
        if (console_()) console_().render(rep);
      } catch (e) { console.error("SentinelPanel.onScan:", e); }
    },
    onFix(json) {
      try {
        const r = JSON.parse(json);
        flash(r.ok ? "✓ " + r.msg : "✗ " + r.msg);
        if (console_()) console_().onFix(json);
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
