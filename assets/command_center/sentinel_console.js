/* ============================================================
   SENTINEL — Consola de seguridad.

   Recibe el mismo reporte que el panel lateral y lo convierte en una
   superficie de trabajo: puntaje con anillo, rejilla de los 16 controles
   de blindaje, matriz MITRE ATT&CK por tactica y tabla de hallazgos con
   evidencia desplegable y filtros por severidad.

   Expone window.SentinelConsole { setBridge, render, toggle, onFix, onReport }.
   ============================================================ */
"use strict";

(function () {
  const SEV = ["CRITICA", "ALTA", "MEDIA", "BAJA", "INFO"];
  const SEV_VAR = {
    CRITICA: "var(--sc-crit)", ALTA: "var(--sc-alta)", MEDIA: "var(--sc-media)",
    BAJA: "var(--sc-baja)", INFO: "var(--sc-info)",
  };
  const ST_TXT = { ok: "Correcto", warn: "Advertencia", fail: "Falla", unknown: "Sin evaluar" };
  const ST_CLS = { ok: "c-ok", warn: "c-media", fail: "c-alta", unknown: "c-info" };
  // Orden de la cadena de ataque: la matriz se lee como avanzaria una intrusion.
  const TACTICS = ["Acceso inicial", "Ejecucion", "Persistencia",
    "Escalada de privilegios", "Evasion de defensas", "Acceso a credenciales",
    "Movimiento lateral", "Mando y control"];

  let bridge = null;
  let last = null;
  let filter = "TODO";
  const open = new Set();          // hallazgos desplegados, se conservan al re-render
  let toastTimer = null;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  /* ---------- Veredicto ---------- */
  function verdict(score, sev) {
    if (sev.CRITICA) return ["c-crit", "Compromiso probable",
      "Hay indicios directos de compromiso. Atiende esto antes de seguir usando el equipo."];
    if (score === null) return ["c-info", "Auditando…",
      "Recogiendo el estado de las defensas del sistema."];
    if (score >= 90 && !sev.ALTA) return ["c-ok", "Equipo endurecido",
      "La configuracion es solida y no quedan exposiciones de alto riesgo."];
    if (score >= 70) return ["c-media", "Proteccion parcial",
      "Las defensas basicas estan activas, pero quedan controles sin aplicar."];
    if (score >= 40) return ["c-alta", "Exposicion elevada",
      "Varias defensas clave estan desactivadas. El equipo es vulnerable a ataques conocidos."];
    return ["c-crit", "Exposicion critica",
      "La mayoria de las defensas estan ausentes. No conviene usarlo en red asi."];
  }

  function scoreColor(s) {
    if (s === null) return "var(--sc-info)";
    if (s >= 80) return "var(--sc-ok)";
    if (s >= 50) return "var(--sc-media)";
    return "var(--sc-crit)";
  }

  /* ---------- Anillo del puntaje ---------- */
  function ring(score) {
    const R = 62, C = 2 * Math.PI * R;
    const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100;
    const col = scoreColor(score);
    return `
      <div class="sc-ring">
        <svg width="150" height="150" viewBox="0 0 150 150" aria-hidden="true">
          <circle cx="75" cy="75" r="${R}" fill="none"
                  stroke="var(--sc-line)" stroke-width="9"/>
          <circle cx="75" cy="75" r="${R}" fill="none" stroke="${col}"
                  stroke-width="9" stroke-linecap="round"
                  stroke-dasharray="${(C * pct).toFixed(1)} ${C.toFixed(1)}"/>
        </svg>
        <div class="val">
          <b style="color:${col}">${score === null ? "—" : score}</b>
          <span>Blindaje / 100</span>
        </div>
      </div>`;
  }

  /* ---------- Indicadores ---------- */
  function kpis(rep, findings) {
    const score = typeof rep.hardening_score === "number" ? rep.hardening_score : null;
    const sev = {};
    for (const f of findings) sev[f.severity_label] = (sev[f.severity_label] || 0) + 1;
    const [vc, vt, vd] = verdict(score, sev);
    const total = findings.length || 1;

    const bars = SEV.filter((k) => sev[k])
      .map((k) => `<i style="flex:${sev[k]};background:${SEV_VAR[k]}"></i>`).join("");
    const legend = SEV.filter((k) => sev[k])
      .map((k) => `<span class="${"c-" + k.toLowerCase()}">${k[0] + k.slice(1).toLowerCase()} <b>${sev[k]}</b></span>`)
      .join("");

    const checks = rep.hardening || [];
    const malos = checks.filter((c) => c.status === "fail" || c.status === "warn").length;
    const cov = rep.attack_coverage || {};

    return `
      <div class="sc-card gauge">${ring(score)}</div>
      <div class="sc-card sc-verdict">
        <h3 class="${vc}">${esc(vt)}</h3>
        <p>${esc(vd)}</p>
        <div class="sc-bars">${bars || '<i style="flex:1;background:var(--sc-line)"></i>'}</div>
        <div class="sc-legend">${legend || '<span>Sin hallazgos</span>'}</div>
      </div>
      <div class="sc-card">
        <div class="sc-stats">
          <div class="sc-stat"><b>${findings.length}</b><span>Hallazgos</span></div>
          <div class="sc-stat"><b class="${malos ? "c-alta" : "c-ok"}">${malos}</b>
            <span>Controles a corregir</span></div>
          <div class="sc-stat"><b>${cov.total_tecnicas || 0}</b><span>Tecnicas ATT&amp;CK</span></div>
          <div class="sc-stat"><b>${checks.length}</b><span>Controles auditados</span></div>
        </div>
      </div>`;
  }

  /* ---------- Rejilla de controles ---------- */
  function controls(checks) {
    if (!checks.length) {
      return '<div class="sc-empty">Auditando el blindaje del sistema…</div>';
    }
    const rank = { fail: 0, warn: 1, unknown: 2, ok: 3 };
    return [...checks]
      .sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9))
      .map((c) => {
        const ai = c.attack_info || {};
        const fixable = c.fix_command && (c.status === "fail" || c.status === "warn");
        return `
        <div class="sc-ctl ${esc(c.status)}">
          <div class="t">${esc(c.title)}</div>
          <div class="d">${esc(c.detail)}</div>
          <div class="r">
            <span class="sc-tag ${ST_CLS[c.status] || "c-info"}">${ST_TXT[c.status] || c.status}</span>
            ${fixable ? `<button class="sc-fix" data-fix="${esc(c.key)}">Blindar</button>` : ""}
            <span class="att">${esc(ai.id || "")}</span>
          </div>
        </div>`;
      }).join("");
  }

  /* ---------- Matriz ATT&CK ---------- */
  function matrix(cov) {
    const tecs = (cov && cov.tecnicas) || [];
    if (!tecs.length) {
      return '<div class="sc-empty">No se evidenciaron tecnicas catalogadas.</div>';
    }
    const byTac = {};
    for (const t of tecs) (byTac[t.tactic || "Sin clasificar"] ||= []).push(t);
    return Object.keys(byTac)
      .sort((a, b) => {
        const ia = TACTICS.indexOf(a), ib = TACTICS.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      })
      .map((tac) => `
        <div class="sc-tac">
          <h4>${esc(tac)}</h4>
          ${byTac[tac].map((t) => `
            <div class="sc-tec">
              <b>${esc(t.id)}</b><i>${t.hallazgos}</i>
              <span>${esc(t.name)}</span>
            </div>`).join("")}
        </div>`).join("");
  }

  /* ---------- Hallazgos ---------- */
  function findingKey(f) {
    return (f.category || "") + "|" + (f.title || "");
  }

  function findings(list) {
    const shown = filter === "TODO" ? list : list.filter((f) => f.severity_label === filter);
    if (!shown.length) {
      return `<div class="sc-empty">Sin hallazgos${filter === "TODO" ? "" : " de severidad " + filter.toLowerCase()}.</div>`;
    }
    return shown.slice(0, 200).map((f) => {
      const k = findingKey(f);
      const isOpen = open.has(k);
      const ai = f.attack_info || {};
      const ev = Object.entries(f.evidence || {})
        .filter(([kk, v]) => !["fix_command", "cis", "reboot"].includes(kk) &&
                             v !== null && v !== "" &&
                             !(Array.isArray(v) && !v.length))
        .map(([kk, v]) => `<b>${esc(kk)}:</b> ${esc(Array.isArray(v) ? v.join(", ") : v)}`)
        .join("<br>");
      return `
        <div class="sc-find ${esc(f.severity_label)}">
          <button class="sc-fhead" data-k="${esc(k)}" aria-expanded="${isOpen}">
            <span class="sc-tag c-${(f.severity_label || "info").toLowerCase()}">${esc(f.severity_label)}</span>
            <span class="sc-fcat">${esc(f.category)}</span>
            <span class="sc-ftitle">${esc(f.title)}</span>
            <span class="sc-fatt">${esc(ai.id || "")}</span>
          </button>
          ${isOpen ? `<div class="sc-fbody">
            <p>${esc(f.detail)}</p>
            ${ai.id ? `<p><b>${esc(ai.id)}</b> — ${esc(ai.name)} · Tactica: ${esc(ai.tactic)}</p>` : ""}
            ${ev ? `<div class="sc-ev">${ev}</div>` : ""}
          </div>` : ""}
        </div>`;
    }).join("");
  }

  function filters(list) {
    const counts = { TODO: list.length };
    for (const f of list) counts[f.severity_label] = (counts[f.severity_label] || 0) + 1;
    return ["TODO", ...SEV].filter((k) => k === "TODO" || counts[k])
      .map((k) => `<button class="sc-chip" data-f="${k}" aria-pressed="${filter === k}">
        ${k === "TODO" ? "Todos" : k} ${counts[k] || 0}</button>`).join("");
  }

  /* ---------- Render ---------- */
  function render(rep) {
    last = rep;
    const root = $("scRoot");
    if (!root || !rep) return;

    // Los riesgos ya mitigados por firewall no son hallazgos pendientes.
    const list = (rep.findings || []).filter((f) => !(f.evidence && f.evidence.blocked));
    const checks = rep.hardening || [];
    const threat = ["ALTA", "CRITICA"].includes(rep.max_severity);
    root.classList.toggle("threat", threat);

    $("scKpi").innerHTML = kpis(rep, list);
    $("scControls").innerHTML = controls(checks);
    $("scMatrix").innerHTML = matrix(rep.attack_coverage);
    $("scFilters").innerHTML = filters(list);
    $("scFindings").innerHTML = findings(list);

    const malos = checks.filter((c) => c.status === "fail" || c.status === "warn").length;
    $("scCtlCount").textContent = checks.length
      ? `${malos} de ${checks.length} requieren accion` : "";
    $("scFindCount").textContent = `${list.length} en total`;
    const cov = rep.attack_coverage || {};
    $("scMatCount").textContent = `${cov.total_tecnicas || 0} tecnicas evidenciadas`;
    $("scClock").textContent = new Date().toLocaleTimeString("es-PE", { hour12: false });
  }

  function toast(msg) {
    const t = $("scToast");
    if (!t) return;
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 6000);
  }

  /* ---------- Terminal: helpers de salida ---------- */
  let termBusy = false;
  function termScroll() {
    const out = $("scTermOut");
    if (out) out.scrollTop = out.scrollHeight;
  }
  function termLine(text, cls) {
    const out = $("scTermOut");
    if (!out) return;
    const div = document.createElement("div");
    if (cls) div.className = cls;
    div.textContent = text;
    out.appendChild(div);
    termScroll();
  }
  function termEcho(cmd) {
    const w = document.querySelector(".sc-term-welcome");
    if (w) w.remove();
    termLine(cmd, "sc-term-cmdline");
  }
  function termRunning() {
    termBusy = true;
    const out = $("scTermOut");
    const div = document.createElement("div");
    div.className = "sc-term-run-msg";
    div.id = "scTermRun";
    div.textContent = "ejecutando…";
    out.appendChild(div);
    termScroll();
  }
  function onCommandResult(json) {
    termBusy = false;
    const run = $("scTermRun");
    if (run) run.remove();
    let r = {};
    try { r = JSON.parse(json); } catch (_) { }
    if (r.stdout) termLine(r.stdout.replace(/\s+$/, ""), "sc-term-body");
    if (r.stderr) termLine(r.stderr.replace(/\s+$/, ""), "sc-term-err");
    if (!r.stdout && !r.stderr) termLine("(sin salida)", "sc-term-exit");
    const bad = r.exit_code !== 0;
    termLine("exit " + r.exit_code, "sc-term-exit" + (bad ? " bad" : ""));
  }

  /* ---------- Eventos ---------- */
  function wire() {
    const root = $("scRoot");
    if (!root) return;

    root.addEventListener("click", (e) => {
      const fix = e.target.closest("[data-fix]");
      if (fix) {
        if (bridge && bridge.apply_fix) {
          fix.disabled = true;
          fix.textContent = "Aplicando…";
          bridge.apply_fix(fix.dataset.fix);
          toast("Pidiendo permiso de administrador para aplicar el blindaje…");
        }
        return;
      }
      const chip = e.target.closest("[data-f]");
      if (chip) { filter = chip.dataset.f; if (last) render(last); return; }

      const head = e.target.closest(".sc-fhead");
      if (head) {
        const k = head.dataset.k;
        if (open.has(k)) open.delete(k); else open.add(k);
        if (last) render(last);
        return;
      }
    });

    $("scScan").addEventListener("click", () => {
      if (bridge && bridge.request_scan) {
        bridge.request_scan();
        toast("Re-escaneando el equipo…");
      }
    });

    const informe = (pdf) => {
      if (!bridge || !bridge.generate_report) return;
      const label = ($("scLabel").value || "EQUIPO").trim();
      bridge.generate_report(label, !!pdf);
      toast(pdf ? "Generando informe en PDF…" : "Generando informe…");
    };
    $("scReport").addEventListener("click", () => informe(false));
    $("scReportPdf").addEventListener("click", () => informe(true));
    $("scToggle").addEventListener("click", () => api.toggle(false));

    // --- Terminal ---
    const term = $("scTerm");
    $("scTermBtn").addEventListener("click", () => {
      term.hidden = !term.hidden;
      if (!term.hidden) $("scTermCmd").focus();
    });
    $("scTermClose").addEventListener("click", () => { term.hidden = true; });
    $("scTermForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const input = $("scTermCmd");
      const cmd = input.value.trim();
      if (!cmd) return;
      termEcho(cmd);
      input.value = "";
      if (bridge && bridge.run_command) {
        termRunning();
        bridge.run_command(cmd);
      } else {
        termLine("(sin conexion con el motor)", "sc-term-err");
      }
    });

    // El boton que abre la consola vive fuera de #scRoot (en el panel lateral).
    const abrir = $("scOpen");
    if (abrir) abrir.addEventListener("click", () => api.toggle(true));

    // Escape cierra la consola y devuelve la vista del orbe.
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("scRoot").hidden) api.toggle(false);
    });
  }

  const api = {
    setBridge(b) { bridge = b; },
    render,
    onCommandResult,
    onFix(json) {
      let r = {};
      try { r = JSON.parse(json); } catch (_) { }
      toast(r.msg || (r.ok ? "Blindaje aplicado." : "No se pudo aplicar el blindaje."));
      if (last) render(last);
    },
    onReport(json) {
      let r = {};
      try { r = JSON.parse(json); } catch (_) { }
      toast(r.msg || "Informe generado.");
    },
    toggle(force) {
      const root = $("scRoot");
      if (!root) return;
      const show = (force === undefined) ? root.hidden : force;
      root.hidden = !show;
      const btn = document.getElementById("scOpen");
      if (btn) btn.setAttribute("aria-pressed", String(show));
      if (show) {
        // Cierra los overlays heredados del Command Center para que no tapen
        // la consola ni capturen el teclado de la terminal.
        ["chatPanel", "uploadPanel", "analysisCard"].forEach((id) => {
          const el = document.getElementById(id);
          if (el) el.setAttribute("hidden", "");
        });
        if (last) render(last);
      }
    },
  };

  window.SentinelConsole = api;
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
