/* ============================================================
   J.A.R.V.I.S — shell logic (faithful recreation).
   Drives the central neural Orb + caption + response line +
   bottom command bar. Works standalone (preview) and in Qt.
   ============================================================ */
"use strict";

const $ = (s) => document.querySelector(s);

/* ---------- Themes ---------- */
const THEMES = {
  cyan:   { PRI:"#19d4ff", PRI_DIM:"#0a5f77", TEXT:"#bdeaff", BG:"#060a10" },
  gold:   { PRI:"#f59e0b", PRI_DIM:"#78350f", TEXT:"#fde68a", BG:"#0f0a02" },
  green:  { PRI:"#00ff88", PRI_DIM:"#006633", TEXT:"#7affcc", BG:"#040e08" },
  purple: { PRI:"#a855f7", PRI_DIM:"#5b21b6", TEXT:"#c084fc", BG:"#07030f" },
  red:    { PRI:"#ff3b30", PRI_DIM:"#7a1a15", TEXT:"#ffaaaa", BG:"#0e0404" },
  white:  { PRI:"#e2e8f0", PRI_DIM:"#64748b", TEXT:"#cbd5e1", BG:"#050a14" },
};
const THEME_ORDER = ["cyan", "gold", "green", "purple", "red", "white"];
let themeIdx = 0;

function hexA(hex, a) {
  hex = hex.replace("#", "");
  if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
  const n = parseInt(hex, 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}
function applyThemeColors(c) {
  const r = document.documentElement.style;
  r.setProperty("--pri", c.PRI); r.setProperty("--pri-dim", c.PRI_DIM);
  r.setProperty("--text", c.TEXT); r.setProperty("--bg", c.BG);
  r.setProperty("--glow", hexA(c.PRI, 0.30)); r.setProperty("--hair", hexA(c.PRI, 0.18));
  if (window.Orb) window.Orb.setTheme(c);
}
function cycleTheme() { themeIdx = (themeIdx + 1) % THEME_ORDER.length; applyThemeColors(THEMES[THEME_ORDER[themeIdx]]); }

/* ---------- State ---------- */
const CAPTION = { LISTENING:"VIGILANDO", THINKING:"ANALIZANDO", SPEAKING:"INFORMANDO", MUTED:"EN PAUSA" };
let muted = false;
function setState(state) {
  if (window.Orb) window.Orb.setState(state);
  document.body.classList.toggle("speaking", state === "SPEAKING");
  const cap = $("#orbCaption"); cap.dataset.state = state;
  $("#capTxt").textContent = CAPTION[state] || state;
  const miniTxt = $("#miniCapTxt"); if (miniTxt) miniTxt.textContent = CAPTION[state] || state;
  muted = (state === "MUTED");
  const mic = $("#micToggle");
  mic.classList.toggle("muted", muted); mic.classList.toggle("listening", !muted);
  mic.setAttribute("aria-pressed", String(muted));
  if (window.setIcon) window.setIcon($("#micIcon"), muted ? "mic_off" : "mic");
}

/* ---------- Response / subtitle line ---------- */
function setResponse(t) { $("#response").textContent = t; }
function clearResponse() { $("#response").textContent = ""; }
function streamChunk(chunk) { const r = $("#response"); r.textContent = (r.textContent + chunk).slice(-260); }

function setConnection(online, label) {
  // reflected on the mini caption colour only (no explicit status pill in this layout)
  if (label) setResponse(label);
}

/* ---------- Chat panel (modo teclado, estilo Claude Code) ---------- */
let chatBotEl = null;           // current streaming assistant bubble
function chatIsOpen() { const p = $("#chatPanel"); return p && !p.hasAttribute("hidden"); }
function chatOpen() {
  const p = $("#chatPanel"); if (!p) return;
  p.removeAttribute("hidden");
  document.body.classList.add("chat-on");
  document.body.classList.add("controls-on");   // revela barra + funciones
  const inp = $("#textInput");
  if (inp) { inp.placeholder = "Escribí tu mensaje…"; setTimeout(() => inp.focus(), 60); }
}
function chatClose() {
  const p = $("#chatPanel"); if (!p) return;
  p.setAttribute("hidden", "");
  document.body.classList.remove("chat-on");
  document.body.classList.remove("controls-on");  // oculta barra + funciones → solo la bola
  const inp = $("#textInput"); if (inp) inp.placeholder = "Pregúntale a SENTINEL…";
}
function chatToggle() { chatIsOpen() ? chatClose() : chatOpen(); }
function _chatClearEmpty() { const e = $("#chatEmpty"); if (e) e.remove(); }
function _chatScroll() { const l = $("#chatLog"); if (l) l.scrollTop = l.scrollHeight; }
function chatAddUser(text) {
  const log = $("#chatLog"); if (!log) return;
  _chatClearEmpty();
  const d = document.createElement("div"); d.className = "msg user";
  d.innerHTML = '<span class="who">TÚ</span>'; d.appendChild(document.createTextNode(text));
  log.appendChild(d); _chatScroll();
  chatBotEl = null; // next assistant chunk starts a fresh bubble
}
function chatStartBot() {
  if (!chatIsOpen()) { chatBotEl = null; return; }
  const log = $("#chatLog"); if (!log) return;
  _chatClearEmpty();
  chatBotEl = document.createElement("div"); chatBotEl.className = "msg bot";
  chatBotEl.innerHTML = '<span class="who">SENTINEL</span><span class="body"></span>';
  log.appendChild(chatBotEl); _chatScroll();
}
function chatUpdateBot(text) {
  if (!chatIsOpen()) return;
  if (!chatBotEl) chatStartBot();
  const body = chatBotEl.querySelector(".body"); if (body) body.textContent = text;
  _chatScroll();
}

/* ---------- Bridge (Qt) ---------- */
let pyBridge = null;
function setupBridge() {
  if (typeof QWebChannel === "undefined" || !window.qt || !window.qt.webChannelTransport) return;
  new QWebChannel(qt.webChannelTransport, (ch) => {
    pyBridge = ch.objects.pyBridge;
    if (pyBridge.request_theme) pyBridge.request_theme();
    // SENTINEL: conectar señales de seguridad al panel en vivo
    if (pyBridge.scan_result && window.SentinelPanel) {
      pyBridge.scan_result.connect((json) => window.SentinelPanel.onScan(json));
      if (pyBridge.fix_result) pyBridge.fix_result.connect((j) => window.SentinelPanel.onFix(j));
      if (pyBridge.analysis_result) pyBridge.analysis_result.connect((j) => window.SentinelPanel.onAnalysis(j));
      window.SentinelPanel.setBridge(pyBridge);
      if (window.SentinelAnalysis) window.SentinelAnalysis.setBridge(pyBridge);
    }
  });
}

/* ---------- Actions ---------- */
// ¿El texto parece un objetivo a analizar? (URL, hash o ruta de archivo)
function looksLikeTarget(t) {
  const s = t.trim();
  if (/^(https?:\/\/|www\.)/i.test(s)) return true;
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(s)) return true;
  if (/^[a-zA-Z]:\\/.test(s) || /^\//.test(s)) return true;     // ruta windows/unix
  if (/^[\w-]+\.[\w.-]+\/\S*/.test(s)) return true;             // dominio/ruta
  return false;
}

function sendText(t) {
  if (!t.trim()) return;
  // Seguridad: si parece archivo/URL/hash, lo analizamos en vez de chatear.
  if (looksLikeTarget(t) && pyBridge && pyBridge.analyze_path) {
    setResponse("🔍 Analizando " + t + "…");
    pyBridge.analyze_path(t.trim());
    return;
  }
  setResponse("› " + t);
  if (chatIsOpen()) chatAddUser(t);
  if (pyBridge && pyBridge.on_text_command) pyBridge.on_text_command(t); else mockReply();
}
function toggleMute() { if (pyBridge && pyBridge.toggle_mute) pyBridge.toggle_mute(); setState(!muted ? "MUTED" : "LISTENING"); }
function doStop() { if (pyBridge && pyBridge.stop) pyBridge.stop(); else setState("LISTENING"); }
function doFullscreen() {
  if (pyBridge && pyBridge.toggle_fullscreen) return pyBridge.toggle_fullscreen();
  if (!document.fullscreenElement) document.documentElement.requestFullscreen?.(); else document.exitFullscreen?.();
}
function showCamera() { $("#campreview").removeAttribute("hidden"); }
function hideCamera() { $("#campreview").setAttribute("hidden", ""); $("#camImg").removeAttribute("src"); }
function setCamFrame(dataUrl) { $("#camImg").src = dataUrl; showCamera(); }

async function openCamera() {
  // In the app, Python (cv2) drives the stream and pushes frames via setCamFrame.
  if (pyBridge && pyBridge.open_camera) { pyBridge.open_camera(); showCamera(); return; }
  // Browser-preview fallback: getUserMedia into the <video>.
  try {
    const v = $("#camVideo"); $("#camImg").style.display = "none"; v.hidden = false;
    v.srcObject = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
    showCamera();
  } catch (e) { setResponse("No se pudo abrir la cámara: " + (e && e.message ? e.message : e)); }
}
function closeCamera() {
  if (pyBridge && pyBridge.close_camera) pyBridge.close_camera();
  const v = $("#camVideo"); if (v.srcObject) { v.srcObject.getTracks().forEach((t) => t.stop()); v.srcObject = null; }
  hideCamera();
}
function toggleCamera() {
  if ($("#campreview").hasAttribute("hidden")) openCamera(); else closeCamera();
}

/* ---------- Hooks called by Python ---------- */
window.updateState = setState;
window.updateVolume = (v) => { if (window.Orb) window.Orb.setVolume(Math.max(0, Math.min(1, v))); };
window.setThemeColors = (c) => applyThemeColors({ PRI:c.PRI, PRI_DIM:c.PRI_DIM, TEXT:c.TEXT, BG:c.BG });
window.clearResponse = clearResponse;
window.streamChunk = streamChunk;
window.setResponse = setResponse;
window.writeLog = setResponse;
window.setConnection = setConnection;
window.openCamera = openCamera;
window.closeCamera = closeCamera;
window.showCamera = showCamera;
window.hideCamera = hideCamera;
window.setCamFrame = setCamFrame;
window.chatOpen = chatOpen;
window.chatClose = chatClose;
window.chatToggle = chatToggle;
window.chatStartBot = chatStartBot;
window.chatUpdateBot = chatUpdateBot;

/* ---------- Panel de subida de archivo ---------- */
function uploadOpen() { const p = $("#uploadPanel"); if (p) p.removeAttribute("hidden"); }
function uploadClose() { const p = $("#uploadPanel"); if (p) p.setAttribute("hidden", ""); }
window.uploadOpen = uploadOpen;
window.uploadClose = uploadClose;
window.uploadToggle = () => { const p = $("#uploadPanel"); if (p) (p.hasAttribute("hidden") ? uploadOpen() : uploadClose()); };

/* ---------- Mini neural indicator ---------- */
function initMiniOrb() {
  const canvas = $("#mini-canvas"); if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height, cx = W / 2, cy = H / 2, R = 38, N = 26;
  const pts = Array.from({ length: N }, () => ({ theta: Math.random() * Math.PI * 2, phi: Math.acos(Math.random() * 2 - 1) }));
  let ry = 0;
  function frame() {
    ctx.clearRect(0, 0, W, H);
    const pri = getComputedStyle(document.documentElement).getPropertyValue("--pri").trim() || "#19d4ff";
    ry += muted ? 0.004 : 0.02;
    const proj = pts.map((p) => {
      const x = R * Math.sin(p.phi) * Math.cos(p.theta), y = R * Math.sin(p.phi) * Math.sin(p.theta), z = R * Math.cos(p.phi);
      return { x: x * Math.cos(ry) - z * Math.sin(ry), y, z: x * Math.sin(ry) + z * Math.cos(ry) };
    });
    proj.forEach((a, i) => proj.forEach((b, j) => { if (j <= i) return;
      const d = Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z);
      if (d < 34) { ctx.beginPath(); ctx.moveTo(cx + a.x, cy + a.y); ctx.lineTo(cx + b.x, cy + b.y);
        ctx.strokeStyle = pri; ctx.globalAlpha = (1 - d / 34) * 0.4; ctx.lineWidth = 0.6; ctx.stroke(); } }));
    proj.forEach((a) => { const s = (a.z + R) / (2 * R) * 0.7 + 0.3; ctx.beginPath(); ctx.arc(cx + a.x, cy + a.y, 1.4 * s, 0, Math.PI * 2);
      ctx.fillStyle = pri; ctx.globalAlpha = s; ctx.fill(); });
    ctx.globalAlpha = 1; requestAnimationFrame(frame);
  }
  frame();
}

/* ---------- Clock ---------- */
function tickClock() {
  const n = new Date();
  $("#clockTime").textContent = n.toLocaleTimeString("es-PE", { hour12: false });
  $("#clockDate").textContent = n.toLocaleDateString("es-ES", { weekday: "short", day: "2-digit", month: "short", year: "numeric" });
}
function mockReply() {
  setState("THINKING");
  setTimeout(() => { setState("SPEAKING");
    const r = "Vista previa de la interfaz. Al cablear el WebChannel responderé con voz y acciones reales.";
    let i = 0; clearResponse(); const id = setInterval(() => { streamChunk(r[i] || ""); if (++i >= r.length) { clearInterval(id); setState("LISTENING"); } }, 14);
  }, 800);
}

/* ---------- Wire ---------- */
function wire() {
  $("#btnTheme").addEventListener("click", cycleTheme);
  $("#btnMin").addEventListener("click", () => pyBridge?.minimize?.());
  $("#btnMax").addEventListener("click", () => pyBridge?.toggle_max?.());
  $("#btnClose").addEventListener("click", () => pyBridge?.close_win?.());
  $("#btnSettings").addEventListener("click", () => pyBridge?.open_settings?.());
  $("#btnTerminal").addEventListener("click", () => pyBridge?.open_terminal?.());
  $("#btnFolder").addEventListener("click", () => pyBridge?.open_folder?.());
  $("#btnWhatsapp").addEventListener("click", () => pyBridge?.open_whatsapp?.());

  $("#micToggle").addEventListener("click", toggleMute);
  $("#camBtn").addEventListener("click", toggleCamera);
  $("#camClose").addEventListener("click", closeCamera);
  $("#chatClose")?.addEventListener("click", chatClose);
  $("#uploadCloseBtn")?.addEventListener("click", uploadClose);
  $("#uploadBtn")?.addEventListener("click", () => { pyBridge?.open_file?.(); uploadClose(); });
  const up = $("#uploadPanel");
  if (up) {
    ["dragover", "dragenter"].forEach((ev) => up.addEventListener(ev, (e) => { e.preventDefault(); up.classList.add("drag"); }));
    ["dragleave", "drop"].forEach((ev) => up.addEventListener(ev, () => up.classList.remove("drag")));
    up.addEventListener("drop", (e) => { e.preventDefault(); const f = e.dataTransfer?.files?.[0];
      if (f) { setResponse("Archivo: " + f.name); pyBridge?.drop_file?.(f.name); uploadClose(); } });
  }
  $("#stopBtn").addEventListener("click", doStop);
  $("#fsBtn").addEventListener("click", doFullscreen);
  $("#exitBtn").addEventListener("click", () => pyBridge?.close_win?.());

  const input = $("#textInput");
  $("#sendBtn").addEventListener("click", () => { sendText(input.value); input.value = ""; });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { sendText(input.value); input.value = ""; } });

  // Frameless window dragging: ONLY the top ~54px strip acts as a title bar,
  // so clicking the orb / empty space never accidentally moves the window.
  document.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    if (e.clientY > 54) return;
    if (e.target.closest("button, input, a")) return;
    if (pyBridge && pyBridge.start_move) pyBridge.start_move();
  });

  const dz = $("#dropzone");
  dz.addEventListener("click", () => pyBridge?.open_file?.());
  ["dragover", "dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove("drag")));
  dz.addEventListener("drop", (e) => { e.preventDefault(); const f = e.dataTransfer?.files?.[0];
    if (f) { setResponse("Archivo: " + f.name); pyBridge?.drop_file?.(f.name); } });
}

/* ---------- Boot ---------- */
window.addEventListener("DOMContentLoaded", () => {
  if (window.Orb) window.Orb.init();
  initMiniOrb();
  applyThemeColors(THEMES[THEME_ORDER[themeIdx]]);
  wire();
  setupBridge();
  setState("LISTENING");
  tickClock(); setInterval(tickClock, 1000);
  if (!pyBridge) setResponse("SENTINEL en línea. Sistema protegido.");
});
