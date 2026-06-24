/* ============================================================
   Inline SVG icon set (Feather-style, stroke=currentColor).
   No external font/CDN — always renders, works offline / in PWA.
   Use:  <span class="ico" data-icon="mic"></span>
   ============================================================ */
"use strict";
(function () {
  const S = (inner, opts = "") =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ` +
    `stroke-linecap="round" stroke-linejoin="round" ${opts}>${inner}</svg>`;

  const ICONS = {
    settings: S('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>'),
    terminal: S('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>'),
    folder: S('<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'),
    palette: S('<circle cx="13.5" cy="6.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="17.5" cy="10.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="8.5" cy="7.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="6.5" cy="12.5" r="1.2" fill="currentColor" stroke="none"/><path d="M12 2C6.5 2 2 6 2 11c0 4 3 7 7 7 1 0 1.5-.8 1.5-1.5 0-.4-.2-.7-.4-1-.2-.3-.4-.6-.4-1 0-.8.7-1.5 1.5-1.5H13c3.3 0 6-2.2 6-5.5C19 4.6 15.9 2 12 2z"/>'),
    minimize: S('<line x1="5" y1="12" x2="19" y2="12"/>'),
    maximize: S('<rect x="5" y="5" width="14" height="14" rx="2"/>'),
    close: S('<line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/>'),
    mic: S('<path d="M12 2a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"/><path d="M19 11a7 7 0 0 1-14 0"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="8" y1="22" x2="16" y2="22"/>'),
    mic_off: S('<line x1="2" y1="2" x2="22" y2="22"/><path d="M9 9v2a3 3 0 0 0 5.1 2.1"/><path d="M15 10.3V5a3 3 0 0 0-5.9-.8"/><path d="M19 11a7 7 0 0 1-10.8 5.9M5 11a7 7 0 0 0 .3 2"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="8" y1="22" x2="16" y2="22"/>'),
    camera: S('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h3l2-3h8l2 3h3a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="3.5"/>'),
    stop: S('<rect x="6" y="6" width="12" height="12" rx="2.5" fill="currentColor" stroke="none"/>'),
    fullscreen: S('<path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/>'),
    send: S('<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>'),
    logout: S('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>'),
    attach: S('<path d="M21.4 11.05 12.25 20.2a5 5 0 0 1-7.07-7.07l9.19-9.19a3 3 0 0 1 4.24 4.24l-9.2 9.19a1 1 0 0 1-1.41-1.41l8.48-8.49"/>'),
    whatsapp: S('<path d="M21 11.5a8.5 8.5 0 0 1-12.6 7.43L3 21l2.13-5.3A8.5 8.5 0 1 1 21 11.5z"/><path d="M8.5 8.5c0 4 3 7 6.5 7 .5 0 1-.4 1-1l-.2-1.3-2 .6c-1.4-.6-2.4-1.6-3-3l.6-2-1.3-.2c-.6 0-1.1.5-1.1 1z" fill="currentColor" stroke="none"/>'),
  };

  window.AMSY_ICONS = ICONS;
  window.setIcon = function (el, name) {
    if (el && ICONS[name]) { el.innerHTML = ICONS[name]; el.dataset.icon = name; }
  };
  window.renderIcons = function (root) {
    (root || document).querySelectorAll(".ico[data-icon]").forEach((el) => {
      const n = el.dataset.icon; if (ICONS[n]) el.innerHTML = ICONS[n];
    });
  };
  document.addEventListener("DOMContentLoaded", () => window.renderIcons());
})();
