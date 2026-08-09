/* ============================================================
   SENTINEL — Lluvia "matrix" de fondo (estética hacker).
   Caracteres verdes cayendo, sutil, detrás del orbe. Se intensifica
   en rojo cuando hay amenaza (body.threat).
   ============================================================ */
"use strict";

(function () {
  const canvas = document.getElementById("matrix");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const GLYPHS = "アイウエオカキクケコサシスセソ0123456789ABCDEF<>/\\$#@*+=ﾊﾐﾋｰｳ".split("");
  let cols = 0, drops = [], fontSize = 14;

  function resize() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    cols = Math.floor(canvas.width / fontSize);
    drops = new Array(cols).fill(0).map(() => Math.random() * -50);
  }

  function draw() {
    // estela: cubrir con negro semitransparente (deja rastro)
    ctx.fillStyle = "rgba(3, 8, 6, 0.10)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const threat = document.body.classList.contains("threat");
    const head = threat ? "#ff5a78" : "#7dffce";   // cabeza de la columna
    const tail = threat ? "rgba(255,51,85,0.5)" : "rgba(47,230,168,0.45)";
    ctx.font = fontSize + "px 'JetBrains Mono', monospace";

    for (let i = 0; i < drops.length; i++) {
      const ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
      const x = i * fontSize;
      const y = drops[i] * fontSize;
      // cabeza brillante
      ctx.fillStyle = head;
      ctx.fillText(ch, x, y);
      // un caracter de estela más tenue
      ctx.fillStyle = tail;
      ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0], x, y - fontSize);

      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
    requestAnimationFrame(draw);
  }

  window.addEventListener("resize", resize);
  resize();
  draw();
})();
