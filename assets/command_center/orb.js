/* ============================================================
   AMSY Holographic Neural Core — multi-layer reactor orb.
   Layers (back → front):
     1. ambient core glow
     2. inner 3D neural sphere (90 nodes + synapses)  [from sphere.html]
     3. gyroscopic 3D rings (tilted ellipses, counter-rotating)
     4. holographic IRIS that opens/closes (segmented aperture)
     5. outer HUD tick ring + rotating scanner arc
   Reacts to LISTENING / THINKING / SPEAKING / MUTED + volume.
   API: window.Orb.{init,setState,setVolume,setTheme}
   ============================================================ */
"use strict";
(function () {
  const canvas = document.getElementById("sphere-canvas");
  const ctx = canvas.getContext("2d");
  const orbWrapper = document.getElementById("orbWrapper");

  let width, height, sphereRadius = 180;
  let rotationX = 0, rotationY = 0;
  let baseIntensity = 1.0;
  let currentState = "LISTENING";
  let currentVolume = 0.0;
  let t = 0;                 // global frame time
  let aperture = 0.5;        // 0 = closed, 1 = fully open  (the "open/close" hologram)
  let ringSpin = 0, scanSpin = 0, tickSpin = 0;
  let themeColors = { PRI: "#19d4ff", PRI_DIM: "#0a5f77", TEXT: "#bdeaff", BG: "#060a10" };

  const NODE_COUNT = 90;
  const nodes = [];

  function hexToRgba(hex, a) {
    if (/^#([A-Fa-f0-9]{3}){1,2}$/.test(hex)) {
      let c = hex.substring(1).split("");
      if (c.length === 3) c = [c[0], c[0], c[1], c[1], c[2], c[2]];
      c = "0x" + c.join("");
      return `rgba(${[(c >> 16) & 255, (c >> 8) & 255, c & 255].join(",")},${a})`;
    }
    return hex;
  }

  /* ---------------- inner neural sphere ---------------- */
  class Node {
    constructor() {
      this.theta = Math.random() * Math.PI * 2;
      this.phi = Math.acos(Math.random() * 2 - 1);
      this.x = this.y = this.z = 0;
      this.size = 1.2 + Math.random() * 2.5;
      this.pulse = Math.random() * Math.PI * 2;
      this.pulseSpeed = 0.03 + Math.random() * 0.06;
      this.synapticFiring = 0;
      this.randomizeColor();
    }
    randomizeColor() {
      const r = Math.random();
      this.color = r > 0.6 ? themeColors.PRI : r > 0.2 ? themeColors.TEXT : themeColors.PRI_DIM;
    }
    update(rx, ry, radius) {
      let sp = currentState === "THINKING" ? 4.5 : currentState === "SPEAKING" ? 2.0 : currentState === "MUTED" ? 0.25 : 1;
      this.pulse += this.pulseSpeed * sp;
      if (this.synapticFiring > 0) this.synapticFiring -= 0.04;
      const x = radius * Math.sin(this.phi) * Math.cos(this.theta);
      const y = radius * Math.sin(this.phi) * Math.sin(this.theta);
      const z = radius * Math.cos(this.phi);
      const x1 = x * Math.cos(ry) - z * Math.sin(ry);
      const z1 = x * Math.sin(ry) + z * Math.cos(ry);
      const y2 = y * Math.cos(rx) - z1 * Math.sin(rx);
      const z2 = y * Math.sin(rx) + z1 * Math.cos(rx);
      this.x = x1; this.y = y2; this.z = z2;
    }
    draw(cx, cy, intensity) {
      const scale = (this.z + sphereRadius) / (sphereRadius * 2) * 0.75 + 0.25;
      const firing = this.synapticFiring * 4.0;
      const opacity = scale * (0.4 + Math.sin(this.pulse) * 0.25) * intensity;
      const sm = currentState === "SPEAKING" ? 1.0 + currentVolume * 2.0 : 1.0;
      ctx.beginPath();
      ctx.arc(cx + this.x, cy + this.y, this.size * scale * sm + firing, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.globalAlpha = Math.min(1.0, opacity + this.synapticFiring);
      ctx.fill();
      if (scale > 0.6 || this.synapticFiring > 0.1) {
        ctx.shadowBlur = (15 + firing * 10) * intensity; ctx.shadowColor = this.color; ctx.fill(); ctx.shadowBlur = 0;
      }
    }
  }

  /* ---------------- holographic ring helpers ---------------- */
  // A tilted 3D ring drawn as a squashed ellipse, optionally segmented.
  function gyroRing(cx, cy, r, tilt, squash, rot, segs, gap, lw, color, alpha) {
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(tilt);
    ctx.scale(1, squash);
    ctx.lineWidth = lw;
    ctx.strokeStyle = color;
    ctx.globalAlpha = alpha;
    ctx.shadowBlur = 8; ctx.shadowColor = color;
    if (segs <= 1) {
      ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI * 2); ctx.stroke();
    } else {
      const seg = (Math.PI * 2) / segs;
      for (let i = 0; i < segs; i++) {
        const s = rot + i * seg;
        ctx.beginPath(); ctx.arc(0, 0, r, s, s + seg * (1 - gap)); ctx.stroke();
      }
    }
    ctx.shadowBlur = 0;
    ctx.restore();
  }

  // The iris: N petals/segments arranged around the core that slide out (open)
  // and back in (close). `open` in 0..1.
  function drawIris(cx, cy, baseR, open, rot, color, intensity) {
    const PETALS = 6;
    const reach = baseR * (0.42 + open * 0.62);
    const arcLen = (Math.PI * 2 / PETALS) * (0.34 + open * 0.30);
    ctx.save();
    ctx.lineCap = "round";
    for (let i = 0; i < PETALS; i++) {
      const a = rot + i * (Math.PI * 2 / PETALS);
      ctx.beginPath();
      ctx.arc(cx, cy, reach, a - arcLen / 2, a + arcLen / 2);
      ctx.lineWidth = 2.2;
      ctx.strokeStyle = color;
      ctx.globalAlpha = (0.25 + open * 0.5) * intensity;
      ctx.shadowBlur = 10; ctx.shadowColor = color;
      ctx.stroke();
      // little end-caps (markers) at each petal
      const ex = cx + Math.cos(a) * reach, ey = cy + Math.sin(a) * reach;
      ctx.beginPath(); ctx.arc(ex, ey, 1.8, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.globalAlpha = (0.5 + open * 0.5) * intensity; ctx.fill();
    }
    ctx.shadowBlur = 0;
    ctx.restore();
  }

  // Outer HUD ring: fixed-ish ticks + a couple of long cardinal markers.
  function drawTickRing(cx, cy, r, rot, color, intensity) {
    const TICKS = 64;
    ctx.save();
    ctx.strokeStyle = color;
    for (let i = 0; i < TICKS; i++) {
      const a = rot + (i / TICKS) * Math.PI * 2;
      const long = i % 8 === 0;
      const r1 = r, r2 = r + (long ? 9 : 4);
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
      ctx.lineTo(cx + Math.cos(a) * r2, cy + Math.sin(a) * r2);
      ctx.lineWidth = long ? 1.4 : 0.7;
      ctx.globalAlpha = (long ? 0.55 : 0.28) * intensity;
      ctx.stroke();
    }
    ctx.restore();
  }

  // Rotating scanner arc that sweeps around the outer ring.
  function drawScanner(cx, cy, r, rot, color, intensity) {
    ctx.save();
    ctx.lineWidth = 2.4; ctx.lineCap = "round";
    ctx.shadowBlur = 12; ctx.shadowColor = color;
    ctx.strokeStyle = color; ctx.globalAlpha = 0.8 * intensity;
    ctx.beginPath(); ctx.arc(cx, cy, r, rot, rot + 0.6); ctx.stroke();
    ctx.globalAlpha = 0.3 * intensity;
    ctx.beginPath(); ctx.arc(cx, cy, r, rot + Math.PI, rot + Math.PI + 0.35); ctx.stroke();
    ctx.shadowBlur = 0;
    ctx.restore();
  }

  /* ---------------- sizing ---------------- */
  function resize() {
    width = canvas.width = orbWrapper.clientWidth;
    height = canvas.height = orbWrapper.clientHeight;
    // inner sphere radius; outer HUD ring extends to ~1.3x, so keep headroom
    sphereRadius = Math.min(width, height) * 0.32;
    if (sphereRadius > 175) sphereRadius = 175;
    if (sphereRadius < 95) sphereRadius = 95;
  }
  window.addEventListener("resize", resize);

  function triggerRipple() {
    const ripple = document.createElement("div");
    ripple.className = "ripple";
    ripple.style.left = "50%"; ripple.style.top = "50%"; ripple.style.transform = "translate(-50%,-50%)";
    orbWrapper.appendChild(ripple);
    setTimeout(() => ripple.remove(), 1500);
    nodes.forEach((n) => { if (Math.random() > 0.6) n.synapticFiring = 0.9; });
  }
  function createParticle() {
    const p = document.createElement("div");
    p.className = "data-particle";
    p.style.left = (width / 2 + (Math.random() - 0.5) * sphereRadius * 1.8) + "px";
    p.style.top = (height / 2 + (Math.random() - 0.5) * sphereRadius * 1.8) + "px";
    orbWrapper.appendChild(p);
    const anim = p.animate([
      { transform: "translate(0,0) scale(1)", opacity: 0 },
      { transform: `translate(${(Math.random() - 0.5) * 100}px,-80px) scale(1.4)`, opacity: 0.85, offset: 0.5 },
      { transform: `translate(${(Math.random() - 0.5) * 200}px,-180px) scale(0)`, opacity: 0 },
    ], { duration: 1200 + Math.random() * 2000, easing: "ease-out" });
    anim.onfinish = () => p.remove();
  }

  /* ---------------- main loop ---------------- */
  function animate() {
    t += 1;
    ctx.clearRect(0, 0, width, height);
    const cx = width / 2, cy = height / 2;
    const PRI = themeColors.PRI, TXT = themeColors.TEXT, DIM = themeColors.PRI_DIM;

    // canvas breathing scale
    if (currentState === "SPEAKING") canvas.style.transform = `scale(${1.0 + currentVolume * 0.22})`;
    else if (currentState === "THINKING") canvas.style.transform = `scale(${1.02 + Math.sin(t * 0.05) * 0.02})`;
    else canvas.style.transform = "scale(1)";

    // intensity + rotation per state
    let intensity = baseIntensity;
    if (currentState === "MUTED") { intensity = 0.45; rotationY += 0.0006; rotationX += 0.0002; }
    else if (currentState === "THINKING") { intensity = 1.6; rotationY += 0.018; rotationX += 0.006; }
    else if (currentState === "SPEAKING") { intensity = 1.2 + currentVolume * 0.8; rotationY += 0.006 + currentVolume * 0.03; rotationX += 0.002; }
    else { intensity = 1.0 + (Math.random() - 0.5) * 0.12; rotationY += 0.0022; rotationX += 0.0008; }

    // ring spins
    const spinBase = currentState === "THINKING" ? 0.020 : currentState === "SPEAKING" ? 0.010 + currentVolume * 0.02 : currentState === "MUTED" ? 0.001 : 0.004;
    ringSpin += spinBase; scanSpin += spinBase * 2.2; tickSpin += spinBase * 0.35;

    // aperture target (the open/close hologram)
    let apTarget;
    if (currentState === "MUTED") apTarget = 0.06;
    else if (currentState === "THINKING") apTarget = 0.92 + Math.sin(t * 0.08) * 0.08;
    else if (currentState === "SPEAKING") apTarget = 0.55 + currentVolume * 0.45;
    else apTarget = 0.42 + Math.sin(t * 0.022) * 0.18; // idle breathing iris
    aperture += (apTarget - aperture) * 0.08;

    let radius = sphereRadius;
    if (currentState === "SPEAKING") radius = sphereRadius * (1.0 + currentVolume * 0.30);
    else if (currentState === "THINKING") radius = sphereRadius * (1.0 + Math.sin(t * 0.05) * 0.04);

    const R = sphereRadius; // layout reference radius

    // 1) ambient core glow
    if (currentState !== "MUTED") {
      const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius * 0.95);
      const go = 0.22 + (currentState === "SPEAKING" ? currentVolume * 0.35 : 0.06);
      g.addColorStop(0, hexToRgba(PRI, go)); g.addColorStop(1, "transparent");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, radius * 0.95, 0, Math.PI * 2); ctx.fill();
    }

    // 2) inner neural sphere
    nodes.forEach((n) => n.update(rotationX, rotationY, radius));
    const connLimit = currentState === "MUTED" ? 1 : currentState === "THINKING" ? 5 : 3;
    let distT = currentState === "MUTED" ? 100 : currentState === "THINKING" ? 170 : 140;
    if (currentState === "SPEAKING") distT = 140 + currentVolume * 70;
    for (let i = 0; i < nodes.length; i++) {
      let c = 0;
      for (let j = i + 1; j < nodes.length; j++) {
        if (c > connLimit) break;
        const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y, dz = nodes[i].z - nodes[j].z;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        if (dist < distT) {
          c++;
          const sc = ((nodes[i].z + nodes[j].z) / 2 + radius) / (radius * 2);
          ctx.beginPath(); ctx.lineWidth = 0.5 + sc * 1.8;
          ctx.moveTo(cx + nodes[i].x, cy + nodes[i].y); ctx.lineTo(cx + nodes[j].x, cy + nodes[j].y);
          const grad = ctx.createLinearGradient(cx + nodes[i].x, cy + nodes[i].y, cx + nodes[j].x, cy + nodes[j].y);
          grad.addColorStop(0, nodes[i].color); grad.addColorStop(1, nodes[j].color);
          ctx.strokeStyle = grad; ctx.globalAlpha = (1 - dist / distT) * 0.42 * sc * intensity; ctx.stroke();
          if (Math.random() > (currentState === "THINKING" ? 0.93 : 0.992)) { ctx.lineWidth = 3.5; ctx.globalAlpha *= 2.5; ctx.stroke(); nodes[i].synapticFiring = 0.7; }
        }
      }
    }
    nodes.sort((a, b) => a.z - b.z);
    nodes.forEach((n) => n.draw(cx, cy, intensity));
    ctx.globalAlpha = 1;

    // 3) gyroscopic 3D rings — counter-rotating, tilted
    gyroRing(cx, cy, R * 1.04, ringSpin * 0.6, 0.30, 0, 1, 0, 1.1, hexToRgba(TXT, 0.5 * intensity), 0.5 * intensity);
    gyroRing(cx, cy, R * 1.12, -ringSpin * 0.8 + 1.05, 0.55, 0, 3, 0.5, 1.4, PRI, 0.55 * intensity);
    gyroRing(cx, cy, R * 1.20, ringSpin * 0.5 + 2.1, 0.22, 0, 5, 0.42, 1.0, hexToRgba(PRI, 0.45 * intensity), 0.45 * intensity);

    // 4) holographic iris (opens / closes)
    drawIris(cx, cy, R, aperture, -ringSpin * 1.3, PRI, intensity);

    // 5) outer HUD tick ring + rotating scanner
    drawTickRing(cx, cy, R * 1.30, tickSpin, hexToRgba(TXT, 0.9), intensity);
    drawScanner(cx, cy, R * 1.30, scanSpin, PRI, intensity);

    ctx.globalAlpha = 1;

    // stats (if present)
    const ss = document.getElementById("stat-sync"), sl = document.getElementById("stat-load");
    if (ss) ss.textContent = (currentState === "THINKING" ? 99.4 + Math.random() * 0.5 : 98.8 + Math.random() * 0.8).toFixed(1) + "%";
    if (sl) sl.textContent = (currentState === "THINKING" ? Math.floor(2 + Math.random() * 4) : currentState === "MUTED" ? "0" : Math.floor(6 + Math.random() * 7)) + " ms";

    if (currentState !== "MUTED") {
      const pc = currentState === "THINKING" ? 0.4 : currentState === "SPEAKING" ? 0.6 : 0.985;
      if (Math.random() > pc) createParticle();
    }
    if (currentState === "THINKING" && Math.random() > 0.93) triggerRipple();

    requestAnimationFrame(animate);
  }

  window.Orb = {
    init() { resize(); nodes.length = 0; for (let i = 0; i < NODE_COUNT; i++) nodes.push(new Node()); animate(); },
    setState(s) { currentState = s; baseIntensity = s === "MUTED" ? 0.55 : s === "SPEAKING" ? 1.2 : 1.0; },
    setVolume(v) {
      currentVolume = v;
      const halo = document.getElementById("ambient-halo");
      if (halo && currentState === "SPEAKING") {
        halo.style.transform = `translate(-50%,-50%) scale(${1.0 + v * 0.65})`;
        halo.style.background = `radial-gradient(circle, ${hexToRgba(themeColors.PRI, 0.12 + v * 0.22)} 0%, transparent 70%)`;
      } else if (halo) {
        halo.style.transform = "translate(-50%,-50%)";
        halo.style.background = `radial-gradient(circle, ${hexToRgba(themeColors.PRI, 0.2)} 0%, transparent 70%)`;
      }
    },
    setTheme(c) {
      themeColors = { PRI: c.PRI || themeColors.PRI, PRI_DIM: c.PRI_DIM || themeColors.PRI_DIM, TEXT: c.TEXT || themeColors.TEXT, BG: c.BG || themeColors.BG };
      nodes.forEach((n) => n.randomizeColor());
    },
  };
})();
