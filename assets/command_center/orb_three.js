/* ============================================================
   TWO TWENTY — Orbe de partículas Three.js (constelación neural).
   Portado de jarvis_ui/src/orb.ts. 2000 partículas conectadas,
   electrones viajando por las conexiones, reactivo a estados y volumen.
   Estados: idle | listening | thinking | speaking.
   Expone window.Orb { init, setState, setVolume, setTheme, triggerDemo }.
   Requiere THREE global (three.min.js UMD cargado antes).
   ============================================================ */
"use strict";

function createOrb(canvas) {
  let destroyed = false;
  const N = 2000;

  const container = canvas.parentElement || canvas;
  function getSize() {
    const w = container.clientWidth || window.innerWidth;
    const h = container.clientHeight || window.innerHeight;
    return [Math.max(2, w), Math.max(2, h)];
  }
  let [W, H] = getSize();

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(W, H, false);
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, W / H, 1, 1000);
  camera.position.z = 80;

  // ── Particles ──
  const geo = new THREE.BufferGeometry();
  const pos = new Float32Array(N * 3);
  const vel = new Float32Array(N * 3);
  const phase = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    const r = Math.pow(Math.random(), 0.5) * 25;
    pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
    pos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    pos[i * 3 + 2] = r * Math.cos(phi);
    phase[i] = Math.random() * 1000;
  }

  // Objetivo "CARA": las partículas forman DOS OJOS + una BOCA (que se abre al
  // hablar), usando el mismo sistema de partículas del orbe.
  const faceTarget = new Float32Array(N * 3);
  const mouthData = new Float32Array(N);   // !=0 → partícula de la BOCA (signo = labio)
  const pupilFlag = new Float32Array(N);   // 1 → partícula de PUPILA (sigue el mouse)
  for (let i = 0; i < N; i++) {
    const slot = i % 100;
    let ex, ey, ez;
    if (slot < 76) {
      // ── OJOS (38% izquierdo, 38% derecho) ──
      const left = slot < 38;
      const cx = left ? -11.5 : 11.5, cy = 4.0;
      const role = Math.random();
      if (role < 0.55) {                     // contorno (almendra)
        const u = Math.random() * 2 - 1;
        const lidH = 4.7 * (1 - u * u);
        ex = cx + u * 7.9;
        ey = cy + (Math.random() < 0.5 ? lidH : -lidH * 0.82);
        ez = (Math.random() - 0.5) * 2.0;
      } else if (role < 0.80) {              // iris
        const a = Math.random() * Math.PI * 2, rr = Math.sqrt(Math.random());
        ex = cx + Math.cos(a) * rr * 6.6;
        ey = cy + Math.sin(a) * rr * 3.4;
        ez = (Math.random() - 0.5) * 2.0;
      } else {                               // pupila
        const a = Math.random() * Math.PI * 2, rr = Math.random() * 1.7;
        ex = cx + Math.cos(a) * rr;
        ey = cy + Math.sin(a) * rr * 0.95;
        ez = (Math.random() - 0.5) * 1.5 + 2.9;
        pupilFlag[i] = 1;                     // esta partícula sigue el mouse
      }
      mouthData[i] = 0;
    } else {
      // ── BOCA (24%) — dos labios que se separan al abrir ──
      const u = Math.random() * 2 - 1;
      const curve = 1 - u * u;               // 0 en las esquinas
      const lipSign = Math.random() < 0.5 ? 1 : -1;
      ex = u * 9.0;
      ey = -9.0 + lipSign * 0.5 * curve;     // cerrada: línea fina
      ez = (Math.random() - 0.5) * 2.0;
      mouthData[i] = lipSign * curve;        // se separa al abrir (máx en el centro)
    }
    faceTarget[i * 3] = ex; faceTarget[i * 3 + 1] = ey; faceTarget[i * 3 + 2] = ez;
  }

  geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
  const mat = new THREE.PointsMaterial({
    color: 0x2fe6a8, size: 0.4, transparent: true, opacity: 0.6,
    sizeAttenuation: true, blending: THREE.AdditiveBlending, depthWrite: false,
  });
  const points = new THREE.Points(geo, mat);
  scene.add(points);

  // ── Connection lines ──
  const MAX_LINES = 8000;
  const linePos = new Float32Array(MAX_LINES * 6);
  const lineGeo = new THREE.BufferGeometry();
  lineGeo.setAttribute("position", new THREE.BufferAttribute(linePos, 3));
  lineGeo.setDrawRange(0, 0);
  const lineMat = new THREE.LineBasicMaterial({
    color: 0x2fe6a8, transparent: true, opacity: 0.0,
    blending: THREE.AdditiveBlending, depthWrite: false,
  });
  const lines = new THREE.LineSegments(lineGeo, lineMat);
  scene.add(lines);

  // ── Electrons ──
  const MAX_ELECTRONS = 200;
  const electronGeo = new THREE.BufferGeometry();
  const electronPos = new Float32Array(MAX_ELECTRONS * 3);
  electronGeo.setAttribute("position", new THREE.BufferAttribute(electronPos, 3));
  electronGeo.setDrawRange(0, 0);
  const electronMat = new THREE.PointsMaterial({
    color: 0xffffff, size: 0.8, transparent: true, opacity: 1.0,
    sizeAttenuation: true, blending: THREE.AdditiveBlending, depthWrite: false,
  });
  const electronPoints = new THREE.Points(electronGeo, electronMat);
  scene.add(electronPoints);

  const activeElectrons = [];
  let electronSpawnRate = 0, targetElectronRate = 0, lastElectronSpawn = 0;
  let activeConnections = [];

  // ── Base state vars ──
  let state = "idle";
  let targetRadius = 25, currentRadius = 25;
  let targetSpeed = 0.3, currentSpeed = 0.3;
  let targetBright = 0.6, currentBright = 0.6;
  let targetSize = 0.4, currentSize = 0.4;
  let lineAmount = 0, targetLineAmount = 0;
  const lineDistance = 8;
  let spinX = 0, spinY = 0, spinZ = 0;
  let transitionEnergy = 0, lastState = "idle";
  let cloudZ = 0, cloudZVel = 0;
  let vortexStrength = 0, targetVortex = 0;
  let breathAmp = 0, targetBreathAmp = 0;
  let eyesMode = 0, targetEyes = 0, blinkT = 0;       // modo CARA (ojos)
  let mouthOpen = 0, targetMouthOpen = 0;             // apertura de la BOCA
  let gazeX = 0, gazeY = 0, targetGazeX = 0, targetGazeY = 0;   // mirada (pupilas)
  let shockwave = 0, prevBass = 0, burstCooldown = 1.5;
  let prevT = 0;

  // ── Audio ──
  let analyser = null;
  let freqData = new Uint8Array(64);
  let bass = 0, mid = 0, treble = 0;
  let extLevel = 0; // volumen externo (TTS de Two Twenty) cuando no hay analyser
  const clock = new THREE.Clock();

  // ── Colours ──
  const COL_BASE = new THREE.Color(0x2fe6a8);
  const COL_THINK = new THREE.Color(0x66ffd0);
  const COL_SPEAK = new THREE.Color(0x37e0a0);
  const COL_BRIGHT = new THREE.Color(0xbfffe8);
  const COL_FLASH = new THREE.Color(0xffffff);
  const _tmpColor = new THREE.Color();
  const _rainbowCol = new THREE.Color();

  let demoActive = false, demoStartTime = 0, demoBurstNextAt = 0;
  const DEMO_DURATION = 10.0;

  function animate() {
    if (destroyed) return;
    requestAnimationFrame(animate);
    const t = clock.getElapsedTime();
    const dt = Math.min(t - prevT, 0.05);
    prevT = t;

    if (demoActive && t - demoStartTime >= DEMO_DURATION) demoActive = false;
    const demoElapsed = demoActive ? (t - demoStartTime) : -1;
    const demoBigBang = demoActive && demoElapsed < 2.0;
    const demoVortex = demoActive && demoElapsed >= 2.0 && demoElapsed < 5.0;
    const demoPulse = demoActive && demoElapsed >= 5.0 && demoElapsed < 7.5;
    const demoCollapse = demoActive && demoElapsed >= 7.5;

    if (demoActive) {
      if (demoBigBang) { targetRadius = 40; targetSpeed = 1.0; targetBright = 1.0; targetSize = 0.75; targetLineAmount = 1.0; targetElectronRate = 0.04; targetVortex = 0.5; targetBreathAmp = 2.5; }
      else if (demoVortex) { targetRadius = 32; targetSpeed = 0.9; targetBright = 1.0; targetSize = 0.65; targetLineAmount = 1.0; targetElectronRate = 0.04; targetVortex = 4.5; targetBreathAmp = 2.0; }
      else if (demoPulse) { targetRadius = 28; targetSpeed = 0.7; targetBright = 0.95; targetSize = 0.55; targetLineAmount = 0.9; targetElectronRate = 0.03; targetVortex = 2.0; targetBreathAmp = 3.0; }
      else { targetRadius = 10; targetSpeed = 0.5; targetBright = 0.85; targetSize = 0.5; targetLineAmount = 0.7; targetElectronRate = 0.015; targetVortex = 1.0; targetBreathAmp = 0.5; }
    } else {
      switch (state) {
        case "idle": targetRadius = 28; targetSpeed = 0.2; targetBright = 0.5; targetSize = 0.35; targetLineAmount = 0.15; targetElectronRate = 0; targetVortex = 0; targetBreathAmp = 0; break;
        case "listening": targetRadius = 22; targetSpeed = 0.3; targetBright = 0.65; targetSize = 0.4; targetLineAmount = 0.4; targetElectronRate = 0; targetVortex = 0; targetBreathAmp = 0; break;
        case "thinking": targetRadius = 16; targetSpeed = 0.5; targetBright = 0.7; targetSize = 0.3; targetLineAmount = 1.0; targetElectronRate = 0.015; targetVortex = 0; targetBreathAmp = 0; break;
        case "speaking": targetRadius = 20; targetSpeed = 0.45; targetBright = 0.78; targetSize = 0.46; targetLineAmount = 0.92; targetElectronRate = 0.01; targetVortex = 1.4; targetBreathAmp = 1.0; break;
      }
    }

    const L = demoActive ? 0.06 : 0.022;
    currentRadius += (targetRadius - currentRadius) * L;
    currentSpeed += (targetSpeed - currentSpeed) * L;
    currentBright += (targetBright - currentBright) * L;
    currentSize += (targetSize - currentSize) * L;
    lineAmount += (targetLineAmount - lineAmount) * L;
    electronSpawnRate += (targetElectronRate - electronSpawnRate) * L;
    vortexStrength += (targetVortex - vortexStrength) * (demoActive ? 0.08 : 0.025);
    breathAmp += (targetBreathAmp - breathAmp) * (demoActive ? 0.08 : 0.025);
    eyesMode += (targetEyes - eyesMode) * 0.045;   // morph suave hacia/desde la cara
    // Parpadeo ocasional cuando los ojos están formados.
    let blink = 0;
    if (eyesMode > 0.5) {
      if (t > blinkT) { blinkT = t + 2.5 + Math.random() * 3.5; }
      const dt2 = blinkT - t;
      if (dt2 < 0.18) { blink = Math.sin((0.18 - dt2) / 0.18 * Math.PI); }  // cierre/apertura
    }
    // Boca: se abre con el VOLUMEN al hablar (con un mínimo de movimiento al hablar).
    const speakingNow = (state === "speaking");
    targetMouthOpen = speakingNow ? Math.min(1, extLevel * 1.7 + 0.32) : 0;
    mouthOpen += (targetMouthOpen - mouthOpen) * 0.32;
    gazeX += (targetGazeX - gazeX) * 0.08;   // pupilas siguen el mouse (suave)
    gazeY += (targetGazeY - gazeY) * 0.08;

    if (state !== lastState) { transitionEnergy = 1.0; lastState = state; }
    transitionEnergy *= 0.985;
    if (transitionEnergy > 0.05) {
      spinX += transitionEnergy * 0.012 * Math.sin(t * 1.7);
      spinY += transitionEnergy * 0.015;
      spinZ += transitionEnergy * 0.008 * Math.cos(t * 1.3);
    }
    if (demoActive) { spinY += 0.008 * (demoVortex ? 3.0 : 1.0); spinX += Math.sin(t * 0.7) * 0.003; }

    bass = 0; mid = 0; treble = 0;
    if (analyser) {
      analyser.getByteFrequencyData(freqData);
      let bS = 0, mS = 0, tS = 0;
      for (let i = 0; i < 8; i++) bS += freqData[i];
      for (let i = 8; i < 24; i++) mS += freqData[i];
      for (let i = 24; i < 48; i++) tS += freqData[i];
      bass = bS / (8 * 255); mid = mS / (16 * 255); treble = tS / (24 * 255);
    } else if (extLevel > 0.001) {
      bass = extLevel; mid = extLevel * 0.6; treble = extLevel * 0.3;
    }

    const bassJump = Math.max(0, bass - prevBass - 0.04) * 5.0;
    shockwave = Math.max(shockwave * 0.82, bassJump);
    prevBass = bass;

    if (demoActive) {
      if (t >= demoBurstNextAt) {
        const intensity = demoBigBang ? 0.9 : demoVortex ? 0.6 : demoPulse ? 0.75 : 0.4;
        shockwave = Math.max(shockwave, intensity);
        if (demoBigBang && demoElapsed < 0.05) shockwave = 1.0;
        const interval = demoBigBang ? 0.5 : demoVortex ? 0.7 : demoPulse ? 0.9 : 1.5;
        demoBurstNextAt = t + interval + Math.random() * 0.3;
      }
    } else if (state === "speaking") {
      burstCooldown -= dt;
      if (burstCooldown <= 0) { shockwave = Math.max(shockwave, 0.28); burstCooldown = 1.3 + Math.random() * 0.5; }
    } else { burstCooldown = 1.5; }

    let zTarget = Math.sin(t * 0.12) * 8;
    if (state === "thinking") zTarget = Math.sin(t * 0.3) * 15 + Math.sin(t * 0.9) * 6;
    else if (state === "speaking") zTarget = Math.sin(t * 0.18) * 7 - bass * 8;
    else if (demoActive) zTarget = Math.sin(t * 0.4) * 12;
    cloudZVel += (zTarget - cloudZ) * 0.008; cloudZVel *= 0.94; cloudZ += cloudZVel;

    var rotK = 1 - eyesMode * 0.96;   // en modo ojos, mirar al frente (sin girar)
    points.rotation.set(spinX * rotK, spinY * rotK, spinZ * rotK); points.position.z = cloudZ;
    lines.rotation.set(spinX * rotK, spinY * rotK, spinZ * rotK); lines.position.z = cloudZ;

    const p = geo.getAttribute("position");
    const a = p.array;
    const speaking = state === "speaking" && !demoActive;

    for (let i = 0; i < N; i++) {
      const i3 = i * 3;
      const x = a[i3], y = a[i3 + 1], z = a[i3 + 2];
      const px = phase[i];
      vel[i3] += Math.sin(t * 0.05 + px) * 0.001 * currentSpeed;
      vel[i3 + 1] += Math.cos(t * 0.06 + px * 1.3) * 0.001 * currentSpeed;
      vel[i3 + 2] += Math.sin(t * 0.055 + px * 0.7) * 0.001 * currentSpeed;
      vel[i3] += Math.sin(t * 0.02 + px * 2.1 + y * 0.1) * 0.0008 * currentSpeed;
      vel[i3 + 1] += Math.cos(t * 0.025 + px * 1.7 + z * 0.1) * 0.0008 * currentSpeed;
      vel[i3 + 2] += Math.sin(t * 0.022 + px * 0.9 + x * 0.1) * 0.0008 * currentSpeed;
      const dist = Math.sqrt(x * x + y * y + z * z) || 0.01;
      const radiusTarget = (speaking || demoActive)
        ? currentRadius * (1.0 + Math.sin(t * 3.5 + px * 0.2) * 0.15 * breathAmp)
        : currentRadius;
      const pullBase = demoCollapse
        ? Math.max(0, dist - radiusTarget) * 0.015 + 0.002
        : Math.max(0, dist - radiusTarget) * 0.002 + 0.0003;
      vel[i3] -= (x / dist) * pullBase; vel[i3 + 1] -= (y / dist) * pullBase; vel[i3 + 2] -= (z / dist) * pullBase;
      if (bass > 0.05) {
        const bf = (speaking || demoActive) ? bass * 0.032 : bass * 0.02;
        vel[i3] += (x / dist) * bf; vel[i3 + 1] += (y / dist) * bf; vel[i3 + 2] += (z / dist) * bf;
      }
      if (mid > 0.1) {
        const pulse = Math.sin(t * 8 + px);
        const mf = (speaking || demoActive) ? mid * 0.022 : mid * 0.012;
        vel[i3] += (x / dist) * mf * pulse; vel[i3 + 1] += (y / dist) * mf * pulse;
      }
      if (speaking) {
        if (vortexStrength > 0.01) {
          const xzLen = Math.sqrt(x * x + z * z) || 0.01;
          vel[i3] += (-z / xzLen) * vortexStrength * 0.0022;
          vel[i3 + 2] += (x / xzLen) * vortexStrength * 0.0022;
          vel[i3 + 1] += Math.sin(px) * vortexStrength * 0.0005;
        }
        if (shockwave > 0.005) {
          vel[i3] += (x / dist) * shockwave * 0.10; vel[i3 + 1] += (y / dist) * shockwave * 0.05; vel[i3 + 2] += (z / dist) * shockwave * 0.10;
        }
        if (breathAmp > 0.005) {
          const bp = Math.sin(t * 7.5 + px * 0.4) * breathAmp * 0.0018;
          vel[i3] += (x / dist) * bp; vel[i3 + 1] += (y / dist) * bp; vel[i3 + 2] += (z / dist) * bp;
        }
        if (treble > 0.08) {
          const jitter = (Math.random() - 0.5) * treble * 0.04;
          vel[i3] += jitter; vel[i3 + 1] += jitter * 0.5; vel[i3 + 2] += jitter;
        }
      }
      if (demoActive) {
        if (vortexStrength > 0.01) {
          const xzLen = Math.sqrt(x * x + z * z) || 0.01;
          vel[i3] += (-z / xzLen) * vortexStrength * 0.004;
          vel[i3 + 2] += (x / xzLen) * vortexStrength * 0.004;
          if (demoVortex) {
            const xyLen = Math.sqrt(x * x + y * y) || 0.01;
            vel[i3] += (-y / xyLen) * vortexStrength * 0.0015;
            vel[i3 + 1] += (x / xyLen) * vortexStrength * 0.0015;
          }
          vel[i3 + 1] += Math.sin(px * 2.3 + t) * vortexStrength * 0.001;
        }
        if (shockwave > 0.005) {
          vel[i3] += (x / dist) * shockwave * 0.18; vel[i3 + 1] += (y / dist) * shockwave * 0.18; vel[i3 + 2] += (z / dist) * shockwave * 0.18;
        }
        if (breathAmp > 0.005) {
          const bp = Math.sin(t * 9.0 + px * 0.5) * breathAmp * 0.0035;
          vel[i3] += (x / dist) * bp; vel[i3 + 1] += (y / dist) * bp; vel[i3 + 2] += (z / dist) * bp;
        }
        if (demoPulse) {
          const ring = Math.sin(dist * 5.0 - t * 12.0 + px) * 0.003;
          vel[i3] += (x / dist) * ring; vel[i3 + 1] += (y / dist) * ring; vel[i3 + 2] += (z / dist) * ring;
        }
        if (demoBigBang) {
          const chaos = (Math.random() - 0.5) * 0.04;
          vel[i3] += chaos; vel[i3 + 1] += chaos * 0.7; vel[i3 + 2] += chaos;
        }
      }
      // ── CARA: tirar cada partícula a su objetivo (ojos con parpadeo / boca que abre) ──
      if (eyesMode > 0.01) {
        const pull = 0.07 * eyesMode;
        let tx = faceTarget[i3];
        let ty = faceTarget[i3 + 1];
        const tz = faceTarget[i3 + 2];
        if (mouthData[i] !== 0) {
          ty += mouthData[i] * mouthOpen * eyesMode * 6.5;   // separa los labios al hablar
        } else {
          const by = 1 - blink * 0.92;                       // parpadeo → achata el ojo
          ty = 4.0 + (ty - 4.0) * by;
          if (pupilFlag[i]) {                                // pupilas siguen el mouse
            tx += gazeX * 3.2 * eyesMode;
            ty += -gazeY * 2.4 * eyesMode;
          }
        }
        vel[i3]     += (tx - x) * pull;
        vel[i3 + 1] += (ty - y) * pull;
        vel[i3 + 2] += (tz - z) * pull;
      }
      const damp = (demoActive ? 0.988 : 0.992) * (eyesMode > 0.3 ? 0.96 : 1.0);
      vel[i3] *= damp; vel[i3 + 1] *= damp; vel[i3 + 2] *= damp;
      a[i3] += vel[i3]; a[i3 + 1] += vel[i3 + 1]; a[i3 + 2] += vel[i3 + 2];
    }
    p.needsUpdate = true;

    if (lineAmount > 0.01) {
      const lp = lineGeo.getAttribute("position");
      const la = lp.array;
      let lineCount = 0;
      const maxDist = lineDistance * (1 + bass * ((speaking || demoActive) ? 0.8 : 0.5));
      const maxDistSq = maxDist * maxDist;
      const step = Math.max(1, Math.floor(N / 600));
      for (let i = 0; i < N && lineCount < MAX_LINES; i += step) {
        const i3 = i * 3;
        const x1 = a[i3], y1 = a[i3 + 1], z1 = a[i3 + 2];
        for (let j = i + step; j < N && lineCount < MAX_LINES; j += step) {
          const j3 = j * 3;
          const dx = a[j3] - x1, dy = a[j3 + 1] - y1, dz = a[j3 + 2] - z1;
          if (dx * dx + dy * dy + dz * dz < maxDistSq) {
            const idx = lineCount * 6;
            la[idx] = x1; la[idx + 1] = y1; la[idx + 2] = z1;
            la[idx + 3] = a[j3]; la[idx + 4] = a[j3 + 1]; la[idx + 5] = a[j3 + 2];
            lineCount++;
          }
        }
      }
      lineGeo.setDrawRange(0, lineCount * 2);
      lp.needsUpdate = true;
      lineMat.opacity = lineAmount * 0.12 + shockwave * 0.15;
      activeConnections = [];
      for (let c = 0; c < Math.min(lineCount, 500); c++) {
        const ci = c * 6;
        activeConnections.push({ x1: la[ci], y1: la[ci + 1], z1: la[ci + 2], x2: la[ci + 3], y2: la[ci + 4], z2: la[ci + 5] });
      }
    } else {
      lineGeo.setDrawRange(0, 0); activeConnections = [];
    }

    const maxElec = demoActive ? 25 : speaking ? 10 : 3;
    const spawnGap = demoActive ? 0.06 : speaking ? 0.18 : 1.0;
    const eSpeed = demoActive ? 0.014 + Math.random() * 0.012 : speaking ? 0.009 + Math.random() * 0.009 : 0.003 + Math.random() * 0.003;
    if (activeConnections.length > 0 && electronSpawnRate > 0.005) {
      if (activeElectrons.length < maxElec && (t - lastElectronSpawn) > spawnGap) {
        const conn = activeConnections[Math.floor(Math.random() * activeConnections.length)];
        activeElectrons.push({ sx: conn.x1, sy: conn.y1, sz: conn.z1, ex: conn.x2, ey: conn.y2, ez: conn.z2, t: 0, speed: eSpeed });
        lastElectronSpawn = t;
      }
    }
    const ep = electronGeo.getAttribute("position");
    const ea = ep.array;
    let aliveCount = 0;
    for (let e = activeElectrons.length - 1; e >= 0; e--) {
      const el = activeElectrons[e];
      el.t += el.speed;
      if (el.t >= 1) { activeElectrons.splice(e, 1); continue; }
      const ei = aliveCount * 3;
      ea[ei] = el.sx + (el.ex - el.sx) * el.t;
      ea[ei + 1] = el.sy + (el.ey - el.sy) * el.t;
      ea[ei + 2] = el.sz + (el.ez - el.sz) * el.t;
      aliveCount++;
    }
    electronGeo.setDrawRange(0, aliveCount);
    ep.needsUpdate = true;
    electronPoints.rotation.set(spinX * rotK, spinY * rotK, spinZ * rotK); electronPoints.position.z = cloudZ;
    electronMat.size = demoActive ? 1.4 + shockwave * 1.2 : speaking ? 1.0 + shockwave * 0.8 : 0.8;
    electronMat.opacity = demoActive ? 1.0 : speaking ? 1.0 + shockwave * 0.5 : 1.0;

    if (demoActive) {
      const hue = ((t - demoStartTime) * 0.2) % 1.0;
      _rainbowCol.setHSL(hue, 1.0, 0.6);
      if (shockwave > 0.4) _rainbowCol.lerp(COL_FLASH, Math.min(1, (shockwave - 0.4) * 2.0));
      mat.opacity = Math.min(1.4, currentBright + shockwave * 0.3);
      mat.size = currentSize + shockwave * 0.5;
      mat.color.lerp(_rainbowCol, 0.12); lineMat.color.lerp(_rainbowCol, 0.12);
      lineMat.opacity = lineAmount * 0.18 + shockwave * 0.25;
      electronMat.color.lerp(_rainbowCol, 0.15);
    } else if (speaking) {
      mat.opacity = Math.min(1.2, currentBright + bass * 0.18 + shockwave * 0.25);
      mat.size = currentSize + bass * 0.20 + shockwave * 0.30;
      const pulseIntensity = (bass * 0.7 + mid * 0.2 + shockwave * 0.5);
      const wave = 0.5 + 0.5 * Math.sin(t * 12.0 + bass * 8.0);
      _tmpColor.lerpColors(COL_SPEAK, COL_BRIGHT, Math.min(1, pulseIntensity * wave));
      if (shockwave > 0.18) _tmpColor.lerp(COL_FLASH, (shockwave - 0.18) * 3.0);
      mat.color.lerp(_tmpColor, 0.14); lineMat.color.lerp(_tmpColor, 0.14);
      electronMat.color.set(0xffffff);
    } else {
      mat.opacity = currentBright + bass * 0.08;
      mat.size = currentSize + bass * 0.05;
      if (state === "thinking") { mat.color.lerp(COL_THINK, 0.015); lineMat.color.lerp(COL_THINK, 0.015); }
      else { mat.color.lerp(COL_BASE, 0.015); lineMat.color.lerp(COL_BASE, 0.015); }
      electronMat.color.set(0xffffff);
    }

    if (demoActive) {
      const dT = demoElapsed;
      camera.position.x = Math.sin(dT * 0.5) * 12;
      camera.position.y = Math.cos(dT * 0.35) * 8;
      camera.position.z = 80 + Math.sin(dT * 0.6) * 15;
    } else {
      camera.position.x = Math.sin(t * 0.02) * 5;
      camera.position.y = Math.cos(t * 0.03) * 3;
      camera.position.z = 80;
    }
    camera.lookAt(0, 0, cloudZ * 0.2);
    renderer.render(scene, camera);
  }

  function onResize() {
    [W, H] = getSize();
    camera.aspect = W / H;
    camera.updateProjectionMatrix();
    renderer.setSize(W, H, false);
  }
  window.addEventListener("resize", onResize);
  // Mirada: las pupilas siguen el cursor cuando la cara está formada.
  window.addEventListener("mousemove", function (e) {
    targetGazeX = Math.max(-1, Math.min(1, (e.clientX / window.innerWidth - 0.5) * 2));
    targetGazeY = Math.max(-1, Math.min(1, (e.clientY / window.innerHeight - 0.5) * 2));
  });
  // Re-size si el contenedor cambia (paneles, layout)
  if (window.ResizeObserver) {
    try { new ResizeObserver(onResize).observe(container); } catch (e) {}
  }
  animate();

  return {
    setState(s) { state = s; },
    setEyes(on) { targetEyes = on ? 1 : 0; },
    setLevel(v) { extLevel = Math.max(0, Math.min(1, v || 0)); },
    setAnalyser(an) { analyser = an; if (an) freqData = new Uint8Array(an.frequencyBinCount); },
    triggerDemo() { demoActive = true; demoStartTime = clock.getElapsedTime(); demoBurstNextAt = demoStartTime; shockwave = 1.0; transitionEnergy = 1.0; },
    destroy() { destroyed = true; window.removeEventListener("resize", onResize); renderer.dispose(); },
  };
}

// ── Bootstrap: conecta con la interfaz de Two Twenty (window.Orb) ──
(function () {
  const canvas = document.getElementById("sphere-canvas");
  if (!canvas) return;
  const orb = createOrb(canvas);
  const MAP = { LISTENING: "listening", THINKING: "thinking", SPEAKING: "speaking", MUTED: "idle" };
  window.Orb = {
    init() { /* ya está corriendo */ },
    setState(s) { orb.setState(MAP[s] || "idle"); },
    setVolume(v) { orb.setLevel(v); },
    setTheme() { /* mantiene su paleta nativa (azul constelación) */ },
    setEyes(on) { orb.setEyes(on); },
    triggerDemo() { orb.triggerDemo(); },
  };
})();
