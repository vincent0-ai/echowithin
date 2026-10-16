/* Air Hockey — solo vs AI, local 2P, online 1v1 (host-authoritative). No dependencies. */
(function () {
  'use strict';
  var W = 1.0, H = 1.5, TARGET = 7;
  var PUCK_R = 0.035, MALLET_R = 0.075, GOAL_W = 0.38;
  var state = {
    mode: 'solo', difficulty: 'normal', over: false, scores: [0, 0], streak: 0,
    roomId: null, player: 0, isHost: true, guestToken: null,
    puck: { x: 0.5, y: 0.75, vx: 0, vy: 0 },
    p1: { x: 0.5, y: 1.28, vx: 0, vy: 0, tx: 0.5, ty: 1.28 },
    p2: { x: 0.5, y: 0.22, vx: 0, vy: 0, tx: 0.5, ty: 0.22 },
    serveTimer: 0, aiTick: 0, netTick: 0, inputTick: 0,
    deadX: 0.5, deadY: 0.75, deadT: 0
  };
  // Per-difficulty brain: easy is slow, dozy and sprays shots; hard is fast and precise.
  var AI = {
    easy:   { speed: 0.80, lunge: 1.35, react: 18, err: 0.11, aggression: 0.12, guardY: 0.20, pressY: 0.35,
              missRate: 0.32, trackErr: 0.085, strikeErr: 0.070, maxCap: 1.7, guardBlend: 0.45,
              stallFrames: 90, hustle: 1.0, whiff: 0.10, gain: 7,  base: 0.12, dead: 0.008 },
    normal: { speed: 1.40, lunge: 1.90, react: 8,  err: 0.05,  aggression: 0.50, guardY: 0.16, pressY: 0.55,
              missRate: 0.10, trackErr: 0.030, strikeErr: 0.025, maxCap: 2.6, guardBlend: 0.65,
              stallFrames: 55, hustle: 1.08, whiff: 0.02, gain: 10, base: 0.18, dead: 0.005 },
    hard:   { speed: 2.30, lunge: 2.70, react: 3,  err: 0.016, aggression: 0.90, guardY: 0.13, pressY: 0.68,
              missRate: 0.02, trackErr: 0.006, strikeErr: 0.007, maxCap: 3.4, guardBlend: 0.82,
              stallFrames: 32, hustle: 1.12, whiff: 0.0,  gain: 13, base: 0.25, dead: 0.003 }
  };
  // Adaptive AI brain: persists across rallies so it can adjust to the player.
  var aiMem = {
    tx: 0.5, ty: 0.22, aimX: 0.5, aimHold: 0,
    stall: 0, decide: 0, jitterX: 0,
    press: false, strike: false
  };
  function aiResetBrain() {
    aiMem.tx = 0.5; aiMem.ty = 0.22; aiMem.aimX = 0.5; aiMem.aimHold = 0;
    aiMem.stall = 0; aiMem.decide = 0; aiMem.jitterX = 0;
    aiMem.press = false; aiMem.strike = false;
  }

  // Dead-puck referee: if the puck hasn't meaningfully moved for a while, whistle
  // and re-serve from center. A puck wedged in a corner can never be pushed out
  // positionally (every placement normal lands outside the walls), and simulation
  // proved no inside mallet action extracts a fully dead one — so the whistle is
  // the geometry-proof safety net, with a fast fuse inside corner zones (neither
  // side can play a wedged puck; our corners are unreachable for the player).
  // Dribbling moves the puck, so live play never trips it. Host-authoritative.
  function refereeDeadPuck(dt) {
    if (state.over) { state.deadT = 0; return; }
    var moved = Math.hypot(state.puck.x - state.deadX, state.puck.y - state.deadY);
    var spd = Math.hypot(state.puck.vx, state.puck.vy);
    if (moved > 0.012 || spd > 0.25) {
      state.deadX = state.puck.x; state.deadY = state.puck.y; state.deadT = 0;
      return;
    }
    var p = state.puck;
    var cornered = (p.y < 0.22 || p.y > H - 0.22) && (p.x < 0.17 || p.x > W - 0.17);
    state.deadT += dt;
    if (state.deadT > (cornered ? 1.2 : 2.5)) {
      state.puck = { x: 0.5, y: 0.75, vx: (Math.random() - 0.5) * 0.6, vy: (Math.random() < 0.5 ? -1 : 1) * 0.8 };
      state.deadX = 0.5; state.deadY = 0.75; state.deadT = 0;
      aiMem.stall = 0; aiMem.aimHold = 0; aiMem.decide = 99;
      setStatus('Puck reset — play!');
    }
  }
  function resetDeadTrack(x, y) { state.deadX = x; state.deadY = y; state.deadT = 0; }
  var canvas = document.getElementById('air-canvas');
  var ctx = canvas.getContext('2d');
  var socket = window.__airSocket || null;
  try { if (!socket && typeof io !== 'undefined') socket = io({ transports: ['websocket', 'polling'] }); } catch (e) { socket = null; }

  function sizeCanvas() {
    var wrap = canvas.parentElement;
    var w = Math.min(wrap.clientWidth || 340, 420);
    var h = w * H / W;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    ctx.setTransform(dpr * w, 0, 0, dpr * w, 0, 0);
    draw();
  }
  function X(x) { return x; }
  function Y(y) { return y; }

  function draw() {
    var w = W, h = H;
    ctx.fillStyle = '#eef2f5'; ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#ffffff';
    roundRect(0.03, 0.03, w - 0.06, h - 0.06, 0.12); ctx.fill();
    ctx.strokeStyle = '#2c5f8a'; ctx.lineWidth = 0.008; ctx.stroke();
    ctx.strokeStyle = '#2c5f8a'; ctx.lineWidth = 0.006; ctx.setLineDash([0.04, 0.03]);
    ctx.beginPath(); ctx.moveTo(0.05, h / 2); ctx.lineTo(w - 0.05, h / 2); ctx.stroke(); ctx.setLineDash([]);
    ctx.strokeStyle = '#2c5f8a'; ctx.lineWidth = 0.006;
    ctx.beginPath(); ctx.arc(w / 2, h / 2, 0.11, 0, 7); ctx.stroke();
    ctx.fillStyle = '#1c2733';
    ctx.fillRect(w / 2 - GOAL_W / 2, 0.028, GOAL_W, 0.012);
    ctx.fillRect(w / 2 - GOAL_W / 2, h - 0.04, GOAL_W, 0.012);
    drawPuck(); drawMallet(state.p1, '#b8423f'); drawMallet(state.p2, '#2c5f8a');
  }
  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }
  function drawPuck() {
    ctx.beginPath(); ctx.arc(X(state.puck.x), Y(state.puck.y), PUCK_R, 0, 7);
    ctx.fillStyle = '#3e2217'; ctx.fill();
    ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 0.006; ctx.stroke();
  }
  function drawMallet(m, color) {
    ctx.beginPath(); ctx.arc(X(m.x), Y(m.y), MALLET_R, 0, 7);
    ctx.fillStyle = color; ctx.fill();
    ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 0.008; ctx.stroke();
    ctx.beginPath(); ctx.arc(X(m.x), Y(m.y), MALLET_R * 0.4, 0, 7);
    ctx.fillStyle = 'rgba(255,255,255,0.85)'; ctx.fill();
  }

  function clampMallets() {
    state.p1.x = Math.max(MALLET_R, Math.min(W - MALLET_R, state.p1.x));
    state.p1.y = Math.max(H / 2 + 0.02, Math.min(H - MALLET_R - 0.02, state.p1.y));
    state.p2.x = Math.max(MALLET_R, Math.min(W - MALLET_R, state.p2.x));
    state.p2.y = Math.max(MALLET_R + 0.02, Math.min(H / 2 - 0.02, state.p2.y));
  }

  function stepPhysics(dt) {
    var p = state.puck;
    p.x += p.vx * dt; p.y += p.vy * dt;
    p.vx *= 0.998; p.vy *= 0.998;
    var sp = Math.hypot(p.vx, p.vy), max = 2.6;
    if (sp > max) { p.vx *= max / sp; p.vy *= max / sp; }
    var inMouth = Math.abs(p.x - W / 2) < GOAL_W / 2;
    if (p.x < PUCK_R + 0.03) { p.x = PUCK_R + 0.03; p.vx = Math.abs(p.vx) * 0.92; }
    if (p.x > W - PUCK_R - 0.03) { p.x = W - PUCK_R - 0.03; p.vx = -Math.abs(p.vx) * 0.92; }
    if (p.y < PUCK_R + 0.03) {
      if (inMouth) return goal(0);
      p.y = PUCK_R + 0.03; p.vy = Math.abs(p.vy) * 0.92;
    }
    if (p.y > H - PUCK_R - 0.03) {
      if (inMouth) return goal(1);
      p.y = H - PUCK_R - 0.03; p.vy = -Math.abs(p.vy) * 0.92;
    }
    collide(state.p1); collide(state.p2);
    containPuck();
    return false;
  }

  // Hard containment AFTER collisions: a mallet pressing the puck into a corner
  // can otherwise shove it through the wall, where it rests out of reach forever
  // (positional resolution runs after the wall bounce). Kill only the outward
  // velocity component — inward motion is preserved, goals are never blocked
  // (goal() already consumed any puck crossing the line inside the mouth).
  function containPuck() {
    var p = state.puck;
    var minX = PUCK_R + 0.03, maxX = W - PUCK_R - 0.03;
    var minY = PUCK_R + 0.03, maxY = H - PUCK_R - 0.03;
    var inMouth = Math.abs(p.x - W / 2) < GOAL_W / 2;
    if (p.x < minX) { p.x = minX; if (p.vx < 0) p.vx = 0; }
    if (p.x > maxX) { p.x = maxX; if (p.vx > 0) p.vx = 0; }
    if (p.y < minY && !(inMouth && p.vy < 0)) { p.y = minY; if (p.vy < 0) p.vy = 0; }
    if (p.y > maxY && !(inMouth && p.vy > 0)) { p.y = maxY; if (p.vy > 0) p.vy = 0; }
  }

  function collide(m) {
    var p = state.puck;
    var dx = p.x - m.x, dy = p.y - m.y, d = Math.hypot(dx, dy), min = PUCK_R + MALLET_R;
    if (d > 0 && d < min) {
      var nx = dx / d, ny = dy / d;
      p.x = m.x + nx * min; p.y = m.y + ny * min;
      var rel = (p.vx - m.vx) * nx + (p.vy - m.vy) * ny;
      if (rel < 0) {
        p.vx -= 1.85 * rel * nx; p.vy -= 1.85 * rel * ny;
        p.vx += m.vx * 0.35; p.vy += m.vy * 0.35;
      }
    }
  }

  function goal(scorer) {
    state.scores[scorer]++;
    updateScores();
    if (state.mode === 'online' && socket && state.roomId && state.isHost) {
      socket.emit('air_score', { room_id: state.roomId, scores: state.scores });
    }
    if (state.scores[scorer] >= TARGET) { endMatch(scorer); return true; }
    state.puck = { x: 0.5, y: 0.75, vx: (Math.random() - 0.5) * 0.6, vy: (scorer === 0 ? -1 : 1) * 0.8 };
    // Fresh serve: clear stall + re-aim so the AI attacks the new puck immediately.
    aiMem.stall = 0; aiMem.aimHold = 0; aiMem.decide = 99;
    resetDeadTrack(0.5, 0.75);
    return true;
  }

  function updateScores() {
    // Perspective-aware: online guest (player 1) sees own score under YOU.
    var mine, theirs;
    if (state.mode === 'online' && state.player === 1) { mine = state.scores[1]; theirs = state.scores[0]; }
    else { mine = state.scores[0]; theirs = state.scores[1]; }
    document.getElementById('score-val-p1').textContent = mine;
    document.getElementById('score-val-p2').textContent = theirs;
    var ls = document.getElementById('live-streak');
    if (ls) ls.textContent = state.streak;
  }

  function getGuestToken() {
    try {
      var t = localStorage.getItem('ew_guest_token');
      if (!t) { t = 'g_' + Math.random().toString(36).slice(2, 14); localStorage.setItem('ew_guest_token', t); }
      return t;
    } catch (e) {
      if (!state.guestToken) state.guestToken = 'g_' + Math.random().toString(36).slice(2, 14);
      return state.guestToken;
    }
  }

  function refreshBoard() {
    try { if (typeof window.fetchLeaderboard === 'function') window.fetchLeaderboard(); } catch (e) {}
  }

  function careerWins() {
    try {
      var k = 'ew_career_air_hockey';
      var n = parseInt(localStorage.getItem(k) || '0', 10) || 0;
      n += 1; localStorage.setItem(k, String(n));
      return n;
    } catch (e) { return 1; }
  }

  function submitScore(cat, score, extra) {
    score = Math.round(Number(score) || 0);
    if (score <= 0) return;
    var payload = { game: 'air_hockey', category: cat, score: score, metadata: extra || {}, guest_token: getGuestToken(), username: 'Guest' };
    fetch('/api/games/leaderboard/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).then(refreshBoard).catch(function () {});
  }

  // Lifetime ranked points: base by difficulty + streak bonus, accumulated
  // across wins like the older arcade games (backend keeps the peak).
  var RANK_BASE = { easy: 100, normal: 200, hard: 300, online: 200, local: 100 };
  function addRanked(earned) {
    var k = 'ew_air_ranked_score', cur = 0;
    try { cur = parseInt(localStorage.getItem(k) || '0', 10) || 0; } catch (e) {}
    cur += earned;
    try { localStorage.setItem(k, String(cur)); } catch (e) {}
    return cur;
  }

  function recordWin() {
    state.streak++;
    var base = RANK_BASE[state.difficulty] || RANK_BASE[state.mode] || 100;
    submitScore('win_streak', state.streak, { mode: state.mode });
    submitScore('total_wins', careerWins(), { mode: state.mode });
    submitScore('ranked_score', addRanked(base + 25 * state.streak), { mode: state.mode, difficulty: state.difficulty });
  }

  function endMatch(winner) {
    state.over = true;
    var meWon = (state.mode === 'online') ? (winner === state.player) : (winner === 0);
    if (meWon) { recordWin(); }
    else state.streak = 0;
    updateScores();
    document.getElementById('air-result-title').textContent = meWon ? 'YOU WON!' : (state.mode === 'local' ? ('PLAYER ' + (winner + 1) + ' WON!') : 'YOU LOST');
    document.getElementById('air-result-overlay').style.display = 'flex';
  }

  function resetPositions() {
    state.puck = { x: 0.5, y: 0.75, vx: (Math.random() - 0.5) * 0.6, vy: -0.8 };
    state.p1 = { x: 0.5, y: 1.28, vx: 0, vy: 0, tx: 0.5, ty: 1.28 };
    state.p2 = { x: 0.5, y: 0.22, vx: 0, vy: 0, tx: 0.5, ty: 0.22 };
    aiResetBrain();
    resetDeadTrack(0.5, 0.75);
  }

  function resetMatch() {
    state.scores = [0, 0]; state.over = false;
    resetPositions(); updateScores();
    aiResetBrain();
    document.getElementById('air-result-overlay').style.display = 'none';
    setStatus(state.mode === 'online' ? 'Rally!' : 'Drag to play.');
  }

  function setStatus(t) {
    var el = document.getElementById('room-status');
    if (el && state.mode === 'online') el.textContent = t;
    document.getElementById('air-status').textContent = t.length < 30 ? t.toUpperCase() : t;
  }

  function isAuthed() {
    return !!(document.body && document.body.dataset && document.body.dataset.userLoggedIn === 'true');
  }

  // Solo needs an account; local pass-and-play and invite duels stay open.
  function applySoloGate() {
    var locked = (state.mode === 'solo' && !isAuthed());
    var gate = document.getElementById('solo-gate');
    if (gate) gate.style.display = locked ? 'block' : 'none';
    var stage = document.querySelector('.air-stage');
    if (stage) stage.style.display = locked ? 'none' : '';
    return locked;
  }

  function clampNum(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  // Linear puck prediction with side-wall bounces. Used for goalie positioning.
  function predictXAtY(px, py, vx, vy, targetY) {
    if (Math.abs(vy) < 1e-4) return px;
    var t = (targetY - py) / vy;
    if (t < 0 || t > 1.2) return px;
    var minX = PUCK_R + 0.03, maxX = W - PUCK_R - 0.03;
    var x = px + vx * t;
    var guard = 0;
    while ((x < minX || x > maxX) && guard++ < 8) {
      if (x < minX) x = minX + (minX - x);
      if (x > maxX) x = maxX - (x - maxX);
    }
    return clampNum(x, minX, maxX);
  }

  // Pick a spot in/around the opponent goal mouth, biased away from the player
  // mallet so shots are harder to block. Holds for a few decisions to avoid jitter.
  // Each difficulty has a missRate that deliberately sprays wide (easy misses
  // often, hard almost never) — otherwise clamping would make everyone perfect.
  function chooseAim(cfg) {
    var margin = 0.045;
    var lo = W / 2 - GOAL_W / 2 + margin, hi = W / 2 + GOAL_W / 2 - margin;
    if (Math.random() < (cfg.missRate || 0)) {
      var side = Math.random() < 0.5 ? -1 : 1;
      var missBy = 0.06 + Math.random() * 0.10;
      return clampNum(0.5 + side * (GOAL_W / 2 + missBy), 0.08, 0.92);
    }
    var away = (state.p1.x < 0.5) ? 1 : -1;
    var r = Math.random();
    var offset;
    if (r < 0.72) offset = away * GOAL_W * 0.30;       // punish open side
    else if (r < 0.9) offset = -away * GOAL_W * 0.22;  // occasional fake
    else offset = (Math.random() - 0.5) * GOAL_W * 0.3; // variation
    // Triangular-ish error: easy sprays, hard is precise.
    var err = (Math.random() + Math.random() + Math.random() - 1.5) / 1.5;
    // When ahead, take riskier (wider) shots; when behind, play safe (center).
    var diff = state.scores[1] - state.scores[0];
    var spread = diff >= 2 ? 1.15 : (diff <= -2 ? 0.6 : 1.0);
    offset = offset * spread + err * cfg.err * 2;
    return clampNum(0.5 + offset, lo, hi);
  }

  // Position behind the puck along the shot line so the AI drives *through*
  // the puck toward the aim point instead of sitting head-on (which caused
  // the old horizontal vibration deadlock).
  function behindPuck(puck, aimX, aimY) {
    var dx = aimX - puck.x, dy = aimY - puck.y;
    var d = Math.hypot(dx, dy) || 1;
    dx /= d; dy /= d;
    var off = MALLET_R + PUCK_R + 0.022;
    return {
      x: clampNum(puck.x - dx * off, MALLET_R, W - MALLET_R),
      y: clampNum(puck.y - dy * off, MALLET_R + 0.02, H / 2 - 0.03),
      dx: dx, dy: dy
    };
  }

  // Full AI: defend (goalie) -> intercept -> attack (get behind + strike)
  // -> clear stall. Movement runs every frame; decisions run every cfg.react frames.
  function aiControl(dt) {
    var cfg = AI[state.difficulty] || AI.normal;
    var m = state.p2, p = state.puck;
    if (!dt || dt <= 0) dt = 1 / 60;
    dt = Math.min(dt, 1 / 30);

    var puckSp = Math.hypot(p.vx, p.vy);
    // Stall detection: slow puck => force an attacking clear to break deadlock.
    // Easy dawdles (high threshold), hard pounces quickly.
    var stallNeed = cfg.stallFrames || 40;
    if (puckSp < 0.20) aiMem.stall++;
    else aiMem.stall = 0;
    var stalled = aiMem.stall > stallNeed;
    var justStalled = aiMem.stall === stallNeed + 1;

    aiMem.decide++;
    if (aiMem.decide >= cfg.react || justStalled) {
      aiMem.decide = 0;
      var losing = state.scores[1] < state.scores[0];
      var winning = state.scores[1] > state.scores[0];

      // Refresh aim every ~0.7s or once when a stall begins so shots stay varied.
      aiMem.aimHold--;
      if (aiMem.aimHold <= 0 || justStalled) {
        aiMem.aimX = chooseAim(cfg);
        aiMem.aimHold = 30 + ((Math.random() * 20) | 0);
        if (stalled) aiMem.aimX = clampNum(0.5 + (Math.random() - 0.5) * (GOAL_W - 0.09), W / 2 - GOAL_W / 2 + 0.045, W / 2 + GOAL_W / 2 - 0.045);
      }
      // Small held jitter per decision (not per frame) so no vibration.
      aiMem.jitterX = (Math.random() - 0.5) * cfg.err;

      var aimY = H - 0.03; // opponent goal line
      var onAiSide = p.y < H / 2 + 0.06;
      var comingFast = p.vy < -0.45;
      var slowNear = puckSp < 0.55 && p.y < 0.95;
      // Higher difficulties press onto the player side for slow pucks.
      var wantPress = slowNear && (Math.random() < cfg.aggression || stalled) && p.y < cfg.pressY + 0.3;
      aiMem.press = wantPress && !onAiSide;

      var tx = 0.5, ty = 0.22;
      aiMem.strike = false;

      // Puck dead in one of OUR top corners is unplayable: the mallet can never
      // get behind it, and every contact just presses it deeper into the wedge
      // (verified in simulation — wind-up/smash routines cannot extract it).
      // So back off at once and let the referee re-serve (fast 1.2s fuse in
      // corners). Never push the wedge.
      var inCorner = (p.y < 0.22 && (p.x < 0.17 || p.x > W - 0.17) && puckSp < 0.4);
      if (inCorner) {
        tx = 0.5; ty = 0.30; aiMem.strike = false;
      } else if (onAiSide || wantPress || stalled) {
        // --- ATTACK: get behind the puck, then drive through it ---
        var b = behindPuck(p, aiMem.aimX, aimY);
        var mBehindY = m.y < p.y - 0.015; // AI is on the goal side of the puck
        var alignX = Math.abs(m.x - b.x);
        var distBehind = Math.hypot(m.x - b.x, m.y - b.y);
        var distPuck = Math.hypot(m.x - p.x, m.y - p.y);
        if ((mBehindY && alignX < 0.09 && distPuck < 0.22) || (distBehind < 0.03 && mBehindY)) {
          // Strike: aim through the puck, overshooting so contact drives it out.
          // strikeErr makes easy mishit and hard stay laser-precise.
          tx = p.x + b.dx * 0.16 + (Math.random() - 0.5) * 2 * (cfg.strikeErr || 0);
          ty = p.y + b.dy * 0.16 + (Math.random() - 0.5) * (cfg.strikeErr || 0);
          // Whiff: easy occasionally swings and misses the puck entirely.
          if (Math.random() < (cfg.whiff || 0)) tx += (Math.random() < 0.5 ? -1 : 1) * 0.09;
          aiMem.strike = true;
        } else {
          tx = b.x + aiMem.jitterX * 0.4 + (Math.random() - 0.5) * 2 * (cfg.trackErr || 0) * 0.4;
          ty = b.y;
          // If puck is almost stopped right in front of us, go straight at it.
          if (puckSp < 0.12 && distPuck < 0.16) { tx = p.x; ty = p.y - 0.01; aiMem.strike = true; }
        }
        // Adapt: when losing, stay a touch deeper before committing (not on easy).
        if (losing && !aiMem.strike && (cfg.hustle || 1) > 1.0) ty = Math.min(ty, 0.30);
        if (winning && aiMem.strike) tx = clampNum(tx, MALLET_R, W - MALLET_R);
      } else if (comingFast) {
        // --- DEFEND fast shot: goalie cuts the angle ---
        // trackErr makes easy misread bounces; guardBlend keeps easy near center.
        var pred = predictXAtY(p.x, p.y, p.vx, p.vy, cfg.guardY)
          + (Math.random() - 0.5) * 2 * (cfg.trackErr || 0);
        var blend = (cfg.guardBlend == null ? 0.7 : cfg.guardBlend);
        tx = 0.5 * (1 - blend) + pred * blend + aiMem.jitterX * 0.3;
        ty = cfg.guardY;
        // Easy ball-watches: sometimes stays rooted at center, leaving the net open.
        if (Math.random() < (cfg.whiff || 0) * 1.5) tx = 0.5;
        // If already beaten wide, scramble toward the puck line instead of center.
        if (Math.abs(p.x - 0.5) > GOAL_W / 2) tx = clampNum(pred, MALLET_R, W - MALLET_R);
      } else {
        // --- READY: shadow the puck, hold mid between goal and center ---
        var shadow = clampNum(p.x + (Math.random() - 0.5) * 2 * (cfg.trackErr || 0), 0.2, 0.8);
        tx = 0.5 * 0.45 + shadow * 0.55 + aiMem.jitterX * 0.5;
        // Sit deeper when the player holds the puck; step up when it drifts center.
        var threat = (p.y > 0.9) ? 1 : 0;
        ty = threat ? cfg.guardY + 0.02 : 0.24;
        if (p.y > H / 2 && p.y < 0.95 && puckSp < 0.3) ty = 0.32; // creep up, look for a mistake
      }

      aiMem.tx = clampNum(tx, MALLET_R * 0.6, W - MALLET_R * 0.6);
      aiMem.ty = clampNum(ty, MALLET_R, H / 2 - 0.025);
    }

    // --- Smooth pursuit with deadzone (kills the old vibration) ---
    // dead/gain/base per difficulty: easy feels dozy, hard feels razor sharp.
    var dx = aiMem.tx - m.x, dy = aiMem.ty - m.y;
    var d = Math.hypot(dx, dy);
    var ox = m.x, oy = m.y;
    var dead = cfg.dead || 0.004;
    if (d < dead) {
      m.vx *= 0.8; m.vy *= 0.8;
    } else {
      var boost = 1.0;
      var diff2 = state.scores[1] - state.scores[0];
      if (diff2 <= -2) boost = cfg.hustle || 1.0; // adapt: hustle when losing (off on easy)
      var maxSp = cfg.speed * boost * (aiMem.strike ? cfg.lunge : 1.0);
      maxSp = Math.min(maxSp, cfg.maxCap || 3.4);
      var desired = Math.min(maxSp, d * (cfg.gain || 12) + (cfg.base == null ? 0.25 : cfg.base));
      var step = Math.min(d, desired * dt);
      m.x += dx / d * step;
      m.y += dy / d * step;
      m.vx = (m.x - ox) / dt;
      m.vy = (m.y - oy) / dt;
      // Clamp absurd spikes so hits stay powerful but stable.
      var mv = Math.hypot(m.vx, m.vy);
      if (mv > 4) { m.vx *= 4 / mv; m.vy *= 4 / mv; }
    }
  }

  var last = 0, acc = 0;
  function loop(now) {
    requestAnimationFrame(loop);
    if (!last) last = now;
    var dt = Math.min(0.1, (now - last) / 1000); last = now;
    if (state.over) { draw(); return; }
    var sim = (state.mode !== 'online') || state.isHost;
    if (sim) {
      if (state.mode === 'solo') aiControl(dt);
      moveToward(state.p1);
      // Solo: p2 is fully AI-driven (aiControl owns tx/ty and position).
      // Running moveToward on it too pulls it back to a stale target → vibration.
      if (state.mode !== 'solo') moveToward(state.p2);
      clampMallets();
      acc += dt;
      var step = 1 / 120;
      while (acc >= step) { if (stepPhysics(step)) break; acc -= step; }
      refereeDeadPuck(dt);
      if (state.mode === 'online' && state.roomId && socket) {
        state.netTick++;
        if (state.netTick % 3 === 0) {
          socket.emit('air_state', { room_id: state.roomId,
            puck: { x: +state.puck.x.toFixed(4), y: +state.puck.y.toFixed(4), vx: +state.puck.vx.toFixed(3), vy: +state.puck.vy.toFixed(3) },
            p1: { x: +state.p1.x.toFixed(4), y: +state.p1.y.toFixed(4) },
            p2: { x: +state.p2.x.toFixed(4), y: +state.p2.y.toFixed(4) } });
        }
      }
    } else {
      state.puck.x += state.puck.vx * dt; state.puck.y += state.puck.vy * dt;
      moveToward(state.p1 === myMallet() ? state.p1 : state.p2);
    }
    draw();
  }

  function myMallet() { return state.player === 0 ? state.p1 : state.p2; }

  function moveToward(m) {
    var dx = (m.tx || m.x) - m.x, dy = (m.ty || m.y) - m.y;
    m.vx = dx * 18; m.vy = dy * 18;
    m.x += dx * 0.45; m.y += dy * 0.45;
  }

  var pointers = {};
  function toNorm(e) {
    var rect = canvas.getBoundingClientRect();
    return { x: (e.clientX - rect.left) / rect.width, y: (e.clientY - rect.top) / rect.width };
  }
  function malletForPoint(n) {
    if (state.mode === 'local') return (n.y > H / 2) ? state.p1 : state.p2;
    if (state.mode === 'online' && !state.isHost) return state.p2;
    return state.p1;
  }
  canvas.addEventListener('pointerdown', function (e) {
    e.preventDefault();
    try { canvas.setPointerCapture(e.pointerId); } catch (err) {}
    var n = toNorm(e);
    var m = malletForPoint(n);
    pointers[e.pointerId] = m;
    canvas.classList.add('air-dragging');
    m.tx = Math.max(0.03, Math.min(W - 0.03, n.x));
    m.ty = Math.max(0.03, Math.min(H - 0.03, n.y));
    pushInput();
  });
  canvas.addEventListener('pointermove', function (e) {
    var m = pointers[e.pointerId];
    var n = toNorm(e);
    if (m) {
      e.preventDefault();
      m.tx = Math.max(0.03, Math.min(W - 0.03, n.x));
      m.ty = Math.max(0.03, Math.min(H - 0.03, n.y));
      pushInput();
      return;
    }
    // Desktop hover-follow: move mallet with cursor, no click needed.
    // Touch/pen still require drag; local 2P keeps click-to-grab (one mouse).
    if (e.pointerType === 'mouse' && state.mode !== 'local' && !state.over) {
      var h = malletForPoint(n);
      h.tx = Math.max(0.03, Math.min(W - 0.03, n.x));
      h.ty = Math.max(0.03, Math.min(H - 0.03, n.y));
      pushInput();
    }
  });
  function endPointer(e) {
    delete pointers[e.pointerId];
    if (Object.keys(pointers).length === 0) canvas.classList.remove('air-dragging');
  }
  canvas.addEventListener('pointerup', endPointer);
  canvas.addEventListener('pointercancel', endPointer);
  canvas.addEventListener('pointerleave', endPointer);

  function pushInput() {
    if (state.mode !== 'online' || state.isHost || !socket || !state.roomId) return;
    var now = Date.now();
    if (now - state.inputTick < 30) return;
    state.inputTick = now;
    var m = state.p2;
    socket.emit('air_input', { room_id: state.roomId, x: m.tx / W * 2 - 1, y: m.ty / H * 2 - 1 });
  }

  function setMode(m) {
    state.mode = m; resetMatch();
    ['solo', 'local', 'online'].forEach(function (k) {
      var b = document.getElementById('tab-' + k);
      if (b) b.className = 'ew-btn' + (k === m ? '' : '--outline') + ' ew-btn--sm mode-tab';
    });
    var locked = applySoloGate();
    document.getElementById('solo-difficulty-panel').style.display = (m === 'solo' && !locked) ? 'flex' : 'none';
    document.getElementById('online-panel').style.display = m === 'online' ? 'block' : 'none';
    document.getElementById('score-label-p1').textContent = m === 'local' ? 'PLAYER 1' : 'YOU';
    document.getElementById('score-label-p2').textContent = m === 'local' ? 'PLAYER 2' : (m === 'online' ? 'OPPONENT' : 'CPU');
    if (m === 'online') {
      var r = new URLSearchParams(window.location.search).get('room');
      if (r) joinRoom(r.trim().slice(0, 32));
      else setStatus('Create or join a room.');
    }
  }

  function joinRoom(id) {
    state.roomId = id;
    document.getElementById('room-code-input').value = id;
    if (socket) socket.emit('join_air_room', { room_id: id, bond_id: new URLSearchParams(window.location.search).get('bond_id') || undefined });
    setStatus('Joined room ' + id + '. Waiting…');
  }

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-local').addEventListener('click', function () { setMode('local'); });
  document.getElementById('tab-online').addEventListener('click', function () { setMode('online'); });
  var gateDuel = document.getElementById('solo-gate-duel');
  if (gateDuel) gateDuel.addEventListener('click', function () { document.getElementById('tab-online').click(); });
  document.querySelectorAll('.air-diff-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      state.difficulty = b.dataset.diff;
      document.querySelectorAll('.air-diff-btn').forEach(function (x) { x.className = 'ew-btn--outline ew-btn--sm air-diff-btn'; });
      b.className = 'ew-btn ew-btn--sm air-diff-btn';
      resetMatch();
    });
  });
  document.getElementById('air-restart-btn').addEventListener('click', function () {
    if (state.mode === 'online' && socket && state.roomId) socket.emit('air_restart', { room_id: state.roomId });
    resetMatch();
  });
  document.getElementById('air-next-round-btn').addEventListener('click', function () {
    if (state.mode === 'online' && socket && state.roomId) socket.emit('air_restart', { room_id: state.roomId });
    resetMatch();
  });
  document.getElementById('join-room-btn').addEventListener('click', function () {
    var v = (document.getElementById('room-code-input').value || '').trim();
    if (v) joinRoom(v);
  });
  var createBtn = document.getElementById('create-room-btn');
  if (createBtn) createBtn.addEventListener('click', function () {
    joinRoom('air_' + Math.random().toString(36).slice(2, 8));
  });
  document.getElementById('copy-link-btn').addEventListener('click', function () {
    var url = window.location.origin + '/games/air-hockey?room=' + encodeURIComponent(state.roomId || document.getElementById('room-code-input').value || '');
    try { navigator.clipboard.writeText(url); setStatus('Link copied.'); } catch (e) { setStatus(url); }
  });
  document.getElementById('find-match-btn').addEventListener('click', function () {
    if (socket) { socket.emit('find_air_match', { mode: 'auto' }); setStatus('Searching…'); }
  });

  if (socket) {
    socket.on('air_room_joined', function (d) {
      state.player = d.player; state.isHost = d.is_host;
      resetMatch();
      setStatus(d.guest_name ? 'Opponent joined. Rally!' : 'Share the room code.');
    });
    socket.on('air_state', function (d) {
      if (!d) return;
      if (d.puck) { state.puck.x += (d.puck.x - state.puck.x) * 0.5; state.puck.y += (d.puck.y - state.puck.y) * 0.5; state.puck.vx = d.puck.vx || 0; state.puck.vy = d.puck.vy || 0; }
      var remote = state.isHost ? d.p2 : d.p1;
      if (remote) {
        var m = state.isHost ? state.p2 : state.p1;
        m.x += (remote.x - m.x) * 0.5; m.y += (remote.y - m.y) * 0.5;
        m.tx = m.x; m.ty = m.y;
      }
    });
    socket.on('air_input', function (d) {
      if (!d || !state.isHost) return;
      state.p2.tx = Math.max(0.03, Math.min(W - 0.03, (d.x + 1) / 2 * W));
      state.p2.ty = Math.max(0.03, Math.min(H - 0.03, (d.y + 1) / 2 * H));
    });
    socket.on('air_score_update', function (d) {
      if (d && d.scores) { state.scores = d.scores; updateScores(); resetPositions(); }
    });
    socket.on('air_result', function (d) {
      if (!d) return;
      if (d.scores) state.scores = d.scores;
      var w = d.winner;
      var meWon = w === state.player;
      if (meWon) { recordWin(); }
      else state.streak = 0;
      updateScores();
      document.getElementById('air-result-title').textContent = meWon ? 'YOU WON!' : 'YOU LOST';
      document.getElementById('air-result-overlay').style.display = 'flex';
      state.over = true;
    });
    socket.on('air_restarted', function () { resetMatch(); });
    socket.on('air_match_found', function (d) {
      state.roomId = d.room_id; state.player = d.player; state.isHost = d.is_host;
      resetMatch(); setStatus('Matched! Rally!');
    });
    socket.on('air_matchmaking_waiting', function () { setStatus('Waiting for opponent…'); });
    socket.on('air_player_left', function () {
      setStatus('Opponent left.');
      document.getElementById('air-result-title').textContent = 'OPPONENT LEFT';
      document.getElementById('air-result-overlay').style.display = 'flex';
      state.over = true;
    });
  }

  window.__air = {
    getSocketId: function () { return socket ? socket.id : null; },
    sendChallenge: function (sid) { if (socket) { socket.emit('find_air_match', { mode: 'auto' }); socket.emit('send_game_challenge', { game: 'air', target_sid: sid }); } },
    acceptChallenge: function (sid) { if (socket) socket.emit('accept_game_challenge', { game: 'air', challenger_sid: sid }); },
    declineChallenge: function (sid) { if (socket) socket.emit('decline_game_challenge', { game: 'air', challenger_sid: sid }); }
  };

  window.addEventListener('resize', sizeCanvas);
  window.addEventListener('beforeunload', function () {
    if (socket && state.roomId) socket.emit('leave_air_room', { room_id: state.roomId });
  });
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) { TARGET = 7; }
  sizeCanvas(); updateScores(); setMode(new URLSearchParams(window.location.search).get('room') ? 'online' : 'solo');
  requestAnimationFrame(loop);
})();
