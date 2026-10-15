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
    serveTimer: 0, aiTick: 0, netTick: 0, inputTick: 0
  };
  var AI = {
    easy: { speed: 0.9, react: 12, jitter: 0.09 },
    normal: { speed: 1.5, react: 6, jitter: 0.045 },
    hard: { speed: 2.2, react: 2, jitter: 0.015 }
  };
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
    return false;
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

  function recordWin() {
    state.streak++;
    submitScore('win_streak', state.streak, { mode: state.mode });
    submitScore('total_wins', careerWins(), { mode: state.mode });
    submitScore('ranked_score', 1000 + state.streak * 100, { mode: state.mode });
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
  }

  function resetMatch() {
    state.scores = [0, 0]; state.over = false;
    resetPositions(); updateScores();
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

  function aiControl() {
    var cfg = AI[state.difficulty] || AI.normal;
    var m = state.p2;
    state.aiTick++;
    // Decide target a few times per second; move every frame so motion is smooth.
    if (state.aiTick % cfg.react === 0) {
      var p = state.puck, tx = 0.5, ty = 0.22;
      if (p.vy < 0 || p.y < H / 2) {
        tx = p.x + (p.vx * 0.25) + (Math.random() - 0.5) * cfg.jitter * 2;
        ty = Math.min(0.42, Math.max(0.12, p.y - 0.06));
      }
      m.tx = tx; m.ty = ty;
    }
    var dx = m.tx - m.x, dy = m.ty - m.y, d = Math.hypot(dx, dy) || 1;
    var step = Math.min(d, cfg.speed / 60);
    m.vx = dx / d * step * 60; m.vy = dy / d * step * 60;
    m.x += dx / d * step; m.y += dy / d * step;
  }

  var last = 0, acc = 0;
  function loop(now) {
    requestAnimationFrame(loop);
    if (!last) last = now;
    var dt = Math.min(0.1, (now - last) / 1000); last = now;
    if (state.over) { draw(); return; }
    var sim = (state.mode !== 'online') || state.isHost;
    if (sim) {
      if (state.mode === 'solo') aiControl();
      moveToward(state.p1);
      // Solo: p2 is fully AI-driven (aiControl owns tx/ty and position).
      // Running moveToward on it too pulls it back to a stale target → vibration.
      if (state.mode !== 'solo') moveToward(state.p2);
      clampMallets();
      acc += dt;
      var step = 1 / 120;
      while (acc >= step) { if (stepPhysics(step)) break; acc -= step; }
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
    if (socket) socket.emit('join_air_room', { room_id: id });
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
  document.getElementById('create-room-btn').addEventListener('click', function () {
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
