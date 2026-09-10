/**
 * Dots and Boxes Engine for EchoWithin
 * Sourced & enhanced from brianclan/aigames
 * Features:
 *  - 5x5 Dots Grid (4x4 = 16 Boxes)
 *  - Solo vs AI (Easy, Normal, Hard with chain-avoidance)
 *  - Local 2-Player Pass-and-Play
 *  - Online 1v1 Duel via Socket.IO (Matchmaking Queue & Room Codes)
 *  - Web Audio synthesized line draw & box capture chimes
 *  - Offline Sync & Global/Daily/Weekly Leaderboard submission
 */

(function () {
  'use strict';

  // --- Audio Feedback (Web Audio API) ---
  let audioCtx = null;
  let isMuted = localStorage.getItem('ew_dnb_muted') === 'true';

  function getAudioCtx() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) audioCtx = new AudioContextClass();
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume().catch(() => {});
    }
    return audioCtx;
  }

  function playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.15) {
    if (isMuted) return;
    try {
      const ctx = getAudioCtx();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(gainVal, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch (_) {}
  }

  function playLineSound() {
    playTone(480, 'sine', 0.07, 0.2);
  }

  function playBoxSound() {
    playTone(587.33, 'triangle', 0.12, 0.25);
    setTimeout(() => playTone(880, 'sine', 0.2, 0.3), 80);
  }

  function playWinSound() {
    playTone(523.25, 'sine', 0.12, 0.25);
    setTimeout(() => playTone(659.25, 'sine', 0.12, 0.25), 100);
    setTimeout(() => playTone(783.99, 'sine', 0.25, 0.3), 200);
  }

  function playDrawSound() {
    playTone(330, 'sawtooth', 0.15, 0.15);
  }

  // --- Grid Dimensions (5x5 dots -> 4x4 boxes) ---
  const ROWS = 5;
  const COLS = 5;
  const TOTAL_BOXES = (ROWS - 1) * (COLS - 1); // 16

  // --- Difficulty & Ranking Scale ---
  const DIFF_MULTIPLIERS = {
    easy: 100,
    normal: 250,
    hard: 500,
    online: 750
  };

  function getStreakKey(mode, difficulty) {
    if (mode === 'online') return 'ew_dnb_streak_online';
    return `ew_dnb_streak_${difficulty || 'normal'}`;
  }

  function getSavedStreak(mode, difficulty) {
    if (mode === 'local') return 0;
    return parseInt(localStorage.getItem(getStreakKey(mode, difficulty)) || '0', 10);
  }

  function setSavedStreak(mode, difficulty, val) {
    if (mode === 'local') return;
    localStorage.setItem(getStreakKey(mode, difficulty), String(val));
  }

  function getRankedScoreKey() {
    return 'ew_dnb_ranked_score';
  }

  function getSavedRankedScore() {
    return parseInt(localStorage.getItem(getRankedScoreKey()) || '0', 10);
  }

  function addRankedScore(points) {
    const next = getSavedRankedScore() + points;
    localStorage.setItem(getRankedScoreKey(), String(next));
    return next;
  }

  // --- Game State ---
  const state = {
    mode: 'solo', // 'solo' | 'local' | 'online'
    hEdges: Array.from({ length: ROWS }, () => Array(COLS - 1).fill(null)),
    vEdges: Array.from({ length: ROWS - 1 }, () => Array(COLS).fill(null)),
    boxes: Array.from({ length: ROWS - 1 }, () => Array(COLS - 1).fill(null)),
    turn: 0, // 0 = Player 1 (#e06a3b), 1 = Player 2 (#eab308)
    scores: [0, 0],
    difficulty: 'normal', // 'easy' | 'normal' | 'hard'
    isGameOver: false,
    winStreak: getSavedStreak('solo', 'normal'),
    totalWins: parseInt(localStorage.getItem('ew_dnb_total_wins') || '0', 10),
    isCpuThinking: false,

    // Hover state
    hoverEdge: null, // { type: 'h'|'v', row: int, col: int }

    // Online
    socket: null,
    roomId: null,
    isHost: false,
    myPlayer: 0,
    opponentJoined: false,
    opponentName: 'Opponent',
    isSearching: false
  };

  // --- Canvas Setup ---
  let canvas, ctx;

  function initCanvas() {
    canvas = document.getElementById('dnb-canvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
  }

  function resizeCanvas() {
    if (!canvas) return;
    const parentWidth = canvas.parentElement ? canvas.parentElement.clientWidth : 520;
    const size = Math.min(parentWidth - 16, 500);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(size * dpr);
    canvas.height = Math.floor(size * dpr);
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  const W = () => (canvas ? parseFloat(canvas.style.width) || 500 : 500);
  const PAD = () => 36;
  const SPACING = () => (W() - PAD() * 2) / (COLS - 1);

  // --- Storage & Offline Sync ---
  const STORAGE_PENDING_SYNC = 'ew_dnb_pending_sync';
  const STORAGE_GUEST_TOKEN = 'ew_arcade_guest_token';

  function getGuestToken() {
    let token = localStorage.getItem(STORAGE_GUEST_TOKEN);
    if (!token) {
      token = 'gst_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
      localStorage.setItem(STORAGE_GUEST_TOKEN, token);
    }
    return token;
  }

  function queuePendingSync(category, score, metadata = {}) {
    try {
      const items = JSON.parse(localStorage.getItem(STORAGE_PENDING_SYNC) || '[]');
      items.push({
        game: 'dots_and_boxes',
        category,
        score,
        metadata: metadata || {},
        timestamp: new Date().toISOString()
      });
      localStorage.setItem(STORAGE_PENDING_SYNC, JSON.stringify(items));
    } catch (_) {}
  }

  function clearPendingSync(category, score) {
    try {
      let items = JSON.parse(localStorage.getItem(STORAGE_PENDING_SYNC) || '[]');
      items = items.filter(it => !(it.category === category && it.score === score));
      localStorage.setItem(STORAGE_PENDING_SYNC, JSON.stringify(items));
    } catch (_) {}
  }

  async function submitArcadeScore(category, score, metadata = {}) {
    if (!score || score <= 0) return;
    if (state.mode === 'local') return; // Strict local isolation
    try {
      if (!navigator.onLine) {
        queuePendingSync(category, score, metadata);
        return;
      }
      const token = getGuestToken();
      const res = await fetch('/api/games/leaderboard/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          game: 'dots_and_boxes',
          category,
          score,
          metadata,
          guest_token: token
        })
      });
      if (res.ok) {
        clearPendingSync(category, score);
        if (typeof window.fetchLeaderboard === 'function') {
          window.fetchLeaderboard();
        }
      } else {
        queuePendingSync(category, score, metadata);
      }
    } catch (_) {
      queuePendingSync(category, score, metadata);
    }
  }

  async function flushPendingSync() {
    if (!navigator.onLine) return;
    try {
      const raw = localStorage.getItem(STORAGE_PENDING_SYNC);
      if (!raw) return;
      const items = JSON.parse(raw);
      if (!Array.isArray(items) || items.length === 0) return;
      for (const item of items) {
        if (item.game === 'dots_and_boxes') {
          await submitArcadeScore(item.category, item.score, item.metadata || {});
        }
      }
    } catch (_) {}
  }
  window.addEventListener('online', flushPendingSync);

  // --- Logic Helpers ---
  function isBoxComplete(r, c) {
    return (
      state.hEdges[r][c] !== null &&
      state.hEdges[r + 1][c] !== null &&
      state.vEdges[r][c] !== null &&
      state.vEdges[r][c + 1] !== null
    );
  }

  function countBoxEdges(r, c) {
    let count = 0;
    if (state.hEdges[r][c] !== null) count++;
    if (state.hEdges[r + 1][c] !== null) count++;
    if (state.vEdges[r][c] !== null) count++;
    if (state.vEdges[r][c + 1] !== null) count++;
    return count;
  }

  // --- Input Detection ---
  function getEdgeFromCoords(clientX, clientY) {
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const x = (clientX - rect.left) * (W() / rect.width);
    const y = (clientY - rect.top) * (W() / rect.height);

    const pad = PAD();
    const sp = SPACING();

    const gx = x - pad;
    const gy = y - pad;

    const colFrac = gx / sp;
    const rowFrac = gy / sp;

    // Find nearest horizontal edge (r: round, c: floor)
    const hr = Math.round(rowFrac);
    const hc = Math.floor(colFrac);

    // Find nearest vertical edge (r: floor, c: round)
    const vr = Math.floor(rowFrac);
    const vc = Math.round(colFrac);

    const distH = Math.abs(rowFrac - hr) * sp;
    const distV = Math.abs(colFrac - vc) * sp;

    const threshold = sp * 0.35; // 35% of cell width

    if (distH < distV && distH < threshold) {
      if (hr >= 0 && hr < ROWS && hc >= 0 && hc < COLS - 1) {
        return { type: 'h', row: hr, col: hc };
      }
    } else if (distV < threshold) {
      if (vr >= 0 && vr < ROWS - 1 && vc >= 0 && vc < COLS) {
        return { type: 'v', row: vr, col: vc };
      }
    }
    return null;
  }

  function handleLineClick(edge) {
    if (!edge || state.isGameOver || state.isCpuThinking) return;

    // Check if already drawn
    if (edge.type === 'h' && state.hEdges[edge.row][edge.col] !== null) return;
    if (edge.type === 'v' && state.vEdges[edge.row][edge.col] !== null) return;

    if (state.mode === 'online') {
      if (!state.opponentJoined || state.turn !== state.myPlayer) return;
      if (state.socket && state.roomId) {
        state.socket.emit('dnb_line', {
          room_id: state.roomId,
          type: edge.type,
          row: edge.row,
          col: edge.col
        });
      }
      return;
    }

    if (state.mode === 'solo' && state.turn !== 0) return;

    applyLine(edge.type, edge.row, edge.col, state.turn);
  }

  function applyLine(type, r, c, player) {
    if (type === 'h') {
      state.hEdges[r][c] = player;
    } else {
      state.vEdges[r][c] = player;
    }
    playLineSound();

    // Check newly completed boxes
    const completed = [];
    if (type === 'h') {
      if (r > 0 && state.boxes[r - 1][c] === null && isBoxComplete(r - 1, c)) {
        state.boxes[r - 1][c] = player;
        completed.push({ r: r - 1, c });
      }
      if (r < ROWS - 1 && state.boxes[r][c] === null && isBoxComplete(r, c)) {
        state.boxes[r][c] = player;
        completed.push({ r, c });
      }
    } else {
      if (c > 0 && state.boxes[r][c - 1] === null && isBoxComplete(r, c - 1)) {
        state.boxes[r][c - 1] = player;
        completed.push({ r, c: c - 1 });
      }
      if (c < COLS - 1 && state.boxes[r][c] === null && isBoxComplete(r, c)) {
        state.boxes[r][c] = player;
        completed.push({ r, c });
      }
    }

    if (completed.length > 0) {
      state.scores[player] += completed.length;
      playBoxSound();
      // Keep turn!
    } else {
      // Switch turn
      state.turn = 1 - state.turn;
    }

    // Check Game Over
    const totalFilled = state.scores[0] + state.scores[1];
    if (totalFilled === TOTAL_BOXES) {
      handleGameOver();
    } else {
      updateScoreboard();
      updateTurnDisplay();
      if (state.mode === 'solo' && state.turn === 1) {
        triggerCpuTurn();
      }
    }
  }

  function handleGameOver() {
    state.isGameOver = true;
    const isDraw = state.scores[0] === state.scores[1];
    const winner = isDraw ? -1 : state.scores[0] > state.scores[1] ? 0 : 1;

    if (isDraw) {
      playDrawSound();
    } else {
      playWinSound();

      if (state.mode === 'local') {
        // Local 2-Player mode is pass-and-play only.
        // Never submit to global leaderboards or alter ranked stats.
        updateScoreboard();
        updateTurnDisplay();
        showResultModal(isDraw, winner);
        return;
      }

      let didLocalWin = false;
      if (state.mode === 'solo') didLocalWin = winner === 0;
      else if (state.mode === 'online') didLocalWin = winner === state.myPlayer;

      const diffKey = state.mode === 'online' ? 'online' : state.difficulty;
      if (didLocalWin) {
        state.winStreak++;
        setSavedStreak(state.mode, state.difficulty, state.winStreak);
        state.totalWins++;
        localStorage.setItem('ew_dnb_total_wins', String(state.totalWins));

        const pts = DIFF_MULTIPLIERS[diffKey] || 100;
        const newRankedScore = addRankedScore(pts);

        const meta = { difficulty: diffKey, mode: state.mode, multiplier: pts };
        submitArcadeScore('win_streak', state.winStreak, meta);
        submitArcadeScore('total_wins', state.totalWins, meta);
        submitArcadeScore('ranked_score', newRankedScore, meta);
      } else {
        state.winStreak = 0;
        setSavedStreak(state.mode, state.difficulty, 0);
      }
    }

    updateScoreboard();
    updateTurnDisplay();
    showResultModal(isDraw, winner);
  }

  // --- Rendering Loop ---
  function render() {
    if (!ctx) return;
    const w = W();
    const pad = PAD();
    const sp = SPACING();

    ctx.clearRect(0, 0, w, w);

    // Board container
    ctx.fillStyle = '#1e2638';
    ctx.beginPath();
    ctx.roundRect(0, 0, w, w, 12);
    ctx.fill();

    // 1. Draw Completed Boxes
    for (let r = 0; r < ROWS - 1; r++) {
      for (let c = 0; c < COLS - 1; c++) {
        const owner = state.boxes[r][c];
        const bx = pad + c * sp;
        const by = pad + r * sp;
        if (owner !== null) {
          ctx.fillStyle = owner === 0 ? 'rgba(224, 106, 59, 0.28)' : 'rgba(234, 179, 8, 0.28)';
          ctx.beginPath();
          ctx.roundRect(bx + 3, by + 3, sp - 6, sp - 6, 6);
          ctx.fill();

          // Owner initial badge
          ctx.fillStyle = owner === 0 ? '#e06a3b' : '#eab308';
          ctx.font = `bold ${Math.floor(sp * 0.42)}px sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(owner === 0 ? '1' : '2', bx + sp / 2, by + sp / 2);
        } else {
          // Subtle box background
          ctx.fillStyle = '#161d2d';
          ctx.beginPath();
          ctx.roundRect(bx + 4, by + 4, sp - 8, sp - 8, 6);
          ctx.fill();
        }
      }
    }

    // 2. Draw Hover Preview Line
    if (!state.isGameOver && !state.isCpuThinking && state.hoverEdge) {
      const h = state.hoverEdge;
      ctx.save();
      ctx.lineWidth = 4;
      ctx.strokeStyle = state.turn === 0 ? 'rgba(224, 106, 59, 0.45)' : 'rgba(234, 179, 8, 0.45)';
      ctx.lineCap = 'round';
      ctx.beginPath();
      if (h.type === 'h') {
        ctx.moveTo(pad + h.col * sp, pad + h.row * sp);
        ctx.lineTo(pad + (h.col + 1) * sp, pad + h.row * sp);
      } else {
        ctx.moveTo(pad + h.col * sp, pad + h.row * sp);
        ctx.lineTo(pad + h.col * sp, pad + (h.row + 1) * sp);
      }
      ctx.stroke();
      ctx.restore();
    }

    // 3. Draw Drawn Edges
    // Horizontal edges
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS - 1; c++) {
        const owner = state.hEdges[r][c];
        const x1 = pad + c * sp;
        const y1 = pad + r * sp;
        const x2 = pad + (c + 1) * sp;
        const y2 = y1;

        ctx.lineWidth = owner !== null ? 5 : 2;
        ctx.strokeStyle = owner !== null ? (owner === 0 ? '#e06a3b' : '#eab308') : 'rgba(255, 255, 255, 0.08)';
        ctx.lineCap = 'round';
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }
    }

    // Vertical edges
    for (let r = 0; r < ROWS - 1; r++) {
      for (let c = 0; c < COLS; c++) {
        const owner = state.vEdges[r][c];
        const x1 = pad + c * sp;
        const y1 = pad + r * sp;
        const x2 = x1;
        const y2 = pad + (r + 1) * sp;

        ctx.lineWidth = owner !== null ? 5 : 2;
        ctx.strokeStyle = owner !== null ? (owner === 0 ? '#e06a3b' : '#eab308') : 'rgba(255, 255, 255, 0.08)';
        ctx.lineCap = 'round';
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
      }
    }

    // 4. Draw Dots on top of edges
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const x = pad + c * sp;
        const y = pad + r * sp;
        ctx.fillStyle = '#f8fafc';
        ctx.beginPath();
        ctx.arc(x, y, 6, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#334155';
        ctx.beginPath();
        ctx.arc(x, y, 2.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    requestAnimationFrame(render);
  }

  // --- Solo AI (Easy, Normal, Hard) ---
  function getAvailableEdges() {
    const moves = [];
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS - 1; c++) {
        if (state.hEdges[r][c] === null) moves.push({ type: 'h', row: r, col: c });
      }
    }
    for (let r = 0; r < ROWS - 1; r++) {
      for (let c = 0; c < COLS; c++) {
        if (state.vEdges[r][c] === null) moves.push({ type: 'v', row: r, col: c });
      }
    }
    return moves;
  }

  function triggerCpuTurn() {
    if (state.isGameOver) return;
    state.isCpuThinking = true;
    const thinkingEl = document.getElementById('dnb-thinking-indicator');
    if (thinkingEl) thinkingEl.style.display = 'block';

    const delay = state.difficulty === 'easy' ? 400 : state.difficulty === 'hard' ? 650 : 500;
    setTimeout(() => {
      if (state.isGameOver) return;
      state.isCpuThinking = false;
      if (thinkingEl) thinkingEl.style.display = 'none';

      const edge = getCpuMove();
      if (edge) {
        applyLine(edge.type, edge.row, edge.col, 1);
      }
    }, delay);
  }

  function getCpuMove() {
    const available = getAvailableEdges();
    if (available.length === 0) return null;

    // 1. Any move that immediately completes a box?
    const winningMoves = [];
    for (const m of available) {
      if (m.type === 'h') {
        if (m.row > 0 && countBoxEdges(m.row - 1, m.col) === 3) winningMoves.push(m);
        if (m.row < ROWS - 1 && countBoxEdges(m.row, m.col) === 3) winningMoves.push(m);
      } else {
        if (m.col > 0 && countBoxEdges(m.row, m.col - 1) === 3) winningMoves.push(m);
        if (m.col < COLS - 1 && countBoxEdges(m.row, m.col) === 3) winningMoves.push(m);
      }
    }
    if (winningMoves.length > 0) {
      return winningMoves[Math.floor(Math.random() * winningMoves.length)];
    }

    if (state.difficulty === 'easy') {
      return available[Math.floor(Math.random() * available.length)];
    }

    // 2. Safe moves: avoid giving the opponent a 3-sided box
    const safeMoves = [];
    for (const m of available) {
      let createsThirdEdge = false;
      if (m.type === 'h') {
        if (m.row > 0 && countBoxEdges(m.row - 1, m.col) === 2) createsThirdEdge = true;
        if (m.row < ROWS - 1 && countBoxEdges(m.row, m.col) === 2) createsThirdEdge = true;
      } else {
        if (m.col > 0 && countBoxEdges(m.row, m.col - 1) === 2) createsThirdEdge = true;
        if (m.col < COLS - 1 && countBoxEdges(m.row, m.col) === 2) createsThirdEdge = true;
      }
      if (!createsThirdEdge) safeMoves.push(m);
    }

    if (safeMoves.length > 0) {
      return safeMoves[Math.floor(Math.random() * safeMoves.length)];
    }

    // If forced to give away, pick a random remaining move
    return available[Math.floor(Math.random() * available.length)];
  }

  // --- UI Updates ---
  function updateScoreboard() {
    const elP1 = document.getElementById('score-val-p1');
    const elP2 = document.getElementById('score-val-p2');
    const elStreak = document.getElementById('live-streak');
    const labelP1 = document.getElementById('score-label-p1');
    const labelP2 = document.getElementById('score-label-p2');

    if (elP1) elP1.textContent = state.scores[0];
    if (elP2) elP2.textContent = state.scores[1];
    if (elStreak) elStreak.textContent = state.winStreak;

    if (state.mode === 'solo') {
      if (labelP1) labelP1.textContent = 'YOU (AMBER)';
      if (labelP2) labelP2.textContent = 'CPU (GOLD)';
    } else if (state.mode === 'online') {
      const myIsP1 = state.myPlayer === 0;
      if (labelP1) labelP1.textContent = myIsP1 ? 'YOU (AMBER)' : `${state.opponentName.toUpperCase()} (AMBER)`;
      if (labelP2) labelP2.textContent = !myIsP1 ? 'YOU (GOLD)' : `${state.opponentName.toUpperCase()} (GOLD)`;
    } else {
      if (labelP1) labelP1.textContent = 'PLAYER 1 (AMBER)';
      if (labelP2) labelP2.textContent = 'PLAYER 2 (GOLD)';
    }
  }

  function updateTurnDisplay() {
    const turnBadge = document.getElementById('dnb-turn-badge');
    const turnText = document.getElementById('dnb-turn-text');
    if (!turnBadge || !turnText) return;

    turnBadge.setAttribute('data-turn', state.turn === 0 ? 'p1' : 'p2');
    if (state.mode === 'online') {
      const isMyTurn = state.turn === state.myPlayer;
      turnText.textContent = isMyTurn ? 'YOUR TURN' : "OPPONENT'S TURN";
    } else if (state.mode === 'solo') {
      turnText.textContent = state.turn === 0 ? 'YOUR TURN' : 'CPU THINKING...';
    } else {
      turnText.textContent = state.turn === 0 ? "PLAYER 1'S TURN" : "PLAYER 2'S TURN";
    }
  }

  function showResultModal(draw, winner) {
    const overlay = document.getElementById('dnb-result-overlay');
    const title = document.getElementById('dnb-result-title');
    const subtitle = document.getElementById('dnb-result-subtitle');
    if (!overlay || !title || !subtitle) return;

    if (draw) {
      title.textContent = 'ROUND DRAW';
      subtitle.textContent = `Both players completed ${state.scores[0]} boxes.`;
    } else {
      let winText = 'PLAYER 1 WON!';
      if (state.mode === 'solo') {
        winText = winner === 0 ? 'YOU WON!' : 'CPU WON';
      } else if (state.mode === 'online') {
        winText = winner === state.myPlayer ? 'YOU WON!' : `${state.opponentName.toUpperCase()} WON`;
      } else {
        winText = winner === 0 ? 'PLAYER 1 (AMBER) WON' : 'PLAYER 2 (GOLD) WON';
      }
      title.textContent = winText;
      subtitle.textContent = `Completed ${state.scores[winner]} out of ${TOTAL_BOXES} boxes!`;
    }
    setTimeout(() => { overlay.style.display = 'flex'; }, 400);
  }

  function resetGame() {
    state.hEdges = Array.from({ length: ROWS }, () => Array(COLS - 1).fill(null));
    state.vEdges = Array.from({ length: ROWS - 1 }, () => Array(COLS).fill(null));
    state.boxes = Array.from({ length: ROWS - 1 }, () => Array(COLS - 1).fill(null));
    state.turn = 0;
    state.scores = [0, 0];
    state.isGameOver = false;
    state.isCpuThinking = false;
    state.hoverEdge = null;

    const overlay = document.getElementById('dnb-result-overlay');
    if (overlay) overlay.style.display = 'none';

    updateScoreboard();
    updateTurnDisplay();
  }

  function setMode(mode) {
    state.mode = mode;
    const tabSolo = document.getElementById('tab-solo');
    const tabLocal = document.getElementById('tab-local');
    const tabOnline = document.getElementById('tab-online');
    const soloPanel = document.getElementById('solo-difficulty-panel');
    const onlinePanel = document.getElementById('online-panel');

    [tabSolo, tabLocal, tabOnline].forEach(btn => {
      if (btn) {
        btn.classList.remove('ew-btn');
        btn.classList.add('ew-btn--outline');
      }
    });

    if (mode === 'solo' && tabSolo) {
      tabSolo.classList.remove('ew-btn--outline');
      tabSolo.classList.add('ew-btn');
      if (soloPanel) soloPanel.style.display = 'flex';
      if (onlinePanel) onlinePanel.style.display = 'none';
      state.winStreak = getSavedStreak('solo', state.difficulty);
    } else if (mode === 'local' && tabLocal) {
      tabLocal.classList.remove('ew-btn--outline');
      tabLocal.classList.add('ew-btn');
      if (soloPanel) soloPanel.style.display = 'none';
      if (onlinePanel) onlinePanel.style.display = 'none';
      state.winStreak = 0;
    } else if (mode === 'online' && tabOnline) {
      tabOnline.classList.remove('ew-btn--outline');
      tabOnline.classList.add('ew-btn');
      if (soloPanel) soloPanel.style.display = 'none';
      if (onlinePanel) onlinePanel.style.display = 'block';
      state.winStreak = getSavedStreak('online', 'online');
      initOnlineSocket();
    }
    resetGame();
  }

  // --- Online Socket.IO Handlers ---
  function initOnlineSocket() {
    if (state.socket) return;
    if (typeof io === 'undefined') return;

    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('dnb_room_joined', data => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.myPlayer = data.player;
      state.opponentJoined = !!data.guest_name;
      state.opponentName = data.is_host ? (data.guest_name || 'Opponent') : (data.host_name || 'Host');

      const roomStatus = document.getElementById('room-status');
      if (roomStatus) {
        roomStatus.textContent = state.opponentJoined
          ? `Playing vs ${state.opponentName} (You are ${state.myPlayer === 0 ? 'Amber' : 'Gold'})`
          : `Waiting for opponent in room ${state.roomId}...`;
      }
      updateScoreboard();
      updateTurnDisplay();
    });

    state.socket.on('dnb_line_drawn', data => {
      if (data.type === 'h') {
        state.hEdges[data.row][data.col] = data.player;
      } else {
        state.vEdges[data.row][data.col] = data.player;
      }

      data.completed_boxes.forEach(b => {
        state.boxes[b.row][b.col] = b.owner;
      });

      state.scores = data.scores;
      state.turn = data.next_turn;
      playLineSound();
      if (data.completed_boxes.length > 0) playBoxSound();

      updateScoreboard();
      updateTurnDisplay();

      if (data.is_game_over) {
        state.isGameOver = true;
        if (data.winner === -1) {
          playDrawSound();
          showResultModal(true, -1);
        } else {
          playWinSound();
          if (data.winner === state.myPlayer) {
            state.winStreak++;
            state.totalWins++;
            submitArcadeScore('win_streak', state.winStreak);
            submitArcadeScore('total_wins', state.totalWins);
          } else {
            state.winStreak = 0;
          }
          showResultModal(false, data.winner);
        }
      }
    });

    state.socket.on('dnb_restarted', data => {
      resetGame();
      state.turn = data.turn || 0;
      updateTurnDisplay();
    });

    state.socket.on('dnb_player_left', () => {
      state.opponentJoined = false;
      const roomStatus = document.getElementById('room-status');
      if (roomStatus) {
        roomStatus.textContent = 'Opponent disconnected. Waiting for a player...';
      }
    });

    state.socket.on('dnb_match_found', data => {
      state.isSearching = false;
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'Find Match';
        findBtn.disabled = false;
      }
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.myPlayer = data.player;
      state.opponentJoined = true;
      state.opponentName = data.is_host ? data.guest_name : data.host_name;

      const roomStatus = document.getElementById('room-status');
      if (roomStatus) {
        roomStatus.textContent = `Match Found! Playing vs ${state.opponentName} (You are ${state.myPlayer === 0 ? 'Amber' : 'Gold'})`;
      }
      resetGame();
    });

    state.socket.on('dnb_matchmaking_waiting', () => {
      state.isSearching = true;
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) findBtn.textContent = 'Searching... (Cancel)';
      const roomStatus = document.getElementById('room-status');
      if (roomStatus) roomStatus.textContent = 'Searching for an opponent...';
    });

    state.socket.on('dnb_matchmaking_cancelled', () => {
      state.isSearching = false;
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) findBtn.textContent = 'Find Match';
      const roomStatus = document.getElementById('room-status');
      if (roomStatus) roomStatus.textContent = 'Matchmaking cancelled.';
    });

    const urlParams = new URLSearchParams(window.location.search);
    const roomParam = urlParams.get('room');
    if (roomParam) {
      joinRoom(roomParam);
    }
  }

  function joinRoom(roomId) {
    if (!state.socket) initOnlineSocket();
    if (!state.socket || !roomId) return;
    state.socket.emit('join_dnb_room', { room_id: roomId });
    const input = document.getElementById('room-code-input');
    if (input) input.value = roomId;
  }

  // --- Setup Listeners ---
  function setupListeners() {
    if (canvas) {
      canvas.addEventListener('click', e => {
        const edge = getEdgeFromCoords(e.clientX, e.clientY);
        if (edge) handleLineClick(edge);
      });

      canvas.addEventListener('mousemove', e => {
        state.hoverEdge = getEdgeFromCoords(e.clientX, e.clientY);
      });

      canvas.addEventListener('mouseleave', () => {
        state.hoverEdge = null;
      });

      canvas.addEventListener('touchstart', e => {
        e.preventDefault();
        const touch = e.touches[0];
        const edge = getEdgeFromCoords(touch.clientX, touch.clientY);
        if (edge) handleLineClick(edge);
      }, { passive: false });
    }

    const restartBtn = document.getElementById('dnb-restart-btn');
    if (restartBtn) {
      restartBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('dnb_restart', { room_id: state.roomId });
        } else {
          resetGame();
        }
      });
    }

    const nextRoundBtn = document.getElementById('dnb-next-round-btn');
    if (nextRoundBtn) {
      nextRoundBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('dnb_restart', { room_id: state.roomId });
        } else {
          resetGame();
        }
      });
    }

    const muteToggleBtn = document.getElementById('mute-toggle-btn');
    if (muteToggleBtn) {
      muteToggleBtn.textContent = isMuted ? 'Unmute Sound' : 'Mute Sound';
      muteToggleBtn.addEventListener('click', () => {
        isMuted = !isMuted;
        localStorage.setItem('ew_dnb_muted', isMuted ? 'true' : 'false');
        muteToggleBtn.textContent = isMuted ? 'Unmute Sound' : 'Mute Sound';
      });
    }

    // Tabs
    const tabSolo = document.getElementById('tab-solo');
    const tabLocal = document.getElementById('tab-local');
    const tabOnline = document.getElementById('tab-online');
    if (tabSolo) tabSolo.addEventListener('click', () => setMode('solo'));
    if (tabLocal) tabLocal.addEventListener('click', () => setMode('local'));
    if (tabOnline) tabOnline.addEventListener('click', () => setMode('online'));

    // Difficulties
    document.querySelectorAll('.dnb-diff-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.difficulty = btn.getAttribute('data-diff');
        document.querySelectorAll('.dnb-diff-btn').forEach(b => {
          b.classList.remove('ew-btn');
          b.classList.add('ew-btn--outline');
        });
        btn.classList.remove('ew-btn--outline');
        btn.classList.add('ew-btn');
        if (state.mode === 'solo') {
          state.winStreak = getSavedStreak('solo', state.difficulty);
        }
        resetGame();
      });
    });

    // Online Controls
    const findMatchBtn = document.getElementById('find-match-btn');
    if (findMatchBtn) {
      findMatchBtn.addEventListener('click', () => {
        if (!state.socket) initOnlineSocket();
        if (!state.socket) return;
        if (state.isSearching) {
          state.socket.emit('cancel_dnb_matchmaking');
        } else {
          state.socket.emit('find_dnb_match');
        }
      });
    }

    const joinRoomBtn = document.getElementById('join-room-btn');
    const roomCodeInput = document.getElementById('room-code-input');
    if (joinRoomBtn && roomCodeInput) {
      joinRoomBtn.addEventListener('click', () => {
        const code = roomCodeInput.value.trim();
        if (code) joinRoom(code);
      });
    }

    const copyLinkBtn = document.getElementById('copy-link-btn');
    if (copyLinkBtn) {
      copyLinkBtn.addEventListener('click', () => {
        if (!state.roomId) {
          alert('Join or create a room first.');
          return;
        }
        const url = `${window.location.origin}/games/dots-and-boxes?room=${encodeURIComponent(state.roomId)}`;
        navigator.clipboard.writeText(url).then(() => {
          const orig = copyLinkBtn.textContent;
          copyLinkBtn.textContent = 'Copied!';
          setTimeout(() => { copyLinkBtn.textContent = orig; }, 1500);
        }).catch(() => {});
      });
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initCanvas();
    setupListeners();
    resetGame();
    flushPendingSync();
    requestAnimationFrame(render);

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('room')) {
      setMode('online');
    }
  });

  // Export for testing
  window.__dnb = {
    getState: () => ({ ...state }),
    applyLine,
    resetGame,
    setMode,
    isBoxComplete
  };
})();
