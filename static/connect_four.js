/**
 * Connect Four Engine for EchoWithin
 * Features:
 *  - 7x6 Board with animated gravity piece drop
 *  - Solo vs AI (Easy, Normal, Hard with Minimax & Alpha-Beta)
 *  - Local 2-Player Pass-and-Play
 *  - Online 1v1 Duel via Socket.IO (Matchmaking Queue & Room Codes)
 *  - Web Audio synthesized chip drop & win sounds
 *  - Offline Sync & Global/Daily/Weekly Leaderboard submission
 */

(function () {
  'use strict';

  // --- Audio Feedback ---
  let audioCtx = null;
  let isMuted = localStorage.getItem('ew_c4_muted') === 'true';

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

  function playDropSound() {
    playTone(320, 'sine', 0.06, 0.25);
    setTimeout(() => playTone(240, 'triangle', 0.08, 0.2), 30);
  }

  function playWinSound() {
    playTone(440, 'sine', 0.12, 0.25);
    setTimeout(() => playTone(554.37, 'sine', 0.12, 0.25), 100);
    setTimeout(() => playTone(659.25, 'sine', 0.25, 0.3), 200);
  }

  function playDrawSound() {
    playTone(280, 'sawtooth', 0.15, 0.15);
  }

  // --- Board Constants ---
  const ROWS = 6;
  const COLS = 7;

  // --- Difficulty & Ranking Scale ---
  const DIFF_MULTIPLIERS = {
    easy: 100,
    normal: 250,
    hard: 500,
    online: 750
  };

  function getStreakKey(mode, difficulty) {
    if (mode === 'online') return 'ew_c4_streak_online';
    return `ew_c4_streak_${difficulty || 'normal'}`;
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
    return 'ew_c4_ranked_score';
  }

  function getSavedRankedScore() {
    return parseInt(localStorage.getItem(getRankedScoreKey()) || '0', 10);
  }

  function addRankedScore(points) {
    const next = getSavedRankedScore() + points;
    localStorage.setItem(getRankedScoreKey(), String(next));
    return next;
  }

  // --- State ---
  const state = {
    mode: 'solo', // 'solo' | 'local' | 'online'
    board: Array.from({ length: ROWS }, () => Array(COLS).fill(-1)),
    turn: 0, // 0 = Player 1 (Terracotta/Amber #e06a3b), 1 = Player 2 (Gold #eab308)
    difficulty: 'normal', // 'easy' | 'normal' | 'hard'
    isGameOver: false,
    winLine: null,
    scores: [0, 0, 0], // [P1, P2, Ties]
    winStreak: getSavedStreak('solo', 'normal'),
    totalWins: parseInt(localStorage.getItem('ew_c4_total_wins') || '0', 10),

    // Animation
    animCol: -1,
    animRow: -1,
    animProgress: 0,
    animating: false,
    hoverCol: -1,

    // Online
    socket: null,
    roomId: null,
    isHost: false,
    myPlayer: 0,
    opponentJoined: false,
    opponentName: 'Opponent',
    isSearching: false,
    isCpuThinking: false
  };

  // --- Canvas Setup ---
  let canvas, ctx;

  function initCanvas() {
    canvas = document.getElementById('c4-canvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
  }

  function resizeCanvas() {
    if (!canvas) return;
    const parentWidth = canvas.parentElement ? canvas.parentElement.clientWidth : 560;
    const size = Math.min(parentWidth - 16, 560);
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(size * dpr);
    canvas.height = Math.floor((size * (6 / 7) + 50) * dpr);
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size * (6 / 7) + 50}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  const W = () => (canvas ? parseFloat(canvas.style.width) || 560 : 560);
  const H = () => (canvas ? parseFloat(canvas.style.height) || 530 : 530);
  const CELL = () => W() / COLS;
  const BOARD_X = () => 0;
  const BOARD_Y = () => 45;
  const RADIUS = () => CELL() * 0.38;

  // --- Storage & Offline Sync ---
  const STORAGE_PENDING_SYNC = 'ew_c4_pending_sync';
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
        game: 'connect_four',
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
          game: 'connect_four',
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
        if (item.game === 'connect_four') {
          await submitArcadeScore(item.category, item.score, item.metadata || {});
        }
      }
    } catch (_) {}
  }
  window.addEventListener('online', flushPendingSync);

  // --- Logic Helpers ---
  function getDropRow(col, board = state.board) {
    for (let r = ROWS - 1; r >= 0; r--) {
      if (board[r][col] === -1) return r;
    }
    return -1;
  }

  function checkWin(r, c, player, board = state.board) {
    const dirs = [[1, 0], [0, 1], [1, 1], [1, -1]];
    for (const [dr, dc] of dirs) {
      let cells = [[r, c]];
      for (const s of [1, -1]) {
        let nr = r + dr * s;
        let nc = c + dc * s;
        while (nr >= 0 && nr < ROWS && nc >= 0 && nc < COLS && board[nr][nc] === player) {
          cells.push([nr, nc]);
          nr += dr * s;
          nc += dc * s;
        }
      }
      if (cells.length >= 4) return cells;
    }
    return null;
  }

  function isDraw(board = state.board) {
    return board[0].every(v => v !== -1);
  }

  // --- Input & Animation ---
  function getColFromX(clientX) {
    if (!canvas) return -1;
    const rect = canvas.getBoundingClientRect();
    const x = (clientX - rect.left) * (W() / rect.width);
    const col = Math.floor((x - BOARD_X()) / CELL());
    return (col >= 0 && col < COLS) ? col : -1;
  }

  function dropPiece(col) {
    if (state.isGameOver || state.animating || state.isCpuThinking) return;

    if (state.mode === 'online') {
      if (!state.opponentJoined || state.turn !== state.myPlayer) return;
      if (getDropRow(col) === -1) return;
      if (state.socket && state.roomId) {
        state.socket.emit('c4_move', { room_id: state.roomId, col });
      }
      return;
    }

    if (state.mode === 'solo' && state.turn !== 0) return;

    const row = getDropRow(col);
    if (row === -1) return;

    startDropAnimation(col, row, state.turn);
  }

  function startDropAnimation(col, row, player) {
    state.animCol = col;
    state.animRow = row;
    state.animProgress = 0;
    state.animating = true;
  }

  function finishDrop() {
    const row = state.animRow;
    const col = state.animCol;
    const player = state.turn;

    state.board[row][col] = player;
    state.animating = false;
    state.animCol = -1;
    state.animRow = -1;
    state.animProgress = 0;
    playDropSound();

    const winLine = checkWin(row, col, player);
    if (winLine) {
      handleGameOver(false, player, winLine);
    } else if (isDraw()) {
      handleGameOver(true, -1);
    } else {
      state.turn = 1 - state.turn;
      updateTurnDisplay();
      if (state.mode === 'solo' && state.turn === 1) {
        triggerCpuMove();
      }
    }
  }

  function handleGameOver(draw, winner, winLine = null) {
    state.isGameOver = true;
    state.winLine = winLine;

    if (draw) {
      state.scores[2]++;
      playDrawSound();
    } else {
      state.scores[winner]++;
      playWinSound();

      if (state.mode === 'local') {
        // Local 2P mode is pass-and-play only.
        // Never submit to global leaderboards or alter ranked stats.
        updateScoreboard();
        updateTurnDisplay();
        showResultModal(draw, winner);
        return;
      }

      let didLocalWin = false;
      if (state.mode === 'solo') {
        didLocalWin = winner === 0;
      } else if (state.mode === 'online') {
        didLocalWin = winner === state.myPlayer;
      }

      const diffKey = state.mode === 'online' ? 'online' : state.difficulty;
      if (didLocalWin) {
        state.winStreak++;
        setSavedStreak(state.mode, state.difficulty, state.winStreak);
        state.totalWins++;
        localStorage.setItem('ew_c4_total_wins', String(state.totalWins));

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
    showResultModal(draw, winner);
  }

  // --- Rendering Loop ---
  function drawPiece(x, y, player, isPreview = false, isWin = false) {
    const r = RADIUS();
    const color = player === 0 ? '#e06a3b' : '#eab308';

    ctx.save();
    if (isPreview) {
      ctx.globalAlpha = 0.45;
    } else {
      ctx.shadowColor = 'rgba(0,0,0,0.3)';
      ctx.shadowBlur = 4;
      ctx.shadowOffsetY = 2;
    }

    // Radial gradient for 3D token appearance
    const g = ctx.createRadialGradient(x - r * 0.25, y - r * 0.25, r * 0.1, x, y, r);
    if (player === 0) {
      g.addColorStop(0, '#f98055');
      g.addColorStop(1, '#c95729');
    } else {
      g.addColorStop(0, '#fde047');
      g.addColorStop(1, '#ca8a04');
    }

    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();

    if (isWin) {
      ctx.lineWidth = 3.5;
      ctx.strokeStyle = '#ffffff';
      ctx.stroke();
    }

    ctx.restore();
  }

  function render(time) {
    if (!ctx) return;
    const w = W(), h = H();
    const cell = CELL();
    const bx = BOARD_X(), by = BOARD_Y();

    ctx.clearRect(0, 0, w, h);

    // Drop Preview at hover column
    if (!state.isGameOver && !state.animating && state.hoverCol >= 0 && state.hoverCol < COLS) {
      const dropRow = getDropRow(state.hoverCol);
      if (dropRow !== -1) {
        const px = bx + state.hoverCol * cell + cell / 2;
        const py = by - cell * 0.45;
        drawPiece(px, py, state.turn, true);
      }
    }

    // Board container
    ctx.fillStyle = '#1e2638';
    ctx.beginPath();
    ctx.roundRect(bx, by, cell * COLS, cell * ROWS, 12);
    ctx.fill();

    // Board slots & pieces
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const cx = bx + c * cell + cell / 2;
        const cy = by + r * cell + cell / 2;

        const val = state.board[r][c];
        if (val !== -1) {
          const isWin = state.winLine && state.winLine.some(([wr, wc]) => wr === r && wc === c);
          drawPiece(cx, cy, val, false, isWin);
        } else {
          // Empty slot background
          ctx.fillStyle = '#0f172a';
          ctx.beginPath();
          ctx.arc(cx, cy, RADIUS(), 0, Math.PI * 2);
          ctx.fill();
        }
      }
    }

    // Dropping Piece Animation
    if (state.animating && state.animCol !== -1) {
      state.animProgress += 0.09;
      if (state.animProgress >= 1) {
        finishDrop();
      } else {
        const startY = by - cell * 0.45;
        const targetY = by + state.animRow * cell + cell / 2;
        // Ease-in gravity acceleration
        const currentY = startY + (targetY - startY) * (state.animProgress * state.animProgress);
        const currentX = bx + state.animCol * cell + cell / 2;
        drawPiece(currentX, currentY, state.turn, false);
      }
    }

    requestAnimationFrame(render);
  }

  // --- Solo AI (Easy, Normal, Hard) ---
  function triggerCpuMove() {
    if (state.isGameOver) return;
    state.isCpuThinking = true;
    const thinkingEl = document.getElementById('c4-thinking-indicator');
    if (thinkingEl) thinkingEl.style.display = 'block';

    const delay = state.difficulty === 'easy' ? 400 : state.difficulty === 'hard' ? 650 : 500;
    setTimeout(() => {
      if (state.isGameOver) return;
      state.isCpuThinking = false;
      if (thinkingEl) thinkingEl.style.display = 'none';

      const col = getCpuColumn();
      if (col !== -1) {
        const row = getDropRow(col);
        if (row !== -1) {
          startDropAnimation(col, row, 1);
        }
      }
    }, delay);
  }

  function getCpuColumn() {
    const validCols = [];
    for (let c = 0; c < COLS; c++) {
      if (getDropRow(c) !== -1) validCols.push(c);
    }
    if (validCols.length === 0) return -1;

    // 1. Can CPU win immediately?
    for (const c of validCols) {
      const r = getDropRow(c);
      if (checkWin(r, c, 1)) return c;
    }

    // 2. Can player win immediately? Block it!
    for (const c of validCols) {
      const r = getDropRow(c);
      if (checkWin(r, c, 0)) return c;
    }

    if (state.difficulty === 'easy') {
      return validCols[Math.floor(Math.random() * validCols.length)];
    }

    // Normal AI: Prefer center columns and avoid setting up player wins
    if (state.difficulty === 'normal') {
      const preferred = [3, 2, 4, 1, 5, 0, 6].filter(c => validCols.includes(c));
      for (const c of preferred) {
        const r = getDropRow(c);
        // Avoid dropping if it gives player an immediate win above it
        if (r > 0 && checkWin(r - 1, c, 0)) continue;
        return c;
      }
      return preferred[0] || validCols[0];
    }

    // Hard AI: Minimax depth 4 with alpha-beta pruning
    let bestScore = -Infinity;
    let bestCol = validCols[0];
    const orderedCols = [3, 2, 4, 1, 5, 0, 6].filter(c => validCols.includes(c));

    for (const c of orderedCols) {
      const r = getDropRow(c);
      state.board[r][c] = 1;
      const score = minimax(state.board, 4, -Infinity, Infinity, false);
      state.board[r][c] = -1;
      if (score > bestScore) {
        bestScore = score;
        bestCol = c;
      }
    }
    return bestCol;
  }

  function evaluateBoard(b) {
    let score = 0;
    // Center column preference
    for (let r = 0; r < ROWS; r++) {
      if (b[r][3] === 1) score += 4;
      if (b[r][3] === 0) score -= 4;
    }
    return score;
  }

  function minimax(b, depth, alpha, beta, isMaximizing) {
    if (depth === 0) return evaluateBoard(b);

    const valid = [];
    for (let c = 0; c < COLS; c++) {
      if (getDropRow(c, b) !== -1) valid.push(c);
    }
    if (valid.length === 0) return 0;

    if (isMaximizing) {
      let maxEval = -Infinity;
      for (const c of valid) {
        const r = getDropRow(c, b);
        if (checkWin(r, c, 1, b)) return 1000 + depth;
        b[r][c] = 1;
        const ev = minimax(b, depth - 1, alpha, beta, false);
        b[r][c] = -1;
        maxEval = Math.max(maxEval, ev);
        alpha = Math.max(alpha, ev);
        if (beta <= alpha) break;
      }
      return maxEval;
    } else {
      let minEval = Infinity;
      for (const c of valid) {
        const r = getDropRow(c, b);
        if (checkWin(r, c, 0, b)) return -1000 - depth;
        b[r][c] = 0;
        const ev = minimax(b, depth - 1, alpha, beta, true);
        b[r][c] = -1;
        minEval = Math.min(minEval, ev);
        beta = Math.min(beta, ev);
        if (beta <= alpha) break;
      }
      return minEval;
    }
  }

  // --- UI Updates ---
  function updateScoreboard() {
    const elP1 = document.getElementById('score-val-p1');
    const elP2 = document.getElementById('score-val-p2');
    const elTies = document.getElementById('score-val-ties');
    const elStreak = document.getElementById('live-streak');
    const labelP1 = document.getElementById('score-label-p1');
    const labelP2 = document.getElementById('score-label-p2');

    if (elP1) elP1.textContent = state.scores[0];
    if (elP2) elP2.textContent = state.scores[1];
    if (elTies) elTies.textContent = state.scores[2];
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
    const turnBadge = document.getElementById('c4-turn-badge');
    const turnText = document.getElementById('c4-turn-text');
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
    const overlay = document.getElementById('c4-result-overlay');
    const title = document.getElementById('c4-result-title');
    const subtitle = document.getElementById('c4-result-subtitle');
    if (!overlay || !title || !subtitle) return;

    if (draw) {
      title.textContent = 'ROUND DRAW';
      subtitle.textContent = 'The board is completely full.';
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
      subtitle.textContent = 'Connected 4 in a line!';
    }
    setTimeout(() => { overlay.style.display = 'flex'; }, 400);
  }

  function resetGame() {
    state.board = Array.from({ length: ROWS }, () => Array(COLS).fill(-1));
    state.turn = 0;
    state.isGameOver = false;
    state.winLine = null;
    state.animCol = -1;
    state.animRow = -1;
    state.animProgress = 0;
    state.animating = false;
    state.isCpuThinking = false;

    const overlay = document.getElementById('c4-result-overlay');
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

  function setMatchStatus(msg, type = 'normal') {
    const roomStatus = document.getElementById('room-status');
    const findBtn = document.getElementById('find-match-btn');
    if (!roomStatus) return;
    roomStatus.textContent = msg;
    if (type === 'found') {
      roomStatus.style.color = '#15803d';
      roomStatus.style.background = 'rgba(34, 197, 94, 0.12)';
      roomStatus.style.border = '1px solid rgba(34, 197, 94, 0.35)';
      roomStatus.style.padding = '0.45rem 0.85rem';
      roomStatus.style.borderRadius = '6px';
      roomStatus.style.fontWeight = '700';
      roomStatus.style.fontSize = '0.92rem';
      roomStatus.style.display = 'inline-block';
      if (findBtn) {
        findBtn.textContent = 'In Match';
        findBtn.disabled = true;
        findBtn.style.opacity = '0.7';
      }
    } else if (type === 'searching') {
      roomStatus.style.color = '#2563eb';
      roomStatus.style.background = 'transparent';
      roomStatus.style.border = 'none';
      roomStatus.style.padding = '0';
      roomStatus.style.fontWeight = '600';
      roomStatus.style.fontSize = '0.85rem';
      roomStatus.style.display = 'block';
      if (findBtn) {
        findBtn.textContent = 'Searching... (Cancel)';
        findBtn.disabled = false;
        findBtn.style.opacity = '1';
      }
    } else {
      roomStatus.style.color = 'var(--text-secondary)';
      roomStatus.style.background = 'transparent';
      roomStatus.style.border = 'none';
      roomStatus.style.padding = '0';
      roomStatus.style.fontWeight = 'normal';
      roomStatus.style.fontSize = '0.8rem';
      roomStatus.style.display = 'block';
      if (findBtn) {
        findBtn.textContent = 'Find Match';
        findBtn.disabled = false;
        findBtn.style.opacity = '1';
      }
    }
  }

  // --- Online Socket.IO Handlers ---
  function initOnlineSocket() {
    if (state.socket) return;
    if (typeof io === 'undefined') return;

    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('c4_room_joined', data => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.myPlayer = data.player;
      state.opponentJoined = !!data.guest_name;
      state.opponentName = data.is_host ? (data.guest_name || 'Opponent') : (data.host_name || 'Host');

      if (state.opponentJoined) {
        setMatchStatus(`Match Found! Playing vs ${state.opponentName} (You are ${state.myPlayer === 0 ? 'Amber' : 'Gold'})`, 'found');
      } else {
        setMatchStatus(`Waiting for opponent in room ${state.roomId}...`, 'normal');
      }
      updateScoreboard();
      updateTurnDisplay();
    });

    state.socket.on('c4_move_made', data => {
      state.board = data.board;
      state.turn = data.next_turn;
      state.scores = data.scores;
      playDropSound();
      updateScoreboard();
      updateTurnDisplay();

      if (data.winner !== null && data.winner !== undefined) {
        handleGameOver(false, data.winner, data.win_line);
      } else if (data.is_draw) {
        handleGameOver(true, -1);
      }
    });

    state.socket.on('c4_restarted', data => {
      resetGame();
      state.turn = data.turn || 0;
      updateTurnDisplay();
    });

    state.socket.on('c4_player_left', () => {
      state.opponentJoined = false;
      setMatchStatus('Opponent disconnected. Waiting for a player...', 'normal');
    });

    state.socket.on('c4_match_found', data => {
      state.isSearching = false;
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.myPlayer = data.player;
      state.opponentJoined = true;
      state.opponentName = data.is_host ? data.guest_name : data.host_name;

      setMatchStatus(`Match Found! Playing vs ${state.opponentName} (You are ${state.myPlayer === 0 ? 'Amber' : 'Gold'})`, 'found');
      resetGame();
    });

    state.socket.on('c4_matchmaking_waiting', () => {
      state.isSearching = true;
      setMatchStatus('Searching for an opponent...', 'searching');
    });

    state.socket.on('c4_matchmaking_cancelled', () => {
      state.isSearching = false;
      setMatchStatus('Matchmaking cancelled.', 'normal');
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
    state.socket.emit('join_c4_room', { room_id: roomId });
    const input = document.getElementById('room-code-input');
    if (input) input.value = roomId;
  }

  // --- Setup Listeners ---
  function setupListeners() {
    if (canvas) {
      canvas.addEventListener('click', e => {
        const col = getColFromX(e.clientX);
        if (col >= 0) dropPiece(col);
      });

      canvas.addEventListener('mousemove', e => {
        state.hoverCol = getColFromX(e.clientX);
      });

      canvas.addEventListener('mouseleave', () => {
        state.hoverCol = -1;
      });

      canvas.addEventListener('touchstart', e => {
        e.preventDefault();
        const col = getColFromX(e.touches[0].clientX);
        if (col >= 0) dropPiece(col);
      }, { passive: false });
    }

    const restartBtn = document.getElementById('c4-restart-btn');
    if (restartBtn) {
      restartBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('c4_restart', { room_id: state.roomId });
        } else {
          resetGame();
        }
      });
    }

    const nextRoundBtn = document.getElementById('c4-next-round-btn');
    if (nextRoundBtn) {
      nextRoundBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('c4_restart', { room_id: state.roomId });
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
        localStorage.setItem('ew_c4_muted', isMuted ? 'true' : 'false');
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
    document.querySelectorAll('.c4-diff-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.difficulty = btn.getAttribute('data-diff');
        document.querySelectorAll('.c4-diff-btn').forEach(b => {
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

    // Online
    const findMatchBtn = document.getElementById('find-match-btn');
    if (findMatchBtn) {
      findMatchBtn.addEventListener('click', () => {
        if (!state.socket) initOnlineSocket();
        if (!state.socket) return;
        if (state.isSearching) {
          state.socket.emit('cancel_c4_matchmaking');
        } else {
          state.socket.emit('find_c4_match');
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
        const url = `${window.location.origin}/games/connect-four?room=${encodeURIComponent(state.roomId)}`;
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
  window.__c4 = {
    getState: () => ({ ...state }),
    dropPiece,
    resetGame,
    setMode,
    checkWin
  };
})();
