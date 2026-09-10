/**
 * Ping Pong: Arcade Duel
 * Responsive, touch-adapted table tennis arcade game with balanced AI,
 * Web Audio synth, local 2-player, and real-time Socket.IO 1v1 duels.
 */
(function () {
  'use strict';

  const V_WIDTH = 800;
  const V_HEIGHT = 500;
  const PADDLE_W = 14;
  const PADDLE_H = 95;
  const BASE_SPEED = 5;
  const MAX_SPEED = 12;
  const ACCEL = 0.25;

  const canvas = document.getElementById('pong-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Audio Synth (Web Audio API)
  let audioCtx = null;
  let isMuted = localStorage.getItem('ew_pong_muted') === '1';

  function initAudio() {
    if (!audioCtx) {
      try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) audioCtx = new AudioContext();
      } catch (e) {
        // AudioContext not supported
      }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
  }

  function playTone(freq, type, duration, gainVal = 0.08) {
    if (isMuted) return;
    initAudio();
    if (!audioCtx) return;
    try {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
      gain.gain.setValueAtTime(gainVal, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + duration);
    } catch (e) {}
  }

  function soundHit() { playTone(440, 'triangle', 0.08, 0.09); }
  function soundWall() { playTone(220, 'sine', 0.06, 0.07); }
  function soundScore() {
    playTone(523.25, 'triangle', 0.12, 0.1);
    setTimeout(() => playTone(659.25, 'triangle', 0.18, 0.1), 100);
  }
  function soundWin() {
    playTone(523.25, 'triangle', 0.15, 0.12);
    setTimeout(() => playTone(659.25, 'triangle', 0.15, 0.12), 120);
    setTimeout(() => playTone(783.99, 'triangle', 0.25, 0.12), 240);
  }
  function soundLose() {
    playTone(440, 'sine', 0.15, 0.1);
    setTimeout(() => playTone(330, 'sine', 0.25, 0.1), 140);
  }

  // Game State
  const state = {
    mode: 'ai', // 'ai', 'local', 'online'
    difficulty: localStorage.getItem('ew_pong_difficulty') || 'normal',
    targetScore: 3, // 3, 5, 11, or Infinity
    isGameOver: false,
    isPaused: true, // Paused by default on page load so player is in control
    p1: { x: 20, y: V_HEIGHT / 2 - PADDLE_H / 2, width: PADDLE_W, height: PADDLE_H, dy: 0, score: 0, color: '#e06a3b' },
    p2: { x: V_WIDTH - 20 - PADDLE_W, y: V_HEIGHT / 2 - PADDLE_H / 2, width: PADDLE_W, height: PADDLE_H, dy: 0, score: 0, color: '#2e86ab' },
    ball: { x: V_WIDTH / 2, y: V_HEIGHT / 2, radius: 8, vx: BASE_SPEED, vy: 3, speed: BASE_SPEED, color: '#ffffff' },
    consecutiveVolleys: 0,
    maxMatchVolleys: 0,
    totalReturns: 0,
    animFrameId: null,
    // AI tracking
    aiTargetY: V_HEIGHT / 2,
    aiLastPollTime: 0,
    // Online state
    socket: null,
    isHost: true,
    playerIndex: 0, // 0 = left (p1), 1 = right (p2)
    roomId: null,
    opponentName: 'Opponent',
    lastSyncTime: 0,
    isFindingMatch: false,
    // Online integrity state (never trust defaults for match results)
    roomTarget: null,     // shared first-to-N from server; null = local targetScore
    isResolving: false,   // hard guard: never re-enter match-end handling
    connLost: false,      // transport down while in an online room
    wasDropped: false,    // our socket dropped mid-match; rejoin on reconnect
    rejoinAttempts: 0,    // capped rejoin attempts (initial + 1 retry max)
    lastPaddleSend: 0,    // throttle clock for paddle sync (~20 Hz)
    noContestTimer: null  // pending voided-match timer after opponent drop
  };

  const PONG_DEBUG = false;
  function pongDebug(...args) {
    if (PONG_DEBUG && typeof console !== 'undefined' && typeof console.debug === 'function') {
      console.debug('[pong]', ...args);
    }
  }

  // First-to-N that actually governs THIS match: the server-shared room
  // target while online in a room, otherwise the local setting.
  function effectiveTarget() {
    if (state.mode === 'online' && state.roomId
        && typeof state.roomTarget === 'number' && state.roomTarget > 0) {
      return state.roomTarget;
    }
    return state.targetScore;
  }

  function setRematchVisible(visible) {
    const btn = document.getElementById('rematch-btn');
    if (btn) btn.style.display = visible ? '' : 'none';
  }

  function clearNoContestTimer() {
    if (state.noContestTimer) {
      clearTimeout(state.noContestTimer);
      state.noContestTimer = null;
    }
  }

  // Void a match with NO result: no streak change, no points, no leaderboard
  // traffic. Used for leaves, drops, and unrecovered disconnects — never a loss.
  function showNoContest(message) {
    clearNoContestTimer();
    state.isGameOver = true;
    state.isPaused = true;
    if (typeof window.__updatePongPauseBtn === 'function') {
      window.__updatePongPauseBtn(true);
    }
    const banner = document.getElementById('game-over-banner');
    const winnerText = document.getElementById('winner-text');
    const winnerStreak = document.getElementById('winner-streak');
    const winnerPoints = document.getElementById('winner-points');
    if (winnerText) winnerText.textContent = 'Match Void — No Contest';
    if (winnerStreak) {
      winnerStreak.textContent = message;
      winnerStreak.style.display = 'block';
    }
    if (winnerPoints) winnerPoints.style.display = 'none';
    setRematchVisible(false);
    if (banner) banner.style.display = 'block';
    const findBtn = document.getElementById('find-match-btn');
    if (findBtn) {
      findBtn.textContent = 'Find Match';
      findBtn.disabled = false;
      findBtn.style.opacity = '1';
      findBtn.classList.remove('ew-btn--active');
    }
    state.isFindingMatch = false;
  }

  function getStreakKey(diff) {
    return `ew_pong_streak_${diff || state.difficulty}`;
  }

  function getLocalStreak(diff) {
    return parseInt(localStorage.getItem(getStreakKey(diff)) || '0', 10);
  }

  function setLocalStreak(diff, val) {
    localStorage.setItem(getStreakKey(diff), val.toString());
  }

  function getPongRankedScore() {
    return parseInt(localStorage.getItem('ew_pong_ranked_score') || '0', 10);
  }

  function addPongRankedScore(pts) {
    const current = getPongRankedScore();
    const updated = current + pts;
    localStorage.setItem('ew_pong_ranked_score', updated.toString());
    return updated;
  }

  async function fetchUserRank() {
    try {
      const guestToken = localStorage.getItem('arcade_guest_token') || '';
      const guestParam = guestToken ? `&guest_token=${encodeURIComponent(guestToken)}` : '';
      const res = await fetch(`/api/games/leaderboard?game=ping_pong&category=ranked_score&period=all_time${guestParam}`);
      if (!res.ok) return;
      const data = await res.json();
      const rankEl = document.getElementById('my-pong-rank');
      if (rankEl && data.user_record && data.user_record.rank) {
        rankEl.textContent = `Your Rank: #${data.user_record.rank} (${(data.user_record.score || 0).toLocaleString()} pts)`;
      }
    } catch (_) {}
  }

  function updateStatsUI() {
    const streakEl = document.getElementById('my-pong-streak');
    const volleysEl = document.getElementById('my-pong-volleys');
    const winsEl = document.getElementById('my-pong-wins');
    const rankedEl = document.getElementById('my-pong-ranked');
    const activeStreak = state.mode === 'online' ? getLocalStreak('online') : getLocalStreak(state.difficulty);
    if (streakEl) streakEl.textContent = `${activeStreak} wins`;
    if (volleysEl) volleysEl.textContent = (localStorage.getItem('ew_pong_total_volleys') || '0');
    const totalWinsKey = state.mode === 'online' ? 'ew_pong_wins_online' : `ew_pong_wins_${state.difficulty}`;
    if (winsEl) winsEl.textContent = (localStorage.getItem(totalWinsKey) || '0');
    if (rankedEl) rankedEl.textContent = `${getPongRankedScore().toLocaleString()} pts`;
    fetchUserRank();
  }

  // Offline Sync Queue
  function queueOfflineSubmission(payload) {
    try {
      const q = JSON.parse(localStorage.getItem('ew_pong_offline_queue') || '[]');
      q.push(payload);
      localStorage.setItem('ew_pong_offline_queue', JSON.stringify(q));
    } catch (e) {}
  }

  async function flushOfflineQueue() {
    if (!navigator.onLine) return;
    try {
      const q = JSON.parse(localStorage.getItem('ew_pong_offline_queue') || '[]');
      if (!q.length) return;
      const remaining = [];
      for (const item of q) {
        try {
          const res = await fetch('/api/games/leaderboard/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(item)
          });
          if (!res.ok && res.status >= 500) remaining.push(item);
        } catch (e) {
          remaining.push(item);
        }
      }
      localStorage.setItem('ew_pong_offline_queue', JSON.stringify(remaining));
    } catch (e) {}
  }
  window.addEventListener('online', flushOfflineQueue);

  async function submitScore(category, score, metadata = {}) {
    // Strictly isolate local 2-player pass-and-play from competitive leaderboard submissions
    if (state.mode === 'local') return;

    const payload = {
      game: 'ping_pong',
      category: category,
      score: Math.max(1, Math.floor(score)),
      metadata: {
        difficulty: state.mode === 'online' ? 'online' : state.difficulty,
        mode: state.mode,
        returns: state.maxMatchVolleys,
        ...metadata
      },
      guest_token: getOrCreateGuestToken()
    };

    try {
      const res = await fetch('/api/games/leaderboard/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) queueOfflineSubmission(payload);
    } catch (e) {
      queueOfflineSubmission(payload);
    }
  }

  function getOrCreateGuestToken() {
    let tok = localStorage.getItem('ew_guest_token');
    if (!tok) {
      tok = 'g_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      localStorage.setItem('ew_guest_token', tok);
    }
    return tok;
  }

  // Reset ball position & direction
  function resetBall(servingToPlayer1 = false) {
    state.ball.x = V_WIDTH / 2;
    state.ball.y = V_HEIGHT / 2;
    state.ball.speed = BASE_SPEED;
    state.consecutiveVolleys = 0;
    const dir = servingToPlayer1 ? -1 : 1;
    const angle = (Math.random() * 0.6 - 0.3); // slight random start angle
    state.ball.vx = dir * BASE_SPEED * Math.cos(angle);
    state.ball.vy = BASE_SPEED * Math.sin(angle);
  }

  function resetGame() {
    state.p1.score = 0;
    state.p2.score = 0;
    state.p1.y = V_HEIGHT / 2 - PADDLE_H / 2;
    state.p2.y = V_HEIGHT / 2 - PADDLE_H / 2;
    state.p1.dy = 0;
    state.p2.dy = 0;
    state.consecutiveVolleys = 0;
    state.maxMatchVolleys = 0;
    state.isGameOver = false;
    resetBall(Math.random() > 0.5);

    const banner = document.getElementById('game-over-banner');
    if (banner) banner.style.display = 'none';
    const winnerPoints = document.getElementById('winner-points');
    if (winnerPoints) winnerPoints.style.display = 'none';
  }

  // Coordinate scaling helper for touch and mouse
  function getVirtualY(clientY) {
    const rect = canvas.getBoundingClientRect();
    if (!rect.height) return V_HEIGHT / 2;
    const scaleY = V_HEIGHT / rect.height;
    return (clientY - rect.top) * scaleY;
  }

  function getVirtualX(clientX) {
    const rect = canvas.getBoundingClientRect();
    if (!rect.width) return V_WIDTH / 2;
    const scaleX = V_WIDTH / rect.width;
    return (clientX - rect.left) * scaleX;
  }

  // Canvas click toggles unpause
  canvas.addEventListener('click', () => {
    initAudio();
    if (state.isPaused && state.mode !== 'online') {
      state.isPaused = false;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(false);
      }
    }
  });

  // Controls Binding
  window.addEventListener('keydown', (e) => {
    initAudio();
    if (e.key === ' ' || e.code === 'Space') {
      if (state.mode !== 'online') {
        e.preventDefault();
        state.isPaused = !state.isPaused;
        if (typeof window.__updatePongPauseBtn === 'function') {
          window.__updatePongPauseBtn(state.isPaused);
        }
        return;
      }
    }

    const isGuest = (state.mode === 'online' && state.playerIndex === 1);
    if (e.key === 'w' || e.key === 'W') {
      if (isGuest) state.p2.dy = -7; else state.p1.dy = -7;
    }
    if (e.key === 's' || e.key === 'S') {
      if (isGuest) state.p2.dy = 7; else state.p1.dy = 7;
    }

    if (state.mode === 'local' || isGuest) {
      if (e.key === 'ArrowUp') state.p2.dy = -7;
      if (e.key === 'ArrowDown') state.p2.dy = 7;
    } else {
      // In solo/host mode, Arrow keys move Player 1
      if (e.key === 'ArrowUp') state.p1.dy = -7;
      if (e.key === 'ArrowDown') state.p1.dy = 7;
    }
  });

  window.addEventListener('keyup', (e) => {
    const isGuest = (state.mode === 'online' && state.playerIndex === 1);
    if (e.key === 'w' || e.key === 'W' || e.key === 's' || e.key === 'S') {
      if (isGuest) state.p2.dy = 0; else state.p1.dy = 0;
    }
    if (state.mode === 'local' || isGuest) {
      if (e.key === 'ArrowUp' || e.key === 'ArrowDown') state.p2.dy = 0;
    } else {
      if (e.key === 'ArrowUp' || e.key === 'ArrowDown') state.p1.dy = 0;
    }
  });

  // Mouse Move over Canvas
  canvas.addEventListener('mousemove', (e) => {
    initAudio();
    if (state.mode === 'online' && state.playerIndex === 1) {
      // Guest controls right paddle
      state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, getVirtualY(e.clientY) - PADDLE_H / 2));
      sendPaddleSync();
      return;
    }
    const vx = getVirtualX(e.clientX);
    if (state.mode === 'local' && vx > V_WIDTH / 2) {
      state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, getVirtualY(e.clientY) - PADDLE_H / 2));
    } else {
      state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, getVirtualY(e.clientY) - PADDLE_H / 2));
      if (state.mode === 'online') sendPaddleSync();
    }
  });

  // Mobile Touch Controls on Canvas
  let activeTouchIdP1 = null;
  let activeTouchIdP2 = null;

  canvas.addEventListener('touchstart', (e) => {
    initAudio();
    e.preventDefault();
    for (let i = 0; i < e.changedTouches.length; i++) {
      const t = e.changedTouches[i];
      const vx = getVirtualX(t.clientX);
      const vy = getVirtualY(t.clientY);

      if (state.mode === 'online' && state.playerIndex === 1) {
        activeTouchIdP2 = t.identifier;
        state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, vy - PADDLE_H / 2));
        sendPaddleSync();
      } else if (state.mode === 'local' && vx > V_WIDTH / 2) {
        activeTouchIdP2 = t.identifier;
        state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, vy - PADDLE_H / 2));
      } else {
        activeTouchIdP1 = t.identifier;
        state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, vy - PADDLE_H / 2));
        if (state.mode === 'online') sendPaddleSync();
      }
    }
  }, { passive: false });

  canvas.addEventListener('touchmove', (e) => {
    e.preventDefault();
    for (let i = 0; i < e.changedTouches.length; i++) {
      const t = e.changedTouches[i];
      const vy = getVirtualY(t.clientY);

      if (t.identifier === activeTouchIdP1) {
        state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, vy - PADDLE_H / 2));
        if (state.mode === 'online') sendPaddleSync();
      } else if (t.identifier === activeTouchIdP2) {
        state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, vy - PADDLE_H / 2));
        if (state.mode === 'online' && state.playerIndex === 1) sendPaddleSync();
      }
    }
  }, { passive: false });

  canvas.addEventListener('touchend', (e) => {
    for (let i = 0; i < e.changedTouches.length; i++) {
      const id = e.changedTouches[i].identifier;
      if (id === activeTouchIdP1) activeTouchIdP1 = null;
      if (id === activeTouchIdP2) activeTouchIdP2 = null;
    }
  });

  // On-screen Touch Buttons
  const btnUp = document.getElementById('touch-up');
  const btnDown = document.getElementById('touch-down');

  if (btnUp) {
    const startUp = (e) => {
      e.preventDefault();
      initAudio();
      const targetPaddle = (state.mode === 'online' && state.playerIndex === 1) ? state.p2 : state.p1;
      targetPaddle.dy = -7;
    };
    const endUp = (e) => {
      e.preventDefault();
      const targetPaddle = (state.mode === 'online' && state.playerIndex === 1) ? state.p2 : state.p1;
      targetPaddle.dy = 0;
    };
    btnUp.addEventListener('pointerdown', startUp);
    btnUp.addEventListener('pointerup', endUp);
    btnUp.addEventListener('pointerleave', endUp);
  }

  if (btnDown) {
    const startDown = (e) => {
      e.preventDefault();
      initAudio();
      const targetPaddle = (state.mode === 'online' && state.playerIndex === 1) ? state.p2 : state.p1;
      targetPaddle.dy = 7;
    };
    const endDown = (e) => {
      e.preventDefault();
      const targetPaddle = (state.mode === 'online' && state.playerIndex === 1) ? state.p2 : state.p1;
      targetPaddle.dy = 0;
    };
    btnDown.addEventListener('pointerdown', startDown);
    btnDown.addEventListener('pointerup', endDown);
    btnDown.addEventListener('pointerleave', endDown);
  }

  // AI Logic with Human-like imperfection
  function updateAI(now) {
    if (state.mode !== 'ai') return;

    let pollInterval = 120;
    let maxSpeedFraction = 0.75;
    let jitter = 10;

    if (state.difficulty === 'easy') {
      pollInterval = 250;
      maxSpeedFraction = 0.50;
      jitter = 25;
    } else if (state.difficulty === 'hard') {
      pollInterval = 30;
      maxSpeedFraction = 0.95;
      jitter = 0;
    }

    if (now - state.aiLastPollTime > pollInterval) {
      state.aiLastPollTime = now;
      if (state.ball.vx > 0) {
        // Ball approaching AI paddle
        const offset = (Math.random() * (jitter * 2) - jitter);
        state.aiTargetY = state.ball.y + offset;
      } else {
        // Ball heading away: drift toward center slowly
        state.aiTargetY = V_HEIGHT / 2;
      }
    }

    const aiCenter = state.p2.y + state.p2.height / 2;
    const diff = state.aiTargetY - aiCenter;
    const maxAiSpeed = Math.max(3, state.ball.speed * maxSpeedFraction);

    if (Math.abs(diff) > 8) {
      state.p2.dy = Math.sign(diff) * Math.min(Math.abs(diff), maxAiSpeed);
    } else {
      state.p2.dy = 0;
    }
  }

  // Physics & Game Update
  function update(now) {
    if (state.isGameOver) return;
    if (state.isPaused) return;
    if (state.mode === 'online' && !state.roomId) return;
    // Our transport is down: freeze physics rather than simulating (and
    // scoring) a match the opponent cannot see. Resync happens on rejoin.
    if (state.mode === 'online' && state.connLost) return;

    // In online mode, guest receives positions from host
    if (state.mode === 'online' && !state.isHost) {
      // Guest moves their paddle locally
      if (state.p2.dy !== 0) {
        state.p2.y += state.p2.dy;
        state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p2.y));
        sendPaddleSync();
      }
      return;
    }

    // Update paddle positions
    if (state.p1.dy !== 0) {
      state.p1.y += state.p1.dy;
      state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p1.y));
      if (state.mode === 'online' && state.isHost) sendPaddleSync();
    }

    if (state.mode === 'ai') {
      updateAI(now);
      state.p2.y += state.p2.dy;
      state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p2.y));
    } else if (state.mode === 'local') {
      state.p2.y += state.p2.dy;
      state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p2.y));
    }

    // Ball physics
    state.ball.x += state.ball.vx;
    state.ball.y += state.ball.vy;

    // Wall bounce (top and bottom)
    if (state.ball.y - state.ball.radius < 0) {
      state.ball.y = state.ball.radius;
      state.ball.vy = -state.ball.vy;
      soundWall();
    } else if (state.ball.y + state.ball.radius > V_HEIGHT) {
      state.ball.y = V_HEIGHT - state.ball.radius;
      state.ball.vy = -state.ball.vy;
      soundWall();
    }

    // Paddle collision
    let paddle = (state.ball.x < V_WIDTH / 2) ? state.p1 : state.p2;

    if (
      state.ball.x + state.ball.radius >= paddle.x &&
      state.ball.x - state.ball.radius <= paddle.x + paddle.width &&
      state.ball.y + state.ball.radius >= paddle.y &&
      state.ball.y - state.ball.radius <= paddle.y + paddle.height
    ) {
      // Prevent ball sticking inside paddle
      if (paddle === state.p1 && state.ball.vx < 0) {
        state.ball.x = state.p1.x + state.p1.width + state.ball.radius;
        calculateBounce(paddle, 1);
      } else if (paddle === state.p2 && state.ball.vx > 0) {
        state.ball.x = state.p2.x - state.ball.radius;
        calculateBounce(paddle, -1);
      }
    }

    // Goal scoring
    if (state.ball.x - state.ball.radius < 0) {
      // Player 2 scored
      state.p2.score++;
      soundScore();
      onPointScored(2);
    } else if (state.ball.x + state.ball.radius > V_WIDTH) {
      // Player 1 scored
      state.p1.score++;
      soundScore();
      onPointScored(1);
    }

    // Sync online host state
    if (state.mode === 'online' && state.isHost && state.socket) {
      if (now - state.lastSyncTime > 30) {
        state.lastSyncTime = now;
        state.socket.emit('pong_ball_sync', {
          room_id: state.roomId,
          x: state.ball.x,
          y: state.ball.y,
          vx: state.ball.vx,
          vy: state.ball.vy,
          speed: state.ball.speed,
          p1Y: state.p1.y,
          volleys: state.consecutiveVolleys
        });
      }
    }
  }

  function calculateBounce(paddle, dir) {
    state.consecutiveVolleys++;
    state.totalReturns++;
    if (state.consecutiveVolleys > state.maxMatchVolleys) {
      state.maxMatchVolleys = state.consecutiveVolleys;
    }
    soundHit();

    // Hit position normalized (-1 to 1)
    const collidePoint = state.ball.y - (paddle.y + paddle.height / 2);
    const normalizedPoint = collidePoint / (paddle.height / 2);
    const maxAngle = Math.PI / 3.8; // ~47 degrees max
    const bounceAngle = normalizedPoint * maxAngle;

    state.ball.speed = Math.min(state.ball.speed + ACCEL, MAX_SPEED);
    state.ball.vx = dir * state.ball.speed * Math.cos(bounceAngle);
    state.ball.vy = state.ball.speed * Math.sin(bounceAngle);
  }

  function onPointScored(scoringPlayer) {
    const target = effectiveTarget();
    if (target !== Infinity && (state.p1.score >= target || state.p2.score >= target)) {
      finishMatch(scoringPlayer);
    } else {
      resetBall(scoringPlayer === 2);
      if (state.mode === 'online' && state.isHost && state.socket) {
        state.socket.emit('pong_score_update', {
          room_id: state.roomId,
          scores: [state.p1.score, state.p2.score],
          winner: null
        });
      }
    }
  }

  function finishMatch(winningPlayer) {
    // Hard guard: match-end handling must never re-enter while a resolution
    // is in flight or already recorded (echoed / stale / duplicate events).
    if (state.isGameOver || state.isResolving) {
      pongDebug('finishMatch ignored (already over/resolving)', winningPlayer);
      return;
    }
    state.isResolving = true;
    try {
      finishMatchInner(winningPlayer);
    } finally {
      state.isResolving = false;
    }
  }

  function finishMatchInner(winningPlayer) {
    state.isGameOver = true;
    const isPlayer1Winner = winningPlayer === 1;

    if (isPlayer1Winner) soundWin();
    else soundLose();

    // Show banner
    const banner = document.getElementById('game-over-banner');
    const winnerText = document.getElementById('winner-text');
    const winnerStreak = document.getElementById('winner-streak');

    // Perspective-correct result: in solo/local the user is always Player 1;
    // online, the winner maps through our seat. This ONE flag drives both the
    // banner and the rewards — a loser must never earn winner points/streak.
    const myWon = state.mode === 'online'
      ? ((state.playerIndex === 0) === isPlayer1Winner)
      : isPlayer1Winner;

    let title = 'Match Complete';
    if (state.mode === 'ai') {
      title = isPlayer1Winner ? 'You Win!' : 'AI Wins!';
    } else if (state.mode === 'local') {
      title = isPlayer1Winner ? 'Player 1 Wins!' : 'Player 2 Wins!';
    } else if (state.mode === 'online') {
      title = myWon ? 'Victory!' : 'Defeat!';
    }

    if (winnerText) winnerText.textContent = title;

    // Handle Streak and Leaderboard Submissions
    if (state.mode !== 'local') {
      const activeDiff = state.mode === 'online' ? 'online' : state.difficulty;
      let streak = getLocalStreak(activeDiff);

      if (myWon) {
        streak++;
        setLocalStreak(activeDiff, streak);

        // Update total wins
        const winKey = state.mode === 'online' ? 'ew_pong_wins_online' : `ew_pong_wins_${state.difficulty}`;
        const totalWins = parseInt(localStorage.getItem(winKey) || '0', 10) + 1;
        localStorage.setItem(winKey, totalWins.toString());

        // Update total volleys
        const totalVolleys = parseInt(localStorage.getItem('ew_pong_total_volleys') || '0', 10) + state.maxMatchVolleys;
        localStorage.setItem('ew_pong_total_volleys', totalVolleys.toString());

        if (winnerStreak) {
          winnerStreak.textContent = `Win Streak: ${streak} • Rally Returns: ${state.maxMatchVolleys}`;
          winnerStreak.style.display = 'block';
        }

        // Difficulty-scaled ranked points
        let basePoints = 250;
        let volleyMult = 10;
        if (activeDiff === 'easy') { basePoints = 100; volleyMult = 5; }
        else if (activeDiff === 'hard') { basePoints = 500; volleyMult = 20; }
        else if (activeDiff === 'online') { basePoints = 750; volleyMult = 30; }

        const earnedPoints = basePoints + (state.maxMatchVolleys * volleyMult);
        const totalRankedScore = addPongRankedScore(earnedPoints);

        const winnerPoints = document.getElementById('winner-points');
        if (winnerPoints) {
          winnerPoints.textContent = `+${earnedPoints} ranked pts (Total: ${totalRankedScore.toLocaleString()} pts)`;
          winnerPoints.style.display = 'block';
        }

        // Submit to leaderboards
        submitScore('ranked_score', totalRankedScore, { multiplier: volleyMult, match_pts: earnedPoints });
        submitScore('win_streak', streak);
        submitScore('total_wins', totalWins);
        if (state.maxMatchVolleys > 0) {
          submitScore('volleys_returned', state.maxMatchVolleys);
        }
      } else {
        // Player lost: reset streak
        setLocalStreak(activeDiff, 0);
        if (winnerStreak) {
          winnerStreak.textContent = `Streak ended. Best Rally: ${state.maxMatchVolleys}`;
          winnerStreak.style.display = 'block';
        }
        const winnerPoints = document.getElementById('winner-points');
        if (winnerPoints) winnerPoints.style.display = 'none';
      }
      updateStatsUI();
    } else {
      if (winnerStreak) winnerStreak.style.display = 'none';
    }

    if (banner) banner.style.display = 'block';

    if (state.mode === 'online' && state.isHost && state.socket) {
      state.socket.emit('pong_score_update', {
        room_id: state.roomId,
        scores: [state.p1.score, state.p2.score],
        winner: winningPlayer
      });
    }
  }

  // Render Canvas
  function render() {
    ctx.clearRect(0, 0, V_WIDTH, V_HEIGHT);

    // Court background
    ctx.fillStyle = '#121212';
    ctx.fillRect(0, 0, V_WIDTH, V_HEIGHT);

    // Net dashed centerline
    ctx.fillStyle = '#333333';
    for (let i = 0; i < V_HEIGHT; i += 24) {
      ctx.fillRect(V_WIDTH / 2 - 1, i + 4, 2, 14);
    }

    // Paddles
    ctx.fillStyle = state.p1.color;
    ctx.fillRect(state.p1.x, state.p1.y, state.p1.width, state.p1.height);

    ctx.fillStyle = state.p2.color;
    ctx.fillRect(state.p2.x, state.p2.y, state.p2.width, state.p2.height);

    // Ball
    ctx.fillStyle = state.ball.color;
    ctx.beginPath();
    ctx.arc(state.ball.x, state.ball.y, state.ball.radius, 0, Math.PI * 2);
    ctx.fill();

    // Scores
    ctx.fillStyle = '#ffffff';
    ctx.font = '700 32px monospace';
    ctx.fillText(state.p1.score.toString(), V_WIDTH / 4, 52);
    ctx.fillText(state.p2.score.toString(), (V_WIDTH * 3) / 4 - 20, 52);

    // Rally counter in center top
    if (state.consecutiveVolleys > 1) {
      ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.font = '600 14px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(`RALLY: ${state.consecutiveVolleys}`, V_WIDTH / 2, 28);
      ctx.textAlign = 'start';
    }

    // Names in online mode
    if (state.mode === 'online') {
      ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
      ctx.font = '12px sans-serif';
      const p1Label = state.playerIndex === 0 ? 'You' : state.opponentName;
      const p2Label = state.playerIndex === 1 ? 'You' : state.opponentName;
      ctx.fillText(p1Label, 20, V_HEIGHT - 16);
      ctx.textAlign = 'right';
      ctx.fillText(p2Label, V_WIDTH - 20, V_HEIGHT - 16);
      ctx.textAlign = 'start';
    }

    drawPauseOverlay();
  }

  function drawPauseOverlay() {
    if (!state.isPaused) return;
    ctx.save();
    ctx.fillStyle = 'rgba(18, 18, 18, 0.65)';
    ctx.fillRect(0, 0, V_WIDTH, V_HEIGHT);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 32px Poppins, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    if (state.mode === 'online') {
      if (!state.roomId) {
        ctx.fillText('ONLINE 1V1 LOBBY', V_WIDTH / 2, V_HEIGHT / 2 - 18);
        ctx.font = '500 15px Poppins, sans-serif';
        ctx.fillStyle = '#e8dec8';
        ctx.fillText('Find a match or challenge an opponent below to start', V_WIDTH / 2, V_HEIGHT / 2 + 20);
      } else if (state.connLost) {
        ctx.fillText('CONNECTION LOST', V_WIDTH / 2, V_HEIGHT / 2 - 18);
        ctx.font = '500 15px Poppins, sans-serif';
        ctx.fillStyle = '#e8dec8';
        ctx.fillText('Reconnecting… match paused, never forfeited', V_WIDTH / 2, V_HEIGHT / 2 + 20);
      } else {
        ctx.fillText('PAUSED', V_WIDTH / 2, V_HEIGHT / 2 - 18);
        ctx.font = '500 15px Poppins, sans-serif';
        ctx.fillStyle = '#e8dec8';
        ctx.fillText('Waiting for players to serve...', V_WIDTH / 2, V_HEIGHT / 2 + 20);
      }
    } else {
      ctx.fillText('PAUSED', V_WIDTH / 2, V_HEIGHT / 2 - 18);
      ctx.font = '500 15px Poppins, sans-serif';
      ctx.fillStyle = '#e8dec8';
      ctx.fillText('Press Play / Space or Click Canvas to Serve', V_WIDTH / 2, V_HEIGHT / 2 + 20);
    }
    ctx.restore();
  }

  // Main Loop
  function gameLoop(now) {
    try {
      update(now);
      render();
    } catch (err) {
      console.error('Pong game loop error:', err);
    }
    state.animFrameId = requestAnimationFrame(gameLoop);
  }

  // Socket.IO 1v1 Implementation
  function initSocket() {
    if (state.socket) return;
    if (typeof io === 'undefined') return;

    state.socket = io();

    state.socket.on('pong_room_joined', (data) => {
      data = data || {};
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.playerIndex = data.player;
      state.opponentName = data.is_host ? (data.guest_name || 'Opponent') : (data.host_name || 'Host');
      state.roomTarget = (typeof data.target === 'number' && data.target > 0) ? data.target : null;
      state.connLost = false;
      state.wasDropped = false;
      state.rejoinAttempts = 0;
      clearNoContestTimer();
      setRematchVisible(true);
      pongDebug('room joined', data);

      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = `Room ${data.room_id} • Playing vs ${state.opponentName}`;
        statusEl.style.color = '#e06a3b';
      }
      if (data.rejoined && Array.isArray(data.scores)) {
        // Reclaiming our seat after a drop: adopt the live server scores,
        // never reset to a default — a default must never become a result.
        state.p1.score = Math.max(0, Math.floor(Number(data.scores[0]) || 0));
        state.p2.score = Math.max(0, Math.floor(Number(data.scores[1]) || 0));
        state.isGameOver = false;
        const banner = document.getElementById('game-over-banner');
        if (banner) banner.style.display = 'none';
      } else {
        resetGame();
      }
      if (!data.is_host || data.guest_name) {
        state.isPaused = false;
        if (typeof window.__updatePongPauseBtn === 'function') {
          window.__updatePongPauseBtn(false);
        }
      }
    });

    state.socket.on('pong_paddle_sync', (data) => {
      // Opponent paddle renders from live, validated sync state only.
      if (!data || data.room_id !== state.roomId) return;
      if (data.player === state.playerIndex) return; // ignore our own echo
      const y = Number(data.y);
      if (!Number.isFinite(y)) return;
      const clamped = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, y));
      if (state.playerIndex === 0) {
        state.p2.y = clamped;
      } else {
        state.p1.y = clamped;
      }
    });

    state.socket.on('pong_ball_sync', (data) => {
      if (!data || data.room_id !== state.roomId) return;
      if (!state.isHost) {
        const num = (v, fallback) => (Number.isFinite(Number(v)) ? Number(v) : fallback);
        state.ball.x = num(data.x, state.ball.x);
        state.ball.y = num(data.y, state.ball.y);
        state.ball.vx = num(data.vx, state.ball.vx);
        state.ball.vy = num(data.vy, state.ball.vy);
        state.ball.speed = num(data.speed, state.ball.speed);
        const p1Y = Number(data.p1Y);
        if (Number.isFinite(p1Y)) {
          state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, p1Y));
        }
        const volleys = Math.floor(Number(data.volleys));
        if (Number.isFinite(volleys) && volleys >= 0) state.consecutiveVolleys = volleys;
      }
    });

    state.socket.on('pong_score_update', (data) => {
      if (!data || data.room_id !== state.roomId) return;
      if (Array.isArray(data.scores) && data.scores.length >= 2) {
        state.p1.score = Math.max(0, Math.floor(Number(data.scores[0]) || 0));
        state.p2.score = Math.max(0, Math.floor(Number(data.scores[1]) || 0));
      }
      if (data.winner === 1 || data.winner === 2) {
        // A result is only honored when backed by an actually reached score
        // (winner ahead, on the shared first-to-N). Anything else is a
        // phantom/default claim and is dropped — never a forced loss.
        const w = data.winner;
        const ws = w === 1 ? state.p1.score : state.p2.score;
        const ls = w === 1 ? state.p2.score : state.p1.score;
        const target = effectiveTarget();
        const reached = ws > 0 && ws >= ls && (!Number.isFinite(target) || ws >= target);
        if (reached) {
          finishMatch(w);
        } else {
          pongDebug('ignoring phantom winner claim', data);
        }
      }
    });

    state.socket.on('pong_restart', () => {
      clearNoContestTimer();
      setRematchVisible(true);
      state.isPaused = false;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(false);
      }
      resetGame();
    });

    state.socket.on('pong_match_found', (data) => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.playerIndex = data.player;
      state.opponentName = data.is_host ? data.guest_name : data.host_name;
      state.roomTarget = (data && typeof data.target === 'number' && data.target > 0) ? data.target : null;
      state.rejoinAttempts = 0;
      state.wasDropped = false;
      clearNoContestTimer();
      setRematchVisible(true);

      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = `Match Found! Playing vs ${state.opponentName}`;
        statusEl.style.color = '#15803d';
        statusEl.style.background = 'rgba(34, 197, 94, 0.12)';
        statusEl.style.border = '1px solid rgba(34, 197, 94, 0.35)';
        statusEl.style.padding = '0.45rem 0.85rem';
        statusEl.style.borderRadius = '6px';
        statusEl.style.fontWeight = '700';
        statusEl.style.fontSize = '0.92rem';
        statusEl.style.display = 'inline-block';
      }
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'In Match';
        findBtn.disabled = true;
        findBtn.style.opacity = '0.7';
      }
      state.isPaused = false;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(false);
      }
      resetGame();
    });

    state.socket.on('pong_matchmaking_waiting', (data) => {
      state.isFindingMatch = true;
      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = data.message || 'Searching for an opponent...';
        statusEl.style.color = '#2563eb';
      }
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'Searching... (Cancel)';
        findBtn.classList.add('ew-btn--active');
      }
    });

    state.socket.on('pong_matchmaking_cancelled', (data) => {
      state.isFindingMatch = false;
      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = data.message || 'Matchmaking cancelled.';
        statusEl.style.color = 'var(--text-secondary)';
      }
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'Find Match';
        findBtn.classList.remove('ew-btn--active');
      }
    });

    state.socket.on('pong_queue_updated', (data) => {
      if (typeof window.__updatePongOpponentsLobby === 'function') {
        window.__updatePongOpponentsLobby(data.queue || []);
      }
    });

    state.socket.on('game_challenge_received', (data) => {
      if (data.game === 'pong' && typeof window.__showPongChallengeModal === 'function') {
        window.__showPongChallengeModal(data);
      }
    });

    state.socket.on('game_challenge_declined', (data) => {
      if (data.game === 'pong') {
        alert((data.challenger_name || 'Opponent') + ' is unavailable or declined.');
      }
    });

    state.socket.on('pong_player_left', (data) => {
      data = data || {};
      state.isPaused = true;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(true);
      }
      const statusEl = document.getElementById('online-status');
      if (!data.reason || data.reason === 'left') {
        // Explicit leave voids the match immediately — no result recorded.
        if (statusEl) {
          statusEl.textContent = 'Opponent left the match.';
          statusEl.style.color = 'var(--text-secondary)';
          statusEl.style.background = 'transparent';
          statusEl.style.border = 'none';
          statusEl.style.padding = '0';
          statusEl.style.fontWeight = 'normal';
          statusEl.style.fontSize = '0.85rem';
          statusEl.style.display = 'block';
        }
        showNoContest('Opponent left. Match void — no result recorded, streak unchanged.');
        return;
      }
      // Dropped opponent: hold a no-contest wait for the grace window.
      // This path must NEVER resolve as a win/loss for either side.
      const grace = Math.max(5, Math.floor(Number(data.reconnect_grace_sec) || 30));
      if (statusEl) {
        statusEl.textContent = `Opponent disconnected. Waiting ${grace}s for reconnect…`;
        statusEl.style.color = '#b45309';
        statusEl.style.display = 'block';
      }
      clearNoContestTimer();
      state.noContestTimer = setTimeout(() => {
        state.noContestTimer = null;
        state.roomId = null;
        showNoContest('Opponent connection lost. Match void — no result recorded, streak unchanged.');
        if (statusEl) statusEl.textContent = 'Match voided (opponent never returned). Find a new match to play.';
      }, grace * 1000);
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'Find Match';
        findBtn.disabled = false;
        findBtn.style.opacity = '1';
        findBtn.classList.remove('ew-btn--active');
      }
    });

    state.socket.on('pong_opponent_rejoined', (data) => {
      data = data || {};
      if (!state.roomId || data.room_id !== state.roomId) return;
      pongDebug('opponent rejoined', data);
      clearNoContestTimer();
      if (Array.isArray(data.scores)) {
        state.p1.score = Math.max(0, Math.floor(Number(data.scores[0]) || 0));
        state.p2.score = Math.max(0, Math.floor(Number(data.scores[1]) || 0));
      }
      if (typeof data.target === 'number' && data.target > 0) state.roomTarget = data.target;
      state.isGameOver = false;
      state.isPaused = false;
      const banner = document.getElementById('game-over-banner');
      if (banner) banner.style.display = 'none';
      setRematchVisible(true);
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(false);
      }
      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = `Reconnected • Playing vs ${state.opponentName}`;
        statusEl.style.color = '#15803d';
      }
    });

    state.socket.on('pong_room_error', (data) => {
      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = (data && data.message) || 'Could not join room.';
        statusEl.style.color = '#b91c1c';
      }
    });

    state.socket.on('disconnect', (reason) => {
      pongDebug('transport disconnect', reason);
      if (state.mode === 'online' && state.roomId && !state.isGameOver) {
        // Our own connection dropped mid-match: freeze and surface it.
        // Never simulate on, never score, never forfeit.
        state.wasDropped = true;
        state.connLost = true;
        state.isPaused = true;
        if (typeof window.__updatePongPauseBtn === 'function') {
          window.__updatePongPauseBtn(true);
        }
        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          statusEl.textContent = 'Connection lost / Reconnecting…';
          statusEl.style.color = '#b45309';
        }
      }
    });

    state.socket.on('connect', () => {
      pongDebug('transport connect');
      if (state.wasDropped && state.mode === 'online' && state.roomId && !state.isGameOver) {
        // Capped rejoin: one initial attempt + one retry, then stop and let
        // the player requeue manually. Unbounded retry loops are forbidden.
        if (state.rejoinAttempts < 2) {
          state.rejoinAttempts++;
          pongDebug('rejoin attempt', state.rejoinAttempts);
          state.socket.emit('join_pong_room', {
            room_id: state.roomId,
            rejoin: true,
            player: state.playerIndex
          });
        } else {
          state.wasDropped = false;
          state.connLost = false;
          const statusEl = document.getElementById('online-status');
          if (statusEl) {
            statusEl.textContent = 'Could not reconnect. Use "Find Match" to play again.';
            statusEl.style.color = 'var(--text-secondary)';
          }
        }
      }
    });
  }

  function sendPaddleSync() {
    if (state.mode !== 'online' || !state.socket || !state.roomId) return;
    // Throttled to ~20 Hz so keyboard, mouse, touch-drag, and on-screen
    // buttons all emit at the same tick-rate parity (no input starves sync,
    // no input floods the relay).
    const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    if (now - state.lastPaddleSend < 50) return;
    state.lastPaddleSend = now;
    const y = state.playerIndex === 0 ? state.p1.y : state.p2.y;
    state.socket.emit('pong_paddle_sync', {
      room_id: state.roomId,
      player: state.playerIndex,
      y: y
    });
  }

  function sendChallenge(targetSid, targetName) {
    initSocket();
    const streak = getLocalStreak('online') || 0;
    const score = getPongRankedScore() || 0;
    state.socket.emit('send_game_challenge', {
      game: 'pong',
      target_sid: targetSid,
      streak,
      score
    });
    const statusEl = document.getElementById('online-status');
    if (statusEl) {
      statusEl.textContent = `Challenged ${targetName}... Waiting for response.`;
      statusEl.style.color = '#2563eb';
    }
  }

  function acceptChallenge(challengerSid) {
    initSocket();
    state.socket.emit('accept_game_challenge', {
      game: 'pong',
      challenger_sid: challengerSid
    });
  }

  function declineChallenge(challengerSid) {
    if (state.socket) {
      state.socket.emit('decline_game_challenge', {
        game: 'pong',
        challenger_sid: challengerSid
      });
    }
  }

  // Public API
  window.__pong = {
    setMode: (mode) => {
      state.mode = mode;
      if (mode === 'online') initSocket();
      clearNoContestTimer();
      setRematchVisible(true);
      resetGame();
      state.isPaused = true;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(true);
      }
      updateStatsUI();
    },
    setDifficulty: (diff) => {
      state.difficulty = diff;
      localStorage.setItem('ew_pong_difficulty', diff);
      resetGame();
      updateStatsUI();
    },
    getDifficulty: () => state.difficulty,
    setTargetScore: (target) => {
      state.targetScore = target === 'endless' ? Infinity : parseInt(target, 10);
      resetGame();
    },
    togglePause: () => {
      if (state.mode === 'online' && state.roomId && state.socket) return false;
      state.isPaused = !state.isPaused;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(state.isPaused);
      }
      return state.isPaused;
    },
    isPaused: () => state.isPaused,
    rematch: () => {
      if (state.mode === 'online' && state.socket && state.roomId) {
        state.socket.emit('pong_restart', { room_id: state.roomId });
      }
      state.isPaused = false;
      if (typeof window.__updatePongPauseBtn === 'function') {
        window.__updatePongPauseBtn(false);
      }
      resetGame();
    },
    findOnlineMatch: () => {
      initSocket();
      if (!state.socket) return;
      if (state.isFindingMatch) {
        state.isFindingMatch = false;
        state.socket.emit('cancel_pong_matchmaking');
      } else {
        state.isFindingMatch = true;
        const statusEl = document.getElementById('online-status');
        if (statusEl) statusEl.textContent = 'Searching for an opponent...';
        const streak = getLocalStreak('online') || 0;
        const score = getPongRankedScore() || 0;
        // Share our first-to-N so the server can bind both clients to one
        // real target (null = endless rally, no winner possible).
        const target = Number.isFinite(state.targetScore) ? state.targetScore : null;
        state.socket.emit('find_pong_match', { streak, score, target });
      }
    },
    sendChallenge: sendChallenge,
    acceptChallenge: acceptChallenge,
    declineChallenge: declineChallenge,
    getSocketId: () => (state.socket ? state.socket.id : null),
    joinOnlineRoom: (roomId) => {
      initSocket();
      if (state.socket) {
        const statusEl = document.getElementById('online-status');
        if (statusEl) statusEl.textContent = `Connecting to room ${roomId}...`;
        state.socket.emit('join_pong_room', { room_id: roomId });
      }
    },
    toggleMute: () => {
      isMuted = !isMuted;
      localStorage.setItem('ew_pong_muted', isMuted ? '1' : '0');
      return isMuted;
    },
    getRankedScore: getPongRankedScore
  };

  // Automatic pause when leaving browser tab
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (state.mode !== 'online' || !state.roomId) {
        state.isPaused = true;
        if (typeof window.__updatePongPauseBtn === 'function') {
          window.__updatePongPauseBtn(true);
        }
      }
    }
  });

  // Start loop & stats UI
  updateStatsUI();
  flushOfflineQueue();
  state.animFrameId = requestAnimationFrame(gameLoop);
})();
