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
    lastSyncTime: 0
  };

  function getStreakKey(diff) {
    return `ew_pong_streak_${diff || state.difficulty}`;
  }

  function getLocalStreak(diff) {
    return parseInt(localStorage.getItem(getStreakKey(diff)) || '0', 10);
  }

  function setLocalStreak(diff, val) {
    localStorage.setItem(getStreakKey(diff), val.toString());
  }

  function updateStatsUI() {
    const streakEl = document.getElementById('my-pong-streak');
    const volleysEl = document.getElementById('my-pong-volleys');
    const winsEl = document.getElementById('my-pong-wins');
    const activeStreak = state.mode === 'online' ? getLocalStreak('online') : getLocalStreak(state.difficulty);
    if (streakEl) streakEl.textContent = `${activeStreak} wins`;
    if (volleysEl) volleysEl.textContent = (localStorage.getItem('ew_pong_total_volleys') || '0');
    const totalWinsKey = state.mode === 'online' ? 'ew_pong_wins_online' : `ew_pong_wins_${state.difficulty}`;
    if (winsEl) winsEl.textContent = (localStorage.getItem(totalWinsKey) || '0');
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

  // Controls Binding
  window.addEventListener('keydown', (e) => {
    initAudio();
    if (e.key === 'w' || e.key === 'W') state.p1.dy = -7;
    if (e.key === 's' || e.key === 'S') state.p1.dy = 7;

    if (state.mode === 'local') {
      if (e.key === 'ArrowUp') state.p2.dy = -7;
      if (e.key === 'ArrowDown') state.p2.dy = 7;
    } else {
      // In solo mode, Arrow keys can also move Player 1 for user convenience
      if (e.key === 'ArrowUp') state.p1.dy = -7;
      if (e.key === 'ArrowDown') state.p1.dy = 7;
    }
  });

  window.addEventListener('keyup', (e) => {
    if (e.key === 'w' || e.key === 'W' || e.key === 's' || e.key === 'S') state.p1.dy = 0;
    if (state.mode === 'local') {
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

    // In online mode, guest receives positions from host
    if (state.mode === 'online' && !state.isHost) {
      // Guest moves their paddle locally
      state.p2.y += state.p2.dy;
      state.p2.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p2.y));
      return;
    }

    // Update paddle positions
    state.p1.y += state.p1.dy;
    state.p1.y = Math.max(0, Math.min(V_HEIGHT - PADDLE_H, state.p1.y));

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
    if (state.targetScore !== Infinity && (state.p1.score >= state.targetScore || state.p2.score >= state.targetScore)) {
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
    state.isGameOver = true;
    const isPlayer1Winner = winningPlayer === 1;

    if (isPlayer1Winner) soundWin();
    else soundLose();

    // Show banner
    const banner = document.getElementById('game-over-banner');
    const winnerText = document.getElementById('winner-text');
    const winnerStreak = document.getElementById('winner-streak');

    let title = 'Match Complete';
    if (state.mode === 'ai') {
      title = isPlayer1Winner ? 'You Win!' : 'AI Wins!';
    } else if (state.mode === 'local') {
      title = isPlayer1Winner ? 'Player 1 Wins!' : 'Player 2 Wins!';
    } else if (state.mode === 'online') {
      const myWon = (state.playerIndex === 0 && isPlayer1Winner) || (state.playerIndex === 1 && !isPlayer1Winner);
      title = myWon ? 'Victory!' : 'Defeat!';
    }

    if (winnerText) winnerText.textContent = title;

    // Handle Streak and Leaderboard Submissions
    if (state.mode !== 'local') {
      const activeDiff = state.mode === 'online' ? 'online' : state.difficulty;
      let streak = getLocalStreak(activeDiff);

      if (isPlayer1Winner || (state.mode === 'online' && ((state.playerIndex === 0 && isPlayer1Winner) || (state.playerIndex === 1 && !isPlayer1Winner)))) {
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

        const rankedScore = basePoints + (state.maxMatchVolleys * volleyMult);

        // Submit to leaderboards
        submitScore('ranked_score', rankedScore, { multiplier: volleyMult });
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
  }

  // Main Loop
  function gameLoop(now) {
    update(now);
    render();
    state.animFrameId = requestAnimationFrame(gameLoop);
  }

  // Socket.IO 1v1 Implementation
  function initSocket() {
    if (state.socket) return;
    if (typeof io === 'undefined') return;

    state.socket = io();

    state.socket.on('pong_room_joined', (data) => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.playerIndex = data.player;
      state.opponentName = data.is_host ? (data.guest_name || 'Opponent') : (data.host_name || 'Host');

      const statusEl = document.getElementById('online-status');
      if (statusEl) {
        statusEl.textContent = `Room ${data.room_id} • Playing vs ${state.opponentName}`;
        statusEl.style.color = '#e06a3b';
      }
      resetGame();
    });

    state.socket.on('pong_paddle_sync', (data) => {
      if (state.playerIndex === 0) {
        state.p2.y = data.y;
      } else {
        state.p1.y = data.y;
      }
    });

    state.socket.on('pong_ball_sync', (data) => {
      if (!state.isHost) {
        state.ball.x = data.x;
        state.ball.y = data.y;
        state.ball.vx = data.vx;
        state.ball.vy = data.vy;
        state.ball.speed = data.speed;
        state.p1.y = data.p1Y;
        state.consecutiveVolleys = data.volleys;
      }
    });

    state.socket.on('pong_score_update', (data) => {
      if (data.scores) {
        state.p1.score = data.scores[0];
        state.p2.score = data.scores[1];
      }
      if (data.winner) {
        finishMatch(data.winner);
      }
    });

    state.socket.on('pong_restart', () => {
      resetGame();
    });

    state.socket.on('pong_match_found', (data) => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.playerIndex = data.player;
      state.opponentName = data.is_host ? data.guest_name : data.host_name;

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
      resetGame();
    });

    state.socket.on('pong_player_left', () => {
      const statusEl = document.getElementById('online-status');
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
      const findBtn = document.getElementById('find-match-btn');
      if (findBtn) {
        findBtn.textContent = 'Find Match';
        findBtn.disabled = false;
        findBtn.style.opacity = '1';
      }
    });
  }

  function sendPaddleSync() {
    if (state.mode !== 'online' || !state.socket || !state.roomId) return;
    const y = state.playerIndex === 0 ? state.p1.y : state.p2.y;
    state.socket.emit('pong_paddle_sync', {
      room_id: state.roomId,
      player: state.playerIndex,
      y: y
    });
  }

  // Public API
  window.__pong = {
    setMode: (mode) => {
      state.mode = mode;
      if (mode === 'online') initSocket();
      resetGame();
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
    rematch: () => {
      if (state.mode === 'online' && state.socket && state.roomId) {
        state.socket.emit('pong_restart', { room_id: state.roomId });
      }
      resetGame();
    },
    findOnlineMatch: () => {
      initSocket();
      if (state.socket) {
        const statusEl = document.getElementById('online-status');
        if (statusEl) statusEl.textContent = 'Searching for an opponent...';
        state.socket.emit('find_pong_match');
      }
    },
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
    }
  };

  // Start loop & stats UI
  updateStatsUI();
  flushOfflineQueue();
  state.animFrameId = requestAnimationFrame(gameLoop);
})();
