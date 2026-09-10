/**
 * Snake Classic: Responsive, Touch-Adapted Arcade
 * Virtual 20x20 grid, touch-swipe gestures, tactile D-Pad,
 * difficulty presets, and daily/weekly leaderboards.
 */
(function () {
  'use strict';

  const GRID_SIZE = 20; // 20x20 tiles
  const CANVAS_SIZE = 600;
  const TILE_SIZE = CANVAS_SIZE / GRID_SIZE; // 30px per tile

  const canvas = document.getElementById('snake-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Audio Synth (Web Audio API)
  let audioCtx = null;
  let isMuted = localStorage.getItem('ew_snake_muted') === '1';

  function initAudio() {
    if (!audioCtx) {
      try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) audioCtx = new AudioContext();
      } catch (e) {}
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

  function soundEat() {
    playTone(587.33, 'sine', 0.08, 0.1);
    setTimeout(() => playTone(880, 'sine', 0.12, 0.1), 70);
  }
  function soundTurn() { playTone(300, 'sine', 0.03, 0.04); }
  function soundCrash() { playTone(120, 'sawtooth', 0.18, 0.12); }
  function soundGameOver() {
    playTone(392, 'triangle', 0.15, 0.1);
    setTimeout(() => playTone(329.63, 'triangle', 0.2, 0.1), 130);
    setTimeout(() => playTone(261.63, 'triangle', 0.35, 0.1), 280);
  }

  // Game State
  const state = {
    difficulty: localStorage.getItem('ew_snake_difficulty') || 'casual',
    wallMode: 'solid', // 'solid' or 'wrap'
    snake: [{ x: 6, y: 10 }, { x: 5, y: 10 }, { x: 4, y: 10 }],
    direction: 'RIGHT',
    nextDirection: 'RIGHT',
    food: { x: 14, y: 10 },
    score: 0,
    foodEaten: 0,
    speed: 180,
    baseSpeed: 180,
    isGameOver: false,
    isPaused: true, // Paused by default on page load so player can get ready
    timerId: null
  };

  function getBaseSpeed(diff) {
    if (diff === 'turbo') return 85;
    if (diff === 'normal') return 130;
    return 180; // casual
  }

  function getScoreMultiplier(diff) {
    if (diff === 'turbo') return 2.0;
    if (diff === 'normal') return 1.5;
    return 1.0; // casual
  }

  function getBestScoreKey(diff) {
    return `ew_snake_best_${diff || state.difficulty}`;
  }

  function getLocalBest(diff) {
    return parseInt(localStorage.getItem(getBestScoreKey(diff)) || '0', 10);
  }

  function setLocalBest(diff, score) {
    localStorage.setItem(getBestScoreKey(diff), score.toString());
  }

  function updateStatsUI() {
    const bestEl = document.getElementById('my-snake-best');
    const applesEl = document.getElementById('my-snake-apples');
    if (bestEl) bestEl.textContent = `${getLocalBest(state.difficulty).toLocaleString()} pts`;
    if (applesEl) applesEl.textContent = (localStorage.getItem('ew_snake_total_apples') || '0');
  }

  // Offline Sync Queue
  function queueOfflineSubmission(payload) {
    try {
      const q = JSON.parse(localStorage.getItem('ew_snake_offline_queue') || '[]');
      q.push(payload);
      localStorage.setItem('ew_snake_offline_queue', JSON.stringify(q));
    } catch (e) {}
  }

  async function flushOfflineQueue() {
    if (!navigator.onLine) return;
    try {
      const q = JSON.parse(localStorage.getItem('ew_snake_offline_queue') || '[]');
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
      localStorage.setItem('ew_snake_offline_queue', JSON.stringify(remaining));
    } catch (e) {}
  }
  window.addEventListener('online', flushOfflineQueue);

  function getOrCreateGuestToken() {
    let tok = localStorage.getItem('ew_guest_token');
    if (!tok) {
      tok = 'g_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
      localStorage.setItem('ew_guest_token', tok);
    }
    return tok;
  }

  async function submitScore(category, score, metadata = {}) {
    const payload = {
      game: 'snake',
      category: category,
      score: Math.max(1, Math.floor(score)),
      metadata: {
        difficulty: state.difficulty,
        mode: state.wallMode,
        food_eaten: state.foodEaten,
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

  function generateFood() {
    let fx, fy;
    let attempts = 0;
    do {
      fx = Math.floor(Math.random() * GRID_SIZE);
      fy = Math.floor(Math.random() * GRID_SIZE);
      attempts++;
    } while (attempts < 200 && state.snake.some(s => s.x === fx && s.y === fy));
    return { x: fx, y: fy };
  }

  function setDirection(newDir) {
    const opposites = { UP: 'DOWN', DOWN: 'UP', LEFT: 'RIGHT', RIGHT: 'LEFT' };
    if (newDir && newDir !== opposites[state.direction]) {
      if (newDir !== state.direction) soundTurn();
      state.nextDirection = newDir;
    }
  }

  // Touch Swipe Gesture Detection
  let touchStartX = 0;
  let touchStartY = 0;

  canvas.addEventListener('touchstart', (e) => {
    initAudio();
    if (e.touches.length === 1) {
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
    }
  }, { passive: true });

  canvas.addEventListener('touchend', (e) => {
    if (e.changedTouches.length === 1) {
      const touchEndX = e.changedTouches[0].clientX;
      const touchEndY = e.changedTouches[0].clientY;
      const dx = touchEndX - touchStartX;
      const dy = touchEndY - touchStartY;

      if (Math.abs(dx) > Math.abs(dy) && Math.abs(dx) > 24) {
        if (dx > 0) setDirection('RIGHT');
        else setDirection('LEFT');
      } else if (Math.abs(dy) > 24) {
        if (dy > 0) setDirection('DOWN');
        else setDirection('UP');
      }
    }
  }, { passive: true });

  // Virtual On-Screen D-Pad
  const dpadUp = document.getElementById('dpad-up');
  const dpadDown = document.getElementById('dpad-down');
  const dpadLeft = document.getElementById('dpad-left');
  const dpadRight = document.getElementById('dpad-right');

  function bindDpad(btn, dir) {
    if (!btn) return;
    const trigger = (e) => {
      e.preventDefault();
      initAudio();
      setDirection(dir);
    };
    btn.addEventListener('pointerdown', trigger);
  }
  bindDpad(dpadUp, 'UP');
  bindDpad(dpadDown, 'DOWN');
  bindDpad(dpadLeft, 'LEFT');
  bindDpad(dpadRight, 'RIGHT');

  // Keyboard Controls
  window.addEventListener('keydown', (e) => {
    initAudio();
    if (e.key === ' ' || e.code === 'Space') {
      e.preventDefault();
      togglePauseInternal();
      return;
    }
    if (state.isPaused) return;
    if (e.key === 'ArrowUp' || e.key === 'w' || e.key === 'W') setDirection('UP');
    else if (e.key === 'ArrowDown' || e.key === 's' || e.key === 'S') setDirection('DOWN');
    else if (e.key === 'ArrowLeft' || e.key === 'a' || e.key === 'A') setDirection('LEFT');
    else if (e.key === 'ArrowRight' || e.key === 'd' || e.key === 'D') setDirection('RIGHT');
  });

  // Canvas click unpauses
  canvas.addEventListener('click', () => {
    initAudio();
    if (state.isPaused && !state.isGameOver) {
      unpauseGame();
    }
  });

  // Pause / Unpause Helpers
  function unpauseGame() {
    if (!state.isPaused || state.isGameOver) return;
    state.isPaused = false;
    clearInterval(state.timerId);
    state.timerId = setInterval(tick, state.speed);
    render();
    if (typeof window.__updateSnakePauseBtn === 'function') {
      window.__updateSnakePauseBtn(false);
    }
  }

  function pauseGame() {
    if (state.isPaused || state.isGameOver) return;
    state.isPaused = true;
    clearInterval(state.timerId);
    render();
    if (typeof window.__updateSnakePauseBtn === 'function') {
      window.__updateSnakePauseBtn(true);
    }
  }

  function togglePauseInternal() {
    if (state.isGameOver) return;
    if (state.isPaused) unpauseGame();
    else pauseGame();
  }

  // Game Logic Loop
  function tick() {
    if (state.isGameOver) return;
    if (state.isPaused) return;

    state.direction = state.nextDirection;
    const head = { ...state.snake[0] };

    if (state.direction === 'UP') head.y -= 1;
    else if (state.direction === 'DOWN') head.y += 1;
    else if (state.direction === 'LEFT') head.x -= 1;
    else if (state.direction === 'RIGHT') head.x += 1;

    // Handle Wall Collision / Wrap
    if (state.wallMode === 'wrap') {
      if (head.x < 0) head.x = GRID_SIZE - 1;
      else if (head.x >= GRID_SIZE) head.x = 0;
      if (head.y < 0) head.y = GRID_SIZE - 1;
      else if (head.y >= GRID_SIZE) head.y = 0;
    } else {
      if (head.x < 0 || head.x >= GRID_SIZE || head.y < 0 || head.y >= GRID_SIZE) {
        gameOver();
        return;
      }
    }

    // Check Self Bite
    if (state.snake.some(s => s.x === head.x && s.y === head.y)) {
      gameOver();
      return;
    }

    state.snake.unshift(head);

    // Check Food Collision
    if (head.x === state.food.x && head.y === state.food.y) {
      soundEat();
      state.foodEaten++;
      const mult = getScoreMultiplier(state.difficulty);
      state.score += Math.round(10 * mult);
      state.food = generateFood();

      // Speed acceleration (down to floor)
      const minSpeed = state.difficulty === 'turbo' ? 45 : (state.difficulty === 'normal' ? 70 : 120);
      if (state.speed > minSpeed && state.foodEaten % 3 === 0) {
        state.speed = Math.max(minSpeed, state.speed - 3);
        clearInterval(state.timerId);
        state.timerId = setInterval(tick, state.speed);
      }
    } else {
      state.snake.pop();
    }

    render();
  }

  function gameOver() {
    state.isGameOver = true;
    clearInterval(state.timerId);
    soundCrash();
    setTimeout(soundGameOver, 150);

    const banner = document.getElementById('game-over-banner');
    const finalScoreText = document.getElementById('final-score-text');
    if (finalScoreText) {
      finalScoreText.textContent = `Final Score: ${state.score} • Apples: ${state.foodEaten}`;
    }
    if (banner) banner.style.display = 'block';

    // Update Local Best
    const currentBest = getLocalBest(state.difficulty);
    if (state.score > currentBest) {
      setLocalBest(state.difficulty, state.score);
    }

    // Update Total Apples
    const totalApples = parseInt(localStorage.getItem('ew_snake_total_apples') || '0', 10) + state.foodEaten;
    localStorage.setItem('ew_snake_total_apples', totalApples.toString());

    updateStatsUI();

    // Submit to Leaderboard if score > 0
    if (state.score > 0) {
      const mult = getScoreMultiplier(state.difficulty);
      const rankedScore = Math.round(state.score * mult);
      submitScore('ranked_score', rankedScore, { multiplier: mult });
      submitScore('high_score', state.score);
      if (state.foodEaten > 0) {
        submitScore('food_eaten', state.foodEaten);
      }
    }
  }

  function restart() {
    clearInterval(state.timerId);
    state.isGameOver = false;
    state.isPaused = true;
    state.snake = [{ x: 6, y: 10 }, { x: 5, y: 10 }, { x: 4, y: 10 }];
    state.direction = 'RIGHT';
    state.nextDirection = 'RIGHT';
    state.score = 0;
    state.foodEaten = 0;
    state.speed = getBaseSpeed(state.difficulty);
    state.food = generateFood();

    const banner = document.getElementById('game-over-banner');
    if (banner) banner.style.display = 'none';

    render(); // Will draw pause overlay since isPaused = true
    // Don't start timer — user must press Play / Space / click canvas
    if (typeof window.__updateSnakePauseBtn === 'function') {
      window.__updateSnakePauseBtn(true);
    }
  }

  function render() {
    ctx.clearRect(0, 0, CANVAS_SIZE, CANVAS_SIZE);

    // Background grid
    ctx.fillStyle = '#121212';
    ctx.fillRect(0, 0, CANVAS_SIZE, CANVAS_SIZE);

    // Subtle grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= CANVAS_SIZE; i += TILE_SIZE) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, CANVAS_SIZE);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(CANVAS_SIZE, i);
      ctx.stroke();
    }

    // Draw Food (Apple)
    ctx.fillStyle = '#e06a3b'; // Platform terracotta
    const fx = state.food.x * TILE_SIZE + TILE_SIZE / 2;
    const fy = state.food.y * TILE_SIZE + TILE_SIZE / 2;
    ctx.beginPath();
    ctx.arc(fx, fy, TILE_SIZE / 2 - 3, 0, Math.PI * 2);
    ctx.fill();

    // Food leaf highlight
    ctx.fillStyle = '#2e86ab';
    ctx.beginPath();
    ctx.arc(fx + 3, fy - 6, 2.5, 0, Math.PI * 2);
    ctx.fill();

    // Draw Snake
    state.snake.forEach((seg, idx) => {
      const isHead = idx === 0;
      ctx.fillStyle = isHead ? '#2e86ab' : '#226f8e'; // Platform ocean blue palette
      const px = seg.x * TILE_SIZE;
      const py = seg.y * TILE_SIZE;
      const r = isHead ? 6 : 3;

      ctx.beginPath();
      ctx.roundRect(px + 1, py + 1, TILE_SIZE - 2, TILE_SIZE - 2, r);
      ctx.fill();

      if (isHead) {
        // Eyes
        ctx.fillStyle = '#ffffff';
        let e1x = px + 8, e1y = py + 8, e2x = px + 8, e2y = py + 22;
        if (state.direction === 'RIGHT') { e1x = px + 22; e2x = px + 22; }
        else if (state.direction === 'UP') { e1x = px + 8; e1y = py + 8; e2x = px + 22; e2y = py + 8; }
        else if (state.direction === 'DOWN') { e1x = px + 8; e1y = py + 22; e2x = px + 22; e2y = py + 22; }
        ctx.fillRect(e1x - 2, e1y - 2, 4, 4);
        ctx.fillRect(e2x - 2, e2y - 2, 4, 4);
      }
    });

    // Score Overlay in Top Left
    ctx.fillStyle = '#ffffff';
    ctx.font = '700 20px monospace';
    ctx.fillText(`SCORE: ${state.score}`, 16, 32);

    ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.font = '600 13px sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`APPLES: ${state.foodEaten}`, CANVAS_SIZE - 16, 32);
    ctx.textAlign = 'start';

    drawPauseOverlay();
  }

  function drawPauseOverlay() {
    if (!state.isPaused) return;
    ctx.save();
    ctx.fillStyle = 'rgba(18, 18, 18, 0.65)';
    ctx.fillRect(0, 0, CANVAS_SIZE, CANVAS_SIZE);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 32px Poppins, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('PAUSED', CANVAS_SIZE / 2, CANVAS_SIZE / 2 - 18);

    ctx.font = '500 15px Poppins, sans-serif';
    ctx.fillStyle = '#e8dec8';
    ctx.fillText('Press Space or Click Canvas to Play', CANVAS_SIZE / 2, CANVAS_SIZE / 2 + 20);
    ctx.restore();
  }

  // Public Interface
  window.__snake = {
    setDifficulty: (diff) => {
      state.difficulty = diff;
      localStorage.setItem('ew_snake_difficulty', diff);
      restart();
      updateStatsUI();
    },
    getDifficulty: () => state.difficulty,
    setWallMode: (mode) => {
      state.wallMode = mode;
      restart();
    },
    restart: () => {
      restart();
    },
    togglePause: () => {
      togglePauseInternal();
      return state.isPaused;
    },
    isPaused: () => state.isPaused,
    toggleMute: () => {
      isMuted = !isMuted;
      localStorage.setItem('ew_snake_muted', isMuted ? '1' : '0');
      return isMuted;
    }
  };

  // Initialize
  updateStatsUI();
  flushOfflineQueue();
  restart();
})();
