/**
 * Slime Volleyball for EchoWithin
 * Adapted from David Ha's Neural Slime Volleyball (MIT License)
 * Features:
 *  - Solo Mode: Play against trained Neural AI (120-parameter RNN)
 *  - Local 2-Player: Split keyboard / touch on single device
 *  - Online 1v1 (SocketIO): Real-time sync at ~18 Hz
 *  - Full Mobile Touch Support + Procedural Web Audio
 */
(() => {
  'use strict';

  // Coordinate space & constants (Canonical Slime Volley units scaled for high readability)
  const REF_W = 48;
  const REF_H = 26; // Arena ceiling height
  const REF_U = 1.5; // ground height
  const REF_WALL_W = 1.2;
  const REF_WALL_H = 5.2; // Net height proportional to slime
  const SLIME_R = 3.2; // Big, clear slimes (more than double old 1.5)
  const BALL_R = 1.05; // Big, easily visible volleyball
  const GRAVITY = -32.0;
  const PLAYER_SPEED_X = 18.0;
  const PLAYER_SPEED_Y = 14.5;
  const MAX_BALL_SPEED = 24.0;
  const TIMESTEP = 1 / 60; // 60Hz fixed physics step
  const SUB_STEPS = 4; // 4x sub-stepping for zero collision tunneling
  const RESTITUTION = 0.82; // Ball-slime bounce coefficient
  const WALL_RESTITUTION = 0.80; // Ball-wall/net bounce coefficient
  const PADDLE_MOMENTUM_TRANSFER = 0.25; // Horizontal momentum transfer
  const NUDGE = 0.1;
  const FRICTION = 1.0;
  const WIN_SCORE = 5;

  // AI Difficulty & Paddle Physics Presets
  const DIFFICULTY_CONFIG = {
    easy: {
      name: 'Easy',
      reactionDelayMs: 220,    // 220ms reaction delay before tracking changes
      speedCap: 0.58,          // AI paddle moves at 58% of max player speed
      jitterRange: 1.3,        // ±1.3 game units (~26px) random target offset
      jumpDeadzone: 2.2,       // Only jumps if ball is within tight X proximity
      missChance: 0.22,        // Occasional human-like error on sharp shots
      playerSizeBonus: 1.20,   // +20% player paddle size
      serveSpeedScale: 0.75,   // 75% base serve speed
      speedUpPerHit: 1.035     // Gentle rally acceleration
    },
    normal: {
      name: 'Normal',
      reactionDelayMs: 120,    // 120ms reaction delay
      speedCap: 0.76,          // AI paddle moves at 76% of player speed
      jitterRange: 0.7,        // ±0.7 game units (~14px) random target offset
      jumpDeadzone: 1.2,
      missChance: 0.08,
      playerSizeBonus: 1.12,   // +12% player paddle size
      serveSpeedScale: 0.88,   // 88% base serve speed
      speedUpPerHit: 1.045     // Moderate rally acceleration
    },
    hard: {
      name: 'Hard',
      reactionDelayMs: 0,      // Pure frame-by-frame neural agent (original)
      speedCap: 0.95,          // 95% speed
      jitterRange: 0.0,
      jumpDeadzone: 0.0,
      missChance: 0.0,
      playerSizeBonus: 1.0,    // Standard paddle size
      serveSpeedScale: 1.0,    // 100% serve speed
      speedUpPerHit: 1.06      // Standard acceleration
    }
  };

  let canvas, ctx;
  let W = 960, H = 540;
  let factor = W / REF_W;

  function toX(x) { return (x + REF_W / 2) * factor; }
  function toY(y) { return H - (y * factor); }
  function toP(r) { return r * factor; }

  // Audio synthesis (Web Audio API) with master compressor to avoid clipping & distortion
  let AC = null;
  let masterCompressor = null;
  let soundMuted = false;
  let lastBeepTime = 0;
  function beep(freq, dur, type = 'sine', gain = 0.06, slide = 0) {
    if (soundMuted) return;
    const now = (window.performance && performance.now) ? performance.now() : Date.now();
    if (now - lastBeepTime < 50 && (type === 'square' || type === 'triangle')) return;
    lastBeepTime = now;
    try {
      if (!AC) {
        AC = new (window.AudioContext || window.webkitAudioContext)();
        masterCompressor = AC.createDynamicsCompressor();
        masterCompressor.threshold.setValueAtTime(-12, AC.currentTime);
        masterCompressor.knee.setValueAtTime(30, AC.currentTime);
        masterCompressor.ratio.setValueAtTime(12, AC.currentTime);
        masterCompressor.attack.setValueAtTime(0.003, AC.currentTime);
        masterCompressor.release.setValueAtTime(0.25, AC.currentTime);
        masterCompressor.connect(AC.destination);
      }
      if (AC.state === 'suspended') AC.resume().catch(() => {});
      const o = AC.createOscillator(), g = AC.createGain();
      o.type = type;
      o.frequency.setValueAtTime(freq, AC.currentTime);
      if (slide) o.frequency.exponentialRampToValueAtTime(Math.max(30, freq + slide), AC.currentTime + dur);
      g.gain.setValueAtTime(Math.min(gain, 0.08), AC.currentTime);
      g.gain.exponentialRampToValueAtTime(0.0001, AC.currentTime + dur);
      o.connect(g); g.connect(masterCompressor || AC.destination);
      o.start(); o.stop(AC.currentTime + dur);
    } catch (_) {}
  }

  const SFX = {
    bounce: () => beep(240, 0.08, 'triangle', 0.07, -40),
    net: () => beep(180, 0.1, 'square', 0.04, -30),
    whistle: () => {
      beep(1400, 0.12, 'sine', 0.05);
      setTimeout(() => beep(1750, 0.22, 'sine', 0.05), 110);
    },
    win: () => {
      beep(523, 0.15, 'triangle', 0.07);
      setTimeout(() => beep(659, 0.15, 'triangle', 0.07), 120);
      setTimeout(() => beep(784, 0.35, 'triangle', 0.08), 240);
    }
  };

  // Ball class
  class Ball {
    constructor(x = 0, y = 11, vx = 0, vy = 0) {
      this.x = x; this.y = y;
      this.prev_x = x; this.prev_y = y;
      this.vx = vx; this.vy = vy;
      this.r = BALL_R;
      this.rot = 0;
    }
    move(dt = TIMESTEP) {
      this.prev_x = this.x; this.prev_y = this.y;
      this.x += this.vx * dt;
      this.y += this.vy * dt;
      this.rot += (this.vx * dt) / this.r;
    }
    applyGravity(dt = TIMESTEP) {
      this.vy += GRAVITY * dt;
    }
    checkEdges(dt = TIMESTEP) {
      const halfCourt = REF_W / 2;
      const halfNet = REF_WALL_W / 2;
      const topNet = REF_WALL_H;

      // Left Court Wall
      if (this.x <= -halfCourt + this.r) {
        this.x = -halfCourt + this.r;
        this.vx = Math.abs(this.vx) * WALL_RESTITUTION;
        SFX.bounce();
      }
      // Right Court Wall
      if (this.x >= halfCourt - this.r) {
        this.x = halfCourt - this.r;
        this.vx = -Math.abs(this.vx) * WALL_RESTITUTION;
        SFX.bounce();
      }
      // Top Ceiling
      if (this.y >= REF_H - this.r) {
        this.y = REF_H - this.r;
        this.vy = -Math.abs(this.vy) * WALL_RESTITUTION;
        SFX.bounce();
      }

      // Net Collision
      // 1. Vertical post rectangular sides (below top of net)
      if (this.y < topNet) {
        // Approaching from left side of net
        if (this.x + this.r >= -halfNet && this.x < 0) {
          this.x = -halfNet - this.r;
          this.vx = -Math.abs(this.vx) * WALL_RESTITUTION;
          SFX.net();
        }
        // Approaching from right side of net
        else if (this.x - this.r <= halfNet && this.x > 0) {
          this.x = halfNet + this.r;
          this.vx = Math.abs(this.vx) * WALL_RESTITUTION;
          SFX.net();
        }
      }

      // 2. Rounded net top cap (circle at (0, topNet) with radius halfNet)
      const stubDx = this.x;
      const stubDy = this.y - topNet;
      const stubDist2 = stubDx * stubDx + stubDy * stubDy;
      const stubR = halfNet + this.r;
      if (stubDist2 < stubR * stubR && this.y >= topNet) {
        const d = Math.sqrt(stubDist2) || 1;
        const nx = stubDx / d;
        const ny = stubDy / d;
        this.x = nx * stubR;
        this.y = topNet + ny * stubR;
        const dot = this.vx * nx + this.vy * ny;
        if (dot < 0) {
          this.vx = (this.vx - 2 * dot * nx) * WALL_RESTITUTION;
          this.vy = (this.vy - 2 * dot * ny) * WALL_RESTITUTION;
          SFX.net();
        }
      }

      // Ground Floor
      if (this.y <= REF_U + this.r) {
        this.y = REF_U + this.r;
        return this.x <= 0 ? -1 : 1; // -1 = hit left court (P2 point), 1 = hit right court (P1 point)
      }
      return 0;
    }
    bounceSlime(slime) {
      const dx = this.x - slime.x;
      const dy = this.y - slime.y;
      const dist2 = dx * dx + dy * dy;
      const totalR = this.r + slime.r;

      // Semicircle collision: center distance < totalR AND upper dome (dy >= -0.1)
      if (dist2 < totalR * totalR && dy >= -0.1) {
        const d = Math.sqrt(dist2) || 1;
        const nx = dx / d;
        const ny = dy / d;

        // Ensure collision normal is directed upward (curved dome)
        if (ny >= 0) {
          // Positional separation to prevent sticking / sinking
          this.x = slime.x + nx * totalR;
          this.y = slime.y + ny * totalR;

          // Relative velocity
          const relVx = this.vx - slime.vx;
          const relVy = this.vy - slime.vy;
          const dot = relVx * nx + relVy * ny;

          if (dot < 0) {
            const e = RESTITUTION;
            this.vx = (relVx - (1 + e) * dot * nx) + slime.vx + slime.vx * PADDLE_MOMENTUM_TRANSFER;
            this.vy = (relVy - (1 + e) * dot * ny) + slime.vy;

            // Gradual rally acceleration
            GameState.rallyCount = (GameState.rallyCount || 0) + 1;
            const cfg = (typeof DIFFICULTY_CONFIG !== 'undefined' && DIFFICULTY_CONFIG[GameState.difficulty]) ? DIFFICULTY_CONFIG[GameState.difficulty] : null;
            if (cfg && cfg.speedUpPerHit) {
              const mult = Math.min(1.35, Math.pow(cfg.speedUpPerHit, Math.min(10, GameState.rallyCount)));
              this.vx *= mult;
            }
            this.limitSpeed(5.0, MAX_BALL_SPEED);
            SFX.bounce();
            return true;
          }
        }
      }
      return false;
    }
    limitSpeed(minSpeed, maxSpeed) {
      const spd2 = this.vx * this.vx + this.vy * this.vy;
      if (spd2 > maxSpeed * maxSpeed) {
        const spd = Math.sqrt(spd2);
        this.vx = (this.vx / spd) * maxSpeed;
        this.vy = (this.vy / spd) * maxSpeed;
      }
    }
    draw(ctx) {
      const px = toX(this.x), py = toY(this.y), pr = toP(this.r);
      ctx.save();
      ctx.translate(px, py);
      ctx.rotate(this.rot);

      // Volleyball body
      ctx.beginPath();
      ctx.arc(0, 0, pr, 0, Math.PI * 2);
      ctx.fillStyle = '#fffdfa';
      ctx.fill();
      ctx.lineWidth = 1.8;
      ctx.strokeStyle = '#3e2217';
      ctx.stroke();

      // Volleyball leather seams
      ctx.beginPath();
      ctx.arc(-pr * 0.4, 0, pr * 0.6, -Math.PI / 2, Math.PI / 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(pr * 0.4, 0, pr * 0.6, Math.PI / 2, -Math.PI / 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(-pr, 0); ctx.lineTo(pr, 0);
      ctx.stroke();
      ctx.restore();
    }
  }

  // Slime player class
  class Slime {
    constructor(dir, x, color, name = 'Player') {
      this.dir = dir; // -1 = Left (Coral), 1 = Right (Teal)
      this.startX = x;
      this.x = x; this.y = REF_U;
      this.vx = 0; this.vy = 0;
      this.desiredVx = 0;
      this.r = SLIME_R;
      this.color = color;
      this.name = name;
      this.score = 0;
      this.isGrounded = true;
    }
    reset() {
      this.x = this.startX; this.y = REF_U;
      this.vx = 0; this.vy = 0;
      this.desiredVx = 0;
      this.isGrounded = true;
    }
    setInput(left, right, jump, speedScale = 1.0) {
      this.desiredVx = 0;
      const speedX = PLAYER_SPEED_X * speedScale;
      if (left && !right) this.desiredVx = -speedX;
      if (right && !left) this.desiredVx = speedX;
      if (jump && this.isGrounded) {
        this.vy = PLAYER_SPEED_Y;
        this.isGrounded = false;
      }
    }
    update(dt = TIMESTEP) {
      if (!this.isGrounded) {
        this.vy += GRAVITY * dt;
      }
      this.vx = this.desiredVx;
      this.x += this.vx * dt;
      this.y += this.vy * dt;

      if (this.y <= REF_U) {
        this.y = REF_U;
        this.vy = 0;
        this.isGrounded = true;
      }

      // Net and court boundary clamp: slimes can NEVER cross the net
      const halfNet = REF_WALL_W / 2;
      const halfCourt = REF_W / 2;
      if (this.dir === -1) {
        if (this.x < -halfCourt + this.r) this.x = -halfCourt + this.r;
        if (this.x > -halfNet - this.r) this.x = -halfNet - this.r;
      } else {
        if (this.x < halfNet + this.r) this.x = halfNet + this.r;
        if (this.x > halfCourt - this.r) this.x = halfCourt - this.r;
      }
    }
    draw(ctx, ball) {
      const px = toX(this.x), py = toY(this.y), pr = toP(this.r);

      // Slime Dome
      ctx.beginPath();
      ctx.arc(px, py, pr, Math.PI, 0, false);
      ctx.closePath();
      ctx.fillStyle = this.color;
      ctx.fill();
      ctx.lineWidth = 2.5;
      ctx.strokeStyle = '#2c1810';
      ctx.stroke();

      // Pupil / Eye tracking ball
      const eyeAngle = (this.dir === -1) ? (Math.PI / 4) : (3 * Math.PI / 4);
      const eyeOffsetX = Math.cos(eyeAngle) * (pr * 0.55);
      const eyeOffsetY = -Math.sin(eyeAngle) * (pr * 0.55);
      const eyeX = px + eyeOffsetX;
      const eyeY = py + eyeOffsetY;

      // Eye White
      ctx.beginPath();
      ctx.arc(eyeX, eyeY, pr * 0.22, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
      ctx.strokeStyle = '#2c1810';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Pupil looking towards ball
      const bpx = toX(ball.x), bpy = toY(ball.y);
      const bdx = bpx - eyeX, bdy = bpy - eyeY;
      const bdist = Math.sqrt(bdx * bdx + bdy * bdy) || 1;
      const pupilX = eyeX + (bdx / bdist) * (pr * 0.08);
      const pupilY = eyeY + (bdy / bdist) * (pr * 0.08);

      ctx.beginPath();
      ctx.arc(pupilX, pupilY, pr * 0.1, 0, Math.PI * 2);
      ctx.fillStyle = '#1a100b';
      ctx.fill();
    }
  }

  // Trained RNN Neural Network Baseline Policy (David Ha, Neural Slime Volleyball)
  class NeuralAgent {
    constructor() {
      this.nInput = 8 + 7;
      this.inputState = new Float32Array(this.nInput);
      this.outputState = new Float32Array(7);
      this.prevOutputState = new Float32Array(7);

      // 7x15 trained weights matrix
      this.weights = [
        [7.5719, 4.4285, 2.2716, -0.3598, -7.8189, -2.5422, -3.2034, 0.3935, 1.2202, -0.49, -0.0316, 0.5221, 0.7026, 0.4179, -2.1689],
        [1.646, -13.3639, 1.5151, 1.1175, -5.3561, 5.0442, 0.8451, 0.3987, -2.9501, -3.7811, -5.8994, 6.4167, 2.5014, 7.338, -2.9887],
        [2.4586, 13.4191, 2.7395, -3.9708, 1.6548, -2.7554, -1.5345, -6.4708, 9.2426, -0.7392, 0.4452, 1.8828, -2.6277, -10.851, -3.2353],
        [-4.4653, -3.1153, -1.3707, 7.318, 16.0902, 1.4686, 7.0391, 1.7765, -1.155, 2.6697, -8.8877, 1.1958, -3.2839, -5.4425, 1.6809],
        [7.6812, -2.4732, 1.738, 0.3781, 0.8718, 2.5886, 1.6911, 1.2953, -9.0052, -4.6038, -6.7447, -2.5528, 0.4391, -4.9278, -3.6695],
        [-4.8673, -1.6035, 1.5011, -5.6124, 4.9747, 1.8998, 3.0359, 6.2983, -4.8568, -2.1888, -4.1143, -3.9874, -0.0459, 4.7134, 2.8952],
        [-9.3627, -4.685, 0.3601, -1.3699, 9.7294, 11.5596, 0.1918, 3.0783, 0.0329, -0.1362, -0.1188, -0.7579, 0.3278, -0.977, -0.9377]
      ];
      this.bias = [2.2935, -2.0353, -1.7786, 5.4567, -3.6368, 3.4996, -0.0685];
    }
    reset() {
      this.inputState.fill(0);
      this.outputState.fill(0);
      this.prevOutputState.fill(0);
    }
    predict(slime, ball) {
      // Inputs from perspective of right slime (dir = 1)
      const scale = 10.0;
      this.inputState[0] = (slime.x * slime.dir) / scale;
      this.inputState[1] = slime.y / scale;
      this.inputState[2] = (slime.vx * slime.dir) / scale;
      this.inputState[3] = slime.vy / scale;
      this.inputState[4] = (ball.x * slime.dir) / scale;
      this.inputState[5] = ball.y / scale;
      this.inputState[6] = (ball.vx * slime.dir) / scale;
      this.inputState[7] = ball.vy / scale;
      for (let i = 0; i < 7; i++) {
        this.inputState[8 + i] = this.outputState[i];
      }
      for (let i = 0; i < 7; i++) {
        let sum = this.bias[i];
        for (let j = 0; j < 15; j++) {
          sum += this.weights[i][j] * this.inputState[j];
        }
        this.outputState[i] = Math.tanh(sum);
      }
      return {
        forward: this.outputState[0] > 0.75,
        backward: this.outputState[1] > 0.75,
        jump: this.outputState[2] > 0.75
      };
    }
  }

  // --- Difficulty & Ranking Multipliers ---
  const DIFF_MULTIPLIERS = {
    easy: 100,
    normal: 250,
    hard: 500,
    online: 750
  };

  const RETURN_POINTS = {
    easy: 10,
    normal: 20,
    hard: 35,
    online: 50
  };

  function getSlimeStreakKey(mode, difficulty) {
    if (mode === 'online') return 'slime_win_streak_online';
    return `slime_win_streak_${difficulty || 'normal'}`;
  }

  function getSavedSlimeStreak(mode, difficulty) {
    if (mode === 'local') return 0;
    return parseInt(localStorage.getItem(getSlimeStreakKey(mode, difficulty)) || '0', 10);
  }

  function setSavedSlimeStreak(mode, difficulty, val) {
    if (mode === 'local') return;
    localStorage.setItem(getSlimeStreakKey(mode, difficulty), String(val));
    localStorage.setItem('slime_win_streak', String(val));
  }

  function getSlimeRankedScoreKey() {
    return 'slime_ranked_score';
  }

  function getSavedSlimeRankedScore() {
    return parseInt(localStorage.getItem(getSlimeRankedScoreKey()) || '0', 10);
  }

  function addSlimeRankedScore(points) {
    const next = getSavedSlimeRankedScore() + points;
    localStorage.setItem(getSlimeRankedScoreKey(), String(next));
    return next;
  }

  // Main Game State
  const GameState = {
    mode: 'solo', // 'solo', 'local', 'online'
    difficulty: localStorage.getItem('slime_difficulty') || 'normal',
    p1: new Slime(-1, -REF_W / 4, '#e06a3b', 'You'), // Left (Coral)
    p2: new Slime(1, REF_W / 4, '#2e86ab', 'AI Bot'), // Right (Teal)
    ball: new Ball(0, 11, 0, 8),
    ai: new NeuralAgent(),
    serving: -1, // -1 = Left serves, 1 = Right serves
    serveState: 'SERVE_COUNTDOWN', // 'SERVE_COUNTDOWN', 'PLAYING'
    delay: 60, // 60 ticks (~1s) serve countdown
    gameOver: false,
    winner: null,
    isPaused: true, // Paused by default on page load so user can get ready
    winStreak: getSavedSlimeStreak('solo', localStorage.getItem('slime_difficulty') || 'normal'),
    roundWins: parseInt(localStorage.getItem('slime_round_wins') || '0', 10),
    volleysReturned: parseInt(localStorage.getItem('slime_volleys_returned') || '0', 10),
    currentRallyVolleys: 0,
    bestRallyVolleys: parseInt(localStorage.getItem('slime_best_rally') || '0', 10),
    rallyCount: 0,
    lastAiTime: 0,
    lastAiAction: { forward: false, backward: false, jump: false },
    aiJitter: 0,
    isFindingMatch: false,
    // Online state
    socket: null,
    roomId: null,
    isHost: true,
    isOnlineConnected: false,
    latency: 0,
    lastPingTime: 0
  };

  function applyDifficulty(diff) {
    if (!DIFFICULTY_CONFIG[diff]) diff = 'normal';
    GameState.difficulty = diff;
    localStorage.setItem('slime_difficulty', diff);
    const cfg = DIFFICULTY_CONFIG[diff];
    GameState.p1.r = SLIME_R * (cfg.playerSizeBonus || 1.0);
    GameState.p2.r = SLIME_R;
    if (GameState.mode === 'solo') {
      GameState.winStreak = getSavedSlimeStreak('solo', diff);
    }
  }

  // Keyboard input tracking
  const keys = {
    w: false, a: false, d: false,
    up: false, left: false, right: false
  };

  function handleKeyDown(e) {
    if (e.key === ' ' || e.code === 'Space') {
      if (GameState.mode !== 'online') {
        e.preventDefault();
        GameState.isPaused = !GameState.isPaused;
        if (typeof window.__updateSlimePauseBtn === 'function') {
          window.__updateSlimePauseBtn(GameState.isPaused);
        }
        return;
      }
    }

    const code = e.code || '';
    const k = (e.key || '').toLowerCase();

    if (code === 'KeyA' || k === 'a') { keys.a = true; e.preventDefault(); }
    if (code === 'KeyD' || k === 'd') { keys.d = true; e.preventDefault(); }
    if (code === 'KeyW' || k === 'w') { keys.w = true; e.preventDefault(); }

    if (code === 'ArrowLeft' || k === 'arrowleft') { keys.left = true; e.preventDefault(); }
    if (code === 'ArrowRight' || k === 'arrowright') { keys.right = true; e.preventDefault(); }
    if (code === 'ArrowUp' || k === 'arrowup') { keys.up = true; e.preventDefault(); }
  }

  function handleKeyUp(e) {
    const code = e.code || '';
    const k = (e.key || '').toLowerCase();

    if (code === 'KeyA' || k === 'a') keys.a = false;
    if (code === 'KeyD' || k === 'd') keys.d = false;
    if (code === 'KeyW' || k === 'w') keys.w = false;

    if (code === 'ArrowLeft' || k === 'arrowleft') keys.left = false;
    if (code === 'ArrowRight' || k === 'arrowright') keys.right = false;
    if (code === 'ArrowUp' || k === 'arrowup') keys.up = false;
  }

  function resetServe(winnerDir) {
    GameState.rallyCount = 0;
    GameState.serving = winnerDir;
    GameState.serveState = 'SERVE_COUNTDOWN';
    GameState.delay = 60; // 1.0 second countdown at 60Hz

    // Position slimes cleanly at baseline
    GameState.p1.reset();
    GameState.p2.reset();

    // Position ball above server with vx = 0, vy = 0
    GameState.ball.x = winnerDir * (REF_W / 4);
    GameState.ball.y = 11;
    GameState.ball.vx = 0;
    GameState.ball.vy = 0;
  }

  function launchServe() {
    const cfg = DIFFICULTY_CONFIG[GameState.difficulty] || DIFFICULTY_CONFIG.normal;
    let serveSpeed = 5 * (cfg.serveSpeedScale || 1.0);
    // Dynamic Difficulty Adjustment (DDA / Catch-up):
    if (GameState.mode === 'solo' && (GameState.p2.score - GameState.p1.score >= 2)) {
      serveSpeed *= 0.85;
    }
    GameState.ball.vx = (GameState.serving === -1) ? serveSpeed : -serveSpeed;
    GameState.ball.vy = 8 * (cfg.serveSpeedScale || 1.0);
    GameState.serveState = 'PLAYING';
    if (!GameState.isPaused) SFX.whistle();
  }

  function update(dt = TIMESTEP) {
    if (GameState.gameOver) return;
    if (GameState.isPaused) return;
    if (GameState.mode === 'online' && (!GameState.isOnlineConnected || !GameState.roomId)) return;

    // Delay before serve begins (Serve State Machine)
    if (GameState.serveState === 'SERVE_COUNTDOWN') {
      GameState.delay--;
      if (GameState.delay <= 0) {
        launchServe();
      }
      return;
    }

    if (GameState.mode === 'solo') {
      // Player 1 controls
      GameState.p1.setInput(keys.a || keys.left, keys.d || keys.right, keys.w || keys.up);
      GameState.p1.update(dt);

      // Humanized Neural AI for Player 2
      const now = performance.now();
      const cfg = DIFFICULTY_CONFIG[GameState.difficulty] || DIFFICULTY_CONFIG.normal;

      if (now - GameState.lastAiTime >= cfg.reactionDelayMs) {
        GameState.lastAiTime = now;

        // Target jitter
        if (cfg.jitterRange > 0) {
          GameState.aiJitter = (Math.random() * 2 - 1) * cfg.jitterRange;
        } else {
          GameState.aiJitter = 0;
        }

        // Virtual ball with jitter offset so AI doesn't hit the sweet spot every time
        const virtualBall = {
          x: GameState.ball.x + GameState.aiJitter,
          y: GameState.ball.y,
          vx: GameState.ball.vx,
          vy: GameState.ball.vy
        };

        let rawAction = GameState.ai.predict(GameState.p2, virtualBall);

        // Occasional human-like error on sharp shots (easy/normal)
        if (cfg.missChance > 0 && Math.abs(GameState.ball.vx) > 7.5 && Math.random() < cfg.missChance) {
          rawAction.forward = false;
          rawAction.backward = false;
        }

        // Jump deadzone check: AI shouldn't jump if ball is far away horizontally
        if (cfg.jumpDeadzone > 0) {
          const dxToBall = Math.abs(GameState.p2.x - GameState.ball.x);
          if (dxToBall > cfg.jumpDeadzone + GameState.p2.r) {
            rawAction.jump = false;
          }
        }

        GameState.lastAiAction = rawAction;
      }

      // Movement speed scaling & DDA catch-up
      let speedScale = cfg.speedCap;
      if (GameState.p2.score - GameState.p1.score >= 2) {
        speedScale *= 0.90; // 10% speed reduction when player trails
      }

      GameState.p2.setInput(GameState.lastAiAction.forward, GameState.lastAiAction.backward, GameState.lastAiAction.jump, speedScale);
      GameState.p2.update(dt);

      // Sub-stepped physics for zero tunneling
      const subDt = dt / SUB_STEPS;
      for (let s = 0; s < SUB_STEPS; s++) {
        GameState.ball.applyGravity(subDt);
        GameState.ball.move(subDt);
        const p1Hit = GameState.ball.bounceSlime(GameState.p1);
        if (p1Hit) {
          GameState.volleysReturned++;
          GameState.currentRallyVolleys++;
          if (GameState.currentRallyVolleys > GameState.bestRallyVolleys) {
            GameState.bestRallyVolleys = GameState.currentRallyVolleys;
            localStorage.setItem('slime_best_rally', String(GameState.bestRallyVolleys));
          }
          localStorage.setItem('slime_volleys_returned', String(GameState.volleysReturned));
          if (typeof window.__updateSlimeReturnsDisplay === 'function') {
            window.__updateSlimeReturnsDisplay(GameState.volleysReturned, GameState.currentRallyVolleys);
          }
        }
        GameState.ball.bounceSlime(GameState.p2);

        const groundHit = GameState.ball.checkEdges(subDt);
        if (groundHit !== 0) {
          GameState.currentRallyVolleys = 0;

          if (groundHit === -1) {
            // Ball hit left ground -> P2 scores
            GameState.p2.score++;
            if (GameState.p2.score >= WIN_SCORE) endGame(GameState.p2);
            else resetServe(-1);
          } else {
            // Ball hit right ground -> P1 scores
            GameState.p1.score++;
            GameState.roundWins++;
            localStorage.setItem('slime_round_wins', String(GameState.roundWins));
            if (typeof window.__updateSlimeRoundsDisplay === 'function') {
              window.__updateSlimeRoundsDisplay(GameState.roundWins);
            }
            if (GameState.p1.score >= WIN_SCORE) endGame(GameState.p1);
            else resetServe(1);
          }
          break; // Stop sub-steps once point is scored
        }
      }
    } else if (GameState.mode === 'local') {
      // Local 2-Player: P1 = A/D/W, P2 = Left/Right/Up
      GameState.p1.setInput(keys.a, keys.d, keys.w);
      GameState.p1.update(dt);
      GameState.p2.setInput(keys.left, keys.right, keys.up);
      GameState.p2.update(dt);

      const subDt = dt / SUB_STEPS;
      for (let s = 0; s < SUB_STEPS; s++) {
        GameState.ball.applyGravity(subDt);
        GameState.ball.move(subDt);
        GameState.ball.bounceSlime(GameState.p1);
        GameState.ball.bounceSlime(GameState.p2);

        const groundHit = GameState.ball.checkEdges(subDt);
        if (groundHit !== 0) {
          if (groundHit === -1) {
            GameState.p2.score++;
            if (GameState.p2.score >= WIN_SCORE) endGame(GameState.p2);
            else resetServe(-1);
          } else {
            GameState.p1.score++;
            if (GameState.p1.score >= WIN_SCORE) endGame(GameState.p1);
            else resetServe(1);
          }
          break;
        }
      }
    } else if (GameState.mode === 'online') {
      if (GameState.isHost) {
        // Host controls Player 1
        GameState.p1.setInput(keys.a || keys.left, keys.d || keys.right, keys.w || keys.up);
        GameState.p1.update(dt);
        GameState.p2.update(dt); // Guest updated via socket input

        const subDt = dt / SUB_STEPS;
        for (let s = 0; s < SUB_STEPS; s++) {
          GameState.ball.applyGravity(subDt);
          GameState.ball.move(subDt);
          GameState.ball.bounceSlime(GameState.p1);
          GameState.ball.bounceSlime(GameState.p2);

          const groundHit = GameState.ball.checkEdges(subDt);
          if (groundHit !== 0) {
            if (groundHit === -1) {
              GameState.p2.score++;
              if (GameState.p2.score >= WIN_SCORE) endGame(GameState.p2);
              else resetServe(-1);
            } else {
              GameState.p1.score++;
              if (GameState.p1.score >= WIN_SCORE) endGame(GameState.p1);
              else resetServe(1);
            }
            break;
          }
        }
      } else {
        // Guest controls Player 2
        GameState.p2.setInput(keys.a || keys.left, keys.d || keys.right, keys.w || keys.up);
        GameState.p2.update(dt);
        // Extrapolate ball movement between network sync packets so motion stays fluid
        const subDt = dt / SUB_STEPS;
        for (let s = 0; s < SUB_STEPS; s++) {
          GameState.ball.applyGravity(subDt);
          GameState.ball.move(subDt);
          GameState.ball.bounceSlime(GameState.p2);
        }
      }
    }
  }

  function queuePendingSync(game, category, score, metadata = {}) {
    try {
      const raw = localStorage.getItem('arcade_pending_sync');
      const list = raw ? JSON.parse(raw) : [];
      const idx = list.findIndex(item => item.game === game && item.category === category);
      if (idx >= 0) {
        list[idx].score = Math.max(list[idx].score, score);
        list[idx].metadata = metadata || list[idx].metadata || {};
      } else {
        list.push({ game, category, score, metadata: metadata || {} });
      }
      localStorage.setItem('arcade_pending_sync', JSON.stringify(list));
    } catch (_) {}
  }

  function clearPendingSync(game, category, score) {
    try {
      const raw = localStorage.getItem('arcade_pending_sync');
      if (!raw) return;
      let list = JSON.parse(raw);
      list = list.filter(item => !(item.game === game && item.category === category && item.score <= score));
      localStorage.setItem('arcade_pending_sync', JSON.stringify(list));
    } catch (_) {}
  }

  async function submitLeaderboard(category, score, metadata = {}) {
    if (GameState.mode === 'local') return false; // Strict local isolation
    try {
      if (typeof navigator !== 'undefined' && !navigator.onLine) {
        queuePendingSync('slime_volleyball', category, score, metadata);
        return false;
      }
      let guestToken = localStorage.getItem('arcade_guest_token');
      if (!guestToken) {
        guestToken = 'g_' + Math.random().toString(36).substring(2, 15);
        localStorage.setItem('arcade_guest_token', guestToken);
      }
      let playerName = localStorage.getItem('arcade_display_name') || '';
      if (!playerName && guestToken) {
        playerName = 'Player_' + guestToken.substring(2, 7);
      }
      const headers = { 'Content-Type': 'application/json' };
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      if (csrfMeta && csrfMeta.content) headers['X-CSRFToken'] = csrfMeta.content;

      const res = await fetch('/api/games/leaderboard/submit', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify({
          game: 'slime_volleyball',
          category: category,
          score: score,
          username: playerName,
          guest_token: guestToken,
          metadata: metadata || {}
        })
      });
      if (res.ok) {
        clearPendingSync('slime_volleyball', category, score);
        if (typeof window.__refreshSlimeLeaderboard === 'function') {
          window.__refreshSlimeLeaderboard();
        }
        return true;
      } else {
        queuePendingSync('slime_volleyball', category, score, metadata);
        return false;
      }
    } catch (_) {
      queuePendingSync('slime_volleyball', category, score, metadata);
      return false;
    }
  }

  async function syncAllScores() {
    if (GameState.mode === 'local') return;
    try {
      const diffKey = GameState.mode === 'online' ? 'online' : GameState.difficulty;
      const current = GameState.winStreak || getSavedSlimeStreak(GameState.mode, GameState.difficulty);
      const best = parseInt(localStorage.getItem(`slime_best_streak_${diffKey}`) || localStorage.getItem('slime_best_streak') || '0', 10);
      const toSync = Math.max(current, best);
      const meta = { difficulty: diffKey, mode: GameState.mode };
      if (toSync > 0) {
        await submitLeaderboard('win_streak', toSync, meta);
      }
      const volleys = GameState.volleysReturned || parseInt(localStorage.getItem('slime_volleys_returned') || '0', 10);
      if (volleys > 0) {
        await submitLeaderboard('volleys_returned', volleys, meta);
      }
      const rankedScore = getSavedSlimeRankedScore();
      if (rankedScore > 0) {
        await submitLeaderboard('ranked_score', rankedScore, meta);
      }
      const raw = localStorage.getItem('arcade_pending_sync');
      if (raw) {
        const list = JSON.parse(raw);
        for (const item of list) {
          if (item.game === 'slime_volleyball') {
            const ok = await submitLeaderboard(item.category, item.score, item.metadata || {});
            if (ok) clearPendingSync(item.game, item.category, item.score);
          }
        }
      }
    } catch (_) {}
  }

  function endGame(winner) {
    GameState.gameOver = true;
    GameState.winner = winner;
    SFX.win();

    let localPlayerWon = false;
    if (GameState.mode === 'solo') {
      localPlayerWon = (winner === GameState.p1);
    } else if (GameState.mode === 'online') {
      localPlayerWon = (GameState.isHost && winner === GameState.p1) || (!GameState.isHost && winner === GameState.p2);
    }

    if (GameState.mode === 'local') {
      // Local 2P mode is pass-and-play only.
      // Never submit to global leaderboards.
    } else if (localPlayerWon) {
      const diffKey = GameState.mode === 'online' ? 'online' : GameState.difficulty;
      GameState.winStreak += 1;
      setSavedSlimeStreak(GameState.mode, GameState.difficulty, GameState.winStreak);
      const best = Math.max(GameState.winStreak, parseInt(localStorage.getItem(`slime_best_streak_${diffKey}`) || '0', 10));
      localStorage.setItem(`slime_best_streak_${diffKey}`, String(best));
      localStorage.setItem('slime_best_streak', String(best));

      const winPts = DIFF_MULTIPLIERS[diffKey] || 100;
      const volleysBonus = (GameState.volleysReturned || 0) * (RETURN_POINTS[diffKey] || 10);
      const newRankedScore = addSlimeRankedScore(winPts + volleysBonus);

      const meta = { difficulty: diffKey, mode: GameState.mode, multiplier: winPts, returns: GameState.volleysReturned || 0 };
      submitLeaderboard('win_streak', GameState.winStreak, meta);
      submitLeaderboard('ranked_score', newRankedScore, meta);
    } else if (GameState.mode === 'solo' || GameState.mode === 'online') {
      GameState.winStreak = 0;
      setSavedSlimeStreak(GameState.mode, GameState.difficulty, 0);
    }

    const modal = document.getElementById('game-over-banner');
    if (modal) {
      modal.style.display = 'block';
      const txt = document.getElementById('winner-text');
      if (txt) txt.textContent = `${winner.name} wins the match!`;
      const streakTxt = document.getElementById('winner-streak');
      if (streakTxt) {
        if (GameState.winStreak > 0) {
          streakTxt.textContent = `Win Streak: ${GameState.winStreak}`;
          streakTxt.style.display = 'block';
        } else {
          streakTxt.textContent = localPlayerWon ? '' : 'Streak reset to 0';
          streakTxt.style.display = localPlayerWon ? 'none' : 'block';
        }
      }
      const pointsTxt = document.getElementById('winner-points');
      if (pointsTxt) {
        if (localPlayerWon) {
          const diffKey = GameState.mode === 'online' ? 'online' : GameState.difficulty;
          const winPts = DIFF_MULTIPLIERS[diffKey] || 100;
          const volleysBonus = (GameState.volleysReturned || 0) * (RETURN_POINTS[diffKey] || 10);
          const totalPts = getSavedSlimeRankedScore();
          pointsTxt.textContent = `+${winPts + volleysBonus} ranked pts (Total: ${totalPts.toLocaleString()} pts)`;
          pointsTxt.style.display = 'block';
        } else {
          pointsTxt.style.display = 'none';
        }
      }
      if (typeof window.__updateSlimeRankedDisplay === 'function') {
        window.__updateSlimeRankedDisplay();
      }
    }
  }

  function restartMatch() {
    GameState.p1.score = 0;
    GameState.p2.score = 0;
    GameState.gameOver = false;
    GameState.winner = null;
    GameState.ai.reset();
    resetServe(-1);
    const modal = document.getElementById('game-over-banner');
    if (modal) modal.style.display = 'none';

    if (GameState.mode === 'online' && GameState.socket) {
      GameState.socket.emit('slime_restart', { room_id: GameState.roomId });
    }
  }

  function drawCourt() {
    // Sky / Arena background
    ctx.fillStyle = '#f7f4ed';
    ctx.fillRect(0, 0, W, H);

    // Warm court floor
    const groundY = toY(REF_U);
    ctx.fillStyle = '#e8dec8';
    ctx.fillRect(0, groundY, W, H - groundY);
    ctx.fillStyle = '#5c3d2e';
    ctx.fillRect(0, groundY - 3, W, 4);

    // Center Net
    const netX = toX(0) - toP(REF_WALL_W / 2);
    const netTop = toY(REF_WALL_H);
    const netW = toP(REF_WALL_W);
    const netH = groundY - netTop;

    ctx.fillStyle = '#9c7a65';
    ctx.fillRect(netX, netTop, netW, netH);
    ctx.strokeStyle = '#3e2217';
    ctx.lineWidth = 1.8;
    ctx.strokeRect(netX, netTop, netW, netH);

    // Net mesh grid
    ctx.beginPath();
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.4)';
    ctx.lineWidth = 1;
    for (let y = netTop + 8; y < groundY; y += 12) {
      ctx.moveTo(netX, y); ctx.lineTo(netX + netW, y);
    }
    ctx.stroke();

    // Net top stub ball
    ctx.beginPath();
    ctx.arc(toX(0), netTop, netW / 2, 0, Math.PI * 2);
    ctx.fillStyle = '#f0ebe1';
    ctx.fill();
    ctx.stroke();

    // Clean boundary lines
    ctx.strokeStyle = 'rgba(62, 34, 23, 0.15)';
    ctx.lineWidth = 2;
    ctx.strokeRect(2, 2, W - 4, H - 4);
  }

  function drawScoreboard() {
    ctx.save();
    ctx.font = '700 30px Poppins, sans-serif';
    ctx.textAlign = 'center';

    // Left score
    ctx.fillStyle = GameState.p1.color;
    ctx.fillText(`${GameState.p1.score}`, W * 0.25, 46);
    ctx.font = '500 14px Poppins, sans-serif';
    ctx.fillText(GameState.p1.name, W * 0.25, 68);

    // Right score
    ctx.font = '700 30px Poppins, sans-serif';
    ctx.fillStyle = GameState.p2.color;
    ctx.fillText(`${GameState.p2.score}`, W * 0.75, 46);
    ctx.font = '500 14px Poppins, sans-serif';
    ctx.fillText(GameState.p2.name, W * 0.75, 68);

    // Match target in center
    ctx.font = '600 12px Poppins, sans-serif';
    ctx.fillStyle = '#8c7365';
    const centerSub = (GameState.mode === 'solo')
      ? `FIRST TO ${WIN_SCORE} • ${(DIFFICULTY_CONFIG[GameState.difficulty] || DIFFICULTY_CONFIG.normal).name.toUpperCase()}`
      : `FIRST TO ${WIN_SCORE}`;
    ctx.fillText(centerSub, W * 0.5, 30);
    ctx.restore();
  }

  function drawPauseOverlay() {
    if (!GameState.isPaused) return;
    ctx.save();
    ctx.fillStyle = 'rgba(40, 25, 18, 0.45)';
    ctx.fillRect(0, 0, W, H);

    ctx.fillStyle = '#ffffff';
    ctx.font = '700 28px Poppins, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    if (GameState.mode === 'online') {
      if (!GameState.isOnlineConnected || !GameState.roomId) {
        ctx.fillText('ONLINE 1V1 LOBBY', W / 2, H / 2 - 16);
        ctx.font = '500 14px Poppins, sans-serif';
        ctx.fillStyle = '#f7f4ed';
        ctx.fillText('Find a match or challenge an opponent below to start', W / 2, H / 2 + 18);
      } else {
        ctx.fillText('PAUSED', W / 2, H / 2 - 16);
        ctx.font = '500 14px Poppins, sans-serif';
        ctx.fillStyle = '#f7f4ed';
        ctx.fillText('Waiting for players to serve...', W / 2, H / 2 + 18);
      }
    } else {
      ctx.fillText('PAUSED', W / 2, H / 2 - 16);
      ctx.font = '500 14px Poppins, sans-serif';
      ctx.fillStyle = '#f7f4ed';
      ctx.fillText('Press Play / Space or Click Canvas to Serve', W / 2, H / 2 + 18);
    }
    ctx.restore();
  }

  function render() {
    ctx.clearRect(0, 0, W, H);
    drawCourt();
    GameState.p1.draw(ctx, GameState.ball);
    GameState.p2.draw(ctx, GameState.ball);
    GameState.ball.draw(ctx);
    drawScoreboard();
    drawPauseOverlay();
  }

  // Fixed-Timestep Accumulator Loop (60Hz deterministic physics)
  let lastFrameTime = 0;
  let physicsAccumulator = 0;
  const FIXED_DT = 1 / 60;
  const MAX_ACCUMULATOR = 0.1; // Clamp delta to avoid spiral of death on background tabs

  function loop(timestamp) {
    if (!lastFrameTime) lastFrameTime = timestamp || (performance.now ? performance.now() : Date.now());
    const now = timestamp || (performance.now ? performance.now() : Date.now());
    let delta = (now - lastFrameTime) / 1000;
    lastFrameTime = now;
    if (delta > MAX_ACCUMULATOR) delta = MAX_ACCUMULATOR;

    physicsAccumulator += delta;
    while (physicsAccumulator >= FIXED_DT) {
      update(FIXED_DT);
      physicsAccumulator -= FIXED_DT;
    }

    render();
    requestAnimationFrame(loop);
  }

  // 18 Hz Network Synchronization Loop (Online Multiplayer)
  function initNetworkSync() {
    setInterval(() => {
      if (GameState.mode !== 'online' || !GameState.socket || !GameState.isOnlineConnected) return;

      if (GameState.isHost) {
        // Host broadcasts state to Guest (including p2 state to keep sync tight)
        GameState.socket.emit('slime_host_sync', {
          room_id: GameState.roomId,
          ball: { x: GameState.ball.x, y: GameState.ball.y, vx: GameState.ball.vx, vy: GameState.ball.vy },
          p1: { x: GameState.p1.x, y: GameState.p1.y, vx: GameState.p1.vx, vy: GameState.p1.vy },
          p2: { x: GameState.p2.x, y: GameState.p2.y, vx: GameState.p2.vx, vy: GameState.p2.vy },
          scores: [GameState.p1.score, GameState.p2.score]
        });
      } else {
        // Guest sends inputs and coordinates to Host
        GameState.socket.emit('slime_player_input', {
          room_id: GameState.roomId,
          p2: {
            x: GameState.p2.x, y: GameState.p2.y,
            vx: GameState.p2.vx, vy: GameState.p2.vy,
            desiredVx: GameState.p2.desiredVx, desiredVy: GameState.p2.desiredVy
          }
        });
      }
    }, 55); // ~18 Hz
  }

  // Online Socket Connection & Lobby Setup
  function connectSocket(roomId, isHost = true) {
    if (typeof io === 'undefined') {
      alert('Socket connection unavailable.');
      return;
    }
    if (!GameState.socket) {
      GameState.socket = io({ transports: ['websocket', 'polling'] });

      GameState.socket.on('slime_room_joined', (data) => {
        GameState.roomId = data.room_id;
        GameState.isHost = data.is_host;
        GameState.isOnlineConnected = true;
        GameState.p1.name = data.host_name || 'Host';
        GameState.p2.name = data.guest_name || 'Guest';

        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          if (data.is_host && !data.guest_name) {
            statusEl.textContent = `Room ${data.room_id} (Host). Waiting for opponent to enter...`;
          } else {
            statusEl.textContent = `Connected in room ${data.room_id} (${data.is_host ? 'Host' : 'Guest'}). Ready!`;
          }
        }

        // When opponent enters the game room, reset scores so both players start fresh
        if (data.guest_name) {
          GameState.p1.score = 0;
          GameState.p2.score = 0;
          GameState.gameOver = false;
          GameState.isPaused = false;
          if (typeof window.__updateSlimePauseBtn === 'function') {
            window.__updateSlimePauseBtn(false);
          }
          resetServe(-1);
        }
      });

      GameState.socket.on('slime_host_sync', (data) => {
        if (!GameState.isHost) {
          // Linear interpolation for smooth ball movement
          GameState.ball.x = GameState.ball.x * 0.2 + data.ball.x * 0.8;
          GameState.ball.y = GameState.ball.y * 0.2 + data.ball.y * 0.8;
          GameState.ball.vx = data.ball.vx;
          GameState.ball.vy = data.ball.vy;
          GameState.p1.x = GameState.p1.x * 0.3 + data.p1.x * 0.7;
          GameState.p1.y = GameState.p1.y * 0.3 + data.p1.y * 0.7;
          GameState.p1.vx = data.p1.vx;
          GameState.p1.vy = data.p1.vy;
          GameState.p1.score = data.scores[0];
          GameState.p2.score = data.scores[1];
        }
      });

      GameState.socket.on('slime_player_input', (data) => {
        if (GameState.isHost && data.p2) {
          GameState.p2.desiredVx = data.p2.desiredVx;
          GameState.p2.desiredVy = data.p2.desiredVy;
          GameState.p2.x = GameState.p2.x * 0.3 + data.p2.x * 0.7;
          GameState.p2.y = GameState.p2.y * 0.3 + data.p2.y * 0.7;
        }
      });

      GameState.socket.on('slime_player_left', () => {
        GameState.isPaused = true;
        if (typeof window.__updateSlimePauseBtn === 'function') {
          window.__updateSlimePauseBtn(true);
        }
        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          statusEl.textContent = 'Opponent disconnected.';
          statusEl.style.color = 'var(--text-secondary)';
          statusEl.style.background = 'transparent';
          statusEl.style.border = 'none';
          statusEl.style.padding = '0';
          statusEl.style.fontWeight = 'normal';
          statusEl.style.fontSize = '0.85rem';
          statusEl.style.display = 'block';
        }
        const matchBtn = document.getElementById('find-match-btn');
        if (matchBtn) {
          matchBtn.textContent = 'Find Match';
          matchBtn.disabled = false;
          matchBtn.style.opacity = '1';
          matchBtn.classList.remove('ew-btn--active');
        }
      });

      GameState.socket.on('slime_restart', () => {
        restartMatch();
      });

      GameState.socket.on('slime_matchmaking_waiting', (data) => {
        GameState.isFindingMatch = true;
        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          statusEl.textContent = data.message || 'Searching for an online opponent...';
          statusEl.style.color = '#2563eb';
          statusEl.style.background = 'transparent';
          statusEl.style.border = 'none';
          statusEl.style.padding = '0';
          statusEl.style.fontWeight = '600';
          statusEl.style.fontSize = '0.85rem';
          statusEl.style.display = 'block';
        }
        const matchBtn = document.getElementById('find-match-btn');
        if (matchBtn) {
          matchBtn.textContent = 'Searching... (Cancel)';
          matchBtn.disabled = false;
          matchBtn.style.opacity = '1';
          matchBtn.classList.add('ew-btn--active');
        }
      });

      GameState.socket.on('slime_matchmaking_cancelled', (data) => {
        GameState.isFindingMatch = false;
        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          statusEl.textContent = data.message || 'Matchmaking cancelled.';
          statusEl.style.color = 'var(--text-secondary)';
          statusEl.style.background = 'transparent';
          statusEl.style.border = 'none';
          statusEl.style.padding = '0';
          statusEl.style.fontWeight = 'normal';
          statusEl.style.fontSize = '0.85rem';
          statusEl.style.display = 'block';
        }
        const matchBtn = document.getElementById('find-match-btn');
        if (matchBtn) {
          matchBtn.textContent = 'Find Match';
          matchBtn.disabled = false;
          matchBtn.style.opacity = '1';
          matchBtn.classList.remove('ew-btn--active');
        }
      });

      GameState.socket.on('slime_match_found', (data) => {
        GameState.isFindingMatch = false;
        GameState.mode = 'online';
        GameState.roomId = data.room_id;
        GameState.isHost = data.is_host;
        GameState.isOnlineConnected = true;
        GameState.p1.name = data.host_name || 'Host';
        GameState.p2.name = data.guest_name || 'Guest';
        GameState.p1.score = 0;
        GameState.p2.score = 0;
        GameState.gameOver = false;
        GameState.isPaused = false;
        if (typeof window.__updateSlimePauseBtn === 'function') {
          window.__updateSlimePauseBtn(false);
        }
        resetServe(-1);

        const oppName = data.is_host ? (data.guest_name || 'Guest') : (data.host_name || 'Host');
        const statusEl = document.getElementById('online-status');
        if (statusEl) {
          statusEl.textContent = `Match Found! Playing vs ${oppName} (${data.is_host ? 'Left' : 'Right'})`;
          statusEl.style.color = '#15803d';
          statusEl.style.background = 'rgba(34, 197, 94, 0.12)';
          statusEl.style.border = '1px solid rgba(34, 197, 94, 0.35)';
          statusEl.style.padding = '0.45rem 0.85rem';
          statusEl.style.borderRadius = '6px';
          statusEl.style.fontWeight = '700';
          statusEl.style.fontSize = '0.92rem';
          statusEl.style.display = 'inline-block';
        }
        const matchBtn = document.getElementById('find-match-btn');
        if (matchBtn) {
          matchBtn.textContent = 'In Match';
          matchBtn.disabled = true;
          matchBtn.style.opacity = '0.7';
          matchBtn.classList.remove('ew-btn--active');
        }
      });

      GameState.socket.on('slime_queue_updated', (data) => {
        if (typeof window.__updateSlimeOpponentsLobby === 'function') {
          window.__updateSlimeOpponentsLobby(data.queue || []);
        }
      });

      GameState.socket.on('game_challenge_received', (data) => {
        if (data.game === 'slime' && typeof window.__showSlimeChallengeModal === 'function') {
          window.__showSlimeChallengeModal(data);
        }
      });

      GameState.socket.on('game_challenge_declined', (data) => {
        if (data.game === 'slime') {
          alert((data.challenger_name || 'Opponent') + ' is unavailable or declined.');
        }
      });
    }

    if (roomId) {
      GameState.socket.emit('join_slime_room', { room_id: roomId });
    }
  }

  function findMatch() {
    if (typeof io === 'undefined') {
      alert('Socket connection unavailable.');
      return;
    }
    if (!GameState.socket) {
      connectSocket(null);
    }
    if (GameState.isFindingMatch) {
      GameState.isFindingMatch = false;
      GameState.socket.emit('cancel_slime_matchmaking');
    } else {
      GameState.isFindingMatch = true;
      const statusEl = document.getElementById('online-status');
      if (statusEl) statusEl.textContent = 'Entering matchmaking queue...';
      const matchBtn = document.getElementById('find-match-btn');
      if (matchBtn) {
        matchBtn.textContent = 'Searching... (Cancel)';
        matchBtn.classList.add('ew-btn--active');
      }
      const streak = getSavedSlimeStreak('online', 'online') || 0;
      const score = getSavedSlimeRankedScore() || 0;
      GameState.socket.emit('find_slime_match', { streak, score });
    }
  }

  function sendChallenge(targetSid, targetName) {
    if (!GameState.socket) connectSocket(null);
    const streak = getSavedSlimeStreak('online', 'online') || 0;
    const score = getSavedSlimeRankedScore() || 0;
    GameState.socket.emit('send_game_challenge', {
      game: 'slime',
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

  function acceptChallenge(challengerSid, challengerName) {
    if (!GameState.socket) connectSocket(null);
    GameState.socket.emit('accept_game_challenge', {
      game: 'slime',
      challenger_sid: challengerSid
    });
  }

  function declineChallenge(challengerSid) {
    if (GameState.socket) {
      GameState.socket.emit('decline_game_challenge', {
        game: 'slime',
        challenger_sid: challengerSid
      });
    }
  }

  function cancelMatchmaking() {
    if (GameState.socket && GameState.isFindingMatch) {
      GameState.isFindingMatch = false;
      GameState.socket.emit('cancel_slime_matchmaking');
      const matchBtn = document.getElementById('find-match-btn');
      if (matchBtn) {
        matchBtn.textContent = 'Find Match';
        matchBtn.classList.remove('ew-btn--active');
      }
    }
  }

  // Initialization
  function init() {
    canvas = document.getElementById('slime-canvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    W = canvas.width = 960;
    H = canvas.height = 540;
    factor = W / REF_W;

    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);

    // Canvas click toggles unpause
    canvas.addEventListener('click', () => {
      if (GameState.isPaused && GameState.mode !== 'online') {
        GameState.isPaused = false;
        if (typeof window.__updateSlimePauseBtn === 'function') {
          window.__updateSlimePauseBtn(false);
        }
      }
    });

    // Touch button handlers
    const btnLeft = document.getElementById('touch-left');
    const btnRight = document.getElementById('touch-right');
    const btnJump = document.getElementById('touch-jump');

    if (btnLeft) {
      btnLeft.addEventListener('pointerdown', (e) => { e.preventDefault(); keys.left = true; });
      btnLeft.addEventListener('pointerup', (e) => { e.preventDefault(); keys.left = false; });
      btnLeft.addEventListener('pointerleave', () => { keys.left = false; });
    }
    if (btnRight) {
      btnRight.addEventListener('pointerdown', (e) => { e.preventDefault(); keys.right = true; });
      btnRight.addEventListener('pointerup', (e) => { e.preventDefault(); keys.right = false; });
      btnRight.addEventListener('pointerleave', () => { keys.right = false; });
    }
    if (btnJump) {
      btnJump.addEventListener('pointerdown', (e) => { e.preventDefault(); keys.up = true; });
      btnJump.addEventListener('pointerup', (e) => { e.preventDefault(); keys.up = false; });
      btnJump.addEventListener('pointerleave', () => { keys.up = false; });
    }

    // Rematch button
    const rematchBtn = document.getElementById('rematch-btn');
    if (rematchBtn) rematchBtn.addEventListener('click', restartMatch);

    // Automatic pause when leaving browser tab
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (GameState.mode !== 'online' || !GameState.roomId) {
          GameState.isPaused = true;
          if (typeof window.__updateSlimePauseBtn === 'function') {
            window.__updateSlimePauseBtn(true);
          }
        }
      }
    });

    applyDifficulty(GameState.difficulty);
    initNetworkSync();
    requestAnimationFrame(loop);

    // Sync existing or offline win streak to leaderboard on load & when online
    setTimeout(syncAllScores, 1000);
    window.addEventListener('online', syncAllScores);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Public API for templates
  window.__slime = {
    setMode(mode, roomId = null) {
      if (GameState.isFindingMatch) cancelMatchmaking();
      GameState.mode = mode;
      GameState.gameOver = false;
      GameState.p1.score = 0;
      GameState.p2.score = 0;
      if (mode === 'solo') {
        GameState.p1.name = 'You';
        GameState.p2.name = 'AI Bot';
        GameState.winStreak = getSavedSlimeStreak('solo', GameState.difficulty);
      } else if (mode === 'local') {
        GameState.p1.name = 'Player 1 (WASD)';
        GameState.p2.name = 'Player 2 (Arrows)';
        GameState.winStreak = 0;
      } else if (mode === 'online') {
        GameState.p1.name = 'Host';
        GameState.p2.name = 'Guest';
        GameState.winStreak = getSavedSlimeStreak('online', 'online');
        if (roomId) connectSocket(roomId);
      }
      GameState.isPaused = true; // Always pause when changing modes/tabs
      if (typeof window.__updateSlimePauseBtn === 'function') {
        window.__updateSlimePauseBtn(true);
      }
      resetServe(-1);
    },
    setDifficulty(diff) {
      applyDifficulty(diff);
      return GameState.difficulty;
    },
    getDifficulty() {
      return GameState.difficulty;
    },
    getRoundsWon() {
      return GameState.roundWins;
    },
    toggleMute() {
      soundMuted = !soundMuted;
      return soundMuted;
    },
    togglePause() {
      if (GameState.mode === 'online' && GameState.isOnlineConnected && GameState.roomId) {
        return false;
      }
      GameState.isPaused = !GameState.isPaused;
      if (typeof window.__updateSlimePauseBtn === 'function') {
        window.__updateSlimePauseBtn(GameState.isPaused);
      }
      return GameState.isPaused;
    },
    isPaused() {
      return GameState.isPaused;
    },
    restart: restartMatch,
    findMatch: findMatch,
    cancelMatchmaking: cancelMatchmaking,
    sendChallenge: sendChallenge,
    acceptChallenge: acceptChallenge,
    declineChallenge: declineChallenge,
    getWinStreak: () => GameState.winStreak,
    getVolleysReturned: () => GameState.volleysReturned,
    getBestRallyVolleys: () => GameState.bestRallyVolleys,
    getRankedScore: getSavedSlimeRankedScore,
    syncScores: syncAllScores
  };
})();
