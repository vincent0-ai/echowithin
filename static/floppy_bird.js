(() => {
'use strict';
const W = 480, H = 640, GROUND_Y = H - 80;
let canvas, ctx;
let soundMuted = false;

// =====================================================================
// RNG (seedable so the Daily run is the same for everyone that day)
// =====================================================================
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function hash(str) { let h = 2166136261; for (const c of str) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }
let rand = Math.random;
const pick = arr => arr[Math.floor(rand() * arr.length)];

// =====================================================================
// Tunables
// =====================================================================
const T = {
  gravity: 1500, flap: -400, maxFall: 720,
  pipeW: 72, birdX: 130, birdR: 16, hitR: 13,
  dash:  { mult: 2.6, dur: 1.4, cd: 5.0, scoreMult: 2 },   // J
  ghost: { dur: 2.2, cd: 7.0, grace: 0.6 },                 // K
  smart: { dur: 3.0, cd: 12.0 },                            // J in Flamingo Lagoon: the flamingo dodges for you
};

// =====================================================================
// Mechanics, levels, skins
// =====================================================================
const MECH = {
  thick:     { name: 'Thick pipes',    desc: 'Long tunnels — fly level or ghost through' },
  moving:    { name: 'Drifting pipes', desc: 'Gaps slide up and down' },
  wind:      { name: 'Gusts',          desc: 'Wind shoves you and changes your speed' },
  richcoins: { name: 'Coin rush',      desc: 'Coins everywhere — grab 80% for a star' },
  dark:      { name: 'Darkness',       desc: 'You only see what is close' },
  hail:      { name: 'Hail',           desc: 'Ice falls between the pipes' },
  gravity:   { name: 'Gravity flips',  desc: 'Purple zones turn the world upside down' },
  turbo:     { name: 'Turbo',          desc: 'Faster with every pipe you pass' },
  phantom:   { name: 'Phantom pipes',  desc: 'Shimmering pipes are fake — fly through them' },
};
const LEVELS = [
  { id: 1,  name: 'Nesting Grounds', scene: 'meadow', sub: 'Learn to flop. Try J and K.',       goal: 10, speed: 150, gap: 190, spacing: 285, mech: [],                sky: ['#6fc6ff', '#c9ecff'] },
  { id: 2,  name: 'Flamingo Lagoon', scene: 'lagoon', smart: true, sub: 'Smart flamingo: J dodges for you',       goal: 15, speed: 158, gap: 182, spacing: 275, mech: [],                sky: ['#ff9ec7', '#ffe3ef'] },
  { id: 3,  name: 'Haunted Hollow', scene: 'haunted', sub: 'Ghosts love thick pipes',               goal: 15, speed: 160, gap: 178, spacing: 300, mech: ['thick'],         sky: ['#4a3d7a', '#9c8fd0'] },
  { id: 4,  name: 'Restless Reeds', scene: 'marsh',     sub: 'The gaps will not sit still',       goal: 20, speed: 165, gap: 176, spacing: 275, mech: ['moving'],        sky: ['#7bd4a8', '#e0fff0'] },
  { id: 5,  name: 'Windy Peaks', scene: 'peaks',        sub: 'Watch the gust warning',            goal: 20, speed: 165, gap: 176, spacing: 275, mech: ['wind'],          sky: ['#9fd3ff', '#e8f6ff'] },
  { id: 6,  name: 'Coin Canyon', scene: 'canyon',        sub: 'Greed is a strategy',               goal: 25, speed: 170, gap: 172, spacing: 270, mech: ['richcoins'],     sky: ['#f0b26b', '#ffe9c7'] },
  { id: 7,  name: 'Narrow Straits', scene: 'straits',     sub: 'Tight. Very tight.',                goal: 25, speed: 170, gap: 142, spacing: 270, mech: [],                sky: ['#5aa0d8', '#cfe6ff'] },
  { id: 8,  name: 'Night Flight', scene: 'night',       sub: 'Trust your instincts',              goal: 25, speed: 170, gap: 172, spacing: 270, mech: ['dark'],          sky: ['#0b1030', '#1c2a5a'] },
  { id: 9,  name: 'Hailstorm', scene: 'storm',          sub: 'Ghost laughs at ice',               goal: 30, speed: 175, gap: 172, spacing: 275, mech: ['hail'],          sky: ['#6b7a99', '#b8c4d9'] },
  { id: 10, name: 'Upside Downs', scene: 'islands',       sub: 'Flap pushes you DOWN in purple',    goal: 30, speed: 175, gap: 176, spacing: 275, mech: ['gravity'],       sky: ['#8a5cff', '#e3d6ff'] },
  { id: 11, name: 'Turbo Tunnels', scene: 'sunset',      sub: 'It only gets faster',               goal: 35, speed: 165, gap: 172, spacing: 275, mech: ['turbo'],         sky: ['#ff7b4a', '#ffd4c2'] },
  { id: 12, name: 'Phantom Rows', scene: 'fog',       sub: 'Learn the shimmer',                 goal: 35, speed: 175, gap: 166, spacing: 270, mech: ['phantom'],       sky: ['#2f5f6f', '#a9d8de'] },
  { id: 13, name: 'Chaos Sky', scene: 'inferno',          sub: 'Everything, all at once',           goal: 40, speed: 180, gap: 166, spacing: 275, mech: ['moving', 'wind', 'hail', 'phantom', 'gravity'], sky: ['#c0392b', '#f5b7b1'] },
  { id: 14, name: 'The Long Migration', scene: 'aurora', sub: '60 pipes. No checkpoints.',         goal: 60, speed: 185, gap: 162, spacing: 270, mech: ['moving', 'wind', 'dark', 'hail', 'gravity', 'turbo', 'phantom', 'thick'], sky: ['#1a1a2e', '#e94560'] },
];
const ENDLESS_POOL = ['thick', 'moving', 'wind', 'dark', 'hail', 'gravity', 'turbo', 'phantom'];
const SKINS = [
  { id: 'classic', name: 'Classic',  need: 0,  body: '#ffd84d', belly: '#fff1a8', wing: '#f2a43a' },
  { id: 'rosy',    name: 'Rosy',     need: 6,  body: '#ff8fb8', belly: '#ffd6e6', wing: '#e2447f' },
  { id: 'spectre', name: 'Spectre',  need: 14, body: '#a8f1ff', belly: '#e6fbff', wing: '#5fd7f0' },
  { id: 'ninja',   name: 'Ninja',    need: 22, body: '#2b2f3a', belly: '#4a5060', wing: '#151820', band: '#e53935' },
  { id: 'golden',  name: 'Golden',   need: 32, body: '#ffc107', belly: '#fff3c4', wing: '#ff8f00', shine: true },
  { id: 'rainbow', name: 'Rainbow',  need: 42, rainbow: true },
];
const STAR_MAX = LEVELS.length * 3;
const ENDING_WARN = 0.4; // seconds before a power expires that the bar blinks + chirps
const ENDLESS_UNLOCK = 3, DAILY_UNLOCK = 6; // cleared-level requirements
function powersFor() { return ['dash', 'ghost']; }

// =====================================================================
// Save data
// =====================================================================
const SAVE_KEY = 'floppy.save.v1';
function blankSave() { return { stars: {}, endlessBest: 0, daily: {}, skin: 'classic' }; }
let save = blankSave();
function sanitizeSave(raw) {
  // Browser storage is the player's own, but a hand-edited or corrupted save must never crash the page.
  const out = blankSave();
  if (!raw || typeof raw !== 'object') return out;
  if (raw.stars && typeof raw.stars === 'object') for (const L of LEVELS) { const v = Math.floor(+raw.stars[L.id]); if (v >= 1) out.stars[L.id] = Math.min(3, v); }
  out.endlessBest = Math.max(0, Math.floor(+raw.endlessBest) || 0);
  if (raw.daily && typeof raw.daily === 'object') for (const k of Object.keys(raw.daily).slice(-60)) { if (/^\d{4}-\d{2}-\d{2}$/.test(k)) { const v = Math.floor(+raw.daily[k]); if (v > 0) out.daily[k] = v; } }
  if (SKINS.some(sk => sk.id === raw.skin)) out.skin = raw.skin;
  return out;
}
try { save = sanitizeSave(JSON.parse(localStorage.getItem(SAVE_KEY) || '{}')); } catch (_) {}
function persist() { try { localStorage.setItem(SAVE_KEY, JSON.stringify(save)); } catch (_) {} }
function totalStars() { return Object.values(save.stars).reduce((a, b) => a + b, 0); }
function clearedCount() { let n = 0; for (const L of LEVELS) { if ((save.stars[L.id] || 0) > 0) n++; else break; } return n; }
function unlockedLevels() { return Math.min(LEVELS.length, clearedCount() + 1); }
function skinUnlocked(sk) { return totalStars() >= sk.need; }
function currentSkin() { const sk = SKINS.find(s => s.id === save.skin); return sk && skinUnlocked(sk) ? sk : SKINS[0]; }
function todayKey() { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }

// =====================================================================
// Audio
// =====================================================================
let AC = null;
function beep(freq, dur, type = 'square', vol = 0.06, slide = 0) {
  try {
    if (!AC) AC = new (window.AudioContext || window.webkitAudioContext)();
    const o = AC.createOscillator(), g = AC.createGain();
    o.type = type; o.frequency.setValueAtTime(freq, AC.currentTime);
    if (slide) o.frequency.exponentialRampToValueAtTime(Math.max(30, freq + slide), AC.currentTime + dur);
    g.gain.setValueAtTime(vol, AC.currentTime);
    g.gain.exponentialRampToValueAtTime(0.0001, AC.currentTime + dur);
    o.connect(g).connect(AC.destination); o.start(); o.stop(AC.currentTime + dur);
  } catch (_) {}
}
const SFX = {
  flap:  () => beep(520, 0.08, 'square', 0.04, 200),
  score: () => beep(880, 0.12, 'triangle', 0.06, 300),
  coin:  () => beep(1320, 0.1, 'sine', 0.05, 400),
  dash:  () => beep(200, 0.35, 'sawtooth', 0.05, 900),
  ghost: () => beep(1200, 0.4, 'sine', 0.05, -700),
  die:   () => beep(180, 0.5, 'sawtooth', 0.08, -150),
  nope:  () => beep(140, 0.1, 'square', 0.03),
  ui:    () => beep(700, 0.06, 'triangle', 0.04, 200),
  clear: () => { beep(660, 0.15, 'triangle', 0.06); setTimeout(() => beep(880, 0.15, 'triangle', 0.06), 130); setTimeout(() => beep(1320, 0.3, 'triangle', 0.06), 260); },
  gust:  () => beep(90, 0.5, 'sawtooth', 0.03, 60),
  ending: () => { beep(660, 0.07, 'square', 0.04); setTimeout(() => beep(520, 0.09, 'square', 0.04), 90); },
};

// =====================================================================
// State
// =====================================================================
let S, L;
function resetRun() {
  S = Object.assign(S || {}, {
    t: 0, score: 0, coins: 0, coinsSeen: 0, usedPower: false, speedMult: 1, intensity: 0.45,
    bird: { y: H / 2, vy: 0, rot: 0, wing: 0 },
    pipes: [], coinEnts: [], hail: [], particles: [], popups: [],
    dash: { active: 0, cd: 0, smart: false }, ghost: { active: 0, cd: 0, lingering: 0 },
    gust: { phase: 'idle', t: 0, fx: 0, fy: 0 }, gustNext: 3,
    hailTimer: 1.2, flipped: false, stage: -1, stars: 0, newBest: false,
    shake: 0, groundX: 0, cloudX: 0, hitFlash: 0, scroll: 0, flash: 0,
  });
}
S = { screen: 'menu', menuIdx: 0, selIdx: 0, kind: 'campaign', levelIdx: 0, cardRects: [], menuRects: [] };
resetRun();
L = levelCfg(LEVELS[0]); // menu backdrop

function levelCfg(lv) { return { id: lv.id, name: lv.name, scene: lv.scene, smart: !!lv.smart, sub: lv.sub, goal: lv.goal, speed: lv.speed, gap: lv.gap, spacing: lv.spacing, mechs: new Set(lv.mech), powers: new Set(powersFor(lv.id)), sky: lv.sky.slice() }; }
function endlessStageCfg(stage, r) {
  const n = Math.min(4, 1 + Math.floor(stage / 3));
  const pool = ENDLESS_POOL.slice(), mechs = [];
  for (let i = 0; i < n && pool.length; i++) mechs.push(pool.splice(Math.floor(r() * pool.length), 1)[0]);
  if (stage === 0) mechs.length = 0; // first stretch is plain
  return { speed: Math.min(300, 165 * (1 + stage * 0.045)), gap: Math.max(140, 182 - stage * 4), spacing: 275, mechs: new Set(mechs) };
}
function startRun(kind, levelIdx = 0) {
  S.kind = kind; S.levelIdx = levelIdx;
  if (kind === 'campaign') {
    rand = mulberry32((Date.now() ^ (levelIdx * 7919)) >>> 0);
    L = levelCfg(LEVELS[levelIdx]);
  } else if (kind === 'endless') {
    rand = mulberry32(Date.now() >>> 0);
    L = Object.assign({ id: 0, name: 'Endless', scene: 'meadow', sub: 'How far can you fly?', goal: null, powers: new Set(['dash', 'ghost']), sky: ['#6fc6ff', '#c9ecff'] }, endlessStageCfg(0, rand));
  } else {
    const key = todayKey(), r = mulberry32(hash('floppy:' + key));
    rand = r;
    const pool = ENDLESS_POOL.slice(), mechs = [];
    for (let i = 0; i < 2 + Math.floor(r() * 2); i++) mechs.push(pool.splice(Math.floor(r() * pool.length), 1)[0]);
    L = { id: 0, name: 'Daily ' + key, scene: SCENE_ORDER[Math.floor(r() * SCENE_ORDER.length)], sub: 'Same sky for everyone today', goal: null, speed: 170, gap: 166, spacing: 270, mechs: new Set(mechs), powers: new Set(['dash', 'ghost']), sky: mechs.includes('dark') ? ['#0b1030', '#1c2a5a'] : ['#f6c667', '#ffe8b8'], dailyKey: key };
  }
  resetRun();
  S.screen = 'ready';
}

// =====================================================================
// Entities
// =====================================================================
function spawnPipe(x) {
  const m = L.mechs, thick = m.has('thick') && rand() < 0.35;
  const w = thick ? T.pipeW * 2.1 : T.pipeW;
  const margin = 60, half = L.gap / 2;
  const minY = margin + half, maxY = GROUND_Y - margin - half;
  const gapY = minY + rand() * (maxY - minY);
  const p = { x, w, gapY, base: gapY, passed: false, phantom: false, flip: false, amp: 0, phase: rand() * 6.28 };
  if (m.has('moving') && rand() < 0.75) p.amp = 28 + 30 * S.intensity;
  if (m.has('phantom') && rand() < 0.42) p.phantom = true;
  if (m.has('gravity') && rand() < 0.4) p.flip = true;
  S.pipes.push(p);
  // coins
  if (m.has('richcoins')) {
    for (const dy of [-half * 0.55, 0, half * 0.55]) S.coinEnts.push({ x: x + w / 2, y: 0, pipe: p, dy, got: false, seen: false });
    S.coinEnts.push({ x: x + w + L.spacing / 2, y: 120 + rand() * (GROUND_Y - 240), pipe: null, dy: 0, got: false, seen: false });
  } else {
    if (rand() < 0.6) S.coinEnts.push({ x: x + w / 2, y: 0, pipe: p, dy: (rand() - 0.5) * half * 0.8, got: false, seen: false });
    if (rand() < 0.3) S.coinEnts.push({ x: x + w + L.spacing / 2, y: 120 + rand() * (GROUND_Y - 240), pipe: null, dy: 0, got: false, seen: false });
  }
}
function hitRect(cx, cy, r, rx, ry, rw, rh) {
  const nx = Math.max(rx, Math.min(cx, rx + rw)), ny = Math.max(ry, Math.min(cy, ry + rh));
  const dx = cx - nx, dy = cy - ny; return dx * dx + dy * dy < r * r;
}
function insidePipe(p) {
  if (p.phantom) return false;
  const half = L.gap / 2, y = S.bird.y, r = T.hitR;
  return hitRect(T.birdX, y, r, p.x, 0, p.w, p.gapY - half) || hitRect(T.birdX, y, r, p.x, p.gapY + half, p.w, GROUND_Y - (p.gapY + half));
}
function puff(x, y, color, n = 6, spread = 120, life = 0.5) {
  for (let i = 0; i < n; i++) { const a = Math.random() * 6.28, s = Math.random() * spread; S.particles.push({ x, y, vx: Math.cos(a) * s, vy: Math.sin(a) * s, life, max: life, color, r: 2 + Math.random() * 3 }); }
}
function popup(text, color, x = T.birdX, y = S.bird.y - 40, life = 0.9) { S.popups.push({ x, y, text, color, life }); }

// =====================================================================
// Actions
// =====================================================================
function beginPlay() { S.screen = 'play'; S.bird.vy = T.flap; S.bird.wing = 1; SFX.flap(); }
function flap() {
  if (S.screen === 'ready') return beginPlay();
  if (S.screen !== 'play') return;
  if (S.dash.active > 0 && S.dash.smart) return; // the smart flamingo is driving
  const dir = S.flipped ? -1 : 1;
  S.bird.vy = (S.dash.active > 0 ? -300 : T.flap) * dir;
  S.bird.wing = 1; SFX.flap();
}
function dive() { if (S.screen === 'play' && S.dash.active > 0 && !S.dash.smart) S.bird.vy = 300 * (S.flipped ? -1 : 1); }
function useDash() {
  if (S.screen !== 'play' || !L.powers.has('dash')) return;
  if (S.dash.cd > 0) return SFX.nope();
  S.usedPower = true;
  const smart = !!L.smart, cfg = smart ? T.smart : T.dash;
  S.dash.smart = smart; S.dash.active = cfg.dur; S.dash.cd = cfg.dur + cfg.cd; S.bird.vy = 0; S.shake = 6;
  puff(T.birdX, S.bird.y, '#ff6fa8', 18, 220, 0.6); popup(smart ? 'SMART FLAMINGO!' : 'FLAMINGO!', '#ff8ac2'); SFX.dash();
}
function useGhost() {
  if (S.screen !== 'play' || !L.powers.has('ghost')) return;
  if (S.ghost.cd > 0) return SFX.nope();
  S.usedPower = true;
  S.ghost.active = T.ghost.dur; S.ghost.cd = T.ghost.dur + T.ghost.cd; S.ghost.lingering = 0;
  puff(T.birdX, S.bird.y, '#7fe9ff', 14, 160, 0.7); popup('GHOST!', '#a8f1ff'); SFX.ghost();
}
async function submitLeaderboard(category, score) {
  try {
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
        game: 'floppy_bird',
        category: category,
        score: score,
        username: playerName,
        guest_token: guestToken
      })
    });
    if (res.ok) {
      if (typeof window.__refreshFloppyLeaderboard === 'function') {
        window.__refreshFloppyLeaderboard(category);
      }
    }
  } catch (_) {}
}

function syncAllScores() {
  try {
    if (totalStars() > 0) submitLeaderboard('campaign_stars', totalStars());
    if (save && save.endlessBest > 0) submitLeaderboard('endless_score', save.endlessBest);
  } catch (_) {}
}

function die() {
  if (S.screen !== 'play') return;
  S.screen = 'dead'; S.shake = 14; S.hitFlash = 0.25; S.dash.active = 0; S.ghost.active = 0;
  puff(T.birdX, S.bird.y, '#ffd84d', 20, 260, 0.8);
  if (S.kind === 'endless') {
    if (S.score > save.endlessBest) { save.endlessBest = S.score; S.newBest = true; }
    if (S.score > 0) submitLeaderboard('endless_score', S.score);
  }
  if (S.kind === 'daily') { const v = S.score + S.coins; if (v > (save.daily[L.dailyKey] || 0)) { save.daily[L.dailyKey] = v; S.newBest = true; } }
  persist(); SFX.die();
}
function levelClear() {
  S.screen = 'clear'; S.dash.active = 0; S.ghost.active = 0;
  const pct = S.coinsSeen ? S.coins / S.coinsSeen : 1;
  let stars = 1;
  if (pct >= 0.8) stars++;
  if (L.powers.size ? !S.usedPower : pct >= 1) stars++;
  S.stars = stars; S.coinPct = pct;
  const prev = save.stars[L.id] || 0, before = totalStars();
  S.newBest = stars > prev;
  save.stars[L.id] = Math.max(prev, stars); persist();
  submitLeaderboard('campaign_stars', totalStars());
  S.newSkin = SKINS.find(sk => sk.need > before && sk.need <= totalStars()) || null;
  puff(T.birdX, S.bird.y, '#fff', 30, 300, 1.2); SFX.clear();
}
function retry() { startRun(S.kind, S.levelIdx); }
function goLevels() { S.screen = 'levels'; S.selIdx = Math.min(S.selIdx, 15); SFX.ui(); }
function goMenu() { S.screen = 'menu'; SFX.ui(); }
function selectCard(i) {
  if (i < LEVELS.length) { if (i < unlockedLevels()) { S.selIdx = i; startRun('campaign', i); SFX.ui(); } else SFX.nope(); }
  else if (i === 14) { if (clearedCount() >= ENDLESS_UNLOCK) { S.selIdx = i; startRun('endless'); SFX.ui(); } else SFX.nope(); }
  else if (i === 15) { if (clearedCount() >= DAILY_UNLOCK) { S.selIdx = i; startRun('daily'); SFX.ui(); } else SFX.nope(); }
}
function cycleSkin(dir) {
  const list = SKINS.filter(skinUnlocked); if (list.length < 2) return SFX.nope();
  let i = list.findIndex(s => s.id === currentSkin().id); i = (i + dir + list.length) % list.length;
  save.skin = list[i].id; persist(); SFX.ui();
}

// =====================================================================
// Update
// =====================================================================
function update(dt) {
  S.t += dt;
  S.cloudX = (S.cloudX + dt * 12) % W;
  if (S.screen !== 'play') S.scroll += 18 * dt;
  S.flash = Math.max(0, S.flash - dt);
  S.shake = Math.max(0, S.shake - dt * 40);
  S.hitFlash = Math.max(0, S.hitFlash - dt);
  for (const p of S.particles) { p.x += p.vx * dt; p.y += p.vy * dt; p.vy += 300 * dt; p.life -= dt; }
  S.particles = S.particles.filter(p => p.life > 0);
  for (const p of S.popups) { p.y -= 40 * dt; p.life -= dt; }
  S.popups = S.popups.filter(p => p.life > 0);
  S.bird.wing = Math.max(0, S.bird.wing - dt * 5);
  const b = S.bird;

  if (S.screen === 'play') return updatePlay(dt);
  if (S.screen === 'dead') {
    const dir = S.flipped ? -1 : 1;
    b.vy = Math.max(-T.maxFall, Math.min(T.maxFall, b.vy + T.gravity * dt * dir));
    b.y = Math.max(T.birdR, Math.min(GROUND_Y - T.birdR, b.y + b.vy * dt));
    b.rot = Math.min(Math.PI / 2, b.rot + dt * 6);
    return;
  }
  if (S.screen === 'clear') { b.y += ((H / 2 - 40) - b.y) * Math.min(1, dt * 3); b.rot *= 0.9; b.wing = 1; return; }
  b.y = H / 2 + Math.sin(S.t * 3) * 10; b.rot = Math.sin(S.t * 3) * 0.15;
}

function updatePlay(dt) {
  const b = S.bird, m = L.mechs;
  const prog = L.goal ? S.score / L.goal : Math.min(1, S.score / 60);
  S.intensity = 0.45 + 0.55 * prog;

  // endless stage progression
  if (S.kind === 'endless') {
    const stage = Math.floor(S.score / 8);
    if (stage !== S.stage) {
      S.stage = stage;
      if (stage > 0) {
        Object.assign(L, endlessStageCfg(stage, rand));
        const names = [...L.mechs].map(k => MECH[k].name).join(' + ') || 'clear skies';
        popup('STAGE ' + (stage + 1) + ': ' + names, '#fff', W / 2, 140, 2.2);
        L.scene = SCENE_ORDER[stage % SCENE_ORDER.length];
        L.sky = LEVELS.find(l => l.scene === L.scene).sky.slice();
      }
    }
  }

  // power timers
  const dashWas = S.dash.active;
  S.dash.cd = Math.max(0, S.dash.cd - dt); S.dash.active = Math.max(0, S.dash.active - dt);
  if (dashWas > ENDING_WARN && S.dash.active <= ENDING_WARN && S.dash.active > 0) SFX.ending();
  if (S.ghost.active > ENDING_WARN && S.ghost.active - dt <= ENDING_WARN) SFX.ending();
  S.ghost.cd = Math.max(0, S.ghost.cd - dt);
  if (S.ghost.active > 0) {
    S.ghost.active -= dt;
    if (S.ghost.active <= 0) {
      const stuck = S.pipes.some(p => { const ph = p.phantom; p.phantom = false; const r = insidePipe(p); p.phantom = ph; return r && !ph; });
      if (stuck && S.ghost.lingering < T.ghost.grace) { S.ghost.lingering += dt; S.ghost.active = 0.0001; } else S.ghost.active = 0;
    }
  }
  const dashing = S.dash.active > 0, ghosting = S.ghost.active > 0;

  // gravity zones
  S.flipped = m.has('gravity') && S.pipes.some(p => p.flip && T.birdX > p.x - L.spacing / 2 + p.w / 2 && T.birdX < p.x + L.spacing / 2 + p.w / 2);
  const g = S.flipped ? -1 : 1;

  // wind
  let windMul = 1, windFy = 0;
  if (m.has('wind')) {
    const G = S.gust;
    if (G.phase === 'idle') { S.gustNext -= dt; if (S.gustNext <= 0) { G.phase = 'warn'; G.t = 0.8; G.fx = (rand() < 0.5 ? -0.4 : 0.55) * S.intensity; G.fy = (rand() < 0.5 ? -1 : 1) * (380 + 260 * S.intensity); } }
    else if (G.phase === 'warn') { G.t -= dt; if (G.t <= 0) { G.phase = 'blow'; G.t = 1.2 + 0.6 * S.intensity; SFX.gust(); } }
    else { G.t -= dt; windMul = 1 + G.fx; windFy = G.fy; if (G.t <= 0) { G.phase = 'idle'; S.gustNext = 2.2 + rand() * 2.5; } }
  }
  // turbo
  if (m.has('turbo')) S.speedMult = Math.min(2.0, 1 + S.score * 0.025);
  const speed = L.speed * (dashing ? T.dash.mult : 1) * windMul * S.speedMult;
  S.scroll += speed * dt;

  // bird physics
  if (dashing && S.dash.smart) {
    // Smart flamingo: steer toward the centre of the nearest gap ahead, sidestep hail
    const next = S.pipes.find(p => !p.phantom && p.x + p.w > T.birdX - 10) || S.pipes[0];
    let target = next ? next.gapY : H / 2;
    for (const h of S.hail) if (h.x > T.birdX - 20 && h.x < T.birdX + 140 && Math.abs(h.y - target) < 60) target += h.y < target ? 55 : -55;
    target = Math.max(T.birdR + 30, Math.min(GROUND_Y - T.hitR - 30, target));
    b.vy = Math.max(-560, Math.min(560, (target - b.y) * 9)); b.y += b.vy * dt;
    b.rot += (b.vy / 1400 * g - b.rot) * Math.min(1, 10 * dt);
    if (Math.random() < dt * 60) S.particles.push({ x: T.birdX - 14, y: b.y + (Math.random() - .5) * 18, vx: -speed * 0.8, vy: 0, life: 0.35, max: 0.35, color: '#ffa3cf', r: 2 });
  } else if (dashing) {
    b.vy += (0 - b.vy) * Math.min(1, 7 * dt); b.vy += windFy * 0.4 * dt; b.y += b.vy * dt;
    b.rot += (b.vy / 900 * g - b.rot) * Math.min(1, 10 * dt);
    if (Math.random() < dt * 60) S.particles.push({ x: T.birdX - 14, y: b.y + (Math.random() - .5) * 18, vx: -speed * 0.8, vy: 0, life: 0.35, max: 0.35, color: '#ffa3cf', r: 2 });
  } else {
    b.vy += (T.gravity * g + windFy) * dt;
    b.vy = Math.max(-T.maxFall, Math.min(T.maxFall, b.vy)); b.y += b.vy * dt;
    const up = b.vy * g < 0;
    const target = (up ? -0.45 : Math.min(Math.PI / 2, Math.abs(b.vy) / T.maxFall * 1.6)) * g;
    b.rot += (target - b.rot) * Math.min(1, 8 * dt);
  }
  if (b.y < T.birdR) { b.y = T.birdR; b.vy = Math.max(0, b.vy); if (S.flipped) return die(); }
  if (ghosting && Math.random() < dt * 30) S.particles.push({ x: T.birdX + (Math.random() - .5) * 30, y: b.y + (Math.random() - .5) * 30, vx: 0, vy: -40, life: 0.5, max: 0.5, color: '#9ff0ff', r: 1.5 });

  // world scroll
  S.groundX = (S.groundX + speed * dt) % 48;
  for (const p of S.pipes) { p.x -= speed * dt; if (p.amp) p.gapY = p.base + Math.sin(S.t * 1.7 + p.phase) * p.amp; }
  S.pipes = S.pipes.filter(p => p.x + p.w > -10);
  while (S.pipes.length === 0 || S.pipes[S.pipes.length - 1].x <= W - L.spacing) {
    const last = S.pipes[S.pipes.length - 1];
    spawnPipe(last ? last.x + L.spacing : W + 140);
  }
  for (const c of S.coinEnts) { if (c.pipe) { c.x = c.pipe.x + c.pipe.w / 2; c.y = c.pipe.gapY + c.dy; } else c.x -= speed * dt; }
  // hail
  if (m.has('hail')) {
    S.hailTimer -= dt;
    if (S.hailTimer <= 0) {
      const n = rand() < 0.3 + 0.4 * S.intensity ? 2 : 1;
      for (let i = 0; i < n; i++) S.hail.push({ x: W + 10 + rand() * L.spacing, y: -12, vy: 170 + 130 * S.intensity + rand() * 80, r: 6 + rand() * 4 });
      S.hailTimer = (1.15 - 0.55 * S.intensity) + rand() * 0.6;
    }
  }
  for (const h of S.hail) { h.x -= speed * dt; h.y += h.vy * dt; }
  S.hail = S.hail.filter(h => h.y < GROUND_Y + 20 && h.x > -20);

  // scoring
  for (const p of S.pipes) {
    if (!p.passed && p.x + p.w < T.birdX) {
      p.passed = true;
      const pts = dashing && !S.dash.smart ? T.dash.scoreMult : 1;
      S.score += pts;
      popup('+' + pts, dashing ? '#ff8ac2' : '#fff', T.birdX + 30, b.y - 30, 0.7); SFX.score();
      if (L.goal && S.score >= L.goal) return levelClear();
    }
  }
  // coins
  for (const c of S.coinEnts) {
    if (c.got) continue;
    const dx = c.x - T.birdX, dy = c.y - b.y;
    if (dx * dx + dy * dy < (T.hitR + 10) * (T.hitR + 10)) { c.got = true; c.seen = true; S.coins++; S.coinsSeen++; puff(c.x, c.y, '#ffe066', 6, 90, 0.4); SFX.coin(); }
    else if (!c.seen && c.x < T.birdX - 24) { c.seen = true; S.coinsSeen++; }
  }
  S.coinEnts = S.coinEnts.filter(c => !c.got && c.x > -20);

  // collisions
  if (b.y + T.hitR >= GROUND_Y) { b.y = GROUND_Y - T.hitR; return die(); }
  if (!ghosting) {
    if (S.pipes.some(insidePipe)) return die();
    for (const h of S.hail) { const dx = h.x - T.birdX, dy = h.y - b.y; if (dx * dx + dy * dy < (h.r + T.hitR - 2) * (h.r + T.hitR - 2)) return die(); }
  }
}

// =====================================================================
// Draw helpers
// =====================================================================
function rr(x, y, w, h, r) { ctx.beginPath(); ctx.roundRect(x, y, w, h, r); }
function text(str, x, y, size, color = '#fff', weight = 'bold', align = 'center') {
  ctx.font = weight + ' ' + size + 'px system-ui'; ctx.textAlign = align; ctx.textBaseline = 'middle';
  ctx.lineWidth = Math.max(2, size / 8); ctx.strokeStyle = 'rgba(0,0,0,.55)'; ctx.strokeText(str, x, y);
  ctx.fillStyle = color; ctx.fillText(str, x, y);
}
function plain(str, x, y, size, color = '#fff', weight = 'normal', align = 'center') {
  ctx.font = weight + ' ' + size + 'px system-ui'; ctx.textAlign = align; ctx.textBaseline = 'middle'; ctx.fillStyle = color; ctx.fillText(str, x, y);
}
function overlay(alpha) { ctx.fillStyle = 'rgba(10,16,40,' + alpha + ')'; ctx.fillRect(0, 0, W, H); }
function starStr(n) { return '★'.repeat(n) + '☆'.repeat(3 - n); }
function skinColors(sk) {
  if (sk.rainbow) { const h = (S.t * 120) % 360; return { body: 'hsl(' + h + ',90%,60%)', belly: 'hsl(' + h + ',90%,85%)', wing: 'hsl(' + ((h + 40) % 360) + ',90%,50%)' }; }
  return sk;
}

function drawBird(x, y, opts = {}) {
  const b = S.bird, dashing = opts.dashing ?? S.dash.active > 0, ghosting = opts.ghosting ?? S.ghost.active > 0;
  const sk = opts.skin || currentSkin(), c = skinColors(sk);
  ctx.save();
  ctx.translate(x, y);
  if (opts.flipped ?? S.flipped) ctx.scale(1, -1);
  ctx.rotate(opts.rot ?? b.rot);
  if (ghosting) { ctx.globalAlpha = 0.5 + Math.sin(S.t * 14) * 0.12; ctx.shadowColor = '#7fe9ff'; ctx.shadowBlur = 22; }
  const body = dashing ? '#ff6fa8' : c.body, belly = dashing ? '#ffc1dd' : c.belly, wingC = dashing ? '#e2447f' : c.wing;
  if (dashing) {
    ctx.strokeStyle = body; ctx.lineWidth = 6; ctx.lineCap = 'round';
    ctx.beginPath(); ctx.moveTo(8, -4); ctx.quadraticCurveTo(28, -14, 26, -34); ctx.stroke();
    ctx.strokeStyle = '#3b2a1a'; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(-6, 10); ctx.lineTo(-30, 14); ctx.moveTo(-2, 12); ctx.lineTo(-28, 20); ctx.stroke();
  }
  ctx.fillStyle = body; ctx.beginPath(); ctx.ellipse(0, 0, T.birdR + 2, T.birdR - 1, 0, 0, 6.29); ctx.fill();
  ctx.fillStyle = belly; ctx.beginPath(); ctx.ellipse(-2, 5, 10, 7, 0, 0, 6.29); ctx.fill();
  if (sk.shine && !dashing) { ctx.fillStyle = 'rgba(255,255,255,.55)'; ctx.beginPath(); ctx.ellipse(-5, -7, 6, 3, -0.5, 0, 6.29); ctx.fill(); }
  const wingA = (b.wing > 0 ? -0.9 * b.wing : 0.25) + Math.sin(S.t * (dashing ? 40 : 18)) * 0.25;
  ctx.save(); ctx.translate(-4, 1); ctx.rotate(wingA); ctx.fillStyle = wingC; ctx.beginPath(); ctx.ellipse(-2, 4, 11, 6, 0.2, 0, 6.29); ctx.fill(); ctx.restore();
  if (dashing) {
    ctx.fillStyle = body; ctx.beginPath(); ctx.arc(26, -36, 7, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(28, -37, 3, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#222'; ctx.beginPath(); ctx.arc(29, -37, 1.4, 0, 6.29); ctx.fill();
    ctx.beginPath(); ctx.moveTo(31, -34); ctx.lineTo(42, -30); ctx.lineTo(31, -27); ctx.closePath(); ctx.fill();
    if (S.dash.smart && (opts.dashing ?? true)) { ctx.fillStyle = '#111'; rr(22, -41, 12, 6, 2); ctx.fill(); ctx.fillRect(19, -39, 4, 2); ctx.fillStyle = 'rgba(255,255,255,.5)'; ctx.fillRect(24, -40, 3, 1.5); }
  } else {
    if (sk.band) { ctx.fillStyle = sk.band; ctx.fillRect(-2, -12, 18, 5); ctx.beginPath(); ctx.moveTo(-2, -10); ctx.lineTo(-16, -16); ctx.lineTo(-14, -8); ctx.closePath(); ctx.fill(); }
    ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(7, -5, 5.5, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#222'; ctx.beginPath(); ctx.arc(9, -5, 2.5, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#ff7a2f'; rr(12, -1, 12, 7, 3); ctx.fill();
  }
  ctx.restore();
}


// =====================================================================
// Scenery — every level is a different place (parallax layers, procedural)
// =====================================================================
const SCENE_ORDER = ['meadow', 'lagoon', 'haunted', 'marsh', 'peaks', 'canyon', 'straits', 'night', 'storm', 'islands', 'sunset', 'fog', 'inferno', 'aurora'];
function n1(i) { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); } // cheap hash → [0,1)
function hills(color, par, amp, baseY, wl, o) {
  ctx.fillStyle = color; ctx.beginPath(); ctx.moveTo(0, GROUND_Y);
  for (let x = 0; x <= W; x += 8) { const u = (x + o * par) / wl * 6.283; ctx.lineTo(x, baseY - amp * (0.6 * Math.sin(u) + 0.4 * Math.sin(u * 2.7 + 1.3))); }
  ctx.lineTo(W, GROUND_Y); ctx.closePath(); ctx.fill();
}
function mountains(color, par, hMin, hMax, baseY, width, o, snow) {
  ctx.fillStyle = color;
  const off = (o * par) % width;
  for (let k = -1; k <= W / width + 1; k++) {
    const idx = k + Math.floor((o * par) / width), px = k * width - off + width / 2, h = hMin + n1(idx) * (hMax - hMin);
    ctx.beginPath(); ctx.moveTo(px - width * 0.6, baseY); ctx.lineTo(px, baseY - h); ctx.lineTo(px + width * 0.6, baseY); ctx.closePath(); ctx.fill();
    if (snow) { ctx.fillStyle = snow; ctx.beginPath(); ctx.moveTo(px - width * 0.14, baseY - h * 0.75); ctx.lineTo(px, baseY - h); ctx.lineTo(px + width * 0.14, baseY - h * 0.75); ctx.closePath(); ctx.fill(); ctx.fillStyle = color; }
  }
}
function mesas(color, par, baseY, o) {
  ctx.fillStyle = color; const width = 150, off = (o * par) % width;
  for (let k = -1; k <= W / width + 1; k++) {
    const idx = k + Math.floor((o * par) / width), x = k * width - off, h = 60 + n1(idx) * 90, w = 60 + n1(idx + 9) * 60;
    ctx.beginPath(); ctx.moveTo(x, baseY); ctx.lineTo(x + 12, baseY - h); ctx.lineTo(x + w - 12, baseY - h); ctx.lineTo(x + w, baseY); ctx.closePath(); ctx.fill();
  }
}
function stars(n, alpha, maxY) {
  for (let i = 0; i < n; i++) { const x = n1(i) * W, y = n1(i + 500) * maxY, tw = 0.5 + 0.5 * Math.sin(S.t * (1 + n1(i + 900) * 2) + i); ctx.fillStyle = 'rgba(255,255,255,' + (alpha * tw) + ')'; ctx.fillRect(x, y, 2, 2); }
}
function moon(x, y, r, color, glow) {
  if (glow) { const g = ctx.createRadialGradient(x, y, r, x, y, r * 3); g.addColorStop(0, glow); g.addColorStop(1, 'rgba(0,0,0,0)'); ctx.fillStyle = g; ctx.fillRect(x - r * 3, y - r * 3, r * 6, r * 6); }
  ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, r, 0, 6.29); ctx.fill();
}
function clouds(color, par, y0, o, big) {
  ctx.fillStyle = color;
  for (let i = 0; i < 5; i++) {
    const wl = W + 200, cx = ((i * 137 - o * par * (1 + i * 0.25)) % wl + wl) % wl - 100, cy = y0 + (i % 3) * 55, k = big ? 1.6 : 1;
    ctx.beginPath(); ctx.arc(cx, cy, 22 * k, 0, 7); ctx.arc(cx + 24 * k, cy - 10 * k, 26 * k, 0, 7); ctx.arc(cx + 52 * k, cy, 20 * k, 0, 7); ctx.fill();
  }
}
function deadTrees(color, par, baseY, o) {
  ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.lineCap = 'round'; const width = 120, off = (o * par) % width;
  for (let k = -1; k <= W / width + 1; k++) {
    const idx = k + Math.floor((o * par) / width), x = k * width - off + n1(idx) * 60, h = 50 + n1(idx + 3) * 50;
    ctx.beginPath(); ctx.moveTo(x, baseY); ctx.lineTo(x, baseY - h); ctx.moveTo(x, baseY - h * 0.6); ctx.lineTo(x - 18, baseY - h * 0.85); ctx.moveTo(x, baseY - h * 0.45); ctx.lineTo(x + 16, baseY - h * 0.7); ctx.stroke();
  }
}
function reeds(color, par, baseY, o) {
  ctx.strokeStyle = color; ctx.lineWidth = 2; const width = 22, off = (o * par) % width;
  for (let k = -1; k <= W / width + 1; k++) { const idx = k + Math.floor((o * par) / width), x = k * width - off, h = 20 + n1(idx) * 40, sway = Math.sin(S.t * 2 + idx) * 4; ctx.beginPath(); ctx.moveTo(x, baseY); ctx.quadraticCurveTo(x + sway, baseY - h / 2, x + sway * 2, baseY - h); ctx.stroke(); }
}
function water(y, top, bottom, o) {
  const g = ctx.createLinearGradient(0, y, 0, GROUND_Y); g.addColorStop(0, top); g.addColorStop(1, bottom); ctx.fillStyle = g; ctx.fillRect(0, y, W, GROUND_Y - y);
  ctx.strokeStyle = 'rgba(255,255,255,.35)'; ctx.lineWidth = 1.5;
  for (let i = 0; i < 12; i++) { const wl = W + 80, x = ((i * 61 - o * 0.5) % wl + wl) % wl - 40, yy = y + 8 + (i * 13) % (GROUND_Y - y - 10); ctx.beginPath(); ctx.moveTo(x, yy); ctx.lineTo(x + 20 + (i % 3) * 10, yy); ctx.stroke(); }
}
function birdsFlock(color, o, y0) {
  ctx.strokeStyle = color; ctx.lineWidth = 2;
  for (let i = 0; i < 5; i++) { const x = ((W + 60) - ((o * 0.35 + i * 40) % (W + 120))), y = y0 + i * 9 + Math.sin(S.t * 2 + i) * 4, f = Math.sin(S.t * 8 + i) * 3; ctx.beginPath(); ctx.moveTo(x - 7, y + f); ctx.lineTo(x, y); ctx.lineTo(x + 7, y + f); ctx.stroke(); }
}
function fogBands(color, par, o) {
  for (let i = 0; i < 4; i++) { const y = 120 + i * 110, x = ((-(o * par * (1 + i * 0.3)) % (W + 300)) + W + 300) % (W + 300) - 300; ctx.fillStyle = color; ctx.beginPath(); ctx.ellipse(x + 150, y, 220, 26, 0, 0, 6.29); ctx.fill(); }
}
function aurora(o) {
  for (let b = 0; b < 3; b++) {
    const hue = 120 + b * 60 + Math.sin(S.t * 0.5 + b) * 30;
    ctx.fillStyle = 'hsla(' + hue + ',90%,60%,.16)'; ctx.beginPath(); ctx.moveTo(0, 0);
    for (let x = 0; x <= W; x += 10) ctx.lineTo(x, 60 + b * 50 + Math.sin((x + o * 0.2) / 70 + S.t * 0.8 + b) * 30 + Math.sin(x / 23 + S.t) * 8);
    ctx.lineTo(W, 0); ctx.closePath(); ctx.fill();
  }
}
const SCENES = {
  meadow:  { ground: ['#7ccf5a', '#c9a15a'], draw(o) { clouds('rgba(255,255,255,.75)', 0.2, 80, o); hills('#9ad98a', 0.15, 45, GROUND_Y - 70, 260, o); hills('#6fbf62', 0.35, 30, GROUND_Y - 25, 150, o); } },
  lagoon:  { ground: ['#f2d59b', '#e3bd7a'], draw(o) { moon(400, 90, 34, '#fff3b0', 'rgba(255,240,180,.45)'); clouds('rgba(255,255,255,.7)', 0.2, 70, o); water(GROUND_Y - 110, '#7fd6e8', '#2f9fbf', o); birdsFlock('#c94f7c', o, 150); hills('#e39ac0', 0.3, 18, GROUND_Y - 100, 200, o); } },
  haunted: { ground: ['#4c3f6b', '#2e2542'], draw(o) { moon(120, 100, 40, '#f5f0d8', 'rgba(200,190,255,.35)'); stars(50, 0.7, 300); hills('#3a2f59', 0.15, 40, GROUND_Y - 60, 240, o); deadTrees('#1f1830', 0.45, GROUND_Y + 2, o); if (Math.sin(S.t * 3) > 0.7) birdsFlock('#1f1830', o * 2, 90); } },
  marsh:   { ground: ['#6bbf7a', '#8a7b4c'], draw(o) { clouds('rgba(255,255,255,.6)', 0.2, 70, o); hills('#a3dcae', 0.15, 30, GROUND_Y - 80, 300, o); water(GROUND_Y - 60, '#8fd8c8', '#4faa9a', o); reeds('#2f7a4a', 0.5, GROUND_Y + 2, o); } },
  peaks:   { ground: ['#e9f3ff', '#b9c9dd'], draw(o) { clouds('rgba(255,255,255,.85)', 0.15, 60, o, true); mountains('#6f86a8', 0.12, 160, 260, GROUND_Y, 170, o, '#f4f8ff'); mountains('#4f6484', 0.28, 90, 160, GROUND_Y, 120, o, '#e0e8f4'); } },
  canyon:  { ground: ['#e0a05a', '#b8743a'], draw(o) { moon(80, 80, 30, '#fff1c2', 'rgba(255,230,150,.5)'); mesas('#d98a4e', 0.12, GROUND_Y, o); mesas('#b0623a', 0.3, GROUND_Y, o); } },
  straits: { ground: ['#8fa5a8', '#6c7f86'], draw(o) { clouds('rgba(255,255,255,.7)', 0.25, 60, o); water(GROUND_Y - 130, '#4f9fd6', '#1f5f8f', o); mountains('#3f5f6a', 0.2, 120, 200, GROUND_Y - 120, 140, o); birdsFlock('#fff', o, 120); } },
  night:   { ground: ['#2e3d55', '#1a2236'], draw(o) { stars(90, 0.9, GROUND_Y - 100); moon(380, 110, 28, '#e9ecff', 'rgba(180,200,255,.3)'); hills('#141c33', 0.15, 40, GROUND_Y - 50, 240, o); hills('#0d1326', 0.35, 26, GROUND_Y - 15, 150, o); } },
  storm:   { ground: ['#9aa7b5', '#6b7684'], draw(o) { clouds('rgba(60,70,90,.85)', 0.35, 40, o, true); clouds('rgba(90,100,120,.6)', 0.6, 140, o, true); hills('#55606f', 0.2, 30, GROUND_Y - 40, 200, o); if (Math.random() < 0.004) S.flash = 0.12; } },
  islands: { ground: ['#b48cff', '#7c5cc4'], draw(o) { clouds('rgba(255,255,255,.55)', 0.2, 60, o); const width = 220, off = (o * 0.25) % width; for (let k = -1; k <= 3; k++) { const idx = k + Math.floor((o * 0.25) / width), x = k * width - off + 40, y = 140 + n1(idx) * 220 + Math.sin(S.t + idx) * 8; ctx.fillStyle = '#5b3fa0'; ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + 120, y); ctx.lineTo(x + 80, y + 50); ctx.lineTo(x + 40, y + 44); ctx.closePath(); ctx.fill(); ctx.fillStyle = '#b48cff'; ctx.fillRect(x, y - 8, 120, 10); } } },
  sunset:  { ground: ['#ff9f6b', '#c96a3a'], draw(o) { moon(240, GROUND_Y - 120, 70, '#ffdd88', 'rgba(255,170,80,.55)'); ctx.fillStyle = 'rgba(255,120,60,.25)'; for (let i = 0; i < 5; i++) ctx.fillRect(0, GROUND_Y - 200 + i * 30, W, 8); hills('#8a3d3d', 0.15, 40, GROUND_Y - 60, 260, o); hills('#5c2a2a', 0.35, 26, GROUND_Y - 20, 150, o); } },
  fog:     { ground: ['#9fbfb8', '#6e8c86'], draw(o) { hills('#5f8a86', 0.12, 50, GROUND_Y - 90, 280, o); deadTrees('#3d5f5c', 0.3, GROUND_Y - 30, o); fogBands('rgba(220,240,240,.35)', 0.4, o); } },
  inferno: { ground: ['#7a2f2f', '#4a1c1c'], draw(o) { clouds('rgba(80,20,20,.7)', 0.4, 40, o, true); mountains('#5a1f1f', 0.2, 120, 220, GROUND_Y, 150, o); ctx.fillStyle = 'rgba(255,120,40,.35)'; for (let i = 0; i < 6; i++) { const x = ((i * 90 - o * 0.5) % (W + 60) + W + 60) % (W + 60) - 30; ctx.beginPath(); ctx.arc(x, GROUND_Y - 6, 10 + (i % 3) * 4, 0, 6.29); ctx.fill(); } if (Math.random() < 0.006) S.flash = 0.1; } },
  aurora:  { ground: ['#2b2b4a', '#1a1a2e'], draw(o) { stars(70, 0.8, 300); aurora(o); moon(90, 90, 22, '#fff', 'rgba(255,255,255,.2)'); mountains('#12122a', 0.15, 120, 220, GROUND_Y, 160, o, '#2c2c50'); birdsFlock('#ffffff', o, 200); } },
};

function drawWorld() {
  const dashing = S.dash.active > 0, ghosting = S.ghost.active > 0, half = L.gap / 2;
  // sky
  const sky = ctx.createLinearGradient(0, 0, 0, GROUND_Y);
  sky.addColorStop(0, L.sky[0]); sky.addColorStop(1, L.sky[1]);
  ctx.fillStyle = sky; ctx.fillRect(0, 0, W, GROUND_Y);
  const scene = SCENES[L.scene] || SCENES.meadow;
  scene.draw(S.scroll);
  if (dashing) { ctx.fillStyle = 'rgba(255,120,180,.35)'; ctx.fillRect(0, 0, W, GROUND_Y); }
  // gravity zones
  for (const p of S.pipes) if (p.flip) {
    const x0 = p.x - L.spacing / 2 + p.w / 2, x1 = p.x + L.spacing / 2 + p.w / 2;
    ctx.fillStyle = 'rgba(150,80,255,.22)'; ctx.fillRect(x0, 0, x1 - x0, GROUND_Y);
    ctx.fillStyle = 'rgba(200,160,255,.5)'; ctx.font = 'bold 26px system-ui'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    for (let y = 40 + (S.t * 60) % 80; y < GROUND_Y; y += 80) ctx.fillText('⇧', (x0 + x1) / 2, y);
  }
  // speed lines
  if (dashing || S.gust.phase === 'blow') {
    const dir = S.gust.phase === 'blow' && !dashing ? Math.sign(S.gust.fx) : 1;
    ctx.strokeStyle = 'rgba(255,255,255,.5)'; ctx.lineWidth = 2;
    for (let i = 0; i < 14; i++) {
      const y = (i * 53 + S.t * 900 * (i % 3 + 1)) % GROUND_Y, x = (i * 97 + S.t * 1400) % (W + 200) - 100;
      const sx = dir > 0 ? W - x : x; ctx.beginPath(); ctx.moveTo(sx, y); ctx.lineTo(sx - 60 * dir, y); ctx.stroke();
    }
  }
  // pipes
  for (const p of S.pipes) {
    const top = p.gapY - half, bot = p.gapY + half;
    ctx.save();
    if (p.phantom) { ctx.globalAlpha = 0.45 + Math.sin(S.t * 9 + p.phase) * 0.12; }
    else if (ghosting) ctx.globalAlpha = 0.55;
    const grad = ctx.createLinearGradient(p.x, 0, p.x + p.w, 0);
    if (p.phantom) { grad.addColorStop(0, '#7fd8e6'); grad.addColorStop(0.5, '#c6f6ff'); grad.addColorStop(1, '#5fb8c8'); }
    else { grad.addColorStop(0, '#5ad35a'); grad.addColorStop(0.5, '#8ef08e'); grad.addColorStop(1, '#3f9f3f'); }
    ctx.fillStyle = grad; ctx.fillRect(p.x, 0, p.w, top); ctx.fillRect(p.x, bot, p.w, GROUND_Y - bot);
    ctx.fillStyle = p.phantom ? '#3e8c9a' : '#2e7d32';
    rr(p.x - 4, top - 26, p.w + 8, 26, 4); ctx.fill(); rr(p.x - 4, bot, p.w + 8, 26, 4); ctx.fill();
    ctx.fillStyle = 'rgba(255,255,255,.18)'; ctx.fillRect(p.x + 8, 0, 8, Math.max(0, top - 26)); ctx.fillRect(p.x + 8, bot + 26, 8, Math.max(0, GROUND_Y - bot - 26));
    if (p.phantom) { ctx.setLineDash([6, 6]); ctx.lineDashOffset = -S.t * 40; ctx.strokeStyle = 'rgba(255,255,255,.7)'; ctx.lineWidth = 2; ctx.strokeRect(p.x, 0, p.w, top); ctx.strokeRect(p.x, bot, p.w, GROUND_Y - bot); }
    ctx.restore();
  }
  // coins
  for (const c of S.coinEnts) {
    const sx = Math.abs(Math.cos(S.t * 6 + c.x * 0.05));
    ctx.fillStyle = '#ffcf3d'; ctx.beginPath(); ctx.ellipse(c.x, c.y, 9 * sx + 1, 9, 0, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#ffe98a'; ctx.beginPath(); ctx.ellipse(c.x, c.y, 5 * sx + 0.5, 5, 0, 0, 6.29); ctx.fill();
  }
  // hail
  for (const h of S.hail) {
    ctx.strokeStyle = 'rgba(200,235,255,.5)'; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(h.x, h.y); ctx.lineTo(h.x + 10, h.y - 26); ctx.stroke();
    ctx.fillStyle = '#e8f7ff'; ctx.beginPath(); ctx.arc(h.x, h.y, h.r, 0, 6.29); ctx.fill();
    ctx.fillStyle = '#9ed3f0'; ctx.beginPath(); ctx.arc(h.x + 2, h.y + 2, h.r * 0.5, 0, 6.29); ctx.fill();
  }
  for (const p of S.particles) { ctx.globalAlpha = p.life / p.max; ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7); ctx.fill(); }
  ctx.globalAlpha = 1;
  drawBird(T.birdX, S.bird.y);
  // ground
  ctx.fillStyle = scene.ground[1]; ctx.fillRect(0, GROUND_Y, W, H - GROUND_Y);
  ctx.fillStyle = scene.ground[0]; ctx.fillRect(0, GROUND_Y, W, 12);
  ctx.fillStyle = 'rgba(0,0,0,.18)';
  for (let x = -48 + (48 - S.groundX); x < W + 48; x += 48) { ctx.beginPath(); ctx.moveTo(x, GROUND_Y); ctx.lineTo(x + 24, GROUND_Y); ctx.lineTo(x + 12, GROUND_Y + 12); ctx.fill(); }
  // darkness
  if (L.mechs.has('dark') && (S.screen === 'play' || S.screen === 'dead')) {
    const g = ctx.createRadialGradient(T.birdX, S.bird.y, 80, T.birdX, S.bird.y, 210);
    g.addColorStop(0, 'rgba(4,6,20,0)'); g.addColorStop(1, 'rgba(4,6,20,.96)');
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, GROUND_Y);
  }
  // gust warning / indicator
  if (S.gust.phase !== 'idle') {
    const G = S.gust, blink = G.phase === 'warn' ? (Math.sin(S.t * 25) > 0) : true;
    if (blink) {
      const arrow = (G.fx > 0 ? '⟶' : '⟵') + ' ' + (G.fy < 0 ? '⇧' : '⇩');
      text((G.phase === 'warn' ? 'GUST! ' : '') + arrow, W / 2, 110, 26, G.phase === 'warn' ? '#ffe066' : '#dff4ff');
    }
  }
}

function drawPowerBar(x, label, key, pw, total, color, activeColor, enabled) {
  const w = 190, h = 18, y = GROUND_Y + 30;
  ctx.fillStyle = 'rgba(0,0,0,.35)'; rr(x, y, w, h, 9); ctx.fill();
  if (!enabled) { plain('[' + key + '] ' + label + '  — locked', x + 4, y - 12, 12, 'rgba(255,255,255,.45)', 'bold', 'left'); return; }
  const ready = pw.cd <= 0, active = pw.active > 0, fill = ready ? 1 : 1 - pw.cd / total;
  const ending = active && pw.active <= ENDING_WARN && Math.sin(S.t * 40) > 0;
  ctx.fillStyle = ending ? '#fff' : active ? activeColor : ready ? color : 'rgba(255,255,255,.35)';
  if (fill > 0) { rr(x + 2, y + 2, (w - 4) * fill, h - 4, 7); ctx.fill(); }
  if (ready && !active) { ctx.strokeStyle = 'rgba(255,255,255,' + (0.4 + Math.sin(S.t * 6) * 0.3) + ')'; ctx.lineWidth = 2; rr(x, y, w, h, 9); ctx.stroke(); }
  plain('[' + key + '] ' + label + (active ? (pw.active <= ENDING_WARN ? '  ENDING' : '  ✦') : ready ? '  READY' : ''), x + 4, y - 12, 12, '#fff', 'bold', 'left');
}

function drawHUD() {
  const inRun = S.screen === 'play' || S.screen === 'dead' || S.screen === 'clear';
  if (inRun) {
    const label = S.kind === 'campaign' ? 'L' + L.id + ' · ' + L.name : S.kind === 'endless' ? 'ENDLESS · stage ' + (S.stage + 1) : L.name;
    text(label, 12, 18, 13, '#fff', 'bold', 'left');
    text('● ' + S.coins, W - 12, 18, 14, '#ffe066', 'bold', 'right');
    const scoreStr = L.goal ? Math.min(S.score, L.goal) + ' / ' + L.goal : String(S.score);
    text(scoreStr, W / 2, 52, L.goal ? 40 : 56);
    if (L.goal) { ctx.fillStyle = 'rgba(0,0,0,.35)'; rr(W / 2 - 90, 80, 180, 8, 4); ctx.fill(); ctx.fillStyle = '#ffe066'; rr(W / 2 - 90, 80, 180 * Math.min(1, S.score / L.goal), 8, 4); ctx.fill(); }
    if (S.speedMult > 1.01) text('×' + S.speedMult.toFixed(2), W / 2 + 110, 52, 16, '#ffb27a');
    if (S.kind === 'endless') text('best ' + save.endlessBest, W - 12, 40, 12, 'rgba(255,255,255,.8)', 'bold', 'right');
    if (S.kind === 'daily') text('best ' + (save.daily[L.dailyKey] || 0), W - 12, 40, 12, 'rgba(255,255,255,.8)', 'bold', 'right');
  }
  drawPowerBar(20, L.smart ? 'SMART FLAMINGO' : 'FLAMINGO DASH', 'J', S.dash, L.smart ? T.smart.dur + T.smart.cd : T.dash.dur + T.dash.cd, '#ff6fa8', '#ffb3d4', L.powers.has('dash'));
  drawPowerBar(W - 210, 'GHOST', 'K', S.ghost, T.ghost.dur + T.ghost.cd, '#5fd7f0', '#bdf3ff', L.powers.has('ghost'));
  for (const p of S.popups) {
    ctx.globalAlpha = Math.min(1, p.life * 2);
    text(p.text, p.x, p.y, p.text.length > 12 ? 16 : 22, p.color); ctx.globalAlpha = 1;
  }
}

// ---------------- screens ----------------
function drawMenu() {
  overlay(0.35);
  text('FLOPPY BIRD', W / 2, 120, 54, '#ffd84d');
  text('SUPER POWERS EDITION', W / 2, 165, 20);
  const sk = currentSkin();
  drawBird(W / 2, 240, { skin: sk, dashing: false, ghosting: false, flipped: false, rot: Math.sin(S.t * 3) * 0.15 });
  const cleared = clearedCount(), stars = totalStars();
  const items = [
    { label: 'CAMPAIGN', sub: cleared + ' / ' + LEVELS.length + ' levels cleared', ok: true },
    { label: 'ENDLESS', sub: cleared >= ENDLESS_UNLOCK ? 'best ' + save.endlessBest : 'clear level ' + ENDLESS_UNLOCK + ' to unlock', ok: cleared >= ENDLESS_UNLOCK },
    { label: 'DAILY FLIGHT', sub: cleared >= DAILY_UNLOCK ? 'today: ' + (save.daily[todayKey()] || 0) : 'clear level ' + DAILY_UNLOCK + ' to unlock', ok: cleared >= DAILY_UNLOCK },
    { label: '◀  SKIN: ' + sk.name.toUpperCase() + '  ▶', sub: nextSkinHint(), ok: true },
  ];
  S.menuRects = [];
  items.forEach((it, i) => {
    const y = 320 + i * 58, sel = i === S.menuIdx;
    ctx.fillStyle = sel ? 'rgba(255,216,77,.25)' : 'rgba(0,0,0,.25)'; rr(70, y - 22, 340, 46, 10); ctx.fill();
    if (sel) { ctx.strokeStyle = '#ffd84d'; ctx.lineWidth = 2; rr(70, y - 22, 340, 46, 10); ctx.stroke(); }
    text(it.label, W / 2, y - 6, 18, it.ok ? '#fff' : 'rgba(255,255,255,.45)');
    plain(it.sub, W / 2, y + 12, 11, 'rgba(255,255,255,.75)');
    S.menuRects.push({ x: 70, y: y - 22, w: 340, h: 46 });
  });
  plain('★ ' + stars + ' / ' + STAR_MAX, W / 2, 290, 14, '#ffd84d', 'bold');
  plain('↑↓ choose · ENTER select', W / 2, H - 30, 12, 'rgba(255,255,255,.8)');
}
function nextSkinHint() {
  const stars = totalStars(), next = SKINS.find(s => s.need > stars);
  return next ? next.name + ' at ★ ' + next.need : 'all skins unlocked';
}
function drawLevels() {
  overlay(0.45);
  text('CHOOSE YOUR SKY', W / 2, 48, 30, '#ffd84d');
  plain('★ ' + totalStars() + ' / ' + STAR_MAX + '   ·   ' + clearedCount() + ' / ' + LEVELS.length + ' cleared', W / 2, 82, 13, 'rgba(255,255,255,.85)');
  const unlocked = unlockedLevels(), cleared = clearedCount();
  S.cardRects = [];
  for (let i = 0; i < 16; i++) {
    const col = i % 4, row = Math.floor(i / 4), x = 25 + col * 110, y = 112 + row * 96, w = 100, h = 86;
    const sel = i === S.selIdx;
    let title, num, stars = -1, ok, sub = '';
    if (i < LEVELS.length) { const lv = LEVELS[i]; title = lv.name; num = String(lv.id); stars = save.stars[lv.id] || 0; ok = i < unlocked; sub = lv.mech.map(k => MECH[k].name).join(', ') || (lv.id === 7 ? 'narrow gaps' : lv.id === 2 ? 'smart flamingo' : 'basics'); }
    else if (i === 14) { title = 'Endless'; num = '∞'; ok = cleared >= ENDLESS_UNLOCK; sub = ok ? 'best ' + save.endlessBest : 'clear L' + ENDLESS_UNLOCK; }
    else { title = 'Daily'; num = '☀'; ok = cleared >= DAILY_UNLOCK; sub = ok ? 'today ' + (save.daily[todayKey()] || 0) : 'clear L' + DAILY_UNLOCK; }
    ctx.fillStyle = ok ? (sel ? 'rgba(255,216,77,.28)' : 'rgba(255,255,255,.14)') : 'rgba(0,0,0,.35)'; rr(x, y, w, h, 10); ctx.fill();
    if (sel) { ctx.strokeStyle = '#ffd84d'; ctx.lineWidth = 2.5; rr(x, y, w, h, 10); ctx.stroke(); }
    const dim = ok ? '#fff' : 'rgba(255,255,255,.35)';
    text(num, x + w / 2, y + 22, 26, ok ? '#ffd84d' : dim);
    plain(title, x + w / 2, y + 48, title.length > 14 ? 9.5 : 11, dim, 'bold');
    if (!ok) plain('LOCKED', x + w / 2, y + 66, 10, 'rgba(255,255,255,.4)', 'bold');
    else if (stars >= 0) plain(starStr(stars), x + w / 2, y + 68, 15, stars ? '#ffd84d' : 'rgba(255,255,255,.5)');
    else plain(sub, x + w / 2, y + 68, 10, 'rgba(255,255,255,.8)');
    S.cardRects.push({ x, y, w, h });
  }
  const i = S.selIdx;
  if (i < LEVELS.length) { const lv = LEVELS[i]; plain(lv.name + ' — ' + (lv.mech.length ? lv.mech.map(k => MECH[k].desc).join(' · ') : lv.sub), W / 2, 508, 11.5, '#ffe9a8'); }
  plain('Back to Menu (Esc)', W / 2, H - 30, 12, 'rgba(255,255,255,.85)');
}
function drawReady() {
  overlay(0.4);
  const lvNum = S.kind === 'campaign' ? 'LEVEL ' + L.id : S.kind === 'endless' ? 'ENDLESS' : 'DAILY FLIGHT';
  text(lvNum, W / 2, 120, 22, '#ffd84d');
  text(L.name.toUpperCase(), W / 2, 160, L.name.length > 14 ? 30 : 38);
  plain(L.sub, W / 2, 198, 15, '#ffe9a8', 'italic');
  const mechs = [...L.mechs];
  let y = 240;
  if (mechs.length) { for (const k of mechs.slice(0, 5)) { plain(MECH[k].name + ' — ' + MECH[k].desc, W / 2, y, 12.5, '#dff4ff'); y += 20; } if (mechs.length > 5) { plain('+ ' + (mechs.length - 5) + ' more…', W / 2, y, 12, '#dff4ff'); y += 20; } }
  else if (!L.smart) { plain('Clear skies. Just you and the pipes.', W / 2, y, 12.5, '#dff4ff'); y += 20; }
  if (L.smart) { plain('Smart flamingo — J dodges the pipes for you for 3 s, then a long cooldown', W / 2, y, 12.5, '#ffb3d4'); y += 20; }
  y += 14;
  if (L.goal) text('GOAL: pass ' + L.goal + ' pipes', W / 2, y, 20); else text('Fly until you drop', W / 2, y, 20);
  y += 34;
  const pw = [...L.powers].map(p => p === 'dash' ? (L.smart ? 'J smart flamingo' : 'J dash') : 'K ghost').join('  +  ');
  plain('powers: ' + pw, W / 2, y, 13, '#ffb3d4');
  if (S.kind === 'campaign') { const st = save.stars[L.id] || 0; plain(starStr(st), W / 2, y + 26, 20, st ? '#ffd84d' : 'rgba(255,255,255,.5)'); }
  if (L.id === 1) { plain('SPACE / click / ↑ to flop.  J = flamingo dash (2× points).  K = ghost.', W / 2, 470, 12.5, '#fff'); }
  if (L.id === 10) { plain('In purple zones the ceiling is the floor. Flap carefully.', W / 2, 470, 12.5, '#fff'); }
  text('SPACE to fly', W / 2, 505 + Math.sin(S.t * 4) * 4, 20, 'rgba(255,255,255,' + (0.6 + Math.sin(S.t * 4) * 0.3) + ')');
  plain('Back (Esc)', W / 2, H - 30, 13, 'rgba(255,255,255,.9)');
}
function drawDead() {
  overlay(0.45);
  text('SPLAT', W / 2, 180, 60, '#ff6b6b');
  if (L.goal) { text(S.score + ' / ' + L.goal + ' pipes', W / 2, 250, 28); plain('● ' + S.coins + ' coins', W / 2, 284, 15, '#ffe066'); }
  else { text(S.kind === 'daily' ? (S.score + S.coins) + ' points' : S.score + ' pipes', W / 2, 250, 30); plain(S.kind === 'daily' ? S.score + ' pipes + ' + S.coins + ' coins' : '● ' + S.coins + ' coins', W / 2, 284, 15, '#ffe066'); if (S.newBest) text('NEW BEST!', W / 2, 318, 22, '#ffd84d'); }
  text('SPACE  retry', W / 2, 370 + Math.sin(S.t * 4) * 3, 18);
  plain('Back to Levels (Esc)', W / 2, 400, 13, 'rgba(255,255,255,.85)');
}
function drawClear() {
  overlay(0.45);
  const last = S.kind === 'campaign' && S.levelIdx === LEVELS.length - 1;
  text(last ? 'MIGRATION COMPLETE' : 'LEVEL CLEAR', W / 2, 150, last ? 34 : 46, '#7fffa0');
  const shown = Math.min(3, Math.floor(S.t * 2));
  const s = '★'.repeat(Math.min(S.stars, shown)) + '☆'.repeat(3 - Math.min(S.stars, shown));
  text(s, W / 2, 215, 48, '#ffd84d');
  plain('★ cleared', W / 2, 262, 13, '#fff');
  plain((S.coinPct >= 0.8 ? '★' : '☆') + ' coins ' + Math.round(S.coinPct * 100) + '% (need 80%)', W / 2, 282, 13, S.coinPct >= 0.8 ? '#fff' : 'rgba(255,255,255,.6)');
  const third = L.powers.size ? (!S.usedPower ? '★ no powers used' : '☆ powers used (try without J / K)') : (S.coinPct >= 1 ? '★ all coins' : '☆ all coins');
  plain(third, W / 2, 302, 13, third[0] === '★' ? '#fff' : 'rgba(255,255,255,.6)');
  if (S.newBest) text('NEW RECORD', W / 2, 335, 18, '#ffd84d');
  if (S.newSkin) plain('unlocked skin: ' + S.newSkin.name + '  (pick it on the menu)', W / 2, 358, 13, '#a8f1ff');
  if (last) plain('You flew every sky. Endless and Daily await.', W / 2, 400, 13, '#dff4ff');
  text(last ? 'SPACE  level select' : 'SPACE  next level', W / 2, 440 + Math.sin(S.t * 4) * 3, 18);
  plain('Retry (R)  ·  Back to Levels (Esc)', W / 2, 470, 12, 'rgba(255,255,255,.85)');
}

function draw() {
  ctx.save();
  if (S.shake > 0) ctx.translate((Math.random() - .5) * S.shake, (Math.random() - .5) * S.shake);
  drawWorld();
  drawHUD();
  if (S.screen === 'menu') drawMenu();
  else if (S.screen === 'levels') drawLevels();
  else if (S.screen === 'ready') drawReady();
  else if (S.screen === 'dead') drawDead();
  else if (S.screen === 'clear') drawClear();
  ctx.restore();
  if (S.hitFlash > 0) { ctx.fillStyle = 'rgba(255,255,255,' + S.hitFlash * 2 + ')'; ctx.fillRect(0, 0, W, H); }
  if (S.flash > 0) { ctx.fillStyle = 'rgba(255,255,255,' + S.flash * 4 + ')'; ctx.fillRect(0, 0, W, H); }
}

// =====================================================================
// Input
// =====================================================================
function menuSelect() {
  if (S.menuIdx === 0) goLevels();
  else if (S.menuIdx === 1) selectCard(14);
  else if (S.menuIdx === 2) selectCard(15);
  else cycleSkin(1);
}
function nextLevel() {
  if (S.kind !== 'campaign') return goLevels();
  if (S.levelIdx + 1 >= LEVELS.length) return goLevels();
  S.selIdx = S.levelIdx + 1; startRun('campaign', S.levelIdx + 1);
}
function onKey(e) {
  const k = e.key, sc = S.screen;
  const handled = [' ', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter', 'Escape', 'w', 'W', 's', 'S', 'j', 'J', 'k', 'K', 'r', 'R'];
  if (!handled.includes(k)) return;
  e.preventDefault(); if (e.repeat) return;
  if (sc === 'menu') {
    if (k === 'ArrowUp' || k === 'w' || k === 'W') { S.menuIdx = (S.menuIdx + 3) % 4; SFX.ui(); }
    else if (k === 'ArrowDown' || k === 's' || k === 'S') { S.menuIdx = (S.menuIdx + 1) % 4; SFX.ui(); }
    else if (k === 'ArrowLeft') { if (S.menuIdx === 3) cycleSkin(-1); }
    else if (k === 'ArrowRight') { if (S.menuIdx === 3) cycleSkin(1); }
    else if (k === 'Enter' || k === ' ') menuSelect();
    return;
  }
  if (sc === 'levels') {
    if (k === 'ArrowLeft') S.selIdx = Math.max(0, S.selIdx - 1);
    else if (k === 'ArrowRight') S.selIdx = Math.min(15, S.selIdx + 1);
    else if (k === 'ArrowUp' || k === 'w' || k === 'W') S.selIdx = Math.max(0, S.selIdx - 4);
    else if (k === 'ArrowDown' || k === 's' || k === 'S') S.selIdx = Math.min(15, S.selIdx + 4);
    else if (k === 'Enter' || k === ' ') return selectCard(S.selIdx);
    else if (k === 'Escape') return goMenu();
    SFX.ui(); return;
  }
  if (k === 'Escape') return goLevels();
  if (sc === 'ready') { if (k === ' ' || k === 'ArrowUp' || k === 'w' || k === 'W' || k === 'Enter') beginPlay(); return; }
  if (sc === 'dead') { if (k === ' ' || k === 'r' || k === 'R' || k === 'Enter' || k === 'ArrowUp') retry(); return; }
  if (sc === 'clear') { if (k === ' ' || k === 'Enter') nextLevel(); else if (k === 'r' || k === 'R') retry(); return; }
  // play
  if (k === ' ' || k === 'ArrowUp' || k === 'w' || k === 'W') flap();
  else if (k === 'ArrowDown' || k === 's' || k === 'S') dive();
  else if (k === 'j' || k === 'J') useDash();
  else if (k === 'k' || k === 'K') useGhost();
  else if (k === 'r' || k === 'R') retry();
}
function canvasPoint(e) { const r = canvas.getBoundingClientRect(); return { x: (e.clientX - r.left) * W / r.width, y: (e.clientY - r.top) * H / r.height }; }
function inRect(p, r) { return p.x >= r.x && p.x <= r.x + r.w && p.y >= r.y && p.y <= r.y + r.h; }

let last = performance.now(), running = true;
function frame(now) {
  const dt = Math.min(0.05, (now - last) / 1000); last = now;
  if (running && ctx) { update(dt); draw(); }
  requestAnimationFrame(frame);
}

function initGame() {
  canvas = document.getElementById('c');
  if (!canvas) return;
  ctx = canvas.getContext('2d');
  window.addEventListener('keydown', onKey);
  canvas.addEventListener('pointerdown', e => {
    e.preventDefault();
    if (AC && AC.state === 'suspended') { AC.resume().catch(() => {}); }
    const p = canvasPoint(e), sc = S.screen;
    if (sc === 'menu') { const i = S.menuRects.findIndex(r => inRect(p, r)); if (i >= 0) { S.menuIdx = i; menuSelect(); } return; }
    if (sc === 'levels') {
      if (p.y >= H - 55) { goMenu(); return; }
      const i = S.cardRects.findIndex(r => inRect(p, r)); if (i >= 0) selectCard(i); return;
    }
    if (sc === 'ready') {
      if (p.y >= H - 60) { goLevels(); return; }
      return beginPlay();
    }
    if (sc === 'dead') {
      if ((p.y >= 385 && p.y <= 430) || p.y >= H - 55) { goLevels(); return; }
      return retry();
    }
    if (sc === 'clear') {
      if ((p.y >= 450 && p.y <= 495) || p.y >= H - 55) { goLevels(); return; }
      return nextLevel();
    }
    flap();
  });
  canvas.addEventListener('touchstart', e => {
    if (AC && AC.state === 'suspended') { AC.resume().catch(() => {}); }
    if (S.screen !== 'play') return;
    if (e.touches.length === 2) useDash();
    else if (e.touches.length >= 3) useGhost();
  }, { passive: true });

  last = performance.now();
  requestAnimationFrame(frame);
  document.addEventListener('visibilitychange', () => { last = performance.now(); });

  // Sync existing progress to leaderboard on load
  setTimeout(() => {
    try {
      if (totalStars() > 0) submitLeaderboard('campaign_stars', totalStars());
      if (save && save.endlessBest > 0) submitLeaderboard('endless_score', save.endlessBest);
    } catch (_) {}
  }, 1000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initGame);
} else {
  initGame();
}

window.__floppy = {
  T, LEVELS, MECH, SKINS, SCENES, SCENE_ORDER, get S() { return S; }, get L() { return L; }, get save() { return save; },
  get soundMuted() { return soundMuted; },
  set soundMuted(v) { soundMuted = !!v; },
  toggleMute() { soundMuted = !soundMuted; return soundMuted; },
  update, draw, startRun, beginPlay, flap, useDash, useGhost, retry, selectCard, goLevels, goMenu, persist,
  step(dt, n = 1) { for (let i = 0; i < n; i++) update(dt); draw(); return S; },
  pause(p = true) { running = !p; },
  wipe() { save = blankSave(); persist(); },
  syncScores: syncAllScores,
  submitScore: submitLeaderboard
};
})();