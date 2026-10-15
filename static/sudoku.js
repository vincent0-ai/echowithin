/* Sudoku Together — fresh boards via /api/games/sudoku/new, solo + co-op. No dependencies. */
(function () {
  'use strict';
  var state = {
    mode: 'solo', puzzle: null, solution: null, grid: new Array(81).fill(0),
    givens: new Array(81).fill(false), selected: -1, mistakes: 0, over: false,
    seconds: 0, timerId: null, difficulty: 'medium', source: '',
    roomId: null, partnerCursor: -1, guestToken: null
  };
  var gridEl = document.getElementById('sudoku-grid');
  var padEl = document.getElementById('sudoku-pad');
  var socket = null;
  try { if (typeof io !== 'undefined') socket = io({ transports: ['websocket', 'polling'] }); } catch (e) { socket = null; }

  var cells = [];
  for (var i = 0; i < 81; i++) {
    (function (idx) {
      var d = document.createElement('div');
      d.className = 'sudoku-cell'; d.setAttribute('role', 'gridcell');
      d.setAttribute('tabindex', '0');
      d.addEventListener('click', function () { select(idx); });
      d.addEventListener('keydown', function (e) {
        if (e.key >= '1' && e.key <= '9') enterNumber(parseInt(e.key, 10));
        else if (e.key === 'Backspace' || e.key === 'Delete' || e.key === '0') enterNumber(0);
      });
      gridEl.appendChild(d); cells.push(d);
    })(i);
  }
  for (var n = 1; n <= 9; n++) {
    (function (v) {
      var b = document.createElement('button');
      b.type = 'button'; b.textContent = v;
      b.addEventListener('click', function () { enterNumber(v); });
      padEl.appendChild(b);
    })(n);
  }

  function fmt(s) { return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }

  function localFallback(seed) {
    var rng = seed ? function () { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; } : Math.random;
    var g = Array.from({ length: 9 }, () => new Array(9).fill(0));
    function valid(r, c, v) {
      for (var i = 0; i < 9; i++) { if (g[r][i] === v || g[i][c] === v) return false; }
      var br = 3 * Math.floor(r / 3), bc = 3 * Math.floor(c / 3);
      for (var i = 0; i < 3; i++) for (var j = 0; j < 3; j++) if (g[br + i][bc + j] === v) return false;
      return true;
    }
    function fill(p) {
      if (p === 81) return true;
      var r = Math.floor(p / 9), c = p % 9;
      var nums = [1, 2, 3, 4, 5, 6, 7, 8, 9].sort(() => rng() - 0.5);
      for (var k = 0; k < 9; k++) {
        if (valid(r, c, nums[k])) { g[r][c] = nums[k]; if (fill(p + 1)) return true; g[r][c] = 0; }
      }
      return false;
    }
    fill(0);
    var holes = state.difficulty === 'easy' ? 36 : (state.difficulty === 'hard' ? 50 : 44);
    var order = Array.from({ length: 81 }, (_, i) => i).sort(() => rng() - 0.5);
    var puzzle = g.map(r => r.slice());
    order.slice(0, holes).forEach(function (i) { puzzle[Math.floor(i / 9)][i % 9] = 0; });
    return { puzzle: puzzle, solution: g, difficulty: state.difficulty };
  }

  async function loadPuzzle() {
    setStatus('Loading a fresh puzzle…');
    var data = null;
    try {
      var res = await fetch('/api/games/sudoku/new?difficulty=' + encodeURIComponent(state.difficulty));
      var payload = await res.json();
      if (payload && payload.success && payload.puzzle) data = payload;
    } catch (e) { data = null; }
    if (!data) {
      var fb = localFallback(Date.now() % 2147483647);
      data = { puzzle: fb.puzzle, solution: fb.solution, difficulty: fb.difficulty, source: 'local' };
    }
    applyPuzzle(data);
  }

  function applyPuzzle(data) {
    state.puzzle = data.puzzle; state.solution = data.solution;
    state.difficulty = (data.difficulty || state.difficulty).toLowerCase();
    state.source = data.source || '';
    state.grid = []; state.givens = [];
    for (var r = 0; r < 9; r++) for (var c = 0; c < 9; c++) {
      var v = (data.puzzle[r] && data.puzzle[r][c]) || 0;
      state.grid.push(v); state.givens.push(v !== 0);
    }
    state.selected = -1; state.mistakes = 0; state.over = false; state.seconds = 0;
    document.getElementById('sudoku-mistakes').textContent = '0';
    document.getElementById('sudoku-diff-badge').textContent = state.difficulty.charAt(0).toUpperCase() + state.difficulty.slice(1);
    hideResult(); render(); startTimer();
    setStatus(state.mode === 'coop' ? 'Shared puzzle ready.' : 'Fresh puzzle ready.');
  }

  function render() {
    for (var i = 0; i < 81; i++) {
      var el = cells[i], v = state.grid[i];
      el.textContent = v === 0 ? '' : v;
      el.className = 'sudoku-cell' + (state.givens[i] ? ' given' : (v === 0 ? '' : ' entry'));
      if (i === state.selected) el.classList.add('selected');
      if (i === state.partnerCursor) el.classList.add('partner');
    }
    if (state.selected >= 0) {
      var sr = Math.floor(state.selected / 9), sc = state.selected % 9, sv = state.grid[state.selected];
      for (var j = 0; j < 81; j++) {
        var r = Math.floor(j / 9), c = j % 9;
        if (r === sr || c === sc || (Math.floor(r / 3) === Math.floor(sr / 3) && Math.floor(c / 3) === Math.floor(sc / 3))) cells[j].classList.add('related');
        if (sv !== 0 && state.grid[j] === sv && j !== state.selected) cells[j].classList.add('related');
      }
    }
  }

  function select(idx) {
    if (state.over) return;
    state.selected = idx; render();
    if (state.mode === 'coop' && socket && state.roomId) {
      socket.emit('sudoku_cursor_move', { room_id: state.roomId, r: Math.floor(idx / 9), c: idx % 9 });
    }
  }

  function enterNumber(v) {
    if (state.over || state.selected < 0 || state.givens[state.selected]) return;
    var idx = state.selected;
    if (v === 0) {
      state.grid[idx] = 0; render(); pushCell(idx, 0); return;
    }
    if (state.solution && v !== state.solution[Math.floor(idx / 9)][idx % 9]) {
      state.mistakes++;
      document.getElementById('sudoku-mistakes').textContent = state.mistakes;
      cells[idx].classList.add('error');
      setTimeout(render, 450);
      if (state.mistakes >= 3) { state.over = true; showResult('OUT OF LIVES', 'Three mistakes. Try a new puzzle.'); }
      return;
    }
    state.grid[idx] = v; render(); pushCell(idx, v);
    if (state.grid.every(function (x, i) { return x !== 0 && (!state.solution || x === state.solution[Math.floor(i / 9)][i % 9]); })) {
      state.over = true; clearInterval(state.timerId);
      submitSolve();
      showResult(state.mode === 'coop' ? 'SOLVED TOGETHER!' : 'SOLVED!', 'Completed in ' + fmt(state.seconds) + '.');
      if (state.mode === 'coop' && socket && state.roomId) socket.emit('sudoku_solved', { room_id: state.roomId });
    }
  }

  function pushCell(idx, v) {
    if (state.mode === 'coop' && socket && state.roomId) {
      socket.emit('sudoku_cell_update', { room_id: state.roomId, r: Math.floor(idx / 9), c: idx % 9, v: v });
    }
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

  function timeScore() {
    var mult = state.difficulty === 'hard' ? 3 : (state.difficulty === 'easy' ? 1 : 2);
    return Math.max(1, Math.min(10000000, (Math.max(1, 3600 - state.seconds)) * mult));
  }

  function submitSolve() {
    var payload = { game: 'sudoku', category: 'ranked_score', score: timeScore(), metadata: { mode: state.mode, difficulty: state.difficulty }, guest_token: getGuestToken(), username: 'Guest' };
    fetch('/api/games/leaderboard/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).catch(function () {});
  }

  function startTimer() {
    clearInterval(state.timerId);
    document.getElementById('sudoku-time').textContent = '0:00';
    state.timerId = setInterval(function () {
      if (state.over) return;
      state.seconds++;
      document.getElementById('sudoku-time').textContent = fmt(state.seconds);
    }, 1000);
  }

  function setStatus(t) {
    var el = document.getElementById('room-status');
    if (el && state.mode === 'coop') el.textContent = t;
  }

  function showResult(title, sub) {
    document.getElementById('sudoku-result-title').textContent = title;
    document.getElementById('sudoku-result-subtitle').textContent = sub;
    document.getElementById('sudoku-result-overlay').style.display = 'flex';
  }
  function hideResult() { document.getElementById('sudoku-result-overlay').style.display = 'none'; }

  function setMode(m) {
    state.mode = m;
    document.getElementById('tab-solo').className = 'ew-btn' + (m === 'solo' ? '' : '--outline') + ' ew-btn--sm mode-tab';
    document.getElementById('tab-coop').className = 'ew-btn' + (m === 'coop' ? '' : '--outline') + ' ew-btn--sm mode-tab';
    document.getElementById('online-panel').style.display = m === 'coop' ? 'block' : 'none';
    document.getElementById('sudoku-partner').style.display = m === 'coop' ? 'inline-flex' : 'none';
    if (m === 'coop') {
      var r = new URLSearchParams(window.location.search).get('room');
      if (r) joinRoom(r.trim().slice(0, 32));
      else setStatus('Create or join a room to solve together.');
    }
    loadPuzzle();
  }

  function joinRoom(id) {
    state.roomId = id;
    document.getElementById('room-code-input').value = id;
    if (socket) socket.emit('join_sudoku_room', { room_id: id });
    setStatus('Joined room ' + id + '.');
  }

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-coop').addEventListener('click', function () { setMode('coop'); });
  document.getElementById('sudoku-new-btn').addEventListener('click', function () {
    if (state.mode === 'coop' && socket && state.roomId) socket.emit('sudoku_restart', { room_id: state.roomId });
    loadPuzzle();
  });
  document.getElementById('sudoku-again-btn').addEventListener('click', function () {
    if (state.mode === 'coop' && socket && state.roomId) socket.emit('sudoku_restart', { room_id: state.roomId });
    loadPuzzle();
  });
  document.getElementById('sudoku-erase-btn').addEventListener('click', function () { enterNumber(0); });
  document.getElementById('join-room-btn').addEventListener('click', function () {
    var v = (document.getElementById('room-code-input').value || '').trim();
    if (v) joinRoom(v);
  });
  document.getElementById('create-room-btn').addEventListener('click', function () {
    joinRoom('sudoku_' + Math.random().toString(36).slice(2, 8));
  });
  document.getElementById('copy-link-btn').addEventListener('click', function () {
    var url = window.location.origin + '/games/sudoku?room=' + encodeURIComponent(state.roomId || document.getElementById('room-code-input').value || '');
    try { navigator.clipboard.writeText(url); setStatus('Link copied.'); } catch (e) { setStatus(url); }
  });

  if (socket) {
    socket.on('sudoku_room_joined', function (d) {
      if (d.partner_name) {
        document.getElementById('sudoku-partner-name').textContent = d.partner_name;
        setStatus('Partner joined. Solving together.');
      }
    });
    socket.on('sudoku_cell_update', function (d) {
      var idx = d.r * 9 + d.c;
      if (!state.givens[idx] && !state.over) { state.grid[idx] = d.v; render(); }
    });
    socket.on('sudoku_cursor_move', function (d) {
      state.partnerCursor = d.r * 9 + d.c; render();
    });
    socket.on('sudoku_restarted', function () { loadPuzzle(); });
    socket.on('sudoku_solved', function () {
      if (!state.over) submitSolve();
      state.over = true; clearInterval(state.timerId);
      showResult('SOLVED TOGETHER!', 'Partner completed the puzzle.');
    });
    socket.on('sudoku_partner_left', function () { setStatus('Partner left.'); });
  }

  window.__sudoku = {
    getSocketId: function () { return socket ? socket.id : null; }
  };

  window.addEventListener('beforeunload', function () {
    if (socket && state.roomId) socket.emit('leave_sudoku_room', { room_id: state.roomId });
  });
  setMode(new URLSearchParams(window.location.search).get('room') ? 'coop' : 'solo');
})();
