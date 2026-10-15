/* Sudoku Together — fresh boards via /api/games/sudoku/new, solo + co-op. No dependencies. */
(function () {
  'use strict';
  var state = {
    mode: 'solo', puzzle: null, solution: null, grid: new Array(81).fill(0),
    givens: new Array(81).fill(false), selected: -1, mistakes: 0, over: false,
    seconds: 0, timerId: null, difficulty: 'medium', source: '',
    roomId: null, partnerCursor: -1, guestToken: null,
    pendingValue: 0, wrongIdx: -1, wrongVal: 0, wrongTimer: null
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
  var padBtns = [];
  for (var n = 1; n <= 9; n++) {
    (function (v) {
      var b = document.createElement('button');
      b.type = 'button'; b.textContent = v; b.dataset.value = v;
      b.addEventListener('click', function () { padTap(v); });
      padEl.appendChild(b); padBtns.push(b);
    })(n);
  }

  function paintPad() {
    for (var i = 0; i < padBtns.length; i++) {
      var on = state.pendingValue === parseInt(padBtns[i].dataset.value, 10);
      padBtns[i].classList.toggle('active', on);
      padBtns[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }
  }

  // Number pad: works with a selected cell AND standalone (number-first paint mode).
  function padTap(v) {
    if (state.over) return;
    if (state.selected >= 0 && !state.givens[state.selected]) {
      enterNumber(v);
      state.pendingValue = v; paintPad();
    } else {
      state.pendingValue = (state.pendingValue === v) ? 0 : v;
      paintPad();
    }
  }

  function fmt(s) { return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); }

  function localFallback(seed) {
    var rng = seed ? function () { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; } : Math.random;
    var g = Array.from({ length: 9 }, () => new Array(9).fill(0));
    function valid(bd, r, c, v) {
      for (var i = 0; i < 9; i++) { if (bd[r][i] === v || bd[i][c] === v) return false; }
      var br = 3 * Math.floor(r / 3), bc = 3 * Math.floor(c / 3);
      for (var i = 0; i < 3; i++) for (var j = 0; j < 3; j++) if (bd[br + i][bc + j] === v) return false;
      return true;
    }
    function fill(p) {
      if (p === 81) return true;
      var r = Math.floor(p / 9), c = p % 9;
      var nums = [1, 2, 3, 4, 5, 6, 7, 8, 9].sort(() => rng() - 0.5);
      for (var k = 0; k < 9; k++) {
        if (valid(g, r, c, nums[k])) { g[r][c] = nums[k]; if (fill(p + 1)) return true; g[r][c] = 0; }
      }
      return false;
    }
    // Count completions, stopping early at 2. Operates on a copy.
    function countSolutions(board) {
      var bd = board.map(function (row) { return row.slice(); });
      var count = 0;
      function solve(pos) {
        if (count >= 2) return;
        while (pos < 81 && bd[Math.floor(pos / 9)][pos % 9]) pos++;
        if (pos === 81) { count++; return; }
        var r = Math.floor(pos / 9), c = pos % 9;
        for (var n = 1; n <= 9; n++) {
          if (valid(bd, r, c, n)) {
            bd[r][c] = n; solve(pos + 1); bd[r][c] = 0;
            if (count >= 2) return;
          }
        }
      }
      solve(0);
      return count;
    }
    fill(0);
    // Greedy dig with a time budget: keep a hole only while the board stays
    // uniquely solvable. Fewer holes just means an easier (but always fair) board.
    var target = state.difficulty === 'easy' ? 36 : (state.difficulty === 'hard' ? 50 : 44);
    var deadline = Date.now() + 1500;
    var order = Array.from({ length: 81 }, (_, i) => i).sort(() => rng() - 0.5);
    var puzzle = g.map(r => r.slice());
    var holes = 0;
    for (var q = 0; q < order.length && holes < target; q++) {
      if (Date.now() > deadline) break;
      var i = order[q], rr = Math.floor(i / 9), cc = i % 9;
      var backup = puzzle[rr][cc];
      puzzle[rr][cc] = 0;
      if (countSolutions(puzzle) === 1) holes++;
      else puzzle[rr][cc] = backup;
    }
    return { puzzle: puzzle, solution: g, difficulty: state.difficulty };
  }

  async function loadPuzzle() {
    setStatus('Loading…');
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
    // Co-op: offer my board as the room's shared puzzle (server keeps the first).
    if (state.mode === 'coop' && socket && state.roomId && state.puzzle && state.solution) {
      socket.emit('sudoku_puzzle_share', { room_id: state.roomId, puzzle: state.puzzle,
        solution: state.solution, difficulty: state.difficulty });
    }
  }

  function applyPuzzle(data, fromShare) {
    state.puzzle = data.puzzle; state.solution = data.solution;
    state.difficulty = (data.difficulty || state.difficulty).toLowerCase();
    state.source = data.source || '';
    state.grid = []; state.givens = [];
    for (var r = 0; r < 9; r++) for (var c = 0; c < 9; c++) {
      var v = (data.puzzle[r] && data.puzzle[r][c]) || 0;
      state.grid.push(v); state.givens.push(v !== 0);
    }
    state.selected = -1; state.mistakes = 0; state.over = false; state.seconds = 0;
    state.pendingValue = 0; state.wrongIdx = -1; state.partnerCursor = -1;
    if (state.wrongTimer) { clearTimeout(state.wrongTimer); state.wrongTimer = null; }
    paintPad();
    document.getElementById('sudoku-mistakes').textContent = '0';
    document.getElementById('sudoku-diff-badge').textContent = state.difficulty.charAt(0).toUpperCase() + state.difficulty.slice(1);
    hideResult(); render(); startTimer();
    setStatus('Ready.');
  }

  function render() {
    for (var i = 0; i < 81; i++) {
      var el = cells[i], v = state.grid[i];
      var showWrong = (i === state.wrongIdx);
      el.textContent = showWrong ? state.wrongVal : (v === 0 ? '' : v);
      el.className = 'sudoku-cell' + (state.givens[i] ? ' given' : (showWrong ? ' error' : (v === 0 ? '' : ' entry')));
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
    state.selected = idx;
    // Number-first paint mode: tapping a cell applies the armed digit.
    if (state.pendingValue && !state.givens[idx]) {
      enterNumber(state.pendingValue);
      if (state.mode === 'coop' && socket && state.roomId) {
        socket.emit('sudoku_cursor_move', { room_id: state.roomId, r: Math.floor(idx / 9), c: idx % 9 });
      }
      return;
    }
    render();
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
      // Show the rejected digit in red briefly so the tap is visibly answered.
      state.wrongIdx = idx; state.wrongVal = v; render();
      if (state.wrongTimer) clearTimeout(state.wrongTimer);
      state.wrongTimer = setTimeout(function () {
        state.wrongIdx = -1; state.wrongTimer = null;
        if (!state.over) render();
      }, 650);
      if (state.mistakes >= 3) { state.over = true; state.pendingValue = 0; paintPad(); showResult('OUT OF LIVES', 'Three mistakes. Try a new puzzle.'); }
      return;
    }
    state.grid[idx] = v; render(); pushCell(idx, v);
    if (state.grid.every(function (x, i) { return x !== 0 && (!state.solution || x === state.solution[Math.floor(i / 9)][i % 9]); })) {
      state.over = true; clearInterval(state.timerId);
      state.pendingValue = 0; paintPad();
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

  function isAuthed() {
    return !!(document.body && document.body.dataset && document.body.dataset.userLoggedIn === 'true');
  }

  // Solo needs an account; co-op invite play stays open to guests.
  function applySoloGate() {
    var locked = (state.mode === 'solo' && !isAuthed());
    var gate = document.getElementById('solo-gate');
    if (gate) gate.style.display = locked ? 'block' : 'none';
    var stage = document.querySelector('.sudoku-stage');
    if (stage) stage.style.display = locked ? 'none' : '';
    return locked;
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
      else setStatus('Create or join a room.');
    }
    if (applySoloGate()) return;
    loadPuzzle();
  }

  function joinRoom(id) {
    state.roomId = id;
    document.getElementById('room-code-input').value = id;
    if (socket) socket.emit('join_sudoku_room', { room_id: id, bond_id: new URLSearchParams(window.location.search).get('bond_id') || undefined });
    setStatus('Joined room ' + id + '.');
  }

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-coop').addEventListener('click', function () { setMode('coop'); });
  var gateDuel = document.getElementById('solo-gate-duel');
  if (gateDuel) gateDuel.addEventListener('click', function () { document.getElementById('tab-coop').click(); });
  document.getElementById('sudoku-new-btn').addEventListener('click', function () {
    // Co-op: only the restart initiator loads — the relay tells us if that's us.
    if (state.mode === 'coop' && socket && state.roomId) socket.emit('sudoku_restart', { room_id: state.roomId });
    else loadPuzzle();
  });
  document.getElementById('sudoku-again-btn').addEventListener('click', function () {
    if (state.mode === 'coop' && socket && state.roomId) socket.emit('sudoku_restart', { room_id: state.roomId });
    else loadPuzzle();
  });
  document.getElementById('sudoku-erase-btn').addEventListener('click', function () {
    state.pendingValue = 0; paintPad(); enterNumber(0);
  });
  document.getElementById('join-room-btn').addEventListener('click', function () {
    var v = (document.getElementById('room-code-input').value || '').trim();
    if (v) joinRoom(v);
  });
  var createBtn = document.getElementById('create-room-btn');
  if (createBtn) createBtn.addEventListener('click', function () {
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
        setStatus('Partner joined.');
      } else if (d.has_puzzle) {
        setStatus('Loading…');
      }
    });
    socket.on('sudoku_puzzle', function (d) {
      if (!d || !d.puzzle || !d.solution) return;
      applyPuzzle(d, true);
    });
    socket.on('sudoku_cell_update', function (d) {
      var idx = d.r * 9 + d.c;
      if (!state.givens[idx] && !state.over) { state.grid[idx] = d.v; render(); }
    });
    socket.on('sudoku_cursor_move', function (d) {
      state.partnerCursor = d.r * 9 + d.c; render();
    });
    socket.on('sudoku_restarted', function (d) {
      // Only the restart initiator loads a fresh board (then shares it);
      // the partner waits for the shared board instead of loading a different one.
      var amRestarter = !d || !d.restarter || (socket && d.restarter === socket.id);
      if (amRestarter) loadPuzzle();
      else setStatus('New puzzle…');
    });
    socket.on('sudoku_solved', function () {
      if (!state.over) submitSolve();
      state.over = true; clearInterval(state.timerId);
      showResult('SOLVED TOGETHER!', 'Partner completed the puzzle.');
    });
    socket.on('sudoku_partner_left', function () {
      state.partnerCursor = -1;
      document.getElementById('sudoku-partner-name').textContent = '–';
      render(); setStatus('Partner left.');
    });
  }

  window.__sudoku = {
    getSocketId: function () { return socket ? socket.id : null; }
  };

  window.addEventListener('beforeunload', function () {
    if (socket && state.roomId) socket.emit('leave_sudoku_room', { room_id: state.roomId });
  });
  setMode(new URLSearchParams(window.location.search).get('room') ? 'coop' : 'solo');
})();
