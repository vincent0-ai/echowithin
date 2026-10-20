/* Sudoku Together — fresh boards via /api/games/sudoku/new, solo + co-op. No dependencies. */
(function () {
  'use strict';
  var state = {
    mode: 'solo', puzzle: null, solution: null, grid: new Array(81).fill(0),
    givens: new Array(81).fill(false), selected: -1, mistakes: 0, over: false,
    seconds: 0, timerId: null, difficulty: 'medium', source: '',
    roomId: null, partnerCursor: -1, guestToken: null, isHost: true,
    wrongCells: {}, hasShared: false, roomGrid: null, seatToken: null,
    entries: 0
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
      b.type = 'button'; b.textContent = v; b.dataset.value = v;
      b.addEventListener('click', function () { padTap(v); });
      padEl.appendChild(b);
    })(n);
  }

  // Two-step input: tap a cell to select it, then tap a digit. The pad never
  // stays armed, so exploring the board can't drop numbers by accident.
  function padTap(v) {
    if (state.over) return;
    if (state.selected < 0 || state.givens[state.selected]) return;
    enterNumber(v);
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
    // Count completions, stopping early at 2 and at the shared deadline so a
    // slow phone never freezes on a fallback board. Aborted => treat as
    // ambiguous and keep the given cell.
    function countSolutions(board, deadline) {
      var bd = board.map(function (row) { return row.slice(); });
      var count = 0, nodes = 0, aborted = false;
      function solve(pos) {
        if (count >= 2 || aborted) return;
        nodes += 1;
        if ((nodes & 511) === 0 && Date.now() > deadline) { aborted = true; return; }
        while (pos < 81 && bd[Math.floor(pos / 9)][pos % 9]) pos++;
        if (pos === 81) { count++; return; }
        var r = Math.floor(pos / 9), c = pos % 9;
        for (var n = 1; n <= 9; n++) {
          if (valid(bd, r, c, n)) {
            bd[r][c] = n; solve(pos + 1); bd[r][c] = 0;
            if (count >= 2 || aborted) return;
          }
        }
      }
      solve(0);
      return aborted ? 2 : count;
    }
    fill(0);
    // Greedy dig with a time budget: keep a hole only while the board stays
    // uniquely solvable. Fewer holes just means an easier (but always fair) board.
    var target = state.difficulty === 'easy' ? 36 : (state.difficulty === 'hard' ? 50 : 44);
    var deadline = Date.now() + 1200;
    var order = Array.from({ length: 81 }, (_, i) => i).sort(() => rng() - 0.5);
    var puzzle = g.map(r => r.slice());
    var holes = 0;
    for (var q = 0; q < order.length && holes < target; q++) {
      if (Date.now() > deadline) break;
      var i = order[q], rr = Math.floor(i / 9), cc = i % 9;
      var backup = puzzle[rr][cc];
      puzzle[rr][cc] = 0;
      if (countSolutions(puzzle, deadline) === 1) holes++;
      else puzzle[rr][cc] = backup;
    }
    return { puzzle: puzzle, solution: g, difficulty: state.difficulty };
  }

  function usableBoard(data) {
    if (!data || !Array.isArray(data.puzzle) || !Array.isArray(data.solution)) return false;
    if (data.puzzle.length !== 9 || data.solution.length !== 9) return false;
    for (var r = 0; r < 9; r++) {
      if (!Array.isArray(data.puzzle[r]) || data.puzzle[r].length !== 9) return false;
      if (!Array.isArray(data.solution[r]) || data.solution[r].length !== 9) return false;
    }
    return true;
  }

  var loadSeq = 0;
  async function loadPuzzle() {
    var seq = ++loadSeq;
    setStatus('Loading…');
    var data = null;
    var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 12000) : null;
    try {
      var res = await fetch('/api/games/sudoku/new?difficulty=' + encodeURIComponent(state.difficulty),
        ctrl ? { signal: ctrl.signal, cache: 'no-store' } : { cache: 'no-store' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var payload = await res.json();
      if (payload && payload.success && usableBoard(payload)) data = payload;
    } catch (e) { data = null; }
    if (timer) clearTimeout(timer);
    // Ignore stale responses (rapid New Puzzle taps) and never stomp a board
    // the partner just shared with us.
    if (seq !== loadSeq) return;
    if (state.mode === 'coop' && state.hasShared) return;
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

  function sameBoard(a, b) {
    if (!a || !b) return false;
    for (var r = 0; r < 9; r++) for (var c = 0; c < 9; c++) {
      if (((a[r] && a[r][c]) || 0) !== ((b[r] && b[r][c]) || 0)) return false;
    }
    return true;
  }

  // Restore the room's entries (late join or reconnect). The room is
  // authoritative for every non-given cell, including cleared ones.
  function mergeRoomGrid() {
    if (!state.roomGrid) return;
    for (var i = 0; i < 81; i++) {
      if (state.givens[i]) continue;
      var v = state.roomGrid[i] || 0;
      state.grid[i] = v;
      if (v) delete state.wrongCells[i];
    }
    state.roomGrid = null;
    syncMistakes();
    render();
  }

  function applyPuzzle(data, fromShare) {
    state.puzzle = data.puzzle; state.solution = data.solution;
    var requested = String(data.difficulty || '').toLowerCase();
    if (requested === 'easy' || requested === 'medium' || requested === 'hard') state.difficulty = requested;
    state.source = data.source || '';
    state.grid = []; state.givens = [];
    for (var r = 0; r < 9; r++) for (var c = 0; c < 9; c++) {
      var v = (data.puzzle[r] && data.puzzle[r][c]) || 0;
      state.grid.push(v); state.givens.push(v !== 0);
    }
    state.selected = -1; state.mistakes = 0; state.over = false; state.seconds = 0;
    state.wrongCells = {}; state.partnerCursor = -1; state.entries = 0;
    document.getElementById('sudoku-mistakes').textContent = '0';
    document.getElementById('sudoku-diff-badge').textContent = state.difficulty.charAt(0).toUpperCase() + state.difficulty.slice(1);
    var diffSel = document.getElementById('sudoku-diff-select');
    if (diffSel) diffSel.value = state.difficulty;
    hideResult(); render();
    if (fromShare) mergeRoomGrid();
    startTimer();
    setStatus(fromShare ? 'Partner board.' : 'Ready.');
  }

  function render() {
    for (var i = 0; i < 81; i++) {
      var el = cells[i], v = state.grid[i];
      var wrong = state.wrongCells[i];
      el.textContent = wrong ? wrong : (v === 0 ? '' : v);
      el.className = 'sudoku-cell' + (state.givens[i] ? ' given' : (wrong ? ' error' : (v === 0 ? '' : ' entry')));
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
    render();
    if (state.mode === 'coop' && socket && state.roomId) {
      socket.emit('sudoku_cursor_move', { room_id: state.roomId, r: Math.floor(idx / 9), c: idx % 9 });
    }
  }

  // Mistakes live on cells: a wrong digit stays red on that cell until it is
  // corrected or erased, and the count is simply how many cells are wrong now.
  function syncMistakes() {
    state.mistakes = Object.keys(state.wrongCells).length;
    var el = document.getElementById('sudoku-mistakes');
    if (el) el.textContent = state.mistakes;
  }

  function enterNumber(v) {
    if (state.over || state.selected < 0 || state.givens[state.selected]) return;
    var idx = state.selected;
    if (v === 0) {
      delete state.wrongCells[idx];
      state.grid[idx] = 0; syncMistakes(); render(); pushCell(idx, 0); return;
    }
    if (state.solution && v !== state.solution[Math.floor(idx / 9)][idx % 9]) {
      state.wrongCells[idx] = v;
      syncMistakes(); render();
      return;
    }
    delete state.wrongCells[idx];
    state.grid[idx] = v; state.entries++; syncMistakes(); render(); pushCell(idx, v);
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
    fetch('/api/games/leaderboard/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function () {
        if (typeof window.fetchLeaderboard === 'function') window.fetchLeaderboard();
      })
      .catch(function () {});
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
    } else if (state.roomId && socket) {
      socket.emit('leave_sudoku_room', { room_id: state.roomId });
      state.roomId = null; state.roomGrid = null; state.hasShared = false;
      state.partnerCursor = -1;
      document.getElementById('sudoku-partner-name').textContent = '–';
    }
    if (applySoloGate()) return;
    loadPuzzle();
  }

  // Per-tab room token: survives a refresh (sessionStorage) and gives each
  // tab its own seat, so a second tab cannot hijack the first one's place.
  function clientToken() {
    if (state.seatToken) return state.seatToken;
    var key = 'ew_sudoku_seat_' + String(state.roomId || '');
    try {
      var saved = sessionStorage.getItem(key);
      if (!saved) {
        saved = 's_' + Math.random().toString(36).slice(2, 14);
        sessionStorage.setItem(key, saved);
      }
      state.seatToken = saved;
    } catch (e) {
      state.seatToken = 's_' + Math.random().toString(36).slice(2, 14);
    }
    return state.seatToken;
  }

  var bondId = new URLSearchParams(window.location.search).get('bond_id') || undefined;

  function joinRoom(id) {
    if (state.roomId && state.roomId !== id && socket) {
      socket.emit('leave_sudoku_room', { room_id: state.roomId });
    }
    if (state.roomId !== id) state.seatToken = null;
    state.roomId = id;
    state.roomGrid = null;
    state.hasShared = false;
    state.partnerCursor = -1;
    document.getElementById('room-code-input').value = id;
    if (!socket) { setStatus('Co-op is offline.'); return; }
    socket.emit('join_sudoku_room', { room_id: id, bond_id: bondId, client_token: clientToken() });
    setStatus('Joined room ' + id + '.');
  }

  // Only the room host cycles puzzles; the partner follows the shared board.
  function requestRestart(nextDifficulty) {
    if (state.mode === 'coop' && socket && state.roomId) {
      if (!state.isHost) {
        var sel = document.getElementById('sudoku-diff-select');
        if (sel) sel.value = state.difficulty;
        setStatus('Your partner picks the puzzle.');
        return;
      }
      if (nextDifficulty) state.difficulty = nextDifficulty;
      socket.emit('sudoku_restart', { room_id: state.roomId });
    } else {
      if (nextDifficulty) state.difficulty = nextDifficulty;
      loadPuzzle();
    }
  }

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-coop').addEventListener('click', function () { setMode('coop'); });
  var gateDuel = document.getElementById('solo-gate-duel');
  if (gateDuel) gateDuel.addEventListener('click', function () { document.getElementById('tab-coop').click(); });
  document.getElementById('sudoku-new-btn').addEventListener('click', function () { requestRestart(); });
  document.getElementById('sudoku-again-btn').addEventListener('click', function () { requestRestart(); });
  document.getElementById('sudoku-erase-btn').addEventListener('click', function () { enterNumber(0); });
  var diffSelect = document.getElementById('sudoku-diff-select');
  if (diffSelect) diffSelect.addEventListener('change', function () {
    requestRestart(diffSelect.value);
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
    var code = state.roomId || (document.getElementById('room-code-input').value || '').trim();
    if (!code) { setStatus('No room yet.'); return; }
    var url = window.location.origin + '/games/sudoku?room=' + encodeURIComponent(code);
    try { navigator.clipboard.writeText(url); setStatus('Link copied.'); } catch (e) { setStatus(url); }
  });

  if (socket) {
    socket.on('connect', function () {
      // A reconnect gets a new sid; re-seat so the partner keeps their seat.
      if (state.mode === 'coop' && state.roomId) {
        socket.emit('join_sudoku_room', { room_id: state.roomId, bond_id: bondId, client_token: clientToken() });
      }
    });
    socket.on('sudoku_room_error', function (d) {
      setStatus((d && d.message) || 'Could not join.');
    });
    socket.on('sudoku_room_joined', function (d) {
      state.isHost = d.is_host !== false;
      if (Array.isArray(d.grid) && d.grid.length === 81) state.roomGrid = d.grid;
      if (d.has_puzzle) state.hasShared = true;
      if (d.partner_name) {
        document.getElementById('sudoku-partner-name').textContent = d.partner_name;
        setStatus('Partner joined.');
      } else if (d.has_puzzle) {
        setStatus('Loading…');
      }
    });
    socket.on('sudoku_puzzle', function (d) {
      if (!usableBoard(d)) return;
      state.hasShared = true;
      if (sameBoard(d.puzzle, state.puzzle)) { mergeRoomGrid(); return; }
      applyPuzzle(d, true);
    });
    socket.on('sudoku_cell_update', function (d) {
      var idx = d.r * 9 + d.c;
      if (!state.givens[idx] && !state.over) {
        state.grid[idx] = d.v;
        if (state.wrongCells[idx] !== undefined) { delete state.wrongCells[idx]; syncMistakes(); }
        render();
      }
    });
    socket.on('sudoku_cursor_move', function (d) {
      state.partnerCursor = d.r * 9 + d.c; render();
    });
    socket.on('sudoku_restarted', function (d) {
      // Only the restart initiator loads a fresh board (then shares it);
      // the partner waits for the shared board instead of loading a different one.
      var amRestarter = !d || !d.restarter || (socket && d.restarter === socket.id);
      if (amRestarter) {
        state.hasShared = false; state.roomGrid = null;
        loadPuzzle();
      } else {
        state.roomGrid = null;
        setStatus('New puzzle…');
      }
    });
    socket.on('sudoku_solved', function () {
      if (!state.over && state.entries > 0) submitSolve();
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
