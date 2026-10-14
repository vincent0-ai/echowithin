/* Gomoku 15x15 — solo vs AI, local 2P, online 1v1. No dependencies. */
(function () {
  'use strict';
  var N = 15, CELLS = N * N;
  var state = {
    mode: 'solo', board: new Array(CELLS).fill(-1), turn: 0, over: false,
    moves: 0, difficulty: 'normal', scores: [0, 0, 0], streak: 0,
    roomId: null, player: 0, isHost: true, guestToken: null, thinking: false
  };
  var canvas = document.getElementById('gomoku-canvas');
  var ctx = canvas.getContext('2d');
  var socket = window.__gomokuSocket || null;
  try { if (!socket && typeof io !== 'undefined') socket = io({ transports: ['websocket', 'polling'] }); } catch (e) { socket = null; }

  var css = getComputedStyle(document.documentElement);
  var C_BLACK = '#3e2217', C_WHITE = '#ffffff', C_LINE = '#c9b795', C_BG = '#f6efe4', C_WIN = '#2c5f8a';

  function sizeCanvas() {
    var wrap = canvas.parentElement;
    var w = Math.min(wrap.clientWidth || 520, 520);
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = w * dpr; canvas.height = w * dpr;
    canvas.style.width = w + 'px'; canvas.style.height = w + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  var winLine = null;
  function draw() {
    var w = canvas.clientWidth || 320, pad = w * 0.06, step = (w - pad * 2) / (N - 1);
    ctx.fillStyle = C_BG; ctx.fillRect(0, 0, w, w);
    ctx.strokeStyle = C_LINE; ctx.lineWidth = 1;
    ctx.beginPath();
    for (var i = 0; i < N; i++) {
      ctx.moveTo(pad + i * step, pad); ctx.lineTo(pad + i * step, w - pad);
      ctx.moveTo(pad, pad + i * step); ctx.lineTo(w - pad, pad + i * step);
    }
    ctx.stroke();
    var pts = [[3, 3], [3, 11], [11, 3], [11, 11], [7, 7]];
    ctx.fillStyle = C_LINE;
    pts.forEach(function (p) { ctx.beginPath(); ctx.arc(pad + p[0] * step, pad + p[1] * step, 2.5, 0, 7); ctx.fill(); });
    for (var idx = 0; idx < CELLS; idx++) {
      var v = state.board[idx];
      if (v < 0) continue;
      var r = Math.floor(idx / N), c = idx % N;
      var x = pad + c * step, y = pad + r * step, rad = step * 0.44;
      var inWin = winLine && winLine.some(function (cell) { return cell[0] === r && cell[1] === c; });
      ctx.beginPath(); ctx.arc(x, y, rad, 0, 7);
      if (v === 0) { ctx.fillStyle = inWin ? C_WIN : C_BLACK; ctx.fill(); }
      else { ctx.fillStyle = inWin ? '#dbeafe' : C_WHITE; ctx.fill(); ctx.strokeStyle = inWin ? C_WIN : C_BLACK; ctx.lineWidth = 1.5; ctx.stroke(); }
    }
    if (state.turn === 0) { document.getElementById('gomoku-turn-dot').style.background = '#3e2217'; }
    else { document.getElementById('gomoku-turn-dot').style.background = '#ffffff'; }
  }

  function checkWin(board, r, c, p) {
    var dirs = [[0, 1], [1, 0], [1, 1], [1, -1]];
    for (var d = 0; d < 4; d++) {
      var line = [[r, c]], dr = dirs[d][0], dc = dirs[d][1], nr = r + dr, nc = c + dc;
      while (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] === p) { line.push([nr, nc]); nr += dr; nc += dc; }
      nr = r - dr; nc = c - dc;
      while (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] === p) { line.unshift([nr, nc]); nr -= dr; nc -= dc; }
      if (line.length >= 5) return line;
    }
    return null;
  }

  function candidates(board) {
    var seen = {}, out = [];
    for (var i = 0; i < CELLS; i++) {
      if (board[i] < 0) continue;
      var r = Math.floor(i / N), c = i % N;
      for (var dr = -2; dr <= 2; dr++) for (var dc = -2; dc <= 2; dc++) {
        var nr = r + dr, nc = c + dc, k = nr * N + nc;
        if (nr >= 0 && nr < N && nc >= 0 && nc < N && board[k] < 0 && !seen[k]) { seen[k] = 1; out.push(k); }
      }
    }
    if (!out.length) out.push(Math.floor(CELLS / 2));
    return out;
  }

  function scorePos(board, idx, p) {
    board[idx] = p;
    var r = Math.floor(idx / N), c = idx % N, s = 0;
    var dirs = [[0, 1], [1, 0], [1, 1], [1, -1]];
    for (var d = 0; d < 4; d++) {
      var count = 1, open = 0, dr = dirs[d][0], dc = dirs[d][1], nr = r + dr, nc = c + dc;
      while (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] === p) { count++; nr += dr; nc += dc; }
      if (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] < 0) open++;
      nr = r - dr; nc = c - dc;
      while (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] === p) { count++; nr -= dr; nc -= dc; }
      if (nr >= 0 && nr < N && nc >= 0 && nc < N && board[nr * N + nc] < 0) open++;
      if (count >= 5) s += 100000;
      else if (count === 4 && open === 2) s += 10000;
      else if (count === 4 && open === 1) s += 1000;
      else if (count === 3 && open === 2) s += 500;
      else if (count === 3 && open === 1) s += 50;
      else if (count === 2 && open === 2) s += 10;
      else s += count;
    }
    board[idx] = -1;
    return s;
  }

  function aiMove() {
    var cands = candidates(state.board);
    var depth = state.difficulty === 'easy' ? 8 : (state.difficulty === 'hard' ? 40 : 20);
    var pool = cands.slice(0, depth);
    var best = pool[0], bestScore = -1;
    var me = state.turn, opp = 1 - me;
    for (var i = 0; i < pool.length; i++) {
      var idx = pool[i];
      var s = scorePos(state.board, idx, me) * 1.0 + scorePos(state.board, idx, opp) * 0.85 + Math.random() * 5;
      if (s > bestScore) { bestScore = s; best = idx; }
    }
    return best;
  }

  function setStatus(t) {
    var el = document.getElementById('room-status');
    if (el && state.mode === 'online') el.textContent = t;
    document.getElementById('gomoku-turn-text').textContent = t.length < 26 ? t.toUpperCase() : t;
  }

  function updateScores() {
    document.getElementById('score-val-p1').textContent = state.scores[0];
    document.getElementById('score-val-ties').textContent = state.scores[2];
    document.getElementById('score-val-p2').textContent = state.scores[1];
    var ls = document.getElementById('live-streak');
    if (ls) ls.textContent = state.streak;
  }

  function showResult(title, sub) {
    document.getElementById('gomoku-result-title').textContent = title;
    document.getElementById('gomoku-result-subtitle').textContent = sub;
    document.getElementById('gomoku-result-overlay').style.display = 'flex';
  }
  function hideResult() { document.getElementById('gomoku-result-overlay').style.display = 'none'; }

  function submitScore(category, score, extra) {
    var payload = { game: 'gomoku', category: category, score: score, metadata: extra || {} };
    if (!document.cookie.includes('session')) {
      if (!state.guestToken) state.guestToken = 'g_' + Math.random().toString(36).slice(2, 14);
      payload.guest_token = state.guestToken;
      payload.username = 'Guest';
    }
    fetch('/api/games/leaderboard/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).catch(function () {});
  }

  function endRound(winner, line, isDraw) {
    state.over = true; winLine = line || null; draw();
    if (winner === null && isDraw) {
      state.scores[2]++; state.streak = 0; submitScore('win_streak', 1, { mode: state.mode });
      showResult("DRAW", 'Board is full.');
    } else if (winner !== null) {
      state.scores[winner]++;
      var meWon = (state.mode === 'online') ? (winner === state.player) : (winner === 0);
      if (meWon) { state.streak++; submitScore('win_streak', state.streak, { mode: state.mode, difficulty: state.difficulty }); submitScore('total_wins', state.scores[winner], { mode: state.mode }); }
      else state.streak = 0;
      showResult(meWon ? 'YOU WON!' : (state.mode === 'local' ? ('PLAYER ' + (winner + 1) + ' WON!') : 'YOU LOST'), 'Five in a row.');
    }
    updateScores();
  }

  function placeStone(idx) {
    if (state.over || state.board[idx] !== -1) return false;
    if (state.mode === 'online' && state.turn !== state.player) return false;
    if (state.mode === 'online' && socket && state.roomId) socket.emit('gomoku_move', { room_id: state.roomId, idx: idx });
    else applyMove(idx, state.turn);
    return true;
  }

  function applyMove(idx, player) {
    state.board[idx] = player; state.moves++;
    var r = Math.floor(idx / N), c = idx % N;
    var line = checkWin(state.board, r, c, player);
    var isDraw = !line && state.moves >= CELLS;
    if (line || isDraw) { endRound(line ? player : null, line, isDraw); return; }
    state.turn = 1 - player; winLine = null; draw();
    setStatus(state.mode === 'local' ? ('Player ' + (state.turn + 1) + ' to move') : (state.turn === 0 ? 'Your turn' : 'Waiting'));
    if (state.mode === 'solo' && state.turn === 1 && !state.over) {
      state.thinking = true;
      document.getElementById('gomoku-thinking').style.display = 'block';
      setTimeout(function () {
        document.getElementById('gomoku-thinking').style.display = 'none';
        state.thinking = false;
        if (!state.over) applyMove(aiMove(), 1);
      }, state.difficulty === 'hard' ? 450 : 300);
    }
  }

  function resetBoard() {
    state.board = new Array(CELLS).fill(-1); state.moves = 0; state.over = false; winLine = null;
    state.turn = (state.mode === 'online') ? state.turn : 0;
    hideResult(); draw();
    setStatus(state.mode === 'local' ? 'Player 1 to move' : 'Your turn');
    if (state.mode === 'solo' && state.turn === 1) { var t = state.turn; state.turn = 1; applyMove(aiMove(), 1); }
  }

  function setMode(m) {
    state.mode = m; resetBoard();
    ['solo', 'local', 'online'].forEach(function (k) {
      var b = document.getElementById('tab-' + k);
      if (b) b.className = 'ew-btn' + (k === m ? '' : '--outline') + ' ew-btn--sm mode-tab';
    });
    document.getElementById('solo-difficulty-panel').style.display = m === 'solo' ? 'flex' : 'none';
    document.getElementById('online-panel').style.display = m === 'online' ? 'block' : 'none';
    document.getElementById('score-label-p1').textContent = m === 'local' ? 'PLAYER 1 (BLACK)' : 'YOU (BLACK)';
    document.getElementById('score-label-p2').textContent = m === 'local' ? 'PLAYER 2 (WHITE)' : (m === 'online' ? 'OPPONENT (WHITE)' : 'CPU (WHITE)');
    if (m === 'online') joinFromUrl();
  }

  function roomFromUrl() {
    var m = new URLSearchParams(window.location.search).get('room');
    return (m || '').trim().slice(0, 32);
  }

  function joinRoom(id) {
    state.roomId = id;
    if (socket) socket.emit('join_gomoku_room', { room_id: id });
    setStatus('Joined room ' + id + '. Waiting for opponent…');
    var input = document.getElementById('room-code-input');
    if (input) input.value = id;
  }

  function joinFromUrl() {
    var r = roomFromUrl();
    if (r) joinRoom(r);
    else setStatus('Create or join a room.');
  }

  canvas.addEventListener('click', function (e) {
    if (state.thinking) return;
    var rect = canvas.getBoundingClientRect();
    var w = rect.width, pad = w * 0.06, step = (w - pad * 2) / (N - 1);
    var c = Math.round((e.clientX - rect.left - pad) / step);
    var r = Math.round((e.clientY - rect.top - pad) / step);
    if (r < 0 || r >= N || c < 0 || c >= N) return;
    placeStone(r * N + c);
  });

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-local').addEventListener('click', function () { setMode('local'); });
  document.getElementById('tab-online').addEventListener('click', function () { setMode('online'); });
  document.querySelectorAll('.gomoku-diff-btn').forEach(function (b) {
    b.addEventListener('click', function () {
      state.difficulty = b.dataset.diff;
      document.querySelectorAll('.gomoku-diff-btn').forEach(function (x) { x.className = 'ew-btn--outline ew-btn--sm gomoku-diff-btn'; });
      b.className = 'ew-btn ew-btn--sm gomoku-diff-btn';
      resetBoard();
    });
  });
  document.getElementById('gomoku-restart-btn').addEventListener('click', function () {
    if (state.mode === 'online' && socket && state.roomId) socket.emit('gomoku_restart', { room_id: state.roomId });
    else resetBoard();
  });
  document.getElementById('gomoku-next-round-btn').addEventListener('click', function () {
    if (state.mode === 'online' && socket && state.roomId) socket.emit('gomoku_restart', { room_id: state.roomId });
    else resetBoard();
  });
  document.getElementById('join-room-btn').addEventListener('click', function () {
    var v = (document.getElementById('room-code-input').value || '').trim();
    if (v) joinRoom(v);
  });
  document.getElementById('create-room-btn').addEventListener('click', function () {
    joinRoom('gomoku_' + Math.random().toString(36).slice(2, 8));
  });
  document.getElementById('copy-link-btn').addEventListener('click', function () {
    var url = window.location.origin + '/games/gomoku?room=' + encodeURIComponent(state.roomId || document.getElementById('room-code-input').value || '');
    try { navigator.clipboard.writeText(url); setStatus('Link copied.'); } catch (e) { setStatus(url); }
  });
  document.getElementById('find-match-btn').addEventListener('click', function () {
    if (socket) { socket.emit('find_gomoku_match', { mode: 'auto' }); setStatus('Searching for opponent…'); }
  });

  if (socket) {
    socket.on('gomoku_room_joined', function (d) {
      state.player = d.player; state.isHost = d.is_host;
      if (d.turn !== undefined) state.turn = d.turn;
      resetBoardSilent();
      setStatus(d.guest_name ? 'Opponent joined. ' + (state.turn === state.player ? 'Your turn.' : 'Waiting.') : 'Share the room code with a friend.');
    });
    socket.on('gomoku_move_made', function (d) {
      state.board[d.idx] = d.player; state.moves++;
      state.scores = d.scores; state.turn = d.next_turn;
      if (d.winner !== null && d.winner !== undefined || d.is_draw) {
        var w = d.is_draw ? null : d.winner;
        state.over = true; winLine = d.win_line || null; draw();
        var meWon = w === state.player;
        if (w === null) { state.streak = 0; showResult('DRAW', 'Board is full.'); }
        else { if (meWon) state.streak++; else state.streak = 0; showResult(meWon ? 'YOU WON!' : 'YOU LOST', 'Five in a row.'); }
        updateScores();
      } else { winLine = null; draw(); setStatus(d.next_turn === state.player ? 'Your turn.' : 'Opponent thinking…'); }
    });
    socket.on('gomoku_restarted', function (d) {
      state.board = new Array(CELLS).fill(-1); state.moves = 0; state.over = false; winLine = null;
      state.turn = d.turn; hideResult(); draw();
      setStatus(state.turn === state.player ? 'Your turn.' : 'Opponent thinking…');
    });
    socket.on('gomoku_match_found', function (d) {
      state.roomId = d.room_id; state.player = d.player; state.isHost = d.is_host;
      state.turn = d.turn; state.board = new Array(CELLS).fill(-1); state.moves = 0; state.over = false; winLine = null;
      hideResult(); draw(); setStatus('Matched! ' + (state.turn === state.player ? 'Your turn.' : 'Waiting.'));
    });
    socket.on('gomoku_matchmaking_waiting', function () { setStatus('Waiting for an opponent…'); });
    socket.on('gomoku_player_left', function () { setStatus('Opponent left.'); showResult('OPPONENT LEFT', 'Share the room code to play again.'); });
    socket.on('gomoku_room_error', function (d) { setStatus(d.message || 'Room full.'); });
  }

  function resetBoardSilent() {
    state.board = new Array(CELLS).fill(-1); state.moves = 0; state.over = false; winLine = null;
    hideResult(); draw();
  }

  window.__gomoku = {
    getSocketId: function () { return socket ? socket.id : null; },
    sendChallenge: function (sid) { if (socket) { socket.emit('find_gomoku_match', { mode: 'auto' }); socket.emit('send_game_challenge', { game: 'gomoku', target_sid: sid }); } },
    acceptChallenge: function (sid) { if (socket) socket.emit('accept_game_challenge', { game: 'gomoku', challenger_sid: sid }); },
    declineChallenge: function (sid) { if (socket) socket.emit('decline_game_challenge', { game: 'gomoku', challenger_sid: sid }); }
  };

  window.addEventListener('resize', sizeCanvas);
  window.addEventListener('beforeunload', function () {
    if (socket && state.roomId) socket.emit('leave_gomoku_room', { room_id: state.roomId });
  });
  sizeCanvas(); updateScores(); setMode(roomFromUrl() ? 'online' : 'solo');
})();
