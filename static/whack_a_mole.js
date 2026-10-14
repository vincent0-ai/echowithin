/* Whack-'Em-All — solo timed rounds + same-seed 1v1 score duels. No dependencies. */
(function () {
  'use strict';
  var SKINS = ['🐹', '🐭', '🐸', '🐵', '🐷', '🐥'];
  var state = {
    mode: 'solo', roundSecs: 30, score: 0, playing: false, timeLeft: 0,
    timerId: null, spawnId: null, upIdx: -1, seed: 1,
    roomId: null, player: 0, oppScore: 0, finished: false, guestToken: null
  };
  var grid = document.getElementById('whack-grid');
  var socket = null;
  try { if (typeof io !== 'undefined') socket = io({ transports: ['websocket', 'polling'] }); } catch (e) { socket = null; }

  var cells = [];
  for (var i = 0; i < 9; i++) {
    (function (idx) {
      var d = document.createElement('div');
      d.className = 'whack-hole'; d.setAttribute('role', 'gridcell');
      d.setAttribute('tabindex', '0');
      d.setAttribute('aria-label', 'Hole ' + (idx + 1));
      d.innerHTML = '<span class="mole">🐹</span>';
      function hit(e) { if (e) e.preventDefault(); whack(idx, d); }
      d.addEventListener('pointerdown', hit);
      d.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') hit(e); });
      grid.appendChild(d); cells.push(d);
    })(i);
  }

  function rng() {
    state.seed = (state.seed * 1103515245 + 12345) & 0x7fffffff;
    return state.seed / 0x7fffffff;
  }

  function setScore(v) {
    state.score = v;
    document.getElementById('whack-score').textContent = v;
  }

  function setStatus(t) {
    var el = document.getElementById('room-status');
    if (el) el.textContent = t;
  }

  function hideMole() {
    if (state.upIdx >= 0) cells[state.upIdx].classList.remove('up');
    state.upIdx = -1;
  }

  function showMole() {
    hideMole();
    var idx = Math.floor(rng() * 9);
    var skin = SKINS[Math.floor(rng() * SKINS.length)];
    state.upIdx = idx;
    cells[idx].querySelector('.mole').textContent = skin;
    cells[idx].classList.add('up');
    clearTimeout(state.spawnId);
    state.spawnId = setTimeout(function () {
      if (state.playing) showMole();
      else hideMole();
    }, 700);
  }

  function whack(idx, el) {
    if (!state.playing) return;
    if (idx === state.upIdx) {
      setScore(state.score + 1);
      el.classList.add('hit');
      setTimeout(function () { el.classList.remove('hit'); }, 120);
      hideMole();
      if (navigator.vibrate) { try { navigator.vibrate(10); } catch (e) {} }
      pushScore();
    } else {
      setScore(Math.max(0, state.score - 1));
    }
  }

  var lastPush = 0;
  function pushScore() {
    if (state.mode !== 'duel' || !socket || !state.roomId) return;
    var now = Date.now();
    if (now - lastPush < 500) return;
    lastPush = now;
    socket.emit('whack_score', { room_id: state.roomId, score: state.score });
  }

  function submitSolo() {
    var payload = { game: 'whack_a_mole', category: 'high_score', score: state.score, metadata: { mode: 'solo', round: String(state.roundSecs) } };
    if (!document.cookie.includes('session')) {
      if (!state.guestToken) state.guestToken = 'g_' + Math.random().toString(36).slice(2, 14);
      payload.guest_token = state.guestToken;
      payload.username = 'Guest';
    }
    fetch('/api/games/leaderboard/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).catch(function () {});
  }

  function startRound() {
    hideResult();
    state.seed = (state.seed * 9301 + 49297) & 0x7fffffff || 1;
    setScore(0); state.timeLeft = state.roundSecs; state.playing = true; state.finished = false;
    document.getElementById('whack-time').textContent = state.timeLeft;
    document.getElementById('whack-start-btn').textContent = 'Playing…';
    document.getElementById('whack-start-btn').disabled = true;
    showMole();
    clearInterval(state.timerId);
    state.timerId = setInterval(function () {
      state.timeLeft--;
      document.getElementById('whack-time').textContent = Math.max(0, state.timeLeft);
      if (state.timeLeft <= 0) finishRound();
    }, 1000);
  }

  function finishRound() {
    clearInterval(state.timerId); clearTimeout(state.spawnId);
    state.playing = false; hideMole();
    document.getElementById('whack-start-btn').textContent = 'Start';
    document.getElementById('whack-start-btn').disabled = false;
    if (state.mode === 'solo') {
      submitSolo();
      showResult('TIME!', 'You scored ' + state.score + '.');
    } else if (socket && state.roomId && !state.finished) {
      state.finished = true;
      socket.emit('whack_finish', { room_id: state.roomId, score: state.score });
      showResult('DONE!', 'You scored ' + state.score + '. Waiting for rival…');
    }
  }

  function showResult(title, sub) {
    document.getElementById('whack-result-title').textContent = title;
    document.getElementById('whack-result-subtitle').textContent = sub;
    document.getElementById('whack-result-overlay').style.display = 'flex';
  }
  function hideResult() { document.getElementById('whack-result-overlay').style.display = 'none'; }

  function setMode(m) {
    state.mode = m;
    document.getElementById('tab-solo').className = 'ew-btn' + (m === 'solo' ? '' : '--outline') + ' ew-btn--sm mode-tab';
    document.getElementById('tab-duel').className = 'ew-btn' + (m === 'duel' ? '' : '--outline') + ' ew-btn--sm mode-tab';
    document.getElementById('online-panel').style.display = m === 'duel' ? 'block' : 'none';
    document.getElementById('whack-opp').style.display = m === 'duel' ? 'inline-flex' : 'none';
    if (m === 'duel') {
      var r = new URLSearchParams(window.location.search).get('room');
      if (r) joinRoom(r.trim().slice(0, 32));
      else setStatus('Create or join a room. Both players get the same mole order.');
    }
  }

  function joinRoom(id) {
    state.roomId = id;
    document.getElementById('room-code-input').value = id;
    if (socket) socket.emit('join_whack_room', { room_id: id, seed: (state.seed % 2147483647) || 0 });
    setStatus('Joined room ' + id + '. Press Start together.');
  }

  document.getElementById('tab-solo').addEventListener('click', function () { setMode('solo'); });
  document.getElementById('tab-duel').addEventListener('click', function () { setMode('duel'); });
  document.getElementById('round-len-btn').addEventListener('click', function () {
    state.roundSecs = state.roundSecs === 30 ? 60 : 30;
    this.textContent = 'Round: ' + state.roundSecs + 's';
    document.getElementById('whack-time').textContent = state.roundSecs;
  });
  document.getElementById('whack-start-btn').addEventListener('click', startRound);
  document.getElementById('whack-again-btn').addEventListener('click', hideResult);
  document.getElementById('join-room-btn').addEventListener('click', function () {
    var v = (document.getElementById('room-code-input').value || '').trim();
    if (v) joinRoom(v);
  });
  document.getElementById('create-room-btn').addEventListener('click', function () {
    state.seed = Math.floor(Math.random() * 2147483647) || 1;
    joinRoom('whack_' + Math.random().toString(36).slice(2, 8));
  });
  document.getElementById('copy-link-btn').addEventListener('click', function () {
    var url = window.location.origin + '/games/whack-a-mole?room=' + encodeURIComponent(state.roomId || document.getElementById('room-code-input').value || '');
    try { navigator.clipboard.writeText(url); setStatus('Link copied.'); } catch (e) { setStatus(url); }
  });
  document.getElementById('find-match-btn').addEventListener('click', function () {
    if (socket) { socket.emit('find_whack_match', { mode: 'auto' }); setStatus('Searching…'); }
  });

  if (socket) {
    socket.on('whack_room_joined', function (d) {
      state.player = d.player; state.seed = d.seed || 1;
      setStatus(d.guest_name ? 'Rival joined. Press Start together!' : 'Share the room code.');
    });
    socket.on('whack_state', function (d) {
      var scores = (d && d.scores) || [0, 0];
      var opp = state.player === 0 ? scores[1] : scores[0];
      state.oppScore = opp;
      document.getElementById('whack-opp-score').textContent = opp;
    });
    socket.on('whack_match_found', function (d) {
      state.roomId = d.room_id; state.player = d.player; state.seed = d.seed || 1;
      document.getElementById('room-code-input').value = d.room_id;
      setStatus('Matched! Press Start together.');
    });
    socket.on('whack_matchmaking_waiting', function () { setStatus('Waiting for a rival…'); });
    socket.on('whack_result', function (d) {
      var scores = (d && d.scores) || [0, 0];
      var mine = state.player === 0 ? scores[0] : scores[1];
      var theirs = state.player === 0 ? scores[1] : scores[0];
      var w = d.winner;
      showResult(w === null || w === undefined ? 'DRAW!' : (w === state.player ? 'YOU WIN!' : 'RIVAL WINS'),
        'You ' + mine + ' · Rival ' + theirs + '.');
    });
    socket.on('whack_player_left', function () { setStatus('Rival left.'); });
  }

  window.__whack = {
    getSocketId: function () { return socket ? socket.id : null; },
    sendChallenge: function (sid) { if (socket) { socket.emit('find_whack_match', { mode: 'auto' }); socket.emit('send_game_challenge', { game: 'whack', target_sid: sid }); } },
    acceptChallenge: function (sid) { if (socket) socket.emit('accept_game_challenge', { game: 'whack', challenger_sid: sid }); },
    declineChallenge: function (sid) { if (socket) socket.emit('decline_game_challenge', { game: 'whack', challenger_sid: sid }); }
  };

  window.addEventListener('beforeunload', function () {
    if (socket && state.roomId) socket.emit('leave_whack_room', { room_id: state.roomId });
  });
  setMode(new URLSearchParams(window.location.search).get('room') ? 'duel' : 'solo');
})();
