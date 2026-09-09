/**
 * Tic-Tac-Toe Engine for EchoWithin
 * Features:
 *  - Solo vs AI (Easy, Medium, Hard with fork detection)
 *  - Local 2-Player Pass-and-Play
 *  - Online 1v1 Duel via Socket.IO (Matchmaking queue & Room Codes)
 *  - Offline Sync & Global/Daily/Weekly Leaderboard submission
 *  - Web Audio synthesized feedback
 */

(function () {
  'use strict';

  // --- Audio Feedback (Synthesized via Web Audio API) ---
  let audioCtx = null;
  let isMuted = localStorage.getItem('ew_ttt_muted') === 'true';

  function getAudioCtx() {
    if (!audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) {
        audioCtx = new AudioContextClass();
      }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
      audioCtx.resume().catch(() => {});
    }
    return audioCtx;
  }

  function playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.15) {
    if (isMuted) return;
    try {
      const ctx = getAudioCtx();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(gainVal, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + duration);
    } catch (_) {}
  }

  function playMoveSound(symbol) {
    if (symbol === 'x') {
      playTone(480, 'sine', 0.09, 0.2);
    } else {
      playTone(640, 'triangle', 0.09, 0.2);
    }
  }

  function playWinSound() {
    playTone(523.25, 'sine', 0.12, 0.25);
    setTimeout(() => playTone(659.25, 'sine', 0.12, 0.25), 100);
    setTimeout(() => playTone(783.99, 'sine', 0.25, 0.3), 200);
  }

  function playDrawSound() {
    playTone(330, 'sawtooth', 0.15, 0.15);
    setTimeout(() => playTone(280, 'sawtooth', 0.2, 0.15), 140);
  }

  // --- Win Patterns (3x3) ---
  const WIN_PATTERNS = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8],
    [0, 3, 6], [1, 4, 7], [2, 5, 8],
    [0, 4, 8], [2, 4, 6]
  ];

  // --- Game State ---
  const state = {
    mode: 'solo', // 'solo' | 'local' | 'online'
    board: Array(9).fill(''),
    turn: 'x',
    playerSymbol: 'x',
    cpuSymbol: 'o',
    difficulty: 'medium',
    isGameOver: false,
    scores: { x: 0, o: 0, ties: 0 },
    winStreak: 0,
    totalWins: 0,
    isThinking: false,

    // Online
    socket: null,
    roomId: null,
    isHost: false,
    mySymbol: 'x',
    opponentJoined: false,
    opponentName: 'Opponent',
    isSearching: false
  };

  // --- DOM Elements ---
  const els = {};

  function cacheElements() {
    els.boardCells = document.querySelectorAll('.ttt-cell');
    els.turnIndicator = document.getElementById('ttt-turn-indicator');
    els.turnText = document.getElementById('ttt-turn-text');
    els.thinkingIndicator = document.getElementById('ttt-thinking-indicator');
    els.restartBtn = document.getElementById('ttt-restart-btn');
    els.muteToggleBtn = document.getElementById('mute-toggle-btn');

    // Tabs
    els.tabSolo = document.getElementById('tab-solo');
    els.tabLocal = document.getElementById('tab-local');
    els.tabOnline = document.getElementById('tab-online');

    // Panels
    els.soloPanel = document.getElementById('solo-settings-panel');
    els.onlinePanel = document.getElementById('online-panel');

    // Solo Config
    els.pickX = document.getElementById('pick-x');
    els.pickO = document.getElementById('pick-o');
    els.diffButtons = document.querySelectorAll('.ttt-diff-btn');

    // Online Controls
    els.findMatchBtn = document.getElementById('find-match-btn');
    els.roomCodeInput = document.getElementById('room-code-input');
    els.joinRoomBtn = document.getElementById('join-room-btn');
    els.copyLinkBtn = document.getElementById('copy-link-btn');
    els.roomStatus = document.getElementById('room-status');

    // Scoreboard
    els.scoreCardX = document.getElementById('score-card-x');
    els.scoreCardO = document.getElementById('score-card-o');
    els.scoreLabelX = document.getElementById('score-label-x');
    els.scoreLabelO = document.getElementById('score-label-o');
    els.scoreValX = document.getElementById('score-val-x');
    els.scoreValTies = document.getElementById('score-val-ties');
    els.scoreValO = document.getElementById('score-val-o');
    els.liveStreak = document.getElementById('live-streak');

    // Result Overlay
    els.resultOverlay = document.getElementById('ttt-result-overlay');
    els.resultTitle = document.getElementById('ttt-result-title');
    els.resultSubtitle = document.getElementById('ttt-result-subtitle');
    els.nextRoundBtn = document.getElementById('ttt-next-round-btn');
  }

  // --- Storage & Offline Sync ---
  const STORAGE_PENDING_SYNC = 'ew_ttt_pending_sync';
  const STORAGE_GUEST_TOKEN = 'ew_arcade_guest_token';

  function getGuestToken() {
    let token = localStorage.getItem(STORAGE_GUEST_TOKEN);
    if (!token) {
      token = 'gst_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
      localStorage.setItem(STORAGE_GUEST_TOKEN, token);
    }
    return token;
  }

  function queuePendingSync(category, score) {
    try {
      const items = JSON.parse(localStorage.getItem(STORAGE_PENDING_SYNC) || '[]');
      items.push({
        game: 'tic_tac_toe',
        category,
        score,
        timestamp: new Date().toISOString()
      });
      localStorage.setItem(STORAGE_PENDING_SYNC, JSON.stringify(items));
    } catch (_) {}
  }

  function clearPendingSync(category, score) {
    try {
      let items = JSON.parse(localStorage.getItem(STORAGE_PENDING_SYNC) || '[]');
      items = items.filter(it => !(it.category === category && it.score === score));
      localStorage.setItem(STORAGE_PENDING_SYNC, JSON.stringify(items));
    } catch (_) {}
  }

  async function submitArcadeScore(category, score) {
    if (!score || score <= 0) return;
    try {
      if (!navigator.onLine) {
        queuePendingSync(category, score);
        return;
      }
      const token = getGuestToken();
      const res = await fetch('/api/games/leaderboard/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          game: 'tic_tac_toe',
          category,
          score,
          guest_token: token
        })
      });
      if (res.ok) {
        clearPendingSync(category, score);
        if (typeof window.fetchLeaderboard === 'function') {
          window.fetchLeaderboard();
        }
      } else {
        queuePendingSync(category, score);
      }
    } catch (_) {
      queuePendingSync(category, score);
    }
  }

  async function flushPendingSync() {
    if (!navigator.onLine) return;
    try {
      const raw = localStorage.getItem(STORAGE_PENDING_SYNC);
      if (!raw) return;
      const items = JSON.parse(raw);
      if (!Array.isArray(items) || items.length === 0) return;
      for (const item of items) {
        if (item.game === 'tic_tac_toe') {
          await submitArcadeScore(item.category, item.score);
        }
      }
    } catch (_) {}
  }
  window.addEventListener('online', flushPendingSync);

  // --- UI Updates ---
  function updateScoreboard() {
    if (els.scoreValX) els.scoreValX.textContent = state.scores.x;
    if (els.scoreValTies) els.scoreValTies.textContent = state.scores.ties;
    if (els.scoreValO) els.scoreValO.textContent = state.scores.o;
    if (els.liveStreak) els.liveStreak.textContent = state.winStreak;

    if (state.mode === 'solo') {
      if (els.scoreLabelX) els.scoreLabelX.textContent = state.playerSymbol === 'x' ? 'X (YOU)' : 'X (CPU)';
      if (els.scoreLabelO) els.scoreLabelO.textContent = state.playerSymbol === 'o' ? 'O (YOU)' : 'O (CPU)';
    } else if (state.mode === 'online') {
      const myIsX = state.mySymbol === 'x';
      if (els.scoreLabelX) els.scoreLabelX.textContent = myIsX ? 'X (YOU)' : `X (${state.opponentName})`;
      if (els.scoreLabelO) els.scoreLabelO.textContent = !myIsX ? 'O (YOU)' : `O (${state.opponentName})`;
    } else {
      if (els.scoreLabelX) els.scoreLabelX.textContent = 'X (P1)';
      if (els.scoreLabelO) els.scoreLabelO.textContent = 'O (P2)';
    }
  }

  function updateTurnDisplay() {
    if (!els.turnIndicator || !els.turnText) return;
    const isX = state.turn === 'x';
    els.turnIndicator.setAttribute('data-turn', state.turn);
    if (state.mode === 'online') {
      const isMyTurn = state.turn === state.mySymbol;
      els.turnText.textContent = isMyTurn ? 'YOUR TURN' : "OPPONENT'S TURN";
    } else if (state.mode === 'solo') {
      const isPlayerTurn = state.turn === state.playerSymbol;
      els.turnText.textContent = isPlayerTurn ? 'YOUR TURN' : 'CPU THINKING...';
    } else {
      els.turnText.textContent = isX ? "PLAYER 1 (X) TURN" : "PLAYER 2 (O) TURN";
    }
  }

  function renderBoard() {
    els.boardCells.forEach((cell, idx) => {
      const val = state.board[idx];
      cell.setAttribute('data-symbol', val);
      cell.classList.remove('win-line');
      const inner = cell.querySelector('.ttt-cell-inner') || cell;
      if (val === 'x') {
        inner.innerHTML = `<svg viewBox="0 0 32 32" width="48" height="48" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round"><line x1="8" y1="8" x2="24" y2="24"/><line x1="24" y1="8" x2="8" y2="24"/></svg>`;
      } else if (val === 'o') {
        inner.innerHTML = `<svg viewBox="0 0 32 32" width="48" height="48" fill="none" stroke="currentColor" stroke-width="5"><circle cx="16" cy="16" r="8"/></svg>`;
      } else {
        inner.innerHTML = '';
      }
    });
  }

  function setMode(mode) {
    state.mode = mode;
    [els.tabSolo, els.tabLocal, els.tabOnline].forEach(btn => {
      if (btn) {
        btn.classList.remove('ew-btn');
        btn.classList.add('ew-btn--outline');
      }
    });

    if (mode === 'solo' && els.tabSolo) {
      els.tabSolo.classList.remove('ew-btn--outline');
      els.tabSolo.classList.add('ew-btn');
      if (els.soloPanel) els.soloPanel.style.display = 'flex';
      if (els.onlinePanel) els.onlinePanel.style.display = 'none';
    } else if (mode === 'local' && els.tabLocal) {
      els.tabLocal.classList.remove('ew-btn--outline');
      els.tabLocal.classList.add('ew-btn');
      if (els.soloPanel) els.soloPanel.style.display = 'none';
      if (els.onlinePanel) els.onlinePanel.style.display = 'none';
    } else if (mode === 'online' && els.tabOnline) {
      els.tabOnline.classList.remove('ew-btn--outline');
      els.tabOnline.classList.add('ew-btn');
      if (els.soloPanel) els.soloPanel.style.display = 'none';
      if (els.onlinePanel) els.onlinePanel.style.display = 'block';
      initOnlineSocket();
    }
    resetGame();
  }

  // --- Core Game Logic ---
  function checkWin(symbol, board = state.board) {
    return WIN_PATTERNS.find(pattern => pattern.every(index => board[index] === symbol)) || null;
  }

  function isDraw(board = state.board) {
    return board.every(cell => cell !== '');
  }

  function handleCellClick(index) {
    if (state.isGameOver || state.isThinking) return;
    if (state.board[index] !== '') return;

    if (state.mode === 'online') {
      if (!state.opponentJoined) return;
      if (state.turn !== state.mySymbol) return;
      // Send move to server
      if (state.socket && state.roomId) {
        state.socket.emit('ttt_move', { room_id: state.roomId, index });
      }
      return;
    }

    if (state.mode === 'solo') {
      if (state.turn !== state.playerSymbol) return;
      applyMove(index, state.playerSymbol);
      if (!state.isGameOver) {
        triggerCpuTurn();
      }
      return;
    }

    // Local 2-Player
    applyMove(index, state.turn);
  }

  function applyMove(index, symbol) {
    state.board[index] = symbol;
    playMoveSound(symbol);
    renderBoard();

    const winPattern = checkWin(symbol);
    if (winPattern) {
      endGame(false, symbol, winPattern);
      return;
    }

    if (isDraw()) {
      endGame(true, null);
      return;
    }

    state.turn = state.turn === 'x' ? 'o' : 'x';
    updateTurnDisplay();
  }

  function endGame(draw, winner, winPattern = null) {
    state.isGameOver = true;
    state.isThinking = false;
    if (els.thinkingIndicator) els.thinkingIndicator.style.display = 'none';

    if (winPattern) {
      winPattern.forEach(idx => {
        if (els.boardCells[idx]) els.boardCells[idx].classList.add('win-line');
      });
    }

    if (draw) {
      state.scores.ties++;
      playDrawSound();
      showResultModal(true, null);
    } else {
      state.scores[winner]++;
      playWinSound();

      let didLocalPlayerWin = false;
      if (state.mode === 'solo') {
        didLocalPlayerWin = winner === state.playerSymbol;
      } else if (state.mode === 'online') {
        didLocalPlayerWin = winner === state.mySymbol;
      } else {
        didLocalPlayerWin = true; // Local play
      }

      if (didLocalPlayerWin) {
        state.winStreak++;
        state.totalWins++;
        submitArcadeScore('win_streak', state.winStreak);
        submitArcadeScore('total_wins', state.totalWins);
      } else {
        state.winStreak = 0;
      }

      showResultModal(false, winner);
    }
    updateScoreboard();
  }

  function showResultModal(draw, winner) {
    if (!els.resultOverlay) return;
    if (draw) {
      els.resultTitle.textContent = 'ROUND DRAW';
      els.resultSubtitle.textContent = 'No player connected 3 in a line.';
    } else {
      let winnerLabel = winner.toUpperCase();
      if (state.mode === 'solo') {
        winnerLabel = winner === state.playerSymbol ? 'YOU WON!' : 'CPU WON';
      } else if (state.mode === 'online') {
        winnerLabel = winner === state.mySymbol ? 'YOU WON!' : `${state.opponentName.toUpperCase()} WON`;
      } else {
        winnerLabel = `${winner.toUpperCase()} TAKES THE ROUND`;
      }
      els.resultTitle.textContent = winnerLabel;
      els.resultSubtitle.textContent = 'Connected 3 in a line!';
    }
    setTimeout(() => {
      els.resultOverlay.style.display = 'flex';
    }, 400);
  }

  function resetGame() {
    state.board = Array(9).fill('');
    state.isGameOver = false;
    state.isThinking = false;
    state.turn = 'x';
    if (els.thinkingIndicator) els.thinkingIndicator.style.display = 'none';
    if (els.resultOverlay) els.resultOverlay.style.display = 'none';

    renderBoard();
    updateTurnDisplay();
    updateScoreboard();

    if (state.mode === 'solo' && state.playerSymbol === 'o') {
      triggerCpuTurn();
    }
  }

  // --- Solo AI Logic (Easy, Medium, Hard) ---
  function triggerCpuTurn() {
    if (state.isGameOver) return;
    state.isThinking = true;
    if (els.thinkingIndicator) els.thinkingIndicator.style.display = 'block';

    const delay = state.difficulty === 'easy' ? 400 : state.difficulty === 'hard' ? 600 : 500;
    setTimeout(() => {
      if (state.isGameOver) return;
      state.isThinking = false;
      if (els.thinkingIndicator) els.thinkingIndicator.style.display = 'none';
      const move = getCpuMove();
      if (move !== null) {
        applyMove(move, state.cpuSymbol);
      }
    }, delay);
  }

  function getEmptyCells(b = state.board) {
    const list = [];
    for (let i = 0; i < 9; i++) {
      if (b[i] === '') list.push(i);
    }
    return list;
  }

  function findWinningMove(sym, b = state.board) {
    const empty = getEmptyCells(b);
    for (const idx of empty) {
      b[idx] = sym;
      if (checkWin(sym, b)) {
        b[idx] = '';
        return idx;
      }
      b[idx] = '';
    }
    return null;
  }

  function findForkMove(sym, b = state.board) {
    const empty = getEmptyCells(b);
    if (empty.length < 5) return null;
    for (const idx of empty) {
      b[idx] = sym;
      let winCount = 0;
      for (const nextIdx of getEmptyCells(b)) {
        b[nextIdx] = sym;
        if (checkWin(sym, b)) winCount++;
        b[nextIdx] = '';
      }
      b[idx] = '';
      if (winCount >= 2) return idx;
    }
    return null;
  }

  function getCpuMove() {
    const empty = getEmptyCells();
    if (empty.length === 0) return null;

    if (state.difficulty === 'easy') {
      // 30% chance to block or win, otherwise random
      if (Math.random() < 0.3) {
        const win = findWinningMove(state.cpuSymbol);
        if (win !== null) return win;
        const block = findWinningMove(state.playerSymbol);
        if (block !== null) return block;
      }
      return empty[Math.floor(Math.random() * empty.length)];
    }

    if (state.difficulty === 'medium') {
      // 20% mistake chance
      if (Math.random() > 0.2) {
        const win = findWinningMove(state.cpuSymbol);
        if (win !== null) return win;
        const block = findWinningMove(state.playerSymbol);
        if (block !== null) return block;
        if (state.board[4] === '') return 4;
      }
      return empty[Math.floor(Math.random() * empty.length)];
    }

    // Hard AI (Optimal strategy)
    // 1. Winning move
    const win = findWinningMove(state.cpuSymbol);
    if (win !== null) return win;
    // 2. Block player's win
    const block = findWinningMove(state.playerSymbol);
    if (block !== null) return block;
    // 3. Create fork
    const fork = findForkMove(state.cpuSymbol);
    if (fork !== null) return fork;
    // 4. Block player's fork
    const blockFork = findForkMove(state.playerSymbol);
    if (blockFork !== null) return blockFork;
    // 5. Center
    if (state.board[4] === '') return 4;
    // 6. Opposite corner
    const corners = [0, 2, 6, 8];
    const playerCorners = corners.filter(c => state.board[c] === state.playerSymbol);
    if (playerCorners.length === 1) {
      const opp = { 0: 8, 2: 6, 6: 2, 8: 0 };
      if (state.board[opp[playerCorners[0]]] === '') return opp[playerCorners[0]];
    }
    // 7. Any corner
    const emptyCorners = corners.filter(c => state.board[c] === '');
    if (emptyCorners.length > 0) {
      return emptyCorners[Math.floor(Math.random() * emptyCorners.length)];
    }
    // 8. Random remaining
    return empty[Math.floor(Math.random() * empty.length)];
  }

  // --- Online 1v1 Networking via Socket.IO ---
  function initOnlineSocket() {
    if (state.socket) return;
    if (typeof io === 'undefined') return;

    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('ttt_room_joined', data => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.mySymbol = data.symbol;
      state.opponentJoined = !!data.guest_name;
      state.opponentName = data.is_host ? (data.guest_name || 'Opponent') : (data.host_name || 'Host');

      if (els.roomStatus) {
        els.roomStatus.textContent = state.opponentJoined
          ? `Playing vs ${state.opponentName} (You are ${state.mySymbol.toUpperCase()})`
          : `Waiting for opponent in room ${state.roomId}...`;
      }
      updateScoreboard();
      updateTurnDisplay();
    });

    state.socket.on('ttt_move_made', data => {
      state.board = data.board;
      state.turn = data.next_turn;
      state.scores = data.scores;
      playMoveSound(data.symbol);
      renderBoard();
      updateScoreboard();
      updateTurnDisplay();

      if (data.winner) {
        endGame(false, data.winner, data.win_pattern);
      } else if (data.is_draw) {
        endGame(true, null);
      }
    });

    state.socket.on('ttt_restarted', data => {
      resetGame();
      state.turn = data.turn || 'x';
      updateTurnDisplay();
    });

    state.socket.on('ttt_player_left', () => {
      state.opponentJoined = false;
      if (els.roomStatus) {
        els.roomStatus.textContent = 'Opponent disconnected. Waiting for a player...';
      }
    });

    state.socket.on('ttt_match_found', data => {
      state.isSearching = false;
      if (els.findMatchBtn) {
        els.findMatchBtn.textContent = 'Find Match';
        els.findMatchBtn.disabled = false;
      }
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.mySymbol = data.symbol;
      state.opponentJoined = true;
      state.opponentName = data.is_host ? data.guest_name : data.host_name;

      if (els.roomStatus) {
        els.roomStatus.textContent = `Match Found! Playing vs ${state.opponentName} (You are ${state.mySymbol.toUpperCase()})`;
      }
      resetGame();
    });

    state.socket.on('ttt_matchmaking_waiting', () => {
      state.isSearching = true;
      if (els.findMatchBtn) {
        els.findMatchBtn.textContent = 'Searching... (Cancel)';
      }
      if (els.roomStatus) {
        els.roomStatus.textContent = 'Searching for an opponent...';
      }
    });

    state.socket.on('ttt_matchmaking_cancelled', () => {
      state.isSearching = false;
      if (els.findMatchBtn) {
        els.findMatchBtn.textContent = 'Find Match';
        els.findMatchBtn.disabled = false;
      }
      if (els.roomStatus) {
        els.roomStatus.textContent = 'Matchmaking cancelled.';
      }
    });

    // Check URL room param
    const urlParams = new URLSearchParams(window.location.search);
    const roomParam = urlParams.get('room');
    if (roomParam) {
      joinRoom(roomParam);
    }
  }

  function joinRoom(roomId) {
    if (!state.socket) initOnlineSocket();
    if (!state.socket || !roomId) return;
    state.socket.emit('join_ttt_room', { room_id: roomId });
    if (els.roomCodeInput) els.roomCodeInput.value = roomId;
  }

  // --- Event Listeners Setup ---
  function setupEvents() {
    // Cells
    els.boardCells.forEach(cell => {
      const idx = parseInt(cell.getAttribute('data-index'), 10);
      cell.addEventListener('click', () => handleCellClick(idx));
      cell.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleCellClick(idx);
        }
      });
    });

    // Restart
    if (els.restartBtn) {
      els.restartBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('ttt_restart', { room_id: state.roomId });
        } else {
          resetGame();
        }
      });
    }

    if (els.nextRoundBtn) {
      els.nextRoundBtn.addEventListener('click', () => {
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('ttt_restart', { room_id: state.roomId });
        } else {
          resetGame();
        }
      });
    }

    // Mute
    if (els.muteToggleBtn) {
      els.muteToggleBtn.textContent = isMuted ? 'Unmute Sound' : 'Mute Sound';
      els.muteToggleBtn.addEventListener('click', () => {
        isMuted = !isMuted;
        localStorage.setItem('ew_ttt_muted', isMuted ? 'true' : 'false');
        els.muteToggleBtn.textContent = isMuted ? 'Unmute Sound' : 'Mute Sound';
      });
    }

    // Mode Tabs
    if (els.tabSolo) els.tabSolo.addEventListener('click', () => setMode('solo'));
    if (els.tabLocal) els.tabLocal.addEventListener('click', () => setMode('local'));
    if (els.tabOnline) els.tabOnline.addEventListener('click', () => setMode('online'));

    // Mark Picker
    if (els.pickX) {
      els.pickX.addEventListener('click', () => {
        state.playerSymbol = 'x';
        state.cpuSymbol = 'o';
        els.pickX.classList.add('active');
        if (els.pickO) els.pickO.classList.remove('active');
        resetGame();
      });
    }
    if (els.pickO) {
      els.pickO.addEventListener('click', () => {
        state.playerSymbol = 'o';
        state.cpuSymbol = 'x';
        els.pickO.classList.add('active');
        if (els.pickX) els.pickX.classList.remove('active');
        resetGame();
      });
    }

    // Difficulty Buttons
    els.diffButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const diff = btn.getAttribute('data-diff');
        state.difficulty = diff;
        els.diffButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        resetGame();
      });
    });

    // Online Controls
    if (els.findMatchBtn) {
      els.findMatchBtn.addEventListener('click', () => {
        if (!state.socket) initOnlineSocket();
        if (!state.socket) return;
        if (state.isSearching) {
          state.socket.emit('cancel_ttt_matchmaking');
        } else {
          state.socket.emit('find_ttt_match');
        }
      });
    }

    if (els.joinRoomBtn && els.roomCodeInput) {
      els.joinRoomBtn.addEventListener('click', () => {
        const code = els.roomCodeInput.value.trim();
        if (code) joinRoom(code);
      });
    }

    if (els.copyLinkBtn) {
      els.copyLinkBtn.addEventListener('click', () => {
        if (!state.roomId) {
          alert('Join or create a room first.');
          return;
        }
        const url = `${window.location.origin}/games/tic-tac-toe?room=${encodeURIComponent(state.roomId)}`;
        navigator.clipboard.writeText(url).then(() => {
          const original = els.copyLinkBtn.textContent;
          els.copyLinkBtn.textContent = 'Copied!';
          setTimeout(() => { els.copyLinkBtn.textContent = original; }, 1500);
        }).catch(() => {});
      });
    }
  }

  // --- Init ---
  document.addEventListener('DOMContentLoaded', () => {
    cacheElements();
    setupEvents();
    renderBoard();
    updateScoreboard();
    updateTurnDisplay();
    flushPendingSync();

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('room')) {
      setMode('online');
    }
  });

  // Export for testing
  window.__ttt = {
    getState: () => ({ ...state }),
    applyMove,
    resetGame,
    setMode,
    checkWin
  };
})();
