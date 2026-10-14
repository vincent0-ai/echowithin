(() => {
  'use strict';

  const starters = ['coffee', 'sunset', 'garden', 'music', 'journey', 'movie', 'beach', 'kitchen'];
  const state = {
    mode: 'local',
    socket: null,
    roomId: null,
    playerNum: 1,
    turn: 1,
    target: 12,
    chain: [],
    used: new Set()
  };

  const els = {};
  const params = new URLSearchParams(window.location.search);

  function initEls() {
    [
      'chain-turn-text', 'chain-online-status', 'chain-local-btn', 'chain-online-btn',
      'chain-room-input', 'chain-create-btn', 'chain-join-btn', 'chain-progress',
      'chain-next-letter', 'chain-list', 'chain-word-input', 'chain-submit-btn',
      'chain-message'
    ].forEach(id => { els[id] = document.getElementById(id); });
  }

  function setStatus(message, error = false) {
    if (!els['chain-message']) return;
    els['chain-message'].textContent = message || '';
    els['chain-message'].style.color = error ? 'var(--danger-color,#dc2626)' : 'var(--text-secondary)';
  }

  function setOnlineStatus(message, error = false) {
    if (!els['chain-online-status']) return;
    els['chain-online-status'].textContent = message || '';
    els['chain-online-status'].style.color = error ? 'var(--danger-color,#dc2626)' : 'var(--text-secondary)';
  }

  function normalizeWord(value) {
    return (value || '').toLowerCase().replace(/[^a-z]/g, '').slice(0, 24);
  }

  function startLocal() {
    state.mode = 'local';
    state.socket = state.socket || null;
    const starter = starters[Math.floor(Math.random() * starters.length)];
    state.chain = [starter];
    state.used = new Set([starter]);
    state.turn = 1;
    state.target = 12;
    state.playerNum = 1;
    setOnlineStatus('Pass & Play on this screen.');
    setStatus('');
    render();
  }

  function connectSocket() {
    if (state.socket || typeof io !== 'function') return;
    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('connect', () => {
      setOnlineStatus('Connected. Join or create a room.');
    });

    state.socket.on('chain_room_joined', data => {
      state.mode = 'online';
      state.roomId = data.room_id;
      state.playerNum = data.player_num || 1;
      state.chain = Array.isArray(data.chain) ? data.chain : [];
      state.used = new Set(state.chain);
      state.turn = data.turn || 1;
      state.target = data.target || 12;
      setOnlineStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for partner...');
      render();
    });

    state.socket.on('chain_partner_update', data => {
      setOnlineStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for partner...');
    });

    state.socket.on('chain_updated', data => {
      state.chain = Array.isArray(data.chain) ? data.chain : state.chain;
      state.used = new Set(state.chain);
      state.turn = data.turn || state.turn;
      state.target = data.target || state.target;
      setStatus(data.complete ? 'Chain complete. Nice teamwork.' : '');
      render();
    });

    state.socket.on('chain_error', data => {
      setStatus((data && data.message) || 'Could not add that word.', true);
    });

    state.socket.on('chain_partner_left', () => {
      setOnlineStatus('Partner left. Start a fresh room.', true);
    });

    window.addEventListener('beforeunload', () => {
      if (state.socket && state.roomId) {
        try { state.socket.emit('leave_chain_room', { room_id: state.roomId }); } catch (_) {}
      }
    });
  }

  function joinRoom(roomId) {
    const code = (roomId || '').trim();
    if (!code) {
      setStatus('Enter a room code.', true);
      return;
    }
    connectSocket();
    if (!state.socket) {
      setOnlineStatus('Live play is unavailable. Please reconnect and retry.', true);
      return;
    }
    state.roomId = code;
    state.socket.emit('chain_join_room', {
      room_id: code,
      bond_id: params.get('bond_id') || undefined
    });
  }

  function submitWord() {
    const input = els['chain-word-input'];
    const word = normalizeWord(input ? input.value : '');
    if (!word) return;
    if (state.mode === 'online') {
      if (state.turn !== state.playerNum) {
        setStatus('It is your partner turn.', true);
        return;
      }
      state.socket.emit('chain_submit_word', { room_id: state.roomId, word });
      if (input) input.value = '';
      return;
    }

    const previous = state.chain[state.chain.length - 1] || '';
    const expected = previous.slice(-1);
    if (word.length < 3) {
      setStatus('Use at least 3 letters.', true);
      return;
    }
    if (previous && !word.startsWith(expected)) {
      setStatus(`Word must start with "${expected.toUpperCase()}".`, true);
      return;
    }
    if (state.used.has(word)) {
      setStatus('That word was already used.', true);
      return;
    }
    state.chain.push(word);
    state.used.add(word);
    state.turn = state.turn === 1 ? 2 : 1;
    if (input) input.value = '';
    setStatus(state.chain.length >= state.target ? 'Chain complete. Nice teamwork.' : '');
    render();
  }

  function render() {
    const last = state.chain[state.chain.length - 1] || '';
    const complete = state.chain.length >= state.target;
    if (els['chain-list']) {
      els['chain-list'].innerHTML = state.chain.map(word => `<span class="chain-word">${word}</span>`).join('');
    }
    if (els['chain-progress']) {
      els['chain-progress'].textContent = `${Math.min(state.chain.length, state.target)} / ${state.target} words`;
    }
    if (els['chain-next-letter']) {
      els['chain-next-letter'].textContent = complete ? 'Complete' : `Next letter: ${last ? last.slice(-1).toUpperCase() : '-'}`;
    }
    if (els['chain-turn-text']) {
      if (complete) {
        els['chain-turn-text'].textContent = 'Chain complete';
      } else if (state.mode === 'online') {
        els['chain-turn-text'].textContent = state.turn === state.playerNum ? 'Your turn' : 'Partner turn';
      } else {
        els['chain-turn-text'].textContent = `Player ${state.turn} turn`;
      }
    }
    if (els['chain-word-input']) {
      els['chain-word-input'].placeholder = last ? `Word starting with ${last.slice(-1).toUpperCase()}` : 'Type next word';
      els['chain-word-input'].disabled = complete || (state.mode === 'online' && state.turn !== state.playerNum);
    }
    if (els['chain-submit-btn']) {
      els['chain-submit-btn'].disabled = complete || (state.mode === 'online' && state.turn !== state.playerNum);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    initEls();

    els['chain-local-btn']?.addEventListener('click', startLocal);
    els['chain-online-btn']?.addEventListener('click', () => {
      state.mode = 'online';
      connectSocket();
      setOnlineStatus('Create a room or enter a code.');
    });
    els['chain-create-btn']?.addEventListener('click', () => {
      const code = `chain_${Math.random().toString(36).slice(2, 6)}`;
      if (els['chain-room-input']) els['chain-room-input'].value = code;
      joinRoom(code);
    });
    els['chain-join-btn']?.addEventListener('click', () => joinRoom(els['chain-room-input']?.value));
    els['chain-submit-btn']?.addEventListener('click', submitWord);
    els['chain-word-input']?.addEventListener('keydown', e => {
      if (e.key === 'Enter') submitWord();
    });

    const roomParam = params.get('room');
    if (roomParam) {
      if (els['chain-room-input']) els['chain-room-input'].value = roomParam;
      joinRoom(roomParam);
    } else {
      startLocal();
    }
  });
})();
