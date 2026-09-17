/**
 * Word Bond: Duet for EchoWithin
 * Cooperative 2-Player Word Deduction based on Codenames Duet
 * Zero external dependencies — pure vanilla JavaScript & WebSockets.
 */
(() => {
  'use strict';

  // --- Curated Wholesome Word Bank (~400 clean, evocative nouns) ---
  const WORD_BANK = [
    'Coffee', 'Starlight', 'Blanket', 'Forest', 'Whispers', 'Journey', 'Passport', 'Symphony', 'Key', 'Horizon',
    'Moon', 'Garden', 'Canvas', 'Bridge', 'Echo', 'Treasure', 'Lighthouse', 'Sunset', 'Mountain', 'Melody',
    'Clock', 'Spark', 'Compass', 'Feather', 'Velvet', 'Castle', 'Island', 'Rain', 'River', 'Story',
    'Dream', 'Secret', 'Mirror', 'Lantern', 'Shadow', 'Flame', 'Anchor', 'Harbor', 'Window', 'Breeze',
    'Meadow', 'Tower', 'Crown', 'Silver', 'Golden', 'Ocean', 'Desert', 'Valley', 'Galaxy', 'Puzzle',
    'Map', 'Letter', 'Guitar', 'Piano', 'Feast', 'Orchard', 'Sunrise', 'Cloud', 'Stone', 'Cottage',
    'Library', 'Candle', 'Ribbon', 'Planet', 'Comet', 'Dawn', 'Dusk', 'Cabin', 'Glacier', 'Oasis',
    'Path', 'Stream', 'Shore', 'Haven', 'Voyage', 'Orbit', 'Song', 'Poem', 'Ring', 'Diamond',
    'Pearl', 'Amber', 'Crystal', 'Marble', 'Velvet', 'Silk', 'Locket', 'Diary', 'Compass', 'Whistle',
    'Shield', 'Armor', 'Scroll', 'Tablet', 'Chest', 'Crown', 'Scepter', 'Bell', 'Chime', 'Harp',
    'Flute', 'Violin', 'Drum', 'Trumpet', 'Stage', 'Curtain', 'Balcony', 'Gardenia', 'Orchid', 'Jasmine',
    'Rose', 'Tulip', 'Lotus', 'Sunflower', 'Daisy', 'Cedar', 'Willow', 'Pine', 'Oak', 'Maple',
    'Canyon', 'Volcano', 'Cavern', 'Fountain', 'Grotto', 'Palace', 'Temple', 'Chapel', 'Harbor', 'Bay',
    'Cove', 'Lagoon', 'Arch', 'Column', 'Statue', 'Gallery', 'Museum', 'Market', 'Village', 'Plaza',
    'Cafe', 'Bistro', 'Bakery', 'Teapot', 'Cup', 'Chalice', 'Goblet', 'Flask', 'Kettle', 'Plate',
    'Honey', 'Berry', 'Apple', 'Peach', 'Cherry', 'Vanilla', 'Cinnamon', 'Almond', 'Olive', 'Basil',
    'Mint', 'Lavender', 'Thyme', 'Ginger', 'Pepper', 'Sugar', 'Caramel', 'Chocolate', 'Pastry', 'Bread',
    'Bicycle', 'Carriage', 'Train', 'Vessel', 'Ship', 'Sail', 'Mast', 'Rudder', 'Helm', 'Wheel',
    'Pillow', 'Quilt', 'Hearth', 'Fireplace', 'Chimney', 'Attic', 'Porch', 'Roof', 'Gate', 'Fence',
    'Basket', 'Hamper', 'Satchel', 'Pocket', 'Scarf', 'Glove', 'Cloak', 'Boot', 'Shoe', 'Sandal',
    'Crown', 'Diadem', 'Bracelet', 'Necklace', 'Brooch', 'Earring', 'Mirror', 'Comb', 'Brush', 'Ribbon',
    'Kite', 'Balloon', 'Globe', 'Atlas', 'Chronicle', 'Novel', 'Scroll', 'Tome', 'Ledger', 'Journal',
    'Hourglass', 'Sundial', 'Pendulum', 'Needle', 'Thread', 'Spool', 'Loom', 'Weave', 'Fabric', 'Tapestry',
    'Palette', 'Easel', 'Brush', 'Chisel', 'Mosaic', 'Pottery', 'Clay', 'Vase', 'Urn', 'Pitcher',
    'Gazebo', 'Pavilion', 'Greenhouse', 'Conservatory', 'Solarium', 'Terrace', 'Veranda', 'Courtyard', 'Fountain', 'Well',
    'Spring', 'Brook', 'Creek', 'Waterfall', 'Cascade', 'Rapids', 'Delta', 'Estuary', 'Tide', 'Wave',
    'Ripple', 'Surf', 'Foam', 'Mist', 'Fog', 'Haze', 'Vapor', 'Frost', 'Snow', 'Blizzard',
    'Breeze', 'Zephyr', 'Gale', 'Storm', 'Thunder', 'Lightning', 'Rainbow', 'Halo', 'Aurora', 'Eclipse',
    'Meteor', 'Cosmos', 'Nebula', 'Zenith', 'Nadir', 'Equator', 'Polar', 'Tropic', 'Solstice', 'Equinox',
    'Sanctuary', 'Refuge', 'Shelter', 'Retreat', 'Hideaway', 'Haven', 'Harbor', 'Port', 'Anchor', 'Dock'
  ];

  // --- Seedable Pseudo-Random Number Generator (Mulberry32) ---
  function createRng(seed) {
    let s = Math.abs(Number(seed) || 123456789);
    return function () {
      s = (s + 0x6D2B79F5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // --- Game State ---
  const state = {
    mode: 'online', // 'online', 'pass', 'solo'
    seed: Math.floor(Math.random() * 1000000),
    words: [], // 25 words
    // Keycard types: 'green', 'assassin', 'bystander'
    keycardA: [], // 25 types from Side A's perspective
    keycardB: [], // 25 types from Side B's perspective
    revealed: [], // 25 entries: null or 'green' | 'assassin' | 'bystander'
    mySide: 'A', // 'A' or 'B'
    activeGiver: 'A', // which side gives the clue this turn
    activePhase: 'clue', // 'clue' or 'guess'
    currentClue: null, // { word: 'OCEAN', count: 2 }
    guessesRemaining: 0,
    tokensLeft: 9,
    agentsFound: 0,
    isGameOver: false,
    isVictory: false,
    showKey: true,
    socket: null,
    roomId: null,
    isHost: true
  };

  /**
   * Generates a deterministic 5x5 board and dual keycards matching
   * Codenames Duet canonical distribution.
   */
  function generateBoard(seed) {
    const rng = createRng(seed);

    // Pick 25 unique words
    const shuffledWords = [...WORD_BANK];
    for (let i = shuffledWords.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [shuffledWords[i], shuffledWords[j]] = [shuffledWords[j], shuffledWords[i]];
    }
    const words = shuffledWords.slice(0, 25);

    // Create 25 slot distributions matching canonical Duet:
    // 3: Green / Green
    // 1: Assassin / Assassin
    // 1: Green / Assassin
    // 1: Assassin / Green
    // 5: Green / Bystander
    // 5: Bystander / Green
    // 1: Assassin / Bystander
    // 1: Bystander / Assassin
    // 7: Bystander / Bystander
    const slots = [
      ...Array(3).fill(['green', 'green']),
      ...Array(1).fill(['assassin', 'assassin']),
      ...Array(1).fill(['green', 'assassin']),
      ...Array(1).fill(['assassin', 'green']),
      ...Array(5).fill(['green', 'bystander']),
      ...Array(5).fill(['bystander', 'green']),
      ...Array(1).fill(['assassin', 'bystander']),
      ...Array(1).fill(['bystander', 'assassin']),
      ...Array(7).fill(['bystander', 'bystander'])
    ];

    // Shuffle slot pairings
    for (let i = slots.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [slots[i], slots[j]] = [slots[j], slots[i]];
    }

    const keycardA = slots.map(s => s[0]);
    const keycardB = slots.map(s => s[1]);
    const revealed = Array(25).fill(null);

    return { words, keycardA, keycardB, revealed };
  }

  // --- UI Renderers ---

  function initBoard() {
    const container = document.getElementById('duet-board');
    if (!container) return;
    container.innerHTML = '';

    state.words.forEach((word, idx) => {
      const card = document.createElement('div');
      card.className = 'duet-card';
      card.id = `duet-card-${idx}`;
      card.dataset.idx = idx;

      // Card word label
      const label = document.createElement('div');
      label.className = 'duet-card-word';
      label.textContent = word;
      card.appendChild(label);

      // Keycard pip (for clue-giving assistance)
      const pip = document.createElement('div');
      pip.className = 'duet-key-pip';
      pip.id = `duet-pip-${idx}`;
      card.appendChild(pip);

      card.addEventListener('click', () => onCardClicked(idx));
      container.appendChild(card);
    });

    updateBoardDisplay();
  }

  function updateBoardDisplay() {
    const container = document.getElementById('duet-board');
    if (container) {
      if (state.showKey) {
        container.classList.add('show-key');
      } else {
        container.classList.remove('show-key');
      }
    }

    const myKey = (state.mySide === 'A') ? state.keycardA : state.keycardB;

    state.words.forEach((_, idx) => {
      const card = document.getElementById(`duet-card-${idx}`);
      const pip = document.getElementById(`duet-pip-${idx}`);
      if (!card || !pip) return;

      // Update key pip color
      const type = myKey[idx];
      pip.className = `duet-key-pip pip-${type === 'green' ? 'green' : (type === 'assassin' ? 'black' : 'tan')}`;

      // Update revealed status
      const rev = state.revealed[idx];
      card.classList.remove('guessed-green', 'guessed-bystander', 'guessed-assassin');
      if (rev === 'green') {
        card.classList.add('guessed-green');
      } else if (rev === 'bystander') {
        card.classList.add('guessed-bystander');
      } else if (rev === 'assassin') {
        card.classList.add('guessed-assassin');
      }
    });

    updateStatusUI();
  }

  function updateStatusUI() {
    // Agents found
    const agentsEl = document.getElementById('duet-agents-count');
    if (agentsEl) agentsEl.textContent = `${state.agentsFound} / 15`;

    // Tokens
    const tokensContainer = document.getElementById('duet-tokens-container');
    if (tokensContainer) {
      tokensContainer.innerHTML = '';
      for (let i = 0; i < 9; i++) {
        const tok = document.createElement('span');
        tok.className = (i < state.tokensLeft) ? 'duet-token' : 'duet-token spent';
        tok.textContent = (i + 1);
        tokensContainer.appendChild(tok);
      }
    }

    // Role text & Phase bars
    const turnText = document.getElementById('duet-turn-text');
    const roleText = document.getElementById('duet-role-text');
    const avatar = document.getElementById('duet-turn-avatar');
    const activeClueBar = document.getElementById('duet-active-clue-bar');
    const giveClueBar = document.getElementById('duet-give-clue-bar');

    const isMyTurnToGiveClue = (state.activeGiver === state.mySide) && (state.activePhase === 'clue');
    const isMyTurnToGuess = (state.activeGiver !== state.mySide) && (state.activePhase === 'guess');

    if (avatar) {
      avatar.style.background = isMyTurnToGiveClue ? '#2e86ab' : (isMyTurnToGuess ? '#e06a3b' : '#8c7d6b');
    }

    if (state.mode === 'pass') {
      if (state.activePhase === 'clue') {
        if (turnText) turnText.textContent = `Side ${state.activeGiver}'s Turn: Give a Clue`;
        if (roleText) roleText.textContent = `Inspect your keycard and enter 1 word + number of cards.`;
      } else {
        const guesser = (state.activeGiver === 'A') ? 'B' : 'A';
        if (turnText) turnText.textContent = `Side ${guesser}'s Turn: Guessing Cards`;
        if (roleText) roleText.textContent = `Tap cards matching the clue. Tap "Pass" when done.`;
      }
    } else {
      if (state.activePhase === 'clue') {
        if (isMyTurnToGiveClue) {
          if (turnText) turnText.textContent = 'Your Turn: Give a Clue';
          if (roleText) roleText.textContent = 'Pick green cards from your key and type a single-word hint.';
        } else {
          if (turnText) turnText.textContent = 'Partner is thinking of a clue...';
          if (roleText) roleText.textContent = 'Waiting for your partner to submit a clue and count.';
        }
      } else {
        if (isMyTurnToGuess) {
          if (turnText) turnText.textContent = 'Your Turn: Guess Cards!';
          if (roleText) roleText.textContent = 'Tap the cards that fit your partner\'s clue.';
        } else {
          if (turnText) turnText.textContent = 'Partner is guessing cards...';
          if (roleText) roleText.textContent = 'Watch live as your partner uncovers your clues.';
        }
      }
    }

    // Toggle Input bars
    if (giveClueBar) {
      giveClueBar.style.display = (state.activePhase === 'clue' && (isMyTurnToGiveClue || state.mode === 'pass' || state.mode === 'solo')) ? 'block' : 'none';
    }
    if (activeClueBar) {
      activeClueBar.style.display = (state.activePhase === 'guess') ? 'block' : 'none';
      if (state.currentClue) {
        const display = document.getElementById('duet-clue-display');
        const countDisplay = document.getElementById('duet-guesses-left');
        if (display) display.textContent = `${state.currentClue.word} • ${state.currentClue.count}`;
        if (countDisplay) countDisplay.textContent = `(Guesses remaining: ${state.guessesRemaining})`;
      }
    }
  }

  // --- Core Game Logic ---

  function startNewGame(seed = null) {
    state.seed = (seed !== null) ? seed : Math.floor(Math.random() * 1000000);
    const board = generateBoard(state.seed);
    state.words = board.words;
    state.keycardA = board.keycardA;
    state.keycardB = board.keycardB;
    state.revealed = board.revealed;
    state.activeGiver = 'A';
    state.activePhase = 'clue';
    state.currentClue = null;
    state.guessesRemaining = 0;
    state.tokensLeft = 9;
    state.agentsFound = 0;
    state.isGameOver = false;
    state.isVictory = false;

    hideGameOverModal();
    initBoard();
  }

  function onCardClicked(idx) {
    if (state.isGameOver) return;
    if (state.activePhase !== 'guess') return;
    if (state.revealed[idx] !== null) return; // already revealed

    // Check permissions
    if (state.mode === 'online') {
      const isMyTurnToGuess = (state.activeGiver !== state.mySide);
      if (!isMyTurnToGuess) return;
      if (state.socket && state.roomId) {
        state.socket.emit('duet_guess_card', { room_id: state.roomId, card_idx: idx });
      }
      return;
    }

    // Pass and Play or Solo
    applyCardGuess(idx);
  }

  function applyCardGuess(idx) {
    if (state.revealed[idx] !== null) return;

    // The card is judged against the CLUE GIVER's keycard!
    const giverKey = (state.activeGiver === 'A') ? state.keycardA : state.keycardB;
    const result = giverKey[idx]; // 'green', 'bystander', 'assassin'

    state.revealed[idx] = result;

    if (result === 'green') {
      state.agentsFound++;
      state.guessesRemaining--;

      // Check win condition (all 15 agents found)
      if (state.agentsFound >= 15) {
        state.isGameOver = true;
        state.isVictory = true;
        updateBoardDisplay();
        showGameOverModal(true, 'Incredible teamwork! You found all 15 agents.');
        return;
      }

      // Can continue guessing if guesses remaining > 0, otherwise turn ends
      if (state.guessesRemaining <= 0) {
        endTurn();
      } else {
        updateBoardDisplay();
      }
    } else if (result === 'bystander') {
      // Turn ends immediately on bystander
      state.tokensLeft--;
      if (state.tokensLeft <= 0) {
        state.isGameOver = true;
        state.isVictory = false;
        updateBoardDisplay();
        showGameOverModal(false, 'Out of time tokens! The mission ran out of time.');
        return;
      }
      endTurn();
    } else if (result === 'assassin') {
      // Immediate loss
      state.isGameOver = true;
      state.isVictory = false;
      updateBoardDisplay();
      showGameOverModal(false, 'Mission compromised! An assassin was uncovered.');
    }
  }

  function submitClue(word, count) {
    word = (word || '').trim().toUpperCase();
    count = parseInt(count, 10);
    if (!word) {
      alert('Please enter a one-word clue.');
      return;
    }
    if (word.includes(' ')) {
      alert('Clues must be a single word (no spaces).');
      return;
    }

    if (state.mode === 'online') {
      if (state.socket && state.roomId) {
        state.socket.emit('duet_give_clue', {
          room_id: state.roomId,
          clue: word,
          count: count
        });
      }
      return;
    }

    applyClue(word, count);
  }

  function applyClue(word, count) {
    state.currentClue = { word, count };
    state.guessesRemaining = (count === 0) ? 99 : (count + 1); // 1 bonus guess allowed
    state.activePhase = 'guess';
    updateBoardDisplay();
  }

  function endTurn() {
    if (state.mode === 'online') {
      if (state.socket && state.roomId) {
        state.socket.emit('duet_end_turn', { room_id: state.roomId });
      }
      return;
    }
    applyEndTurn();
  }

  function applyEndTurn() {
    state.activeGiver = (state.activeGiver === 'A') ? 'B' : 'A';
    state.activePhase = 'clue';
    state.currentClue = null;
    state.guessesRemaining = 0;

    // In pass and play, swap side so clue giver sees their key
    if (state.mode === 'pass') {
      state.mySide = state.activeGiver;
    }

    updateBoardDisplay();
  }

  function showGameOverModal(isVictory, message) {
    const modal = document.getElementById('duet-game-over-modal');
    const icon = document.getElementById('duet-modal-icon');
    const title = document.getElementById('duet-modal-title');
    const body = document.getElementById('duet-modal-body');

    if (modal) {
      if (icon) icon.textContent = isVictory ? '🎉' : '💀';
      if (title) title.textContent = isVictory ? 'Mission Accomplished!' : 'Mission Failed';
      if (body) body.textContent = message;
      modal.style.display = 'flex';
    }
  }

  function hideGameOverModal() {
    const modal = document.getElementById('duet-game-over-modal');
    if (modal) modal.style.display = 'none';
  }

  // --- Socket.IO Online Multi-Room System ---

  function connectSocket() {
    if (state.socket) return;
    if (typeof io !== 'function') return;

    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('connect', () => {
      const statusEl = document.getElementById('duet-online-status');
      if (statusEl) statusEl.textContent = 'Connected to server. Ready to join room.';
    });

    state.socket.on('duet_room_joined', (data) => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.mySide = data.side || (data.is_host ? 'A' : 'B');

      const statusEl = document.getElementById('duet-online-status');
      if (statusEl) {
        statusEl.textContent = `Room: ${data.room_id} | Playing Side ${state.mySide} vs ${data.partner_name || 'Partner'}`;
        statusEl.style.color = '#15803d';
      }

      if (data.seed !== undefined) {
        startNewGame(data.seed);
      }
    });

    state.socket.on('duet_clue_given', (data) => {
      applyClue(data.clue, data.count);
    });

    state.socket.on('duet_card_guessed', (data) => {
      applyCardGuess(data.card_idx);
    });

    state.socket.on('duet_turn_ended', () => {
      applyEndTurn();
    });

    state.socket.on('duet_restarted', (data) => {
      startNewGame(data.seed);
    });

    state.socket.on('duet_partner_left', () => {
      const statusEl = document.getElementById('duet-online-status');
      if (statusEl) {
        statusEl.textContent = 'Partner left the room.';
        statusEl.style.color = '#b8423f';
      }
    });
  }

  function joinRoom(roomId) {
    if (!roomId) return;
    connectSocket();
    state.roomId = roomId;
    if (state.socket) {
      state.socket.emit('join_duet_room', { room_id: roomId });
    }
  }

  // --- DOM Setup & Event Listeners ---

  document.addEventListener('DOMContentLoaded', () => {
    // Mode tabs
    const tabOnline = document.getElementById('tab-duet-online');
    const tabPass = document.getElementById('tab-duet-pass');
    const tabSolo = document.getElementById('tab-duet-solo');
    const onlinePanel = document.getElementById('duet-online-panel');

    function setActiveTab(activeBtn) {
      [tabOnline, tabPass, tabSolo].forEach(btn => {
        if (!btn) return;
        btn.className = (btn === activeBtn) ? 'ew-btn ew-btn--sm mode-tab' : 'ew-btn--outline ew-btn--sm mode-tab';
      });
    }

    if (tabOnline) {
      tabOnline.addEventListener('click', () => {
        setActiveTab(tabOnline);
        state.mode = 'online';
        if (onlinePanel) onlinePanel.style.display = 'block';
        connectSocket();
        updateBoardDisplay();
      });
    }

    if (tabPass) {
      tabPass.addEventListener('click', () => {
        setActiveTab(tabPass);
        state.mode = 'pass';
        if (onlinePanel) onlinePanel.style.display = 'none';
        state.mySide = state.activeGiver;
        updateBoardDisplay();
      });
    }

    if (tabSolo) {
      tabSolo.addEventListener('click', () => {
        setActiveTab(tabSolo);
        state.mode = 'solo';
        if (onlinePanel) onlinePanel.style.display = 'none';
        state.mySide = 'A';
        updateBoardDisplay();
      });
    }

    // Toggle Keycard
    const toggleKeyBtn = document.getElementById('duet-toggle-key-btn');
    if (toggleKeyBtn) {
      toggleKeyBtn.addEventListener('click', () => {
        state.showKey = !state.showKey;
        toggleKeyBtn.textContent = state.showKey ? '👁️ Show My Clue Key' : '🙈 Hide My Clue Key';
        updateBoardDisplay();
      });
    }

    // Clue Submission
    const sendClueBtn = document.getElementById('duet-send-clue-btn');
    const clueWordInput = document.getElementById('duet-clue-word-input');
    const clueCountInput = document.getElementById('duet-clue-count-input');

    if (sendClueBtn && clueWordInput && clueCountInput) {
      sendClueBtn.addEventListener('click', () => {
        submitClue(clueWordInput.value, clueCountInput.value);
        clueWordInput.value = '';
      });
      clueWordInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          submitClue(clueWordInput.value, clueCountInput.value);
          clueWordInput.value = '';
        }
      });
    }

    // End Turn (Pass)
    const endTurnBtn = document.getElementById('duet-end-turn-btn');
    if (endTurnBtn) {
      endTurnBtn.addEventListener('click', endTurn);
    }

    // New Game / Play Again
    const newGameBtn = document.getElementById('duet-new-game-btn');
    const playAgainBtn = document.getElementById('duet-modal-play-again-btn');

    function handleRestart() {
      const newSeed = Math.floor(Math.random() * 1000000);
      if (state.mode === 'online' && state.socket && state.roomId) {
        state.socket.emit('duet_restart', { room_id: state.roomId, seed: newSeed });
      } else {
        startNewGame(newSeed);
      }
    }

    if (newGameBtn) newGameBtn.addEventListener('click', handleRestart);
    if (playAgainBtn) playAgainBtn.addEventListener('click', handleRestart);

    // Online room management
    const createRoomBtn = document.getElementById('duet-create-room-btn');
    const joinRoomBtn = document.getElementById('duet-join-room-btn');
    const roomInput = document.getElementById('duet-room-input');
    const findMatchBtn = document.getElementById('duet-find-match-btn');

    if (createRoomBtn && roomInput) {
      createRoomBtn.addEventListener('click', () => {
        const code = Math.random().toString(36).substring(2, 8);
        roomInput.value = code;
        joinRoom(code);
      });
    }

    if (joinRoomBtn && roomInput) {
      joinRoomBtn.addEventListener('click', () => {
        const code = (roomInput.value || '').trim();
        if (!code) {
          alert('Please enter a room code.');
          return;
        }
        joinRoom(code);
      });
    }

    if (findMatchBtn && roomInput) {
      findMatchBtn.addEventListener('click', () => {
        const code = 'duet_' + Math.random().toString(36).substring(2, 6);
        roomInput.value = code;
        joinRoom(code);
      });
    }

    // URL room code param
    const urlParams = new URLSearchParams(window.location.search);
    const roomParam = urlParams.get('room');
    if (roomParam) {
      if (roomInput) roomInput.value = roomParam;
      joinRoom(roomParam);
    } else {
      // Start initial board
      startNewGame();
    }
  });

  // Expose minimal API for debugging
  window.__wordDuet = {
    getState: () => state,
    startNewGame: startNewGame,
    joinRoom: joinRoom
  };
})();
