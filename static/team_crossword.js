/**
 * Team Crossword for EchoWithin
 * Real-time Collaborative 5x5 Mini Crosswords for Couples
 * Zero external dependencies — pure vanilla JavaScript & WebSockets.
 */
(() => {
  'use strict';

  // --- Curated Built-In Mini Crossword Pack (5x5 Grids) ---
  const PUZZLES = [
    {
      id: 'mini_1',
      title: 'Sweethearts',
      size: 5,
      // Grid:
      // H E A R T
      // O M E G A
      // N O V E L
      // E L I T E
      // Y E A S T
      solution: [
        'H','E','A','R','T',
        'O','M','E','G','A',
        'N','O','V','E','L',
        'E','L','I','T','E',
        'Y','E','A','S','T'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Symbol of romance and love' },
          { num: 6, r: 1, c: 0, clue: 'Final letter of the Greek alphabet' },
          { num: 7, r: 2, c: 0, clue: 'Bedtime reading material' },
          { num: 8, r: 3, c: 0, clue: 'Select group or top tier' },
          { num: 9, r: 4, c: 0, clue: 'Bread-making organism' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Sweet term of endearment' },
          { num: 2, r: 0, c: 1, clue: 'Whole or complete amount' },
          { num: 3, r: 0, c: 2, clue: 'A single flight on an airplane' },
          { num: 4, r: 0, c: 3, clue: 'Avenue or highway' },
          { num: 5, r: 0, c: 4, clue: 'Sample a cup of wine or dessert' }
        ]
      }
    },
    {
      id: 'mini_2',
      title: 'Morning Coffee',
      size: 5,
      // B E A N S
      // E A G L E
      // A M U S E
      // N U T M Y  -> N U D G E
      // S E E D S
      solution: [
        'B','E','A','N','S',
        'E','A','G','L','E',
        'A','M','U','S','E',
        'C','A','F','E','S',
        'H','O','F','F','S'
      ],
      // Better clean 5x5:
      // S M I L E
      // H A V E N
      // A D O R E
      // R O U N D
      // E N T E R
      solution: [
        'S','M','I','L','E',
        'H','A','V','E','N',
        'A','D','O','R','E',
        'R','O','U','N','D',
        'E','N','T','E','R'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Warm greeting on your partner’s face' },
          { num: 6, r: 1, c: 0, clue: 'Peaceful sanctuary or safe retreat' },
          { num: 7, r: 2, c: 0, clue: 'Love deeply and cherish' },
          { num: 8, r: 3, c: 0, clue: 'Circular, like a wedding ring' },
          { num: 9, r: 4, c: 0, clue: 'Walk through the front door' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Give a portion to your partner' },
          { num: 2, r: 0, c: 1, clue: 'Madly in love' },
          { num: 3, r: 0, c: 2, clue: 'Ivory tower resident' },
          { num: 4, r: 0, c: 3, clue: 'Acquire knowledge together' },
          { num: 5, r: 0, c: 4, clue: 'Conclusion of a romantic film' }
        ]
      }
    },
    {
      id: 'mini_3',
      title: 'Weekend Getaway',
      size: 5,
      // C A B I N
      // A R O M A
      // B E A C H
      // I M B U E
      // N A P E S
      solution: [
        'C','A','B','I','N',
        'A','R','O','M','A',
        'B','E','A','C','H',
        'I','M','B','U','E',
        'N','A','P','E','S'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Cozy wooden shelter in the woods' },
          { num: 6, r: 1, c: 0, clue: 'Pleasant fragrance of breakfast' },
          { num: 7, r: 2, c: 0, clue: 'Sandy shore for long romantic strolls' },
          { num: 8, r: 3, c: 0, clue: 'Inspire or saturate with feeling' },
          { num: 9, r: 4, c: 0, clue: 'Backs of necks' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Cozy place to sleep on a train' },
          { num: 2, r: 0, c: 1, clue: 'A single flower or branch on a tree' },
          { num: 3, r: 0, c: 2, clue: 'Small fruit in blueberry pancakes' },
          { num: 4, r: 0, c: 3, clue: 'Glacier ice or polar formation' },
          { num: 5, r: 0, c: 4, clue: 'Birds’ cozy resting perches' }
        ]
      }
    },
    {
      id: 'mini_4',
      title: 'Starlight Walk',
      size: 5,
      // M O O N S
      // O A S I S
      // O C E A N
      // N I G H T
      // S T A R S
      solution: [
        'M','O','O','N','S',
        'O','A','S','I','S',
        'O','C','E','A','N',
        'N','I','G','H','T',
        'S','T','A','R','S'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Nighttime glowing celestial bodies' },
          { num: 6, r: 1, c: 0, clue: 'Fertile haven in the desert' },
          { num: 7, r: 2, c: 0, clue: 'Vast body of saltwater' },
          { num: 8, r: 3, c: 0, clue: 'When the stars come out' },
          { num: 9, r: 4, c: 0, clue: 'Twinkling lights in the clear sky' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Atmosphere or emotional state' },
          { num: 2, r: 0, c: 1, clue: 'Hardwood trees in autumn' },
          { num: 3, r: 0, c: 2, clue: 'Greek god of wild nature' },
          { num: 4, r: 0, c: 3, clue: 'Dusk before bedtime' },
          { num: 5, r: 0, c: 4, clue: 'Tidies up the kitchen together' }
        ]
      }
    },
    {
      id: 'mini_5',
      title: 'Cozy Evening',
      size: 5,
      // P I A N O
      // I C I N G
      // A M B E R
      // N E R D Y
      // O G R E S
      solution: [
        'P','I','A','N','O',
        'I','C','I','N','G',
        'A','M','B','E','R',
        'N','E','R','D','Y',
        'O','G','R','E','S'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Musical instrument with 88 keys' },
          { num: 6, r: 1, c: 0, clue: 'Sweet frosting on birthday cake' },
          { num: 7, r: 2, c: 0, clue: 'Warm golden gemstone' },
          { num: 8, r: 3, c: 0, clue: 'Endearing love of trivia and games' },
          { num: 9, r: 4, c: 0, clue: 'Fantasy folklore giants' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Instrument played with two sticks' },
          { num: 2, r: 0, c: 1, clue: 'Cold winter treat' },
          { num: 3, r: 0, c: 2, clue: 'Yellow fall tree leaf' },
          { num: 4, r: 0, c: 3, clue: 'Requirement or necessity' },
          { num: 5, r: 0, c: 4, clue: 'Fairytale creatures' }
        ]
      }
    },
    {
      id: 'mini_6',
      title: 'Seaside Breeze',
      size: 5,
      solution: [
        'T','I','D','E','S',
        'I','S','L','E','S',
        'D','A','N','C','E',
        'E','V','E','N','T',
        'S','S','S','S','S'
      ],
      // Clean classical cross:
      solution: [
        'C','R','O','W','N',
        'R','A','D','I','O',
        'O','V','A','T','E',
        'W','I','T','C','H',
        'N','O','E','H','S'
      ],
      solution: [
        'S','P','A','R','K',
        'P','L','A','N','E',
        'A','U','D','I','O',
        'R','I','S','E','N',
        'K','N','E','E','S'
      ],
      clues: {
        across: [
          { num: 1, r: 0, c: 0, clue: 'Chemistry between two soulmates' },
          { num: 6, r: 1, c: 0, clue: 'Jetliner to a romantic holiday' },
          { num: 7, r: 2, c: 0, clue: 'Sound from favorite speakers' },
          { num: 8, r: 3, c: 0, clue: 'Awakened with the morning sun' },
          { num: 9, r: 4, c: 0, clue: 'Joints supporting a dance twirl' }
        ],
        down: [
          { num: 1, r: 0, c: 0, clue: 'Firework glow' },
          { num: 2, r: 0, c: 1, clue: 'Folded pastry or paper crease' },
          { num: 3, r: 0, c: 2, clue: 'Daily love affirmation' },
          { num: 4, r: 0, c: 3, clue: 'Sprint to the finish line' },
          { num: 5, r: 0, c: 4, clue: 'Family members and relatives' }
        ]
      }
    }
  ];

  // --- Game State ---
  const state = {
    mode: 'online', // 'online', 'solo'
    puzzleIdx: 0,
    puzzle: PUZZLES[0],
    grid: Array(25).fill(''),
    cursor: { r: 0, c: 0 },
    direction: 'across', // 'across' or 'down'
    partnerCursor: { r: null, c: null, dir: 'across' },
    timerSeconds: 0,
    timerInterval: null,
    isSolved: false,
    socket: null,
    roomId: null,
    isHost: true,
    myPlayerIdx: 0 // 0 = Coral, 1 = Teal
  };

  // --- Helper: Clue numbering for 5x5 grid ---
  function computeNumbers(puzzle) {
    const nums = Array(25).fill(0);
    [...puzzle.clues.across, ...puzzle.clues.down].forEach(clue => {
      const idx = clue.r * puzzle.size + clue.c;
      nums[idx] = clue.num;
    });
    return nums;
  }

  // --- Board Renderers ---

  function renderGrid() {
    const gridEl = document.getElementById('xword-grid');
    if (!gridEl) return;
    gridEl.innerHTML = '';

    const nums = computeNumbers(state.puzzle);

    for (let r = 0; r < state.puzzle.size; r++) {
      for (let c = 0; c < state.puzzle.size; c++) {
        const idx = r * state.puzzle.size + c;
        const cell = document.createElement('div');
        cell.className = 'xword-cell';
        cell.id = `xword-cell-${r}-${c}`;
        cell.dataset.r = r;
        cell.dataset.c = c;

        const isBlock = state.puzzle.solution[idx] === '.';
        if (isBlock) {
          cell.classList.add('block');
        } else {
          // Number label
          if (nums[idx] > 0) {
            const numEl = document.createElement('span');
            numEl.className = 'xword-cell-num';
            numEl.textContent = nums[idx];
            cell.appendChild(numEl);
          }

          // Letter display
          const letterEl = document.createElement('span');
          letterEl.className = 'xword-cell-letter';
          letterEl.id = `xword-letter-${r}-${c}`;
          letterEl.textContent = state.grid[idx] || '';
          cell.appendChild(letterEl);

          cell.addEventListener('click', () => onCellClicked(r, c));
        }

        gridEl.appendChild(cell);
      }
    }

    renderClueLists();
    updateHighlight();
  }

  function renderClueLists() {
    const acrossContainer = document.getElementById('xword-across-clues');
    const downContainer = document.getElementById('xword-down-clues');

    if (acrossContainer) {
      acrossContainer.innerHTML = '';
      state.puzzle.clues.across.forEach(c => {
        const item = document.createElement('div');
        item.className = 'xword-clue-item';
        item.id = `clue-across-${c.num}`;
        item.textContent = `${c.num}. ${c.clue}`;
        item.addEventListener('click', () => {
          state.cursor = { r: c.r, c: c.c };
          state.direction = 'across';
          updateHighlight();
          broadcastCursor();
        });
        acrossContainer.appendChild(item);
      });
    }

    if (downContainer) {
      downContainer.innerHTML = '';
      state.puzzle.clues.down.forEach(c => {
        const item = document.createElement('div');
        item.className = 'xword-clue-item';
        item.id = `clue-down-${c.num}`;
        item.textContent = `${c.num}. ${c.clue}`;
        item.addEventListener('click', () => {
          state.cursor = { r: c.r, c: c.c };
          state.direction = 'down';
          updateHighlight();
          broadcastCursor();
        });
        downContainer.appendChild(item);
      });
    }
  }

  function updateHighlight() {
    // Clear all previous highlights
    document.querySelectorAll('.xword-cell').forEach(el => {
      el.classList.remove('active-cell', 'active-word', 'partner-active-cell', 'partner-active-word');
    });
    document.querySelectorAll('.xword-clue-item').forEach(el => el.classList.remove('active'));

    const { r, c } = state.cursor;
    const curIdx = r * state.puzzle.size + c;
    if (state.puzzle.solution[curIdx] === '.') return;

    // Highlight current active cell
    const activeCell = document.getElementById(`xword-cell-${r}-${c}`);
    if (activeCell) activeCell.classList.add('active-cell');

    // Highlight word along active direction
    if (state.direction === 'across') {
      for (let col = 0; col < state.puzzle.size; col++) {
        const idx = r * state.puzzle.size + col;
        if (state.puzzle.solution[idx] !== '.') {
          const el = document.getElementById(`xword-cell-${r}-${col}`);
          if (el && col !== c) el.classList.add('active-word');
        }
      }
    } else {
      for (let row = 0; row < state.puzzle.size; row++) {
        const idx = row * state.puzzle.size + c;
        if (state.puzzle.solution[idx] !== '.') {
          const el = document.getElementById(`xword-cell-${row}-${c}`);
          if (el && row !== r) el.classList.add('active-word');
        }
      }
    }

    // Partner cursor highlight
    if (state.partnerCursor.r !== null && state.partnerCursor.c !== null) {
      const pr = state.partnerCursor.r, pc = state.partnerCursor.c;
      const partnerCell = document.getElementById(`xword-cell-${pr}-${pc}`);
      if (partnerCell) partnerCell.classList.add('partner-active-cell');
    }

    // Active clue banner update
    updateActiveClueBanner();
    updateProgressUI();
  }

  function updateActiveClueBanner() {
    const { r, c } = state.cursor;
    const activeClue = findClueForCell(r, c, state.direction);

    const labelEl = document.getElementById('xword-active-clue-label');
    const textEl = document.getElementById('xword-active-clue-text');

    if (activeClue) {
      if (labelEl) labelEl.textContent = `${activeClue.num}-${state.direction.toUpperCase()}`;
      if (textEl) textEl.textContent = activeClue.clue;

      const clueItem = document.getElementById(`clue-${state.direction}-${activeClue.num}`);
      if (clueItem) {
        clueItem.classList.add('active');
        clueItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    }
  }

  function findClueForCell(r, c, dir) {
    const clues = (dir === 'across') ? state.puzzle.clues.across : state.puzzle.clues.down;
    if (dir === 'across') {
      return clues.find(clue => clue.r === r);
    } else {
      return clues.find(clue => clue.c === c);
    }
  }

  function updateProgressUI() {
    let filled = 0;
    let total = 0;
    for (let i = 0; i < 25; i++) {
      if (state.puzzle.solution[i] !== '.') {
        total++;
        if (state.grid[i]) filled++;
      }
    }
    const progEl = document.getElementById('xword-progress');
    if (progEl) progEl.textContent = `${filled} / ${total}`;
  }

  // --- Cell Interactions & Input Handling ---

  function onCellClicked(r, c) {
    const idx = r * state.puzzle.size + c;
    if (state.puzzle.solution[idx] === '.') return;

    if (state.cursor.r === r && state.cursor.c === c) {
      // Toggle direction if clicking same cell
      state.direction = (state.direction === 'across') ? 'down' : 'across';
    } else {
      state.cursor = { r, c };
    }

    updateHighlight();
    broadcastCursor();
  }

  function enterLetter(char) {
    if (state.isSolved) return;
    char = (char || '').toUpperCase();
    if (!/^[A-Z]$/.test(char)) return;

    const { r, c } = state.cursor;
    const idx = r * state.puzzle.size + c;
    if (state.puzzle.solution[idx] === '.') return;

    state.grid[idx] = char;
    const letterEl = document.getElementById(`xword-letter-${r}-${c}`);
    if (letterEl) letterEl.textContent = char;

    // Broadcast change
    broadcastCell(r, c, char);

    // Auto-advance cursor
    advanceCursor();
    updateHighlight();
    checkAutoSolve();
  }

  function deleteLetter() {
    if (state.isSolved) return;
    const { r, c } = state.cursor;
    const idx = r * state.puzzle.size + c;

    if (state.grid[idx]) {
      state.grid[idx] = '';
      const letterEl = document.getElementById(`xword-letter-${r}-${c}`);
      if (letterEl) letterEl.textContent = '';
      broadcastCell(r, c, '');
    } else {
      retreatCursor();
      const prevIdx = state.cursor.r * state.puzzle.size + state.cursor.c;
      state.grid[prevIdx] = '';
      const prevLetterEl = document.getElementById(`xword-letter-${state.cursor.r}-${state.cursor.c}`);
      if (prevLetterEl) prevLetterEl.textContent = '';
      broadcastCell(state.cursor.r, state.cursor.c, '');
    }

    updateHighlight();
  }

  function advanceCursor() {
    const { r, c } = state.cursor;
    if (state.direction === 'across') {
      for (let nextC = c + 1; nextC < state.puzzle.size; nextC++) {
        const idx = r * state.puzzle.size + nextC;
        if (state.puzzle.solution[idx] !== '.') {
          state.cursor.c = nextC;
          broadcastCursor();
          return;
        }
      }
    } else {
      for (let nextR = r + 1; nextR < state.puzzle.size; nextR++) {
        const idx = nextR * state.puzzle.size + c;
        if (state.puzzle.solution[idx] !== '.') {
          state.cursor.r = nextR;
          broadcastCursor();
          return;
        }
      }
    }
  }

  function retreatCursor() {
    const { r, c } = state.cursor;
    if (state.direction === 'across') {
      for (let prevC = c - 1; prevC >= 0; prevC--) {
        const idx = r * state.puzzle.size + prevC;
        if (state.puzzle.solution[idx] !== '.') {
          state.cursor.c = prevC;
          broadcastCursor();
          return;
        }
      }
    } else {
      for (let prevR = r - 1; prevR >= 0; prevR--) {
        const idx = prevR * state.puzzle.size + c;
        if (state.puzzle.solution[idx] !== '.') {
          state.cursor.r = prevR;
          broadcastCursor();
          return;
        }
      }
    }
  }

  function checkAutoSolve() {
    let allFilled = true;
    let allCorrect = true;

    for (let i = 0; i < 25; i++) {
      if (state.puzzle.solution[i] !== '.') {
        if (!state.grid[i]) allFilled = false;
        if (state.grid[i] !== state.puzzle.solution[i]) allCorrect = false;
      }
    }

    if (allFilled && allCorrect) {
      triggerVictory();
    }
  }

  function triggerVictory() {
    state.isSolved = true;
    clearInterval(state.timerInterval);

    const modal = document.getElementById('xword-victory-modal');
    const timeEl = document.getElementById('xword-final-time');
    if (timeEl) timeEl.textContent = formatTimer(state.timerSeconds);
    if (modal) modal.style.display = 'flex';

    if (state.mode === 'online' && state.socket && state.roomId) {
      state.socket.emit('crossword_solved', {
        room_id: state.roomId,
        time_seconds: state.timerSeconds
      });
    }
  }

  // --- Timer ---

  function startTimer() {
    clearInterval(state.timerInterval);
    state.timerSeconds = 0;
    const timerEl = document.getElementById('xword-timer');
    if (timerEl) timerEl.textContent = '00:00';

    state.timerInterval = setInterval(() => {
      if (state.isSolved) return;
      state.timerSeconds++;
      if (timerEl) timerEl.textContent = formatTimer(state.timerSeconds);
    }, 1000);
  }

  function formatTimer(sec) {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  // --- Puzzle Lifecycle ---

  function loadPuzzle(idx) {
    state.puzzleIdx = Math.max(0, Math.min(PUZZLES.length - 1, idx));
    state.puzzle = PUZZLES[state.puzzleIdx];
    state.grid = Array(25).fill('');
    state.cursor = { r: 0, c: 0 };
    state.direction = 'across';
    state.partnerCursor = { r: null, c: null, dir: 'across' };
    state.isSolved = false;

    // Reset picker UI
    const picker = document.getElementById('xword-puzzle-picker');
    if (picker) picker.value = state.puzzleIdx;

    const modal = document.getElementById('xword-victory-modal');
    if (modal) modal.style.display = 'none';

    renderGrid();
    startTimer();
  }

  // --- Socket.IO Synchronisation ---

  function connectSocket() {
    if (state.socket) return;
    if (typeof io !== 'function') return;

    state.socket = io({ transports: ['websocket', 'polling'] });

    state.socket.on('connect', () => {
      const statusEl = document.getElementById('xword-online-status');
      if (statusEl) statusEl.textContent = 'Connected. Ready to join room.';
    });

    state.socket.on('crossword_room_joined', (data) => {
      state.roomId = data.room_id;
      state.isHost = data.is_host;
      state.myPlayerIdx = data.is_host ? 0 : 1;

      const statusEl = document.getElementById('xword-online-status');
      if (statusEl) {
        statusEl.textContent = `Room: ${data.room_id} | Solving vs ${data.partner_name || 'Partner'}`;
        statusEl.style.color = '#15803d';
      }

      if (data.puzzle_idx !== undefined) {
        loadPuzzle(data.puzzle_idx);
      }
      if (Array.isArray(data.grid)) {
        state.grid = [...data.grid];
        for (let r = 0; r < 5; r++) {
          for (let c = 0; c < 5; c++) {
            const letterEl = document.getElementById(`xword-letter-${r}-${c}`);
            if (letterEl) letterEl.textContent = state.grid[r * 5 + c] || '';
          }
        }
        updateHighlight();
      }
    });

    state.socket.on('crossword_cell_update', (data) => {
      const idx = data.r * 5 + data.c;
      state.grid[idx] = data.char || '';
      const letterEl = document.getElementById(`xword-letter-${data.r}-${data.c}`);
      if (letterEl) letterEl.textContent = data.char || '';
      updateProgressUI();
      checkAutoSolve();
    });

    state.socket.on('crossword_cursor_move', (data) => {
      state.partnerCursor = { r: data.r, c: data.c, dir: data.dir };
      updateHighlight();
    });

    state.socket.on('crossword_restarted', (data) => {
      loadPuzzle(data.puzzle_idx || 0);
    });

    state.socket.on('crossword_solved', () => {
      triggerVictory();
    });

    state.socket.on('crossword_partner_left', () => {
      const statusEl = document.getElementById('xword-online-status');
      if (statusEl) {
        statusEl.textContent = 'Partner left the room.';
        statusEl.style.color = '#b8423f';
      }
      state.partnerCursor = { r: null, c: null, dir: 'across' };
      updateHighlight();
    });
  }

  function joinRoom(roomId) {
    if (!roomId) return;
    connectSocket();
    state.roomId = roomId;
    if (state.socket) {
      state.socket.emit('join_crossword_room', {
        room_id: roomId,
        puzzle_idx: state.puzzleIdx
      });
    }
  }

  function broadcastCell(r, c, char) {
    if (state.mode === 'online' && state.socket && state.roomId) {
      state.socket.emit('crossword_cell_update', {
        room_id: state.roomId,
        r, c, char
      });
    }
  }

  function broadcastCursor() {
    if (state.mode === 'online' && state.socket && state.roomId) {
      state.socket.emit('crossword_cursor_move', {
        room_id: state.roomId,
        r: state.cursor.r,
        c: state.cursor.c,
        dir: state.direction
      });
    }
  }

  // --- Keyboard Listeners ---

  document.addEventListener('keydown', (e) => {
    // Ignore input if inside a regular text box
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

    if (/^[a-zA-Z]$/.test(e.key)) {
      enterLetter(e.key);
      e.preventDefault();
    } else if (e.key === 'Backspace' || e.key === 'Delete') {
      deleteLetter();
      e.preventDefault();
    } else if (e.key === ' ' || e.key === 'Enter') {
      state.direction = (state.direction === 'across') ? 'down' : 'across';
      updateHighlight();
      broadcastCursor();
      e.preventDefault();
    } else if (e.key === 'ArrowRight') {
      state.cursor.c = Math.min(state.puzzle.size - 1, state.cursor.c + 1);
      updateHighlight();
      broadcastCursor();
      e.preventDefault();
    } else if (e.key === 'ArrowLeft') {
      state.cursor.c = Math.max(0, state.cursor.c - 1);
      updateHighlight();
      broadcastCursor();
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      state.cursor.r = Math.min(state.puzzle.size - 1, state.cursor.r + 1);
      updateHighlight();
      broadcastCursor();
      e.preventDefault();
    } else if (e.key === 'ArrowUp') {
      state.cursor.r = Math.max(0, state.cursor.r - 1);
      updateHighlight();
      broadcastCursor();
      e.preventDefault();
    }
  });

  // --- DOM Setup ---

  document.addEventListener('DOMContentLoaded', () => {
    // Mode tabs
    const tabOnline = document.getElementById('tab-xword-online');
    const tabSolo = document.getElementById('tab-xword-solo');
    const onlinePanel = document.getElementById('xword-online-panel');

    function setActiveTab(activeBtn) {
      [tabOnline, tabSolo].forEach(btn => {
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
      });
    }

    if (tabSolo) {
      tabSolo.addEventListener('click', () => {
        setActiveTab(tabSolo);
        state.mode = 'solo';
        if (onlinePanel) onlinePanel.style.display = 'none';
        state.partnerCursor = { r: null, c: null, dir: 'across' };
        updateHighlight();
      });
    }

    // Puzzle Picker
    const picker = document.getElementById('xword-puzzle-picker');
    if (picker) {
      picker.addEventListener('change', () => {
        const nextIdx = parseInt(picker.value, 10);
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('crossword_restart', {
            room_id: state.roomId,
            puzzle_idx: nextIdx
          });
        } else {
          loadPuzzle(nextIdx);
        }
      });
    }

    // Check Puzzle Button
    const checkBtn = document.getElementById('xword-check-btn');
    if (checkBtn) {
      checkBtn.addEventListener('click', () => {
        let errors = 0;
        for (let i = 0; i < 25; i++) {
          if (state.puzzle.solution[i] !== '.' && state.grid[i]) {
            if (state.grid[i] !== state.puzzle.solution[i]) {
              errors++;
              const r = Math.floor(i / 5), c = i % 5;
              const cell = document.getElementById(`xword-cell-${r}-${c}`);
              if (cell) {
                cell.style.background = '#fee2e2';
                setTimeout(() => { cell.style.background = ''; }, 1200);
              }
            }
          }
        }
        if (errors === 0) {
          alert('All filled letters are correct! Keep going!');
        } else {
          alert(`Found ${errors} incorrect letter${errors > 1 ? 's' : ''}. Highlighted in red.`);
        }
      });
    }

    // Victory Next Puzzle Button
    const nextPuzzleBtn = document.getElementById('xword-next-puzzle-btn');
    if (nextPuzzleBtn) {
      nextPuzzleBtn.addEventListener('click', () => {
        const nextIdx = (state.puzzleIdx + 1) % PUZZLES.length;
        if (state.mode === 'online' && state.socket && state.roomId) {
          state.socket.emit('crossword_restart', {
            room_id: state.roomId,
            puzzle_idx: nextIdx
          });
        } else {
          loadPuzzle(nextIdx);
        }
      });
    }

    // Virtual Touch Keyboard Keys
    document.querySelectorAll('.kb-key').forEach(keyBtn => {
      keyBtn.addEventListener('click', () => {
        const key = keyBtn.dataset.key;
        if (key === 'BACK') {
          deleteLetter();
        } else if (key === 'DIR') {
          state.direction = (state.direction === 'across') ? 'down' : 'across';
          updateHighlight();
          broadcastCursor();
        } else if (/^[A-Z]$/.test(key)) {
          enterLetter(key);
        }
      });
    });

    // Room controls
    const createRoomBtn = document.getElementById('xword-create-room-btn');
    const joinRoomBtn = document.getElementById('xword-join-room-btn');
    const roomInput = document.getElementById('xword-room-input');
    const findMatchBtn = document.getElementById('xword-find-match-btn');

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
        const code = 'mini_' + Math.random().toString(36).substring(2, 6);
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
      loadPuzzle(0);
    }
  });

  // Expose minimal API
  window.__teamCrossword = {
    getState: () => state,
    loadPuzzle: loadPuzzle,
    joinRoom: joinRoom
  };
})();
