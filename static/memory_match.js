document.addEventListener('DOMContentLoaded', () => {
    const symbols = [
        'heart', 'ring', 'rose', 'home', 'sun', 'moon', 'star', 'music',
        'camera', 'cake', 'wave', 'fire', 'butterfly', 'flower', 'theater',
        'diamond', 'gift', 'spark'
    ];
    const labels = {
        heart: 'HEART', ring: 'RING', rose: 'ROSE', home: 'HOME',
        sun: 'SUN', moon: 'MOON', star: 'STAR', music: 'MUSIC',
        camera: 'PHOTO', cake: 'CAKE', wave: 'WAVE', fire: 'FIRE',
        butterfly: 'WINGS', flower: 'FLOWER', theater: 'STAGE',
        diamond: 'GEM', gift: 'GIFT', spark: 'SPARK'
    };

    let mode = 'solo';
    let size = 16;
    let cards = [];
    let flippedCards = [];
    let matchedPairs = 0;
    let player1Score = 0;
    let player2Score = 0;
    let currentPlayer = 1;
    let timerInterval = null;
    let timeElapsed = 0;
    let socket = null;
    let roomId = null;
    let joinedRoom = false;
    let myPlayerNum = 1;
    let lockBoard = false;

    const ui = {
        setupPanel: document.getElementById('setup-panel'),
        gameInfo: document.getElementById('game-info'),
        gridContainer: document.getElementById('grid-container'),
        modeSelect: document.getElementById('mode-select'),
        sizeSelect: document.getElementById('size-select'),
        startBtn: document.getElementById('start-btn'),
        scoreP1: document.getElementById('score-p1'),
        scoreP2: document.getElementById('score-p2'),
        turnIndicator: document.getElementById('turn-indicator'),
        timer: document.getElementById('timer'),
        modal: document.getElementById('game-over-modal'),
        winnerText: document.getElementById('winner-text'),
        statsText: document.getElementById('stats-text'),
        replayBtn: document.getElementById('replay-btn'),
        onlineStatus: document.getElementById('online-status')
    };

    const params = new URLSearchParams(window.location.search);
    const urlRoom = params.get('room');
    const bondId = params.get('bond_id');

    ui.startBtn.addEventListener('click', startGame);
    ui.replayBtn.addEventListener('click', resetGame);
    ui.modeSelect.addEventListener('change', () => {
        if (ui.modeSelect.value === 'online') {
            if (socket) disconnectSocket();
            ui.startBtn.textContent = urlRoom ? 'Join Room' : 'Create Room';
            setStatus(urlRoom
                ? 'Room ' + urlRoom + ' — pick a board size, then Join Room.'
                : 'Pick a board size, then Create Room to invite a partner.');
        } else {
            disconnectSocket();
        }
    });

    if (urlRoom) {
        ui.modeSelect.value = 'online';
        ui.startBtn.textContent = 'Join Room';
        setStatus('Room ' + urlRoom + ' — pick a board size, then Join Room. The host deals.');
    }

    function setStatus(message, isError = false) {
        ui.onlineStatus.textContent = message || '';
        ui.onlineStatus.style.color = isError ? 'var(--danger-color,#dc2626)' : 'var(--text-secondary)';
    }

    function disconnectSocket() {
        if (socket) socket.disconnect();
        socket = null;
        joinedRoom = false;
        roomId = null;
        ui.sizeSelect.disabled = false;
        ui.startBtn.disabled = false;
        ui.startBtn.textContent = 'Start Game';
        setStatus('');
    }

    function initSocket() {
        if (socket) return;
        if (typeof io === 'undefined') {
            setStatus('Live play is unavailable. Try again after reconnecting.', true);
            return;
        }
        roomId = urlRoom || `memory_${Math.random().toString(36).slice(2, 8)}`;
        socket = io({ transports: ['websocket', 'polling'] });
        setStatus('Connecting to room...');

        socket.on('connect', () => {
            socket.emit('memory_join_room', { room: roomId, bond_id: bondId || undefined });
        });

        socket.on('memory_room_joined', (data) => {
            myPlayerNum = data.player_num || 1;
            mode = 'online';
            joinedRoom = true;
            if (myPlayerNum === 1) {
                // Host: deal with the size chosen in the (still visible) setup panel.
                // Emitting here (not on the Start press) guarantees we are already
                // in the room — the old immediate emit raced the join and could hit
                // 'Session not found'.
                size = parseInt(ui.sizeSelect.value, 10) || 16;
                setStatus('Dealing your ' + (size >= 36 ? '6×6' : '4×4') + ' board...');
                socket.emit('memory_start_game', { room: roomId, size });
                return;
            }
            ui.sizeSelect.disabled = true;
            ui.startBtn.textContent = 'Waiting for Host…';
            ui.startBtn.disabled = true;
            setupBoard(data.cards || [], { online: true, labels: data.labels || labels });
            currentPlayer = data.turn || 1;
            player1Score = Number((data.scores || {})['1'] || 0);
            player2Score = Number((data.scores || {})['2'] || 0);
            markMatched(data.matched || []);
            updateScoreUI();
            updateTurnUI();
            setStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for host to deal...');
        });

        socket.on('memory_partner_update', (data) => {
            setStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for partner...');
        });

        socket.on('memory_start_game', (data) => {
            setupBoard(data.cards || [], { online: true, labels: data.labels || labels });
            currentPlayer = data.turn || 1;
            player1Score = Number((data.scores || {})['1'] || 0);
            player2Score = Number((data.scores || {})['2'] || 0);
            updateScoreUI();
            updateTurnUI();
            hideGameOver();
        });

        socket.on('memory_flip_card', (data) => {
            const cardElement = ui.gridContainer.children[data.index];
            if (cardElement) cardElement.classList.add('flipped');
        });

        socket.on('memory_card_result', (data) => {
            lockBoard = true;
            setTimeout(() => {
                const c1 = ui.gridContainer.children[data.c1];
                const c2 = ui.gridContainer.children[data.c2];
                if (data.match) {
                    if (c1) c1.classList.add('matched');
                    if (c2) c2.classList.add('matched');
                    matchedPairs++;
                } else {
                    if (c1) c1.classList.remove('flipped');
                    if (c2) c2.classList.remove('flipped');
                }
                player1Score = Number((data.scores || {})['1'] || 0);
                player2Score = Number((data.scores || {})['2'] || 0);
                currentPlayer = data.turn || currentPlayer;
                updateScoreUI();
                updateTurnUI();
                lockBoard = false;
                if (data.complete) showGameOver();
            }, 700);
        });

        socket.on('memory_turn_change', (data) => {
            currentPlayer = data.turn || currentPlayer;
            updateTurnUI();
        });

        socket.on('memory_error', (data) => {
            setStatus((data && data.message) || 'Game sync error. Please retry.', true);
            setTimeout(() => setStatus(currentPlayer === myPlayerNum ? 'Your turn.' : 'Waiting for partner...'), 2200);
        });

        socket.on('memory_partner_left', () => {
            setStatus('Partner left. Start a fresh challenge.', true);
        });
    }

    function startGame() {
        mode = ui.modeSelect.value;
        size = parseInt(ui.sizeSelect.value, 10);
        if (mode === 'online') {
            // Already in a room: host re-deals with the panel's size, guest waits.
            if (socket && joinedRoom) {
                if (myPlayerNum === 1) {
                    size = parseInt(ui.sizeSelect.value, 10) || 16;
                    socket.emit('memory_start_game', { room: roomId, size });
                } else {
                    setStatus('Waiting for host to deal…');
                }
                return;
            }
            // Fresh join only. The host's deal goes out from the
            // memory_room_joined handler with the size chosen above.
            ui.sizeSelect.disabled = false;
            initSocket();
            ui.startBtn.disabled = true;
            setStatus('Joining room...');
            setTimeout(() => { if (!joinedRoom) ui.startBtn.disabled = false; }, 4000);
            return;
        }
        setupBoard(generateCards(size), { online: false, labels });
    }

    function generateCards(gridSize) {
        const pairsCount = gridSize / 2;
        const selected = symbols.slice(0, pairsCount);
        const deck = [...selected, ...selected];
        for (let i = deck.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [deck[i], deck[j]] = [deck[j], deck[i]];
        }
        return deck;
    }

    function setupBoard(deck, options = {}) {
        ui.setupPanel.style.display = 'none';
        ui.gameInfo.style.display = 'flex';
        ui.gridContainer.style.display = 'grid';
        size = deck.length || size;
        ui.gridContainer.className = `grid-container size-${size === 16 ? '4x4' : '6x6'}`;
        ui.gridContainer.innerHTML = '';

        cards = deck;
        flippedCards = [];
        matchedPairs = 0;
        player1Score = 0;
        player2Score = 0;
        currentPlayer = 1;
        lockBoard = false;

        if (mode === 'solo') {
            ui.scoreP2.style.display = 'none';
            ui.turnIndicator.style.display = 'none';
            ui.timer.style.display = 'block';
            ui.scoreP1.textContent = 'Pairs: 0';
            startTimer();
        } else {
            ui.scoreP2.style.display = 'block';
            ui.turnIndicator.style.display = 'block';
            ui.timer.style.display = 'none';
            updateScoreUI();
            updateTurnUI();
        }

        const displayLabels = options.labels || labels;
        cards.forEach((symbol, index) => {
            const cardElement = document.createElement('div');
            cardElement.className = 'card';
            cardElement.dataset.index = index;
            cardElement.dataset.symbol = symbol;
            cardElement.innerHTML = `
                <div class="card-face card-back">?</div>
                <div class="card-face card-front">${displayLabels[symbol] || symbol}</div>
            `;
            cardElement.addEventListener('click', () => onCardClick(index, cardElement));
            ui.gridContainer.appendChild(cardElement);
        });
    }

    function onCardClick(index, cardElement) {
        if (lockBoard) return;
        if (cardElement.classList.contains('flipped') || cardElement.classList.contains('matched')) return;
        if (mode === 'online') {
            if (currentPlayer !== myPlayerNum) {
                setStatus('Waiting for your turn.');
                return;
            }
            socket.emit('memory_flip_card', { room: roomId, index });
            return;
        }

        cardElement.classList.add('flipped');
        flippedCards.push({ index, element: cardElement, symbol: cards[index] });
        checkLocalMatch();
    }

    function checkLocalMatch() {
        if (flippedCards.length < 2) return;
        lockBoard = true;
        const [card1, card2] = flippedCards;
        const isMatch = card1.symbol === card2.symbol;
        setTimeout(() => {
            if (isMatch) {
                card1.element.classList.add('matched');
                card2.element.classList.add('matched');
                matchedPairs++;
                if (mode === 'solo') {
                    player1Score++;
                    ui.scoreP1.textContent = `Pairs: ${player1Score}`;
                } else {
                    if (currentPlayer === 1) player1Score++;
                    else player2Score++;
                    updateScoreUI();
                }
            } else {
                card1.element.classList.remove('flipped');
                card2.element.classList.remove('flipped');
                if (mode !== 'solo') currentPlayer = currentPlayer === 1 ? 2 : 1;
                updateTurnUI();
            }
            flippedCards = [];
            lockBoard = false;
            if (matchedPairs === cards.length / 2) showGameOver();
        }, 700);
    }

    function markMatched(indexes) {
        indexes.forEach((idx) => {
            const card = ui.gridContainer.children[idx];
            if (card) card.classList.add('flipped', 'matched');
        });
        matchedPairs = Math.floor(indexes.length / 2);
    }

    function updateScoreUI() {
        ui.scoreP1.textContent = `P1: ${player1Score}`;
        ui.scoreP2.textContent = `P2: ${player2Score}`;
    }

    function updateTurnUI() {
        if (mode === 'online') {
            ui.turnIndicator.textContent = currentPlayer === myPlayerNum ? 'Your Turn' : 'Partner Turn';
        } else {
            ui.turnIndicator.textContent = `Player ${currentPlayer} Turn`;
        }
    }

    function startTimer() {
        timeElapsed = 0;
        ui.timer.textContent = 'Time: 0s';
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            timeElapsed++;
            ui.timer.textContent = `Time: ${timeElapsed}s`;
        }, 1000);
    }

    function showGameOver() {
        if (timerInterval) clearInterval(timerInterval);
        ui.modal.style.display = 'flex';
        if (mode === 'solo') {
            const key = `memoryBestTime_${size}`;
            const previous = Number(localStorage.getItem(key) || Infinity);
            const isNewBest = timeElapsed < previous;
            if (isNewBest) localStorage.setItem(key, String(timeElapsed));
            ui.winnerText.textContent = 'You Win';
            ui.statsText.innerHTML = `Time: ${timeElapsed}s<br>Best Time: ${isNewBest ? timeElapsed : previous}s`;
            return;
        }
        if (player1Score === player2Score) ui.winnerText.textContent = 'Tie Game';
        else {
            const winner = player1Score > player2Score ? 1 : 2;
            ui.winnerText.textContent = mode === 'online'
                ? (winner === myPlayerNum ? 'You Win' : 'Partner Wins')
                : `Player ${winner} Wins`;
        }
        ui.statsText.textContent = `Score: ${player1Score} - ${player2Score}`;
        if (mode === 'online' && myPlayerNum === 1) {
            // Host can change board size before the next deal.
            ui.sizeSelect.disabled = false;
            ui.setupPanel.style.display = 'block';
            ui.startBtn.textContent = 'Deal New Board';
            ui.startBtn.disabled = false;
        }
    }

    function hideGameOver() {
        ui.modal.style.display = 'none';
    }

    function resetGame() {
        hideGameOver();
        if (mode === 'online' && socket && roomId && myPlayerNum === 1) {
            size = parseInt(ui.sizeSelect.value, 10) || 16;
            socket.emit('memory_start_game', { room: roomId, size });
            return;
        }
        if (mode === 'online') {
            ui.setupPanel.style.display = 'block';
            ui.startBtn.textContent = 'Waiting for Host…';
            ui.startBtn.disabled = true;
            setStatus('Waiting for host to deal a new board.');
            return;
        }
        ui.startBtn.textContent = 'Start Game';
        ui.startBtn.disabled = false;
        ui.sizeSelect.disabled = false;
        ui.setupPanel.style.display = 'block';
        ui.gameInfo.style.display = 'none';
        ui.gridContainer.style.display = 'none';
    }
});
