document.addEventListener('DOMContentLoaded', () => {
    const emojis = ['❤️', '💍', '🌹', '🏠', '☀️', '🌙', '⭐', '🎵', '📸', '🎂', '🌊', '🔥', '🦋', '🌸', '🎭', '💎', '🧸', '🎪'];
    
    let mode = 'solo';
    let size = 16;
    let cards = [];
    let flippedCards = [];
    let matchedPairs = 0;
    
    let player1Score = 0;
    let player2Score = 0;
    let currentPlayer = 1; // 1 or 2
    
    let timerInterval = null;
    let timeElapsed = 0;
    
    let isMyTurn = true;
    let socket = null;
    let roomId = null;
    let amIHost = false;
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

    ui.startBtn.addEventListener('click', startGame);
    ui.replayBtn.addEventListener('click', resetGame);
    ui.modeSelect.addEventListener('change', () => {
        if(ui.modeSelect.value === 'online') {
            ui.onlineStatus.textContent = "Connecting to socket room...";
            initSocket();
        } else {
            ui.onlineStatus.textContent = "";
            if (socket) socket.disconnect();
            socket = null;
        }
    });

    function initSocket() {
        if (typeof io === 'undefined') {
            ui.onlineStatus.textContent = "Socket.IO not available.";
            ui.startBtn.disabled = true;
            return;
        }
        
        const params = new URLSearchParams(window.location.search);
        roomId = params.get('room');
        const bondId = params.get('bond_id');
        
        if (!roomId) {
            ui.onlineStatus.textContent = "Error: No room ID in URL.";
            ui.startBtn.disabled = true;
            return;
        }

        socket = io();
        ui.startBtn.disabled = false;
        
        socket.emit('memory_join_room', { room: roomId, bond_id: bondId });
        
        socket.on('memory_room_joined', (data) => {
            amIHost = data.host;
            ui.onlineStatus.textContent = amIHost ? "Waiting for opponent... You are host." : "Connected as guest.";
        });
        
        socket.on('memory_start_game', (data) => {
            handleRemoteStart(data);
        });

        socket.on('memory_flip_card', (data) => {
            handleRemoteFlip(data.index);
        });

        socket.on('memory_card_result', (data) => {
            handleRemoteResult(data);
        });

        socket.on('memory_turn_change', (data) => {
            currentPlayer = data.turn;
            isMyTurn = (amIHost && currentPlayer === 1) || (!amIHost && currentPlayer === 2);
            updateTurnUI();
        });
    }

    function startGame() {
        mode = ui.modeSelect.value;
        size = parseInt(ui.sizeSelect.value);
        
        if (mode === 'online') {
            if (!amIHost) {
                alert("Only host can start the game.");
                return;
            }
            const gameCards = generateCards(size);
            socket.emit('memory_start_game', { room: roomId, size, cards: gameCards });
            setupBoard(gameCards);
        } else {
            setupBoard(generateCards(size));
        }
    }

    function handleRemoteStart(data) {
        if (amIHost) return;
        size = data.size;
        ui.sizeSelect.value = size;
        mode = 'online';
        ui.modeSelect.value = 'online';
        setupBoard(data.cards);
    }

    function generateCards(gridSize) {
        let pairsCount = gridSize / 2;
        let selectedEmojis = emojis.slice(0, pairsCount);
        let deck = [...selectedEmojis, ...selectedEmojis];
        
        // Shuffle
        for (let i = deck.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [deck[i], deck[j]] = [deck[j], deck[i]];
        }
        return deck;
    }

    function setupBoard(deck) {
        ui.setupPanel.style.display = 'none';
        ui.gameInfo.style.display = 'flex';
        ui.gridContainer.style.display = 'grid';
        
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
            isMyTurn = true;
        } else {
            ui.scoreP2.style.display = 'block';
            ui.turnIndicator.style.display = 'block';
            ui.timer.style.display = 'none';
            updateScoreUI();
            
            if (mode === 'online') {
                isMyTurn = amIHost;
            } else {
                isMyTurn = true;
            }
            updateTurnUI();
        }

        cards.forEach((emoji, index) => {
            const cardElement = document.createElement('div');
            cardElement.className = 'card';
            cardElement.dataset.index = index;
            cardElement.dataset.emoji = emoji;
            
            cardElement.innerHTML = `
                <div class="card-face card-back"></div>
                <div class="card-face card-front">${emoji}</div>
            `;
            
            cardElement.addEventListener('click', () => onCardClick(index, cardElement));
            ui.gridContainer.appendChild(cardElement);
        });
    }

    function onCardClick(index, cardElement) {
        if (lockBoard || !isMyTurn) return;
        if (cardElement.classList.contains('flipped') || cardElement.classList.contains('matched')) return;

        flipCard(index, cardElement);

        if (mode === 'online') {
            socket.emit('memory_flip_card', { room: roomId, index });
        }

        checkMatch();
    }

    function flipCard(index, cardElement) {
        cardElement.classList.add('flipped');
        flippedCards.push({ index, element: cardElement, emoji: cards[index] });
    }

    function handleRemoteFlip(index) {
        if (isMyTurn) return; // Ignore if it's my turn
        const cardElement = ui.gridContainer.children[index];
        if (cardElement) {
            flipCard(index, cardElement);
        }
    }

    function checkMatch() {
        if (flippedCards.length < 2) return;

        lockBoard = true;
        const [card1, card2] = flippedCards;
        const isMatch = card1.emoji === card2.emoji;

        if (mode === 'online') {
            if (amIHost) {
                // Host decides result
                setTimeout(() => {
                    socket.emit('memory_card_result', { room: roomId, match: isMatch, c1: card1.index, c2: card2.index });
                    processResult(isMatch, card1, card2);
                }, 1000);
            }
        } else {
            setTimeout(() => {
                processResult(isMatch, card1, card2);
            }, 1000);
        }
    }

    function handleRemoteResult(data) {
        if (amIHost) return;
        const card1 = { index: data.c1, element: ui.gridContainer.children[data.c1] };
        const card2 = { index: data.c2, element: ui.gridContainer.children[data.c2] };
        processResult(data.match, card1, card2);
    }

    function processResult(isMatch, card1, card2) {
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
            
            checkWin();
        } else {
            card1.element.classList.remove('flipped');
            card2.element.classList.remove('flipped');
            
            if (mode !== 'solo') {
                currentPlayer = currentPlayer === 1 ? 2 : 1;
                updateTurnUI();
                if (mode === 'online' && amIHost) {
                    socket.emit('memory_turn_change', { room: roomId, turn: currentPlayer });
                }
            }
        }

        flippedCards = [];
        lockBoard = false;
        
        if (mode === 'online' && !amIHost) {
            isMyTurn = (currentPlayer === 2);
        } else if (mode === 'online' && amIHost) {
            isMyTurn = (currentPlayer === 1);
        } else {
            isMyTurn = true; // Local/solo always true
        }
    }

    function updateScoreUI() {
        ui.scoreP1.textContent = `P1: ${player1Score}`;
        ui.scoreP2.textContent = `P2: ${player2Score}`;
    }

    function updateTurnUI() {
        if (mode === 'online') {
            ui.turnIndicator.textContent = isMyTurn ? "Your Turn" : "Opponent's Turn";
        } else {
            ui.turnIndicator.textContent = `Player ${currentPlayer}'s Turn`;
        }
    }

    function startTimer() {
        timeElapsed = 0;
        ui.timer.textContent = `Time: 0s`;
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            timeElapsed++;
            ui.timer.textContent = `Time: ${timeElapsed}s`;
        }, 1000);
    }

    function checkWin() {
        if (matchedPairs === size / 2) {
            if (timerInterval) clearInterval(timerInterval);
            setTimeout(showGameOver, 500);
        }
    }

    function showGameOver() {
        ui.modal.style.display = 'flex';
        if (mode === 'solo') {
            let bestTime = localStorage.getItem(`memoryBestTime_${size}`) || Infinity;
            let isNewBest = false;
            if (timeElapsed < bestTime) {
                bestTime = timeElapsed;
                localStorage.setItem(`memoryBestTime_${size}`, bestTime);
                isNewBest = true;
            }
            ui.winnerText.textContent = 'You Win!';
            ui.statsText.innerHTML = `Time: ${timeElapsed}s<br>Best Time: ${bestTime}s ${isNewBest ? '(New Best!)' : ''}`;
        } else {
            if (player1Score > player2Score) {
                ui.winnerText.textContent = mode === 'online' && amIHost ? 'You Win!' : mode === 'online' ? 'Opponent Wins!' : 'Player 1 Wins!';
            } else if (player2Score > player1Score) {
                ui.winnerText.textContent = mode === 'online' && !amIHost ? 'You Win!' : mode === 'online' ? 'Opponent Wins!' : 'Player 2 Wins!';
            } else {
                ui.winnerText.textContent = 'It\\'s a Tie!';
            }
            ui.statsText.textContent = `Score: ${player1Score} - ${player2Score}`;
        }
        
        if (mode === 'online' && !amIHost) {
            ui.replayBtn.style.display = 'none'; // Only host can restart
            ui.statsText.innerHTML += '<br>Waiting for host to restart...';
        } else {
            ui.replayBtn.style.display = 'inline-block';
        }
        
        if (mode === 'online' && amIHost) {
            socket.emit('memory_game_over', { room: roomId, p1Score: player1Score, p2Score: player2Score });
        }
    }

    function resetGame() {
        ui.modal.style.display = 'none';
        ui.setupPanel.style.display = 'block';
        ui.gameInfo.style.display = 'none';
        ui.gridContainer.style.display = 'none';
    }
});
