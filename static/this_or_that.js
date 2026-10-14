const fallbackPairs = [
    ['Cook dinner together', 'Order takeout'],
    ['Movie night in', 'Night out dancing'],
    ['Sunrise', 'Sunset'],
    ['Beach vacation', 'Mountain cabin'],
    ['Text goodnight', 'Call goodnight'],
    ['Road trip', 'Fly to destination'],
    ['Handwritten letter', 'Surprise gift'],
    ['Cuddle in silence', 'Deep conversations'],
    ['Plan everything', 'Be spontaneous'],
    ['Coffee', 'Tea'],
    ['Comedy', 'Drama'],
    ['Pancakes', 'Waffles'],
    ['Camping', 'Glamping'],
    ['Photos', 'Videos'],
    ['Board games', 'Video games']
];

let mode = null;
let socket = null;
let room = null;
let bondId = null;
let currentRound = 0;
const totalRounds = 10;
let gamePairs = [];
let p1Choices = [];
let p2Choices = [];
let myChoices = [];
let score = 0;
let timer = null;
let timeLeft = 15;
let myPlayerNum = 1;
let localCurrentPlayer = 1;
let roundResolved = false;

const setupScreen = document.getElementById('setup-screen');
const gameScreen = document.getElementById('game-screen');
const resultScreen = document.getElementById('result-screen');
const optionA = document.getElementById('option-a');
const optionB = document.getElementById('option-b');
const timerBar = document.getElementById('timer-bar');
const roundResult = document.getElementById('round-result');
const btnNext = document.getElementById('btn-next');
const roundDisplay = document.getElementById('round-display');
const scoreDisplay = document.getElementById('score-display');
const waitingOverlay = document.getElementById('waiting-overlay');
const onlineStatus = document.getElementById('online-status');

document.getElementById('btn-solo').addEventListener('click', () => startGame('solo'));
document.getElementById('btn-local').addEventListener('click', () => startGame('local'));
document.getElementById('btn-online').addEventListener('click', () => initOnline());
document.getElementById('btn-restart').addEventListener('click', () => {
    resultScreen.classList.add('hidden');
    setupScreen.classList.remove('hidden');
});

optionA.addEventListener('click', () => makeChoice('A'));
optionB.addEventListener('click', () => makeChoice('B'));
btnNext.addEventListener('click', () => {
    btnNext.classList.add('hidden');
    roundResult.innerHTML = '';
    if (mode === 'local') {
        if (localCurrentPlayer === 1) {
            localCurrentPlayer = 2;
            showRound();
        } else {
            localCurrentPlayer = 1;
            nextRound();
        }
    } else {
        nextRound();
    }
});

const params = new URLSearchParams(window.location.search);
if (params.get('room')) {
    initOnline();
}

function setOnlineStatus(message, isError = false) {
    onlineStatus.classList.remove('hidden');
    onlineStatus.innerText = message;
    onlineStatus.style.color = isError ? 'var(--danger-color,#dc2626)' : 'var(--tot-text-sec)';
}

function shuffle(array) {
    for (let cur = array.length; cur > 0;) {
        const rand = Math.floor(Math.random() * cur);
        cur--;
        [array[cur], array[rand]] = [array[rand], array[cur]];
    }
    return array;
}

function initOnline() {
    room = params.get('room') || `tot_${Math.random().toString(36).slice(2, 8)}`;
    bondId = params.get('bond_id') || '';
    mode = 'online';
    setOnlineStatus('Connecting...');

    if (typeof io === 'undefined') {
        setOnlineStatus('Live play is unavailable. Please reconnect and retry.', true);
        return;
    }
    if (socket) socket.disconnect();
    socket = io({ transports: ['websocket', 'polling'] });

    socket.on('connect', () => {
        socket.emit('tot_join_room', { room, bond_id: bondId || undefined });
    });

    socket.on('tot_room_joined', (data) => {
        myPlayerNum = data.player_num || 1;
        gamePairs = Array.isArray(data.pairs) && data.pairs.length ? data.pairs : shuffle([...fallbackPairs]).slice(0, 10);
        setOnlineStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for partner...');
        startGame('online', true);
    });

    socket.on('tot_partner_update', (data) => {
        setOnlineStatus(data.partner_connected ? 'Partner connected.' : 'Waiting for partner...');
    });

    socket.on('tot_choice_update', (data) => {
        if (Number(data.round) !== currentRound || roundResolved) return;
        if (!data.ready) {
            waitingOverlay.classList.remove('hidden');
            return;
        }
        waitingOverlay.classList.add('hidden');
        p1Choices[currentRound] = data.p1_choice;
        p2Choices[currentRound] = data.p2_choice;
        roundResolved = true;
        handleRoundResult(data.p1_choice, data.p2_choice);
    });

    socket.on('tot_error', (data) => {
        setOnlineStatus((data && data.message) || 'Game sync error. Please retry.', true);
    });

    socket.on('tot_partner_left', () => {
        setOnlineStatus('Partner left. Start a fresh challenge.', true);
    });
}

function startGame(selectedMode, fromOnlineJoin = false) {
    mode = selectedMode;
    currentRound = 0;
    score = 0;
    p1Choices = [];
    p2Choices = [];
    myChoices = [];
    localCurrentPlayer = 1;

    if (mode !== 'online' || !fromOnlineJoin) {
        gamePairs = shuffle([...fallbackPairs]).slice(0, 10);
    }

    setupScreen.classList.add('hidden');
    gameScreen.classList.remove('hidden');
    resultScreen.classList.add('hidden');

    if (mode === 'solo' || mode === 'local') {
        scoreDisplay.classList.add('hidden');
    } else {
        scoreDisplay.classList.remove('hidden');
        scoreDisplay.innerText = 'Score: 0';
    }

    showRound();
}

function showRound() {
    if (currentRound >= totalRounds) {
        endGame();
        return;
    }
    roundResolved = false;
    optionA.classList.remove('selected', 'disabled');
    optionB.classList.remove('selected', 'disabled');
    roundResult.innerHTML = '';
    btnNext.classList.add('hidden');
    waitingOverlay.classList.add('hidden');

    const pair = gamePairs[currentRound] || fallbackPairs[currentRound % fallbackPairs.length];
    optionA.innerText = pair[0];
    optionB.innerText = pair[1];

    if (mode === 'local') {
        roundDisplay.innerText = `Round ${currentRound + 1}/10 - Player ${localCurrentPlayer}'s Turn`;
    } else {
        roundDisplay.innerText = `Round ${currentRound + 1}/10`;
    }

    startTimer();
}

function startTimer() {
    clearInterval(timer);
    timeLeft = 15;
    timerBar.style.width = '100%';
    timerBar.style.transition = 'none';
    setTimeout(() => {
        timerBar.style.transition = 'width 1s linear';
        timer = setInterval(() => {
            timeLeft--;
            timerBar.style.width = `${(timeLeft / 15) * 100}%`;
            if (timeLeft <= 0) {
                clearInterval(timer);
                makeChoice(null);
            }
        }, 1000);
    }, 50);
}

function makeChoice(choice) {
    if (roundResolved) return;
    clearInterval(timer);
    optionA.classList.add('disabled');
    optionB.classList.add('disabled');
    if (choice === 'A') optionA.classList.add('selected');
    if (choice === 'B') optionB.classList.add('selected');

    if (mode === 'solo') {
        p1Choices[currentRound] = choice;
        setTimeout(nextRound, 700);
    } else if (mode === 'local') {
        if (localCurrentPlayer === 1) {
            p1Choices[currentRound] = choice;
            setTimeout(() => {
                btnNext.innerText = "Player 2's Turn";
                btnNext.classList.remove('hidden');
            }, 350);
        } else {
            p2Choices[currentRound] = choice;
            roundResolved = true;
            handleRoundResult(p1Choices[currentRound], p2Choices[currentRound]);
        }
    } else if (mode === 'online') {
        myChoices[currentRound] = choice;
        waitingOverlay.classList.remove('hidden');
        socket.emit('tot_choice', { room, round: currentRound, choice });
    }
}

function handleRoundResult(c1, c2) {
    const same = c1 === c2 && c1 !== null && c1 !== undefined;
    if (same) {
        score += 2;
        roundResult.innerHTML = '<span class="in-sync">In Sync! (+2 pts)</span>';
    } else {
        const pair = gamePairs[currentRound];
        const text1 = c1 ? pair[c1 === 'A' ? 0 : 1] : 'Timeout';
        const text2 = c2 ? pair[c2 === 'A' ? 0 : 1] : 'Timeout';
        roundResult.innerHTML = `<span class="split">Split! P1: ${text1} | P2: ${text2}</span>`;
    }

    scoreDisplay.innerText = `Score: ${score}`;
    setTimeout(() => {
        if (mode === 'local' || mode === 'online') {
            btnNext.innerText = 'Next Round';
            btnNext.classList.remove('hidden');
        } else {
            nextRound();
        }
    }, 1000);
}

function nextRound() {
    currentRound++;
    showRound();
}

function endGame() {
    gameScreen.classList.add('hidden');
    resultScreen.classList.remove('hidden');
    clearInterval(timer);

    let html = '';
    if (mode === 'solo') {
        document.getElementById('final-score').innerText = 'Your Preferences';
        document.getElementById('final-verdict').innerText = 'Thanks for playing';
        gamePairs.forEach((pair, i) => {
            const choice = p1Choices[i];
            const text = choice ? pair[choice === 'A' ? 0 : 1] : 'Timeout';
            html += `<div class="summary-item"><strong>Round ${i + 1}:</strong> ${pair[0]} vs ${pair[1]}<br>You picked: <em>${text}</em></div>`;
        });
    } else {
        const syncCount = score / 2;
        const percent = (syncCount / totalRounds) * 100;
        document.getElementById('final-score').innerText = `${syncCount}/${totalRounds} - ${Math.round(percent)}% In Sync`;
        let verdict = 'Opposites attract';
        if (percent >= 90) verdict = 'Almost perfectly in sync';
        else if (percent >= 70) verdict = 'Great minds';
        else if (percent >= 50) verdict = 'Beautifully different';
        document.getElementById('final-verdict').innerText = verdict;

        gamePairs.forEach((pair, i) => {
            const c1 = p1Choices[i];
            const c2 = p2Choices[i];
            const t1 = c1 ? pair[c1 === 'A' ? 0 : 1] : 'Timeout';
            const t2 = c2 ? pair[c2 === 'A' ? 0 : 1] : 'Timeout';
            const status = (c1 === c2 && c1) ? '<span style="color:var(--tot-success)">In Sync</span>' : '<span style="color:var(--tot-text-mut)">Split</span>';
            html += `<div class="summary-item"><strong>Round ${i + 1}: ${pair[0]} vs ${pair[1]}</strong>${status}<br>P1: ${t1} | P2: ${t2}</div>`;
        });
    }
    document.getElementById('history-container').innerHTML = html;
}
