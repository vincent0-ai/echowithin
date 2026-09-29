const pairsBank = [
    // Relationship & Lifestyle
    ["Cook dinner together", "Order takeout"], ["Movie night in", "Night out dancing"],
    ["Sunrise", "Sunset"], ["Beach vacation", "Mountain cabin"],
    ["Text goodnight", "Call goodnight"], ["Big wedding", "Small elopement"],
    ["City life", "Country life"], ["Stay up late", "Wake up early"],
    ["Share dessert", "Get own desserts"], ["Matching outfits", "Complementary outfits"],
    ["Road trip", "Fly to destination"], ["Hotel", "Airbnb"],
    ["Handwritten letter", "Surprise gift"], ["Cuddle in silence", "Deep conversations"],
    ["Home cooked meal", "Fancy restaurant"], ["Double date", "Just the two of us"],
    ["Morning person", "Night owl"], ["Save money", "Spend money"],
    ["Routine", "Spontaneity"], ["Texting", "Calling"],
    // Personality
    ["Plan everything", "Be spontaneous"], ["Talk it out", "Need space first"],
    ["Sweet", "Savory"], ["Summer", "Winter"], ["Dogs", "Cats"],
    ["Books", "Movies"], ["Introvert", "Extrovert"], ["Window seat", "Aisle seat"],
    ["Messy", "Neat"], ["Logic", "Emotion"], ["Optimist", "Realist"],
    ["Leader", "Follower"], ["Work hard", "Play hard"], ["Coffee", "Tea"],
    ["Beer", "Wine"], ["Podcast", "Music"], ["Read the book", "Watch the movie"],
    ["Comedy", "Drama"], ["Horror", "Rom-com"], ["Action", "Sci-fi"],
    // Fun Hypotheticals
    ["Time travel to past", "Time travel to future"], ["Invisibility", "Flying"],
    ["Always too hot", "Always too cold"], ["No phone for a week", "No food seasoning for a month"],
    ["Live in a treehouse", "Live in a submarine"], ["Read minds", "See the future"],
    ["Teleportation", "Super strength"], ["Zombie apocalypse", "Alien invasion"],
    ["Lose all memories", "Lose all possessions"], ["Be Batman", "Be Superman"],
    ["Live on Mars", "Live under the ocean"], ["Breathe underwater", "Fly"],
    ["Talk to animals", "Speak all languages"], ["Unlimited money", "Unlimited time"],
    ["Never sleep", "Never eat"], ["Stop time", "Rewind time"],
    // Food & Drink
    ["Pizza", "Burgers"], ["Tacos", "Sushi"], ["Ice cream", "Cake"],
    ["Pancakes", "Waffles"], ["Bacon", "Sausage"], ["Ketchup", "Mustard"],
    ["Coke", "Pepsi"], ["Sparkling water", "Still water"], ["White wine", "Red wine"],
    ["Dark chocolate", "Milk chocolate"], ["Vanilla", "Chocolate"], ["Apples", "Oranges"],
    ["Smoothie", "Juice"], ["Spicy", "Mild"], ["Pasta", "Rice"],
    ["Fries", "Onion rings"], ["Mashed potatoes", "Baked potatoes"], ["Steak", "Chicken"],
    // Travel & Adventure
    ["Europe", "Asia"], ["Road trip", "Cruise"], ["Resort", "Backpacking"],
    ["Historical sites", "Nature trails"], ["Amusement park", "National park"],
    ["Pool", "Ocean"], ["Train", "Bus"], ["Skiing", "Surfing"],
    ["Camping", "Glamping"], ["Museums", "Shopping"], ["Local food", "Familiar food"],
    ["Tour guide", "Explore alone"], ["Packed schedule", "Relaxing schedule"],
    ["Photos", "Videos"], ["Souvenirs", "Memories"], ["Window shopping", "Actual shopping"],
    // Entertainment
    ["Netflix", "YouTube"], ["Spotify", "Apple Music"], ["Marvel", "DC"],
    ["Star Wars", "Star Trek"], ["Board games", "Video games"], ["PlayStation", "Xbox"],
    ["PC gaming", "Console gaming"], ["Pop", "Rock"], ["Hip hop", "R&B"],
    ["Live concert", "Music festival"], ["Theater", "Cinema"], ["Fiction", "Non-fiction"],
    ["Audiobooks", "Physical books"], ["Kindle", "Paperback"], ["Drawing", "Painting"],
    ["Singing", "Dancing"], ["Guitar", "Piano"], ["Photography", "Videography"],
    ["Twitter", "Instagram"], ["TikTok", "Reddit"]
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
let score = 0;
let timer = null;
let timeLeft = 15;
let myPlayerNum = 1;
let localCurrentPlayer = 1;

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

function shuffle(array) {
    let cur = array.length, rand;
    while (cur != 0) {
        rand = Math.floor(Math.random() * cur);
        cur--;
        [array[cur], array[rand]] = [array[rand], array[cur]];
    }
    return array;
}

function initOnline() {
    const params = new URLSearchParams(window.location.search);
    room = params.get('room') || 'default_room';
    bondId = params.get('bond_id') || 'default_bond';
    
    document.getElementById('online-status').classList.remove('hidden');
    
    if (typeof io !== 'undefined') {
        socket = io();
        socket.emit('tot_join_room', { room, bond_id: bondId });
        
        // Use generic broadcast_to_room for socket logic if specific endpoints aren't implemented
        socket.on('broadcast_to_room', (data) => {
            if (data.event === 'tot_sync_pairs') {
                gamePairs = data.data.pairs;
                myPlayerNum = 2; // I received it, so I am player 2
                document.getElementById('online-status').innerText = 'Partner found! Starting...';
                setTimeout(() => startGame('online', true), 500);
            } else if (data.event === 'tot_choice_made') {
                if (data.data.playerNum !== myPlayerNum) {
                    p2Choices[currentRound] = data.data.choice;
                    checkBothAnsweredOnline();
                }
            }
        });
        
        // Simulating the room state locally
        setTimeout(() => {
            if (!gamePairs.length) {
                // I am host
                myPlayerNum = 1;
                let shuffled = shuffle([...pairsBank]);
                gamePairs = shuffled.slice(0, 10);
                socket.emit('broadcast_to_room', { room, event: 'tot_sync_pairs', data: { pairs: gamePairs } });
                document.getElementById('online-status').innerText = 'Starting...';
                startGame('online', true);
            }
        }, 1500); 
    } else {
        document.getElementById('online-status').innerText = 'Socket.IO not available.';
    }
}

function emitSocket(event, data) {
    if (socket) {
        socket.emit('broadcast_to_room', { room, event, data });
    }
}

function startGame(selectedMode, isOnlineInit = false) {
    mode = selectedMode;
    currentRound = 0;
    score = 0;
    p1Choices = [];
    p2Choices = [];
    
    if (mode !== 'online' || !isOnlineInit) {
        let shuffled = shuffle([...pairsBank]);
        gamePairs = shuffled.slice(0, 10);
    }
    
    setupScreen.classList.add('hidden');
    gameScreen.classList.remove('hidden');
    
    if (mode === 'solo' || mode === 'local') {
        scoreDisplay.classList.add('hidden');
    } else {
        scoreDisplay.classList.remove('hidden');
        scoreDisplay.innerText = `Score: 0`;
    }
    
    showRound();
}

function showRound() {
    if (currentRound >= totalRounds) {
        endGame();
        return;
    }
    
    optionA.classList.remove('selected', 'disabled');
    optionB.classList.remove('selected', 'disabled');
    roundResult.innerHTML = '';
    btnNext.classList.add('hidden');
    waitingOverlay.classList.add('hidden');
    
    const pair = gamePairs[currentRound];
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
                if (mode === 'solo' || mode === 'local') {
                    makeChoice(null);
                } else if (mode === 'online') {
                    if (p1Choices[currentRound] === undefined) {
                        makeChoice(null);
                    }
                }
            }
        }, 1000);
    }, 50);
}

function makeChoice(choice) {
    clearInterval(timer);
    optionA.classList.add('disabled');
    optionB.classList.add('disabled');
    
    if (choice === 'A') optionA.classList.add('selected');
    if (choice === 'B') optionB.classList.add('selected');
    
    if (mode === 'solo') {
        p1Choices[currentRound] = choice;
        setTimeout(nextRound, 1000);
    } else if (mode === 'local') {
        if (localCurrentPlayer === 1) {
            p1Choices[currentRound] = choice;
            setTimeout(() => {
                btnNext.innerText = "Player 2's Turn";
                btnNext.classList.remove('hidden');
            }, 500);
        } else {
            p2Choices[currentRound] = choice;
            handleRoundResult(p1Choices[currentRound], p2Choices[currentRound]);
        }
    } else if (mode === 'online') {
        p1Choices[currentRound] = choice;
        emitSocket('tot_choice_made', { playerNum: myPlayerNum, choice: choice });
        waitingOverlay.classList.remove('hidden');
        checkBothAnsweredOnline();
    }
}

function checkBothAnsweredOnline() {
    if (p1Choices[currentRound] !== undefined && p2Choices[currentRound] !== undefined) {
        waitingOverlay.classList.add('hidden');
        let myC = p1Choices[currentRound];
        let opC = p2Choices[currentRound];
        let c1 = myPlayerNum === 1 ? myC : opC;
        let c2 = myPlayerNum === 1 ? opC : myC;
        handleRoundResult(c1, c2);
    }
}

function handleRoundResult(c1, c2) {
    let same = (c1 === c2 && c1 !== null);
    if (same) {
        score += 2;
        roundResult.innerHTML = `<span class="in-sync">In Sync! (+2 pts)</span>`;
    } else {
        let text1 = c1 ? gamePairs[currentRound][c1==='A'?0:1] : 'Timeout';
        let text2 = c2 ? gamePairs[currentRound][c2==='A'?0:1] : 'Timeout';
        roundResult.innerHTML = `<span class="split">Split! P1: ${text1} | P2: ${text2}</span>`;
    }
    
    scoreDisplay.innerText = `Score: ${score}`;
    
    setTimeout(() => {
        if (mode === 'local' || mode === 'online') {
            btnNext.innerText = "Next Round";
            btnNext.classList.remove('hidden');
        } else {
            nextRound();
        }
    }, 1500);
}

function nextRound() {
    currentRound++;
    showRound();
}

function endGame() {
    gameScreen.classList.add('hidden');
    resultScreen.classList.remove('hidden');
    
    let html = '';
    if (mode === 'solo') {
        document.getElementById('final-score').innerText = 'Your Preferences:';
        document.getElementById('final-verdict').innerText = 'Thanks for playing!';
        gamePairs.forEach((pair, i) => {
            let choice = p1Choices[i];
            let text = choice ? pair[choice==='A'?0:1] : 'Timeout';
            html += `<div class="summary-item"><strong>Round ${i+1}:</strong> ${pair[0]} vs ${pair[1]}<br>You picked: <em>${text}</em></div>`;
        });
    } else {
        let syncCount = score / 2;
        let percent = (syncCount / totalRounds) * 100;
        document.getElementById('final-score').innerText = `${syncCount}/${totalRounds} — ${Math.round(percent)}% In Sync!`;
        
        let verdict = '';
        if (percent >= 90) verdict = 'Soulmates!';
        else if (percent >= 70) verdict = 'Great minds!';
        else if (percent >= 50) verdict = 'Beautifully different';
        else verdict = 'Opposites attract!';
        document.getElementById('final-verdict').innerText = verdict;
        
        gamePairs.forEach((pair, i) => {
            let c1, c2;
            if (mode === 'local') {
                c1 = p1Choices[i];
                c2 = p2Choices[i];
            } else {
                c1 = myPlayerNum === 1 ? p1Choices[i] : p2Choices[i];
                c2 = myPlayerNum === 1 ? p2Choices[i] : p1Choices[i];
            }
            
            let t1 = c1 ? pair[c1==='A'?0:1] : 'Timeout';
            let t2 = c2 ? pair[c2==='A'?0:1] : 'Timeout';
            
            let status = (c1===c2 && c1!==null) ? '<span style="color:var(--tot-success)">In Sync!</span>' : '<span style="color:var(--tot-text-mut)">Split</span>';
            
            html += `<div class="summary-item">
                <strong>Round ${i+1}: ${pair[0]} vs ${pair[1]}</strong>
                ${status}<br>
                P1: ${t1} | P2: ${t2}
            </div>`;
        });
    }
    
    document.getElementById('history-container').innerHTML = html;
}
