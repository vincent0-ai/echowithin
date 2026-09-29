const urlParams = new URLSearchParams(window.location.search);
const room = urlParams.get('room');
const bondId = urlParams.get('bond_id');

let socket = null;
if (typeof io !== 'undefined') {
    socket = io();
}

// Word Bank (150+ words with AI emoji mappings for Solo mode)
const wordBank = {
    // Animals
    "dog": ["🐶", "🦴"], "cat": ["🐱", "🧶"], "elephant": ["🐘", "🥜"], "butterfly": ["🦋", "🌸"], 
    "penguin": ["🐧", "❄️"], "dolphin": ["🐬", "🌊"], "lion": ["🦁", "👑"], "tiger": ["🐅", "🥩"],
    "monkey": ["🐒", "🍌"], "bear": ["🐻", "🍯"], "rabbit": ["🐰", "🥕"], "frog": ["🐸", "🪷"],
    "turtle": ["🐢", "🏖️"], "snake": ["🐍", "🏜️"], "horse": ["🐎", "🤠"], "cow": ["🐄", "🥛"],
    "pig": ["🐷", "泥"], "chicken": ["🐔", "🥚"], "duck": ["🦆", "🍞"], "owl": ["🦉", "🌙"],
    "bat": ["🦇", "🧛"], "wolf": ["🐺", "🌕"], "fox": ["🦊", "🌲"], "deer": ["🦌", "🌲"],
    "whale": ["🐳", "🌊"], "shark": ["🦈", "🩸"], "octopus": ["🐙", "🌊"], "crab": ["🦀", "🏖️"],
    
    // Food
    "pizza": ["🍕", "🧀"], "sushi": ["🍣", "🍚"], "chocolate": ["🍫", "😋"], "coffee": ["☕", "🌅"], 
    "banana": ["🍌", "🐒"], "taco": ["🌮", "🇲🇽"], "burger": ["🍔", "🍟"], "hotdog": ["🌭", "⚾"],
    "fries": ["🍟", "🥔"], "icecream": ["🍦", "☀️"], "donut": ["🍩", "☕"], "cookie": ["🍪", "🥛"],
    "cake": ["🎂", "🎉"], "pie": ["🥧", "🍎"], "apple": ["🍎", "🐛"], "orange": ["🍊", "🧃"],
    "grape": ["🍇", "🍷"], "watermelon": ["🍉", "☀️"], "strawberry": ["🍓", "🍰"], "cherry": ["🍒", "🎰"],
    "peach": ["🍑", "🌳"], "pineapple": ["🍍", "🏝️"], "kiwi": ["🥝", "🐦"], "avocado": ["🥑", "🍞"],
    "tomato": ["🍅", "🥗"], "carrot": ["🥕", "🐰"], "corn": ["🌽", "🍿"], "broccoli": ["🥦", "🥗"],

    // Activities
    "swimming": ["🏊", "🌊"], "dancing": ["💃", "🎶"], "cooking": ["🍳", "👨‍🍳"], "sleeping": ["😴", "🛌"], 
    "reading": ["📖", "🤓"], "camping": ["⛺", "🔥"], "running": ["🏃", "👟"], "walking": ["🚶", "🌳"],
    "biking": ["🚴", "🚵"], "driving": ["🚗", "🛣️"], "flying": ["✈️", "☁️"], "sailing": ["⛵", "🌊"],
    "fishing": ["🎣", "🐟"], "hunting": ["🏹", "🦌"], "shopping": ["🛍️", "🛒"], "working": ["💼", "💻"],
    "studying": ["📚", "✏️"], "writing": ["✍️", "📝"], "painting": ["🎨", "🖌️"], "singing": ["🎤", "🎶"],
    "playing": ["🎮", "🕹️"], "watching": ["📺", "🍿"], "listening": ["🎧", "🎶"], "talking": ["🗣️", "📞"],

    // Places
    "beach": ["🏖️", "🌊"], "mountain": ["🏔️", "🧗"], "hospital": ["🏥", "🩺"], "school": ["🏫", "🎒"], 
    "castle": ["🏰", "👑"], "airport": ["✈️", "🧳"], "city": ["🏙️", "🚕"], "country": ["🏞️", "🚜"],
    "forest": ["🌲", "🐻"], "desert": ["🏜️", "🐪"], "island": ["🏝️", "🌴"], "space": ["🌌", "🚀"],
    "moon": ["🌕", "🚀"], "sun": ["☀️", "🌻"], "star": ["⭐", "🌌"], "planet": ["🪐", "🌌"],
    "house": ["🏠", "👨‍👩‍👧"], "apartment": ["🏢", "🏙️"], "hotel": ["🏨", "🧳"], "restaurant": ["🍽️", "🍷"],
    "bar": ["🍻", "🍸"], "cafe": ["☕", "🥐"], "store": ["🏪", "🛍️"], "mall": ["🏬", "🛍️"],

    // Emotions
    "love": ["❤️", "😍"], "angry": ["😡", "🤬"], "scared": ["😱", "😨"], "excited": ["🤩", "🎉"], 
    "surprised": ["😲", "🤯"], "nervous": ["😬", "💦"], "happy": ["😀", "😊"], "sad": ["😢", "😭"],
    "tired": ["🥱", "😴"], "bored": ["😒", "🥱"], "confused": ["😕", "🤷"], "proud": ["😌", "🏆"],
    "ashamed": ["😳", "🫣"], "guilty": ["🥺", "⛓️"], "jealous": ["😒", "💔"], "hopeful": ["🤞", "✨"],

    // Objects
    "umbrella": ["☔", "🌧️"], "guitar": ["🎸", "🎶"], "camera": ["📷", "🖼️"], "diamond": ["💎", "💍"], 
    "rocket": ["🚀", "🌌"], "rainbow": ["🌈", "🌧️"], "phone": ["📱", "📞"], "computer": ["💻", "⌨️"],
    "television": ["📺", "🛋️"], "radio": ["📻", "🎶"], "clock": ["🕰️", "⏳"], "watch": ["⌚", "⏱️"],
    "glasses": ["👓", "🤓"], "sunglasses": ["🕶️", "☀️"], "shoes": ["👟", "👞"], "hat": ["🎩", "🧢"],
    "shirt": ["👕", "👔"], "pants": ["👖", "🩳"], "dress": ["👗", "👠"], "ring": ["💍", "💎"]
};
const allWords = Object.keys(wordBank);

// Commonly used emoji for the picker
const commonEmojis = [
    // Faces
    "😀","😃","😄","😁","😆","😅","😂","🤣","🥲","☺️","😊","😇","🙂","🙃","😉","😌","😍","🥰","😘","😗","😙","😚","😋","😛",
    "😝","😜","🤪","🤨","🧐","🤓","😎","🥸","🤩","🥳","😏","😒","😞","😔","😟","😕","🙁","☹️","😣","😖","😫","😩","🥺","😢",
    "😭","😤","😠","😡","🤬","🤯","😳","🥵","🥶","😱","😨","😰","😥","😓","🫣","🤗","🫡","🤔","🫢","🤭","🤫","🤥","😶","😐",
    "😑","😬","🙄","😯","😦","😧","😮","😲","🥱","😴","🤤","😪","😵","🤐","🥴","🤢","🤮","🤧","😷","🤒","🤕","🤑","🤠","😈",
    "👿","👹","👺","🤡","💩","👻","💀","👽","👾","🤖",
    // Hearts & Emotions
    "❤️","🧡","💛","💚","💙","💜","🤎","🖤","🤍","💔","❤️‍🔥","❤️‍🩹","❣️","💕","💞","💓","💗","💖","💘","💝","💟","☮️","✝️","☪️","🕉️",
    "☸️","✡️","🔯","🕎","☯️","☦️","🛐","⛎","♈","♉","♊","♋","♌","♍","♎","♏","♐","♑","♒","♓","🆔","⚛️",
    // Nature & Animals
    "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐻‍❄️","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔","🐧","🐦","🐤","🦆","🦅","🦉","🦇",
    "🐺","🐗","🐴","🦄","🐝","🪱","🐛","🦋","🐌","🐞","🐜","🪰","🪲","🪳","🦟","🦗","🕷️","🦂","🐢","🐍","🦎","🦖","🦕","🐙",
    "🦑","🦐","🦞","🦀","🐡","🐠","🐟","🐬","🐳","🐋","🦈","🦭","🐊","🐅","🐆","🦓","🦍","🦧","🦣","🐘","🦛","🦏","🐪","🐫",
    "🦒","🦘","🦬","🐃","🐂","🐄","🐎","🐖","🐏","🐑","🦙","🐐","🦌","🐕","🐩","🦮","🐕‍🦺","🐈","🐈‍⬛","🪶","🐓","🦃","🦤","🦚",
    "🦜","🦢","🦩","🕊️","🐇","🦝","🦨","🦡","🦫","🦦","🦥","🐁","🐀","🐿️","🦔","🐾","🐉","🐲","🌵","🎄","🌲","🌳","🌴","🪵",
    // Food & Drink
    "🍇","🍈","🍉","🍊","🍋","🍌","🍍","🥭","🍎","🍏","🍐","🍑","🍒","🍓","🫐","🥝","🍅","🫒","🥥","🥑","🍆","🥔","🥕","🌽",
    "🌶️","🫑","🥒","🥬","🥦","🧄","🧅","🍄","🥜","🫘","🌰","🍞","🥐","🥖","🫓","🥨","🥯","🥞","🧇","🧀","🍖","🍗","🥩","🥓",
    "🍔","🍟","🍕","🌭","🥪","🌮","🌯","🫔","🥙","🧆","🥚","🍳","🥘","🍲","🫕","🥣","🥗","🍿","🧈","🧂","🥫","🍱","🍘","🍙",
    "🍚","🍛","🍜","🍝","🍠","🍢","🍣","🍤","🍥","🥮","🍡","🥟","🥠","🥡","🦀","🦞","🦐","🦑","🦪","🍦","🍧","🍨","🍩","🍪",
    "🎂","🍰","🧁","🥧","🍫","🍬","🍭","🍮","🍯","🍼","🥛","☕","🫖","🍵","🍶","🍾","🍷","🍸","🍹","🍺","🍻","🥂","🥃","🥤",
    "🧋","🧃","🧉","🧊","🥢","🍽️","🍴","🥄","🔪","🏺",
    // Activities & Objects
    "⚽","🏀","🏈","⚾","🥎","🎾","🏐","🏉","🥏","🎱","🪀","🏓","🏸","🏒","🏑","🥍","🏏","🪃","🥅","⛳","🪁","🏹","🎣","🤿",
    "🥊","🥋","🎽","🛹","🛼","🛷","⛸️","🥌","🎿","⛷️","🏂","🪂","🏋️","🤼","🤸","⛹️","🤺","🤾","🏌️","🏇","🧘","🏄","🏊","🤽",
    "🚣","🧗","🚵","🚴","🏆","🥇","🥈","🥉","🏅","🎖️","🏵️","🎗️","🎫","🎟️","🎪","🤹","🎭","🩰","🎨","🎬","🎤","🎧","🎼","🎹",
    "🥁","🪘","🎷","🎺","🪗","🎸","🪕","🎻","🎲","♟️","🎯","🎳","🎮","🎰","🧩"
];

// State
let mode = null; // 'solo', 'local', 'online'
let role = null; // 'giver', 'guesser'
let currentRound = 1;
const maxRounds = 10;
let score = 0;
let currentWord = "";
let currentClue = [];
let attemptsLeft = 3;
let isPlayer1 = true; // In local/online, player 1 starts as giver

// UI Elements
const screens = {
    menu: document.getElementById('screen-menu'),
    giver: document.getElementById('screen-giver'),
    guesser: document.getElementById('screen-guesser'),
    wait: document.getElementById('screen-wait'),
    result: document.getElementById('screen-result'),
    end: document.getElementById('screen-end')
};

// Initialization
function showScreen(screenId) {
    Object.values(screens).forEach(s => s.classList.remove('active'));
    screens[screenId].classList.add('active');
}

function updateStats() {
    document.getElementById('stats-bar').style.display = 'flex';
    document.getElementById('stat-round').innerText = `Round: ${currentRound}/${maxRounds}`;
    document.getElementById('stat-score').innerText = `Score: ${score}`;
}

// Mode Selection
document.getElementById('btn-solo').onclick = () => startSolo();
document.getElementById('btn-local').onclick = () => startLocal();
document.getElementById('btn-online').onclick = () => startOnline();

// --- SOLO MODE ---
function startSolo() {
    mode = 'solo';
    score = 0;
    currentRound = 1;
    playSoloRound();
}

function playSoloRound() {
    if (currentRound > maxRounds) return endGame();
    
    currentWord = allWords[Math.floor(Math.random() * allWords.length)];
    currentClue = wordBank[currentWord] || ["❓"];
    
    attemptsLeft = 3;
    role = 'guesser';
    
    updateStats();
    showScreen('guesser');
    document.getElementById('received-clue').innerText = currentClue.join("");
    document.getElementById('guess-input').value = "";
    document.getElementById('guess-feedback').innerText = "";
    document.getElementById('attempts-left').innerText = attemptsLeft;
}

// --- LOCAL MODE ---
function startLocal() {
    mode = 'local';
    score = 0;
    currentRound = 1;
    isPlayer1 = true;
    playLocalRound();
}

function playLocalRound() {
    if (currentRound > maxRounds) return endGame();
    
    currentWord = allWords[Math.floor(Math.random() * allWords.length)];
    currentClue = [];
    attemptsLeft = 3;
    
    // Switch roles every round
    role = (currentRound % 2 !== 0) ? 'giver' : 'guesser'; 
    // Wait, in Pass & Play, someone has to be Giver, then they pass device to Guesser.
    
    updateStats();
    
    // Giver screen setup
    showScreen('giver');
    document.getElementById('secret-word').innerText = currentWord;
    document.getElementById('current-clue-builder').innerText = "";
    document.getElementById('btn-submit-clue').disabled = true;
    
    alert(`Pass the device to Player ${(currentRound % 2 !== 0) ? "1" : "2"} (Clue Giver). Press OK when ready.`);
}

// --- ONLINE MODE ---
function startOnline() {
    mode = 'online';
    if (!room || !bondId) {
        alert("Missing room or bond ID in URL.");
        return;
    }
    
    document.getElementById('room-info').style.display = 'block';
    document.getElementById('room-code-display').innerText = room;
    document.getElementById('btn-solo').disabled = true;
    document.getElementById('btn-local').disabled = true;
    document.getElementById('btn-online').disabled = true;
    
    socket.emit('emoji_join_room', { room, bond_id: bondId });
}

if (socket) {
    socket.on('emoji_room_joined', (data) => {
        isPlayer1 = data.is_creator;
        if (data.player_count === 2) {
            if (isPlayer1) {
                // Creator starts the first round
                startOnlineRound();
            }
        }
    });
    
    socket.on('emoji_round_started', (data) => {
        currentRound = data.round;
        currentWord = data.word;
        role = (isPlayer1 === data.giver_is_p1) ? 'giver' : 'guesser';
        attemptsLeft = 3;
        currentClue = [];
        
        updateStats();
        
        if (role === 'giver') {
            showScreen('giver');
            document.getElementById('secret-word').innerText = currentWord;
            document.getElementById('current-clue-builder').innerText = "";
            document.getElementById('btn-submit-clue').disabled = true;
        } else {
            showScreen('wait');
            document.getElementById('wait-msg').innerText = "Waiting for Clue Giver...";
        }
    });
    
    socket.on('emoji_clue_submitted', (data) => {
        if (role === 'guesser') {
            currentClue = data.clue;
            showScreen('guesser');
            document.getElementById('received-clue').innerText = currentClue.join("");
            document.getElementById('guess-input').value = "";
            document.getElementById('guess-feedback').innerText = "";
            document.getElementById('attempts-left').innerText = attemptsLeft;
        } else {
            showScreen('wait');
            document.getElementById('wait-msg').innerText = "Waiting for Guesser...";
        }
    });
    
    socket.on('emoji_guess_result', (data) => {
        if (data.correct) {
            score += data.points;
            showResultScreen(true, data.points);
        } else {
            attemptsLeft = data.attempts_left;
            if (attemptsLeft > 0) {
                if (role === 'guesser') {
                    document.getElementById('guess-feedback').innerText = "Incorrect! Try again.";
                    document.getElementById('guess-feedback').className = "error-msg";
                    document.getElementById('attempts-left').innerText = attemptsLeft;
                    document.getElementById('guess-input').value = "";
                }
            } else {
                showResultScreen(false, 0);
            }
        }
    });
}

function startOnlineRound() {
    socket.emit('emoji_start_round', {
        room, bond_id: bondId,
        round: currentRound,
        word: allWords[Math.floor(Math.random() * allWords.length)],
        giver_is_p1: (currentRound % 2 !== 0)
    });
}


// --- CLUE GIVER LOGIC ---
const emojiPickerContainer = document.getElementById('emoji-picker-container');
commonEmojis.forEach(emoji => {
    const btn = document.createElement('button');
    btn.className = 'emoji-btn';
    btn.innerText = emoji;
    btn.onclick = () => {
        if (currentClue.length < 5) {
            currentClue.push(emoji);
            document.getElementById('current-clue-builder').innerText = currentClue.join("");
            document.getElementById('btn-submit-clue').disabled = false;
        }
    };
    emojiPickerContainer.appendChild(btn);
});

document.getElementById('btn-clear-clue').onclick = () => {
    currentClue = [];
    document.getElementById('current-clue-builder').innerText = "";
    document.getElementById('btn-submit-clue').disabled = true;
};

document.getElementById('btn-submit-clue').onclick = () => {
    if (currentClue.length === 0) return;
    
    if (mode === 'local') {
        alert("Pass the device to the Guesser. Press OK when ready.");
        showScreen('guesser');
        document.getElementById('received-clue').innerText = currentClue.join("");
        document.getElementById('guess-input').value = "";
        document.getElementById('guess-feedback').innerText = "";
        document.getElementById('attempts-left').innerText = attemptsLeft;
    } else if (mode === 'online') {
        socket.emit('emoji_submit_clue', { room, bond_id: bondId, clue: currentClue });
    }
};

// --- GUESSER LOGIC ---
document.getElementById('btn-submit-guess').onclick = () => {
    const guess = document.getElementById('guess-input').value.trim().toLowerCase();
    if (!guess) return;
    
    if (mode === 'solo' || mode === 'local') {
        if (guess === currentWord.toLowerCase()) {
            // Correct
            const points = calculatePoints();
            score += points;
            showResultScreen(true, points);
        } else {
            // Incorrect
            attemptsLeft--;
            document.getElementById('attempts-left').innerText = attemptsLeft;
            if (attemptsLeft > 0) {
                document.getElementById('guess-feedback').innerText = "Incorrect! Try again.";
                document.getElementById('guess-feedback').className = "error-msg";
                document.getElementById('guess-input').value = "";
            } else {
                showResultScreen(false, 0);
            }
        }
    } else if (mode === 'online') {
        if (guess === currentWord.toLowerCase()) {
            socket.emit('emoji_submit_guess', { room, bond_id: bondId, correct: true, points: calculatePoints() });
        } else {
            socket.emit('emoji_submit_guess', { room, bond_id: bondId, correct: false, attempts_left: attemptsLeft - 1 });
        }
    }
};

document.getElementById('guess-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        document.getElementById('btn-submit-guess').click();
    }
});

function calculatePoints() {
    // Fewer emojis = more points
    const base = 100;
    const penalty = (currentClue.length - 1) * 10;
    return Math.max(10, base - penalty);
}

// --- RESULTS ---
function showResultScreen(isWin, points) {
    showScreen('result');
    document.getElementById('result-word-reveal').innerText = `The word was: ${currentWord.toUpperCase()}`;
    if (isWin) {
        document.getElementById('result-points').innerText = `Correct! +${points} points`;
        document.getElementById('result-points').className = "success-msg";
    } else {
        document.getElementById('result-points').innerText = `Out of attempts!`;
        document.getElementById('result-points').className = "error-msg";
    }
}

document.getElementById('btn-next-round').onclick = () => {
    currentRound++;
    if (mode === 'solo') {
        playSoloRound();
    } else if (mode === 'local') {
        playLocalRound();
    } else if (mode === 'online') {
        if (isPlayer1) {
            startOnlineRound();
        } else {
            showScreen('wait');
            document.getElementById('wait-msg').innerText = "Waiting for next round to start...";
        }
    }
};

function endGame() {
    showScreen('end');
    document.getElementById('final-score-display').innerText = `Final Score: ${score}`;
    document.getElementById('stats-bar').style.display = 'none';
}
