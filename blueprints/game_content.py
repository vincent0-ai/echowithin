"""Server-owned content selection for lightweight games.

The host/session creates the seed and content set here, then sockets deliver the
same payload to both players. External APIs are optional enrichments elsewhere;
these local banks keep games playable when an API is unavailable or rate-limited.
"""

import datetime
import hashlib
import random
import secrets

import database


THIS_OR_THAT_BANK = [
    ("Cook dinner together", "Order takeout"),
    ("Movie night in", "Night out dancing"),
    ("Sunrise", "Sunset"),
    ("Beach vacation", "Mountain cabin"),
    ("Text goodnight", "Call goodnight"),
    ("Big wedding", "Small elopement"),
    ("City life", "Country life"),
    ("Stay up late", "Wake up early"),
    ("Share dessert", "Get own desserts"),
    ("Road trip", "Fly to destination"),
    ("Handwritten letter", "Surprise gift"),
    ("Cuddle in silence", "Deep conversations"),
    ("Home cooked meal", "Fancy restaurant"),
    ("Plan everything", "Be spontaneous"),
    ("Talk it out", "Need space first"),
    ("Sweet", "Savory"),
    ("Summer", "Winter"),
    ("Books", "Movies"),
    ("Window seat", "Aisle seat"),
    ("Logic", "Emotion"),
    ("Coffee", "Tea"),
    ("Comedy", "Drama"),
    ("Time travel to past", "Time travel to future"),
    ("Invisibility", "Flying"),
    ("Teleportation", "Super strength"),
    ("Unlimited money", "Unlimited time"),
    ("Pizza", "Burgers"),
    ("Tacos", "Sushi"),
    ("Pancakes", "Waffles"),
    ("Spicy", "Mild"),
    ("Camping", "Glamping"),
    ("Packed schedule", "Relaxing schedule"),
    ("Photos", "Videos"),
    ("Netflix", "YouTube"),
    ("Board games", "Video games"),
    ("Live concert", "Music festival"),
    ("Slow dance", "Karaoke night"),
    ("Puppies", "Kittens"),
    ("Picnic in the park", "Rooftop dinner"),
    ("Museum day", "Amusement park"),
    ("Matching outfits", "Opposite styles"),
    ("Early morning hike", "Midnight drive"),
    ("Garden together", "DIY project"),
    ("Save for travel", "Save for a house"),
    ("Front-row seats", "Back-row cuddles"),
    ("Hot chocolate", "Mulled wine"),
    ("Rainy day in", "Sunny day out"),
    ("Journal together", "Vlog together"),
    ("Learn a language", "Learn an instrument"),
    ("Puzzle night", "Trivia night"),
    ("Thrift shopping", "Mall shopping"),
    ("Sunrise coffee", "Midnight snacks"),
    ("Hold hands", "Arm around shoulder"),
    ("Long texts", "Voice notes"),
    ("Anniversary trip", "Anniversary party"),
    ("Dance in the rain", "Sing in the car"),
    ("Charades", "Pictionary"),
    ("Stargaze", "Cloud-watch"),
    ("Breakfast in bed", "Midnight feast"),
    ("Apologize first", "Forgive first"),
]


MEMORY_EMOJIS = [
    "heart", "ring", "rose", "home", "sun", "moon", "star", "music",
    "camera", "cake", "wave", "fire", "butterfly", "flower", "theater",
    "diamond", "gift", "spark",
]

MEMORY_SYMBOLS = {
    "heart": "HEART",
    "ring": "RING",
    "rose": "ROSE",
    "home": "HOME",
    "sun": "SUN",
    "moon": "MOON",
    "star": "STAR",
    "music": "MUSIC",
    "camera": "PHOTO",
    "cake": "CAKE",
    "wave": "WAVE",
    "fire": "FIRE",
    "butterfly": "BUTTERFLY",
    "flower": "FLOWER",
    "theater": "THEATER",
    "diamond": "DIAMOND",
    "gift": "GIFT",
    "spark": "SPARK",
}


WORD_CHAIN_STARTERS = [
    "coffee", "sunset", "garden", "music", "journey", "movie", "beach",
    "kitchen", "dream", "letter", "puzzle", "dance", "winter", "picnic",
    "camera", "story", "lighthouse", "rain", "festival", "comfort",
]


EMOJI_CHARADES_BANK = [
    {"id": "emoji_road_trip", "answer": "Road trip", "hint": "A shared adventure by car", "clue": ["car", "map", "music"]},
    {"id": "emoji_movie_night", "answer": "Movie night", "hint": "Screens, snacks, and staying in", "clue": ["popcorn", "tv", "sofa"]},
    {"id": "emoji_breakfast_bed", "answer": "Breakfast in bed", "hint": "A cozy morning surprise", "clue": ["eggs", "coffee", "bed"]},
    {"id": "emoji_sunset_walk", "answer": "Sunset walk", "hint": "A golden-hour stroll", "clue": ["sunset", "feet", "heart"]},
    {"id": "emoji_karaoke", "answer": "Karaoke night", "hint": "Singing loudly, accuracy optional", "clue": ["microphone", "music", "laugh"]},
    {"id": "emoji_picnic", "answer": "Picnic date", "hint": "Food outdoors on a blanket", "clue": ["basket", "sandwich", "sun"]},
    {"id": "emoji_stargazing", "answer": "Stargazing", "hint": "Counting constellations together", "clue": ["stars", "night", "moon"]},
    {"id": "emoji_baking", "answer": "Baking cookies", "hint": "Sweet treats from the oven", "clue": ["cookie", "oven", "smile"]},
    {"id": "emoji_beach", "answer": "Beach day", "hint": "Sand, waves and sun", "clue": ["beach", "sun", "smile"]},
    {"id": "emoji_game_night", "answer": "Game night", "hint": "Cards, dice and laughter", "clue": ["cards", "laugh", "night"]},
    {"id": "emoji_first_date", "answer": "First date", "hint": "Where it all began", "clue": ["heart", "coffee", "smile"]},
    {"id": "emoji_dance", "answer": "Dance party", "hint": "Moving to the beat", "clue": ["music", "party", "laugh"]},
    {"id": "emoji_cooking", "answer": "Cooking together", "hint": "Two chefs, one kitchen", "clue": ["food", "fire", "smile"]},
    {"id": "emoji_rain", "answer": "Rainy day", "hint": "Puddles and grey skies", "clue": ["rain", "cloud", "sofa"]},
    {"id": "emoji_garden", "answer": "Gardening", "hint": "Planting flowers side by side", "clue": ["flower", "sun", "smile"]},
    {"id": "emoji_proposal", "answer": "Marriage proposal", "hint": "Down on one knee", "clue": ["ring", "heart", "smile"]},
    {"id": "emoji_snow", "answer": "Snow day", "hint": "White winter fun", "clue": ["snow", "smile", "play"]},
]


CROSSWORD_PACK = [
    {
        "id": "mini_heart",
        "title": "Sweethearts",
        "size": 5,
        "solution": list("HEARTOMEGANOVELELITEYEAST"),
        "clues": {
            "across": [
                {"num": 1, "r": 0, "c": 0, "clue": "Symbol of romance"},
                {"num": 6, "r": 1, "c": 0, "clue": "Final Greek letter"},
                {"num": 7, "r": 2, "c": 0, "clue": "Bedtime reading"},
                {"num": 8, "r": 3, "c": 0, "clue": "Top tier"},
                {"num": 9, "r": 4, "c": 0, "clue": "Bread-making organism"},
            ],
            "down": [
                {"num": 1, "r": 0, "c": 0, "clue": "Sweet term of endearment"},
                {"num": 2, "r": 0, "c": 1, "clue": "Whole amount"},
                {"num": 3, "r": 0, "c": 2, "clue": "Single airplane flight"},
                {"num": 4, "r": 0, "c": 3, "clue": "Highway"},
                {"num": 5, "r": 0, "c": 4, "clue": "Sample dessert"},
            ],
        },
    },
    {
        "id": "mini_smile",
        "title": "Morning Smile",
        "size": 5,
        "solution": list("SMILEHAVENADOREROUNDENTER"),
        "clues": {
            "across": [
                {"num": 1, "r": 0, "c": 0, "clue": "Warm greeting"},
                {"num": 6, "r": 1, "c": 0, "clue": "Safe retreat"},
                {"num": 7, "r": 2, "c": 0, "clue": "Love deeply"},
                {"num": 8, "r": 3, "c": 0, "clue": "Circular"},
                {"num": 9, "r": 4, "c": 0, "clue": "Go inside"},
            ],
            "down": [
                {"num": 1, "r": 0, "c": 0, "clue": "Give a portion"},
                {"num": 2, "r": 0, "c": 1, "clue": "Madly in love"},
                {"num": 3, "r": 0, "c": 2, "clue": "Ivory tower resident"},
                {"num": 4, "r": 0, "c": 3, "clue": "Acquire knowledge"},
                {"num": 5, "r": 0, "c": 4, "clue": "Conclusion"},
            ],
        },
    },
    {
        "id": "mini_cabin",
        "title": "Weekend Cabin",
        "size": 5,
        "solution": list("CABINAROMABEACHIMBUENAPES"),
        "clues": {
            "across": [
                {"num": 1, "r": 0, "c": 0, "clue": "Cozy wooden shelter"},
                {"num": 6, "r": 1, "c": 0, "clue": "Pleasant fragrance"},
                {"num": 7, "r": 2, "c": 0, "clue": "Sandy shore"},
                {"num": 8, "r": 3, "c": 0, "clue": "Saturate with feeling"},
                {"num": 9, "r": 4, "c": 0, "clue": "Backs of necks"},
            ],
            "down": [
                {"num": 1, "r": 0, "c": 0, "clue": "Place to sleep on a train"},
                {"num": 2, "r": 0, "c": 1, "clue": "Single flower branch"},
                {"num": 3, "r": 0, "c": 2, "clue": "Small fruit"},
                {"num": 4, "r": 0, "c": 3, "clue": "Polar formation"},
                {"num": 5, "r": 0, "c": 4, "clue": "Bird resting perches"},
            ],
        },
    },
]


def new_seed():
    return secrets.randbelow(1_000_000_000)


def content_id(prefix, value):
    raw = repr(value).encode("utf-8", "ignore")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"{prefix}:{digest}"


def recent_content_ids(pair_key, game_id, limit=80):
    db = getattr(database, "db", None)
    if db is None or not pair_key:
        return set()
    try:
        cursor = db["game_recent_content"].find(
            {"pair_key": pair_key, "game_id": game_id},
            {"content_id": 1},
        ).sort("seen_at", -1).limit(limit)
        return {doc.get("content_id") for doc in cursor if doc.get("content_id")}
    except Exception:
        return set()


def remember_content(pair_key, game_id, ids):
    db = getattr(database, "db", None)
    if db is None or not pair_key:
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        col = db["game_recent_content"]
        for cid in ids:
            col.update_one(
                {"pair_key": pair_key, "game_id": game_id, "content_id": cid},
                {"$set": {"seen_at": now}},
                upsert=True,
            )
    except Exception:
        pass


def _choose_items(items, count, seed, pair_key, game_id, prefix):
    rng = random.Random(seed)
    shuffled = list(items)
    rng.shuffle(shuffled)
    recent = recent_content_ids(pair_key, game_id)
    fresh = [item for item in shuffled if content_id(prefix, item) not in recent]
    if len(fresh) < count:
        fresh = shuffled
    chosen = fresh[:count]
    remember_content(pair_key, game_id, [content_id(prefix, item) for item in chosen])
    return chosen


def build_session_content(game_id, *, seed=None, pair_key=None, size=16):
    seed = int(seed if seed is not None else new_seed())
    rng = random.Random(seed)

    if game_id == "this_or_that":
        pairs = _choose_items(THIS_OR_THAT_BANK, 10, seed, pair_key, game_id, "tot")
        return {"seed": seed, "pairs": [list(pair) for pair in pairs]}

    if game_id == "memory_match":
        pair_count = max(2, min(int(size) // 2, len(MEMORY_EMOJIS)))
        symbols = _choose_items(MEMORY_EMOJIS, pair_count, seed, pair_key, game_id, "memory")
        deck = symbols + symbols
        rng.shuffle(deck)
        return {
            "seed": seed,
            "size": pair_count * 2,
            "cards": deck,
            "labels": MEMORY_SYMBOLS,
        }

    if game_id == "team_crossword":
        puzzle = _choose_items(CROSSWORD_PACK, 1, seed, pair_key, game_id, "xword")[0]
        return {"seed": seed, "puzzle": puzzle}

    if game_id == "emoji_decoder":
        prompt = _choose_items(EMOJI_CHARADES_BANK, 1, seed, pair_key, game_id, "emoji")[0]
        return {"seed": seed, "prompt": prompt}

    if game_id == "word_duet":
        words = _choose_items(WORD_CHAIN_STARTERS, 1, seed, pair_key, game_id, "chain")
        return {"seed": seed, "starter": words[0], "target": 12}

    return {"seed": seed}

