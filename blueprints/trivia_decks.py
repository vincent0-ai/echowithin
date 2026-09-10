import html
import json
import random
import urllib.request

TRIVIA_CATEGORIES = [
    {"id": "any", "name": "Mixed / Any Category"},
    {"id": "9", "name": "General Knowledge"},
    {"id": "17", "name": "Science & Nature"},
    {"id": "18", "name": "Computers & Tech"},
    {"id": "23", "name": "World History"},
    {"id": "22", "name": "Geography & Travel"},
    {"id": "11", "name": "Film & Cinema"},
    {"id": "12", "name": "Music"},
    {"id": "15", "name": "Video Games & Pop Culture"},
]

CURATED_TRIVIA_PACKS = [
    # General Knowledge
    {
        "label": "What is the largest ocean on Earth?",
        "options": ["Pacific Ocean", "Atlantic Ocean", "Indian Ocean", "Arctic Ocean"],
        "correct_option": "Pacific Ocean",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "Who wrote the play 'Romeo and Juliet'?",
        "options": ["William Shakespeare", "Christopher Marlowe", "Jane Austen", "Charles Dickens"],
        "correct_option": "William Shakespeare",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "How many bones are in the adult human body?",
        "options": ["206", "198", "214", "250"],
        "correct_option": "206",
        "category": "General Knowledge",
        "difficulty": "medium"
    },
    {
        "label": "Which country gifted the Statue of Liberty to the United States?",
        "options": ["France", "United Kingdom", "Spain", "Germany"],
        "correct_option": "France",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "What is the primary currency of Japan?",
        "options": ["Yen", "Won", "Yuan", "Ringgit"],
        "correct_option": "Yen",
        "category": "General Knowledge",
        "difficulty": "easy"
    },

    # General Knowledge
    {
        "label": "Which planet in our solar system is known as the Red Planet?",
        "options": ["Mars", "Venus", "Jupiter", "Saturn"],
        "correct_option": "Mars",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "What is the capital city of Australia?",
        "options": ["Canberra", "Sydney", "Melbourne", "Brisbane"],
        "correct_option": "Canberra",
        "category": "General Knowledge",
        "difficulty": "medium"
    },
    {
        "label": "What is the hardest natural substance known on Earth?",
        "options": ["Diamond", "Graphene", "Titanium", "Corundum"],
        "correct_option": "Diamond",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "Which artist painted the Mona Lisa?",
        "options": ["Leonardo da Vinci", "Pablo Picasso", "Vincent van Gogh", "Michelangelo"],
        "correct_option": "Leonardo da Vinci",
        "category": "General Knowledge",
        "difficulty": "easy"
    },
    {
        "label": "How many time zones are there in Russia?",
        "options": ["11", "9", "7", "13"],
        "correct_option": "11",
        "category": "General Knowledge",
        "difficulty": "hard"
    },
    {
        "label": "What is the rarest blood type in the world?",
        "options": ["AB-Negative", "O-Positive", "B-Negative", "A-Negative"],
        "correct_option": "AB-Negative",
        "category": "General Knowledge",
        "difficulty": "medium"
    },
    # Science & Nature
    {
        "label": "What is the chemical symbol for gold?",
        "options": ["Au", "Ag", "Fe", "Gd"],
        "correct_option": "Au",
        "category": "Science & Nature",
        "difficulty": "easy"
    },
    {
        "label": "What organelle is considered the powerhouse of the cell?",
        "options": ["Mitochondria", "Nucleus", "Ribosome", "Endoplasmic Reticulum"],
        "correct_option": "Mitochondria",
        "category": "Science & Nature",
        "difficulty": "easy"
    },
    {
        "label": "What is the speed of light in a vacuum (approx)?",
        "options": ["300,000 km/s", "150,000 km/s", "1,000,000 km/s", "30,000 km/s"],
        "correct_option": "300,000 km/s",
        "category": "Science & Nature",
        "difficulty": "medium"
    },
    {
        "label": "Which gas makes up approximately 78% of Earth's atmosphere?",
        "options": ["Nitrogen", "Oxygen", "Carbon Dioxide", "Argon"],
        "correct_option": "Nitrogen",
        "category": "Science & Nature",
        "difficulty": "medium"
    },
    {
        "label": "What is the only mammal capable of true flight?",
        "options": ["Bat", "Flying Squirrel", "Sugar Glider", "Colugo"],
        "correct_option": "Bat",
        "category": "Science & Nature",
        "difficulty": "easy"
    },
    {
        "label": "What is the largest living species of reptile?",
        "options": ["Saltwater Crocodile", "Komodo Dragon", "Leatherback Sea Turtle", "Green Anaconda"],
        "correct_option": "Saltwater Crocodile",
        "category": "Science & Nature",
        "difficulty": "medium"
    },
    # Computers & Tech
    {
        "label": "In computer science, what does 'HTTP' stand for?",
        "options": ["HyperText Transfer Protocol", "High Threat Terminal Protocol", "Hyper Transfer Terminal Page", "HyperText Transit Path"],
        "correct_option": "HyperText Transfer Protocol",
        "category": "Computers & Tech",
        "difficulty": "easy"
    },
    {
        "label": "Who is credited with inventing the World Wide Web in 1989?",
        "options": ["Tim Berners-Lee", "Alan Turing", "Vint Cerf", "Linus Torvalds"],
        "correct_option": "Tim Berners-Lee",
        "category": "Computers & Tech",
        "difficulty": "medium"
    },
    {
        "label": "What does CPU stand for in computer hardware?",
        "options": ["Central Processing Unit", "Core Power Utility", "Computer Program Unit", "Central Program User"],
        "correct_option": "Central Processing Unit",
        "category": "Computers & Tech",
        "difficulty": "easy"
    },
    {
        "label": "Which programming language was created by Guido van Rossum?",
        "options": ["Python", "Ruby", "Rust", "Go"],
        "correct_option": "Python",
        "category": "Computers & Tech",
        "difficulty": "easy"
    },
    {
        "label": "What year was the first iPhone released to the public?",
        "options": ["2007", "2005", "2008", "2010"],
        "correct_option": "2007",
        "category": "Computers & Tech",
        "difficulty": "easy"
    },
    {
        "label": "What is the name of the protocol used for real-time bi-directional web communication?",
        "options": ["WebSocket", "FTP", "SNMP", "Telnet"],
        "correct_option": "WebSocket",
        "category": "Computers & Tech",
        "difficulty": "medium"
    },
    # World History
    {
        "label": "In which year did the Apollo 11 mission land humans on the Moon?",
        "options": ["1969", "1965", "1972", "1968"],
        "correct_option": "1969",
        "category": "World History",
        "difficulty": "easy"
    },
    {
        "label": "Who was the first Emperor of a unified China?",
        "options": ["Qin Shi Huang", "Sun Tzu", "Kublai Khan", "Han Wudi"],
        "correct_option": "Qin Shi Huang",
        "category": "World History",
        "difficulty": "medium"
    },
    {
        "label": "The ancient city of Rome was founded on the banks of which river?",
        "options": ["Tiber", "Danube", "Po", "Rhine"],
        "correct_option": "Tiber",
        "category": "World History",
        "difficulty": "medium"
    },
    {
        "label": "Which treaty ended World War I in 1919?",
        "options": ["Treaty of Versailles", "Treaty of Paris", "Treaty of Ghent", "Treaty of Utrecht"],
        "correct_option": "Treaty of Versailles",
        "category": "World History",
        "difficulty": "medium"
    },
    # Geography & Travel
    {
        "label": "Which is the longest river in the world by most geographical surveys?",
        "options": ["Nile", "Amazon", "Yangtze", "Mississippi"],
        "correct_option": "Nile",
        "category": "Geography & Travel",
        "difficulty": "easy"
    },
    {
        "label": "Which country has the greatest number of natural lakes?",
        "options": ["Canada", "Russia", "United States", "Sweden"],
        "correct_option": "Canada",
        "category": "Geography & Travel",
        "difficulty": "medium"
    },
    {
        "label": "What is the highest mountain peak in Africa?",
        "options": ["Mount Kilimanjaro", "Mount Kenya", "Mount Stanley", "Ras Dashen"],
        "correct_option": "Mount Kilimanjaro",
        "category": "Geography & Travel",
        "difficulty": "easy"
    },
    {
        "label": "What is the smallest independent state/country in the world by area?",
        "options": ["Vatican City", "Monaco", "Nauru", "San Marino"],
        "correct_option": "Vatican City",
        "category": "Geography & Travel",
        "difficulty": "easy"
    },
    # Film & Cinema
    {
        "label": "Which film won the first Academy Award for Best Animated Feature in 2001?",
        "options": ["Shrek", "Monsters, Inc.", "Toy Story", "Jimmy Neutron"],
        "correct_option": "Shrek",
        "category": "Film & Cinema",
        "difficulty": "medium"
    },
    {
        "label": "Who directed the 2010 mind-bending science fiction film 'Inception'?",
        "options": ["Christopher Nolan", "Denis Villeneuve", "Steven Spielberg", "James Cameron"],
        "correct_option": "Christopher Nolan",
        "category": "Film & Cinema",
        "difficulty": "easy"
    },
    {
        "label": "What color pill does Neo choose to take in 'The Matrix' (1999)?",
        "options": ["Red", "Blue", "Green", "Yellow"],
        "correct_option": "Red",
        "category": "Film & Cinema",
        "difficulty": "easy"
    },
    # Music
    {
        "label": "How many keys are on a standard acoustic piano?",
        "options": ["88", "76", "92", "84"],
        "correct_option": "88",
        "category": "Music",
        "difficulty": "easy"
    },
    {
        "label": "Which legendary band was known as the 'Fab Four'?",
        "options": ["The Beatles", "The Rolling Stones", "The Who", "Led Zeppelin"],
        "correct_option": "The Beatles",
        "category": "Music",
        "difficulty": "easy"
    },
    {
        "label": "What musical interval is known as the 'Devil's Interval'?",
        "options": ["Tritone", "Major Seventh", "Minor Second", "Perfect Fifth"],
        "correct_option": "Tritone",
        "category": "Music",
        "difficulty": "hard"
    },
    # Video Games & Pop Culture
    {
        "label": "What is the best-selling video game of all time with over 300 million copies sold?",
        "options": ["Minecraft", "Tetris", "Grand Theft Auto V", "Wii Sports"],
        "correct_option": "Minecraft",
        "category": "Video Games & Pop Culture",
        "difficulty": "easy"
    },
    {
        "label": "In 'The Legend of Zelda', who is the legendary green-clad hero player character?",
        "options": ["Link", "Zelda", "Ganon", "Navi"],
        "correct_option": "Link",
        "category": "Video Games & Pop Culture",
        "difficulty": "easy"
    },
    {
        "label": "Which Pokémon is known by National Pokédex number #025?",
        "options": ["Pikachu", "Charizard", "Bulbasaur", "Eevee"],
        "correct_option": "Pikachu",
        "category": "Video Games & Pop Culture",
        "difficulty": "easy"
    },
]

CATEGORY_NAME_MAP = {
    "9": "General Knowledge",
    "17": "Science & Nature",
    "18": "Computers & Tech",
    "23": "World History",
    "22": "Geography & Travel",
    "11": "Film & Cinema",
    "12": "Music",
    "15": "Video Games & Pop Culture"
}


def get_curated_trivia_questions(amount=10, category=None, difficulty=None):
    """Filter curated questions by category/difficulty with fallback to full pool."""
    pool = list(CURATED_TRIVIA_PACKS)
    if category and category != 'any':
        cat_name = CATEGORY_NAME_MAP.get(str(category), category)
        filtered = [q for q in pool if q.get('category', '').lower() == cat_name.lower()]
        if filtered:
            pool = filtered
    if difficulty and difficulty in ('easy', 'medium', 'hard'):
        diff_filtered = [q for q in pool if q.get('difficulty') == difficulty]
        if diff_filtered:
            pool = diff_filtered

    random.shuffle(pool)
    selected = pool[:amount]
    # Format and shuffle options
    formatted = []
    for q in selected:
        opts = list(q['options'])
        random.shuffle(opts)
        formatted.append({
            'label': q['label'][:200],
            'options': [o[:100] for o in opts[:4]],
            'correct_option': q['correct_option'][:100]
        })
    return formatted


def fetch_community_trivia(amount=10, category=None, difficulty=None):
    """Fetch trivia questions from Open Trivia Database with automatic HTML unescaping,

    choice shuffling, and instant fallback to curated trivia packs.
    """
    amount = max(2, min(20, int(amount or 10)))

    url = f"https://opentdb.com/api.php?amount={amount}&type=multiple"
    if category and category != 'any' and str(category).isdigit():
        url += f"&category={category}"
    if difficulty and difficulty in ('easy', 'medium', 'hard'):
        url += f"&difficulty={difficulty}"

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'EchoWithin-Trivia/1.0 (Mozilla/5.0 Compatible)'}
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('response_code') == 0 and data.get('results'):
                questions = []
                for item in data['results']:
                    lbl = html.unescape(item.get('question', '')).strip()
                    correct = html.unescape(item.get('correct_answer', '')).strip()
                    incorrect = [html.unescape(a).strip() for a in item.get('incorrect_answers', [])]
                    all_opts = [correct] + incorrect
                    random.shuffle(all_opts)
                    questions.append({
                        'label': lbl[:200],
                        'options': [opt[:100] for opt in all_opts[:4]],
                        'correct_option': correct[:100]
                    })
                if questions and len(questions) >= 2:
                    return questions
    except Exception:
        pass

    # Fallback to rich curated packs
    return get_curated_trivia_questions(amount=amount, category=category, difficulty=difficulty)
