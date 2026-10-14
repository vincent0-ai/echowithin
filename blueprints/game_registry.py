"""Shared registry for EchoWithin games.

Keep this file free of secrets and environment-specific values. It is imported
by both the Games page and Bond Challenge so those surfaces cannot drift.
"""

from copy import deepcopy


GAMES = [
    {
        "id": "trivia",
        "name": "Trivia Challenge",
        "type": "party",
        "players": "2-30",
        "description": "Host a live question room with timed answers and podium results.",
        "icon": "fa-solid fa-bolt",
        "category": "party",
        "route": "/games/create?type=trivia",
        "bond_route": "/games/create?type=trivia",
    },
    {
        "id": "poll",
        "name": "Interactive Polls",
        "type": "party",
        "players": "2-30",
        "description": "Create a quick live vote and compare responses together.",
        "icon": "fa-solid fa-chart-simple",
        "category": "party",
        "route": "/games/create?type=poll",
        "bond_route": "/games/create?type=poll",
    },
    {
        "id": "wyr",
        "name": "Would You Rather",
        "type": "party",
        "players": "2-30",
        "description": "Debate a two-choice dilemma and see how the room splits.",
        "icon": "fa-solid fa-code-compare",
        "category": "party",
        "route": "/games/create?type=wyr",
        "bond_route": "/games/create?type=wyr",
    },
    {
        "id": "ttal",
        "name": "Two Truths & a Lie",
        "type": "party",
        "players": "2-30",
        "description": "Submit three statements and guess which one is the lie.",
        "icon": "fa-solid fa-user-secret",
        "category": "party",
        "route": "/games/create?type=ttal",
        "bond_route": "/games/create?type=ttal",
    },
    {
        "id": "story",
        "name": "Story Chain",
        "type": "party",
        "players": "2-30",
        "description": "Take turns writing one sentence at a time.",
        "icon": "fa-solid fa-feather-pointed",
        "category": "party",
        "route": "/games/create?type=story",
        "bond_route": "/games/create?type=story",
    },
    {
        "id": "caption",
        "name": "Caption This",
        "type": "party",
        "players": "2-30",
        "description": "Write captions for a prompt and vote for the funniest one.",
        "icon": "fa-solid fa-comment-dots",
        "category": "party",
        "route": "/games/create?type=caption",
        "bond_route": "/games/create?type=caption",
    },
    {
        "id": "this_or_that",
        "name": "This or That",
        "type": "co-op",
        "players": "1-2",
        "description": "Pick between pairs and discover how often you match.",
        "icon": "fa-solid fa-arrows-left-right",
        "category": "coop",
        "route": "/games/this-or-that",
        "bond_route": "/games/this-or-that",
    },
    {
        "id": "emoji_decoder",
        "name": "Emoji Decoder",
        "type": "co-op",
        "players": "1-2",
        "description": "Give emoji clues while your partner guesses the phrase.",
        "icon": "fa-solid fa-icons",
        "category": "coop",
        "route": "/games/emoji-decoder",
        "bond_route": "/games/emoji-decoder",
    },
    {
        "id": "team_crossword",
        "name": "Team Crossword",
        "type": "co-op",
        "players": "1-2",
        "description": "Solve a mini crossword together with live synced letters.",
        "icon": "fa-solid fa-table-cells",
        "category": "coop",
        "route": "/games/team-crossword",
        "bond_route": "/games/team-crossword",
    },
    {
        "id": "memory_match",
        "name": "Memory Match",
        "type": "versus",
        "players": "1-2",
        "description": "Flip cards, find matching pairs, and keep the turn on a match.",
        "icon": "fa-solid fa-layer-group",
        "category": "coop",
        "route": "/games/memory-match",
        "bond_route": "/games/memory-match",
    },
    {
        "id": "word_duet",
        "name": "Word Bond: Duet",
        "type": "co-op",
        "players": "1-2",
        "description": "Now a clearer Word Chain: take turns adding related words without repeats.",
        "icon": "fa-solid fa-link",
        "category": "coop",
        "route": "/games/word-duet",
        "bond_route": "/games/word-duet",
    },
    {
        "id": "floppy_bird",
        "name": "Floppy Bird: Super Powers",
        "type": "solo",
        "players": "1",
        "description": "Dodge obstacles, collect powers, and chase a high score.",
        "icon": "fa-solid fa-dove",
        "category": "arcade",
        "route": "/games/floppy-bird",
        "bond_route": "/games/floppy-bird",
    },
    {
        "id": "snake",
        "name": "Snake Classic",
        "type": "solo",
        "players": "1",
        "description": "A fast classic score chase with simple controls.",
        "icon": "fa-solid fa-route",
        "category": "arcade",
        "route": "/games/snake",
        "bond_route": "/games/snake",
    },
    {
        "id": "tic_tac_toe",
        "name": "Tic-Tac-Toe",
        "type": "versus",
        "players": "2",
        "description": "Classic three-in-a-row with live turns.",
        "icon": "fa-solid fa-xmark",
        "category": "arcade",
        "route": "/games/tic-tac-toe",
        "bond_route": "/games/tic-tac-toe",
    },
    {
        "id": "connect_four",
        "name": "Connect Four",
        "type": "versus",
        "players": "2",
        "description": "Drop tokens and connect four before your partner does.",
        "icon": "fa-solid fa-circle-dot",
        "category": "arcade",
        "route": "/games/connect-four",
        "bond_route": "/games/connect-four",
    },
    {
        "id": "dots_and_boxes",
        "name": "Dots and Boxes",
        "type": "versus",
        "players": "2",
        "description": "Draw lines, complete boxes, and control the board.",
        "icon": "fa-solid fa-border-all",
        "category": "arcade",
        "route": "/games/dots-and-boxes",
        "bond_route": "/games/dots-and-boxes",
    },
    {
        "id": "ping_pong",
        "name": "Ping Pong",
        "type": "versus",
        "players": "2",
        "description": "Fast paddle rallies with live 1v1 sync.",
        "icon": "fa-solid fa-table-tennis-paddle-ball",
        "category": "arcade",
        "route": "/games/ping-pong",
        "bond_route": "/games/ping-pong",
    },
    {
        "id": "slime_volleyball",
        "name": "Slime Volleyball",
        "type": "versus",
        "players": "2",
        "description": "Bounce, jump, and spike in a playful live duel.",
        "icon": "fa-solid fa-volleyball",
        "category": "arcade",
        "route": "/games/slime-volleyball",
        "bond_route": "/games/slime-volleyball",
    },
]


GAME_BY_ID = {game["id"]: game for game in GAMES}
BOND_GAME_LABELS = {game["id"]: game["name"] for game in GAMES}


def all_games():
    return deepcopy(GAMES)


def get_game(game_id):
    game = GAME_BY_ID.get(game_id)
    return deepcopy(game) if game else None


def game_label(game_id):
    return BOND_GAME_LABELS.get(game_id, game_id)


def game_route(game_id, *, for_bond=False):
    game = GAME_BY_ID.get(game_id)
    if not game:
        return "/games"
    key = "bond_route" if for_bond else "route"
    return game.get(key) or game.get("route") or "/games"
