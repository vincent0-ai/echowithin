"""Tests for Gomoku, Sudoku Together, Whack-'Em-All, and Air Hockey wiring."""
import os
from unittest.mock import MagicMock, patch

import main as m
from blueprints.game import VALID_ARCADE_CATEGORIES
from blueprints.game_registry import GAME_BY_ID, BOND_GAME_IDS
from blueprints.game_stats import GAME_LABELS

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')

PAGES = {
    'gomoku': ('/games/gomoku', 'gomoku.html', 'gomoku.js'),
    'sudoku': ('/games/sudoku', 'sudoku.html', 'sudoku.js'),
    'whack_a_mole': ('/games/whack-a-mole', 'whack_a_mole.html', 'whack_a_mole.js'),
    'air_hockey': ('/games/air-hockey', 'air_hockey.html', 'air_hockey.js'),
}


class TestNewGameRoutesAndUI:
    def test_pages_render_with_js_and_back_link(self, client):
        for _gid, (route, _tpl, js) in PAGES.items():
            res = client.get(route)
            assert res.status_code == 200, route
            html = res.get_data(as_text=True)
            assert js in html, route
            assert 'Back to Games' in html, route

    def test_online_modes_present(self, client):
        html = client.get('/games/gomoku').get_data(as_text=True)
        assert 'id="tab-solo"' in html
        assert 'id="tab-local"' in html
        assert 'id="tab-online"' in html
        assert 'id="gomoku-canvas"' in html
        html = client.get('/games/air-hockey').get_data(as_text=True)
        assert 'id="air-canvas"' in html
        html = client.get('/games/sudoku').get_data(as_text=True)
        assert 'id="sudoku-grid"' in html
        assert 'id="sudoku-pad"' in html
        html = client.get('/games/whack-a-mole').get_data(as_text=True)
        assert 'id="whack-grid"' in html

    def test_registry_entries_and_bond_eligibility(self):
        for gid in ('gomoku', 'sudoku', 'whack_a_mole', 'air_hockey'):
            assert gid in GAME_BY_ID, gid
            assert GAME_BY_ID[gid]['route'].startswith('/games/'), gid
        assert 'gomoku' in BOND_GAME_IDS
        assert 'sudoku' in BOND_GAME_IDS
        assert 'whack_a_mole' in BOND_GAME_IDS
        assert 'air_hockey' in BOND_GAME_IDS

    def test_leaderboard_categories(self):
        assert 'gomoku' in VALID_ARCADE_CATEGORIES
        assert 'win_streak' in VALID_ARCADE_CATEGORIES['gomoku']
        assert 'whack_a_mole' in VALID_ARCADE_CATEGORIES
        assert 'high_score' in VALID_ARCADE_CATEGORIES['whack_a_mole']
        assert 'sudoku' in VALID_ARCADE_CATEGORIES
        assert 'air_hockey' in VALID_ARCADE_CATEGORIES

    def test_elo_labels(self):
        assert GAME_LABELS.get('gomoku') == 'Gomoku'
        assert GAME_LABELS.get('whack_a_mole') == "Whack-'Em-All"
        assert GAME_LABELS.get('air_hockey') == 'Air Hockey'
        assert 'gomoku' in m.GAMES_WITH_MATCH_TRACKING
        assert 'whack_a_mole' in m.GAMES_WITH_MATCH_TRACKING
        assert 'air_hockey' in m.GAMES_WITH_MATCH_TRACKING


class TestNewGameSocketHandlers:
    def _handlers(self):
        return {getattr(c.args[0], '__name__', ''): c.args[0]
                for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}

    def test_handlers_registered(self):
        h = self._handlers()
        for name in ('handle_join_gomoku_room', 'handle_gomoku_move', 'handle_find_gomoku_match',
                     'handle_join_whack_room', 'handle_whack_score', 'handle_whack_finish', 'handle_find_whack_match',
                     'handle_join_sudoku_room', 'handle_sudoku_cell_update', 'handle_sudoku_cursor_move',
                     'handle_join_air_room', 'handle_air_input', 'handle_air_state', 'handle_air_score', 'handle_find_air_match'):
            assert name in h, name

    def test_gomoku_win_detection_five_in_row(self):
        n = m.GOMOKU_SIZE
        board = [-1] * (n * n)
        for c in range(5, 10):
            board[7 * n + c] = 0
        line = m.check_gomoku_win(board, 7, 7, 0)
        assert line is not None and len(line) >= 5
        board2 = [-1] * (n * n)
        for c in range(5, 9):
            board2[7 * n + c] = 1
        assert m.check_gomoku_win(board2, 7, 6, 1) is None

    def test_sudoku_fallback_board_valid(self):
        from blueprints.game import _sudoku_fallback_board
        board = _sudoku_fallback_board(seed=42)
        assert len(board['puzzle']) == 9 and len(board['solution']) == 9
        sol = board['solution']
        assert {sol[0][c] for c in range(9)} == set(range(1, 10))
        assert {sol[r][0] for r in range(9)} == set(range(1, 10))

    def test_sudoku_valid_board_guard(self):
        from blueprints.game import _sudoku_fallback_board, _sudoku_valid_board
        board = _sudoku_fallback_board(seed=3, difficulty='easy')
        assert _sudoku_valid_board(board['puzzle'], board['solution'])
        assert not _sudoku_valid_board([[1] * 9] * 9, [[1] * 9] * 9)
        bad_solution = [row[:] for row in board['solution']]
        bad_solution[0][0] = bad_solution[0][1]
        assert not _sudoku_valid_board(board['puzzle'], bad_solution)
        riddled = [row[:] for row in board['puzzle']]
        r, c = next((r, c) for r in range(9) for c in range(9) if riddled[r][c])
        riddled[r][c] = (riddled[r][c] % 9) + 1
        assert not _sudoku_valid_board(riddled, board['solution'])

    def test_sudoku_cache_rotates_and_expires(self):
        import blueprints.game as g
        saved = dict(g._SUDOKU_CACHE)
        g._SUDOKU_CACHE.clear()
        try:
            a = g._sudoku_fallback_board(seed=1, difficulty='easy')
            b = g._sudoku_fallback_board(seed=2, difficulty='easy')
            g._sudoku_store(a, 1000.0)
            g._sudoku_store(b, 1000.0)
            first = g._sudoku_take_cached('easy', 1001.0)
            second = g._sudoku_take_cached('easy', 1001.0)
            assert first['puzzle'] != second['puzzle']
            assert g._sudoku_take_cached('easy', 1001.0) is None
            g._sudoku_store(a, 1000.0)
            expired = 1000.0 + g._SUDOKU_CACHE_TTL + 1
            assert g._sudoku_take_cached('easy', expired) is None
        finally:
            g._SUDOKU_CACHE.clear()
            g._SUDOKU_CACHE.update(saved)

    def test_sudoku_difficulty_normalization(self):
        from blueprints.game import _sudoku_norm_difficulty
        assert _sudoku_norm_difficulty('Expert') == 'hard'
        assert _sudoku_norm_difficulty('Beginner') == 'easy'
        assert _sudoku_norm_difficulty('weird') == 'medium'
        assert _sudoku_norm_difficulty(None) == 'medium'

    def test_sudoku_api_serves_cached_board_uncached(self, client):
        import time
        import blueprints.game as g
        saved = dict(g._SUDOKU_CACHE)
        g._SUDOKU_CACHE.clear()
        board = g._sudoku_fallback_board(seed=5, difficulty='easy')
        g._sudoku_store(board, time.time())
        try:
            res = client.get('/api/games/sudoku/new?difficulty=easy')
            data = res.get_json()
            assert res.status_code == 200
            assert data['success'] is True and data['source'] == 'cache'
            assert data['difficulty'] == 'easy'
            assert res.headers.get('Cache-Control') == 'no-store'
        finally:
            g._SUDOKU_CACHE.clear()
            g._SUDOKU_CACHE.update(saved)

    def test_sudoku_cursor_move_relayed_without_echo(self):
        """Partner taps relay to the room (not back to sender) with cell coords."""
        h = self._handlers()['handle_sudoku_cursor_move']
        req = MagicMock()
        req.sid = 'sid_a'
        guest = MagicMock()
        guest.is_authenticated = False
        m.active_sudoku_rooms['r1'] = {'host_sid': 'sid_a', 'guest_sid': None}
        try:
            with patch.object(m, 'request', req), \
                    patch.object(m, 'current_user', guest), \
                    patch.object(m, 'emit') as mock_emit:
                h({'room_id': 'r1', 'r': 8, 'c': 0})
        finally:
            m.active_sudoku_rooms.pop('r1', None)
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'sudoku_cursor_move'
        assert args[1] == {'r': 8, 'c': 0}
        assert kwargs.get('include_self') is False
        assert kwargs.get('room') == 'r1'


def _authed(uid='u-host', name='Host'):
    stub = MagicMock()
    stub.is_authenticated = True
    stub.id = uid
    stub.username = name
    return stub


def _guest():
    stub = MagicMock()
    stub.is_authenticated = False
    return stub


def _call_join(handler_name, room_id, sid, user):
    handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}
    req = MagicMock()
    req.sid = sid
    data = {'room_id': room_id, 'room': room_id}
    with patch.object(m, 'request', req), \
            patch.object(m, 'current_user', user), \
            patch.object(m, 'emit') as mock_emit, \
            patch.object(m, 'join_room'):
        handlers[handler_name](data)
    return mock_emit


# handler -> (room dict on main, joined event name)
ROOM_JOIN_CASES = {
    'handle_join_gomoku_room': ('active_gomoku_rooms', 'gomoku_room_joined'),
    'handle_join_whack_room': ('active_whack_rooms', 'whack_room_joined'),
    'handle_join_sudoku_room': ('active_sudoku_rooms', 'sudoku_room_joined'),
    'handle_join_air_room': ('active_air_rooms', 'air_room_joined'),
    'handle_join_ttt_room': ('active_ttt_rooms', 'ttt_room_joined'),
    'handle_join_c4_room': ('active_c4_rooms', 'c4_room_joined'),
    'handle_join_dnb_room': ('active_dnb_rooms', 'dnb_room_joined'),
    'handle_join_pong_room': ('active_pong_rooms', 'pong_room_joined'),
    'handle_join_slime_room': ('active_slime_rooms', 'slime_room_joined'),
    'handle_join_duet_room': ('active_duet_rooms', 'duet_room_joined'),
    'handle_join_crossword_room': ('active_crossword_rooms', 'crossword_room_joined'),
    'handle_memory_join_room': ('active_memory_rooms', 'memory_room_joined'),
    'handle_tot_join_room': ('active_tot_rooms', 'tot_room_joined'),
    'handle_emoji_join_room': ('active_emoji_rooms', 'emoji_room_joined'),
    'handle_chain_join_room': ('active_chain_rooms', 'chain_room_joined'),
}


class TestDuelRoomCreationGate:
    def test_guest_cannot_open_rooms_but_can_join(self):
        for handler_name, (dict_name, joined_event) in ROOM_JOIN_CASES.items():
            rooms = getattr(m, dict_name)
            room_id = 'gate_%s' % handler_name
            rooms.pop(room_id, None)

            # Guest creation attempt opens nothing and emits no join.
            guest_emit = _call_join(handler_name, room_id, 'sid_guest', _guest())
            assert room_id not in rooms, handler_name
            assert not any(c[0][0] == joined_event for c in guest_emit.call_args_list), handler_name

            # Member opens the room fine.
            _call_join(handler_name, room_id, 'sid_host', _authed())
            assert room_id in rooms, handler_name

            # Guest joins the existing room fine.
            join_emit = _call_join(handler_name, room_id, 'sid_guest2', _guest())
            assert any(c[0][0] == joined_event for c in join_emit.call_args_list), handler_name

            rooms.pop(room_id, None)

    def test_sudoku_join_stores_bond_id_for_challenge_reuse(self):
        """Bond challenges land both partners in one room: bond_id must stick."""
        from blueprints.bonds import _find_open_bond_room
        import datetime
        handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                    for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}
        room_id = 'bond_sudo_reuse'
        m.active_sudoku_rooms.pop(room_id, None)
        req = MagicMock()
        req.sid = 'sid_challenger'
        data = {'room_id': room_id, 'room': room_id, 'bond_id': 'bond_1'}
        with patch.object(m, 'request', req), \
                patch.object(m, 'current_user', _authed('u1', 'A')), \
                patch.object(m, 'emit'), \
                patch.object(m, 'join_room'):
            handlers['handle_join_sudoku_room'](data)
        assert m.active_sudoku_rooms[room_id].get('bond_id') == 'bond_1'
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        found, waiter_is_partner = _find_open_bond_room(m, 'sudoku', 'bond_1', 'u2', 'u1', now_utc)
        assert found == room_id
        assert waiter_is_partner is True
        m.active_sudoku_rooms.pop(room_id, None)
