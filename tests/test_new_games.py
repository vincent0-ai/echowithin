"""Tests for Gomoku, Sudoku Together, Whack-'Em-All, and Air Hockey wiring."""
import os

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
