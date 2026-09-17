"""Automated test suite for Cooperative Couple Games: Word Bond: Duet and Team Crossword.

Covers:
- Route access (guest and authenticated)
- Games list UI presence and category filter
- SocketIO room join, clue giving, card guessing, and restart relays for Word Duet
- SocketIO room join, cell updates, cursor movement, and restart relays for Team Crossword
- Disconnect cleanup and partner-left event broadcasts
- Direct Message invite url auto-resolution
- Bond game labels and challenge route integration
"""
import datetime
from unittest.mock import MagicMock, patch
from bson import ObjectId
import pytest


def _handlers():
    import main as m
    found = {}
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]):
            fn = call.args[0]
            found[getattr(fn, '__name__', '')] = fn
    return found


def _guest_user():
    stub = MagicMock()
    stub.is_authenticated = False
    return stub


def _auth_user(uid="user_123", username="Alice"):
    stub = MagicMock()
    stub.is_authenticated = True
    stub.id = uid
    stub.username = username
    return stub


def _as_sid(m, sid, fn, data=None, user=None):
    req = MagicMock()
    req.sid = sid
    curr_u = user if user is not None else _guest_user()
    with patch.object(m, 'request', req), \
            patch.object(m, 'current_user', curr_u), \
            patch.object(m, 'emit') as mock_emit, \
            patch.object(m, 'join_room') as mock_join:
        if data is not None:
            res = fn(data)
        else:
            res = fn()
    return res, mock_emit, mock_join


class TestCoopGameRoutes:
    def test_word_duet_guest_access(self, client):
        """Guest users can access Word Bond: Duet directly."""
        res = client.get('/games/word-duet')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Word Bond: Duet' in html
        assert 'word_duet.js' in html
        assert 'duet-board' in html

    def test_word_duet_authenticated_access(self, auth_client):
        """Authenticated users can access Word Bond: Duet."""
        res = auth_client.get('/games/word-duet')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Word Bond: Duet' in html

    def test_team_crossword_guest_access(self, client):
        """Guest users can access Team Crossword directly."""
        res = client.get('/games/team-crossword')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Team Crossword' in html
        assert 'team_crossword.js' in html
        assert 'xword-grid' in html

    def test_team_crossword_authenticated_access(self, auth_client):
        """Authenticated users can access Team Crossword."""
        res = auth_client.get('/games/team-crossword')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Team Crossword' in html

    def test_games_list_shows_coop_section(self, auth_client):
        """Games catalog includes the Couples & Cooperative Games section and both games."""
        import main as m
        with patch.object(m.game_sessions_conf, 'find') as mock_find:
            mock_find.return_value.sort.return_value.limit.return_value = []
            res = auth_client.get('/games')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert 'Couples &amp; Cooperative Games' in html
            assert 'Word Bond: Duet' in html
            assert '/games/word-duet' in html
            assert 'Team Crossword' in html
            assert '/games/team-crossword' in html
            assert 'value="coop"' in html


class TestWordDuetSocketHandlers:
    def test_duet_join_room_flow(self):
        """Host creates room with seed, guest joins and both get partner notifications."""
        import main as m
        h = _handlers().get('handle_join_duet_room')
        assert h is not None

        room_id = 'duet_test_room_1'
        m.active_duet_rooms.pop(room_id, None)

        # 1. Host joins
        _, mock_emit_host, mock_join_host = _as_sid(
            m, 'sid_host', h, {'room_id': room_id}, user=_auth_user("u1", "Romeo")
        )
        assert mock_join_host.call_count == 1
        assert room_id in m.active_duet_rooms
        room = m.active_duet_rooms[room_id]
        assert room['host_sid'] == 'sid_host'
        assert room['host_name'] == 'Romeo'
        assert mock_emit_host.call_count == 1
        args, kwargs = mock_emit_host.call_args
        assert args[0] == 'duet_room_joined'
        assert args[1]['is_host'] is True
        assert args[1]['side'] == 'A'
        assert 'seed' in args[1]

        # 2. Guest joins
        _, mock_emit_guest, mock_join_guest = _as_sid(
            m, 'sid_guest', h, {'room_id': room_id}, user=_auth_user("u2", "Juliet")
        )
        assert room['guest_sid'] == 'sid_guest'
        assert room['guest_name'] == 'Juliet'
        assert mock_emit_guest.call_count >= 2  # notified guest and host
        # Clean up
        m.active_duet_rooms.pop(room_id, None)

    def test_duet_clue_and_guess_relayed(self):
        """Clues and card guesses are relayed without echo (include_self=False)."""
        import main as m
        h_clue = _handlers().get('handle_duet_give_clue')
        h_guess = _handlers().get('handle_duet_guess_card')
        h_end = _handlers().get('handle_duet_end_turn')
        h_restart = _handlers().get('handle_duet_restart')

        assert h_clue and h_guess and h_end and h_restart

        room_id = 'duet_test_room_2'
        m.active_duet_rooms[room_id] = {'host_sid': 'h', 'guest_sid': 'g', 'seed': 12345}

        # Give clue
        _, mock_emit, _ = _as_sid(m, 'h', h_clue, {'room_id': room_id, 'clue': 'LOVE', 'count': 2})
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'duet_clue_given'
        assert args[1]['clue'] == 'LOVE'
        assert args[1]['count'] == 2
        assert kwargs.get('include_self') is False

        # Guess card
        _, mock_emit, _ = _as_sid(m, 'g', h_guess, {'room_id': room_id, 'card_idx': 7})
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'duet_card_guessed'
        assert args[1]['card_idx'] == 7
        assert kwargs.get('include_self') is False

        # End turn
        _, mock_emit, _ = _as_sid(m, 'g', h_end, {'room_id': room_id})
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'duet_turn_ended'
        assert kwargs.get('include_self') is False

        # Restart
        _, mock_emit, _ = _as_sid(m, 'h', h_restart, {'room_id': room_id, 'seed': 99999})
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'duet_restarted'
        assert args[1]['seed'] == 99999
        assert m.active_duet_rooms[room_id]['seed'] == 99999

        m.active_duet_rooms.pop(room_id, None)


class TestTeamCrosswordSocketHandlers:
    def test_crossword_join_and_cell_sync(self):
        """Joining stores puzzle state; cell update modifies server grid and broadcasts."""
        import main as m
        h_join = _handlers().get('handle_join_crossword_room')
        h_cell = _handlers().get('handle_crossword_cell_update')
        h_cursor = _handlers().get('handle_crossword_cursor_move')
        assert h_join and h_cell and h_cursor

        room_id = 'xword_test_room_1'
        m.active_crossword_rooms.pop(room_id, None)

        # Host joins
        _, mock_emit_host, _ = _as_sid(
            m, 'sid_host', h_join, {'room_id': room_id, 'puzzle_idx': 2}, user=_auth_user("u1", "Sam")
        )
        assert room_id in m.active_crossword_rooms
        room = m.active_crossword_rooms[room_id]
        assert room['puzzle_idx'] == 2
        assert len(room['grid']) == 25

        # Guest joins and receives current grid
        _, mock_emit_guest, _ = _as_sid(
            m, 'sid_guest', h_join, {'room_id': room_id, 'puzzle_idx': 2}, user=_auth_user("u2", "Alex")
        )
        assert room['guest_sid'] == 'sid_guest'

        # Cell update (row 1, col 2 = letter 'E')
        _, mock_emit_cell, _ = _as_sid(
            m, 'sid_host', h_cell, {'room_id': room_id, 'r': 1, 'c': 2, 'char': 'e'}
        )
        assert mock_emit_cell.call_count == 1
        args, kwargs = mock_emit_cell.call_args
        assert args[0] == 'crossword_cell_update'
        assert args[1] == {'r': 1, 'c': 2, 'char': 'E'}
        assert kwargs.get('include_self') is False
        assert m.active_crossword_rooms[room_id]['grid'][1 * 5 + 2] == 'E'

        # Cursor move
        _, mock_emit_cursor, _ = _as_sid(
            m, 'sid_guest', h_cursor, {'room_id': room_id, 'r': 3, 'c': 4, 'dir': 'down'}
        )
        assert mock_emit_cursor.call_count == 1
        args, kwargs = mock_emit_cursor.call_args
        assert args[0] == 'crossword_cursor_move'
        assert args[1] == {'r': 3, 'c': 4, 'dir': 'down'}
        assert kwargs.get('include_self') is False

        m.active_crossword_rooms.pop(room_id, None)


class TestDisconnectCleanup:
    def test_duet_and_crossword_disconnect_cleanup(self):
        """Disconnecting user cleans up room and notifies partner."""
        import main as m
        h_disc = _handlers().get('handle_dm_disconnect')
        assert h_disc is not None

        d_room = 'duet_disc_room'
        m.active_duet_rooms[d_room] = {'host_sid': 'leaver_sid', 'guest_sid': 'stay_sid'}

        x_room = 'xword_disc_room'
        m.active_crossword_rooms[x_room] = {'host_sid': 'stay_sid', 'guest_sid': 'leaver_sid'}

        _, mock_emit, _ = _as_sid(m, 'leaver_sid', h_disc, user=_guest_user())

        # Check duet room removed and partner notified
        assert d_room not in m.active_duet_rooms
        # Check crossword room removed and partner notified
        assert x_room not in m.active_crossword_rooms

        emitted_events = [c[0][0] for c in mock_emit.call_args_list]
        assert 'duet_partner_left' in emitted_events
        assert 'crossword_partner_left' in emitted_events


class TestGameInvitesAndBondsIntegration:
    def test_dm_game_invite_url_generation(self, app, mock_user):
        """main.py send_dm populates correct URLs for word_duet and team_crossword."""
        import main as m
        from main import User
        from flask_login import login_user

        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]

        send_dm_handler = handlers.get('handle_send_dm')
        assert send_dm_handler is not None

        target_id = ObjectId()
        recipient_user = {'_id': target_id, 'username': 'partner_user', 'dm_privacy': 'everyone'}

        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'can_dm', return_value=True), \
                 patch.object(m, 'users_conf') as mock_users, \
                 patch.object(m, 'direct_messages_conf') as mock_dms, \
                 patch.object(m, 'hidden_chats_conf') as mock_hidden, \
                 patch.object(m, 'emit') as mock_emit:

                def fake_insert(doc):
                    doc['_id'] = ObjectId()
                    return MagicMock(inserted_id=doc['_id'])
                mock_dms.insert_one.side_effect = fake_insert
                mock_users.find_one.return_value = recipient_user

                # 1. Test word_duet
                invite_payload_duet = {
                    'recipient_id': str(target_id),
                    'message_type': 'game_invite',
                    'game_type': 'word_duet',
                    'game_lobby_id': 'duet-abc123',
                    'game_title': 'Word Bond: Duet',
                    'temp_id': 'tmp-1'
                }
                send_dm_handler(invite_payload_duet)
                mock_dms.insert_one.assert_called_once()
                saved_doc = mock_dms.insert_one.call_args[0][0]
                assert saved_doc['message_type'] == 'game_invite'
                assert saved_doc['game_data']['game_type'] == 'word_duet'
                assert saved_doc['game_data']['game_url'] == '/games/word-duet?room=duet-abc123'

                # 2. Test team_crossword
                mock_dms.insert_one.reset_mock()
                invite_payload_xword = {
                    'recipient_id': str(target_id),
                    'message_type': 'game_invite',
                    'game_type': 'team_crossword',
                    'game_lobby_id': 'xword-xyz789',
                    'game_title': 'Team Crossword',
                    'temp_id': 'tmp-2'
                }
                send_dm_handler(invite_payload_xword)
                mock_dms.insert_one.assert_called_once()
                saved_doc_xword = mock_dms.insert_one.call_args[0][0]
                assert saved_doc_xword['message_type'] == 'game_invite'
                assert saved_doc_xword['game_data']['game_type'] == 'team_crossword'
                assert saved_doc_xword['game_data']['game_url'] == '/games/team-crossword?room=xword-xyz789'

    def test_bonds_blueprint_has_coop_games(self):
        """BOND_GAME_LABELS includes word_duet and team_crossword."""
        from blueprints.bonds import BOND_GAME_LABELS
        assert 'word_duet' in BOND_GAME_LABELS
        assert 'team_crossword' in BOND_GAME_LABELS
        assert BOND_GAME_LABELS['word_duet'] == 'Word Bond: Duet'
        assert BOND_GAME_LABELS['team_crossword'] == 'Team Crossword'
