"""Regression tests for the Online 1v1 Duel pong fixes.

Covers: score-relay echo exclusion + winner validation, join/rejoin grace
flow, shared first-to-N target, explicit-leave void, disconnect seat hold,
lobby queue alias, and the slime restart echo guard.
"""
import datetime
from unittest.mock import MagicMock, patch

import pytest


def _handlers():
    import main as m
    found = {}
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]):
            fn = call.args[0]
            found[getattr(fn, '__name__', '')] = fn
    return found


@pytest.fixture()
def pong_state():
    """Isolate pong room/queue globals per test."""
    import main as m
    saved_rooms = dict(m.active_pong_rooms)
    saved_queue = list(m.pong_matchmaking_queue)
    m.active_pong_rooms.clear()
    m.pong_matchmaking_queue.clear()
    try:
        yield m
    finally:
        m.active_pong_rooms.clear()
        m.active_pong_rooms.update(saved_rooms)
        m.pong_matchmaking_queue.clear()
        m.pong_matchmaking_queue.extend(saved_queue)


def _guest_user():
    stub = MagicMock()
    stub.is_authenticated = False
    return stub


def _as_sid(m, sid, fn, *args, **kwargs):
    req = MagicMock()
    req.sid = sid
    with patch.object(m, 'request', req), \
            patch.object(m, 'current_user', _guest_user()), \
            patch.object(m, 'emit') as mock_emit, \
            patch.object(m, 'join_room') as mock_join, \
            patch.object(m, 'leave_room') as mock_leave:
        result = fn(*args, **kwargs)
    return result, mock_emit, mock_join, mock_leave


class TestPongScoreRelay:
    def test_valid_winner_relayed_without_self_echo(self, pong_state):
        m = pong_state
        h = _handlers()['handle_pong_score_update']
        m.active_pong_rooms['r1'] = {'host_sid': 'A', 'guest_sid': 'B',
                                     'scores': [0, 0], 'target': 3}
        _, mock_emit, _, _ = _as_sid(
            m, 'A', h, {'room_id': 'r1', 'scores': [3, 0], 'winner': 1})
        assert mock_emit.call_count == 1
        args, kwargs = mock_emit.call_args
        assert args[0] == 'pong_score_update'
        assert kwargs.get('include_self') is False  # echo storm guard
        assert args[1]['winner'] == 1
        assert m.active_pong_rooms['r1']['scores'] == [3, 0]

    def test_phantom_winner_stripped_scores_still_relay(self, pong_state):
        m = pong_state
        h = _handlers()['handle_pong_score_update']
        m.active_pong_rooms['r1'] = {'host_sid': 'A', 'guest_sid': 'B',
                                     'scores': [0, 0], 'target': 3}
        for bad in ({'room_id': 'r1', 'scores': [0, 0], 'winner': 1},
                    {'room_id': 'r1', 'scores': [2, 1], 'winner': 1},
                    {'room_id': 'r1', 'scores': [3, 0], 'winner': 9},
                    {'room_id': 'r1', 'scores': [3, 0], 'winner': 2}):
            _, mock_emit, _, _ = _as_sid(m, 'A', h, dict(bad))
            relayed = mock_emit.call_args[0][1]
            assert 'winner' not in relayed, f"phantom winner leaked: {bad}"
            assert relayed['scores'] == bad['scores']

    def test_tolerates_malformed_payloads(self, pong_state):
        m = pong_state
        h = _handlers()['handle_pong_score_update']
        m.active_pong_rooms['r1'] = {'host_sid': 'A', 'scores': [0, 0]}
        _as_sid(m, 'A', h, None)
        _as_sid(m, 'A', h, {})
        _as_sid(m, 'A', h, {'room_id': 'r1'})


class TestPongJoinRejoin:
    def test_full_room_rejects_stranger(self, pong_state):
        m = pong_state
        h = _handlers()['handle_join_pong_room']
        _as_sid(m, 'A', h, {'room_id': 'duel1'})
        _as_sid(m, 'B', h, {'room_id': 'duel1'})
        _, mock_emit, _, _ = _as_sid(m, 'C', h, {'room_id': 'duel1'})
        err = mock_emit.call_args[0]
        assert err[0] == 'pong_room_error'

    def test_joined_payload_carries_scores_and_target(self, pong_state):
        m = pong_state
        h = _handlers()['handle_join_pong_room']
        _, mock_emit, _, _ = _as_sid(m, 'A', h, {'room_id': 'duel1'})
        payload = mock_emit.call_args[0][1]
        assert payload['scores'] == [0, 0]
        assert 'target' in payload
        assert payload['player'] == 0 and payload['is_host'] is True

    def test_disconnect_drops_room_immediately_no_rejoin(self, pong_state):
        m = pong_state
        handlers = _handlers()
        join = handlers['handle_join_pong_room']
        disc = handlers['handle_dm_disconnect']
        _as_sid(m, 'A', join, {'room_id': 'duel1'})
        _as_sid(m, 'B', join, {'room_id': 'duel1'})

        # Guest transport drops: room is immediately voided and deleted (no coming back).
        _, mock_emit, _, _ = _as_sid(m, 'B', disc)
        left = [c for c in mock_emit.call_args_list if c[0][0] == 'pong_player_left']
        assert left, "expected pong_player_left on disconnect"
        assert left[0][0][1]['reason'] == 'disconnected'
        assert 'duel1' not in m.active_pong_rooms
        # Queue must not retain the dropped sid.
        assert all(q['sid'] != 'B' for q in m.pong_matchmaking_queue)

        # Rejoin attempt cannot reclaim old room because old room is gone; starts fresh afresh
        _, mock_emit2, _, _ = _as_sid(m, 'C', join, {'room_id': 'duel1'})
        joined = [c for c in mock_emit2.call_args_list if c[0][0] == 'pong_room_joined'][0][0][1]
        assert joined['is_host'] is True  # C is fresh host of a new room
        assert joined['scores'] == [0, 0]

    def test_unattended_room_pruned_after_one_hour(self, pong_state):
        m = pong_state
        handlers = _handlers()
        join = handlers['handle_join_pong_room']
        _as_sid(m, 'A', join, {'room_id': 'duel1'})
        m.active_pong_rooms['duel1']['created_at'] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2))
        m._prune_unattended_game_rooms()
        assert 'duel1' not in m.active_pong_rooms

    def test_explicit_leave_voids_match(self, pong_state):
        m = pong_state
        handlers = _handlers()
        _as_sid(m, 'A', handlers['handle_join_pong_room'], {'room_id': 'duel1'})
        _as_sid(m, 'B', handlers['handle_join_pong_room'], {'room_id': 'duel1'})
        _, mock_emit, _, _ = _as_sid(
            m, 'A', handlers['handle_leave_pong_room'], {'room_id': 'duel1'})
        left = [c for c in mock_emit.call_args_list if c[0][0] == 'pong_player_left']
        assert left and left[0][0][1]['reason'] == 'left'
        assert 'duel1' not in m.active_pong_rooms


class TestPongMatchmaking:
    def test_shared_first_to_n_from_host(self, pong_state):
        m = pong_state
        h = _handlers()['handle_find_pong_match']
        _as_sid(m, 'A', h, {'streak': 0, 'score': 0, 'target': 5})
        _, mock_emit, _, _ = _as_sid(m, 'B', h, {'streak': 0, 'score': 0, 'target': 3})
        found = [c for c in mock_emit.call_args_list if c[0][0] == 'pong_match_found']
        assert len(found) == 2  # host + guest endpoints (same mocked emit)
        assert all(c[0][1]['target'] == 5 for c in found)  # host's (A's) target wins
        assert len(m.active_pong_rooms) == 1
        room = next(iter(m.active_pong_rooms.values()))
        assert room['target'] == 5


class TestLobbyAlias:
    def test_broadcast_includes_queue_key(self, pong_state):
        m = pong_state
        with patch.object(m, 'emit') as mock_emit:
            m.broadcast_matchmaking_queue(
                [{'sid': 'A', 'user_name': 'Ann', 'streak': 1, 'score': 10},
                 {'sid': 'B', 'user_name': 'Bob', 'streak': 0, 'score': 0}],
                'pong_queue_updated')
        for call in mock_emit.call_args_list:
            payload = call[0][1]
            assert 'queue' in payload and 'opponents' in payload
            assert payload['queue'] == payload['opponents']


class TestSlimeRestartEcho:
    def test_slime_restart_excludes_sender(self, pong_state):
        m = pong_state
        h = _handlers()['handle_slime_restart']
        with patch.object(m, 'emit') as mock_emit:
            h({'room_id': 's1'})
        assert mock_emit.call_count == 1
        assert mock_emit.call_args[1].get('include_self') is False


class TestPingPongPerspectiveMirror:
    def test_ping_pong_guest_perspective_mirror(self):
        """Verify static/ping_pong.js displays online guest on the left side with mirrored ball coordinates."""
        import os
        js_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'ping_pong.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert 'isMirrored' in content
        assert 'state.mode === \'online\' && state.playerIndex === 1' in content
        assert 'V_WIDTH - state.ball.x' in content
        assert 'state.p2.color' in content


class TestSlimeVolleyballControlsAndServeSync:
    def test_slime_volleyball_template_has_slider_and_jump(self):
        """Verify templates/slime_volleyball.html has movement slider and single jump button."""
        import os
        html_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'slime_volleyball.html')
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert 'id="slime-slider-wrapper"' in content
        assert 'id="slime-slider-thumb"' in content
        assert 'id="touch-jump"' in content

    def test_slime_volleyball_js_serve_state_sync_and_slider(self):
        """Verify static/slime_volleyball.js synchronizes serveState and uses
        single-authority guest sync (seq stale-drop; the old p2LastHitTime
        timer guard was the phantom-bounce mechanism and is gone)."""
        import os
        js_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'slime_volleyball.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert 'serveState: GameState.serveState' in content
        assert 'p2LastHitTime' not in content
        assert 'GameState.lastHostSeq' in content
        assert 'slime-slider-wrapper' in content
        assert 'updateSlider' in content


class TestLobbyCleanupAndNoComingBack:
    def test_lobby_closed_when_host_leaves(self, pong_state):
        m = pong_state
        handlers = _handlers()
        leave_fn = handlers['handle_leave_game']
        mock_sessions = MagicMock()
        mock_sessions.find_one.return_value = {'lobby_id': 'lob1', 'host_id': 'user_host_1'}

        with patch.object(m, 'game_sessions_conf', mock_sessions):
            m.active_game_players['lob1'] = {
                'user_host_1': {'name': 'Host'},
                'user_guest_2': {'name': 'Guest'}
            }
            # Host leaves lobby
            with patch.object(m, 'current_user', MagicMock(id='user_host_1', is_authenticated=True)):
                with patch('main.emit') as mock_emit, patch('main.leave_room'):
                    leave_fn({'lobby_id': 'lob1'})

                    # Assert game_lobby_closed emitted and lobby marked closed/deactivated
                    closed_calls = [c for c in mock_emit.call_args_list if c[0][0] == 'game_lobby_closed']
                    assert len(closed_calls) == 1
                    assert 'lob1' not in m.active_game_players
                    mock_sessions.update_one.assert_called()
                    update_arg = mock_sessions.update_one.call_args[0][1]['$set']
                    assert update_arg['deactivated'] is True
                    assert update_arg['status'] == 'closed'

    def test_duet_leave_socket_voids_room(self, pong_state):
        m = pong_state
        handlers = _handlers()
        leave_duet = handlers['handle_leave_duet_room']
        m.active_duet_rooms['duet_1'] = {'host_sid': 'sid_A', 'guest_sid': 'sid_B'}

        with patch('main.request', MagicMock(sid='sid_A')), \
             patch('main.emit') as mock_emit, \
             patch('main.leave_room'):
            leave_duet({'room_id': 'duet_1'})
            assert 'duet_1' not in m.active_duet_rooms
            partner_left = [c for c in mock_emit.call_args_list if c[0][0] == 'duet_partner_left']
            assert len(partner_left) == 1
            assert partner_left[0][0][1]['reason'] == 'left'

    def test_unattended_lobbies_pruned(self):
        from blueprints.game import _prune_unattended_lobbies
        import main as m
        mock_conf = MagicMock()
        mock_conf.find.return_value.limit.return_value = [{'lobby_id': 'old_stale_1'}]
        with patch.object(m, 'game_sessions_conf', mock_conf), \
             patch.object(m, 'game_votes_conf', MagicMock()), \
             patch.object(m, 'game_submissions_conf', MagicMock()):
            _prune_unattended_lobbies()
            assert mock_conf.update_many.called
            assert mock_conf.delete_many.called


class TestMultiplayerHostSettingsAndRandomFirstMover:
    def test_pong_target_update_host_only(self, pong_state):
        m = pong_state
        handlers = _handlers()
        h_target = handlers['handle_pong_target_update']
        m.active_pong_rooms['room_target_test'] = {
            'host_sid': 'sid_host',
            'guest_sid': 'sid_guest',
            'target': 3,
            'scores': [0, 0]
        }

        # Guest attempts to change target -> rejected
        _, mock_emit_guest, _, _ = _as_sid(
            m, 'sid_guest', h_target, {'room_id': 'room_target_test', 'target': 7}
        )
        assert m.active_pong_rooms['room_target_test']['target'] == 3
        err_calls = [c for c in mock_emit_guest.call_args_list if c[0][0] == 'pong_room_error']
        assert len(err_calls) == 1
        assert any(c[0][0] == 'pong_target_updated' for c in mock_emit_guest.call_args_list) is False

        # Host changes target -> accepted and broadcast
        _, mock_emit_host, _, _ = _as_sid(
            m, 'sid_host', h_target, {'room_id': 'room_target_test', 'target': 7}
        )
        assert m.active_pong_rooms['room_target_test']['target'] == 7
        assert mock_emit_host.call_count == 1
        args, kwargs = mock_emit_host.call_args
        assert args[0] == 'pong_target_updated'
        assert args[1]['target'] == 7

    def test_crossword_restart_host_only(self, pong_state):
        m = pong_state
        handlers = _handlers()
        h_restart = handlers['handle_crossword_restart']
        m.active_crossword_rooms['room_xword_test'] = {
            'host_sid': 'sid_host',
            'guest_sid': 'sid_guest',
            'puzzle_idx': 0,
            'grid': [''] * 25
        }

        # Guest attempts to change puzzle -> rejected
        _, mock_emit_guest, _, _ = _as_sid(
            m, 'sid_guest', h_restart, {'room_id': 'room_xword_test', 'puzzle_idx': 3}
        )
        assert m.active_crossword_rooms['room_xword_test']['puzzle_idx'] == 0
        assert mock_emit_guest.call_count == 0

        # Host changes puzzle -> accepted and broadcast
        _, mock_emit_host, _, _ = _as_sid(
            m, 'sid_host', h_restart, {'room_id': 'room_xword_test', 'puzzle_idx': 3}
        )
        assert m.active_crossword_rooms['room_xword_test']['puzzle_idx'] == 3
        assert mock_emit_host.call_count == 1
        args, kwargs = mock_emit_host.call_args
        assert args[0] == 'crossword_restarted'
        assert args[1]['puzzle_idx'] == 3
        m.active_crossword_rooms.pop('room_xword_test', None)

    def test_random_first_mover_across_games(self, pong_state):
        m = pong_state
        handlers = _handlers()

        # 1. Ping Pong join & restart
        h_pong_join = handlers['handle_join_pong_room']
        h_pong_restart = handlers['handle_pong_restart']
        _as_sid(m, 'sid_h', h_pong_join, {'room_id': 'r_pong_rnd'})
        _, emit_join, _, _ = _as_sid(m, 'sid_g', h_pong_join, {'room_id': 'r_pong_rnd'})
        join_payload = [c[0][1] for c in emit_join.call_args_list if c[0][0] == 'pong_room_joined'][0]
        assert join_payload['serving_player'] in (0, 1)

        _, emit_restart, _, _ = _as_sid(m, 'sid_h', h_pong_restart, {'room_id': 'r_pong_rnd'})
        restart_payload = [c[0][1] for c in emit_restart.call_args_list if c[0][0] == 'pong_restart'][0]
        assert restart_payload['serving_player'] in (0, 1)

        # 2. Slime Volleyball join & restart
        h_slime_join = handlers['handle_join_slime_room']
        h_slime_restart = handlers['handle_slime_restart']
        _as_sid(m, 'sid_sh', h_slime_join, {'room_id': 'r_slime_rnd'})
        _, emit_slime_join, _, _ = _as_sid(m, 'sid_sg', h_slime_join, {'room_id': 'r_slime_rnd'})
        s_join_payload = [c[0][1] for c in emit_slime_join.call_args_list if c[0][0] == 'slime_room_joined'][0]
        assert s_join_payload['serving'] in (-1, 1)

        _, emit_slime_restart, _, _ = _as_sid(m, 'sid_sh', h_slime_restart, {'room_id': 'r_slime_rnd'})
        s_restart_payload = [c[0][1] for c in emit_slime_restart.call_args_list if c[0][0] == 'slime_restart'][0]
        assert s_restart_payload['serving'] in (-1, 1)

        # 3. Tic-Tac-Toe join
        h_ttt_join = handlers['handle_join_ttt_room']
        _as_sid(m, 'sid_th', h_ttt_join, {'room_id': 'r_ttt_rnd'})
        _, emit_ttt_join, _, _ = _as_sid(m, 'sid_tg', h_ttt_join, {'room_id': 'r_ttt_rnd'})
        ttt_payload = [c[0][1] for c in emit_ttt_join.call_args_list if c[0][0] == 'ttt_room_joined'][0]
        assert ttt_payload['turn'] in ('x', 'o')

        # 4. Connect Four join
        h_c4_join = handlers['handle_join_c4_room']
        _as_sid(m, 'sid_c4h', h_c4_join, {'room_id': 'r_c4_rnd'})
        _, emit_c4_join, _, _ = _as_sid(m, 'sid_c4g', h_c4_join, {'room_id': 'r_c4_rnd'})
        c4_payload = [c[0][1] for c in emit_c4_join.call_args_list if c[0][0] == 'c4_room_joined'][0]
        assert c4_payload['turn'] in (0, 1)

        # 5. Dots and Boxes join
        h_dnb_join = handlers['handle_join_dnb_room']
        _as_sid(m, 'sid_dnbh', h_dnb_join, {'room_id': 'r_dnb_rnd'})
        _, emit_dnb_join, _, _ = _as_sid(m, 'sid_dnbg', h_dnb_join, {'room_id': 'r_dnb_rnd'})
        dnb_payload = [c[0][1] for c in emit_dnb_join.call_args_list if c[0][0] == 'dnb_room_joined'][0]
        assert dnb_payload['turn'] in (0, 1)

        # 6. Word Duet join
        h_duet_join = handlers['handle_join_duet_room']
        _as_sid(m, 'sid_dh', h_duet_join, {'room_id': 'r_duet_rnd'})
        _, emit_duet_join, _, _ = _as_sid(m, 'sid_dg', h_duet_join, {'room_id': 'r_duet_rnd'})
        duet_payload = [c[0][1] for c in emit_duet_join.call_args_list if c[0][0] == 'duet_room_joined'][0]
        assert duet_payload['active_giver'] in ('A', 'B')


