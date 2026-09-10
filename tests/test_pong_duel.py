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

    def test_disconnect_holds_seat_and_rejoin_reclaims(self, pong_state):
        m = pong_state
        handlers = _handlers()
        join = handlers['handle_join_pong_room']
        disc = handlers['handle_dm_disconnect']
        _as_sid(m, 'A', join, {'room_id': 'duel1'})
        _as_sid(m, 'B', join, {'room_id': 'duel1'})

        # Guest transport drops: room must be KEPT (no forced result).
        _, mock_emit, _, _ = _as_sid(m, 'B', disc)
        left = [c for c in mock_emit.call_args_list if c[0][0] == 'pong_player_left']
        assert left, "expected pong_player_left on disconnect"
        assert left[0][0][1]['reason'] == 'disconnected'
        assert 'duel1' in m.active_pong_rooms
        assert m.active_pong_rooms['duel1']['disconnected_side'] == 'guest_sid'
        # Queue must not retain the dropped sid.
        assert all(q['sid'] != 'B' for q in m.pong_matchmaking_queue)

        # Same player returns on a fresh sid inside the window: seat reclaimed
        # with live scores, opponent notified — never a full-room refusal.
        m.active_pong_rooms['duel1']['scores'] = [2, 1]
        _, mock_emit2, _, _ = _as_sid(
            m, 'C', join, {'room_id': 'duel1', 'rejoin': True, 'player': 1})
        names = [c[0][0] for c in mock_emit2.call_args_list]
        assert 'pong_room_joined' in names
        assert 'pong_opponent_rejoined' in names
        joined = [c for c in mock_emit2.call_args_list if c[0][0] == 'pong_room_joined'][0][0][1]
        assert joined['rejoined'] is True
        assert joined['scores'] == [2, 1]
        assert m.active_pong_rooms['duel1']['guest_sid'] == 'C'

    def test_stale_room_pruned_after_grace(self, pong_state):
        m = pong_state
        handlers = _handlers()
        join = handlers['handle_join_pong_room']
        _as_sid(m, 'A', join, {'room_id': 'duel1'})
        _as_sid(m, 'B', join, {'room_id': 'duel1'})
        _as_sid(m, 'B', handlers['handle_dm_disconnect'])
        m.active_pong_rooms['duel1']['disconnected_at'] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=9999))
        _, mock_emit, _, _ = _as_sid(m, 'D', join, {'room_id': 'duel1'})
        payload = mock_emit.call_args[0][1]
        assert mock_emit.call_args[0][0] == 'pong_room_joined'
        assert payload['is_host'] is True  # fresh room, D is the new host

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
