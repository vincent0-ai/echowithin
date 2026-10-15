"""Event-readiness simulation suite (Phase 2).

Scripted two-client simulations + forgery/race batteries for every game,
risk-ordered: realtime duels -> turn-based duels -> co-op -> party -> solo.

Each test documents OBSERVED server behavior. Tests asserting GOOD behavior
fail if a regression appears; tests documenting ACCEPTED relay behavior pin
it explicitly so event-day risk is visible.
"""
import datetime
from unittest.mock import MagicMock, patch


def _handlers():
    import main as m
    found = {}
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]):
            fn = call.args[0]
            found[getattr(fn, '__name__', '')] = fn
    return found


def _guest():
    stub = MagicMock()
    stub.is_authenticated = False
    return stub


def _authed(uid='u1', name='P1'):
    stub = MagicMock()
    stub.is_authenticated = True
    stub.id = uid
    stub.username = name
    return stub


def _as_sid(m, sid, fn, data=None, user=None):
    req = MagicMock()
    req.sid = sid
    curr = user if user is not None else _guest()
    with patch.object(m, 'request', req), \
            patch.object(m, 'current_user', curr), \
            patch.object(m, 'emit') as mock_emit, \
            patch.object(m, 'join_room'), \
            patch.object(m, 'leave_room'):
        fn(data)
    return mock_emit


def _emits_to(mock_emit, event, room=None):
    out = []
    for c in mock_emit.call_args_list:
        if c[0][0] != event:
            continue
        if room is not None and c[1].get('room') != room:
            continue
        out.append(c)
    return out


def _save_rooms(m, *names):
    saved = {}
    for n in names:
        obj = getattr(m, n)
        saved[n] = dict(obj) if isinstance(obj, dict) else list(obj)
    return saved


def _restore_rooms(m, saved):
    for n, rooms in saved.items():
        obj = getattr(m, n)
        obj.clear()
        if isinstance(obj, dict):
            obj.update(rooms)
        else:
            obj.extend(rooms)


PONG_ROOMS = ('active_pong_rooms', 'pong_matchmaking_queue')
SLIME_ROOMS = ('active_slime_rooms', 'slime_matchmaking_queue')
AIR_ROOMS = ('active_air_rooms', 'air_matchmaking_queue')


def _pong_room(h, m, room_id='sim_pong', target=5):
    _as_sid(m, 'sid_host', h['handle_join_pong_room'],
            {'room_id': room_id}, user=_authed('u_host', 'Host'))
    _as_sid(m, 'sid_guest', h['handle_join_pong_room'],
            {'room_id': room_id}, user=_authed('u_guest', 'Guest'))
    m.active_pong_rooms[room_id]['target'] = target
    return room_id


class TestPongTwoClientSim:
    def test_score_converges_both_sides_no_echo(self):
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            mock_emit = _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                                {'room_id': rid, 'scores': [1, 0]})
            relayed = _emits_to(mock_emit, 'pong_score_update', room=rid)
            assert len(relayed) == 1
            assert relayed[0][0][1]['scores'] == [1, 0]
            assert relayed[0][1].get('include_self') is False
            assert m.active_pong_rooms[rid]['scores'] == [1, 0]
        finally:
            _restore_rooms(m, saved)

    def test_paddle_sync_side_checked(self):
        """Host may only sync player 0, guest player 1; strangers dropped."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            bad = _as_sid(m, 'sid_host', h['handle_pong_paddle_sync'],
                          {'room_id': rid, 'player': 1, 'y': 100, 'seq': 1})
            assert _emits_to(bad, 'pong_paddle_sync', room=rid) == []
            stranger = _as_sid(m, 'sid_stranger', h['handle_pong_paddle_sync'],
                               {'room_id': rid, 'player': 1, 'y': 100, 'seq': 1})
            assert _emits_to(stranger, 'pong_paddle_sync', room=rid) == []
            ok = _as_sid(m, 'sid_guest', h['handle_pong_paddle_sync'],
                         {'room_id': rid, 'player': 1, 'y': 100, 'seq': 1})
            assert len(_emits_to(ok, 'pong_paddle_sync', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_join_pong_room'],
                                {'room_id': rid}, user=_authed('u3', 'Third'))
            assert _emits_to(mock_emit, 'pong_room_error')
        finally:
            _restore_rooms(m, saved)

    def test_full_room_rejects_third_client(self):
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_join_pong_room'],
                                {'room_id': rid}, user=_authed('u3', 'Third'))
            assert _emits_to(mock_emit, 'pong_room_error')
        finally:
            _restore_rooms(m, saved)

    def test_non_host_score_claims_dropped(self):
        """FIXED (BUG-001): only the host sim's scores are accepted, stored
        and relayed; guest/stranger claims are dropped silently."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            with patch.object(m, 'record_match_result'):
                guest = _as_sid(m, 'sid_guest', h['handle_pong_score_update'],
                                {'room_id': rid, 'scores': [0, 3]})
                assert _emits_to(guest, 'pong_score_update', room=rid) == []
                stranger = _as_sid(m, 'sid_stranger', h['handle_pong_score_update'],
                                   {'room_id': rid, 'scores': [9, 9]})
                assert _emits_to(stranger, 'pong_score_update', room=rid) == []
                assert m.active_pong_rooms[rid]['scores'] == [0, 0]
                host = _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                               {'room_id': rid, 'scores': [1, 0]})
                relayed = _emits_to(host, 'pong_score_update', room=rid)
                assert len(relayed) == 1 and relayed[0][0][1]['scores'] == [1, 0]
                assert m.active_pong_rooms[rid]['scores'] == [1, 0]
        finally:
            _restore_rooms(m, saved)

    def test_member_restart_works_stranger_restart_dropped(self):
        """FIXED (BUG-003): pong_restart requires room membership; stranger
        drops silently, member (either side) rematch still works."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            m.active_pong_rooms[rid]['scores'] = [4, 2]
            stranger = _as_sid(m, 'sid_stranger', h['handle_pong_restart'],
                               {'room_id': rid})
            assert _emits_to(stranger, 'pong_restart', room=rid) == []
            assert m.active_pong_rooms[rid]['scores'] == [4, 2]
            member = _as_sid(m, 'sid_guest', h['handle_pong_restart'],
                             {'room_id': rid})
            assert m.active_pong_rooms[rid]['scores'] == [0, 0]
            assert len(_emits_to(member, 'pong_restart', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)

    def test_only_host_scoreline_records_ranked_win(self):
        """FIXED (BUG-001): a self-consistent scoreline + winner is recorded
        only from the host sim; guest forgery is dropped with no record."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m, target=5)
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_guest', h['handle_pong_score_update'],
                        {'room_id': rid, 'scores': [0, 5], 'winner': 2})
                assert mock_rec.call_count == 0
                _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                        {'room_id': rid, 'scores': [0, 5], 'winner': 2})
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] == 'u_guest'
        finally:
            _restore_rooms(m, saved)

    def test_repeated_winner_emits_record_once_restart_reopens(self):
        """FIXED (BUG-002): one match doc per room; a member restart starts a
        new recordable match."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m, target=5)
            with patch.object(m, 'record_match_result') as mock_rec:
                for _ in range(3):
                    _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                            {'room_id': rid, 'scores': [5, 0], 'winner': 1})
                assert mock_rec.call_count == 1
                _as_sid(m, 'sid_host', h['handle_pong_restart'], {'room_id': rid})
                _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                        {'room_id': rid, 'scores': [5, 0], 'winner': 1})
                assert mock_rec.call_count == 2
        finally:
            _restore_rooms(m, saved)


def _slime_room(h, m, room_id='sim_slime'):
    _as_sid(m, 'sid_host', h['handle_join_slime_room'],
            {'room_id': room_id}, user=_authed('u_host', 'Host'))
    _as_sid(m, 'sid_guest', h['handle_join_slime_room'],
            {'room_id': room_id}, user=_authed('u_guest', 'Guest'))
    return room_id


class TestSlimeTwoClientSim:
    def test_host_sync_and_input_side_gated(self):
        """FIXED (BUG-004): slime_host_sync accepts host only, slime_player_input
        guest only; forged authoritative state from anyone else is dropped."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            payload = {'room_id': rid, 'ball': {'x': 999, 'y': 999},
                       'scores': [7, 0], 'serveState': 'PLAYING',
                       'seq': 1, 'tSend': 1.0}
            stranger = _as_sid(m, 'sid_stranger', h['handle_slime_host_sync'],
                               dict(payload))
            assert _emits_to(stranger, 'slime_host_sync', room=rid) == []
            guest = _as_sid(m, 'sid_guest', h['handle_slime_host_sync'],
                            dict(payload))
            assert _emits_to(guest, 'slime_host_sync', room=rid) == []
            host = _as_sid(m, 'sid_host', h['handle_slime_host_sync'],
                           dict(payload))
            relayed = _emits_to(host, 'slime_host_sync', room=rid)
            assert len(relayed) == 1
            assert relayed[0][1].get('include_self') is False
            inp = {'room_id': rid, 'p2': {'x': 1.0}, 'seq': 2}
            host_inp = _as_sid(m, 'sid_host', h['handle_slime_player_input'],
                               dict(inp))
            assert _emits_to(host_inp, 'slime_player_input', room=rid) == []
            guest_inp = _as_sid(m, 'sid_guest', h['handle_slime_player_input'],
                                dict(inp))
            assert len(_emits_to(guest_inp, 'slime_player_input', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)

    def test_restart_requires_membership(self):
        """FIXED (BUG-003): slime_restart drops non-members; host rematch works."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            before = m.active_slime_rooms[rid].get('serving')
            stranger = _as_sid(m, 'sid_stranger', h['handle_slime_restart'],
                               {'room_id': rid})
            assert _emits_to(stranger, 'slime_restart', room=rid) == []
            assert m.active_slime_rooms[rid].get('serving') == before
            host = _as_sid(m, 'sid_host', h['handle_slime_restart'],
                           {'room_id': rid})
            assert len(_emits_to(host, 'slime_restart', room=rid)) == 1
            assert m.active_slime_rooms[rid].get('serving') in (-1, 1)
        finally:
            _restore_rooms(m, saved)

    def test_match_end_garbage_winner_dropped(self):
        """FIXED (part of BUG-005): winner outside host/guest records nothing
        (previously recorded a draw with ELO effect)."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            with patch.object(m, 'record_match_result') as mock_rec:
                for bad in ('draw', '', None, 'HOST', 0):
                    _as_sid(m, 'sid_host', h['handle_slime_match_end'],
                            {'room_id': rid, 'winner': bad})
                assert mock_rec.call_count == 0
        finally:
            _restore_rooms(m, saved)
        """GOOD: only the host sid may report the match result."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_guest', h['handle_slime_match_end'],
                        {'room_id': rid, 'winner': 'guest'})
                assert mock_rec.call_count == 0
        finally:
            _restore_rooms(m, saved)

    def test_match_end_host_reports_either_winner_unchecked(self):
        """OBSERVED: host-reported winner/score stored without validation
        against played points."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_host', h['handle_slime_match_end'],
                        {'room_id': rid, 'winner': 'guest',
                         'score': {'host': 0, 'guest': 99}})
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] == 'u_guest'
        finally:
            _restore_rooms(m, saved)


def _air_room(h, m, room_id='sim_air'):
    _as_sid(m, 'sid_host', h['handle_join_air_room'],
            {'room_id': room_id}, user=_authed('u_host', 'Host'))
    _as_sid(m, 'sid_guest', h['handle_join_air_room'],
            {'room_id': room_id}, user=_authed('u_guest', 'Guest'))
    return room_id


class TestAirTwoClientSim:
    def test_state_and_score_guest_gated(self):
        """GOOD: air_state/air_score/air_input enforce host/guest sids."""
        import main as m
        saved = _save_rooms(m, *AIR_ROOMS)
        try:
            h = _handlers()
            rid = _air_room(h, m)
            with patch.object(m, 'record_match_result') as mock_rec:
                e1 = _as_sid(m, 'sid_guest', h['handle_air_state'],
                             {'room_id': rid, 'puck': {'x': 1}, 'scores': [0, 7]})
                assert _emits_to(e1, 'air_state', room=rid) == []
                e2 = _as_sid(m, 'sid_guest', h['handle_air_score'],
                             {'room_id': rid, 'scores': [0, 7]})
                assert _emits_to(e2, 'air_score_update', room=rid) == []
                assert mock_rec.call_count == 0
                assert m.active_air_rooms[rid]['scores'] == [0, 0]
        finally:
            _restore_rooms(m, saved)

    def test_restart_requires_membership(self):
        """FIXED (BUG-003): air_restart drops strangers; member rematch works."""
        import main as m
        saved = _save_rooms(m, *AIR_ROOMS)
        try:
            h = _handlers()
            rid = _air_room(h, m)
            m.active_air_rooms[rid]['scores'] = [6, 5]
            stranger = _as_sid(m, 'sid_stranger', h['handle_air_restart'],
                               {'room_id': rid})
            assert _emits_to(stranger, 'air_restarted', room=rid) == []
            assert m.active_air_rooms[rid]['scores'] == [6, 5]
            member = _as_sid(m, 'sid_guest', h['handle_air_restart'],
                             {'room_id': rid})
            assert m.active_air_rooms[rid]['scores'] == [0, 0]
            assert len(_emits_to(member, 'air_restarted', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)

    def test_tied_scoreline_voided_no_ranked_record(self):
        """FIXED (BUG-006): [7,7] at target 7 emits air_result winner None
        and records nothing (no ELO change)."""
        import main as m
        saved = _save_rooms(m, *AIR_ROOMS)
        try:
            h = _handlers()
            rid = _air_room(h, m)
            with patch.object(m, 'record_match_result') as mock_rec:
                mock_emit = _as_sid(m, 'sid_host', h['handle_air_score'],
                                    {'room_id': rid, 'scores': [7, 7]})
                assert mock_rec.call_count == 0
            results = _emits_to(mock_emit, 'air_result', room=rid)
            assert len(results) == 1
            assert results[0][0][1]['winner'] is None
        finally:
            _restore_rooms(m, saved)


TTT = ('active_ttt_rooms', 'ttt_matchmaking_queue')
C4 = ('active_c4_rooms', 'c4_matchmaking_queue')
DNB = ('active_dnb_rooms', 'dnb_matchmaking_queue')
GOMOKU = ('active_gomoku_rooms', 'gomoku_matchmaking_queue')
WHACK = ('active_whack_rooms', 'whack_matchmaking_queue')


def _ttt_room(h, m, room_id='sim_ttt'):
    _as_sid(m, 'sid_host', h['handle_join_ttt_room'],
            {'room_id': room_id}, user=_authed('u_host', 'Host'))
    _as_sid(m, 'sid_guest', h['handle_join_ttt_room'],
            {'room_id': room_id}, user=_authed('u_guest', 'Guest'))
    return room_id


class TestTttSeatHijack:
    def test_third_joiner_rejected_seats_intact(self):
        """FIXED (BUG-007): full room rejects third socket; host/guest
        rejoins refresh without disturbing seats."""
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            hijack = _as_sid(m, 'sid_hijacker', h['handle_join_ttt_room'],
                             {'room_id': rid}, user=_authed('u_hij', 'Hijacker'))
            assert m.active_ttt_rooms[rid]['guest_sid'] == 'sid_guest'
            errs = [c for c in hijack.call_args_list if c[0][0] == 'ttt_room_error']
            assert len(errs) == 1
            assert not [c for c in hijack.call_args_list if c[0][0] == 'ttt_room_joined']
            host_re = _as_sid(m, 'sid_host', h['handle_join_ttt_room'],
                              {'room_id': rid}, user=_authed('u_host', 'Host'))
            joined = [c for c in host_re.call_args_list if c[0][0] == 'ttt_room_joined']
            assert joined and joined[0][0][1]['is_host'] is True
            assert m.active_ttt_rooms[rid]['guest_sid'] == 'sid_guest'
        finally:
            _restore_rooms(m, saved)

    def test_out_of_turn_and_occupied_moves_dropped(self):
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            first = m.active_ttt_rooms[rid]['turn']
            first_sid = 'sid_host' if first == 'x' else 'sid_guest'
            second_sid = 'sid_guest' if first == 'x' else 'sid_host'
            e1 = _as_sid(m, second_sid, h['handle_ttt_move'],
                         {'room_id': rid, 'index': 0})
            assert _emits_to(e1, 'ttt_move_made', room=rid) == []
            assert m.active_ttt_rooms[rid]['board'][0] == ''
            e2 = _as_sid(m, first_sid, h['handle_ttt_move'],
                         {'room_id': rid, 'index': 0})
            assert len(_emits_to(e2, 'ttt_move_made', room=rid)) == 1
            e3 = _as_sid(m, first_sid, h['handle_ttt_move'],
                         {'room_id': rid, 'index': 0})
            assert _emits_to(e3, 'ttt_move_made', room=rid) == []
        finally:
            _restore_rooms(m, saved)

    def test_malformed_moves_never_throw(self):
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            for bad in (None, {}, {'room_id': rid}, {'room_id': rid, 'index': 99},
                        {'room_id': rid, 'index': -1}, {'room_id': rid, 'index': 'x'},
                        {'room_id': rid, 'index': None}, {'room_id': 'nope', 'index': 4}):
                _as_sid(m, 'sid_host', h['handle_ttt_move'], bad)
            assert m.active_ttt_rooms[rid]['board'] == [''] * 9
        finally:
            _restore_rooms(m, saved)

    def test_full_win_records_single_match(self):
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            m.active_ttt_rooms[rid]['turn'] = 'x'
            moves = [('sid_host', 0), ('sid_guest', 3), ('sid_host', 1),
                     ('sid_guest', 4), ('sid_host', 2)]
            with patch.object(m, 'record_match_result') as mock_rec:
                last_emit = None
                for sid, idx in moves:
                    last_emit = _as_sid(m, sid, h['handle_ttt_move'],
                                        {'room_id': rid, 'index': idx})
                made = _emits_to(last_emit, 'ttt_move_made', room=rid)
                assert made and made[0][0][1]['winner'] == 'x'
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] == 'u_host'
        finally:
            _restore_rooms(m, saved)


class TestUngatedRestarts:
    def test_stranger_restarts_dropped_member_restart_works(self):
        """FIXED (BUG-003): ttt/c4/gomoku/dnb restarts require membership."""
        import main as m
        h = _handlers()
        cases = [
            ('active_ttt_rooms', 'handle_join_ttt_room', 'handle_ttt_restart', 'ttt_restarted'),
            ('active_c4_rooms', 'handle_join_c4_room', 'handle_c4_restart', 'c4_restarted'),
            ('active_gomoku_rooms', 'handle_join_gomoku_room', 'handle_gomoku_restart', 'gomoku_restarted'),
            ('active_dnb_rooms', 'handle_join_dnb_room', 'handle_dnb_restart', 'dnb_restarted'),
        ]
        for dict_name, join_name, restart_name, event in cases:
            rooms = getattr(m, dict_name)
            rid = 'sim_rst_%s' % dict_name
            rooms.pop(rid, None)
            try:
                _as_sid(m, 'sid_host', h[join_name], {'room_id': rid},
                        user=_authed('u_host', 'Host'))
                _as_sid(m, 'sid_guest', h[join_name], {'room_id': rid},
                        user=_authed('u_guest', 'Guest'))
                stranger = _as_sid(m, 'sid_stranger', h[restart_name], {'room_id': rid})
                assert _emits_to(stranger, event, room=rid) == [], dict_name
                host = _as_sid(m, 'sid_host', h[restart_name], {'room_id': rid})
                assert len(_emits_to(host, event, room=rid)) == 1, dict_name
            finally:
                rooms.pop(rid, None)

    def test_restart_keeps_series_scores_ttt(self):
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            m.active_ttt_rooms[rid]['scores'] = {'x': 2, 'o': 1, 'ties': 0}
            _as_sid(m, 'sid_host', h['handle_ttt_restart'], {'room_id': rid})
            assert m.active_ttt_rooms[rid]['board'] == [''] * 9
            assert m.active_ttt_rooms[rid]['scores'] == {'x': 2, 'o': 1, 'ties': 0}
        finally:
            _restore_rooms(m, saved)


class TestTurnGameMoveValidation:
    def test_c4_gravity_malformed_and_turn_dropped(self):
        import main as m
        saved = _save_rooms(m, *C4)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_c4_room'], {'room_id': 'sim_c4'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_c4_room'], {'room_id': 'sim_c4'},
                    user=_authed('u_guest', 'Guest'))
            m.active_c4_rooms['sim_c4']['turn'] = 0
            for bad in ({'room_id': 'sim_c4', 'col': 99}, {'room_id': 'sim_c4', 'col': -1},
                        {'room_id': 'sim_c4', 'col': 'x'}, {'room_id': 'nope', 'col': 0}):
                _as_sid(m, 'sid_host', h['handle_c4_move'], bad)
            e = _as_sid(m, 'sid_guest', h['handle_c4_move'], {'room_id': 'sim_c4', 'col': 0})
            assert _emits_to(e, 'c4_move_made', room='sim_c4') == []
            e2 = _as_sid(m, 'sid_host', h['handle_c4_move'], {'room_id': 'sim_c4', 'col': 0})
            made = _emits_to(e2, 'c4_move_made', room='sim_c4')
            assert made and made[0][0][1]['row'] == 5
        finally:
            _restore_rooms(m, saved)

    def test_dnb_extra_turn_rule_and_bounds(self):
        import main as m
        saved = _save_rooms(m, *DNB)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_dnb_room'], {'room_id': 'sim_dnb'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_dnb_room'], {'room_id': 'sim_dnb'},
                    user=_authed('u_guest', 'Guest'))
            m.active_dnb_rooms['sim_dnb']['turn'] = 0
            for bad in ({'room_id': 'sim_dnb', 'type': 'h', 'row': 99, 'col': 0},
                        {'room_id': 'sim_dnb', 'type': 'x', 'row': 0, 'col': 0},
                        {'room_id': 'sim_dnb', 'type': 'h', 'row': 0, 'col': 99}):
                _as_sid(m, 'sid_host', h['handle_dnb_line'], bad)
            assert m.active_dnb_rooms['sim_dnb']['turn'] == 0
            seq = [('sid_host', 'h', 0, 0), ('sid_guest', 'h', 1, 0),
                   ('sid_host', 'v', 0, 0), ('sid_guest', 'v', 0, 1)]
            last = None
            for sid, t, r, c in seq:
                last = _as_sid(m, sid, h['handle_dnb_line'],
                               {'room_id': 'sim_dnb', 'type': t, 'row': r, 'col': c})
            made = _emits_to(last, 'dnb_line_drawn', room='sim_dnb')
            assert made and made[0][0][1]['completed_boxes'] == [{'row': 0, 'col': 0, 'owner': 1}]
            assert made[0][0][1]['extra_turn'] is True
            assert m.active_dnb_rooms['sim_dnb']['turn'] == 1
        finally:
            _restore_rooms(m, saved)

    def test_whack_member_gated_score_capped(self):
        import main as m
        saved = _save_rooms(m, *WHACK)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_guest', 'Guest'))
            e = _as_sid(m, 'sid_stranger', h['handle_whack_score'],
                        {'room_id': 'sim_wh', 'score': 5000})
            assert _emits_to(e, 'whack_state', room='sim_wh') == []
            _as_sid(m, 'sid_host', h['handle_whack_score'],
                    {'room_id': 'sim_wh', 'score': 42})
            assert m.active_whack_rooms['sim_wh']['scores'][0] == 42
            _as_sid(m, 'sid_host', h['handle_whack_score'],
                    {'room_id': 'sim_wh', 'score': 99999999})
            assert m.active_whack_rooms['sim_wh']['scores'][0] == 42
        finally:
            _restore_rooms(m, saved)

    def test_whack_finish_records_once_both_done(self):
        import main as m
        saved = _save_rooms(m, *WHACK)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_guest', 'Guest'))
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_host', h['handle_whack_finish'],
                        {'room_id': 'sim_wh', 'score': 42})
                assert mock_rec.call_count == 0
                last = _as_sid(m, 'sid_guest', h['handle_whack_finish'],
                               {'room_id': 'sim_wh', 'score': 42})
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] is None
                res = _emits_to(last, 'whack_result', room='sim_wh')
                assert res and res[0][0][1]['winner'] is None
        finally:
            _restore_rooms(m, saved)


COOP_JOINS = {
    'handle_join_ttt_room': ('active_ttt_rooms', {'room_id': 'sim_cj'}, 'ttt_room_error'),
    'handle_memory_join_room': ('active_memory_rooms', {'room': 'sim_cj'}, 'memory_error'),
    'handle_join_sudoku_room': ('active_sudoku_rooms', {'room_id': 'sim_cj'}, 'sudoku_room_error'),
    'handle_tot_join_room': ('active_tot_rooms', {'room': 'sim_cj'}, 'tot_error'),
    'handle_join_duet_room': ('active_duet_rooms', {'room_id': 'sim_cj'}, 'duet_room_error'),
    'handle_chain_join_room': ('active_chain_rooms', {'room': 'sim_cj'}, 'chain_error'),
    'handle_emoji_join_room': ('active_emoji_rooms', {'room_id': 'sim_cj'}, 'emoji_room_error'),
    'handle_join_crossword_room': ('active_crossword_rooms', {'room_id': 'sim_cj', 'puzzle_idx': 0}, 'crossword_room_error'),
}


class TestCoopSeatSteal:
    def test_third_joiner_rejected_all_coop(self):
        """FIXED (BUG-007): every coop/ttt join rejects a third socket and
        keeps seats; host + guest rejoins refresh cleanly."""
        import main as m
        h = _handlers()
        for join_name, (dict_name, payload, err_event) in COOP_JOINS.items():
            rooms = getattr(m, dict_name)
            rid = payload.get('room_id') or payload.get('room')
            rooms.pop(rid, None)
            try:
                _as_sid(m, 'sid_host', h[join_name], dict(payload),
                        user=_authed('u_host', 'Host'))
                _as_sid(m, 'sid_guest', h[join_name], dict(payload),
                        user=_authed('u_guest', 'Guest'))
                hijack = _as_sid(m, 'sid_hijacker', h[join_name], dict(payload),
                                 user=_authed('u_hij', 'Hijacker'))
                assert rooms[rid]['guest_sid'] == 'sid_guest', join_name
                assert rooms[rid]['host_sid'] == 'sid_host', join_name
                assert any(c[0][0] == err_event for c in hijack.call_args_list), join_name
                rejoin = _as_sid(m, 'sid_guest', h[join_name], dict(payload),
                                 user=_authed('u_guest', 'Guest'))
                assert rooms[rid]['guest_sid'] == 'sid_guest', join_name
                assert not any(c[0][0] == err_event for c in rejoin.call_args_list), join_name
            finally:
                rooms.pop(rid, None)


    def test_user_reclaim_on_fresh_transport(self):
        """G2: same seated user on a new sid reclaims the seat (sid
        refreshed); a different user on a new sid is rejected."""
        import main as m
        h = _handlers()
        rooms = m.active_duet_rooms
        rooms.pop('sim_reclaim', None)
        try:
            _as_sid(m, 'sid_host', h['handle_join_duet_room'], {'room_id': 'sim_reclaim'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_duet_room'], {'room_id': 'sim_reclaim'},
                    user=_authed('u_guest', 'Guest'))
            re = _as_sid(m, 'sid_guest_fresh', h['handle_join_duet_room'],
                         {'room_id': 'sim_reclaim'}, user=_authed('u_guest', 'Guest'))
            assert rooms['sim_reclaim']['guest_sid'] == 'sid_guest_fresh'
            joined = [c for c in re.call_args_list if c[0][0] == 'duet_room_joined']
            assert joined and joined[0][0][1]['is_host'] is False
            hijack = _as_sid(m, 'sid_hij', h['handle_join_duet_room'],
                             {'room_id': 'sim_reclaim'}, user=_authed('u_hij', 'Hijacker'))
            assert any(c[0][0] == 'duet_room_error' for c in hijack.call_args_list)
            assert rooms['sim_reclaim']['guest_sid'] == 'sid_guest_fresh'
        finally:
            rooms.pop('sim_reclaim', None)
    def test_malformed_int_fields_dropped(self):
        """FIXED (BUG-010/G4): non-numeric int fields are dropped silently,
        never raising out of the handler (duet + crossword + emoji)."""
        import main as m
        h = _handlers()
        rooms = m.active_duet_rooms
        rooms.pop('sim_duet_int', None)
        xrooms = m.active_crossword_rooms
        xrooms.pop('sim_xw_int', None)
        try:
            _as_sid(m, 'sid_host', h['handle_join_duet_room'], {'room_id': 'sim_duet_int'},
                    user=_authed('u_host', 'Host'))
            e1 = _as_sid(m, 'sid_host', h['handle_duet_give_clue'],
                         {'room_id': 'sim_duet_int', 'clue': 'LOVE', 'count': 'abc'})
            assert _emits_to(e1, 'duet_clue_given', room='sim_duet_int') == []
            e2 = _as_sid(m, 'sid_host', h['handle_duet_guess_card'],
                         {'room_id': 'sim_duet_int', 'card_idx': 'xyz'})
            assert _emits_to(e2, 'duet_card_guessed', room='sim_duet_int') == []
            e3 = _as_sid(m, 'sid_host', h['handle_duet_restart'],
                         {'room_id': 'sim_duet_int', 'seed': 'nope'})
            restarted = _emits_to(e3, 'duet_restarted', room='sim_duet_int')
            assert len(restarted) == 1
            assert isinstance(restarted[0][0][1]['seed'], int)
            _as_sid(m, 'sid_host', h['handle_join_crossword_room'],
                    {'room_id': 'sim_xw_int', 'puzzle_idx': 'zz'},
                    user=_authed('u_host', 'Host'))
            assert xrooms['sim_xw_int']['puzzle_idx'] == 0
            e4 = _as_sid(m, 'sid_host', h['handle_crossword_cell_update'],
                         {'room_id': 'sim_xw_int', 'r': 'a', 'c': 'b', 'char': 'Q'})
            assert _emits_to(e4, 'crossword_cell_update', room='sim_xw_int') == []
            e5 = _as_sid(m, 'sid_host', h['handle_emoji_start_round'],
                         {'room': 'sim_xw_int', 'round': 'zzz'})
            assert _emits_to(e5, 'emoji_round_started') != []
        finally:
            rooms.pop('sim_duet_int', None)
            xrooms.pop('sim_xw_int', None)

    def test_restart_requires_membership_no_ghost_broadcast(self):
        """FIXED (BUG-011): duet_restart drops non-members and unknown rooms;
        host rematch still rotates seed + giver."""
        import main as m
        h = _handlers()
        rooms = m.active_duet_rooms
        rooms.pop('sim_duet_rst', None)
        try:
            _as_sid(m, 'sid_host', h['handle_join_duet_room'], {'room_id': 'sim_duet_rst'},
                    user=_authed('u_host', 'Host'))
            old_seed = rooms['sim_duet_rst']['seed']
            stranger = _as_sid(m, 'sid_stranger', h['handle_duet_restart'],
                               {'room_id': 'sim_duet_rst', 'seed': 123})
            assert _emits_to(stranger, 'duet_restarted', room='sim_duet_rst') == []
            assert rooms['sim_duet_rst']['seed'] == old_seed
            ghost = _as_sid(m, 'sid_stranger', h['handle_duet_restart'],
                            {'room_id': 'ghost_room_xyz', 'seed': 1})
            assert _emits_to(ghost, 'duet_restarted', room='ghost_room_xyz') == []
            host = _as_sid(m, 'sid_host', h['handle_duet_restart'],
                           {'room_id': 'sim_duet_rst', 'seed': 123})
            assert rooms['sim_duet_rst']['seed'] == 123
            assert len(_emits_to(host, 'duet_restarted', room='sim_duet_rst')) == 1
        finally:
            rooms.pop('sim_duet_rst', None)


class TestEmojiBondScoreForgery:
    def test_non_member_forgery_dropped(self):
        """FIXED (BUG-012): no room membership -> no emit and no bond write,
        even for well-formed authed emits."""
        from bson import ObjectId
        import main as m
        h = _handlers()
        bond_id = str(ObjectId())
        with patch.object(m, 'bonds_conf') as mock_bonds:
            mock_emit = _as_sid(m, 'sid_attacker', h['handle_emoji_submit_guess'],
                                {'room_id': 'never_joined', 'correct': True,
                                 'points': 99999, 'attempts_left': 0, 'bond_id': bond_id},
                                user=_authed('u_attacker', 'Attacker'))
            assert _emits_to(mock_emit, 'emoji_guess_result', room='never_joined') == []
            assert mock_bonds.update_one.call_count == 0
            assert mock_bonds.find_one.call_count == 0

    def test_member_own_bond_credited_capped(self):
        """FIXED (BUG-012): seated member crediting their own bond works, but
        points clamp to the client formula max (100); others' bonds untouched."""
        from bson import ObjectId
        import main as m
        h = _handlers()
        rooms = m.active_emoji_rooms
        own_bond = str(ObjectId())
        other_bond = str(ObjectId())
        rooms.pop('sim_emoji_fix', None)
        try:
            _as_sid(m, 'sid_host', h['handle_emoji_join_room'], {'room_id': 'sim_emoji_fix'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_emoji_join_room'],
                    {'room_id': 'sim_emoji_fix'},
                    user=_authed('u_guest', 'Guest'))

            def fake_find_one(query):
                qid = query.get('_id')
                if qid == ObjectId(own_bond):
                    return {'_id': qid, 'user_a_id': 'u_host', 'user_b_id': 'u_guest'}
                return {'_id': qid, 'user_a_id': 'alice', 'user_b_id': 'bob'}

            with patch.object(m, 'bonds_conf') as mock_bonds:
                mock_bonds.find_one.side_effect = fake_find_one
                mock_emit = _as_sid(m, 'sid_guest', h['handle_emoji_submit_guess'],
                                    {'room_id': 'sim_emoji_fix', 'correct': True,
                                     'points': 99999, 'attempts_left': 0, 'bond_id': own_bond},
                                    user=_authed('u_guest', 'Guest'))
                assert len(_emits_to(mock_emit, 'emoji_guess_result', room='sim_emoji_fix')) == 1
                assert mock_bonds.update_one.call_count == 1
                args = mock_bonds.update_one.call_args[0]
                assert args[0] == {'_id': ObjectId(own_bond)}
                assert args[1] == {'$inc': {'stats.games_played': 1, 'stats.coop_score': 100}}
                mock_bonds.update_one.reset_mock()
                _as_sid(m, 'sid_guest', h['handle_emoji_submit_guess'],
                        {'room_id': 'sim_emoji_fix', 'correct': True,
                         'points': 50, 'attempts_left': 0, 'bond_id': other_bond},
                        user=_authed('u_guest', 'Guest'))
                assert mock_bonds.update_one.call_count == 0
        finally:
            rooms.pop('sim_emoji_fix', None)


class TestSudokuCoopPaths:
    def test_late_joiner_gets_shared_puzzle(self):
        """GOOD: first-share-wins puzzle is handed to late joiners directly."""
        import main as m
        saved = _save_rooms(m, 'active_sudoku_rooms')
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_sudoku_room'], {'room_id': 'sim_sudo'},
                    user=_authed('u_host', 'Host'))
            grid = [[1] * 9 for _ in range(9)]
            _as_sid(m, 'sid_host', h['handle_sudoku_puzzle_share'],
                    {'room_id': 'sim_sudo', 'puzzle': grid, 'solution': grid,
                     'difficulty': 'easy'})
            mock_emit = _as_sid(m, 'sid_guest', h['handle_join_sudoku_room'],
                                {'room_id': 'sim_sudo'}, user=_authed('u_guest', 'Guest'))
            puzzles = [c for c in mock_emit.call_args_list if c[0][0] == 'sudoku_puzzle']
            assert len(puzzles) == 1
        finally:
            _restore_rooms(m, saved)

    def test_stranger_cell_write_relayed(self):
        """OBSERVED: sudoku cells are bounds-checked but not membership-checked;
        any socket can write a partner's grid."""
        import main as m
        saved = _save_rooms(m, 'active_sudoku_rooms')
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_sudoku_room'], {'room_id': 'sim_sudo'},
                    user=_authed('u_host', 'Host'))
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_sudoku_cell_update'],
                                {'room_id': 'sim_sudo', 'r': 0, 'c': 0, 'v': 9})
            assert m.active_sudoku_rooms['sim_sudo']['grid'][0] == 9
            assert len(_emits_to(mock_emit, 'sudoku_cell_update', room='sim_sudo')) == 1
        finally:
            _restore_rooms(m, saved)


class TestChainRulesEnforced:
    def test_wrong_letter_repeat_and_turn_dropped(self):
        """GOOD: chain validates membership, turn, letter-link and repeats."""
        import main as m
        rooms = m.active_chain_rooms
        rooms.pop('sim_chain', None)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_chain_join_room'], {'room': 'sim_chain'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_chain_join_room'], {'room': 'sim_chain'},
                    user=_authed('u_guest', 'Guest'))
            starter = rooms['sim_chain']['chain'][0]
            last_letter = starter[-1]
            e1 = _as_sid(m, 'sid_host', h['handle_chain_submit_word'],
                         {'room': 'sim_chain', 'word': 'zzz'})
            assert [c for c in e1.call_args_list if c[0][0] == 'chain_error']
            assert len(rooms['sim_chain']['chain']) == 1
            w = last_letter * 3
            e2 = _as_sid(m, 'sid_host', h['handle_chain_submit_word'],
                         {'room': 'sim_chain', 'word': w})
            assert len(rooms['sim_chain']['chain']) == 2
            assert rooms['sim_chain']['turn'] == 2
            e3 = _as_sid(m, 'sid_guest', h['handle_chain_submit_word'],
                         {'room': 'sim_chain', 'word': w})
            assert [c for c in e3.call_args_list if c[0][0] == 'chain_error']
            assert len(rooms['sim_chain']['chain']) == 2
            e4 = _as_sid(m, 'sid_host', h['handle_chain_submit_word'],
                         {'room': 'sim_chain', 'word': last_letter * 4})
            assert [c for c in e4.call_args_list if c[0][0] == 'chain_error']
            assert len(rooms['sim_chain']['chain']) == 2
        finally:
            rooms.pop('sim_chain', None)
        import main as m
        saved = _save_rooms(m, *WHACK)
        try:
            h = _handlers()
            _as_sid(m, 'sid_host', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_host', 'Host'))
            _as_sid(m, 'sid_guest', h['handle_join_whack_room'], {'room_id': 'sim_wh'},
                    user=_authed('u_guest', 'Guest'))
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_host', h['handle_whack_finish'],
                        {'room_id': 'sim_wh', 'score': 42})
                assert mock_rec.call_count == 0
                last = _as_sid(m, 'sid_guest', h['handle_whack_finish'],
                               {'room_id': 'sim_wh', 'score': 42})
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] is None
                res = _emits_to(last, 'whack_result', room='sim_wh')
                assert res and res[0][0][1]['winner'] is None
        finally:
            _restore_rooms(m, saved)
