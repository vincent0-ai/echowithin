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

    def test_guest_score_claim_relayed_no_side_check(self):
        """OBSERVED: either side's score claim is accepted + relayed + stored."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            with patch.object(m, 'record_match_result'):
                mock_emit = _as_sid(m, 'sid_guest', h['handle_pong_score_update'],
                                    {'room_id': rid, 'scores': [0, 3]})
            relayed = _emits_to(mock_emit, 'pong_score_update', room=rid)
            assert len(relayed) == 1
            assert relayed[0][0][1]['scores'] == [0, 3]
            assert m.active_pong_rooms[rid]['scores'] == [0, 3]
        finally:
            _restore_rooms(m, saved)

    def test_stranger_off_room_relays_into_match(self):
        """OBSERVED: sender need not be a room member; any socket knowing the
        room_id can inject score relays into a live match."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            with patch.object(m, 'record_match_result'):
                mock_emit = _as_sid(m, 'sid_stranger', h['handle_pong_score_update'],
                                    {'room_id': rid, 'scores': [9, 9]})
            assert len(_emits_to(mock_emit, 'pong_score_update', room=rid)) == 1
            assert m.active_pong_rooms[rid]['scores'] == [9, 9]
        finally:
            _restore_rooms(m, saved)

    def test_guest_restart_zeroes_live_match(self):
        """OBSERVED: pong_restart has no host gate; guest resets scores."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m)
            m.active_pong_rooms[rid]['scores'] = [4, 2]
            mock_emit = _as_sid(m, 'sid_guest', h['handle_pong_restart'],
                                {'room_id': rid})
            assert m.active_pong_rooms[rid]['scores'] == [0, 0]
            assert len(_emits_to(mock_emit, 'pong_restart', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)

    def test_self_consistent_scoreline_records_ranked_win_for_either_side(self):
        """OBSERVED: a self-consistent scoreline + winner from EITHER side is
        recorded as a ranked match (ELO effect)."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m, target=5)
            with patch.object(m, 'record_match_result') as mock_rec:
                _as_sid(m, 'sid_guest', h['handle_pong_score_update'],
                        {'room_id': rid, 'scores': [0, 5], 'winner': 2})
                assert mock_rec.call_count == 1
                assert mock_rec.call_args[1]['winner_id'] == 'u_guest'
        finally:
            _restore_rooms(m, saved)

    def test_repeated_winner_emits_record_repeated_matches(self):
        """OBSERVED: every relayed winner inserts another match doc (no
        idempotency on room_id) -> ELO farming via re-emit."""
        import main as m
        saved = _save_rooms(m, *PONG_ROOMS)
        try:
            h = _handlers()
            rid = _pong_room(h, m, target=5)
            with patch.object(m, 'record_match_result') as mock_rec:
                for _ in range(3):
                    _as_sid(m, 'sid_host', h['handle_pong_score_update'],
                            {'room_id': rid, 'scores': [5, 0], 'winner': 1})
                assert mock_rec.call_count == 3
        finally:
            _restore_rooms(m, saved)


def _slime_room(h, m, room_id='sim_slime'):
    _as_sid(m, 'sid_host', h['handle_join_slime_room'],
            {'room_id': room_id}, user=_authed('u_host', 'Host'))
    _as_sid(m, 'sid_guest', h['handle_join_slime_room'],
            {'room_id': room_id}, user=_authed('u_guest', 'Guest'))
    return room_id


class TestSlimeTwoClientSim:
    def test_host_sync_relayed_without_membership_or_side_check(self):
        """OBSERVED: slime_host_sync is a pure relay; anyone (even a
        non-member) can inject authoritative-looking state, forged scores
        included."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            payload = {'room_id': rid, 'ball': {'x': 999, 'y': 999},
                       'scores': [7, 0], 'serveState': 'PLAYING',
                       'seq': 1, 'tSend': 1.0}
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_slime_host_sync'],
                                dict(payload))
            relayed = _emits_to(mock_emit, 'slime_host_sync', room=rid)
            assert len(relayed) == 1
            assert relayed[0][0][1]['scores'] == [7, 0]
            assert relayed[0][1].get('include_self') is False
        finally:
            _restore_rooms(m, saved)

    def test_restart_by_non_member_resets_serving(self):
        """OBSERVED: slime_restart has no host/member gate."""
        import main as m
        saved = _save_rooms(m, *SLIME_ROOMS)
        try:
            h = _handlers()
            rid = _slime_room(h, m)
            before = m.active_slime_rooms[rid].get('serving')
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_slime_restart'],
                                {'room_id': rid})
            assert len(_emits_to(mock_emit, 'slime_restart', room=rid)) == 1
            assert m.active_slime_rooms[rid].get('serving') in (-1, 1)
            assert before is not None
        finally:
            _restore_rooms(m, saved)

    def test_match_end_guest_report_dropped(self):
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

    def test_restart_by_guest_zeroes_live_match(self):
        """OBSERVED: air_restart has no sid gate; guest zeroes scores."""
        import main as m
        saved = _save_rooms(m, *AIR_ROOMS)
        try:
            h = _handlers()
            rid = _air_room(h, m)
            m.active_air_rooms[rid]['scores'] = [6, 5]
            mock_emit = _as_sid(m, 'sid_guest', h['handle_air_restart'],
                                {'room_id': rid})
            assert m.active_air_rooms[rid]['scores'] == [0, 0]
            assert len(_emits_to(mock_emit, 'air_restarted', room=rid)) == 1
        finally:
            _restore_rooms(m, saved)

    def test_tied_forged_scoreline_awards_guest(self):
        """OBSERVED: [7,7] at target 7 emits air_result winner=1 (guest);
        ties resolve to guest, not draw/void."""
        import main as m
        saved = _save_rooms(m, *AIR_ROOMS)
        try:
            h = _handlers()
            rid = _air_room(h, m)
            with patch.object(m, 'record_match_result'):
                mock_emit = _as_sid(m, 'sid_host', h['handle_air_score'],
                                    {'room_id': rid, 'scores': [7, 7]})
            results = _emits_to(mock_emit, 'air_result', room=rid)
            assert len(results) == 1
            assert results[0][0][1]['winner'] == 1
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
    def test_third_joiner_steals_guest_seat(self):
        import main as m
        saved = _save_rooms(m, *TTT)
        try:
            h = _handlers()
            rid = _ttt_room(h, m)
            mock_emit = _as_sid(m, 'sid_hijacker', h['handle_join_ttt_room'],
                                {'room_id': rid}, user=_authed('u_hij', 'Hijacker'))
            assert m.active_ttt_rooms[rid]['guest_sid'] == 'sid_hijacker'
            joined = [c for c in mock_emit.call_args_list if c[0][0] == 'ttt_room_joined']
            assert joined and joined[0][0][1]['symbol'] == 'o'
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
    def test_stranger_restarts_wipe_live_boards(self):
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
                mock_emit = _as_sid(m, 'sid_stranger', h[restart_name], {'room_id': rid})
                assert len(_emits_to(mock_emit, event, room=rid)) == 1, dict_name
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
                    {'room_id': 'sim_wh', 'score': 99999999})
            assert m.active_whack_rooms['sim_wh']['scores'][0] == 10000
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
    'handle_join_ttt_room': ('active_ttt_rooms', {'room_id': 'sim_cj'}),
    'handle_memory_join_room': ('active_memory_rooms', {'room': 'sim_cj'}),
    'handle_join_sudoku_room': ('active_sudoku_rooms', {'room_id': 'sim_cj'}),
    'handle_tot_join_room': ('active_tot_rooms', {'room': 'sim_cj'}),
    'handle_join_duet_room': ('active_duet_rooms', {'room_id': 'sim_cj'}),
    'handle_chain_join_room': ('active_chain_rooms', {'room': 'sim_cj'}),
    'handle_emoji_join_room': ('active_emoji_rooms', {'room_id': 'sim_cj'}),
    'handle_join_crossword_room': ('active_crossword_rooms', {'room_id': 'sim_cj', 'puzzle_idx': 0}),
}


class TestCoopSeatSteal:
    def test_third_joiner_steals_guest_seat_all_coop(self):
        """OBSERVED: none of the coop/ttt joins reject a third socket; the
        guest seat is silently overwritten mid-session (only pong/slime/air/
        c4/gomoku/whack/dnb guard)."""
        import main as m
        h = _handlers()
        for join_name, (dict_name, payload) in COOP_JOINS.items():
            rooms = getattr(m, dict_name)
            rid = payload.get('room_id') or payload.get('room')
            rooms.pop(rid, None)
            try:
                _as_sid(m, 'sid_host', h[join_name], dict(payload),
                        user=_authed('u_host', 'Host'))
                _as_sid(m, 'sid_guest', h[join_name], dict(payload),
                        user=_authed('u_guest', 'Guest'))
                _as_sid(m, 'sid_hijacker', h[join_name], dict(payload),
                        user=_authed('u_hij', 'Hijacker'))
                assert rooms[rid]['guest_sid'] == 'sid_hijacker', join_name
            finally:
                rooms.pop(rid, None)


class TestDuetRelayRobustness:
    def test_non_numeric_int_fields_raise(self):
        """OBSERVED: duet clue/guess/restart int() casts are unguarded; a
        non-numeric count/card_idx/seed raises ValueError out of the handler."""
        import pytest
        import main as m
        h = _handlers()
        rooms = m.active_duet_rooms
        rooms.pop('sim_duet_int', None)
        try:
            _as_sid(m, 'sid_host', h['handle_join_duet_room'], {'room_id': 'sim_duet_int'},
                    user=_authed('u_host', 'Host'))
            with pytest.raises(ValueError):
                _as_sid(m, 'sid_host', h['handle_duet_give_clue'],
                        {'room_id': 'sim_duet_int', 'clue': 'LOVE', 'count': 'abc'})
            with pytest.raises(ValueError):
                _as_sid(m, 'sid_host', h['handle_duet_guess_card'],
                        {'room_id': 'sim_duet_int', 'card_idx': 'xyz'})
            with pytest.raises(ValueError):
                _as_sid(m, 'sid_host', h['handle_duet_restart'],
                        {'room_id': 'sim_duet_int', 'seed': 'nope'})
        finally:
            rooms.pop('sim_duet_int', None)

    def test_restart_from_non_room_resets_seed_and_broadcasts(self):
        """OBSERVED: duet_restart needs neither membership nor existence; any
        socket resets any room's seed, and emits into arbitrary room names."""
        import main as m
        h = _handlers()
        rooms = m.active_duet_rooms
        rooms.pop('sim_duet_rst', None)
        try:
            _as_sid(m, 'sid_host', h['handle_join_duet_room'], {'room_id': 'sim_duet_rst'},
                    user=_authed('u_host', 'Host'))
            old_seed = rooms['sim_duet_rst']['seed']
            mock_emit = _as_sid(m, 'sid_stranger', h['handle_duet_restart'],
                                {'room_id': 'sim_duet_rst', 'seed': 123})
            assert rooms['sim_duet_rst']['seed'] == 123
            assert rooms['sim_duet_rst']['seed'] != old_seed or old_seed == 123
            assert len(_emits_to(mock_emit, 'duet_restarted', room='sim_duet_rst')) == 1
            ghost = _as_sid(m, 'sid_stranger', h['handle_duet_restart'],
                            {'room_id': 'ghost_room_xyz', 'seed': 1})
            assert len(_emits_to(ghost, 'duet_restarted', room='ghost_room_xyz')) == 1
        finally:
            rooms.pop('sim_duet_rst', None)


class TestEmojiBondScoreForgery:
    def test_any_authed_socket_credits_any_bond(self):
        """OBSERVED: emoji_submit_guess writes arbitrary points to an
        arbitrary bond's coop_score with no room-membership check."""
        from bson import ObjectId
        import main as m
        h = _handlers()
        bond_id = str(ObjectId())
        before = m.bonds_conf.update_one.call_count
        mock_emit = _as_sid(m, 'sid_attacker', h['handle_emoji_submit_guess'],
                            {'room_id': 'never_joined', 'correct': True,
                             'points': 99999, 'attempts_left': 0, 'bond_id': bond_id},
                            user=_authed('u_attacker', 'Attacker'))
        assert len(_emits_to(mock_emit, 'emoji_guess_result', room='never_joined')) == 1
        assert m.bonds_conf.update_one.call_count == before + 1
        args = m.bonds_conf.update_one.call_args[0]
        assert args[0] == {'_id': ObjectId(bond_id)}
        assert args[1] == {'$inc': {'stats.games_played': 1, 'stats.coop_score': 99999}}


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
