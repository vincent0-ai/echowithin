"""Netcode regression tests (Phase 5 verify step).

Guards the Commit 0-5 protocol contract:
- realtime relays must pass seq/ack/tSend fields through untouched
  (clients stale-drop and estimate RTT off these; stripping them
  reintroduces tunnel/phantom symptoms silently);
- Engine.IO heartbeat must stay tuned for long-haul links.

Client-side seq logic (stale-drop, single-authority) lives in JS and is
covered by live __pongNetstats/__slimeNetstats counters plus
scripts/latency_sim.py runs — see commit.md for before/after numbers.
"""

from unittest.mock import MagicMock, patch


def _handlers():
    import main as m
    handlers = {}
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]):
            fn = call.args[0]
            handlers[getattr(fn, '__name__', '')] = fn
    return handlers


def _seed_room(m, kind, room_id='r1', host_sid='sid_A', guest_sid='sid_B'):
    if kind == 'pong':
        m.active_pong_rooms[room_id] = {'host_sid': host_sid, 'guest_sid': guest_sid,
                                        'scores': [0, 0], 'target': None}
    else:
        m.active_slime_rooms[room_id] = {'host_sid': host_sid, 'guest_sid': guest_sid}
    return room_id


def _drop_room(m, kind, room_id='r1'):
    if kind == 'pong':
        m.active_pong_rooms.pop(room_id, None)
    else:
        m.active_slime_rooms.pop(room_id, None)


class TestNetcodeRelayProtocol:
    """Relay passthrough: server is a dumb pipe and must not strip fields."""

    def test_pong_ball_sync_preserves_seq_and_tsend(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_pong_ball_sync')
        assert fn is not None
        payload = {'room_id': 'r1', 'x': 100.12, 'y': 50.5, 'vx': 5.25,
                   'vy': 1.0, 'speed': 5.5, 'p1Y': 200.0, 'volleys': 3,
                   'seq': 4242, 'tSend': 12345.67}
        _seed_room(m, 'pong')
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn(dict(payload))
                    mock_emit.assert_called_with('pong_ball_sync', payload,
                                                 room='r1', include_self=False)
        finally:
            _drop_room(m, 'pong')

    def test_pong_paddle_sync_preserves_seq(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_pong_paddle_sync')
        assert fn is not None
        payload = {'room_id': 'r1', 'player': 1, 'y': 210.44,
                   'seq': 4243, 'tSend': 12346.0}
        _seed_room(m, 'pong')
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_B'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn(dict(payload))
                    mock_emit.assert_called_with('pong_paddle_sync', payload,
                                                 room='r1', include_self=False)
        finally:
            _drop_room(m, 'pong')

    def test_slime_host_sync_preserves_seq_and_ack(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_slime_host_sync')
        assert fn is not None
        payload = {'room_id': 'r1',
                   'ball': {'x': 1.23, 'y': 4.56, 'vx': 2.1, 'vy': 3.3},
                   'p1': {'x': -1.0, 'y': 1.5, 'vx': 0.0, 'vy': 0.0},
                   'scores': [2, 1], 'serveState': 'PLAYING',
                   'seq': 991, 'tSend': 999.0, 'ack': 988}
        _seed_room(m, 'slime')
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn(dict(payload))
                    mock_emit.assert_called_with('slime_host_sync', payload,
                                                 room='r1', include_self=False)
        finally:
            _drop_room(m, 'slime')

    def test_slime_player_input_preserves_seq(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_slime_player_input')
        assert fn is not None
        payload = {'room_id': 'r1',
                   'p2': {'x': 1.0, 'y': 1.5, 'vx': 0.5, 'vy': 0.0,
                          'desiredVx': 2.22},
                   'seq': 992, 'tSend': 1000.0}
        _seed_room(m, 'slime')
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_B'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn(dict(payload))
                    mock_emit.assert_called_with('slime_player_input', payload,
                                                 room='r1', include_self=False)
        finally:
            _drop_room(m, 'slime')

    def test_engineio_heartbeat_tuned_for_long_haul(self):
        import flask_socketio
        calls = flask_socketio.SocketIO.mock_calls
        assert calls, 'expected SocketIO constructor calls to be recorded'
        assert any('ping_timeout' in str(c) and '120' in str(c) for c in calls), \
            'SocketIO must be constructed with ping_timeout=120, got: %r' % (calls,)
        assert any('ping_interval' in str(c) and '25' in str(c) for c in calls), \
            'SocketIO must be constructed with ping_interval=25'

    def test_engineio_max_decode_packets_expanded(self):
        import engineio.payload
        assert engineio.payload.Payload.max_decode_packets >= 500, \
            f"Expected max_decode_packets >= 500, got {engineio.payload.Payload.max_decode_packets}"

    def test_c4_move_accepts_reconnected_authenticated_user(self, app):
        import main as m
        from bson import ObjectId
        user_a_id = str(ObjectId())
        user_b_id = str(ObjectId())
        room_id = 'test_c4_reconnect'
        m.active_c4_rooms[room_id] = {
            'host_sid': 'old_host_sid',
            'host_name': 'HostUser',
            'host_user_id': user_a_id,
            'guest_sid': 'guest_sid',
            'guest_name': 'GuestUser',
            'guest_user_id': user_b_id,
            'board': [[-1] * m.C4_COLS for _ in range(m.C4_ROWS)],
            'turn': 0,
            'scores': [0, 0, 0]
        }
        handlers = {call.args[0].__name__: call.args[0] for call in m.socketio.on.mock_calls if call.args and callable(call.args[0])}
        move_fn = handlers.get('handle_c4_move', m.handle_c4_move)
        try:
            with app.test_request_context():
                user_obj = MagicMock()
                user_obj.is_authenticated = True
                user_obj.id = user_a_id
                req = MagicMock()
                req.sid = 'new_reconnected_sid'
                with patch.object(m, 'current_user', user_obj), \
                     patch.object(m, 'request', req), \
                     patch.object(m, 'join_room') as mock_join, \
                     patch.object(m, 'emit') as mock_emit:
                    move_fn({'room_id': room_id, 'col': 3})
                    # Host sid should have been updated to the new connected sid
                    assert m.active_c4_rooms[room_id]['host_sid'] == 'new_reconnected_sid'
                    mock_join.assert_called_with(room_id)
                    assert mock_emit.called
                    call_args = mock_emit.call_args
                    assert call_args[0][0] == 'c4_move_made'
                    assert call_args[0][1]['col'] == 3
        finally:
            m.active_c4_rooms.pop(room_id, None)

    def test_decrypted_media_cache_hit(self):
        import main as m
        test_key = 'test_public_id_sample'
        m._decrypted_media_cache[test_key] = (b'cached_image_bytes', 'image/jpeg')
        assert test_key in m._decrypted_media_cache
        data, mime = m._decrypted_media_cache[test_key]
        assert data == b'cached_image_bytes'
        assert mime == 'image/jpeg'
        m._decrypted_media_cache.pop(test_key, None)

    def test_bond_calendar_cache_and_invalidation(self):
        from blueprints.bonds import _bond_calendar_cache, _invalidate_bond_calendar_cache
        test_bond_id = 'test_bond_cal_123'
        cache_key = f"{test_bond_id}:user1:2026-10-01:2026-11-15"
        _bond_calendar_cache[cache_key] = {'events': [], 'today': '2026-10-27'}
        assert cache_key in _bond_calendar_cache
        _invalidate_bond_calendar_cache(test_bond_id)
        assert cache_key not in _bond_calendar_cache

    def test_send_push_async_delegation(self):
        from blueprints.bonds import _send_push_async
        mock_m = MagicMock()
        mock_fn = MagicMock()
        mock_fn.queue = MagicMock()
        mock_m.send_push_notification_to_user = mock_fn

        _send_push_async(mock_m, 'u123', 'Title', 'Body', tag='test-tag')
        assert mock_fn.queue.called
        assert not mock_fn.called


class _FakeHistory:
    """Minimal in-memory stand-in for the game_match_history collection."""

    def __init__(self):
        self.docs = []
        self.insert_calls = 0

    def find_one(self, query, *args, **kwargs):
        for doc in self.docs:
            if all(doc.get(k) == v for k, v in query.items()):
                return doc
        return None

    def insert_one(self, doc):
        key = doc.get('match_key')
        if key and any(d.get('match_key') == key for d in self.docs):
            raise Exception('duplicate match_key')
        self.insert_calls += 1
        self.docs.append(doc)
        return MagicMock(inserted_id=len(self.docs))


class _FakeStats:
    def find_one(self, *args, **kwargs):
        return None

    def update_one(self, *args, **kwargs):
        return None


class _EmptyCollection:
    def find_one(self, *args, **kwargs):
        return None

    def insert_one(self, doc):
        return MagicMock()


def _players(uid_a='u1', uid_b='u2'):
    return [
        {'user_id': uid_a, 'username': 'A', 'side': 'host'},
        {'user_id': uid_b, 'username': 'B', 'side': 'guest'},
    ]


def _slime_room(m, room_id, match_no=0):
    m.active_slime_rooms[room_id] = {
        'host_sid': 'sid_A', 'guest_sid': 'sid_B',
        'host_user_id': 'u1', 'guest_user_id': 'u2',
        'host_name': 'A', 'guest_name': 'B',
        'match_no': match_no, 'scores': [0, 0],
    }


def _pong_room(m, room_id, match_no=0):
    m.active_pong_rooms[room_id] = {
        'host_sid': 'sid_A', 'guest_sid': 'sid_B',
        'host_user_id': 'u1', 'guest_user_id': 'u2',
        'host_name': 'A', 'guest_name': 'B',
        'scores': [5, 2], 'target': 5, 'match_no': match_no,
    }


class TestAwardIdempotency:
    """A match result may only be written once per (room, match_no)."""

    def test_record_match_result_is_idempotent_by_match_key(self):
        import main as m
        hist = _FakeHistory()
        with patch.object(m, 'game_match_history_conf', hist), \
                patch.object(m, 'player_stats_conf', _FakeStats()), \
                patch.object(m, 'bonds_conf', _EmptyCollection()):
            first = m.record_match_result(
                'slime_volleyball', 'r1', _players(), 'u1',
                score={'host': 5, 'guest': 2},
                match_key='slime_volleyball:r1:0', match_no=0)
            second = m.record_match_result(
                'slime_volleyball', 'r1', _players(), 'u1',
                score={'host': 5, 'guest': 2},
                match_key='slime_volleyball:r1:0', match_no=0)

            assert hist.insert_calls == 1, 'duplicate award for the same match_key'
            assert second is first, 'repeat must return the original document'

            third = m.record_match_result(
                'slime_volleyball', 'r1', _players(), 'u2',
                score={'host': 2, 'guest': 5},
                match_key='slime_volleyball:r1:1', match_no=1)

            assert hist.insert_calls == 2, 'a rematch is a new, separate award'
            assert third is not None and third['match_no'] == 1

    def test_slime_match_end_awards_once_per_generation(self, app):
        import main as m
        fn = _handlers()['handle_slime_match_end']
        room_id = 'slime_award_once'
        _slime_room(m, room_id, match_no=0)
        payload = {'room_id': room_id, 'winner': 'host', 'score': [5, 3], 'match_no': 0}
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit'), \
                        patch.object(m, 'record_match_result') as rec:
                    fn(dict(payload))
                    fn(dict(payload))
                    fn(dict(payload))
            assert rec.call_count == 1, 'match-end must be idempotent per match_no'
            assert rec.call_args.kwargs['match_key'] == f'slime_volleyball:{room_id}:0'
        finally:
            m.active_slime_rooms.pop(room_id, None)

    def test_slime_match_end_rejects_stale_generation(self, app):
        import main as m
        fn = _handlers()['handle_slime_match_end']
        room_id = 'slime_stale_gen'
        _slime_room(m, room_id, match_no=2)
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit'), \
                        patch.object(m, 'record_match_result') as rec:
                    # Late report from match 1 after the room moved to match 2.
                    fn({'room_id': room_id, 'winner': 'host',
                        'score': [5, 1], 'match_no': 1})
            assert rec.call_count == 0, 'stale generation must not award'
        finally:
            m.active_slime_rooms.pop(room_id, None)

    def test_slime_match_end_rejects_unreached_score(self, app):
        import main as m
        fn = _handlers()['handle_slime_match_end']
        room_id = 'slime_bad_score'
        _slime_room(m, room_id, match_no=0)
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit'), \
                        patch.object(m, 'record_match_result') as rec:
                    fn({'room_id': room_id, 'winner': 'host',
                        'score': [2, 4], 'match_no': 0})
            assert rec.call_count == 0, 'a winner claim below the win score must be rejected'
        finally:
            m.active_slime_rooms.pop(room_id, None)

    def test_slime_restart_assigns_next_generation(self, app):
        import main as m
        fn = _handlers()['handle_slime_restart']
        room_id = 'slime_restart_gen'
        _slime_room(m, room_id, match_no=0)
        m.active_slime_rooms[room_id]['scores'] = [5, 4]
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_B'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn({'room_id': room_id})
            info = m.active_slime_rooms[room_id]
            assert info['match_no'] == 1
            assert info['scores'] == [0, 0]
            event, payload = mock_emit.call_args.args[0], mock_emit.call_args.args[1]
            assert event == 'slime_restart'
            assert payload['match_no'] == 1
            assert mock_emit.call_args.kwargs.get('room') == room_id
        finally:
            m.active_slime_rooms.pop(room_id, None)

    def test_pong_score_update_awards_once_per_generation(self, app):
        import main as m
        fn = _handlers()['handle_pong_score_update']
        room_id = 'pong_award_once'
        _pong_room(m, room_id, match_no=0)
        payload = {'room_id': room_id, 'scores': [5, 2], 'winner': 1, 'match_no': 0}
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit'), \
                        patch.object(m, 'record_match_result') as rec:
                    fn(dict(payload))
                    fn(dict(payload))
            assert rec.call_count == 1
            assert rec.call_args.kwargs['match_key'] == f'ping_pong:{room_id}:0'
        finally:
            m.active_pong_rooms.pop(room_id, None)

    def test_pong_score_update_rejects_stale_generation(self, app):
        import main as m
        fn = _handlers()['handle_pong_score_update']
        room_id = 'pong_stale'
        _pong_room(m, room_id, match_no=1)
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit'), \
                        patch.object(m, 'record_match_result') as rec:
                    fn({'room_id': room_id, 'scores': [5, 2],
                        'winner': 1, 'match_no': 0})
            assert rec.call_count == 0
        finally:
            m.active_pong_rooms.pop(room_id, None)

    def test_pong_restart_assigns_next_generation(self, app):
        import main as m
        fn = _handlers()['handle_pong_restart']
        room_id = 'pong_restart_gen'
        _pong_room(m, room_id, match_no=0)
        try:
            with app.test_request_context():
                req = MagicMock()
                req.sid = 'sid_A'
                with patch.object(m, 'request', req), \
                        patch.object(m, 'emit') as mock_emit:
                    fn({'room_id': room_id})
            info = m.active_pong_rooms[room_id]
            assert info['match_no'] == 1
            assert info['scores'] == [0, 0]
            assert mock_emit.call_args.args[1]['match_no'] == 1
        finally:
            m.active_pong_rooms.pop(room_id, None)

    def test_net_ping_echoes_timestamp_to_caller(self, app):
        import main as m
        fn = _handlers()['handle_net_ping']
        with app.test_request_context():
            req = MagicMock()
            req.sid = 'sid_X'
            with patch.object(m, 'request', req), \
                    patch.object(m, 'emit') as mock_emit:
                fn({'t': 1234.5})
        mock_emit.assert_called_once_with('net_pong', {'t': 1234.5}, room='sid_X')

