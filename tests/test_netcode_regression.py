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

from unittest.mock import patch


def _handlers():
    import main as m
    handlers = {}
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]):
            fn = call.args[0]
            handlers[getattr(fn, '__name__', '')] = fn
    return handlers


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
        with app.test_request_context():
            with patch.object(m, 'emit') as mock_emit:
                fn(dict(payload))
                mock_emit.assert_called_with('pong_ball_sync', payload,
                                             room='r1', include_self=False)

    def test_pong_paddle_sync_preserves_seq(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_pong_paddle_sync')
        assert fn is not None
        payload = {'room_id': 'r1', 'player': 1, 'y': 210.44,
                   'seq': 4243, 'tSend': 12346.0}
        with app.test_request_context():
            with patch.object(m, 'emit') as mock_emit:
                fn(dict(payload))
                mock_emit.assert_called_with('pong_paddle_sync', payload,
                                             room='r1', include_self=False)

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
        with app.test_request_context():
            with patch.object(m, 'emit') as mock_emit:
                fn(dict(payload))
                mock_emit.assert_called_with('slime_host_sync', payload,
                                             room='r1', include_self=False)

    def test_slime_player_input_preserves_seq(self, app):
        import main as m
        handlers = _handlers()
        fn = handlers.get('handle_slime_player_input')
        assert fn is not None
        payload = {'room_id': 'r1',
                   'p2': {'x': 1.0, 'y': 1.5, 'vx': 0.5, 'vy': 0.0,
                          'desiredVx': 2.22},
                   'seq': 992, 'tSend': 1000.0}
        with app.test_request_context():
            with patch.object(m, 'emit') as mock_emit:
                fn(dict(payload))
                mock_emit.assert_called_with('slime_player_input', payload,
                                             room='r1', include_self=False)

    def test_engineio_heartbeat_tuned_for_long_haul(self):
        import flask_socketio
        calls = flask_socketio.SocketIO.mock_calls
        assert calls, 'expected SocketIO constructor calls to be recorded'
        assert any('ping_timeout' in str(c) and '120' in str(c) for c in calls), \
            'SocketIO must be constructed with ping_timeout=120, got: %r' % (calls,)
        assert any('ping_interval' in str(c) and '25' in str(c) for c in calls), \
            'SocketIO must be constructed with ping_interval=25'
