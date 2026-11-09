"""Tests for Real IP resolution (Cloudflare, Traefik, Docker) and Game Reconnection resilience."""

import datetime
from unittest.mock import MagicMock, patch
import pytest

from security import RealIPWSGIMiddleware, get_client_ip, is_valid_ip, is_valid_public_ip
import main as m


class TestRealIPResolution:
    """Verifies client IP extraction under various proxy topologies."""

    def test_cloudflare_connecting_ip_precedence(self):
        """CF-Connecting-IP takes highest precedence over Traefik internal/Docker IPs."""
        environ = {
            'HTTP_CF_CONNECTING_IP': '198.51.100.42',
            'HTTP_X_FORWARDED_FOR': '198.51.100.42, 172.70.10.5, 172.18.0.1',
            'HTTP_X_REAL_IP': '172.18.0.1',
            'REMOTE_ADDR': '172.18.0.2',
        }
        app = MagicMock(return_value=[b'ok'])
        mw = RealIPWSGIMiddleware(app)
        start_response = MagicMock()
        mw(environ, start_response)
        assert environ['REMOTE_ADDR'] == '198.51.100.42'

    def test_true_client_ip_fallback(self):
        """True-Client-IP is used if CF-Connecting-IP is absent."""
        environ = {
            'HTTP_TRUE_CLIENT_IP': '203.0.113.88',
            'HTTP_X_FORWARDED_FOR': '172.18.0.1',
            'REMOTE_ADDR': '172.18.0.2',
        }
        mw = RealIPWSGIMiddleware(MagicMock())
        mw(environ, MagicMock())
        assert environ['REMOTE_ADDR'] == '203.0.113.88'

    def test_x_forwarded_for_public_ip_extraction(self):
        """Extracts the public client IP from X-Forwarded-For chain when behind Traefik."""
        environ = {
            'HTTP_X_FORWARDED_FOR': '203.0.113.99, 172.18.0.1',
            'REMOTE_ADDR': '172.18.0.2',
        }
        mw = RealIPWSGIMiddleware(MagicMock())
        mw(environ, MagicMock())
        assert environ['REMOTE_ADDR'] == '203.0.113.99'

    def test_x_real_ip_when_public(self):
        """Uses X-Real-IP if it is a public IP address."""
        environ = {
            'HTTP_X_REAL_IP': '198.51.100.77',
            'REMOTE_ADDR': '10.0.0.5',
        }
        mw = RealIPWSGIMiddleware(MagicMock())
        mw(environ, MagicMock())
        assert environ['REMOTE_ADDR'] == '198.51.100.77'

    def test_direct_connection_preserves_remote_addr(self):
        """Direct connection without proxy headers preserves standard REMOTE_ADDR."""
        environ = {
            'REMOTE_ADDR': '127.0.0.1',
        }
        mw = RealIPWSGIMiddleware(MagicMock())
        mw(environ, MagicMock())
        assert environ['REMOTE_ADDR'] == '127.0.0.1'

    def test_get_client_ip_helper(self, app):
        """get_client_ip() correctly resolves with request context."""
        with app.test_request_context('/', headers={'CF-Connecting-IP': '198.51.100.123'}):
            assert get_client_ip() == '198.51.100.123'

        with app.test_request_context('/', headers={'X-Forwarded-For': '203.0.113.50, 10.0.0.1'}):
            assert get_client_ip() == '203.0.113.50'


class TestGameDisconnectAndReconnection:
    """Verifies game room preservation during momentary socket drops and client_token reclaim."""

    def _get_handlers(self):
        return {getattr(c.args[0], '__name__', ''): c.args[0]
                for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}

    def test_memory_match_disconnect_keeps_room_for_partner(self, app):
        """When one player disconnects from Memory Match, the room is KEPT alive."""
        handlers = self._get_handlers()
        h_disc = handlers.get('handle_dm_disconnect')
        assert h_disc is not None

        room_id = 'test_mem_disc_room'
        m.active_memory_rooms[room_id] = {
            'host_sid': 'host_123',
            'guest_sid': 'guest_456',
            'scores': {'1': 2, '2': 1},
            'turn': 1,
            'content': {'cards': ['a', 'a'], 'size': 2},
        }

        req = MagicMock()
        req.sid = 'guest_456'
        guest_user = MagicMock()
        guest_user.is_authenticated = False

        with patch.object(m, 'request', req), \
             patch.object(m, 'current_user', guest_user), \
             patch.object(m, 'emit') as mock_emit:
            h_disc()

        # Room MUST still be present in active_memory_rooms!
        assert room_id in m.active_memory_rooms
        assert m.active_memory_rooms[room_id]['guest_disconnected_at'] is not None

        # Partner-left notification emitted
        emitted = [c[0][0] for c in mock_emit.call_args_list]
        assert 'memory_partner_left' in emitted

        # Clean up
        m.active_memory_rooms.pop(room_id, None)

    def test_memory_match_last_player_disconnect_drops_room(self, app):
        """When the last remaining player disconnects, the room is dropped."""
        handlers = self._get_handlers()
        h_disc = handlers.get('handle_dm_disconnect')

        room_id = 'test_mem_drop_room'
        m.active_memory_rooms[room_id] = {
            'host_sid': 'host_123',
            'guest_sid': 'guest_456',
            'host_disconnected_at': 1000.0,  # Host already disconnected previously
            'scores': {'1': 0, '2': 0},
        }

        req = MagicMock()
        req.sid = 'guest_456'
        guest_user = MagicMock()
        guest_user.is_authenticated = False

        with patch.object(m, 'request', req), \
             patch.object(m, 'current_user', guest_user), \
             patch.object(m, 'emit'):
            h_disc()

        # Room dropped because both disconnected
        assert room_id not in m.active_memory_rooms

    def test_client_token_seat_reclaim(self, app):
        """An unauthenticated guest player reconnects with a new SID and reclaims their seat via client_token."""
        handlers = self._get_handlers()
        join_fn = handlers.get('handle_memory_join_room')
        assert join_fn is not None

        room_id = 'test_token_reclaim_room'
        m.active_memory_rooms[room_id] = {
            'host_sid': 'host_sid_1',
            'host_token': 'token_host_abc',
            'host_user_id': None,
            'host_name': 'HostGuest',
            'guest_sid': 'guest_sid_old',
            'guest_token': 'token_guest_xyz',
            'guest_user_id': None,
            'guest_name': 'GuestPlayer',
            'content': {'cards': ['a', 'a'], 'size': 2},
            'scores': {'1': 1, '2': 1},
            'turn': 2,
            'matched': set(),
        }

        req = MagicMock()
        req.sid = 'guest_sid_NEW_TRANSPORT'
        guest_user = MagicMock()
        guest_user.is_authenticated = False

        with patch.object(m, 'request', req), \
             patch.object(m, 'current_user', guest_user), \
             patch.object(m, 'emit') as mock_emit, \
             patch.object(m, 'join_room'):
            # Join with same client_token
            join_fn({'room': room_id, 'client_token': 'token_guest_xyz'})

        # Verified guest seat reclaimed with new SID
        room = m.active_memory_rooms[room_id]
        assert room['guest_sid'] == 'guest_sid_NEW_TRANSPORT'

        # Verified joined event carries rejoined=True
        joined_call = [c for c in mock_emit.call_args_list if c[0][0] == 'memory_room_joined']
        assert len(joined_call) == 1
        payload = joined_call[0][0][1]
        assert payload['rejoined'] is True
        assert payload['player_num'] == 2

        # Clean up
        m.active_memory_rooms.pop(room_id, None)

    def test_prune_unattended_rooms_does_not_prune_active_matches(self):
        """Active matches with recent activity (touched_at within 1 hour) are not pruned even if created earlier."""
        now = datetime.datetime.now(datetime.timezone.utc)
        two_hours_ago = now - datetime.timedelta(hours=2)

        room_id = 'test_active_long_match'
        m.active_memory_rooms[room_id] = {
            'host_sid': 'active_host_sid',
            'guest_sid': 'active_guest_sid',
            'created_at': two_hours_ago,
            'touched_at': now,
        }

        try:
            m._prune_unattended_game_rooms()
            # Active players are still connected, room must NOT be pruned!
            assert room_id in m.active_memory_rooms
        finally:
            m.active_memory_rooms.pop(room_id, None)

    def test_prune_unattended_rooms_drops_abandoned_rooms(self):
        """Rooms with both players disconnected for > 1 hour are pruned."""
        now = datetime.datetime.now(datetime.timezone.utc)
        two_hours_ago = now - datetime.timedelta(hours=2)

        room_id = 'test_abandoned_room'
        m.active_memory_rooms[room_id] = {
            'host_sid': 'sid_1',
            'guest_sid': 'sid_2',
            'host_disconnected_at': 100.0,
            'guest_disconnected_at': 100.0,
            'created_at': two_hours_ago,
            'touched_at': two_hours_ago,
        }

        try:
            m._prune_unattended_game_rooms()
            assert room_id not in m.active_memory_rooms
        finally:
            m.active_memory_rooms.pop(room_id, None)
