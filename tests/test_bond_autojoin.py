"""Bond auto-join: reuse an open waiting room instead of spawning duplicates."""

import datetime
from types import SimpleNamespace

from blueprints.bonds import _find_open_bond_room, BOND_OPEN_ROOM_TTL_S


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _room(host_uid, bond_id, age_s=60, guest=None):
    return {
        'host_sid': 'sid-host',
        'host_user_id': host_uid,
        'guest_sid': guest,
        'guest_name': None,
        'bond_id': bond_id,
        'created_at': _now() - datetime.timedelta(seconds=age_s),
    }


class TestFindOpenBondRoom:
    def test_prefers_partners_waiting_room(self):
        m = SimpleNamespace(active_pong_rooms={
            'bond_ping_mine': _room('me', 'b1'),
            'bond_ping_theirs': _room('partner', 'b1'),
        })
        room_id, waiter_is_partner = _find_open_bond_room(
            m, 'ping_pong', 'b1', 'me', 'partner', _now())
        assert room_id == 'bond_ping_theirs'
        assert waiter_is_partner is True

    def test_reuses_own_room_when_partner_has_none(self):
        m = SimpleNamespace(active_pong_rooms={
            'bond_ping_mine': _room('me', 'b1'),
        })
        room_id, waiter_is_partner = _find_open_bond_room(
            m, 'ping_pong', 'b1', 'me', 'partner', _now())
        assert room_id == 'bond_ping_mine'
        assert waiter_is_partner is False

    def test_skips_full_rooms(self):
        m = SimpleNamespace(active_pong_rooms={
            'bond_ping_full': _room('partner', 'b1', guest='sid-guest'),
        })
        room_id, _ = _find_open_bond_room(m, 'ping_pong', 'b1', 'me', 'partner', _now())
        assert room_id is None

    def test_skips_stale_rooms(self):
        m = SimpleNamespace(active_pong_rooms={
            'bond_ping_old': _room('partner', 'b1', age_s=BOND_OPEN_ROOM_TTL_S + 60),
        })
        room_id, _ = _find_open_bond_room(m, 'ping_pong', 'b1', 'me', 'partner', _now())
        assert room_id is None

    def test_skips_other_bonds_and_games(self):
        m = SimpleNamespace(
            active_pong_rooms={'bond_ping_other': _room('partner', 'b2')},
            active_slime_rooms={'bond_slim_x': _room('partner', 'b1')},
        )
        room_id, _ = _find_open_bond_room(m, 'ping_pong', 'b1', 'me', 'partner', _now())
        assert room_id is None

    def test_unknown_game_returns_none(self):
        m = SimpleNamespace()
        room_id, waiter = _find_open_bond_room(m, 'nope', 'b1', 'me', 'partner', _now())
        assert room_id is None
        assert waiter is False
