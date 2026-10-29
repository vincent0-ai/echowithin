"""Wire-budget estimate for the realtime game protocols.

Builds the exact payload objects the clients emit (same fields, same rounding)
and reports JSON size and bytes/second at the configured send rates.

This is a *derived* budget, not a captured pcap: it answers "how much does the
protocol cost per second" without a live server. For end-to-end latency
measurement use scripts/latency_sim.py against a local instance.

Usage:
    python scripts/netcode_budget.py
"""

import json

# Send rates from the clients.
# - slime_volleyball.js: rAF-gated 55 ms loop (18 Hz)
# - ping_pong.js: ball sync every ~30 ms (30 Hz), paddle sync ~20 Hz
SLIME_RATE_HZ = 1000 / 55
PONG_BALL_RATE_HZ = 1000 / 33
PONG_PADDLE_RATE_HZ = 20


def b(obj):
    return len(json.dumps(obj, separators=(',', ':')).encode('utf-8'))


SLIME_HOST_SYNC = {
    'room_id': 'duel_1a2b3c4d',
    'ball': {'x': -12.34, 'y': 15.67, 'vx': 4.5, 'vy': -3.21},
    'p1': {'x': -12.34, 'y': 11.0, 'vx': 0, 'vy': 0},
    'p2': {'x': 12.34, 'y': 11.0, 'vx': 0, 'vy': 0},
    'scores': [3, 4],
    'serveState': 'PLAYING',
    'serving': -1,
    'delay': 0,
    'rallyCount': 7,
    'match_no': 2,
    'seq': 123456,
    'tSend': 98765.43,
    'ack': 123450,
}

SLIME_INPUT = {
    'room_id': 'duel_1a2b3c4d',
    'p2': {'x': 12.34, 'y': 11.0, 'vx': 4.5, 'vy': 0,
           'desiredVx': 0.8, 'jump': False},
    'seq': 123456,
    'tSend': 98765.43,
}

PONG_BALL_SYNC = {
    'room_id': 'pong_1a2b3c4d',
    'x': 412.34, 'y': 210.11,
    'vx': 6.2, 'vy': -3.4, 'speed': 7.1,
    'p1Y': 210.0, 'volleys': 9,
    'seq': 987654, 'tSend': 98765.43,
}

PONG_PADDLE_SYNC = {
    'room_id': 'pong_1a2b3c4d',
    'player': 1, 'y': 210.44,
    'seq': 987654, 'tSend': 98765.43,
}

PONG_SCORE = {
    'room_id': 'pong_1a2b3c4d',
    'scores': [5, 3], 'winner': 1, 'match_no': 0,
}


def main():
    rows = [
        ('slime host_sync (host -> server -> guest)', b(SLIME_HOST_SYNC), SLIME_RATE_HZ),
        ('slime player_input (guest -> server -> host)', b(SLIME_INPUT), SLIME_RATE_HZ),
        ('pong ball_sync (host -> server -> guest)', b(PONG_BALL_SYNC), PONG_BALL_RATE_HZ),
        ('pong paddle_sync (guest -> server -> host)', b(PONG_PADDLE_SYNC), PONG_PADDLE_RATE_HZ),
    ]
    print(f"{'message':48} {'bytes':>6} {'Hz':>6} {'B/s':>8} {'KiB/s':>7}")
    total = 0.0
    for name, size, rate in rows:
        bps = size * rate
        total += bps
        print(f"{name:48} {size:6d} {rate:6.1f} {bps:8.0f} {bps / 1024:7.2f}")
    print(f"{'one player, worst case (both streams)':48} {'':6} {'':6} {total:8.0f} {total / 1024:7.2f}")
    print()
    print(f"pong score_update (one-off): {b(PONG_SCORE)} bytes")
    print("Server echoes every relayed message once; room fan-out is 1 peer, so "
          "server egress per client equals the sender's rate above.")


if __name__ == '__main__':
    main()
