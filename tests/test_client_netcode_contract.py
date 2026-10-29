"""Client netcode contract tests.

These guard the protocol invariants that live in the game JS. They are static
assertions on the shipped files: no browser or Node toolchain is required, so
they run in CI with the rest of the suite. They prove structure, not runtime
behaviour — live behaviour is measured with scripts/latency_sim.py (see
docs/netcode-investigation.md for what was measured vs modelled).
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), 'r', encoding='utf-8') as fh:
        return fh.read()


class TestStaleAndOutOfOrderHandling:
    def test_slime_drops_stale_match_generation(self):
        js = _read('static/slime_volleyball.js')
        assert 'snapMatch < GameState.matchNo' in js, \
            'slime snapshot handler must drop snapshots from an older match'
        assert 'resolvedMatchNo === GameState.matchNo' in js, \
            'slime endGame must be idempotent per match generation'

    def test_slime_drops_stale_host_seq(self):
        js = _read('static/slime_volleyball.js')
        assert 'lastHostSeq' in js
        assert 'hSeq <= GameState.lastHostSeq' in js, \
            'slime must drop out-of-order host snapshots by sequence id'

    def test_pong_drops_stale_ball_seq_and_match_echo(self):
        js = _read('static/ping_pong.js')
        assert 'lastBallSeq' in js, 'pong must track the last accepted ball seq'
        assert 'msgMatch < state.matchNo' in js, \
            'pong score echoes from an older match must be ignored'

    def test_pong_award_is_idempotent_per_generation(self):
        js = _read('static/ping_pong.js')
        assert 'state.resolvedMatchNo === state.matchNo' in js


class TestFixedTimestep:
    def test_slime_uses_fixed_timestep_accumulator(self):
        js = _read('static/slime_volleyball.js')
        assert 'FIXED_DT' in js and 'physicsAccumulator' in js
        assert 'while (physicsAccumulator >= FIXED_DT)' in js, \
            'slime physics must step in fixed increments, not per-frame delta'

    def test_pong_uses_fixed_timestep_accumulator(self):
        js = _read('static/ping_pong.js')
        assert 'PONG_FIXED_DT' in js and 'pongAccumulator' in js
        assert 'while (pongAccumulator >= PONG_FIXED_DT' in js

    def test_slime_network_sync_not_timer_driven(self):
        js = _read('static/slime_volleyball.js')
        assert 'setInterval(' not in js, \
            'network sync must be rAF-gated; setInterval bursts on refocus'


class TestFairnessPath:
    def test_pong_host_resolves_against_delayed_own_input(self):
        js = _read('static/ping_pong.js')
        assert 'authoritativeOwnPaddleY' in js
        assert 'state.simP1Y' in js, \
            'pong host collisions must use the delayed own-paddle shadow'

    def test_slime_host_resolves_against_delayed_own_input(self):
        js = _read('static/slime_volleyball.js')
        assert 'hostShadowSlime' in js
        assert 'resolveHostHit()' in js, \
            'slime host collisions must use the delayed own-slime shadow'


class TestAwardWiring:
    def test_slime_client_no_longer_guesses_user_ids(self):
        js = _read('static/slime_volleyball.js')
        assert 'GameState.hostUserId' not in js
        assert 'GameState.guestUserId' not in js
        assert 'match_no: GameState.matchNo' in js, \
            'slime match-end report must carry the server match generation'

    def test_slime_rematch_waits_for_local_choice(self):
        js = _read('static/slime_volleyball.js')
        assert 'opponentWantsRematch' in js
        assert 'localRestartPending' in js

    def test_c4_optimistic_move_and_resync(self):
        js = _read('static/connect_four.js')
        assert 'echoPending' in js
        assert 'join_c4_room' in js, \
            'a lost move echo must resync the authoritative board'


class TestConnectionQualityIndicator:
    def test_each_realtime_game_reports_rtt(self):
        for rel in ('static/ping_pong.js', 'static/slime_volleyball.js',
                    'static/connect_four.js'):
            js = _read(rel)
            assert "emit('net_ping'" in js, f'{rel} must probe RTT'
            assert 'net-quality' in js, f'{rel} must drive the quality chip'

    def test_templates_render_the_chip(self):
        for rel in ('templates/ping_pong.html', 'templates/slime_volleyball.html',
                    'templates/connect_four.html'):
            html = _read(rel)
            assert 'id="net-quality"' in html, f'{rel} is missing the RTT chip'
