import hashlib
import pytest
from unittest.mock import patch, MagicMock
from bson.objectid import ObjectId
import datetime

import database
import security


@pytest.fixture(autouse=True)
def clear_bf_state():
    # force in-memory fallback for deterministic tests
    orig = database.redis_cache
    database.redis_cache = None
    # clear in-memory stores
    security._BF_MEMORY.clear()
    security._RATE_LIMIT_MEMORY.clear()
    security._BF_MEMORY_LOCK = security._BF_MEMORY_LOCK  # keep same lock
    yield
    security._BF_MEMORY.clear()
    security._RATE_LIMIT_MEMORY.clear()
    database.redis_cache = orig


def _ctx(app, ip="1.2.3.4"):
    return app.test_request_context('/', environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})


def test_a_attacker_rapid_same_account_same_ip_gets_throttled(app):
    """(a) attacker hammering one account from one IP hits friction then lockout."""
    ip = "198.51.100.10"
    account = "alice@example.com"
    with _ctx(app, ip):
        # 1-3: ok
        for i in range(1, 4):
            cnt, tier, retry, ttl = security.brute_force_record_failure('login', account, ip)
            assert tier == 'ok', f"attempt {i} should be ok, got {tier}"
        # 4th: friction
        cnt, tier, retry, ttl = security.brute_force_record_failure('login', account, ip)
        assert tier == 'friction'
        assert retry == 2
        # 5th: friction
        cnt, tier, retry, ttl = security.brute_force_record_failure('login', account, ip)
        assert tier == 'friction'
        assert retry == 4
        # 6th: lockout
        cnt, tier, retry, ttl = security.brute_force_record_failure('login', account, ip)
        assert tier == 'lockout'
        assert retry > 0
        # further check via check (should still be lockout)
        tier2, cnt2, retry2, ttl2 = security.brute_force_check('login', account, ip)
        assert tier2 == 'lockout'


def test_a_distinct_accounts_from_same_ip_do_not_share_bucket(app):
    """Distinct accounts from same IP have isolated buckets — per-IP outer limit is separate.
    This proves the account+IP scoping: hammering alice does not lock bob on same IP.
    The coarse per-IP limit (20/60) would still catch massive distinct-account stuffing,
    but graduated lockout is per-account, not per-IP.
    """
    ip = "198.51.100.10"
    with _ctx(app, ip):
        # Burn alice to lockout
        for _ in range(6):
            security.brute_force_record_failure('login', 'alice@example.com', ip)
        tier_alice, *_ = security.brute_force_check('login', 'alice@example.com', ip)
        assert tier_alice == 'lockout'
        # bob on same IP should still be ok
        tier_bob, cnt_bob, *_ = security.brute_force_check('login', 'bob@example.com', ip)
        assert tier_bob == 'ok'
        assert cnt_bob == 0


def test_b_shared_ip_legitimate_user_not_blocked(app):
    """(b) legitimate user on shared IP is NOT blocked by other users' failures."""
    shared_ip = "203.0.113.50"
    alice = "alice@campus.example.com"
    bob = "bob@campus.example.com"
    with _ctx(app, shared_ip):
        # Attacker fails alice 6x (lock alice on this IP)
        for _ in range(6):
            security.brute_force_record_failure('login', alice, shared_ip)
        tier_alice_shared, *_ = security.brute_force_check('login', alice, shared_ip)
        assert tier_alice_shared == 'lockout'

        # Bob on same shared IP with correct credentials should NOT be locked
        tier_bob, cnt_bob, retry_bob, _ = security.brute_force_check('login', bob, shared_ip)
        assert tier_bob == 'ok', "bob on shared IP must not be locked by alice's failures"
        # Simulate bob success clears (no failure recorded) — still ok
        security.brute_force_clear('login', bob, shared_ip)
        tier_bob2, *_ = security.brute_force_check('login', bob, shared_ip)
        assert tier_bob2 == 'ok'

        # Alice switching to different IP should NOT be locked (mobile network switch)
        other_ip = "198.51.100.99"
        tier_alice_other, cnt_other, *_ = security.brute_force_check('login', alice, other_ip)
        assert tier_alice_other == 'ok'
        assert cnt_other == 0

        # Alice success on shared IP after lockout would still be blocked until TTL,
        # but after clear (simulating correct password after TTL or admin) she is clear
        security.brute_force_clear('login', alice, shared_ip)
        tier_alice_cleared, *_ = security.brute_force_check('login', alice, shared_ip)
        assert tier_alice_cleared == 'ok'


def test_success_resets_counter(app):
    ip = "10.0.0.1"
    acct = "charlie@example.com"
    with _ctx(app, ip):
        security.brute_force_record_failure('login', acct, ip)
        security.brute_force_record_failure('login', acct, ip)
        tier, cnt, *_ = security.brute_force_check('login', acct, ip)
        assert cnt == 2
        assert tier == 'ok'
        # success clears
        security.brute_force_clear('login', acct, ip)
        tier2, cnt2, *_ = security.brute_force_check('login', acct, ip)
        assert cnt2 == 0
        assert tier2 == 'ok'


def test_api_login_brute_force_integration(app, mock_user):
    """Integration: POST /api/v1/login with mocked DB shows 429 after 6 failures per account+IP."""
    from werkzeug.security import generate_password_hash
    # Use in-memory fallback already via clear_bf_state
    pwd = "correcthorsebatterystaple"
    mock_user['password'] = generate_password_hash(pwd)
    mock_user['username'] = 'alice'
    mock_user['email'] = 'alice@example.com'
    mock_user['is_confirmed'] = True
    # patch users_conf to return mock_user for alice
    with patch('main.users_conf') as mock_users, \
         patch('main.auth_conf') as mock_auth, \
         patch('main.send_code') as mock_send, \
         patch('main.app_tokens_conf') as mock_tokens, \
         patch('main.user_sessions_conf') as mock_sess:
        mock_users.find_one.side_effect = lambda q, *a, **kw: mock_user if q.get('$or') else None
        mock_auth.find_one.return_value = None
        mock_tokens.insert_one.return_value = None
        mock_sess.insert_one.return_value = None
        client = app.test_client()
        ip = "203.0.113.77"
        # first 3 wrong passwords → 401 (ok tier, enumeration-safe)
        for i in range(3):
            resp = client.post('/api/v1/login', json={'username': 'alice', 'password': 'wrong'}, environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})
            assert resp.status_code == 401, f"attempt {i+1} expected 401 got {resp.status_code}"
        # 4th → friction 429
        resp = client.post('/api/v1/login', json={'username': 'alice', 'password': 'wrong'}, environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})
        assert resp.status_code == 429
        assert resp.headers.get('X-BruteForce-Tier') == 'friction'
        # 5th still friction
        resp = client.post('/api/v1/login', json={'username': 'alice', 'password': 'wrong'}, environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})
        assert resp.status_code == 429
        # 6th lockout
        resp = client.post('/api/v1/login', json={'username': 'alice', 'password': 'wrong'}, environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})
        assert resp.status_code == 429
        assert resp.headers.get('X-BruteForce-Tier') == 'lockout'
        # bob correct on same shared IP should still succeed (different account bucket)
        # need to mock bob user as well
        bob_user = dict(mock_user)
        bob_user['username'] = 'bob'
        bob_user['email'] = 'bob@example.com'
        bob_user['password'] = generate_password_hash('bobspassword')
        def find_side(q, *a, **kw):
            ors = q.get('$or', [])
            for cond in ors:
                if cond.get('username') == 'bob' or cond.get('email') == 'bob@example.com':
                    return bob_user
                if cond.get('username') == 'alice' or cond.get('email') == 'alice@example.com':
                    return mock_user
            return None
        mock_users.find_one.side_effect = find_side
        # need to also mock User creation for bob
        with patch('main.User') as MockUser:
            MockUser.return_value = MagicMock(id=str(bob_user['_id']), username='bob')
            # patch login_user to avoid session issues
            with patch('api.login_user'):
                with patch('security.create_app_token', return_value='fake-token'):
                    resp = client.post('/api/v1/login', json={'username': 'bob', 'password': 'bobspassword'}, environ_base={'REMOTE_ADDR': ip}, headers={'X-Forwarded-For': ip})
                    # bob should NOT be locked by alice's failures
                    assert resp.status_code == 200, f"bob should succeed on shared IP, got {resp.status_code} {resp.data}"


def test_share_access_code_per_share_ip_isolation(app):
    """Share access codes are per-share+IP, not global."""
    ip = "192.0.2.10"
    share_a = "share_abc123"
    share_b = "share_xyz789"
    with _ctx(app, ip):
        for _ in range(6):
            security.brute_force_record_failure('share', share_a, ip)
        tier_a, *_ = security.brute_force_check('share', share_a, ip)
        assert tier_a == 'lockout'
        tier_b, *_ = security.brute_force_check('share', share_b, ip)
        assert tier_b == 'ok'
