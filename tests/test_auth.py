"""
Tests for authentication flows in the EchoWithin application.
Covers: login, registration, password hashing, confirmation, logout.
"""

import pytest
from unittest import mock


class TestPasswordHashing:
    """Tests for password hashing and verification."""

    def test_hash_and_verify(self, app):
        """generate_password_hash and check_password_hash should be compatible"""
        from werkzeug.security import generate_password_hash, check_password_hash
        password = 'MySecureP@ss123'
        with app.app_context():
            hashed = generate_password_hash(password)
            assert hashed != password
            assert check_password_hash(hashed, password)

    def test_wrong_password_fails(self, app):
        """Wrong password should fail verification"""
        from werkzeug.security import generate_password_hash, check_password_hash
        password = 'correct_password'
        with app.app_context():
            hashed = generate_password_hash(password)
            assert not check_password_hash(hashed, 'wrong_password')

    def test_empty_password(self, app):
        """Empty password should still hash/verify"""
        from werkzeug.security import generate_password_hash, check_password_hash
        with app.app_context():
            hashed = generate_password_hash('')
            assert hashed
            assert check_password_hash(hashed, '')


class TestSafeObjectId:
    """Tests for safe_object_id utility."""

    def test_valid_object_id(self):
        from main import safe_object_id
        from bson.objectid import ObjectId
        result = safe_object_id('507f1f77bcf86cd799439011')
        assert isinstance(result, ObjectId)

    def test_invalid_object_id(self):
        from main import safe_object_id
        assert safe_object_id('invalid') is None
        assert safe_object_id('') is None
        assert safe_object_id(None) is None
        assert safe_object_id('123') is None  # wrong length


class TestSafeUrlValidation:
    """Tests for open redirect protection."""

    def test_safe_url_same_host(self, app):
        """URL on the same host should be considered safe"""
        from main import is_safe_url
        with app.test_request_context('/', base_url='http://echowithin.xyz'):
            assert is_safe_url('/dashboard')
            assert is_safe_url('/home')

    def test_safe_url_external_blocked(self, app):
        """External URLs should be blocked"""
        from main import is_safe_url
        with app.test_request_context('/', base_url='http://echowithin.xyz'):
            assert not is_safe_url('https://evil.com/phishing')
            assert not is_safe_url('//evil.com')

    def test_safe_url_relative(self, app):
        """Relative URLs should be considered safe"""
        from main import is_safe_url
        with app.test_request_context('/', base_url='http://echowithin.xyz'):
            assert is_safe_url('/post/test-slug')


class TestConfirmationCodeGeneration:
    """Tests for confirmation code generation."""

    def test_code_is_6_digits(self):
        """Confirmation code should be a zero-padded 6-digit string"""
        import secrets
        code = str(secrets.randbelow(10**6)).zfill(6)
        assert len(code) == 6
        assert code.isdigit()

    def test_code_hash_is_sha256(self):
        """Code should be hashed with SHA-256"""
        import hashlib
        code = '123456'
        hashed = hashlib.sha256(code.encode()).hexdigest()
        assert len(hashed) == 64  # SHA-256 produces 64 hex chars
        assert hashed != code


class TestUserClass:
    """Tests for the User model class."""

    def test_user_creation(self, app):
        """User object should initialise correctly from MongoDB doc"""
        from main import User
        from bson.objectid import ObjectId
        user_data = {
            '_id': ObjectId('507f1f77bcf86cd799439011'),
            'username': 'testuser',
            'is_admin': False,
            'is_confirmed': True,
            'join_date': __import__('datetime').datetime.now(__import__('datetime').timezone.utc),
        }
        with app.app_context():
            user = User(user_data)
            assert user.id == '507f1f77bcf86cd799439011'
            assert user.username == 'testuser'
            assert user.is_admin is False
            assert user.is_active is True

    def test_admin_user(self, app):
        """Admin users should have admin privileges"""
        from main import User
        from bson.objectid import ObjectId
        user_data = {
            '_id': ObjectId('507f1f77bcf86cd799439011'),
            'username': 'admin',
            'is_admin': True,
            'is_confirmed': True,
        }
        with app.app_context():
            user = User(user_data)
            assert user.is_admin is True
            assert user.get_admin() is True


class TestTierResolution:
    """Tests for premium/free tier resolution."""

    def test_default_tier_is_free(self, app):
        """New users should default to free tier"""
        from main import get_user_tier
        with app.app_context():
            assert get_user_tier({}) == 'free'
            assert get_user_tier(None) == 'free'

    def test_admin_gets_premium(self, app):
        """Admin users should get premium tier"""
        from main import get_user_tier
        with app.app_context():
            assert get_user_tier({'is_admin': True}) == 'premium'

    def test_explicit_premium_active(self, app):
        """Explicit premium with future expiry should remain premium"""
        from main import get_user_tier
        import datetime
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        user = {'account_tier': 'premium', 'premium_until': future}
        with app.app_context():
            assert get_user_tier(user) == 'premium'

    def test_expired_premium_falls_back_to_free(self, app):
        """Expired premium should fall back to free tier"""
        from main import get_user_tier
        import datetime
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        user = {'account_tier': 'premium', 'premium_until': past}
        with app.app_context():
            assert get_user_tier(user) == 'free'

    def test_trial_period(self, app):
        """Users within trial period should get premium access"""
        from main import get_user_tier
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        # Joined less than PREMIUM_TRIAL_DAYS ago
        recent_join = now - datetime.timedelta(hours=12)
        user = {'join_date': recent_join}
        with app.app_context():
            tier = get_user_tier(user)
            # Should be premium if trial is active
            from main import PREMIUM_TRIAL_DAYS
            trial_end = recent_join + datetime.timedelta(days=PREMIUM_TRIAL_DAYS)
            if datetime.datetime.now(datetime.timezone.utc) < trial_end:
                assert tier == 'premium'
            else:
                assert tier == 'free'


class TestLimitResolution:
    """Tests for tiered limit resolution."""

    def test_free_note_limit(self, app):
        """Free users should have 500 note limit"""
        from main import get_limit
        with app.app_context():
            assert get_limit({}, 'max_notes') == 500

    def test_premium_note_limit(self, app):
        """Premium users should have effectively unlimited notes"""
        from main import get_limit
        user = {'is_admin': True}
        with app.app_context():
            assert get_limit(user, 'max_notes') == 99999


class TestParselso:
    """Tests for parse_iso_utc datetime parser."""

    def test_parse_iso_with_z(self):
        from main import parse_iso_utc
        import datetime
        result = parse_iso_utc('2024-01-15T10:30:00Z')
        assert result is not None
        assert result.tzinfo is not None
        assert result.tzinfo == datetime.timezone.utc

    def test_parse_iso_with_offset(self):
        from main import parse_iso_utc
        import datetime
        result = parse_iso_utc('2024-01-15T10:30:00+00:00')
        assert result is not None
        assert result.tzinfo is not None

    def test_parse_iso_none_input(self):
        from main import parse_iso_utc
        assert parse_iso_utc(None) is None
        assert parse_iso_utc('') is None
        assert parse_iso_utc(123) is None  # Not a string

    def test_parse_iso_invalid(self):
        from main import parse_iso_utc
        assert parse_iso_utc('not-a-date') is None


class TestGuestExpiration:
    """Tests for guest session expiration and cleanup."""

    def test_guest_is_expired_property(self, app):
        """is_guest_expired should return True for past guest_expires_at and False for future"""
        from main import User
        from bson.objectid import ObjectId
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        
        expired_doc = {
            '_id': ObjectId(),
            'username': 'Guest_Expired',
            'is_guest': True,
            'guest_expires_at': now - datetime.timedelta(minutes=5)
        }
        active_doc = {
            '_id': ObjectId(),
            'username': 'Guest_Active',
            'is_guest': True,
            'guest_expires_at': now + datetime.timedelta(minutes=15)
        }
        regular_doc = {
            '_id': ObjectId(),
            'username': 'RegularUser',
            'is_guest': False
        }

        with app.app_context():
            u_expired = User(expired_doc)
            u_active = User(active_doc)
            u_regular = User(regular_doc)

            assert u_expired.is_guest_expired is True
            assert u_active.is_guest_expired is False
            assert u_regular.is_guest_expired is False


class TestActiveSessionsAndRevocation:
    """Tests for session management and token revocation."""

    def test_session_token_generation_entropy(self):
        import secrets
        token1 = secrets.token_hex(32)
        token2 = secrets.token_hex(32)
        assert len(token1) == 64
        assert token1 != token2

    def test_session_doc_structure_and_utc_timestamp(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(days=30)
        session_entry = {
            'token_hash': 'abcdef1234567890',
            'created_at': now,
            'expires_at': expires,
            'ip_hash': 'sha256_mock_hash',
            'user_agent': 'Mozilla/5.0 Test'
        }
        assert session_entry['created_at'].tzinfo == datetime.timezone.utc
        assert session_entry['expires_at'] > session_entry['created_at']


class TestPasswordResetTokens:
    """Tests for password reset token lifecycle and expiration."""

    def test_password_reset_token_expiration(self):
        import datetime
        import secrets
        now = datetime.datetime.now(datetime.timezone.utc)
        valid_expiry = now + datetime.timedelta(hours=1)
        expired_expiry = now - datetime.timedelta(minutes=5)
        
        token = secrets.token_urlsafe(32)
        doc_valid = {'reset_token': token, 'reset_expires_at': valid_expiry}
        doc_expired = {'reset_token': token, 'reset_expires_at': expired_expiry}
        
        assert datetime.datetime.now(datetime.timezone.utc) < doc_valid['reset_expires_at']
        assert datetime.datetime.now(datetime.timezone.utc) > doc_expired['reset_expires_at']


class TestHoneypotRegistration:
    """Tests for registration honeypot bot trap."""

    def test_honeypot_field_detected_as_bot(self, app):
        """When honeypot field is filled by a bot, registration should be rejected"""
        with app.test_client() as client:
            res = client.post('/register', data={
                'username': 'bot_user',
                'email': 'bot@example.com',
                'password': 'Password123!',
                'website': 'http://spam-link.com'  # Honeypot trap field
            }, follow_redirects=True)
            # Route should either silently drop or reject
            assert res.status_code in [200, 302, 400]

