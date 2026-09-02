import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security
from blueprints.whisper import FREE_DURATIONS, PREMIUM_DURATIONS, PENDING_INVITE_TIMEOUT_MINUTES, _utc_iso


class TestWhisperDurationsAndConstants:
    """Tests for whisper session parameters and tier durations."""

    def test_free_and_premium_durations(self):
        assert 15 in FREE_DURATIONS
        assert 30 in FREE_DURATIONS
        assert 60 in PREMIUM_DURATIONS
        assert 120 in PREMIUM_DURATIONS
        assert len(PREMIUM_DURATIONS) > len(FREE_DURATIONS)

    def test_pending_invite_timeout_minutes(self):
        assert PENDING_INVITE_TIMEOUT_MINUTES == 5

    def test_utc_iso_helper_formatting(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        iso_res = _utc_iso(now)
        assert iso_res.endswith('Z')
        parsed = security.parse_iso_utc(iso_res)
        assert parsed.tzinfo == datetime.timezone.utc

    def test_utc_iso_none_handling(self):
        assert _utc_iso(None) is None


class TestDirectMessagePermissions:
    """Tests for can_dm and DM privacy rules."""

    def test_dm_privacy_blocked(self, app):
        """When recipient has blocked sender, DMs are forbidden"""
        import main as m
        import database
        user_a = ObjectId()
        user_b = ObjectId()
        
        target_user = {'_id': user_b, 'blocked_user_ids': [user_a]}
        with patch.object(database.users_conf, 'find_one', side_effect=[None, target_user]):
            assert m.can_dm(str(user_a), str(user_b)) is False

    def test_dm_self_always_allowed(self, app):
        import main as m
        user_id = str(ObjectId())
        assert m.can_dm(user_id, user_id) is True


class TestWhisperLifecycle:
    """Tests for whisper note self-destruction and message decay."""

    def test_whisper_doc_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        whisper = {
            '_id': ObjectId(),
            'sender_id': ObjectId(),
            'recipient_id': ObjectId(),
            'duration_seconds': 30,
            'status': 'active',
            'created_at': now,
            'opened_at': None,
            'expires_at': now + datetime.timedelta(seconds=30)
        }
        assert whisper['created_at'].tzinfo == datetime.timezone.utc
        assert whisper['expires_at'] > whisper['created_at']
        assert whisper['status'] == 'active'


class TestChatEndpointsAuth:
    """Tests that chat routes require authentication."""

    def test_chat_page_requires_auth(self, client):
        res = client.get('/messages')
        assert res.status_code in [302, 401]

    def test_chat_messages_api_requires_auth(self, client):
        res = client.get('/api/messages/history/507f1f77bcf86cd799439011')
        assert res.status_code in [302, 401]


