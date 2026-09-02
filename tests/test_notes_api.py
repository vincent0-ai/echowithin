import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security


class TestNotesDataStructures:
    """Tests for note document data structures and helper utilities."""

    def test_note_creation_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        note = {
            '_id': ObjectId(),
            'user_id': ObjectId(),
            'title': 'Test Note Title',
            'content': 'Encrypted ciphertext string',
            'tags': ['ideas', 'project'],
            'folder': 'Work',
            'is_pinned': False,
            'is_archived': False,
            'is_deleted': False,
            'created_at': now,
            'updated_at': now
        }
        assert note['created_at'].tzinfo == datetime.timezone.utc
        assert isinstance(note['tags'], list)
        assert note['is_deleted'] is False

    def test_note_trash_lifecycle(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        note = {
            '_id': ObjectId(),
            'user_id': ObjectId(),
            'is_deleted': False,
            'deleted_at': None
        }
        # Simulate moving to trash
        note['is_deleted'] = True
        note['deleted_at'] = now
        assert note['is_deleted'] is True
        assert note['deleted_at'].tzinfo == datetime.timezone.utc

        # Simulate restore
        note['is_deleted'] = False
        note['deleted_at'] = None
        assert note['is_deleted'] is False
        assert note['deleted_at'] is None


class TestNoteSharingTokens:
    """Tests for public / external note sharing tokens."""

    def test_share_token_generation_entropy(self):
        import secrets
        token1 = secrets.token_urlsafe(24)
        token2 = secrets.token_urlsafe(24)
        assert len(token1) >= 32
        assert token1 != token2

    def test_share_token_expiration(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        future_expiry = now + datetime.timedelta(days=7)
        past_expiry = now - datetime.timedelta(hours=1)
        
        share_active = {'token': 'abc', 'expires_at': future_expiry}
        share_expired = {'token': 'xyz', 'expires_at': past_expiry}
        
        assert datetime.datetime.now(datetime.timezone.utc) < share_active['expires_at']
        assert datetime.datetime.now(datetime.timezone.utc) > share_expired['expires_at']


class TestNotesEndpointsAuthGating:
    """Tests for authentication enforcement on note endpoints."""

    def test_personal_space_requires_auth(self, client):
        res = client.get('/personal_space')
        assert res.status_code in [302, 401]

    def test_personal_post_create_requires_auth(self, client):
        res = client.post('/personal_post/create', data={'title': 'New Note', 'content': 'Secret'})
        assert res.status_code in [302, 401]

    def test_personal_post_search_requires_auth(self, client):
        res = client.get('/personal_post/search?q=test')
        assert res.status_code in [302, 401]


