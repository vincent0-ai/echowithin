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


class TestAppLockVerify:
    """Tests for the app lock PIN verification endpoint."""

    def test_app_lock_verify_requires_auth(self, client):
        res = client.post('/api/app_lock/verify', json={'pin': '1234'})
        assert res.status_code in [302, 401]

    def test_app_lock_verify_success(self, auth_client, mock_user):
        from werkzeug.security import generate_password_hash
        import database
        pin = "1234"
        database.users_conf.find_one = MagicMock(return_value={
            '_id': ObjectId(mock_user['_id']),
            'app_lock_pin_hash': generate_password_hash(pin)
        })
        res = auth_client.post('/api/app_lock/verify', json={'pin': pin})
        assert res.status_code == 200
        data = res.get_json()
        assert data.get('success') is True

    def test_app_lock_verify_wrong_pin(self, auth_client, mock_user):
        from werkzeug.security import generate_password_hash
        import database
        database.users_conf.find_one = MagicMock(return_value={
            '_id': ObjectId(mock_user['_id']),
            'app_lock_pin_hash': generate_password_hash("1234")
        })
        res = auth_client.post('/api/app_lock/verify', json={'pin': "9999"})
        assert res.status_code == 403
        data = res.get_json()
        assert 'Incorrect PIN' in data.get('error', '')

    def test_app_lock_verify_empty_pin(self, auth_client):
        res = auth_client.post('/api/app_lock/verify', json={'pin': ''})
        assert res.status_code == 400
        data = res.get_json()
        assert 'PIN is required' in data.get('error', '')


class TestPersonalSpaceTabs:
    """Tests for on-demand personal space tab endpoints."""

    def test_personal_space_tabs_require_auth(self, client):
        for tab in ['saved', 'activity', 'locked', 'forms', 'games']:
            res = client.get(f'/personal_space/tab/{tab}')
            assert res.status_code in [302, 401]

    def test_personal_space_tab_saved(self, auth_client):
        res = auth_client.get('/personal_space/tab/saved')
        assert res.status_code == 200

    def test_personal_space_tab_activity(self, auth_client):
        res = auth_client.get('/personal_space/tab/activity')
        assert res.status_code == 200

    def test_personal_space_tab_locked(self, auth_client):
        res = auth_client.get('/personal_space/tab/locked')
        assert res.status_code == 200

    def test_personal_space_tab_forms(self, auth_client):
        res = auth_client.get('/personal_space/tab/forms')
        assert res.status_code == 200

    def test_personal_space_tab_games(self, auth_client):
        res = auth_client.get('/personal_space/tab/games')
        assert res.status_code == 200

    def test_personal_space_tab_invalid(self, auth_client):
        res = auth_client.get('/personal_space/tab/unknown')
        assert res.status_code == 404

    def test_personal_space_tab_pagination_args(self, auth_client):
        res_locked = auth_client.get('/personal_space/tab/locked?locked_page=2')
        assert res_locked.status_code == 200
        res_saved = auth_client.get('/personal_space/tab/saved?saved_page=2')
        assert res_saved.status_code == 200

    def test_personal_space_active_tab_inference(self, auth_client):
        # Visiting with locked_page should infer active_tab='locked'
        res = auth_client.get('/personal_space?locked_page=2')
        assert res.status_code == 200
        assert b'id="tab-locked"' in res.data
        # Visiting with saved_page should infer active_tab='saved'
        res_saved = auth_client.get('/personal_space?saved_page=2')
        assert res_saved.status_code == 200
        assert b'id="tab-saved"' in res_saved.data



