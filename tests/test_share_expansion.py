"""Tests for expanded share note functionality:
- Share note via Direct Message link preview (/api/personal_post/<id>/share-to-dm)
- Share note to Trusted Circle feed (/api/personal_post/<id>/share-to-circle)
- Recipients discovery endpoint (/api/share/recipients)
- Circle feed rendering for shared_note posts
"""

import json
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import pytest

from security import encrypt_community_note


@pytest.fixture
def note_id():
    return ObjectId('507f1f77bcf86cd799439011')


@pytest.fixture
def other_user_id():
    return ObjectId('507f1f77bcf86cd799439022')


@pytest.fixture
def circle_id():
    return ObjectId('507f1f77bcf86cd799439033')


def test_get_share_recipients_unauthorized(client):
    """Anonymous requests cannot fetch share recipients."""
    res = client.get('/api/share/recipients')
    assert res.status_code in (302, 401)


def test_get_share_recipients_success(auth_client, mock_user, other_user_id, circle_id, monkeypatch):
    """Authenticated user fetches their DM contacts and joined circles."""
    import main as m

    mock_dms = MagicMock()
    mock_dms.aggregate.return_value = [{'_id': other_user_id}]
    monkeypatch.setattr(m, 'direct_messages_conf', mock_dms)

    mock_bonds = MagicMock()
    mock_bonds.find.return_value = []
    monkeypatch.setattr(m, 'bonds_conf', mock_bonds)

    mock_perms = MagicMock()
    mock_perms.find.return_value = []
    monkeypatch.setattr(m, 'dm_permissions_conf', mock_perms)

    mock_users = MagicMock()
    mock_users.find.return_value.sort.return_value = [
        {'_id': other_user_id, 'username': 'alice', 'profile_image_url': None}
    ]
    monkeypatch.setattr(m, 'users_conf', mock_users)

    mock_circles = MagicMock()
    mock_circles.find.return_value.sort.return_value = [
        {'_id': circle_id, 'name': 'Design Thinkers', 'members': [mock_user['_id'], other_user_id], 'visibility': 'open'}
    ]
    monkeypatch.setattr(m, 'circles_conf', mock_circles)

    res = auth_client.get('/api/share/recipients')
    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert len(data['contacts']) == 1
    assert data['contacts'][0]['username'] == 'alice'
    assert len(data['circles']) == 1
    assert data['circles'][0]['name'] == 'Design Thinkers'
    assert data['circles'][0]['member_count'] == 2


def test_share_to_dm_success(auth_client, mock_user, note_id, other_user_id, monkeypatch):
    """User shares their note directly with a contact via DM with link preview."""
    import main as m

    # Mock note owned by user
    mock_notes = MagicMock()
    mock_notes.find_one.return_value = {
        '_id': note_id,
        'user_id': mock_user['_id'],
        'title': 'My Secret Project',
        'content': 'Planning the roadmap'
    }
    monkeypatch.setattr(m, 'personal_posts_conf', mock_notes)

    # Mock recipient user exists
    mock_users = MagicMock()
    mock_users.find_one.return_value = {
        '_id': other_user_id,
        'username': 'bob',
        'blocked_user_ids': []
    }
    monkeypatch.setattr(m, 'users_conf', mock_users)

    # Mock can_dm to return True
    monkeypatch.setattr('utils.can_dm', lambda u1, u2: True)

    mock_shares = MagicMock()
    monkeypatch.setattr(m, 'note_shares_conf', mock_shares)

    mock_dms = MagicMock()
    monkeypatch.setattr(m, 'direct_messages_conf', mock_dms)
    monkeypatch.setattr(m, 'hidden_chats_conf', MagicMock())

    res = auth_client.post(f'/api/personal_post/{note_id}/share-to-dm', json={
        'recipient_id': str(other_user_id),
        'permissions': 'view',
        'message': 'Check this out!'
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'share_url' in data
    assert 'bob' in data['message']

    # Verify share link created
    assert mock_shares.insert_one.called
    # Verify DM inserted with note_share type
    assert mock_dms.insert_one.called
    inserted_dm = mock_dms.insert_one.call_args[0][0]
    assert inserted_dm['message_type'] == 'note_share'
    assert inserted_dm['recipient_id'] == other_user_id
    assert 'link_preview' in inserted_dm
    decrypted_dm = m.decrypt_dm(inserted_dm['content'], str(mock_user['_id']), str(other_user_id))
    assert 'Shared Note: Shared Note' not in decrypted_dm
    assert 'Check this out!' in decrypted_dm


def test_share_to_dm_cannot_message(auth_client, mock_user, note_id, other_user_id, monkeypatch):
    """User cannot DM a note if they lack messaging permission with the recipient."""
    import main as m

    mock_notes = MagicMock()
    mock_notes.find_one.return_value = {
        '_id': note_id,
        'user_id': mock_user['_id'],
        'title': 'Note',
        'content': 'Test'
    }
    monkeypatch.setattr(m, 'personal_posts_conf', mock_notes)

    mock_users = MagicMock()
    mock_users.find_one.return_value = {'_id': other_user_id, 'username': 'charlie'}
    monkeypatch.setattr(m, 'users_conf', mock_users)

    # can_dm returns False
    monkeypatch.setattr('utils.can_dm', lambda u1, u2: False)

    res = auth_client.post(f'/api/personal_post/{note_id}/share-to-dm', json={
        'recipient_id': str(other_user_id)
    })
    assert res.status_code == 403
    assert 'permission' in res.get_json()['error'].lower()


def test_share_to_circle_feed_success(auth_client, mock_user, note_id, circle_id, monkeypatch):
    """User posts a note to their Trusted Circle feed."""
    import main as m

    mock_notes = MagicMock()
    mock_notes.find_one.return_value = {
        '_id': note_id,
        'user_id': mock_user['_id'],
        'title': 'Sprint Retrospective',
        'content': 'Here are the key takeaways from sprint 1.'
    }
    monkeypatch.setattr(m, 'personal_posts_conf', mock_notes)

    mock_circles = MagicMock()
    mock_circles.find_one.return_value = {
        '_id': circle_id,
        'name': 'Engineering Team',
        'members': [mock_user['_id']]
    }
    monkeypatch.setattr(m, 'circles_conf', mock_circles)

    mock_shares = MagicMock()
    monkeypatch.setattr(m, 'note_shares_conf', mock_shares)

    mock_posts = MagicMock()
    monkeypatch.setattr(m, 'circle_posts_conf', mock_posts)

    res = auth_client.post(f'/api/personal_post/{note_id}/share-to-circle', json={
        'circle_id': str(circle_id),
        'caption': 'Sharing sprint retro notes with everyone',
        'permissions': 'view'
    })

    assert res.status_code == 200
    data = res.get_json()
    assert data['success'] is True
    assert 'Engineering Team' in data['message']

    # Verify post was created with kind='shared_note'
    assert mock_posts.insert_one.called
    inserted_post = mock_posts.insert_one.call_args[0][0]
    assert inserted_post['kind'] == 'shared_note'
    assert inserted_post['circle_id'] == circle_id
    assert inserted_post['author_id'] == mock_user['_id']


def test_share_to_circle_not_member(auth_client, mock_user, note_id, circle_id, monkeypatch):
    """User cannot post a note to a circle they have not joined."""
    import main as m

    mock_notes = MagicMock()
    mock_notes.find_one.return_value = {
        '_id': note_id,
        'user_id': mock_user['_id']
    }
    monkeypatch.setattr(m, 'personal_posts_conf', mock_notes)

    # find_one returns None (user not in members)
    mock_circles = MagicMock()
    mock_circles.find_one.return_value = None
    monkeypatch.setattr(m, 'circles_conf', mock_circles)

    res = auth_client.post(f'/api/personal_post/{note_id}/share-to-circle', json={
        'circle_id': str(circle_id)
    })
    assert res.status_code == 404
    assert 'not a member' in res.get_json()['error'].lower()


def test_circle_feed_shared_note_render(auth_client, mock_user, circle_id, monkeypatch):
    """Circle feed properly renders shared note post cards."""
    import main as m

    mock_circles = MagicMock()
    mock_circles.find_one.return_value = {
        '_id': circle_id,
        'name': 'Designers Circle',
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'},
        'visibility': 'open'
    }
    monkeypatch.setattr(m, 'circles_conf', mock_circles)

    mock_post_id = ObjectId()
    payload = {
        'caption': 'Check out our new design principles',
        'note_title': 'Design System 2026',
        'share_id': 'abc123xyz',
        'share_url': '/share/note/abc123xyz',
        'snippet': 'Typography, color scales, and layout standards.'
    }

    mock_posts = MagicMock()
    mock_posts.find.return_value.sort.return_value.limit.return_value = [
        {
            '_id': mock_post_id,
            'circle_id': circle_id,
            'author_id': mock_user['_id'],
            'kind': 'shared_note',
            'content': encrypt_community_note(json.dumps(payload), circle_id),
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'reactions': {},
            'comments': [],
            'is_pinned': False
        }
    ]
    monkeypatch.setattr(m, 'circle_posts_conf', mock_posts)
    monkeypatch.setattr(m, 'circle_messages_conf', MagicMock(find=MagicMock(return_value=MagicMock(sort=MagicMock(return_value=MagicMock(limit=MagicMock(return_value=[])))))))
    monkeypatch.setattr(m, 'circle_requests_conf', MagicMock(find=MagicMock(return_value=[])))

    mock_users = MagicMock()
    mock_users.find.return_value = [mock_user]
    monkeypatch.setattr(m, 'users_conf', mock_users)

    res = auth_client.get(f'/circle/{circle_id}')
    assert res.status_code == 200
    assert b'Design System 2026' in res.data
    assert b'Check out our new design principles' in res.data
    assert b'/share/note/abc123xyz' in res.data
    assert b'Open Note' in res.data
