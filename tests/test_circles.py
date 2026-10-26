"""Tests for Private Trusted Circles: chat, feed, polls, events, and member management."""

import datetime
import json
from unittest.mock import MagicMock
from bson.objectid import ObjectId
import pytest

from security import encrypt_community_note


@pytest.fixture(autouse=True)
def isolate_collections():
    import main as m
    orig_circles = m.circles_conf
    orig_circle_posts = m.circle_posts_conf
    orig_circle_messages = m.circle_messages_conf
    orig_circle_requests = m.circle_requests_conf
    orig_users = m.users_conf
    orig_game = m.game_sessions_conf

    m.circles_conf = MagicMock()
    m.circle_posts_conf = MagicMock()
    m.circle_messages_conf = MagicMock()
    m.circle_requests_conf = MagicMock()
    m.users_conf = MagicMock()
    m.game_sessions_conf = MagicMock()

    yield

    m.circles_conf = orig_circles
    m.circle_posts_conf = orig_circle_posts
    m.circle_messages_conf = orig_circle_messages
    m.circle_requests_conf = orig_circle_requests
    m.users_conf = orig_users
    m.game_sessions_conf = orig_game


@pytest.fixture
def circle_id():
    return ObjectId('507f1f77bcf86cd799439022')


@pytest.fixture
def other_user_id():
    return ObjectId('507f1f77bcf86cd799439033')


def test_circles_page_render(auth_client, mock_user):
    import main as m
    mock_cursor = MagicMock()
    mock_cursor.sort.return_value = []
    m.circles_conf.find.return_value = mock_cursor

    resp = auth_client.get('/circles')
    assert resp.status_code == 200
    assert b'Trusted Circles' in resp.data


def test_create_circle(auth_client, mock_user):
    import main as m
    m.circles_conf.insert_one.return_value.inserted_id = ObjectId('507f1f77bcf86cd799439022')
    resp = auth_client.post('/circles/create', data={
        'name': 'Squad Circle',
        'circle_type': 'friends',
        'approval_required': '0'
    })
    assert resp.status_code == 302
    assert '/circle/507f1f77bcf86cd799439022' in resp.location
    assert m.circles_conf.insert_one.called


def test_view_circle_renders_components(auth_client, mock_user, circle_id):
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    circle_doc = {
        '_id': circle_id,
        'name': 'Squad Circle',
        'circle_type': 'friends',
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'},
        'visibility': 'invite_only',
        'created_at': now,
        'updated_at': now
    }

    m.circles_conf.find_one.return_value = circle_doc
    m.circle_posts_conf.find.return_value.sort.return_value.limit.return_value = []
    m.circle_messages_conf.find.return_value.sort.return_value.limit.return_value = []
    m.users_conf.find.return_value = [mock_user]
    m.circle_requests_conf.find.return_value = []
    m.game_sessions_conf.find.return_value.sort.return_value.limit.return_value = []

    resp = auth_client.get(f'/circle/{circle_id}')
    assert resp.status_code == 200
    assert b'Squad Circle' in resp.data
    assert b'Chat' in resp.data
    assert b'Feed' in resp.data
    assert b'Play and plan' in resp.data
    assert b'Members' in resp.data


def test_invite_member_direct_add(auth_client, mock_user, circle_id, other_user_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'name': 'Squad Circle',
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }
    other_user = {
        '_id': other_user_id,
        'username': 'bobfriend',
        'profile_image_url': None
    }

    m.circles_conf.find_one.return_value = circle_doc
    m.users_conf.find_one.return_value = other_user

    resp = auth_client.post(f'/circle/{circle_id}/invite/user', data={'username': 'bobfriend'})
    assert resp.status_code == 302
    assert m.circles_conf.update_one.called
    update_args = m.circles_conf.update_one.call_args[0]
    assert update_args[0] == {'_id': circle_id}
    assert update_args[1]['$addToSet']['members'] == other_user_id


def test_invite_member_disallows_self_and_already_member(auth_client, mock_user, circle_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }

    m.circles_conf.find_one.return_value = circle_doc
    m.users_conf.find_one.return_value = mock_user

    resp = auth_client.post(f'/circle/{circle_id}/invite/user', data={'username': 'testuser'})
    assert resp.status_code == 302
    assert not m.circles_conf.update_one.called


def test_search_invite_users(auth_client, mock_user, circle_id, other_user_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }
    mock_results = [{'_id': other_user_id, 'username': 'alice', 'profile_image_url': None}]

    m.circles_conf.find_one.return_value = circle_doc
    mock_cursor = MagicMock()
    mock_cursor.limit.return_value = mock_results
    m.users_conf.find.return_value = mock_cursor

    resp = auth_client.get(f'/circle/{circle_id}/members/search?q=ali')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'users' in data
    assert len(data['users']) == 1
    assert data['users'][0]['username'] == 'alice'
    assert data['users'][0]['is_member'] is False


def test_chat_message_lifecycle(auth_client, mock_user, circle_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }
    msg_id = ObjectId('507f1f77bcf86cd799439044')

    m.circles_conf.find_one.return_value = circle_doc
    m.circle_messages_conf.insert_one.return_value.inserted_id = msg_id

    # 1. Create message via JSON
    resp = auth_client.post(
        f'/circle/{circle_id}/chat',
        json={'content': 'Hello Circle!'}
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    assert data['message']['content'] == 'Hello Circle!'

    # 2. Edit message
    existing_msg = {
        '_id': msg_id,
        'circle_id': circle_id,
        'author_id': mock_user['_id'],
        'content': encrypt_community_note('Hello Circle!', circle_id),
        'reactions': {}
    }
    m.circle_messages_conf.find_one.return_value = existing_msg

    resp = auth_client.post(
        f'/circle/{circle_id}/chat/{msg_id}/edit',
        json={'content': 'Hello Circle Edited!'}
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert m.circle_messages_conf.update_one.called

    # 3. React to message
    resp = auth_client.post(
        f'/circle/{circle_id}/chat/{msg_id}/react',
        json={'emoji': '❤️'}
    )
    assert resp.status_code == 200
    reactions = resp.get_json()['reactions']
    assert '❤️' in reactions
    assert str(mock_user['_id']) in reactions['❤️']

    # 4. Pin message
    resp = auth_client.post(
        f'/circle/{circle_id}/chat/{msg_id}/pin',
        json={}
    )
    assert resp.status_code == 200
    assert resp.get_json()['is_pinned'] is True

    # 5. Delete message
    resp = auth_client.post(
        f'/circle/{circle_id}/chat/{msg_id}/delete',
        json={}
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert m.circle_messages_conf.delete_one.called


def test_feed_post_lifecycle(auth_client, mock_user, circle_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }
    post_id = ObjectId('507f1f77bcf86cd799439055')

    m.circles_conf.find_one.return_value = circle_doc

    # 1. Create Post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts',
        data={'content': 'Great news team!'}
    )
    assert resp.status_code == 302
    assert m.circle_posts_conf.insert_one.called

    existing_post = {
        '_id': post_id,
        'circle_id': circle_id,
        'author_id': mock_user['_id'],
        'kind': 'post',
        'content': encrypt_community_note('Great news team!', circle_id),
        'reactions': {},
        'comments': [],
        'is_pinned': False
    }
    m.circle_posts_conf.find_one.return_value = existing_post

    # 2. Edit Post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/edit',
        json={'content': 'Updated news team!'}
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    # 3. React Post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/react',
        json={'emoji': '🎉'}
    )
    assert resp.status_code == 200
    assert '🎉' in resp.get_json()['reactions']

    # 4. Comment on Post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/comment',
        json={'content': 'Awesome work!'}
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert resp.get_json()['comment']['content'] == 'Awesome work!'

    # 5. Delete Post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/delete',
        json={}
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert m.circle_posts_conf.delete_one.called


def test_poll_options_and_voting(auth_client, mock_user, circle_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }

    m.circles_conf.find_one.return_value = circle_doc

    # 1. Create poll with 4 options
    resp = auth_client.post(
        f'/circle/{circle_id}/polls',
        data={
            'question': 'Best movie tonight?',
            'options': ['Movie A', 'Movie B', 'Movie C', 'Movie D']
        }
    )
    assert resp.status_code == 302
    assert m.circle_posts_conf.insert_one.called
    inserted_doc = m.circle_posts_conf.insert_one.call_args[0][0]
    assert inserted_doc['kind'] == 'poll'

    # 2. Vote on poll
    poll_id = ObjectId('507f1f77bcf86cd799439066')
    poll_payload = json.dumps({
        'question': 'Best movie tonight?',
        'options': ['Movie A', 'Movie B', 'Movie C', 'Movie D'],
        'votes': {}
    })
    poll_post = {
        '_id': poll_id,
        'circle_id': circle_id,
        'kind': 'poll',
        'content': encrypt_community_note(poll_payload, circle_id)
    }

    m.circle_posts_conf.find_one.return_value = poll_post
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{poll_id}/vote',
        json={'option': 2}
    )
    assert resp.status_code == 200
    assert resp.get_json()['my_vote'] == 2
    assert m.circle_posts_conf.update_one.called


def test_create_and_join_open_circle(auth_client, mock_user, circle_id, other_user_id):
    import main as m
    # 1. Create open circle
    m.circles_conf.insert_one.return_value.inserted_id = circle_id
    resp = auth_client.post('/circles/create', data={
        'name': 'Open Community Hub',
        'circle_type': 'hobby',
        'visibility': 'open',
        'approval_required': '0'
    })
    assert resp.status_code == 302
    assert m.circles_conf.insert_one.called
    insert_doc = m.circles_conf.insert_one.call_args[0][0]
    assert insert_doc['visibility'] == 'open'

    # 2. Join open circle as new member
    open_circle = {
        '_id': circle_id,
        'name': 'Open Community Hub',
        'visibility': 'open',
        'members': [other_user_id],
        'roles': {str(other_user_id): 'owner'}
    }
    m.circles_conf.find_one.return_value = open_circle
    join_resp = auth_client.post(f'/circle/{circle_id}/join')
    assert join_resp.status_code == 302
    assert f'/circle/{circle_id}' in join_resp.location
    assert m.circles_conf.update_one.called
    update_args = m.circles_conf.update_one.call_args[0]
    assert update_args[1]['$addToSet']['members'] == mock_user['_id']


def test_nested_comment_lifecycle(auth_client, mock_user, circle_id):
    import main as m
    circle_doc = {
        '_id': circle_id,
        'owner_id': mock_user['_id'],
        'members': [mock_user['_id']],
        'roles': {str(mock_user['_id']): 'owner'}
    }
    m.circles_conf.find_one.return_value = circle_doc

    post_id = ObjectId('507f1f77bcf86cd799439077')
    parent_comment_id = 'parent123'
    post_doc = {
        '_id': post_id,
        'circle_id': circle_id,
        'author_id': mock_user['_id'],
        'content': encrypt_community_note('A great post', circle_id),
        'comments': [
            {
                'id': parent_comment_id,
                'author_id': mock_user['_id'],
                'author_name': 'testuser',
                'content': encrypt_community_note('Top comment', circle_id),
                'created_at': datetime.datetime.now(datetime.timezone.utc)
            }
        ]
    }
    m.circle_posts_conf.find_one.return_value = post_doc

    # Post nested reply
    resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/comment',
        json={
            'content': 'This is a nested reply',
            'parent_id': parent_comment_id
        }
    )
    assert resp.status_code == 200
    res_data = resp.get_json()
    assert res_data['success'] is True
    assert res_data['comment']['parent_id'] == parent_comment_id
    assert res_data['comment']['reply_to_author'] == 'testuser'
    assert m.circle_posts_conf.update_one.called
    update_doc = m.circle_posts_conf.update_one.call_args[0][1]['$push']['comments']
    assert update_doc['parent_id'] == parent_comment_id
    assert update_doc['reply_to_author'] == 'testuser'

    # Delete comment
    del_resp = auth_client.post(
        f'/circle/{circle_id}/posts/{post_id}/comments/{parent_comment_id}/delete',
        json={}
    )
    assert del_resp.status_code == 200
    assert del_resp.get_json()['success'] is True

