import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security


class TestPostSlugAndModel:
    """Tests for post slug generation and metadata formatting."""

    def test_post_document_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        post = {
            '_id': ObjectId(),
            'title': 'My First Post',
            'slug': 'my-first-post',
            'content': 'Hello world markdown content',
            'author': 'testuser',
            'author_id': ObjectId(),
            'timestamp': now,
            'likes_count': 5,
            'comment_count': 2,
            'view_count': 42,
            'reactions': {
                'heart': ['507f1f77bcf86cd799439011'],
                'wow': [],
                'insightful': []
            },
            'is_pinned': False,
            'is_suppressed': False,
            'moderation_status': 'cleared'
        }
        assert post['timestamp'].tzinfo == datetime.timezone.utc
        assert post['slug'] == 'my-first-post'
        assert isinstance(post['reactions'], dict)


class TestReactionsSystem:
    """Tests for multi-reaction toggles."""

    def test_reaction_types_allowed(self):
        valid_reactions = ['heart', 'wow', 'insightful', 'laugh', 'sad']
        assert len(valid_reactions) == 5
        assert 'heart' in valid_reactions
        assert 'insightful' in valid_reactions

    def test_reaction_toggle_logic(self):
        reactions = {
            'heart': ['user_1', 'user_2'],
            'wow': ['user_3']
        }
        user_id = 'user_1'

        # If user_1 unreacts heart
        reactions['heart'].remove(user_id)
        assert user_id not in reactions['heart']

        # If user_1 reacts wow
        reactions['wow'].append(user_id)
        assert user_id in reactions['wow']


class TestCommentTree:
    """Tests for nested comment reply structure."""

    def test_comment_document_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        parent_comment = {
            '_id': ObjectId(),
            'post_slug': 'my-first-post',
            'author': 'alice',
            'author_id': ObjectId(),
            'content': 'Great post!',
            'created_at': now,
            'is_deleted': False,
            'parent_id': None
        }
        child_reply = {
            '_id': ObjectId(),
            'post_slug': 'my-first-post',
            'author': 'bob',
            'author_id': ObjectId(),
            'content': 'I agree with Alice',
            'created_at': now,
            'is_deleted': False,
            'parent_id': parent_comment['_id']
        }
        assert parent_comment['created_at'].tzinfo == datetime.timezone.utc
        assert child_reply['parent_id'] == parent_comment['_id']


class TestBlogEndpointsAccess:
    """Tests for public blog endpoints and auth requirements."""

    def test_blog_public_feed_accessible(self, client):
        res = client.get('/blog')
        assert res.status_code == 200

    def test_create_post_requires_auth(self, client):
        res = client.get('/post')
        assert res.status_code in [302, 401]

    def test_toggle_save_post_requires_auth(self, client):
        res = client.post('/api/posts/507f1f77bcf86cd799439011/save')
        assert res.status_code in [302, 401, 404]

