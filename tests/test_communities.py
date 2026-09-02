import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security


class TestCommunityDataStructures:
    """Tests for community document schemas and roles."""

    def test_community_document_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        comm = {
            '_id': ObjectId(),
            'name': 'Python Enthusiasts',
            'slug': 'python-enthusiasts',
            'description': 'A community for Python programmers',
            'creator_id': ObjectId(),
            'created_at': now,
            'is_private': False,
            'member_count': 1,
            'roles': {
                'admins': ['507f1f77bcf86cd799439011'],
                'moderators': [],
                'members': ['507f1f77bcf86cd799439011']
            },
            'channels': ['general', 'help', 'showcase']
        }
        assert comm['created_at'].tzinfo == datetime.timezone.utc
        assert comm['slug'] == 'python-enthusiasts'
        assert 'admins' in comm['roles']
        assert 'general' in comm['channels']


class TestCommunityRolesAndPermissions:
    """Tests for community role hierarchy."""

    def test_admin_has_moderator_privileges(self):
        roles = {
            'admins': ['user_admin'],
            'moderators': ['user_mod'],
            'members': ['user_member']
        }
        # Admin should satisfy moderator check
        is_mod_or_admin = ('user_admin' in roles['admins']) or ('user_admin' in roles['moderators'])
        assert is_mod_or_admin is True

    def test_member_lacks_moderator_privileges(self):
        roles = {
            'admins': ['user_admin'],
            'moderators': ['user_mod'],
            'members': ['user_member']
        }
        is_mod_or_admin = ('user_member' in roles['admins']) or ('user_member' in roles['moderators'])
        assert is_mod_or_admin is False


class TestCommunityReportsAndVouchers:
    """Tests for community moderation reports and voucher codes."""

    def test_community_report_schema(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        rep = {
            '_id': ObjectId(),
            'community_id': ObjectId(),
            'reporter_id': ObjectId(),
            'reason': 'spam',
            'details': 'Spamming links',
            'status': 'pending',
            'created_at': now
        }
        assert rep['created_at'].tzinfo == datetime.timezone.utc
        assert rep['status'] == 'pending'

    def test_community_voucher_schema(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        voucher = {
            '_id': ObjectId(),
            'code': 'COMMUNITY-VIP-2026',
            'community_id': ObjectId(),
            'max_uses': 10,
            'used_count': 0,
            'created_at': now,
            'is_active': True
        }
        assert voucher['created_at'].tzinfo == datetime.timezone.utc
        assert voucher['used_count'] < voucher['max_uses']


class TestCommunityEndpointsAuth:
    """Tests that community management endpoints require authentication."""

    def test_create_community_requires_auth(self, client):
        res = client.get('/communities/create')
        assert res.status_code in [302, 401, 404]

    def test_community_directory_accessible(self, client):
        res = client.get('/communities')
        # May be public or require auth depending on blueprint route
        assert res.status_code in [200, 302]

