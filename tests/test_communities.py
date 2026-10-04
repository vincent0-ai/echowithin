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


class TestCommunityPurgeAndOrphans:
    """Tests for community purge, orphan pruning, and admin deletion handling."""

    def test_purge_community_data_removes_all_subcollections(self, monkeypatch):
        import main as m
        from utils import purge_community_data

        comm_id = ObjectId()
        mock_comms = MagicMock()
        mock_notes = MagicMock()
        mock_reactions = MagicMock()
        mock_resources = MagicMock()
        mock_challenges = MagicMock()
        mock_polls = MagicMock()
        mock_poll_votes = MagicMock()
        mock_checkins = MagicMock()
        mock_reports = MagicMock()
        mock_tournaments = MagicMock()
        mock_vouchers = MagicMock()
        mock_memberships = MagicMock()

        mock_comms.find_one.return_value = {'_id': comm_id, 'name': 'Test Comm'}
        mock_resources.find.return_value = []
        mock_notes.find.return_value = []
        mock_polls.find.return_value = []

        monkeypatch.setattr(m, 'communities_conf', mock_comms)
        monkeypatch.setattr(m, 'community_notes_conf', mock_notes)
        monkeypatch.setattr(m, 'community_reactions_conf', mock_reactions)
        monkeypatch.setattr(m, 'community_resources_conf', mock_resources)
        monkeypatch.setattr(m, 'community_challenges_conf', mock_challenges)
        monkeypatch.setattr(m, 'community_polls_conf', mock_polls)
        monkeypatch.setattr(m, 'community_poll_votes_conf', mock_poll_votes)
        monkeypatch.setattr(m, 'community_checkins_conf', mock_checkins)
        monkeypatch.setattr(m, 'community_reports_conf', mock_reports)
        monkeypatch.setattr(m, 'community_tournaments_conf', mock_tournaments)
        monkeypatch.setattr(m, 'community_premium_vouchers_conf', mock_vouchers)
        monkeypatch.setattr(m, 'community_memberships_conf', mock_memberships)

        res = purge_community_data(comm_id)
        assert res is True
        mock_comms.delete_one.assert_called_once_with({'_id': comm_id})
        mock_resources.delete_many.assert_called_once_with({'community_id': comm_id})
        mock_notes.delete_many.assert_called_once_with({'community_id': comm_id})
        mock_challenges.delete_many.assert_called_once_with({'community_id': comm_id})
        mock_polls.delete_many.assert_called_once_with({'community_id': comm_id})

    def test_prune_orphaned_communities_purges_zero_members(self, monkeypatch):
        import main as m
        from utils import prune_orphaned_communities

        comm1_id = ObjectId()
        mock_comms = MagicMock()
        mock_users = MagicMock()

        # comm1 has empty members
        mock_comms.find.return_value = [
            {'_id': comm1_id, 'name': 'Pedro Miguel', 'admin_id': None, 'members': []}
        ]
        mock_comms.find_one.return_value = {'_id': comm1_id, 'name': 'Pedro Miguel'}
        mock_users.find_one.return_value = None

        monkeypatch.setattr(m, 'communities_conf', mock_comms)
        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr(m, 'community_resources_conf', MagicMock())
        monkeypatch.setattr(m, 'community_notes_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reactions_conf', MagicMock())
        monkeypatch.setattr(m, 'community_challenges_conf', MagicMock())
        monkeypatch.setattr(m, 'community_polls_conf', MagicMock())
        monkeypatch.setattr(m, 'community_poll_votes_conf', MagicMock())
        monkeypatch.setattr(m, 'community_checkins_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reports_conf', MagicMock())
        monkeypatch.setattr(m, 'community_tournaments_conf', MagicMock())
        monkeypatch.setattr(m, 'community_premium_vouchers_conf', MagicMock())
        monkeypatch.setattr(m, 'community_memberships_conf', MagicMock())

        pruned = prune_orphaned_communities()
        assert pruned == 1
        mock_comms.delete_one.assert_called_once_with({'_id': comm1_id})

    def test_prune_orphaned_communities_reassigns_admin_if_members_remain(self, monkeypatch):
        import main as m
        from utils import prune_orphaned_communities

        comm2_id = ObjectId()
        member_id = ObjectId()
        mock_comms = MagicMock()
        mock_users = MagicMock()

        # comm2 has admin_id=None, but member_id is still a valid active user
        mock_comms.find.return_value = [
            {'_id': comm2_id, 'name': 'Active Comm', 'admin_id': None, 'members': [member_id], 'moderators': []}
        ]
        mock_users.find_one.side_effect = lambda q, proj=None: {'_id': member_id} if q.get('_id') == member_id else None

        monkeypatch.setattr(m, 'communities_conf', mock_comms)
        monkeypatch.setattr(m, 'users_conf', mock_users)

        pruned = prune_orphaned_communities()
        assert pruned == 0
        mock_comms.update_one.assert_called_once_with(
            {'_id': comm2_id},
            {'$set': {'admin_id': member_id, 'moderators': []}}
        )

    def test_cascade_delete_purges_admin_sole_community(self, monkeypatch):
        import main as m
        from utils import cascade_delete_user_data

        user_id = ObjectId()
        comm_id = ObjectId()
        mock_comms = MagicMock()
        mock_users = MagicMock()

        # User is admin and only member
        mock_comms.find.side_effect = lambda q, *args: (
            [{'_id': comm_id, 'admin_id': user_id, 'members': [user_id], 'moderators': []}]
            if q.get('admin_id') == user_id
            else []
        )
        mock_comms.find_one.return_value = {'_id': comm_id}
        mock_users.find_one.return_value = {'_id': user_id, 'email': 'pedro@example.com'}

        monkeypatch.setattr(m, 'communities_conf', mock_comms)
        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr(m, 'auth_conf', MagicMock())
        monkeypatch.setattr(m, 'user_sessions_conf', MagicMock())
        monkeypatch.setattr(m, 'app_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'fcm_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'push_subscriptions_conf', MagicMock())
        monkeypatch.setattr(m, 'posts_conf', MagicMock())
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'comment_votes_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock())
        monkeypatch.setattr(m, 'unlock_notifications_conf', MagicMock())
        monkeypatch.setattr(m, 'personal_posts_conf', MagicMock())
        monkeypatch.setattr(m, 'note_attachments_conf', MagicMock())
        monkeypatch.setattr(m, 'note_shares_conf', MagicMock())
        monkeypatch.setattr(m, 'note_versions_conf', MagicMock())
        monkeypatch.setattr(m, 'note_discussions_conf', MagicMock())
        monkeypatch.setattr(m, 'direct_messages_conf', MagicMock())
        monkeypatch.setattr(m, 'hidden_chats_conf', MagicMock())
        monkeypatch.setattr(m, 'whisper_sessions_conf', MagicMock())
        monkeypatch.setattr(m, 'whisper_messages_conf', MagicMock())
        monkeypatch.setattr(m, 'bonds_conf', MagicMock())
        monkeypatch.setattr(m, 'community_memberships_conf', MagicMock())
        monkeypatch.setattr(m, 'community_notes_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reactions_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reports_conf', MagicMock())
        monkeypatch.setattr(m, 'community_poll_votes_conf', MagicMock())
        monkeypatch.setattr(m, 'community_checkins_conf', MagicMock())
        monkeypatch.setattr(m, 'community_resources_conf', MagicMock())
        monkeypatch.setattr(m, 'community_challenges_conf', MagicMock())
        monkeypatch.setattr(m, 'community_polls_conf', MagicMock())
        monkeypatch.setattr(m, 'community_tournaments_conf', MagicMock())
        monkeypatch.setattr(m, 'community_premium_vouchers_conf', MagicMock())
        monkeypatch.setattr(m, 'logs_conf', MagicMock())
        monkeypatch.setattr(m, 'activities_conf', MagicMock())
        monkeypatch.setattr(m, 'activity_read_conf', MagicMock())
        monkeypatch.setattr(m, 'payment_grants_conf', MagicMock())
        monkeypatch.setattr(m, 'newsletter_conf', MagicMock())
        monkeypatch.setattr(m, 'account_deletions_conf', MagicMock())

        cascade_delete_user_data(user_id)
        # Should have purged the community because user was sole member
        mock_comms.delete_one.assert_called_with({'_id': comm_id})

