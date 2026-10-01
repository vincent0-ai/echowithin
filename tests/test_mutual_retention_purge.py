import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock

import main as m
from utils import (
    purge_bond_data,
    purge_direct_messages_between,
    cascade_delete_user_data,
)


class TestMutualRetentionAndPurge:
    """Tests for mutual data retention and zero hanging data permanent purge."""

    def test_purge_bond_data_clears_all_subcollections(self, monkeypatch):
        bond_id = ObjectId()
        mock_bonds = MagicMock()
        mock_goals = MagicMock()
        mock_journal = MagicMock()
        mock_moods = MagicMock()
        mock_qotd = MagicMock()
        mock_habits = MagicMock()
        mock_countdowns = MagicMock()
        mock_photos = MagicMock()
        mock_bucketlist = MagicMock()
        mock_recs = MagicMock()
        mock_pulses = MagicMock()

        mock_photos.find.return_value = []
        mock_recs.find.return_value = []

        monkeypatch.setattr(m, 'bonds_conf', mock_bonds)
        monkeypatch.setattr(m, 'bond_goals_conf', mock_goals)
        monkeypatch.setattr(m, 'bond_journal_conf', mock_journal)
        monkeypatch.setattr(m, 'bond_moods_conf', mock_moods)
        monkeypatch.setattr(m, 'bond_qotd_conf', mock_qotd)
        monkeypatch.setattr(m, 'bond_habits_conf', mock_habits)
        monkeypatch.setattr(m, 'bond_countdowns_conf', mock_countdowns)
        monkeypatch.setattr(m, 'bond_album_photos_conf', mock_photos)
        monkeypatch.setattr(m, 'bond_bucketlist_conf', mock_bucketlist)
        monkeypatch.setattr(m, 'bond_recommendations_conf', mock_recs)
        monkeypatch.setattr(m, 'bond_pulses_conf', mock_pulses)

        purge_bond_data(bond_id)

        mock_bonds.delete_one.assert_called_once_with({'_id': bond_id})
        mock_goals.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_journal.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_moods.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_qotd.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_habits.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_countdowns.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_photos.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_bucketlist.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_recs.delete_many.assert_called_once_with({'bond_id': bond_id})
        mock_pulses.delete_many.assert_called_once_with({'bond_id': bond_id})

    def test_purge_direct_messages_between_clears_all_records(self, monkeypatch):
        u_a = ObjectId()
        u_b = ObjectId()
        mock_dms = MagicMock()
        mock_sched = MagicMock()
        mock_hidden = MagicMock()
        mock_perms = MagicMock()

        mock_dms.find.return_value = []

        monkeypatch.setattr(m, 'direct_messages_conf', mock_dms)
        monkeypatch.setattr(m, 'scheduled_messages_conf', mock_sched)
        monkeypatch.setattr(m, 'hidden_chats_conf', mock_hidden)
        monkeypatch.setattr(m, 'dm_permissions_conf', mock_perms)

        purge_direct_messages_between(u_a, u_b)

        mock_dms.delete_many.assert_called_once()
        mock_sched.delete_many.assert_called_once()
        mock_hidden.delete_many.assert_called_once()
        mock_perms.delete_many.assert_called_once()

    def test_cascade_delete_retains_for_active_partner(self, monkeypatch):
        u_a = ObjectId()
        u_b = ObjectId()
        bond_id = ObjectId()

        user_doc_a = {'_id': u_a, 'email': 'a@example.com'}
        partner_doc_b = {'_id': u_b, 'username': 'partner_b'}
        bond_doc = {'_id': bond_id, 'user_a_id': u_a, 'user_b_id': u_b, 'dismissed_by': []}

        mock_users = MagicMock()
        mock_users.find_one.side_effect = lambda q, *a, **kw: partner_doc_b if q.get('_id') == u_b else user_doc_a

        mock_dms = MagicMock()
        mock_dms.find.return_value = [{'_id': ObjectId(), 'sender_id': u_a, 'recipient_id': u_b}]

        mock_hidden = MagicMock()
        mock_hidden.find_one.return_value = None

        mock_bonds = MagicMock()
        mock_bonds.find.return_value = [bond_doc]

        mock_purge_dm = MagicMock()
        mock_purge_bond = MagicMock()

        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr(m, 'direct_messages_conf', mock_dms)
        monkeypatch.setattr(m, 'hidden_chats_conf', mock_hidden)
        monkeypatch.setattr(m, 'bonds_conf', mock_bonds)
        monkeypatch.setattr('utils.purge_direct_messages_between', mock_purge_dm)
        monkeypatch.setattr('utils.purge_bond_data', mock_purge_bond)
        monkeypatch.setattr(m, 'auth_conf', MagicMock())
        monkeypatch.setattr(m, 'user_sessions_conf', MagicMock())
        monkeypatch.setattr(m, 'app_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'fcm_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'push_subscriptions_conf', MagicMock())
        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'comment_votes_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock())
        monkeypatch.setattr(m, 'unlock_notifications_conf', MagicMock())
        monkeypatch.setattr(m, 'personal_posts_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'note_attachments_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'note_shares_conf', MagicMock())
        monkeypatch.setattr(m, 'whisper_sessions_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'whisper_messages_conf', MagicMock())
        monkeypatch.setattr(m, 'communities_conf', MagicMock())
        monkeypatch.setattr(m, 'community_memberships_conf', MagicMock())
        monkeypatch.setattr(m, 'community_notes_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'community_reactions_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reports_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_goals_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_journal_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_moods_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_qotd_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_habits_conf', MagicMock())
        monkeypatch.setattr(m, 'bond_countdowns_conf', MagicMock())

        cascade_delete_user_data(u_a)

        # Partner B is active and holding chat -> do not purge DMs, hide for u_a
        mock_purge_dm.assert_not_called()
        mock_hidden.update_one.assert_called_once()

        # Partner B is active and holding bond -> do not purge bond, archive for B
        mock_purge_bond.assert_not_called()
        mock_bonds.update_one.assert_called_once()
        set_args = mock_bonds.update_one.call_args[0][1]['$set']
        assert set_args['status'] == 'broken'
        assert set_args['partner_account_deleted'] is True

    def test_cascade_delete_purges_when_partner_already_deleted(self, monkeypatch):
        u_a = ObjectId()
        u_b = ObjectId()
        bond_id = ObjectId()

        user_doc_a = {'_id': u_a, 'email': 'a@example.com'}
        bond_doc = {'_id': bond_id, 'user_a_id': u_a, 'user_b_id': u_b, 'dismissed_by': []}

        mock_users = MagicMock()
        mock_users.find_one.side_effect = lambda q, *a, **kw: None if q.get('_id') == u_b else user_doc_a

        mock_dms = MagicMock()
        mock_dms.find.return_value = [{'_id': ObjectId(), 'sender_id': u_a, 'recipient_id': u_b}]

        mock_hidden = MagicMock()
        mock_hidden.find_one.return_value = None

        mock_bonds = MagicMock()
        mock_bonds.find.return_value = [bond_doc]

        mock_purge_dm = MagicMock()
        mock_purge_bond = MagicMock()

        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr(m, 'direct_messages_conf', mock_dms)
        monkeypatch.setattr(m, 'hidden_chats_conf', mock_hidden)
        monkeypatch.setattr(m, 'bonds_conf', mock_bonds)
        monkeypatch.setattr('utils.purge_direct_messages_between', mock_purge_dm)
        monkeypatch.setattr('utils.purge_bond_data', mock_purge_bond)
        monkeypatch.setattr(m, 'auth_conf', MagicMock())
        monkeypatch.setattr(m, 'user_sessions_conf', MagicMock())
        monkeypatch.setattr(m, 'app_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'fcm_tokens_conf', MagicMock())
        monkeypatch.setattr(m, 'push_subscriptions_conf', MagicMock())
        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'comment_votes_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock())
        monkeypatch.setattr(m, 'unlock_notifications_conf', MagicMock())
        monkeypatch.setattr(m, 'personal_posts_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'note_attachments_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'note_shares_conf', MagicMock())
        monkeypatch.setattr(m, 'whisper_sessions_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'whisper_messages_conf', MagicMock())
        monkeypatch.setattr(m, 'communities_conf', MagicMock())
        monkeypatch.setattr(m, 'community_memberships_conf', MagicMock())
        monkeypatch.setattr(m, 'community_notes_conf', MagicMock(find=MagicMock(return_value=[])))
        monkeypatch.setattr(m, 'community_reactions_conf', MagicMock())
        monkeypatch.setattr(m, 'community_reports_conf', MagicMock())

        cascade_delete_user_data(u_a)

        # Partner B was deleted -> neither user is holding -> purge permanently!
        mock_purge_dm.assert_called_once_with(u_a, u_b)
        mock_purge_bond.assert_called_once_with(bond_id)

    def test_api_bond_dismiss_archive_purges_when_partner_deleted(self, auth_client, mock_user, monkeypatch):
        user_id = mock_user['_id']
        partner_id = ObjectId()
        bond_id = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_id,
            'user_b_id': partner_id,
            'status': 'broken',
            'partner_account_deleted': True,
            'dismissed_by': []
        }

        mock_bonds = MagicMock()
        mock_bonds.find_one.return_value = bond_doc
        mock_users = MagicMock()
        mock_users.find_one.return_value = None
        mock_purge_bond = MagicMock()

        monkeypatch.setattr(m, 'bonds_conf', mock_bonds)
        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr('utils.purge_bond_data', mock_purge_bond)

        resp = auth_client.post(f'/api/bonds/{bond_id}/dismiss-archive')
        assert resp.status_code == 200
        assert resp.get_json().get('success') is True
        mock_bonds.update_one.assert_called_once()
        mock_purge_bond.assert_called_once_with(bond_id)

    def test_api_delete_chat_purges_when_partner_deleted(self, auth_client, mock_user, monkeypatch):
        user_id = mock_user['_id']
        partner_id = ObjectId()

        mock_hidden = MagicMock()
        mock_hidden.find_one.return_value = None
        mock_users = MagicMock()
        mock_users.find_one.return_value = None
        mock_socketio = MagicMock()
        mock_purge_dm = MagicMock()

        monkeypatch.setattr(m, 'hidden_chats_conf', mock_hidden)
        monkeypatch.setattr(m, 'users_conf', mock_users)
        monkeypatch.setattr(m, 'socketio', mock_socketio)
        monkeypatch.setattr('utils.purge_direct_messages_between', mock_purge_dm)

        resp = auth_client.post(f'/api/messages/chat/delete/{partner_id}')
        assert resp.status_code == 200
        assert resp.get_json().get('success') is True
        mock_purge_dm.assert_called_once_with(user_id, partner_id)
