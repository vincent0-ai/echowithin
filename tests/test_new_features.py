import datetime
import pytest
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import json


class TestCalendarReminders:
    """Test calendar event reminder offset storage and reminder job dispatch."""

    def test_calendar_reminder_offset_calculation(self):
        from scripts.calendar_reminders import _get_candidate_occurrence_dates

        today = datetime.date(2026, 9, 5)
        start_date = datetime.date(2026, 9, 5)

        # None recurrence returns exact start date
        candidates_none = _get_candidate_occurrence_dates(start_date, 'none', today)
        assert candidates_none == [start_date]

        # Weekly recurrence returns occurrences in window
        start_weekly = datetime.date(2026, 8, 29)  # 7 days ago
        candidates_weekly = _get_candidate_occurrence_dates(start_weekly, 'weekly', today)
        assert datetime.date(2026, 9, 5) in candidates_weekly

    def test_calendar_reminders_dispatch(self):
        import main as m
        from scripts.calendar_reminders import run_calendar_reminders

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        today = now_utc.date()
        target_event_time = (now_utc + datetime.timedelta(minutes=30)).strftime("%H:%M")

        bond_id = ObjectId()
        user1_id = ObjectId()
        user2_id = ObjectId()

        mock_bond = {
            '_id': bond_id,
            'status': 'active',
            'user1_id': user1_id,
            'user2_id': user2_id
        }

        mock_event = {
            '_id': ObjectId(),
            'bond_id': bond_id,
            'title': 'Dinner Date',
            'start_date': today.isoformat(),
            'time': target_event_time,
            'recurrence': 'none',
            'reminder_offset': 60,  # 1 hour before (target is 30 mins from now, so window is active)
            'reminders_sent': [],
            'archived': False,
            'encrypted': False,
            'rsvps': {}
        }

        mock_bonds_conf = MagicMock()
        mock_bonds_conf.find.return_value = [mock_bond]

        mock_events_conf = MagicMock()
        mock_events_conf.find.return_value = [mock_event]

        mock_push = MagicMock()

        with patch.object(m, 'bonds_conf', mock_bonds_conf), \
             patch.object(m, 'bond_events_conf', mock_events_conf), \
             patch.object(m, 'send_push_notification_to_user', mock_push):

            count = run_calendar_reminders()
            assert count == 1
            assert mock_push.call_count == 2
            # Verify category is calendar
            call_kwargs = mock_push.call_args[1]
            assert call_kwargs.get('category') == 'calendar'
            # Verify reminders_sent was updated
            mock_events_conf.update_one.assert_called_once()


class TestGranularNotificationPreferences:
    """Test granular notification preferences API and category filtering."""

    def test_default_preferences_contain_all_eight_categories(self, auth_client, app):
        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-token'

        res = auth_client.get('/api/push/preferences')
        assert res.status_code == 200
        data = res.get_json()
        assert 'preferences' in data
        prefs = data['preferences']
        expected_categories = ['dms', 'whispers', 'bonds', 'anniversaries', 'calendar', 'forms', 'games', 'community']
        for cat in expected_categories:
            assert cat in prefs
            assert prefs[cat] is True

    def test_update_preferences_merges_without_clobbering(self, auth_client, app):
        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-token'

        # Mute games and calendar
        res = auth_client.post('/api/push/preferences',
                               data=json.dumps({'games': False, 'calendar': False}),
                               content_type='application/json')
        assert res.status_code == 200
        data = res.get_json()
        prefs = data['preferences']
        assert prefs['games'] is False
        assert prefs['calendar'] is False
        assert prefs['dms'] is True
        assert prefs['forms'] is True

    def test_send_push_notification_respects_category_mute(self):
        import database
        import notifications

        user_id = ObjectId()
        user_id_str = str(user_id)

        mock_users_conf = MagicMock()
        # User has muted calendar and forms
        mock_users_conf.find_one.return_value = {
            '_id': user_id,
            'notification_preferences': {
                'calendar': False,
                'forms': False,
                'dms': True
            }
        }

        mock_subs_conf = MagicMock()

        with patch.object(database, 'users_conf', mock_users_conf), \
             patch.object(database, 'push_subscriptions_conf', mock_subs_conf), \
             patch.object(notifications, 'VAPID_PRIVATE_KEY', 'dummy_private_key'), \
             patch.object(notifications, 'VAPID_PUBLIC_KEY', 'dummy_public_key'):

            # Explicit category = 'calendar' should be blocked
            notifications.send_push_notification_to_user(user_id_str, "Reminder", "Event starting", category='calendar')
            mock_subs_conf.find.assert_not_called()

            # Inferred category from tag = 'form-response-123' should be blocked
            notifications.send_push_notification_to_user(user_id_str, "New Form Response", "Someone replied", tag='form-response-123')
            mock_subs_conf.find.assert_not_called()

            # Allowed category = 'dms' should proceed to fetch subscriptions
            notifications.send_push_notification_to_user(user_id_str, "New Message", "Hello", category='dms')
            mock_subs_conf.find.assert_called_once()


class TestFormResponseNotifications:
    """Test push notifications sent to form owners on new responses."""

    def test_submit_form_response_notifies_owner(self, client, app):
        import main as m

        owner_id = ObjectId()
        form_id = ObjectId()
        share_id = 'testform123'

        mock_form = {
            '_id': form_id,
            'share_id': share_id,
            'owner_id': owner_id,
            'title': 'Customer Feedback',
            'questions': [{'id': 'q1', 'label': 'Feedback', 'type': 'short_text', 'required': False}],
            'allow_anonymous': True,
            'response_count': 0
        }

        mock_forms_conf = MagicMock()
        mock_forms_conf.find_one.return_value = mock_form
        mock_responses_conf = MagicMock()
        mock_push = MagicMock()

        with patch.object(m, 'forms_conf', mock_forms_conf), \
             patch.object(m, 'form_responses_conf', mock_responses_conf), \
             patch.object(m, 'send_push_notification_to_user', mock_push):

            res = client.post(f'/f/{share_id}/submit',
                              data=json.dumps({'q_q1': 'Great platform!'}),
                              content_type='application/json')
            assert res.status_code == 200

            # Push should be sent to form owner
            mock_push.assert_called_once()
            args, kwargs = mock_push.call_args
            assert args[0] == str(owner_id)
            assert kwargs.get('category') == 'forms'
            assert 'Customer Feedback' in args[1]


class TestGameInviteDM:
    """Test game invite DM handling, serialization, and lobby querying."""

    def test_api_my_game_lobbies(self, auth_client, app):
        import main as m

        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-token'

        mock_lobby = {
            '_id': ObjectId(),
            'lobby_id': 'lobby_xyz',
            'game_type': 'trivia',
            'title': 'Friday Trivia',
            'host_id': ObjectId(),
            'deactivated': False,
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2),
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        }

        mock_sessions_conf = MagicMock()
        mock_sessions_conf.find.return_value.sort.return_value.limit.return_value = [mock_lobby]

        with patch.object(m, 'game_sessions_conf', mock_sessions_conf):
            res = auth_client.get('/api/games/my_lobbies')
            assert res.status_code == 200
            data = res.get_json()
            assert 'lobbies' in data
            assert len(data['lobbies']) == 1
            assert data['lobbies'][0]['lobby_id'] == 'lobby_xyz'
            assert data['lobbies'][0]['title'] == 'Friday Trivia'

    def test_message_history_serializes_game_data(self, auth_client, app):
        import main as m

        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-token'

        target_user_id = ObjectId()
        now = datetime.datetime.now(datetime.timezone.utc)

        mock_msg = {
            '_id': ObjectId(),
            'sender_id': ObjectId(),
            'recipient_id': target_user_id,
            'content': 'Invited you to play Trivia',
            'timestamp': now,
            'is_read': False,
            'message_type': 'game_invite',
            'game_data': {
                'lobby_id': 'lobby_xyz',
                'game_type': 'trivia',
                'title': 'Friday Trivia'
            }
        }

        mock_messages_conf = MagicMock()
        mock_messages_conf.find.return_value.sort.return_value.limit.return_value = [mock_msg]

        mock_users_conf = MagicMock()
        mock_users_conf.find_one.return_value = {'_id': target_user_id, 'username': 'target_user'}

        mock_hidden = MagicMock()
        mock_hidden.find_one.return_value = None

        with patch.object(m, 'direct_messages_conf', mock_messages_conf), \
             patch.object(m, 'users_conf', mock_users_conf), \
             patch.object(m, 'can_dm', return_value=True), \
             patch.object(m, 'hidden_chats_conf', mock_hidden):

            res = auth_client.get(f'/api/messages/history/{target_user_id}')
            assert res.status_code == 200
            data = res.get_json()
            assert 'messages' in data
            assert len(data['messages']) == 1
            item = data['messages'][0]
            assert item['message_type'] == 'game_invite'
            assert 'game_data' in item
            assert item['game_data']['lobby_id'] == 'lobby_xyz'
            assert item['game_data']['title'] == 'Friday Trivia'
