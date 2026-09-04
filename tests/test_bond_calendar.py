import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import patch, MagicMock
from security import encrypt_bond_data, decrypt_bond_data
from blueprints.bonds import (
    _expand_event_dates,
    _get_live_countdown_label,
    _get_aggregated_bond_calendar,
    BOND_SECTIONS,
)
from config import TIER_LIMITS


class TestBondCalendarEncryption:
    """Tests for per-bond Fernet encryption at rest for calendar events."""

    def test_encrypt_event_data_produces_fernet_ciphertext(self, app):
        bond_id = str(ObjectId())
        title = "Romantic Candlelit Dinner"
        with app.app_context():
            ciphertext = encrypt_bond_data(title, bond_id)
            assert ciphertext != title
            assert ciphertext.startswith("gAAAAA")
            decrypted = decrypt_bond_data(ciphertext, bond_id)
            assert decrypted == title

    def test_cross_bond_decryption_cannot_read(self, app):
        bond1_id = str(ObjectId())
        bond2_id = str(ObjectId())
        secret_event = "Secret Surprise Party"
        with app.app_context():
            cipher1 = encrypt_bond_data(secret_event, bond1_id)
            # Decrypting with bond2 key fails or falls back to error marker
            decrypted_by_bond2 = decrypt_bond_data(cipher1, bond2_id)
            assert decrypted_by_bond2 != secret_event
            assert decrypted_by_bond2 == '[Content unavailable — decryption error]'


class TestBondCalendarRecurrence:
    """Tests for recurring event date expansion."""

    def test_weekly_recurrence(self):
        start = datetime.date(2026, 9, 1)  # Tuesday
        r_start = datetime.date(2026, 9, 1)
        r_end = datetime.date(2026, 9, 30)
        dates = _expand_event_dates(start, 'weekly', r_start, r_end)
        # Expected Tuesdays in Sept 2026: 1, 8, 15, 22, 29
        assert len(dates) == 5
        assert dates[0] == datetime.date(2026, 9, 1)
        assert dates[-1] == datetime.date(2026, 9, 29)

    def test_monthly_recurrence(self):
        start = datetime.date(2026, 9, 15)
        r_start = datetime.date(2026, 9, 1)
        r_end = datetime.date(2026, 11, 30)
        dates = _expand_event_dates(start, 'monthly', r_start, r_end)
        assert len(dates) == 3
        assert dates[0] == datetime.date(2026, 9, 15)
        assert dates[1] == datetime.date(2026, 10, 15)
        assert dates[2] == datetime.date(2026, 11, 15)

    def test_yearly_recurrence(self):
        start = datetime.date(2025, 9, 4)
        r_start = datetime.date(2026, 1, 1)
        r_end = datetime.date(2027, 12, 31)
        dates = _expand_event_dates(start, 'yearly', r_start, r_end)
        assert len(dates) == 2
        assert dates[0] == datetime.date(2026, 9, 4)
        assert dates[1] == datetime.date(2027, 9, 4)

    def test_none_recurrence(self):
        start = datetime.date(2026, 9, 10)
        r_start = datetime.date(2026, 9, 1)
        r_end = datetime.date(2026, 9, 30)
        dates = _expand_event_dates(start, 'none', r_start, r_end)
        assert len(dates) == 1
        assert dates[0] == start


class TestBondCalendarCountdownLabels:
    """Tests for live countdown calculation."""

    def test_countdown_labels(self):
        today = datetime.date(2026, 9, 4)
        lbl_today, color_today, diff0 = _get_live_countdown_label(today, today)
        assert lbl_today == "Today!"
        assert color_today == "success"
        assert diff0 == 0

        tomorrow = today + datetime.timedelta(days=1)
        lbl_tom, color_tom, diff1 = _get_live_countdown_label(tomorrow, today)
        assert lbl_tom == "Tomorrow!"
        assert color_tom == "success"
        assert diff1 == 1

        future = today + datetime.timedelta(days=5)
        lbl_fut, color_fut, diff5 = _get_live_countdown_label(future, today)
        assert lbl_fut == "5 days left"
        assert color_fut == "primary"
        assert diff5 == 5

        past = today - datetime.timedelta(days=3)
        lbl_past, color_past, diff_past = _get_live_countdown_label(past, today)
        assert lbl_past == "3 days ago"
        assert color_past == "muted"
        assert diff_past == -3


class TestBondCalendarAggregation:
    """Tests for aggregating custom events, countdowns, goals, and anniversaries."""

    def test_aggregated_calendar_contains_all_sources(self, app):
        import main as m
        bond_id = ObjectId()
        user_a = ObjectId('507f1f77bcf86cd799439011')
        user_b = ObjectId('507f1f77bcf86cd799439022')
        today = datetime.datetime.now(datetime.timezone.utc).date()

        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_a,
            'user_b_id': user_b,
            'status': 'active',
            'accepted_at': datetime.datetime(today.year - 1, today.month, today.day, tzinfo=datetime.timezone.utc)
        }

        with app.app_context():
            enc_ev_title = encrypt_bond_data("Custom Event", str(bond_id))
            enc_cd_title = encrypt_bond_data("Paris Vacation", str(bond_id))
            enc_goal_title = encrypt_bond_data("Save 1000", str(bond_id))

            mock_events = [
                {
                    '_id': ObjectId(),
                    'bond_id': bond_id,
                    'title': enc_ev_title,
                    'start_date': today.isoformat(),
                    'recurrence': 'none',
                    'encrypted': True,
                    'created_by': user_a,
                    'archived': False
                }
            ]
            mock_countdowns = [
                {
                    '_id': ObjectId(),
                    'bond_id': bond_id,
                    'title': enc_cd_title,
                    'event_date': today + datetime.timedelta(days=3),
                    'encrypted': True,
                    'created_by': user_a,
                    'archived': False
                }
            ]
            mock_goals = [
                {
                    '_id': ObjectId(),
                    'bond_id': bond_id,
                    'title': enc_goal_title,
                    'deadline': datetime.datetime(today.year, today.month, today.day, 12, 0, tzinfo=datetime.timezone.utc) + datetime.timedelta(days=5),
                    'status': 'active',
                    'encrypted': True,
                    'proposed_by': user_b
                }
            ]

            mock_ev_conf = MagicMock()
            mock_ev_conf.find.return_value = mock_events
            mock_cd_conf = MagicMock()
            mock_cd_conf.find.return_value = mock_countdowns
            mock_goal_conf = MagicMock()
            mock_goal_conf.find.return_value = mock_goals

            with patch.object(m, 'bond_events_conf', mock_ev_conf), \
                 patch.object(m, 'bond_countdowns_conf', mock_cd_conf), \
                 patch.object(m, 'bond_goals_conf', mock_goal_conf):

                res = _get_aggregated_bond_calendar(bond_doc, None, None, user_a)
                assert res['total_events'] >= 3
                sources = {e['source'] for e in res['events']}
                assert 'custom' in sources
                assert 'countdown' in sources
                assert 'goal' in sources
                assert 'anniversary' in sources
                assert res['nearest_upcoming'] is not None
                assert res['nearest_upcoming']['badge_label'] == 'Today!'


class TestBondCalendarTierLimits:
    """Tests tier limits for the shared calendar."""

    def test_calendar_tier_limits_defined(self):
        assert 'max_events_per_bond' in TIER_LIMITS['free']
        assert 'max_events_per_bond' in TIER_LIMITS['premium']
        assert TIER_LIMITS['free']['max_events_per_bond'] == 20
        assert TIER_LIMITS['premium']['max_events_per_bond'] == 100

    def test_calendar_in_bond_sections(self):
        assert 'calendar' in BOND_SECTIONS


class TestBondCalendarAPIEndpoints:
    """Tests for calendar HTTP endpoints."""

    def test_calendar_get_unauthorized_outsider(self, auth_client, app):
        import main as m
        bond_id = ObjectId()
        user_c = ObjectId()
        user_d = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_c,
            'user_b_id': user_d,
            'status': 'active'
        }
        mock_bonds = MagicMock()
        mock_bonds.find_one.return_value = bond_doc
        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-session-token'
        with patch.object(m, 'bonds_conf', mock_bonds):
            res = auth_client.get(f'/api/bonds/{bond_id}/calendar')
            assert res.status_code == 403

    def test_calendar_create_event_success(self, auth_client, app, mock_user):
        import main as m
        bond_id = ObjectId()
        user_a = mock_user['_id']
        user_b = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_a,
            'user_b_id': user_b,
            'status': 'active'
        }

        mock_bonds = MagicMock()
        mock_bonds.find_one.return_value = bond_doc
        mock_users = MagicMock()
        mock_users.find_one.return_value = mock_user
        mock_events = MagicMock()
        mock_events.count_documents.return_value = 0
        mock_events.insert_one.return_value = MagicMock(inserted_id=ObjectId())

        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-session-token'

        with patch.object(m, 'bonds_conf', mock_bonds), \
             patch.object(m, 'users_conf', mock_users), \
             patch.object(m, 'bond_events_conf', mock_events), \
             patch.object(m, 'send_push_notification_to_user', MagicMock()), \
             patch.object(m.socketio, 'emit', MagicMock()):

            payload = {
                'title': 'Weekend Getaway',
                'start_date': '2026-10-15',
                'time': '14:00',
                'recurrence': 'none',
                'note': 'Bring warm jackets',
                'location': 'Mountain Cabin'
            }
            res = auth_client.post(f'/api/bonds/{bond_id}/calendar/events', json=payload)
            assert res.status_code == 200
            data = res.get_json()
            assert data['success'] is True
            assert 'event_id' in data

    def test_calendar_create_event_limit_reached(self, auth_client, app, mock_user):
        import main as m
        bond_id = ObjectId()
        user_a = mock_user['_id']
        user_b = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_a,
            'user_b_id': user_b,
            'status': 'active'
        }

        mock_bonds = MagicMock()
        mock_bonds.find_one.return_value = bond_doc
        mock_users = MagicMock()
        mock_users.find_one.return_value = dict(
            mock_user,
            join_date=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        )
        mock_events = MagicMock()
        mock_events.count_documents.return_value = 25

        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-session-token'

        with patch.object(m, 'bonds_conf', mock_bonds), \
             patch.object(m, 'users_conf', mock_users), \
             patch.object(m, 'bond_events_conf', mock_events):

            payload = {
                'title': 'Too Many Events',
                'start_date': '2026-10-15'
            }
            res = auth_client.post(f'/api/bonds/{bond_id}/calendar/events', json=payload)
            assert res.status_code == 400
            data = res.get_json()
            assert 'limit reached' in data['error']

    def test_calendar_export_ics_format(self, auth_client, app, mock_user):
        import main as m
        bond_id = ObjectId()
        user_a = mock_user['_id']
        user_b = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': user_a,
            'user_b_id': user_b,
            'status': 'active',
            'accepted_at': datetime.datetime(2025, 5, 1, tzinfo=datetime.timezone.utc)
        }

        mock_bonds = MagicMock()
        mock_bonds.find_one.return_value = bond_doc
        mock_events = MagicMock()
        mock_events.find.return_value = []
        mock_countdowns = MagicMock()
        mock_countdowns.find.return_value = []
        mock_goals = MagicMock()
        mock_goals.find.return_value = []

        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-session-token'

        with patch.object(m, 'bonds_conf', mock_bonds), \
             patch.object(m, 'bond_events_conf', mock_events), \
             patch.object(m, 'bond_countdowns_conf', mock_countdowns), \
             patch.object(m, 'bond_goals_conf', mock_goals):

            res = auth_client.get(f'/api/bonds/{bond_id}/calendar/export.ics')
            assert res.status_code == 200
            assert res.mimetype == 'text/calendar'
            body = res.get_data(as_text=True)
            assert 'BEGIN:VCALENDAR' in body
            assert 'VERSION:2.0' in body
            assert 'END:VCALENDAR' in body
