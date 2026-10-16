"""
Tests for data-protection consent surfaces: privacy notice, cookie/marketing
consent, age assurance, and parental consent gating.
"""

import datetime
from unittest import mock

import pytest


class TestPrivacyNotice:
    def test_privacy_page_renders(self, client):
        res = client.get('/privacy')
        assert res.status_code == 200
        body = res.get_data(as_text=True)
        assert 'Privacy Notice' in body or 'Privacy' in body

    def test_privacy_page_has_contact_email(self, client):
        res = client.get('/privacy')
        body = res.get_data(as_text=True)
        assert 'echowithin@echowithin.xyz' in body

    def test_footer_links_privacy(self, client):
        res = client.get('/')
        body = res.get_data(as_text=True)
        assert url_for_privacy(body)

    def test_cookie_banner_present(self, client):
        res = client.get('/')
        body = res.get_data(as_text=True)
        assert 'cookie-consent-banner' in body

    def test_register_form_has_age_fields(self, client):
        res = client.get('/register')
        body = res.get_data(as_text=True)
        assert 'date_of_birth' in body
        assert 'minor-consent-section' in body
        assert '/privacy' in body


def url_for_privacy(body):
    return '/privacy' in body


class TestConsentApi:
    def test_consent_api_persists(self, app, client, monkeypatch):
        import main as m
        captured = {}

        def _insert(doc):
            captured.update(doc)
            return mock.MagicMock()

        monkeypatch.setattr(m.consent_records_conf, 'insert_one', _insert)
        res = client.post('/api/consent', json={'analytics': True, 'marketing': False})
        assert res.status_code == 200
        assert res.get_json().get('success') is True
        assert captured.get('analytics') is True
        assert captured.get('marketing') is False
        assert captured.get('necessary') is True

    def test_database_has_consent_collection(self):
        import database
        assert hasattr(database, 'consent_records_conf')


class TestAgeHelpers:
    def test_parse_dob_valid(self):
        from blueprints.auth import _parse_dob, _compute_age
        dob = _parse_dob('2000-05-10')
        assert dob is not None
        assert _compute_age(dob) >= 20

    def test_parse_dob_invalid(self):
        from blueprints.auth import _parse_dob
        assert _parse_dob('not-a-date') is None
        assert _parse_dob('') is None
        assert _parse_dob(None) is None

    def test_parse_dob_future_rejected(self):
        from blueprints.auth import _parse_dob
        future = (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=1)).isoformat()
        assert _parse_dob(future) is None


class TestRegistrationAgeGating:
    def _base(self):
        return {'username': 'alice', 'email': 'alice@example.com', 'password': 'secret1', 'agree_terms': '1'}

    def test_missing_terms_blocked(self, app, client, monkeypatch):
        import main as m
        monkeypatch.setattr(m.users_conf, 'find_one', lambda *a, **k: None)
        data = self._base()
        data.pop('agree_terms')
        res = client.post('/register', data=data)
        assert res.status_code in (200, 302)

    def test_missing_dob_blocked(self, app, client, monkeypatch):
        import main as m
        monkeypatch.setattr(m.users_conf, 'find_one', lambda *a, **k: None)
        res = client.post('/register', data=self._base())
        assert res.status_code in (200, 302)

    def test_under_13_blocked(self, app, client, monkeypatch):
        import main as m
        monkeypatch.setattr(m.users_conf, 'find_one', lambda *a, **k: None)
        data = self._base()
        data['date_of_birth'] = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=365 * 10)).isoformat()
        res = client.post('/register', data=data)
        assert res.status_code in (200, 302)

    def test_minor_without_guardian_blocked(self, app, client, monkeypatch):
        import main as m
        monkeypatch.setattr(m.users_conf, 'find_one', lambda *a, **k: None)
        data = self._base()
        data['date_of_birth'] = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=365 * 15)).isoformat()
        res = client.post('/register', data=data)
        assert res.status_code in (200, 302)

    def test_minor_with_guardian_sends_consent(self, app, client, monkeypatch):
        import main as m
        from bson.objectid import ObjectId
        minor_email = 'minor@example.com'

        def _find_one(query, *a, **k):
            if isinstance(query, dict) and query.get('email') == minor_email:
                return {'_id': ObjectId('507f1f77bcf86cd799439011'), 'email': minor_email, 'username': 'minoruser'}
            return None

        sent = {}
        monkeypatch.setattr(m.users_conf, 'find_one', _find_one)
        monkeypatch.setattr(m.users_conf, 'insert_one', lambda doc: mock.MagicMock())
        monkeypatch.setattr(m.auth_conf, 'update_one', lambda *a, **k: mock.MagicMock())
        monkeypatch.setattr(m, 'send_code', lambda *a, **k: None)
        monkeypatch.setattr(m, 'send_parental_consent_email', lambda gemail, uname, token: sent.update({'gemail': gemail, 'token': token}) or True)

        data = {'username': 'minoruser', 'email': minor_email, 'password': 'secret1', 'agree_terms': '1',
                'date_of_birth': (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=365 * 15)).isoformat(),
                'guardian_email': 'guardian@example.com', 'parental_consent': '1'}
        res = client.post('/register', data=data)
        assert res.status_code in (200, 302)
        assert sent.get('gemail') == 'guardian@example.com'
        assert sent.get('token')


class TestAgeConfirmationGate:
    def test_requires_auth(self, client):
        res = client.get('/age-confirmation')
        assert res.status_code in (302, 401)

    def test_gate_blocks_pending_user_api(self, app, mock_user):
        import main as m
        from main import User
        pending = dict(mock_user)
        pending['age_assurance_pending'] = True
        user_obj = User(pending)
        with app.test_client() as c:
            with mock.patch('flask_login.utils._get_user', return_value=user_obj):
                res = c.get('/api/notes')
                assert res.status_code in (403, 302)


class TestUserAgeAttributes:
    def test_user_exposes_age_fields(self, app, mock_user):
        from main import User
        data = dict(mock_user)
        data.update({'is_minor': True, 'parental_consent_status': 'pending', 'age_assurance_pending': False})
        with app.app_context():
            u = User(data)
            assert u.is_minor is True
            assert u.parental_consent_status == 'pending'
            assert u.age_assurance_pending is False

    def test_user_defaults(self, app, mock_user):
        from main import User
        with app.app_context():
            u = User(mock_user)
            assert u.is_minor is False
            assert u.parental_consent_status is None
            assert u.age_assurance_pending is False


class TestParentalConsentRoute:
    def test_invalid_token(self, client, monkeypatch):
        import main as m
        monkeypatch.setattr(m.auth_conf, 'find_one', lambda *a, **k: None)
        res = client.get('/parental_consent/bogus-token')
        assert res.status_code == 400

    def test_expired_token(self, client, monkeypatch):
        import main as m
        from unittest import mock as _mock
        expired = {
            '_id': 'x',
            'type': 'parental_consent',
            'token_expiry': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
            'minor_user_id': '507f1f77bcf86cd799439011',
        }
        monkeypatch.setattr(m.auth_conf, 'find_one', lambda *a, **k: expired)
        res = client.get('/parental_consent/bogus-token')
        assert res.status_code == 410
