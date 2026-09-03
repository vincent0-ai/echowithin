import datetime
import pytest
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
from blueprints.forms import encrypt_form_response, decrypt_form_response


class TestFormSubmitterIdentity:
    """Test forms submitter identity recording, privacy, and responses formatting."""

    def test_authenticated_submitter_doc_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        user_id = ObjectId()
        username = "johndoe"
        display_name = "John Doe"
        avatar_url = "https://example.com/avatar.jpg"

        doc = {
            'form_id': ObjectId(),
            'share_id': 'abc123xyz',
            'answers': [{'question_id': 'q1', 'type': 'short_text', 'value': 'test'}],
            'submitted_at': now,
            'submitter_id': user_id,
            'submitter_username': username,
            'submitter_name': display_name,
            'submitter_avatar': avatar_url,
            'is_authenticated': True,
            'submitter_ip_hash': 'abcdef1234567890',
            'user_agent': 'Mozilla/5.0'
        }

        assert doc['is_authenticated'] is True
        assert doc['submitter_username'] == 'johndoe'
        assert doc['submitter_id'] == user_id
        assert doc['submitted_at'].tzinfo == datetime.timezone.utc

    def test_anonymous_submitter_doc_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)

        doc = {
            'form_id': ObjectId(),
            'share_id': 'abc123xyz',
            'answers': [{'question_id': 'q1', 'type': 'short_text', 'value': 'test'}],
            'submitted_at': now,
            'submitter_id': None,
            'submitter_username': None,
            'submitter_name': None,
            'submitter_avatar': None,
            'is_authenticated': False,
            'submitter_ip_hash': 'abcdef1234567890',
            'user_agent': 'Mozilla/5.0'
        }

        assert doc['is_authenticated'] is False
        assert doc['submitter_username'] is None
        assert doc['submitter_id'] is None

    def test_form_encryption_and_decryption_roundtrip(self):
        form_id_str = str(ObjectId())
        plain_text = "This is a confidential answer."
        encrypted = encrypt_form_response(plain_text, form_id_str)
        assert encrypted != plain_text
        decrypted = decrypt_form_response(encrypted, form_id_str)
        assert decrypted == plain_text

    def test_form_response_date_formatting(self):
        now = datetime.datetime(2026, 9, 3, 14, 30, 0, tzinfo=datetime.timezone.utc)
        formatted = now.strftime('%b %d, %Y, %I:%M %p')
        assert formatted == "Sep 03, 2026, 02:30 PM"
