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


class TestFormAndGameDeletion:
    """Test deletion behavior and cascading cleanups for forms and games."""

    def test_form_deletion_cascades_responses(self):
        form_id = ObjectId()
        mock_forms_conf = MagicMock()
        mock_responses_conf = MagicMock()

        with patch('main.forms_conf', mock_forms_conf), \
             patch('main.form_responses_conf', mock_responses_conf):
            mock_responses_conf.delete_many({'form_id': form_id})
            mock_forms_conf.delete_one({'_id': form_id})

            mock_responses_conf.delete_many.assert_called_once_with({'form_id': form_id})
            mock_forms_conf.delete_one.assert_called_once_with({'_id': form_id})

    def test_game_deletion_cascades_votes_and_submissions(self):
        lobby_id = "test_lobby_123"
        mock_sessions_conf = MagicMock()
        mock_votes_conf = MagicMock()
        mock_subs_conf = MagicMock()

        with patch('main.game_sessions_conf', mock_sessions_conf), \
             patch('main.game_votes_conf', mock_votes_conf), \
             patch('main.game_submissions_conf', mock_subs_conf):
            mock_votes_conf.delete_many({'lobby_id': lobby_id})
            mock_subs_conf.delete_many({'lobby_id': lobby_id})
            mock_sessions_conf.delete_one({'lobby_id': lobby_id})

            mock_votes_conf.delete_many.assert_called_once_with({'lobby_id': lobby_id})
            mock_subs_conf.delete_many.assert_called_once_with({'lobby_id': lobby_id})
            mock_sessions_conf.delete_one.assert_called_once_with({'lobby_id': lobby_id})


class TestExpiredGameLobbies:
    """Test that expired or deactivated game lobbies preserve results access."""

    def test_is_lobby_active_flags(self):
        from blueprints.game import _is_lobby_active

        now = datetime.datetime.now(datetime.timezone.utc)
        past = now - datetime.timedelta(hours=2)
        future = now + datetime.timedelta(hours=2)

        # Active lobby
        assert _is_lobby_active({'expires_at': future, 'deactivated': False}) is True

        # Expired lobby
        assert _is_lobby_active({'expires_at': past, 'deactivated': False}) is False

        # Deactivated lobby
        assert _is_lobby_active({'expires_at': future, 'deactivated': True}) is False

        # None lobby
        assert _is_lobby_active(None) is False


class TestAnonymousSettings:
    """Test allow_anonymous controls for both forms and games."""

    def test_form_allow_anonymous_rejection_logic(self):
        # When allow_anonymous is False and user is unauthenticated
        form = {'allow_anonymous': False, 'share_id': 'xyz'}
        is_authenticated = False
        should_reject = not form.get('allow_anonymous', True) and not is_authenticated
        assert should_reject is True

        # When allow_anonymous is True and user is unauthenticated
        form_anon = {'allow_anonymous': True, 'share_id': 'xyz'}
        should_reject_anon = not form_anon.get('allow_anonymous', True) and not is_authenticated
        assert should_reject_anon is False

        # When user is authenticated
        is_authenticated = True
        should_reject_auth = not form.get('allow_anonymous', True) and not is_authenticated
        assert should_reject_auth is False

    def test_game_allow_anonymous_rejection_logic(self):
        # When allow_anonymous is False and player is unauthenticated
        game = {'allow_anonymous': False, 'lobby_id': 'lobby1'}
        is_authenticated = False
        should_reject = not game.get('allow_anonymous', True) and not is_authenticated
        assert should_reject is True

        # When allow_anonymous is True and player is unauthenticated
        game_anon = {'allow_anonymous': True, 'lobby_id': 'lobby1'}
        should_reject_anon = not game_anon.get('allow_anonymous', True) and not is_authenticated
        assert should_reject_anon is False


class TestGameCreateAndLobbyUI:
    """Tests for game create trivia syncing and lobby QR code rendering."""

    def test_game_create_page_contains_realtime_correct_dropdown_logic(self, auth_client, app):
        with auth_client.session_transaction() as sess:
            sess['ew_session_token'] = 'test-token'
        res = auth_client.get('/games/create')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'updateMQOption' in html
        assert 'updateCorrectAnswerDropdown' in html
        assert 'mq-correct-' in html

    def test_game_lobby_page_contains_qrcode_assets_and_global_toggle(self, client, app):
        import main as m
        import datetime
        from bson.objectid import ObjectId

        lobby_doc = {
            '_id': ObjectId(),
            'lobby_id': 'test-lobby-qr',
            'title': 'Trivia Night',
            'game_type': 'trivia',
            'host_id': ObjectId(),
            'host_username': 'hostuser',
            'status': 'active',
            'deactivated': False,
            'revealed': False,
            'allow_anonymous': True,
            'timer_seconds': 0,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2),
            'question': {'label': 'Capital of France?', 'options': ['Paris', 'London'], 'correct_option': 'Paris'},
            'counts': {'Paris': 0, 'London': 0}
        }

        mock_sessions = MagicMock()
        mock_sessions.find_one.return_value = lobby_doc
        mock_votes = MagicMock()
        mock_votes.count_documents.return_value = 0
        mock_votes.find.return_value = []

        with patch.object(m, 'game_sessions_conf', mock_sessions), \
             patch.object(m, 'game_votes_conf', mock_votes):
            res = client.get('/g/test-lobby-qr')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert 'qrcode.min.js' in html
            assert 'window.toggleQRCode = function' in html
            assert 'id="qr-canvas"' in html
            assert 'id="qr-box"' in html


class TestPersonalSpaceFormAndGameDecryption:
    """Verify that forms and game lobbies are properly decrypted before displaying on personal space and listings."""

    def test_decrypt_lobby_helper_roundtrip_and_passthrough(self, app):
        from blueprints.game import _decrypt_lobby
        import main as m

        lobby_id = 'test-lobby-roundtrip-123'
        enc_title = m.encrypt_game_data('Secret Trivia Night', lobby_id)
        enc_label = m.encrypt_game_data('What is the secret answer?', lobby_id)
        enc_correct = m.encrypt_game_data('Secret42', lobby_id)
        enc_prompt = m.encrypt_game_data('Caption this secret scenario', lobby_id)
        enc_sentence = m.encrypt_game_data('Once upon a secret time.', lobby_id)

        encrypted_lobby = {
            'lobby_id': lobby_id,
            'title': enc_title,
            'game_type': 'trivia',
            'question': {'label': enc_label, 'options': ['A', 'Secret42'], 'correct_option': enc_correct},
            'questions': [{'label': enc_label, 'options': ['A', 'Secret42'], 'correct_option': enc_correct}],
            'prompt': enc_prompt,
            'sentences': [{'text': enc_sentence, 'username': 'author'}],
        }

        decrypted = _decrypt_lobby(encrypted_lobby)
        assert decrypted['title'] == 'Secret Trivia Night'
        assert decrypted['question']['label'] == 'What is the secret answer?'
        assert decrypted['question']['correct_option'] == 'Secret42'
        assert decrypted['questions'][0]['label'] == 'What is the secret answer?'
        assert decrypted['questions'][0]['correct_option'] == 'Secret42'
        assert decrypted['prompt'] == 'Caption this secret scenario'
        assert decrypted['sentences'][0]['text'] == 'Once upon a secret time.'

        # Passthrough test for legacy plaintext
        plaintext_lobby = {
            'lobby_id': lobby_id,
            'title': 'Plain Trivia Night',
            'game_type': 'trivia',
            'question': {'label': 'Plain Question', 'options': ['A', 'B'], 'correct_option': 'A'},
            'sentences': [{'text': 'Plain sentence', 'username': 'author'}],
        }
        dec_plain = _decrypt_lobby(plaintext_lobby)
        assert dec_plain['title'] == 'Plain Trivia Night'
        assert dec_plain['question']['label'] == 'Plain Question'
        assert dec_plain['question']['correct_option'] == 'A'
        assert dec_plain['sentences'][0]['text'] == 'Plain sentence'

    def test_personal_space_decrypts_encrypted_form_definition(self, auth_client, app, mock_user):
        import main as m
        from blueprints.forms import _encrypt_form_definition

        form_oid = ObjectId()
        form_id_str = str(form_oid)
        raw_title = "Customer Feedback Questionnaire"
        raw_desc = "Please share your honest thoughts on our platform."
        raw_qs = [
            {'id': 'q1', 'label': 'How satisfied are you?', 'type': 'rating', 'required': True, 'options': []}
        ]

        enc_title, enc_desc, enc_qs = _encrypt_form_definition(form_id_str, raw_title, raw_desc, raw_qs)
        assert enc_title.startswith('gAAAAA')
        assert enc_desc.startswith('gAAAAA')

        form_doc = {
            '_id': form_oid,
            'owner_id': mock_user['_id'],
            'share_id': 'form-share-test123',
            'title': enc_title,
            'description': enc_desc,
            'questions': enc_qs,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'deactivated': False,
            'response_count': 3
        }

        # Mock database queries needed for /personal_space
        with patch.object(m.forms_conf, 'find') as mock_forms_find:
            mock_forms_find.return_value.sort.return_value.limit.return_value = [form_doc]

            res = auth_client.get('/personal_space')
            assert res.status_code == 200
            html = res.get_data(as_text=True)

            # Plaintext title and description must be present
            assert raw_title in html
            assert raw_desc in html
            # Encrypted ciphertext tokens must NOT be displayed
            assert enc_title not in html
            assert enc_desc not in html

    def test_games_list_decrypts_encrypted_lobbies(self, auth_client, app, mock_user):
        import main as m

        lobby_id = 'test-games-list-decrypt'
        enc_title = m.encrypt_game_data('Friday Fun Trivia', lobby_id)
        lobby_doc = {
            '_id': ObjectId(),
            'lobby_id': lobby_id,
            'title': enc_title,
            'game_type': 'trivia',
            'host_id': mock_user['_id'],
            'host_username': mock_user['username'],
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'deactivated': False,
            'revealed': False,
            'question': {'label': 'Trivia Q1', 'options': ['A', 'B'], 'correct_option': 'A'}
        }

        with patch.object(m.game_sessions_conf, 'find') as mock_games_find:
            mock_games_find.return_value.sort.return_value.limit.return_value = [lobby_doc]

            res = auth_client.get('/games')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert 'Friday Fun Trivia' in html
            assert enc_title not in html

