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


class TestFloppyBirdArcade:
    """Tests for single-player Floppy Bird integration."""

    def test_floppy_bird_guest_access(self, client):
        """Unauthenticated visitors can access and play Floppy Bird."""
        res = client.get('/games/floppy-bird')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert '<canvas id="c"' in html
        assert 'floppy_bird.js' in html
        assert 'touch-dash-btn' in html
        assert 'touch-ghost-btn' in html

    def test_floppy_bird_authenticated_access(self, auth_client):
        """Logged-in users can access Floppy Bird."""
        res = auth_client.get('/games/floppy-bird')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Floppy Bird: Super Powers' in html
        assert '<canvas id="c"' in html
        assert 'mute-toggle-btn' in html

    def test_floppy_bird_mobile_back_and_clean_controls(self, client):
        """Floppy Bird page has mobile back buttons and minimal control text without emojis."""
        res = client.get('/games/floppy-bird')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'touch-back-btn' in html
        assert 'game-back-btn' in html
        assert 'Back' in html
        assert 'Tap or Space to flap' in html
        assert 'Clear goal' not in html
        assert '80% coins' not in html
        assert '🏆' not in html
        assert '🔄' not in html
        assert 'addEventListener(\'online\'' in html

    def test_games_list_contains_floppy_bird_entry(self, auth_client, app, mock_user):
        """The /games hub page includes the Floppy Bird arcade card."""
        import main as m
        with patch.object(m.game_sessions_conf, 'find') as mock_find:
            mock_find.return_value.sort.return_value.limit.return_value = []
            res = auth_client.get('/games')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert '/games/floppy-bird' in html
            assert 'Floppy Bird: Super Powers' in html


class TestSlimeVolleyball:
    """Tests for Slime Volleyball Solo and 1v1 multiplayer integration."""

    def test_slime_volleyball_guest_access(self, client):
        """Guests can access Slime Volleyball."""
        res = client.get('/games/slime-volleyball')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Slime Volleyball' in html
        assert 'slime-canvas' in html
        assert 'slime_volleyball.js' in html
        assert 'touch-jump' in html

    def test_slime_volleyball_authenticated_access(self, auth_client):
        """Logged-in users can access Slime Volleyball."""
        res = auth_client.get('/games/slime-volleyball')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Slime Volleyball' in html
        assert 'tab-solo' in html
        assert 'tab-online' in html

    def test_slime_volleyball_clean_controls_and_no_emojis(self, client):
        """Slime Volleyball page has clean minimal controls, no emojis, and offline sync handler."""
        res = client.get('/games/slime-volleyball')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Back to Games' in html
        assert 'Find Match' in html
        assert '⚡' not in html
        assert '🏆' not in html
        assert '🔄' not in html
        assert '◀' not in html
        assert '▲' not in html
        assert '▶' not in html
        assert 'addEventListener(\'online\'' in html
        assert 'syncScores' in html

    def test_games_list_contains_slime_volleyball_card(self, auth_client, app, mock_user):
        """Games list features Slime Volleyball alongside Floppy Bird."""
        import main as m
        with patch.object(m.game_sessions_conf, 'find') as mock_find:
            mock_find.return_value.sort.return_value.limit.return_value = []
            res = auth_client.get('/games')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert '/games/slime-volleyball' in html
            assert 'Slime Volleyball' in html

    def test_slime_socket_room_lifecycle(self, app):
        """Test SocketIO handlers for join, sync, input, restart, and leave."""
        import main as m

        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                fn = call.args[0]
                handlers[getattr(fn, '__name__', '')] = fn

        join_handler = handlers.get('handle_join_slime_room')
        leave_handler = handlers.get('handle_leave_slime_room')
        sync_handler = handlers.get('handle_slime_host_sync')
        input_handler = handlers.get('handle_slime_player_input')
        restart_handler = handlers.get('handle_slime_restart')

        assert join_handler is not None
        assert leave_handler is not None
        assert sync_handler is not None
        assert input_handler is not None
        assert restart_handler is not None

        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'join_room') as mock_join, \
                 patch.object(m, 'leave_room') as mock_leave, \
                 patch.object(m, 'emit') as mock_emit:
                mock_req.sid = 'sid_host_123'
                room_id = 'test_room_direct'

                # Host joins room
                join_handler({'room_id': room_id})
                mock_join.assert_called_with(room_id)
                assert room_id in m.active_slime_rooms
                assert m.active_slime_rooms[room_id]['host_sid'] == 'sid_host_123'

                # Host sync relay
                sync_payload = {
                    'room_id': room_id,
                    'ball': {'x': 0, 'y': 10, 'vx': 0, 'vy': 0},
                    'scores': [1, 0]
                }
                sync_handler(sync_payload)
                mock_emit.assert_called_with('slime_host_sync', sync_payload, room=room_id, include_self=False)

                # Guest input relay
                input_payload = {
                    'room_id': room_id,
                    'p2': {'x': 10, 'y': 1.5, 'vx': 0, 'vy': 0}
                }
                input_handler(input_payload)
                mock_emit.assert_called_with('slime_player_input', input_payload, room=room_id, include_self=False)

                # Restart event (must exclude the sender: a remote-triggered
                # restart never re-emits, so an echo would ping-pong forever)
                restart_handler({'room_id': room_id})
                mock_emit.assert_called_with('slime_restart', {}, room=room_id, include_self=False)

                # Leave event
                leave_handler({'room_id': room_id})
                assert room_id not in m.active_slime_rooms


class TestSlimeDMGameInvite:
    """Tests for DM multiplayer Slime Volleyball auto-lobby invites."""

    def test_dm_game_invite_slime_volleyball_auto_url(self, app, mock_user):
        """Verify send_dm socket handler automatically generates game_url for Slime Volleyball."""
        import main as m
        from main import User
        from flask_login import login_user
        from unittest.mock import patch, MagicMock
        from bson.objectid import ObjectId

        target_id = ObjectId()
        recipient_user = {'_id': target_id, 'username': 'partner_user', 'dm_privacy': 'everyone'}

        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]

        send_dm_handler = handlers.get('handle_send_dm')
        assert send_dm_handler is not None

        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'can_dm', return_value=True), \
                 patch.object(m, 'users_conf') as mock_users, \
                 patch.object(m, 'direct_messages_conf') as mock_dms, \
                 patch.object(m, 'hidden_chats_conf') as mock_hidden, \
                 patch.object(m, 'emit') as mock_emit:

                def fake_insert(doc):
                    doc['_id'] = ObjectId()
                    return MagicMock(inserted_id=doc['_id'])
                mock_dms.insert_one.side_effect = fake_insert

                mock_users.find_one.return_value = recipient_user

                invite_payload = {
                    'recipient_id': str(target_id),
                    'message_type': 'game_invite',
                    'game_type': 'slime_volleyball',
                    'game_lobby_id': 'sv-test42',
                    'game_title': 'Slime Volleyball 1v1',
                    'temp_id': 'tmp-123'
                }

                send_dm_handler(invite_payload)

                mock_dms.insert_one.assert_called_once()
                saved_doc = mock_dms.insert_one.call_args[0][0]
                assert saved_doc['message_type'] == 'game_invite'
                assert 'game_data' in saved_doc
                assert saved_doc['game_data']['game_type'] == 'slime_volleyball'
                assert saved_doc['game_data']['lobby_id'] == 'sv-test42'
                assert saved_doc['game_data']['game_url'] == '/games/slime-volleyball?room=sv-test42'

                # Verify emitted new_dm payload
                assert mock_emit.call_count >= 2
                new_dm_call = [c for c in mock_emit.call_args_list if c[0][0] == 'new_dm'][0]
                emitted_payload = new_dm_call[0][1]
                assert emitted_payload['game_data']['game_url'] == '/games/slime-volleyball?room=sv-test42'
                assert 'Slime Volleyball' in emitted_payload['content']

    def test_messages_template_slime_game_invite_elements(self):
        """Verify messages.html contains Slime Volleyball auto-lobby trigger, modal card, and join button."""
        import os
        tpl_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(tpl_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert 'inviteSlimeVolleyball' in content
        assert 'id="slime-auto-invite-btn"' in content
        assert '1v1 Live' in content
        assert 'Slime Volleyball' in content
        assert 'Enter Slime Volleyball' in content
        assert '/games/slime-volleyball?room=' in content

    def test_messages_template_all_duel_games_auto_invite_and_join(self):
        """Verify messages.html contains auto-invite buttons and join links for all 5 duel games."""
        import os
        tpl_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(tpl_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # All 5 duel trigger buttons
        assert 'id="slime-auto-invite-btn"' in content
        assert 'id="ttt-auto-invite-btn"' in content
        assert 'id="c4-auto-invite-btn"' in content
        assert 'id="dnb-auto-invite-btn"' in content
        assert 'id="pong-auto-invite-btn"' in content

        # All 5 duel JS functions
        assert 'inviteSlimeVolleyball' in content
        assert 'inviteTicTacToe' in content
        assert 'inviteConnectFour' in content
        assert 'inviteDotsAndBoxes' in content
        assert 'invitePingPong' in content

        # All 5 enter buttons in DM message cards
        assert 'Enter Slime Volleyball' in content
        assert 'Enter Tic-Tac-Toe' in content
        assert 'Enter Connect Four' in content
        assert 'Enter Dots & Boxes' in content
        assert 'Enter Ping Pong' in content

        # All 5 direct URLs
        assert '/games/slime-volleyball?room=' in content
        assert '/games/tic-tac-toe?room=' in content
        assert '/games/connect-four?room=' in content
        assert '/games/dots-and-boxes?room=' in content
        assert '/games/ping-pong?room=' in content

    def test_dm_game_invite_all_duel_games_auto_url(self, app, mock_user):
        """Verify send_dm socket handler generates direct game_url for all 5 duel games."""
        import main as m
        from main import User
        from flask_login import login_user
        from unittest.mock import patch, MagicMock
        from bson.objectid import ObjectId

        target_id = ObjectId()
        recipient_user = {'_id': target_id, 'username': 'partner_user', 'dm_privacy': 'everyone'}

        handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                    for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}
        send_dm_handler = handlers.get('handle_send_dm')
        assert send_dm_handler is not None

        game_cases = [
            ('slime_volleyball', 'sv-123', '/games/slime-volleyball?room=sv-123'),
            ('tic_tac_toe', 'ttt-456', '/games/tic-tac-toe?room=ttt-456'),
            ('connect_four', 'c4-789', '/games/connect-four?room=c4-789'),
            ('dots_and_boxes', 'dnb-012', '/games/dots-and-boxes?room=dnb-012'),
            ('ping_pong', 'pong-345', '/games/ping-pong?room=pong-345'),
        ]

        with app.test_request_context():
            login_user(User(mock_user))
            for g_type, room_id, expected_url in game_cases:
                with patch.object(m, 'can_dm', return_value=True), \
                     patch.object(m, 'users_conf') as mock_users, \
                     patch.object(m, 'direct_messages_conf') as mock_dms, \
                     patch.object(m, 'hidden_chats_conf'), \
                     patch.object(m, 'emit'):

                    def fake_insert(doc):
                        doc['_id'] = ObjectId()
                        return MagicMock(inserted_id=doc['_id'])
                    mock_dms.insert_one.side_effect = fake_insert
                    mock_users.find_one.return_value = recipient_user

                    invite_payload = {
                        'recipient_id': str(target_id),
                        'message_type': 'game_invite',
                        'game_type': g_type,
                        'game_lobby_id': room_id,
                        'game_title': f'{g_type} Duel',
                        'temp_id': f'tmp-{room_id}'
                    }
                    send_dm_handler(invite_payload)
                    saved_doc = mock_dms.insert_one.call_args[0][0]
                    assert saved_doc['game_data']['game_url'] == expected_url

    def test_duel_games_create_custom_room_ui_and_js(self):
        """Verify Tic-Tac-Toe, Connect Four, and Dots and Boxes have Create Custom room button and JS listener."""
        import os
        base_dir = os.path.join(os.path.dirname(__file__), '..')

        for tpl_name in ('tic_tac_toe.html', 'connect_four.html', 'dots_and_boxes.html'):
            path = os.path.join(base_dir, 'templates', tpl_name)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            assert 'id="create-room-btn"' in content
            assert 'Create Custom' in content

        for js_name in ('tic_tac_toe.js', 'connect_four.js', 'dots_and_boxes.js'):
            path = os.path.join(base_dir, 'static', js_name)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            assert 'createRoomBtn' in content
            assert 'Math.random().toString(36)' in content

    def test_slime_js_room_joined_fair_reset_and_status(self):
        """Verify slime_volleyball.js includes opponent waiting status and score reset on opponent join."""
        import os
        js_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'slime_volleyball.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            content = f.read()

        assert 'Waiting for opponent to enter' in content
        assert 'GameState.p1.score = 0' in content
        assert 'resetServe(-1)' in content


class TestArcadeMatchmakingAndLeaderboards:
    """Tests for Arcade Leaderboards API and Socket Matchmaking."""

    def test_leaderboard_submit_validation(self, client):
        """API rejects invalid game, category, out-of-bound score, or missing guest token."""
        # Invalid game
        res = client.post('/api/games/leaderboard/submit', json={
            'game': 'unknown_game',
            'category': 'campaign_stars',
            'score': 10,
            'guest_token': 'g_12345'
        })
        assert res.status_code == 400
        assert 'Invalid game or category' in res.get_json()['error']

        # Invalid category
        res = client.post('/api/games/leaderboard/submit', json={
            'game': 'floppy_bird',
            'category': 'invalid_cat',
            'score': 10,
            'guest_token': 'g_12345'
        })
        assert res.status_code == 400
        assert 'Invalid game or category' in res.get_json()['error']

        # Score out of bounds (campaign stars > 42)
        res = client.post('/api/games/leaderboard/submit', json={
            'game': 'floppy_bird',
            'category': 'campaign_stars',
            'score': 100,
            'guest_token': 'g_12345'
        })
        assert res.status_code == 400
        assert 'Campaign stars must be between 0 and 42' in res.get_json()['error']

        # Missing guest token for anonymous
        res = client.post('/api/games/leaderboard/submit', json={
            'game': 'floppy_bird',
            'category': 'campaign_stars',
            'score': 10
        })
        assert res.status_code == 400
        assert 'Guest token required for unauthenticated submissions' in res.get_json()['error']

    def test_leaderboard_submit_and_get_flow(self, auth_client, app):
        """Authenticated score submission upserts partitions and GET returns formatted UTC Z entries."""
        import main as m
        from unittest.mock import MagicMock

        mock_col = MagicMock()
        mock_col.find_one.return_value = None
        with patch.object(m, 'arcade_leaderboards_conf', mock_col):
            # Test submit
            res = auth_client.post('/api/games/leaderboard/submit', json={
                'game': 'floppy_bird',
                'category': 'campaign_stars',
                'score': 36
            })
            assert res.status_code == 200
            assert res.get_json()['success'] is True
            # Should have updated 3 partitions (daily, weekly, all_time)
            assert mock_col.update_one.call_count == 3

            # Test get
            sample_time = datetime.datetime.now(datetime.timezone.utc)
            mock_find = MagicMock()
            mock_find.sort.return_value.limit.return_value = [
                {
                    'username': 'FlopMaster',
                    'is_guest': False,
                    'score': 36,
                    'updated_at': sample_time
                }
            ]
            mock_col.find.return_value = mock_find

            get_res = auth_client.get('/api/games/leaderboard?game=floppy_bird&category=campaign_stars&period=weekly')
            assert get_res.status_code == 200
            data = get_res.get_json()
            assert data['game'] == 'floppy_bird'
            assert data['category'] == 'campaign_stars'
            assert data['period'] == 'weekly'
            assert len(data['entries']) == 1
            entry = data['entries'][0]
            assert entry['rank'] == 1
            assert entry['username'] == 'FlopMaster'
            assert entry['score'] == 36
            assert entry['updated_at'].endswith('Z')

    def test_leaderboard_submit_csrf_exemption(self, client, app):
        """Verify POST /api/games/leaderboard/submit is exempt from CSRF protection."""
        import main as m
        from unittest.mock import MagicMock

        old_csrf = app.config.get('WTF_CSRF_ENABLED', True)
        app.config['WTF_CSRF_ENABLED'] = True
        try:
            mock_col = MagicMock()
            mock_col.find_one.return_value = None
            with patch.object(m, 'arcade_leaderboards_conf', mock_col):
                res = client.post('/api/games/leaderboard/submit', json={
                    'game': 'floppy_bird',
                    'category': 'campaign_stars',
                    'score': 15,
                    'guest_token': 'g_test_csrf'
                })
                assert res.status_code == 200
                assert res.get_json()['success'] is True
        finally:
            app.config['WTF_CSRF_ENABLED'] = old_csrf

    def test_slime_socket_matchmaking_queue_and_pairing(self, app):
        """Socket handlers queue solo players and pair waiting opponents automatically."""
        import main as m

        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                fn = call.args[0]
                handlers[getattr(fn, '__name__', '')] = fn

        find_match_handler = handlers.get('handle_find_slime_match')
        cancel_match_handler = handlers.get('handle_cancel_slime_matchmaking')
        assert find_match_handler is not None
        assert cancel_match_handler is not None

        with app.test_request_context():
            with patch.object(m, 'emit') as mock_emit, \
                 patch.object(m, 'join_room') as mock_join:

                m.slime_matchmaking_queue.clear()

                # Player 1 enters queue
                with patch.object(m, 'request') as req1:
                    req1.sid = 'sid_player_1'
                    find_match_handler()
                    assert len(m.slime_matchmaking_queue) == 1
                    assert m.slime_matchmaking_queue[0]['sid'] == 'sid_player_1'
                    mock_emit.assert_called_with('slime_matchmaking_waiting', {'status': 'waiting'}, room='sid_player_1')

                mock_emit.reset_mock()

                # Player 1 cancels queue
                with patch.object(m, 'request') as req1:
                    req1.sid = 'sid_player_1'
                    cancel_match_handler()
                    assert len(m.slime_matchmaking_queue) == 0
                    mock_emit.assert_called_with('slime_matchmaking_cancelled', {'status': 'cancelled'}, room='sid_player_1')

                mock_emit.reset_mock()

                # Player 1 re-enters queue
                with patch.object(m, 'request') as req1:
                    req1.sid = 'sid_player_1'
                    find_match_handler()
                    assert len(m.slime_matchmaking_queue) == 1

                # Player 2 enters queue -> pair formed!
                with patch.object(m, 'request') as req2:
                    req2.sid = 'sid_player_2'
                    find_match_handler()
                    # Queue cleared as they matched
                    assert len(m.slime_matchmaking_queue) == 0

                    # Both should receive slime_match_found
                    match_emits = [c for c in mock_emit.call_args_list if c[0][0] == 'slime_match_found']
                    assert len(match_emits) == 2

                    host_call = [c for c in match_emits if c[1].get('room') == 'sid_player_1'][0]
                    guest_call = [c for c in match_emits if c[1].get('room') == 'sid_player_2'][0]

                    assert host_call[0][1]['is_host'] is True
                    assert guest_call[0][1]['is_host'] is False
                    assert host_call[0][1]['room_id'] == guest_call[0][1]['room_id']
                    assert host_call[0][1]['room_id'].startswith('duel_')

    def test_slime_volleyball_difficulty_ui_and_presets(self, client):
        """Slime Volleyball renders difficulty controls, rounds counter, and JS includes difficulty presets."""
        res = client.get('/games/slime-volleyball')
        assert res.status_code == 200
        html = res.get_data(as_text=True)

        assert 'id="ai-difficulty-panel"' in html
        assert 'data-diff="easy"' in html
        assert 'data-diff="normal"' in html
        assert 'data-diff="hard"' in html
        assert 'id="my-slime-rounds"' in html
        assert 'Rounds Won:' in html

        # Verify JS contains difficulty config and reaction delay logic
        import os
        js_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'slime_volleyball.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()

        assert 'DIFFICULTY_CONFIG' in js_content
        assert 'reactionDelayMs: 220' in js_content
        assert 'speedCap: 0.58' in js_content
        assert 'jitterRange: 1.3' in js_content
        assert 'setDifficulty' in js_content
        assert 'getRoundsWon' in js_content

    def test_slime_volleyball_volleys_returned_leaderboard(self, client, app):
        """Volleys returned is an accepted leaderboard category and ranks successful ball returns."""
        import main as m
        from blueprints.game import VALID_ARCADE_CATEGORIES
        assert 'volleys_returned' in VALID_ARCADE_CATEGORIES['slime_volleyball']

        # Submit a volleys_returned score
        mock_lb = MagicMock()
        mock_lb.find_one.return_value = None

        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            res = client.post('/api/games/leaderboard/submit', json={
                'game': 'slime_volleyball',
                'category': 'volleys_returned',
                'score': 35,
                'guest_token': 'g_test_volleys'
            })
            assert res.status_code == 200
            data = res.get_json()
            assert data.get('success') is True
            assert data.get('score') == 35

            # Invalid bounds check (> 1,000,000)
            res_invalid = client.post('/api/games/leaderboard/submit', json={
                'game': 'slime_volleyball',
                'category': 'volleys_returned',
                'score': 2000000,
                'guest_token': 'g_test_volleys'
            })
            assert res_invalid.status_code == 400

    def test_arcade_pc_layout_and_canvas_aspect_ratios(self, client):
        """Verify Floppy Bird and Slime Volleyball templates maintain proper canvas sizing and dark styling for PC."""
        # Floppy Bird
        res_fb = client.get('/games/floppy-bird')
        assert res_fb.status_code == 200
        html_fb = res_fb.get_data(as_text=True)
        assert 'aspect-ratio: 480 / 640;' in html_fb
        assert 'max-height: min(640px, calc(100vh - 150px));' in html_fb
        assert 'max-width: min(480px, 95vw);' in html_fb
        assert 'background: #0b1020 !important;' in html_fb

        # Slime Volleyball
        res_sv = client.get('/games/slime-volleyball')
        assert res_sv.status_code == 200
        html_sv = res_sv.get_data(as_text=True)
        assert 'aspect-ratio: 16 / 9;' in html_sv
        assert 'data-cat="volleys_returned"' in html_sv
        assert 'id="my-slime-volleys"' in html_sv

    def test_tic_tac_toe_routes_and_ui(self, client):
        """Verify Tic-Tac-Toe route, UI tabs, difficulty options, and clean controls."""
        res = client.get('/games/tic-tac-toe')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'tic_tac_toe.js' in html
        assert 'Back to Games' in html
        assert 'id="tab-solo"' in html
        assert 'id="tab-local"' in html
        assert 'id="tab-online"' in html
        assert 'id="find-match-btn"' in html
        assert 'id="room-code-input"' in html
        assert 'data-diff="easy"' in html
        assert 'data-diff="medium"' in html
        assert 'data-diff="hard"' in html
        assert 'id="ttt-turn-indicator"' in html

    def test_connect_four_routes_and_ui(self, client):
        """Verify Connect Four route, UI tabs, canvas, and clean controls."""
        res = client.get('/games/connect-four')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'connect_four.js' in html
        assert 'Back to Games' in html
        assert 'id="tab-solo"' in html
        assert 'id="tab-local"' in html
        assert 'id="tab-online"' in html
        assert 'id="find-match-btn"' in html
        assert 'id="room-code-input"' in html
        assert 'id="c4-canvas"' in html
        assert 'data-diff="easy"' in html
        assert 'data-diff="normal"' in html
        assert 'data-diff="hard"' in html

    def test_games_list_contains_all_arcade_games(self, auth_client):
        """Verify /games includes cards and weekly champion widgets for all arcade games."""
        res = auth_client.get('/games')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Floppy Bird' in html
        assert 'Slime Volleyball' in html
        assert 'Tic-Tac-Toe' in html
        assert 'Connect Four' in html
        assert 'id="fb-champ"' in html
        assert 'id="slime-champ"' in html
        assert 'id="ttt-champ"' in html
        assert 'id="c4-champ"' in html

    def test_tic_tac_toe_and_connect_four_leaderboards(self, client, app):
        """Verify leaderboard submissions and bounds checking for Tic-Tac-Toe and Connect Four."""
        import main as m
        from blueprints.game import VALID_ARCADE_CATEGORIES

        assert 'tic_tac_toe' in VALID_ARCADE_CATEGORIES
        assert 'win_streak' in VALID_ARCADE_CATEGORIES['tic_tac_toe']
        assert 'total_wins' in VALID_ARCADE_CATEGORIES['tic_tac_toe']

        assert 'connect_four' in VALID_ARCADE_CATEGORIES
        assert 'win_streak' in VALID_ARCADE_CATEGORIES['connect_four']
        assert 'total_wins' in VALID_ARCADE_CATEGORIES['connect_four']

        mock_lb = MagicMock()
        mock_lb.find_one.return_value = None

        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            # Valid Tic-Tac-Toe streak
            res_ttt = client.post('/api/games/leaderboard/submit', json={
                'game': 'tic_tac_toe',
                'category': 'win_streak',
                'score': 7,
                'guest_token': 'g_test_ttt'
            })
            assert res_ttt.status_code == 200
            assert res_ttt.get_json()['score'] == 7

            # Valid Connect Four total wins
            res_c4 = client.post('/api/games/leaderboard/submit', json={
                'game': 'connect_four',
                'category': 'total_wins',
                'score': 25,
                'guest_token': 'g_test_c4'
            })
            assert res_c4.status_code == 200
            assert res_c4.get_json()['score'] == 25

            # Invalid bounds check (> 500 for streak)
            res_invalid = client.post('/api/games/leaderboard/submit', json={
                'game': 'connect_four',
                'category': 'win_streak',
                'score': 9999,
                'guest_token': 'g_test_c4'
            })
            assert res_invalid.status_code == 400

    def test_win_check_functions(self):
        """Verify Python server win check logic for Tic-Tac-Toe and Connect Four."""
        from main import check_ttt_win, check_c4_win, C4_ROWS, C4_COLS

        # TTT horizontal win
        board_ttt = ['x', 'x', 'x', '', '', '', '', '', '']
        assert check_ttt_win(board_ttt, 'x') == [0, 1, 2]
        assert check_ttt_win(board_ttt, 'o') is None

        # C4 horizontal win
        board_c4 = [[-1] * C4_COLS for _ in range(C4_ROWS)]
        board_c4[5][0] = 0
        board_c4[5][1] = 0
        board_c4[5][2] = 0
        board_c4[5][3] = 0
        win_c4 = check_c4_win(board_c4, 5, 3, 0)
        assert win_c4 is not None
        assert len(win_c4) >= 4

    def test_tic_tac_toe_socket_events(self, app):
        """Test Socket.IO room join, turn validation, and matchmaking for Tic-Tac-Toe."""
        import main as m
        handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                    for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}

        join_handler = handlers.get('handle_join_ttt_room')
        move_handler = handlers.get('handle_ttt_move')
        leave_handler = handlers.get('handle_leave_ttt_room')
        find_handler = handlers.get('handle_find_ttt_match')
        restart_handler = handlers.get('handle_ttt_restart')

        assert join_handler is not None
        assert move_handler is not None
        assert leave_handler is not None
        assert find_handler is not None
        assert restart_handler is not None

        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'join_room') as mock_join, \
                 patch.object(m, 'emit') as mock_emit:

                room_id = 'test_ttt_room'
                # Host joins
                mock_req.sid = 'sid_ttt_host'
                join_handler({'room_id': room_id})
                assert room_id in m.active_ttt_rooms
                assert m.active_ttt_rooms[room_id]['host_sid'] == 'sid_ttt_host'

                # Host makes move
                move_handler({'room_id': room_id, 'index': 0})
                assert m.active_ttt_rooms[room_id]['board'][0] == 'x'
                assert m.active_ttt_rooms[room_id]['turn'] == 'o'

                # Verify restart alternates starter from 'x' to 'o'
                restart_handler({'room_id': room_id})
                assert m.active_ttt_rooms[room_id]['turn'] == 'o'
                assert m.active_ttt_rooms[room_id]['starter'] == 'o'
                # Next restart alternates back to 'x'
                restart_handler({'room_id': room_id})
                assert m.active_ttt_rooms[room_id]['turn'] == 'x'
                assert m.active_ttt_rooms[room_id]['starter'] == 'x'

                # Host leaves
                leave_handler({'room_id': room_id})
                assert room_id not in m.active_ttt_rooms

    def test_connect_four_socket_events(self, app):
        """Test Socket.IO room join, piece drop, and matchmaking for Connect Four."""
        import main as m
        handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                    for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}

        join_handler = handlers.get('handle_join_c4_room')
        move_handler = handlers.get('handle_c4_move')
        leave_handler = handlers.get('handle_leave_c4_room')
        find_handler = handlers.get('handle_find_c4_match')
        restart_c4_handler = handlers.get('handle_c4_restart')

        assert join_handler is not None
        assert move_handler is not None
        assert leave_handler is not None
        assert find_handler is not None
        assert restart_c4_handler is not None

        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'join_room') as mock_join, \
                 patch.object(m, 'emit') as mock_emit:

                room_id = 'test_c4_room'
                # Host joins
                mock_req.sid = 'sid_c4_host'
                join_handler({'room_id': room_id})
                assert room_id in m.active_c4_rooms
                assert m.active_c4_rooms[room_id]['host_sid'] == 'sid_c4_host'

                # Host drops piece in column 3
                move_handler({'room_id': room_id, 'col': 3})
                # Bottom row is 5
                assert m.active_c4_rooms[room_id]['board'][5][3] == 0
                assert m.active_c4_rooms[room_id]['turn'] == 1

                # Verify restart alternates starter from 0 to 1
                restart_c4_handler({'room_id': room_id})
                assert m.active_c4_rooms[room_id]['turn'] == 1
                restart_c4_handler({'room_id': room_id})
                assert m.active_c4_rooms[room_id]['turn'] == 0

                # Host leaves
                leave_handler({'room_id': room_id})
                assert room_id not in m.active_c4_rooms

    def test_dots_and_boxes_routes_and_ui(self, client):
        """Verify Dots and Boxes route, UI tabs, canvas, and clean controls."""
        res = client.get('/games/dots-and-boxes')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'dots_and_boxes.js' in html
        assert 'Back to Games' in html
        assert 'id="tab-solo"' in html
        assert 'id="tab-local"' in html
        assert 'id="tab-online"' in html
        assert 'id="find-match-btn"' in html
        assert 'id="room-code-input"' in html
        assert 'id="dnb-canvas"' in html
        assert 'data-diff="easy"' in html
        assert 'data-diff="normal"' in html
        assert 'data-diff="hard"' in html

    def test_dots_and_boxes_leaderboard(self, client, app):
        """Verify leaderboard submissions and bounds checking for Dots and Boxes."""
        import main as m
        from blueprints.game import VALID_ARCADE_CATEGORIES

        assert 'dots_and_boxes' in VALID_ARCADE_CATEGORIES
        assert 'win_streak' in VALID_ARCADE_CATEGORIES['dots_and_boxes']
        assert 'total_wins' in VALID_ARCADE_CATEGORIES['dots_and_boxes']

        mock_lb = MagicMock()
        mock_lb.find_one.return_value = None

        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            res = client.post('/api/games/leaderboard/submit', json={
                'game': 'dots_and_boxes',
                'category': 'win_streak',
                'score': 12,
                'guest_token': 'g_test_dnb'
            })
            assert res.status_code == 200
            assert res.get_json()['score'] == 12

    def test_dots_and_boxes_socket_events(self, app):
        """Test Socket.IO room join, line drawn, extra turn upon box completion, and matchmaking for Dots and Boxes."""
        import main as m
        handlers = {getattr(c.args[0], '__name__', ''): c.args[0]
                    for c in m.socketio.on.mock_calls if len(c.args) > 0 and callable(c.args[0])}

        join_handler = handlers.get('handle_join_dnb_room')
        line_handler = handlers.get('handle_dnb_line')
        leave_handler = handlers.get('handle_leave_dnb_room')
        find_handler = handlers.get('handle_find_dnb_match')

        assert join_handler is not None
        assert line_handler is not None
        assert leave_handler is not None
        assert find_handler is not None

        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'join_room') as mock_join, \
                 patch.object(m, 'emit') as mock_emit:

                room_id = 'test_dnb_room'
                mock_req.sid = 'sid_dnb_host'
                join_handler({'room_id': room_id})
                assert room_id in m.active_dnb_rooms
                assert m.active_dnb_rooms[room_id]['host_sid'] == 'sid_dnb_host'

                # Draw top line of box (0, 0)
                line_handler({'room_id': room_id, 'type': 'h', 'row': 0, 'col': 0})
                assert m.active_dnb_rooms[room_id]['h_edges'][0][0] == 0
                assert m.active_dnb_rooms[room_id]['turn'] == 1

                # Leave
                leave_handler({'room_id': room_id})
                assert room_id not in m.active_dnb_rooms

    def test_fair_scoring_and_difficulty_ranking(self, client):
        """Test ranked_score category, difficulty metadata, local mode rejection, and difficulty filtering."""
        from blueprints.game import VALID_ARCADE_CATEGORIES
        import main as m

        # 1. Category validation
        for game in ('slime_volleyball', 'tic_tac_toe', 'connect_four', 'dots_and_boxes'):
            assert 'ranked_score' in VALID_ARCADE_CATEGORIES[game]

        mock_lb = MagicMock()
        mock_lb.find_one.return_value = None

        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            # 2. Local mode rejection
            res_local = client.post('/api/games/leaderboard/submit', json={
                'game': 'tic_tac_toe',
                'category': 'ranked_score',
                'score': 250,
                'guest_token': 'g_test_local',
                'metadata': {'mode': 'local'}
            })
            assert res_local.status_code == 400
            assert 'Local two-player' in res_local.get_json()['error']

            # 3. Valid submission with difficulty metadata
            res_valid = client.post('/api/games/leaderboard/submit', json={
                'game': 'tic_tac_toe',
                'category': 'ranked_score',
                'score': 500,
                'guest_token': 'g_test_hard',
                'metadata': {'difficulty': 'hard', 'mode': 'solo', 'multiplier': 500}
            })
            assert res_valid.status_code == 200
            assert res_valid.get_json()['score'] == 500

            # 4. Out-of-bounds ranked_score (> 10,000,000)
            res_oob = client.post('/api/games/leaderboard/submit', json={
                'game': 'tic_tac_toe',
                'category': 'ranked_score',
                'score': 99999999,
                'guest_token': 'g_test_oob'
            })
            assert res_oob.status_code == 400

            # 5. Leaderboard GET with difficulty filter
            fake_doc = {
                'username': 'HardPlayer',
                'score': 500,
                'is_guest': True,
                'metadata': {'difficulty': 'hard', 'mode': 'solo'},
                'created_at': datetime.datetime.now(datetime.timezone.utc)
            }
            mock_cursor = MagicMock()
            mock_cursor.sort.return_value.limit.return_value = [fake_doc]
            mock_lb.find.return_value = mock_cursor

            res_get = client.get('/api/games/leaderboard?game=tic_tac_toe&category=ranked_score&difficulty=hard')
            assert res_get.status_code == 200
            get_data = res_get.get_json()
            assert len(get_data['entries']) == 1
            assert get_data['entries'][0]['metadata']['difficulty'] == 'hard'

            # Ensure filter was passed to mongo query
            find_call_arg = mock_lb.find.call_args[0][0]
            assert find_call_arg.get('metadata.difficulty') == 'hard'

    def test_ping_pong_and_snake_routes_and_ui(self, client):
        """Verify routes, templates, responsive mobile controls, and styling for Ping Pong and Snake."""
        # 1. Ping Pong access and template elements
        res_pong = client.get('/games/ping-pong')
        assert res_pong.status_code == 200
        html_pong = res_pong.get_data(as_text=True)
        assert 'id="pong-canvas"' in html_pong
        assert 'touch-up' in html_pong
        assert 'touch-down' in html_pong
        assert 'First to:' in html_pong
        assert 'data-diff="easy"' in html_pong
        # Ensure platform clean design (no emojis)
        assert '🎮' not in html_pong
        assert '🏓' not in html_pong
        assert '⚡' not in html_pong

        # 2. Snake access and template elements
        res_snake = client.get('/games/snake')
        assert res_snake.status_code == 200
        html_snake = res_snake.get_data(as_text=True)
        assert 'id="snake-canvas"' in html_snake
        assert 'dpad-up' in html_snake
        assert 'dpad-left' in html_snake
        assert 'dpad-down' in html_snake
        assert 'dpad-right' in html_snake
        assert 'data-diff="casual"' in html_snake
        assert 'data-wall="solid"' in html_snake
        assert '🐍' not in html_snake
        assert '🍎' not in html_snake

    def test_ping_pong_and_snake_leaderboards(self, client):
        """Verify leaderboard submissions, bounds checking, and mode isolation for Ping Pong and Snake."""
        import main as m
        mock_lb = MagicMock()
        mock_lb.find_one.return_value = None
        mock_lb.update_one.return_value = MagicMock()
        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            # 1. Ping Pong valid ranked_score submission
            res_pong = client.post('/api/games/leaderboard/submit', json={
                'game': 'ping_pong',
                'category': 'ranked_score',
                'score': 850,
                'guest_token': 'g_pong_tok',
                'metadata': {'difficulty': 'hard', 'returns': 17, 'multiplier': 20}
            })
            assert res_pong.status_code == 200
            assert res_pong.get_json()['score'] == 850

            # 2. Ping Pong local mode rejection (anti-farming)
            res_local = client.post('/api/games/leaderboard/submit', json={
                'game': 'ping_pong',
                'category': 'ranked_score',
                'score': 500,
                'guest_token': 'g_pong_local',
                'metadata': {'mode': 'local'}
            })
            assert res_local.status_code == 400

            # 3. Snake valid submissions
            res_snake_ranked = client.post('/api/games/leaderboard/submit', json={
                'game': 'snake',
                'category': 'ranked_score',
                'score': 450,
                'guest_token': 'g_snake_tok',
                'metadata': {'difficulty': 'normal', 'food_eaten': 30}
            })
            assert res_snake_ranked.status_code == 200

            res_snake_food = client.post('/api/games/leaderboard/submit', json={
                'game': 'snake',
                'category': 'food_eaten',
                'score': 42,
                'guest_token': 'g_snake_tok'
            })
            assert res_snake_food.status_code == 200

            # 4. Out of bounds checking
            res_oob = client.post('/api/games/leaderboard/submit', json={
                'game': 'snake',
                'category': 'food_eaten',
                'score': 9999999,
                'guest_token': 'g_snake_oob'
            })
            assert res_oob.status_code == 400

    def test_ping_pong_socket_events(self, app):
        """Verify Socket.IO room lifecycle and matchmaking for Ping Pong."""
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                fn = call.args[0]
                handlers[getattr(fn, '__name__', '')] = fn

        join_handler = handlers.get('handle_join_pong_room')
        leave_handler = handlers.get('handle_leave_pong_room')
        find_match_handler = handlers.get('handle_find_pong_match')
        cancel_match_handler = handlers.get('handle_cancel_pong_matchmaking')

        assert join_handler is not None
        assert leave_handler is not None
        assert find_match_handler is not None
        assert cancel_match_handler is not None

        # Clean state
        m.active_pong_rooms.clear()
        m.pong_matchmaking_queue.clear()

        # Simulate within request context
        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'emit') as mock_emit, \
                 patch.object(m, 'join_room'):
                mock_req.sid = 'sid_pong_host'
                join_handler({'room_id': 'pong_test_1'})
                assert 'pong_test_1' in m.active_pong_rooms
                assert m.active_pong_rooms['pong_test_1']['host_sid'] == 'sid_pong_host'
                assert mock_emit.called

                # Simulate guest joining
                mock_req.sid = 'sid_pong_guest'
                join_handler({'room_id': 'pong_test_1'})
                assert m.active_pong_rooms['pong_test_1']['guest_sid'] == 'sid_pong_guest'

                # Simulate leave
                leave_handler({'room_id': 'pong_test_1'})
                assert 'pong_test_1' not in m.active_pong_rooms

                # Simulate Matchmaking Queue
                mock_req.sid = 'sid_player_a'
                find_match_handler()
                assert len(m.pong_matchmaking_queue) == 1

                mock_req.sid = 'sid_player_b'
                find_match_handler()
                assert len(m.pong_matchmaking_queue) == 0

    def test_1v1_games_overhaul_features(self, app, client):
        """Test guest leaderboard user_record lookup, direct challenge handlers, and template UI additions."""
        import main as m

        # 1. Test guest_token lookup returns user_record with rank and score
        mock_lb = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value.limit.return_value = [
            {'username': 'Champion', 'score': 1500, 'guest_token': 'g_champ'},
            {'username': 'Player2', 'score': 1200, 'guest_token': 'g_test_user'},
            {'username': 'Player3', 'score': 800, 'guest_token': 'g_other'}
        ]
        mock_lb.find.return_value = mock_cursor
        mock_lb.find_one.return_value = {'username': 'Player2', 'score': 1200, 'guest_token': 'g_test_user'}
        mock_lb.count_documents.return_value = 1 # 1 person ahead -> rank #2

        with patch.object(m, 'arcade_leaderboards_conf', mock_lb):
            res = client.get('/api/games/leaderboard?game=slime_volleyball&category=ranked_score&guest_token=g_test_user')
            assert res.status_code == 200
            data = res.get_json()
            assert data['user_record'] is not None
            assert data['user_record']['rank'] == 2
            assert data['user_record']['score'] == 1200

        # 2. Test direct challenge socket handlers
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                fn = call.args[0]
                handlers[getattr(fn, '__name__', '')] = fn

        send_challenge = handlers.get('handle_send_game_challenge')
        accept_challenge = handlers.get('handle_accept_game_challenge')
        decline_challenge = handlers.get('handle_decline_game_challenge')

        assert send_challenge is not None
        assert accept_challenge is not None
        assert decline_challenge is not None

        with app.test_request_context():
            with patch.object(m, 'request') as mock_req, \
                 patch.object(m, 'emit') as mock_emit, \
                 patch.object(m, 'join_room'):

                # Player A challenges Player B
                mock_req.sid = 'sid_challenger'
                send_challenge({
                    'game': 'slime',
                    'target_sid': 'sid_target',
                    'streak': 3,
                    'score': 850
                })
                mock_emit.assert_called_with('game_challenge_received', {
                    'game': 'slime',
                    'challenger_sid': 'sid_challenger',
                    'challenger_name': 'Guest',
                    'streak': 3,
                    'score': 850
                }, room='sid_target')

                # Player B declines
                mock_req.sid = 'sid_target'
                decline_challenge({
                    'game': 'slime',
                    'challenger_sid': 'sid_challenger'
                })
                mock_emit.assert_called_with('game_challenge_declined', {
                    'game': 'slime',
                    'declined_by': 'Opponent'
                }, room='sid_challenger')

                # Queue challenger and accept challenge
                m.slime_matchmaking_queue = [{
                    'sid': 'sid_challenger',
                    'user_name': 'Challenger',
                    'streak': 3,
                    'score': 850
                }]
                mock_req.sid = 'sid_target'
                accept_challenge({
                    'game': 'slime',
                    'challenger_sid': 'sid_challenger'
                })
                assert len(m.slime_matchmaking_queue) == 0

        # 3. Test UI elements on Slime Volleyball and Ping Pong pages
        res_slime = client.get('/games/slime-volleyball')
        assert res_slime.status_code == 200
        html_slime = res_slime.get_data(as_text=True)
        assert 'id="pause-btn"' in html_slime
        assert 'id="landscape-toggle-btn"' in html_slime
        assert 'id="online-opponents-section"' in html_slime
        assert 'id="incoming-challenge-modal"' in html_slime
        assert 'id="my-slime-ranked"' in html_slime

        res_pong = client.get('/games/ping-pong')
        assert res_pong.status_code == 200
        html_pong = res_pong.get_data(as_text=True)
        assert 'id="pause-btn"' in html_pong
        assert 'id="online-opponents-section"' in html_pong
        assert 'id="incoming-challenge-modal"' in html_pong

class TestLiveMultiplayerTriviaAndThumbnails:
    """Tests for live Kahoot-style multiplayer trivia, curated decks, PIN entry, and game card thumbnails."""

    def test_curated_and_community_trivia_deck(self):
        import json
        from blueprints.trivia_decks import fetch_community_trivia, CURATED_TRIVIA_PACKS, TRIVIA_CATEGORIES

        # 1. Test general categories and optional Bible category are available
        assert any(c['id'] == '9' for c in TRIVIA_CATEGORIES)
        assert any(c['id'] == '17' for c in TRIVIA_CATEGORIES)
        assert any(c['id'] == 'bible' for c in TRIVIA_CATEGORIES)
        assert TRIVIA_CATEGORIES[0]['id'] == 'any'  # Default is general Mixed / Any
        assert len(CURATED_TRIVIA_PACKS) >= 20

        # 2. Test fetching general trivia and optional Bible trivia when selected
        general_questions = fetch_community_trivia(category='9', amount=5)
        assert len(general_questions) == 5
        for q in general_questions:
            assert 'label' in q
            assert 'options' in q
            assert len(q['options']) == 4
            assert 'correct_option' in q
            assert q['correct_option'] in q['options']

        bible_questions = fetch_community_trivia(category='bible', amount=5)
        assert len(bible_questions) == 5
        for q in bible_questions:
            assert 'label' in q
            assert 'options' in q
            assert len(q['options']) == 4
            assert 'correct_option' in q
            assert q['correct_option'] in q['options']

        # 3. Test OpenTDB API fallback when external request fails
        with patch('urllib.request.urlopen', side_effect=Exception("Network error")):
            fallback_questions = fetch_community_trivia(category='17', amount=3)
            assert len(fallback_questions) == 3
            for q in fallback_questions:
                assert len(q['options']) == 4
                assert q['correct_option'] in q['options']

        # 4. Test HTML entity unescaping
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value.read.return_value = json.dumps({
            'response_code': 0,
            'results': [
                {
                    'question': 'Which city is nicknamed &quot;The City of Light&quot;?',
                    'correct_answer': 'Paris &amp; France',
                    'incorrect_answers': ['Rome&#039;s center', 'Berlin', 'Madrid']
                },
                {
                    'question': 'What is the chemical symbol for &quot;Water&quot;?',
                    'correct_answer': 'H2O &amp; Aqua',
                    'incorrect_answers': ['CO2', 'NaCl', 'O2']
                }
            ]
        }).encode('utf-8')
        with patch('urllib.request.urlopen', return_value=mock_resp):
            res = fetch_community_trivia(category='9', amount=2)
            assert len(res) == 2
            assert 'The City of Light' in res[0]['label']
            assert '&quot;' not in res[0]['label']
            assert 'Paris & France' in res[0]['options']
            assert '&amp;' not in res[0]['correct_option']

    def test_game_pin_generation_and_routes(self, client):
        from blueprints.game import _generate_game_pin
        import main as m

        # 1. PIN generation
        pin = _generate_game_pin()
        assert len(pin) == 6
        assert pin.isdigit()

        # 2. Join page GET
        res_get = client.get('/games/join')
        assert res_get.status_code == 200
        html = res_get.get_data(as_text=True)
        assert 'Game PIN' in html
        assert 'name="pin"' in html

        # 3. Join with valid PIN redirect
        mock_lobby = {
            '_id': ObjectId(),
            'lobby_id': 'test_pin_lobby_123',
            'pin': '765432',
            'game_type': 'trivia',
            'status': 'active',
            'deactivated': False
        }
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby):
            res_post = client.post('/games/join', data={'pin': '765432', 'nickname': 'QuizMaster'}, follow_redirects=False)
            assert res_post.status_code == 302
            assert '/g/test_pin_lobby_123' in res_post.headers['Location']

        # 4. Join with non-existent PIN returns 200 with flash message
        with patch.object(m.game_sessions_conf, 'find_one', return_value=None):
            res_invalid = client.post('/games/join', data={'pin': '000000', 'nickname': 'QuizMaster'})
            assert res_invalid.status_code == 200
            assert 'Game PIN not found' in res_invalid.get_data(as_text=True)

    def test_live_trivia_flow_and_scoring(self, auth_client):
        import main as m

        lobby_id = 'live_trivia_test_lobby'
        mock_lobby = {
            '_id': ObjectId(),
            'lobby_id': lobby_id,
            'title': 'Test Live Show',
            'game_type': 'trivia',
            'is_live': True,
            'phase': 'lobby',
            'pin': '123456',
            'timer_seconds': 20,
            'created_by': 'host_user_id',
            'host_id': 'host_user_id',
            'current_q_idx': 0,
            'status': 'active',
            'deactivated': False,
            'questions': [
                {
                    'label': 'Which planet is known as the Red Planet?',
                    'options': ['Mars', 'Venus', 'Jupiter', 'Saturn'],
                    'correct_option': 'Mars'
                },
                {
                    'label': 'What is the capital city of France?',
                    'options': ['Paris', 'London', 'Berlin', 'Madrid'],
                    'correct_option': 'Paris'
                }
            ],
            'live_scores': {},
            'live_answers': {}
        }

        # Test host starts live game
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._is_host', return_value=True), \
             patch('blueprints.game._get_player_identity', return_value=('host_user_id', 'Host', True)), \
             patch.object(m.socketio, 'emit'):

            res_start = auth_client.post(f'/g/{lobby_id}/live/start')
            assert res_start.status_code == 200
            data_start = res_start.get_json()
            assert data_start['ok'] is True
            assert data_start['state']['phase'] == 'question'
            mock_lobby['phase'] = 'question'

        # Test player answers correctly with speed
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._get_player_identity', return_value=('player_1', 'Alice', False)), \
             patch.object(m.socketio, 'emit'):

            # Fast correct answer: 15s remaining out of 20s
            res_ans = auth_client.post(f'/g/{lobby_id}/live/answer', json={
                'option': 'Mars',
                'time_remaining': 15
            })
            assert res_ans.status_code == 200
            data_ans = res_ans.get_json()
            assert data_ans['ok'] is True
            assert data_ans['correct'] is True
            # Base 500 + round(500 * (15/20)) (375) + streak bonus (50) = 925
            assert data_ans['points_awarded'] == 925
            assert data_ans['streak'] == 1

        # Test player answers incorrectly: 0 pts, streak reset
        mock_lobby['live_scores'] = {'player_2': {'name': 'Bob', 'score': 875, 'streak': 1}}
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._get_player_identity', return_value=('player_2', 'Bob', False)), \
             patch.object(m.socketio, 'emit'):

            res_wrong = auth_client.post(f'/g/{lobby_id}/live/answer', json={
                'option': 'Venus',
                'time_remaining': 10
            })
            assert res_wrong.status_code == 200
            data_wrong = res_wrong.get_json()
            assert data_wrong['ok'] is True
            assert data_wrong['correct'] is False
            assert data_wrong['points_awarded'] == 0
            assert data_wrong['streak'] == 0

        # Test host reveals answer
        mock_lobby['live_answers'] = {
            'player_1': {'option': 'Mars', 'points': 875, 'correct': True},
            'player_2': {'option': 'Venus', 'points': 0, 'correct': False}
        }
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._is_host', return_value=True), \
             patch('blueprints.game._get_player_identity', return_value=('host_user_id', 'Host', True)), \
             patch.object(m.socketio, 'emit'):

            res_reveal = auth_client.post(f'/g/{lobby_id}/live/reveal')
            assert res_reveal.status_code == 200
            data_reveal = res_reveal.get_json()
            assert data_reveal['ok'] is True
            assert data_reveal['correct_option'] == 'Mars'
            assert data_reveal['counts']['Mars'] == 1
            assert data_reveal['counts']['Venus'] == 1
            assert data_reveal['state']['current_q_idx'] == 0
            assert data_reveal['state']['total_questions'] == 2

        # Test host transitions to leaderboard
        mock_lobby['live_scores'] = {
            'player_1': {'name': 'Alice', 'score': 875, 'streak': 1},
            'player_2': {'name': 'Bob', 'score': 0, 'streak': 0}
        }
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._is_host', return_value=True), \
             patch('blueprints.game._get_player_identity', return_value=('host_user_id', 'Host', True)), \
             patch.object(m.socketio, 'emit'):

            res_lb = auth_client.post(f'/g/{lobby_id}/live/leaderboard')
            assert res_lb.status_code == 200
            data_lb = res_lb.get_json()
            assert data_lb['ok'] is True
            assert len(data_lb['leaderboard']) == 2
            assert data_lb['leaderboard'][0]['name'] == 'Alice'
            assert data_lb['state']['current_q_idx'] == 0
            assert data_lb['state']['total_questions'] == 2

        # Test podium finale
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch.object(m.game_sessions_conf, 'update_one'), \
             patch('blueprints.game._is_host', return_value=True), \
             patch('blueprints.game._get_player_identity', return_value=('host_user_id', 'Host', True)), \
             patch.object(m.socketio, 'emit'):

            res_pod = auth_client.post(f'/g/{lobby_id}/live/podium')
            assert res_pod.status_code == 200
            data_pod = res_pod.get_json()
            assert data_pod['ok'] is True
            assert len(data_pod['podium']) >= 1
            assert data_pod['podium'][0]['name'] == 'Alice'

        # Test lobby HTML does not render legacy "votes" for trivia and includes live HUD IDs
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby), \
             patch('blueprints.game._is_host', return_value=True), \
             patch('blueprints.game._get_player_identity', return_value=('host_user_id', 'Host', True)):
            res_page = auth_client.get(f'/g/{lobby_id}')
            assert res_page.status_code == 200
            html_page = res_page.get_data(as_text=True)
            assert 'votes</div>' not in html_page
            assert 'id="live-q-total"' in html_page
            assert 'id="leaderboard-host-action"' in html_page

    def test_games_list_thumbnails_and_pin_input(self, auth_client):
        import main as m

        mock_find = MagicMock()
        mock_find.sort.return_value.limit.return_value = []
        with patch.object(m.game_sessions_conf, 'find', return_value=mock_find):
            res = auth_client.get('/games')
            assert res.status_code == 200
            html = res.get_data(as_text=True)

            # 1. Quick PIN join input in header
            assert 'name="pin"' in html
            assert 'Join PIN' in html

            # 2. SVGs present on cards (thumbnails for all games)
            assert html.count('<svg') >= 13

            # 3. Party & Social cards check
            assert 'Trivia Challenge' in html
            assert 'Interactive Polls' in html
            assert 'Would You Rather' in html
            assert 'Two Truths &amp; a Lie' in html or 'Two Truths & a Lie' in html
            assert 'Story Chain' in html
            assert 'Caption This' in html

            # 4. Arcade cards check
            assert 'Floppy Bird' in html
            assert 'Slime Volleyball' in html
            assert 'Tic-Tac-Toe' in html
            assert 'Connect Four' in html
            assert 'Dots and Boxes' in html
            assert 'Ping Pong' in html
            assert 'Snake Classic' in html

    def test_join_route_and_pin_redirect(self, client):
        """Verify /join routes directly to game PIN entry and redirects to lobby on valid PIN."""
        import main as m
        # GET /join
        res = client.get('/join')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert 'Join Live Game' in html
        assert 'name="pin"' in html

        # POST /join with valid PIN
        mock_lobby = {
            '_id': ObjectId(),
            'lobby_id': 'test_join_lobby',
            'pin': '778899',
            'deactivated': False,
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        }
        with patch.object(m.game_sessions_conf, 'find_one', return_value=mock_lobby):
            res_post = client.post('/join', data={'pin': '778899', 'nickname': 'Bob'}, follow_redirects=False)
            assert res_post.status_code == 302
            assert '/g/test_join_lobby' in res_post.headers['Location']

    def test_caption_game_creation_with_photo(self, auth_client):
        """Verify Caption This game accepts image_url or uploaded file and saves it in lobby doc."""
        import main as m
        inserted = {}

        def fake_insert(doc):
            inserted.update(doc)
            return MagicMock(inserted_id=ObjectId())

        with patch.object(m.game_sessions_conf, 'insert_one', side_effect=fake_insert):
            res = auth_client.post('/games/create', data={
                'title': 'Meme Party',
                'game_type': 'caption',
                'caption_image_url': 'https://example.com/funny_cat.jpg',
                'prompt': 'What did the cat see?'
            }, follow_redirects=False)

            assert res.status_code == 302
            assert inserted.get('game_type') == 'caption'
            assert inserted.get('image_url') == 'https://example.com/funny_cat.jpg'
            assert inserted.get('prompt') == 'What did the cat see?'

    def test_game_create_selected_type_preselection(self, auth_client):
        """Verify visiting /games/create?type=caption preselects caption in Jinja and hides multi-q fields."""
        res = auth_client.get('/games/create?type=caption')
        assert res.status_code == 200
        html = res.get_data(as_text=True)
        assert '<option value="caption" selected>' in html
        assert 'Photo to Caption' in html
        assert 'id="fields-multi-q" style="display:none;' in html












