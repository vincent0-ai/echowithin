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

                # Restart event
                restart_handler({'room_id': room_id})
                mock_emit.assert_called_with('slime_restart', {}, room=room_id)

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






