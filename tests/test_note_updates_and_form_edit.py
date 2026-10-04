import datetime
import json
import pytest
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
from blueprints.forms import _encrypt_form_definition, _decrypt_form_definition
from notifications import notify_saved_note_clones


class TestSavedNoteUpdateNotifications:
    """Tests for real-time WebSocket and push notifications when an original note is updated."""

    def test_notify_saved_note_clones_emits_socket_and_push(self, app):
        source_note_id = ObjectId()
        author_id = ObjectId()
        clone1_id = ObjectId()
        clone1_user_id = ObjectId()
        clone2_id = ObjectId()
        clone2_user_id = ObjectId()

        mock_clones = [
            {'_id': clone1_id, 'user_id': clone1_user_id},
            {'_id': clone2_id, 'user_id': clone2_user_id}
        ]

        mock_posts_conf = MagicMock()
        mock_posts_conf.find.return_value = mock_clones

        mock_socketio = MagicMock()
        mock_send_push = MagicMock()

        with app.app_context(), \
             patch('database.personal_posts_conf', mock_posts_conf), \
             patch('notifications._get_main') as mock_main_getter, \
             patch('notifications.send_push_notification_async', mock_send_push):

            mock_main = MagicMock()
            mock_main.personal_posts_conf = mock_posts_conf
            mock_main.socketio = mock_socketio
            mock_main.redis_cache = None
            mock_main_getter.return_value = mock_main

            notify_saved_note_clones(source_note_id, author_id, "AliceAuthor")

            # Verify query excluded the author
            mock_posts_conf.find.assert_called_once_with(
                {
                    'source_note_id': source_note_id,
                    'user_id': {'$ne': author_id}
                },
                {'_id': 1, 'user_id': 1}
            )

            # Verify socketio.emit was called for both clone owners
            assert mock_socketio.emit.call_count == 2
            mock_socketio.emit.assert_any_call(
                'note_update_available',
                {
                    'note_id': str(clone1_id),
                    'source_note_id': str(source_note_id),
                    'author_name': 'AliceAuthor',
                    'message': 'AliceAuthor updated a note you saved.'
                },
                room=str(clone1_user_id)
            )
            mock_socketio.emit.assert_any_call(
                'note_update_available',
                {
                    'note_id': str(clone2_id),
                    'source_note_id': str(source_note_id),
                    'author_name': 'AliceAuthor',
                    'message': 'AliceAuthor updated a note you saved.'
                },
                room=str(clone2_user_id)
            )

            # Verify send_push_notification_async called for both clone owners
            assert mock_send_push.call_count == 2
            calls = mock_send_push.call_args_list
            assert calls[0][0][0] == str(clone1_user_id)
            assert calls[0][1]['tag'] == f'note-update-{source_note_id}'
            assert calls[0][1]['extra_data']['type'] == 'note_update_available'
            assert calls[0][1]['extra_data']['note_id'] == str(clone1_id)

    def test_notify_saved_note_clones_debounces_push_via_redis(self, app):
        source_note_id = ObjectId()
        author_id = ObjectId()
        clone_id = ObjectId()
        clone_user_id = ObjectId()

        mock_clones = [{'_id': clone_id, 'user_id': clone_user_id}]
        mock_posts_conf = MagicMock()
        mock_posts_conf.find.return_value = mock_clones

        mock_socketio = MagicMock()
        mock_send_push = MagicMock()
        mock_redis = MagicMock()
        # Redis key exists -> debounced!
        mock_redis.get.return_value = "1"

        with app.app_context(), \
             patch('database.personal_posts_conf', mock_posts_conf), \
             patch('notifications._get_main') as mock_main_getter, \
             patch('notifications.send_push_notification_async', mock_send_push):

            mock_main = MagicMock()
            mock_main.personal_posts_conf = mock_posts_conf
            mock_main.socketio = mock_socketio
            mock_main.redis_cache = mock_redis
            mock_main_getter.return_value = mock_main

            notify_saved_note_clones(source_note_id, author_id, "AliceAuthor")

            # Socket still emits immediately for active sessions
            assert mock_socketio.emit.call_count == 1
            # Push notification suppressed due to active debounce
            assert mock_send_push.call_count == 0


class TestFormEditing:
    """Tests for form owners editing questions, titles, and settings."""

    def test_forms_edit_get_unauthorized(self, auth_client, app):
        share_id = "test_form_unauth"
        other_user_id = ObjectId()

        mock_form = {
            '_id': ObjectId(),
            'owner_id': other_user_id,
            'title': 'Other Form',
            'description': 'Description',
            'questions': [],
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        }

        with patch('main.forms_conf.find_one', return_value=mock_form):
            res = auth_client.get(f'/forms/{share_id}/edit')
            # Should redirect with unauthorized flash
            assert res.status_code == 302
            assert '/forms' in res.headers['Location']

    def test_forms_edit_get_owner_renders_page(self, auth_client, app, mock_user):
        share_id = "test_form_owner"
        form_oid = ObjectId()

        questions = [
            {'id': 'q1', 'label': 'What is your name?', 'type': 'short_text', 'required': True, 'options': []},
            {'id': 'q2', 'label': 'Pick a color', 'type': 'single_choice', 'required': False, 'options': ['Red', 'Blue']}
        ]
        enc_title, enc_desc, enc_questions = _encrypt_form_definition(str(form_oid), "My Feedback Form", "Please fill out", questions)

        mock_form = {
            '_id': form_oid,
            'owner_id': mock_user['_id'],
            'title': enc_title,
            'description': enc_desc,
            'questions': enc_questions,
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'allow_anonymous': True,
            'max_responses': 50
        }

        with patch('main.forms_conf.find_one', return_value=mock_form), \
             patch('main.form_responses_conf.count_documents', return_value=3):
            res = auth_client.get(f'/forms/{share_id}/edit')
            assert res.status_code == 200
            html = res.get_data(as_text=True)
            assert 'Edit Form' in html
            assert 'My Feedback Form' in html
            assert 'What is your name?' in html
            assert 'Pick a color' in html
            assert '3 response' in html

    def test_forms_edit_post_updates_questions_and_settings(self, auth_client, app, mock_user):
        share_id = "test_form_save"
        form_oid = ObjectId()

        old_questions = [
            {'id': 'q1', 'label': 'Old Label', 'type': 'short_text', 'required': False, 'options': []}
        ]
        enc_title, enc_desc, enc_questions = _encrypt_form_definition(str(form_oid), "Old Title", "Old Desc", old_questions)

        mock_form = {
            '_id': form_oid,
            'owner_id': mock_user['_id'],
            'title': enc_title,
            'description': enc_desc,
            'questions': enc_questions,
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'expires_at': None
        }

        updated_questions = [
            {'id': 'q1', 'label': 'Updated Question 1', 'type': 'paragraph', 'required': True, 'options': []},
            {'id': 'q2_new', 'label': 'New Rating Question', 'type': 'rating', 'required': False, 'options': []}
        ]

        captured_update = {}
        def mock_update(query, update):
            captured_update.update(update.get('$set', {}))
            return MagicMock(modified_count=1)

        with patch('main.forms_conf.find_one', return_value=mock_form), \
             patch('main.forms_conf.update_one', side_effect=mock_update):

            res = auth_client.post(f'/forms/{share_id}/edit', data={
                'title': 'New Form Title',
                'description': 'Updated Description',
                'expires_in': '1d',
                'max_responses': '100',
                'allow_anonymous': '1',
                'questions_json': json.dumps(updated_questions)
            })

            assert res.status_code == 302
            assert f'/forms/{share_id}/responses' in res.headers['Location']
            assert 'title' in captured_update
            assert 'updated_at' in captured_update
            assert captured_update['updated_at'].tzinfo == datetime.timezone.utc
            assert captured_update['max_responses'] == 100
            assert captured_update['allow_anonymous'] is True
            assert captured_update['expires_at'] is not None

            # Decrypt questions from captured update to ensure they match
            mock_doc_for_decryption = {
                '_id': form_oid,
                'title': captured_update['title'],
                'description': captured_update['description'],
                'questions': captured_update['questions']
            }
            dec = _decrypt_form_definition(mock_doc_for_decryption)
            assert dec['title'] == 'New Form Title'
            assert dec['description'] == 'Updated Description'
            assert len(dec['questions']) == 2
            assert dec['questions'][0]['label'] == 'Updated Question 1'
            assert dec['questions'][0]['type'] == 'paragraph'
            assert dec['questions'][0]['required'] is True
            assert dec['questions'][1]['label'] == 'New Rating Question'
            assert dec['questions'][1]['type'] == 'rating'

    def test_api_edit_form_json_endpoint(self, auth_client, app, mock_user):
        share_id = "test_form_api"
        form_oid = ObjectId()

        mock_form = {
            '_id': form_oid,
            'owner_id': mock_user['_id'],
            'title': 'API Form',
            'description': 'Desc',
            'questions': [{'id': 'q1', 'label': 'Q1', 'type': 'short_text', 'required': False, 'options': []}],
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        }

        captured_update = {}
        def mock_update(query, update):
            captured_update.update(update.get('$set', {}))
            return MagicMock(modified_count=1)

        with patch('main.forms_conf.find_one', return_value=mock_form), \
             patch('main.forms_conf.update_one', side_effect=mock_update):

            payload = {
                'title': 'API Updated Title',
                'description': 'API Updated Desc',
                'questions': [
                    {'id': 'q1', 'label': 'Q1 Modified', 'type': 'short_text', 'required': True, 'options': []}
                ],
                'max_responses': 25,
                'allow_anonymous': False
            }

            res = auth_client.post(
                f'/api/forms/{share_id}/edit',
                json=payload
            )

            assert res.status_code == 200
            data = res.get_json()
            assert data['success'] is True
            assert data['share_id'] == share_id
            assert captured_update['allow_anonymous'] is False
            assert captured_update['max_responses'] == 25
            assert captured_update['updated_at'].tzinfo == datetime.timezone.utc


class TestFormQuestionAlignment:
    """Test smart question alignment and retired answer handling when forms are edited."""

    def test_align_response_answers_retained_and_new_questions(self):
        from blueprints.forms import _align_response_answers

        current_questions = [
            {'id': 'q_name', 'label': 'Full Name', 'type': 'short_text'},
            {'id': 'q_phone', 'label': 'Phone Number', 'type': 'short_text'},  # Replaced Q2 (was Email)
            {'id': 'q_new', 'label': 'Favorite Hobby', 'type': 'short_text'},   # Brand new Q
        ]

        past_answers = [
            {'question_id': 'q_name', 'label': 'Full Name', 'value': 'Alice'},
            {'question_id': 'q_phone', 'label': 'Email Address', 'value': 'alice@example.com'},  # Had same slot ID, but completely different question
        ]

        aligned, retired = _align_response_answers(current_questions, past_answers)

        # 1. Retained question 'Full Name' correctly maps to Alice
        assert aligned['q_name'] is not None
        assert aligned['q_name']['value'] == 'Alice'

        # 2. Replaced question 'Phone Number' is NOT misaligned with the old Email answer
        assert aligned['q_phone'] is None

        # 3. Brand new question has no answer (will render dash)
        assert aligned['q_new'] is None

        # 4. Old 'Email Address' answer is safely preserved in retired list
        assert len(retired) == 1
        assert retired[0]['label'] == 'Email Address'
        assert retired[0]['value'] == 'alice@example.com'

    def test_align_response_answers_retained_with_new_id(self):
        from blueprints.forms import _align_response_answers

        current_questions = [
            {'id': 'q_new_id', 'label': 'Full Name', 'type': 'short_text'},
        ]

        # In past submission, question was also 'Full Name', but had an old ID
        past_answers = [
            {'question_id': 'q_old_id', 'label': 'Full Name', 'value': 'Bob'},
        ]

        aligned, retired = _align_response_answers(current_questions, past_answers)

        # Matched by normalized label because question was retained despite ID change
        assert aligned['q_new_id'] is not None
        assert aligned['q_new_id']['value'] == 'Bob'
        assert len(retired) == 0


class TestFormVersionHistory:
    """Test version snapshots, legacy version synthesis, and multi-version tracking."""

    def test_resolve_form_versions_with_snapshots(self):
        from blueprints.forms import _resolve_form_versions

        v1_created = datetime.datetime(2026, 9, 1, 10, 0, tzinfo=datetime.timezone.utc)
        v2_created = datetime.datetime(2026, 10, 1, 12, 0, tzinfo=datetime.timezone.utc)

        form = {
            '_id': ObjectId(),
            'title': 'Test Questionnaire',
            'version': 2,
            'created_at': v1_created,
            'updated_at': v2_created,
            'questions': [
                {'id': 'q_current_1', 'label': 'Current Q1', 'type': 'short_text'},
                {'id': 'q_current_2', 'label': 'Current Q2', 'type': 'paragraph'}
            ],
            'versions': [
                {
                    'version': 1,
                    'title': 'Test Questionnaire v1',
                    'questions': [
                        {'id': 'q_old_1', 'label': 'Old Q1', 'type': 'short_text'},
                        {'id': 'q_old_2', 'label': 'Old Q2', 'type': 'short_text'}
                    ],
                    'created_at': v1_created,
                    'archived_at': v2_created
                }
            ]
        }

        r1 = {
            '_id': ObjectId(),
            'form_version': 1,
            'submitter_username': 'user1',
            'answers': [{'question_id': 'q_old_1', 'label': 'Old Q1', 'value': 'Ans1'}]
        }
        r2 = {
            '_id': ObjectId(),
            'form_version': 2,
            'submitter_username': 'user2',
            'answers': [{'question_id': 'q_current_1', 'label': 'Current Q1', 'value': 'Ans2'}]
        }

        versions_list, version_map = _resolve_form_versions(form, [r1, r2])

        assert len(versions_list) == 2
        assert versions_list[0]['version'] == 2
        assert versions_list[0]['is_current'] is True
        assert versions_list[0]['response_count'] == 1
        assert versions_list[1]['version'] == 1
        assert versions_list[1]['is_current'] is False
        assert versions_list[1]['response_count'] == 1

        assert r1['version_label'] == 'Version 1'
        assert r2['version_label'] == 'Version 2 (Current)'

    def test_legacy_form_version_synthesis(self):
        from blueprints.forms import _resolve_form_versions

        t1 = datetime.datetime(2026, 9, 4, 10, 0, tzinfo=datetime.timezone.utc)
        t_edit = datetime.datetime(2026, 10, 3, 10, 0, tzinfo=datetime.timezone.utc)

        # Form with no versions array, but edited on Oct 3
        form = {
            '_id': ObjectId(),
            'title': 'Legacy Form',
            'created_at': t1,
            'updated_at': t_edit,
            'questions': [
                {'id': 'q_new_1', 'label': 'New Q1'},
                {'id': 'q_new_2', 'label': 'New Q2'}
            ]
        }

        # Response from Sep 4 answering old question IDs
        r_legacy = {
            '_id': ObjectId(),
            'submitted_at': t1,
            'submitter_username': 'maryel',
            'answers': [
                {'question_id': 'q_legacy_a', 'label': 'Legacy A', 'value': 'A1'},
                {'question_id': 'q_legacy_b', 'label': 'Legacy B', 'value': 'B1'}
            ]
        }

        versions_list, version_map = _resolve_form_versions(form, [r_legacy])

        assert len(versions_list) == 2
        assert 1 in version_map
        assert 2 in version_map
        assert version_map[1]['label'] == 'Version 1 (Initial)'
        assert version_map[2]['label'] == 'Version 2 (Current)'
        assert version_map[1]['response_count'] == 1
        assert r_legacy['form_version'] == 1

    def test_multi_version_user_submission_linking(self):
        from blueprints.forms import _resolve_form_versions

        form = {
            '_id': ObjectId(),
            'version': 2,
            'questions': [{'id': 'q2', 'label': 'Q2'}],
            'versions': [{'version': 1, 'questions': [{'id': 'q1', 'label': 'Q1'}]}]
        }

        r1 = {
            '_id': ObjectId('507f1f77bcf86cd799439011'),
            'form_version': 1,
            'submitter_id': 'user_abc',
            'submitter_username': 'maryel',
            'submitted_at_formatted': 'Sep 4, 2026',
            'answers': [{'question_id': 'q1', 'label': 'Q1', 'value': 'v1 answer'}]
        }
        r2 = {
            '_id': ObjectId('507f1f77bcf86cd799439012'),
            'form_version': 2,
            'submitter_id': 'user_abc',
            'submitter_username': 'maryel',
            'submitted_at_formatted': 'Oct 4, 2026',
            'answers': [{'question_id': 'q2', 'label': 'Q2', 'value': 'v2 answer'}]
        }

        versions_list, version_map = _resolve_form_versions(form, [r1, r2])

        assert r1.get('has_multiple_submissions') is True
        assert r2.get('has_multiple_submissions') is True
        assert len(r1['other_submissions']) == 1
        assert r1['other_submissions'][0]['version'] == 2
        assert len(r2['other_submissions']) == 1
        assert r2['other_submissions'][0]['version'] == 1


class TestVisitorTrackingAndAuth:
    """Test bot user-agent filtering and token auth in requests."""

    def test_is_bot_user_agent(self):
        from blueprints.sharing import _is_bot_user_agent

        assert _is_bot_user_agent('WhatsApp/2.21.12.21 A') is True
        assert _is_bot_user_agent('TelegramBot (like TwitterBot)') is True
        assert _is_bot_user_agent('facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)') is True
        assert _is_bot_user_agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0') is True
        assert _is_bot_user_agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36') is False
        assert _is_bot_user_agent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36') is False
