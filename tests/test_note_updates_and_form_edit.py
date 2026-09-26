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
