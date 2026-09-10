import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security
from blueprints.whisper import FREE_DURATIONS, PREMIUM_DURATIONS, PENDING_INVITE_TIMEOUT_MINUTES, _utc_iso


class TestWhisperDurationsAndConstants:
    """Tests for whisper session parameters and tier durations."""

    def test_free_and_premium_durations(self):
        assert 15 in FREE_DURATIONS
        assert 30 in FREE_DURATIONS
        assert 60 in PREMIUM_DURATIONS
        assert 120 in PREMIUM_DURATIONS
        assert len(PREMIUM_DURATIONS) > len(FREE_DURATIONS)

    def test_pending_invite_timeout_minutes(self):
        assert PENDING_INVITE_TIMEOUT_MINUTES == 5

    def test_utc_iso_helper_formatting(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        iso_res = _utc_iso(now)
        assert iso_res.endswith('Z')
        parsed = security.parse_iso_utc(iso_res)
        assert parsed.tzinfo == datetime.timezone.utc

    def test_utc_iso_none_handling(self):
        assert _utc_iso(None) is None


class TestDirectMessagePermissions:
    """Tests for can_dm and DM privacy rules."""

    def test_dm_privacy_blocked(self, app):
        """When recipient has blocked sender, DMs are forbidden"""
        import main as m
        import database
        user_a = ObjectId()
        user_b = ObjectId()
        
        target_user = {'_id': user_b, 'blocked_user_ids': [user_a]}
        with patch.object(database.users_conf, 'find_one', side_effect=[None, target_user]):
            assert m.can_dm(str(user_a), str(user_b)) is False

    def test_dm_self_always_allowed(self, app):
        import main as m
        user_id = str(ObjectId())
        assert m.can_dm(user_id, user_id) is True


class TestWhisperLifecycle:
    """Tests for whisper note self-destruction and message decay."""

    def test_whisper_doc_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        whisper = {
            '_id': ObjectId(),
            'sender_id': ObjectId(),
            'recipient_id': ObjectId(),
            'duration_seconds': 30,
            'status': 'active',
            'created_at': now,
            'opened_at': None,
            'expires_at': now + datetime.timedelta(seconds=30)
        }
        assert whisper['created_at'].tzinfo == datetime.timezone.utc
        assert whisper['expires_at'] > whisper['created_at']
        assert whisper['status'] == 'active'


class TestWhisperEditHandler:
    """Tests for whisper in-place editing (F6; semantics DISCOVERY W.5)."""

    def _handlers(self):
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]
        return handlers

    def test_edit_overwrites_in_place_without_touching_ttl(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': ObjectId(me),
                       'recipient_id': ObjectId(partner), 'status': 'active'}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(me),
                   'content': 'old', 'message_type': 'text'}
        handlers = self._handlers()
        assert 'handle_whisper_edit' in handlers
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit, \
                    patch.object(m, 'encrypt_dm', return_value='ENC') as enc:
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_edit']({
                    'session_id': str(sid), 'message_id': str(mid), 'content': 'new text'})
                set_doc = msgs.update_one.call_args[0][1]['$set']
                assert set_doc['content'] == 'ENC'
                assert set_doc['edited'] is True
                # Ephemeral guarantee: no history kept, TTL never extended.
                assert 'expires_at' not in set_doc
                enc.assert_called_once_with('new text', me, partner)
                # Fanned out to BOTH rooms (DM parity).
                assert mock_emit.call_count == 2
                rooms = {c.kwargs.get('room') for c in mock_emit.call_args_list}
                assert rooms == {f'user_{me}', f'user_{partner}'}

    def test_edit_rejected_for_non_sender(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': ObjectId(me),
                       'recipient_id': ObjectId(partner), 'status': 'active'}
        # Message belongs to the partner, not me.
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(partner),
                   'content': 'theirs', 'message_type': 'text'}
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_edit']({
                    'session_id': str(sid), 'message_id': str(mid), 'content': 'hijack'})
                msgs.update_one.assert_not_called()
                assert mock_emit.call_count == 1  # error to requester only

    def test_edit_rate_guard_rejects_rapid_reedits(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': ObjectId(me),
                       'recipient_id': ObjectId(partner), 'status': 'active'}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(me),
                   'content': 'v2', 'message_type': 'text',
                   'edited_at': datetime.datetime.now(datetime.timezone.utc)}
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit'):
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_edit']({
                    'session_id': str(sid), 'message_id': str(mid), 'content': 'v3'})
                msgs.update_one.assert_not_called()


class TestWhisperHistoryEndpoint:
    """Tests for history parity: reactions, edited flags."""

    def test_history_returns_reactions_and_edits(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_history
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        ts = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)  # naive, Mongo-style
        session_doc = {'_id': sid, 'initiator_id': me, 'recipient_id': partner,
                       'status': 'active', 'proposed_duration_minutes': 15,
                       'started_at': ts, 'expires_at': ts}
        reacted_text = {'_id': ObjectId(), 'session_id': sid, 'sender_id': partner,
                        'content': 'hello', 'timestamp': ts, 'message_type': 'text',
                        'reactions': {str(partner): '❤️'}, 'edited': True}
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgc:
                sess.find_one.return_value = session_doc
                msgc.find.return_value.sort.return_value.limit.return_value = [dict(reacted_text)]
                res = api_whisper_history(str(sid))
        assert res.status_code == 200
        out = res.get_json()['messages']
        assert len(out) == 1
        txt = out[0]
        assert txt['reactions'] == {str(partner): '❤️'}
        assert txt['edited'] is True
        assert msgc.update_many.called


class TestChatEndpointsAuth:
    """Tests that chat routes require authentication."""

    def test_chat_page_requires_auth(self, client):
        res = client.get('/messages')
        assert res.status_code in [302, 401]

    def test_chat_messages_api_requires_auth(self, client):
        res = client.get('/api/messages/history/507f1f77bcf86cd799439011')
        assert res.status_code in [302, 401]


class TestSocketHandlersPayloadResilience:
    """Tests that socket handlers accept missing, None, or extra arguments without throwing TypeError or AttributeError."""

    def test_handle_join_inbox_with_none_and_args(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        user_obj = User(mock_user)

        with app.test_request_context():
            login_user(user_obj)
            join_inbox_handler = None
            for call in m.socketio.on.mock_calls:
                if len(call.args) > 0 and callable(call.args[0]) and getattr(call.args[0], '__name__', '') == 'handle_join_inbox':
                    join_inbox_handler = call.args[0]
                    break
            assert join_inbox_handler is not None

            with patch('main.join_room') as mock_join:
                # 0 arguments
                join_inbox_handler()
                mock_join.assert_called_with(f"user_{mock_user['_id']}")

                # 1 argument: None (the exact bug encountered when client sends ['join_inbox', None])
                join_inbox_handler(None)
                assert mock_join.call_count == 2

                # Extra arbitrary arguments
                join_inbox_handler(None, "extra", foo="bar")
                assert mock_join.call_count == 3

    def test_handle_viewing_and_leave_chat_with_none(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        user_obj = User(mock_user)

        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                fn = call.args[0]
                handlers[getattr(fn, '__name__', '')] = fn

        with app.test_request_context():
            login_user(user_obj)
            target_handlers = [
                'handle_viewing_chat', 'handle_leave_chat', 'handle_mark_messages_read', 'handle_typing',
                'handle_stop_typing', 'handle_recording_audio', 'handle_stop_recording',
                'handle_join_note', 'handle_leave_note', 'handle_acquire_lock',
                'handle_release_lock', 'handle_note_update', 'handle_discussion_new_comment',
                'handle_send_dm', 'handle_whisper_message', 'handle_whisper_typing',
                'handle_whisper_stop_typing', 'handle_whisper_read',
                'handle_whisper_screenshot', 'handle_whisper_react',
                'handle_whisper_edit'
            ]
            for name in target_handlers:
                assert name in handlers, f"Expected {name} to be registered with socketio.on"
                # Must safely tolerate None, empty dict, or extra args without throwing exceptions
                handlers[name](None)
                handlers[name]({})
                handlers[name](None, "extra", param=123)


class TestWhisperRESTFallbackEndpoints:
    """Tests for REST fallback endpoints: /api/whisper/edit/<mid> and /api/whisper/view_once/burn/<mid>."""

    def test_rest_edit_message_success(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_edit
        me = mock_user['_id']
        partner = ObjectId()
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': me, 'recipient_id': partner,
                       'status': 'active', 'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': me,
                   'content': 'original', 'message_type': 'text'}

        with app.test_request_context(json={'content': 'updated text'}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m.socketio, 'emit') as mock_emit, \
                    patch.object(m, 'encrypt_dm', return_value='ENC_TEXT'):
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                res = api_whisper_edit(str(mid))
                assert res.status_code == 200
                assert res.get_json()['success'] is True
                set_call = msgs.update_one.call_args[0][1]['$set']
                assert set_call['content'] == 'ENC_TEXT'
                assert set_call['edited'] is True
                assert mock_emit.call_count == 2

    def test_rest_edit_message_unauthorized(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_edit
        partner = ObjectId()
        sid, mid = ObjectId(), ObjectId()
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': partner,
                   'content': 'not mine', 'message_type': 'text'}

        with app.test_request_context(json={'content': 'hacked'}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_messages_conf') as msgs:
                msgs.find_one.return_value = dict(msg_doc)
                res = api_whisper_edit(str(mid))
                status = res[1] if isinstance(res, tuple) else res.status_code
                assert status == 403

    def test_rest_edit_message_expired_session(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_edit
        me = mock_user['_id']
        partner = ObjectId()
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': me, 'recipient_id': partner,
                       'status': 'active', 'expires_at': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': me,
                   'content': 'original', 'message_type': 'text'}

        with app.test_request_context(json={'content': 'late edit'}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs:
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                res = api_whisper_edit(str(mid))
                status = res[1] if isinstance(res, tuple) else res.status_code
                assert status == 400

    def test_rest_view_once_burn_success(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_view_once_burn
        me = mock_user['_id']
        partner = ObjectId()
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': partner, 'recipient_id': me, 'status': 'active'}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': partner,
                   'view_once': True, 'image_url': 'https://example.com/p.jpg'}

        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m.socketio, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                res = api_whisper_view_once_burn(str(mid))
                assert res.status_code == 200
                assert res.get_json()['success'] is True
                unset_doc = msgs.update_one.call_args[0][1]['$unset']
                assert 'image_url' in unset_doc
                assert msgs.update_one.call_args[0][1]['$set']['view_once_destroyed'] is True
                assert mock_emit.call_count == 2

    def test_api_whisper_history_serves_partner_image(self, app, mock_user):
        """Verify whisper image sent by partner resolves with valid URL on history load."""
        import main as m
        from main import User, encrypt_dm
        from flask_login import login_user
        from blueprints.whisper import api_whisper_history
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid = ObjectId()
        mid = ObjectId()
        session_doc = {
            '_id': sid,
            'initiator_id': ObjectId(partner),
            'recipient_id': ObjectId(me),
            'status': 'active'
        }
        enc_url = encrypt_dm('https://res.cloudinary.com/demo/image/upload/sample.jpg', partner, me)
        msg_doc = {
            '_id': mid,
            'session_id': sid,
            'sender_id': ObjectId(partner),
            'content': '[Photo]',
            'message_type': 'image',
            'image_url': enc_url,
            'timestamp': datetime.datetime.now(datetime.timezone.utc),
            'is_system': False,
            'is_read': False
        }
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m.socketio, 'emit'):
                sess.find_one.return_value = session_doc
                mock_cursor = MagicMock()
                mock_cursor.sort.return_value = mock_cursor
                mock_cursor.limit.return_value = [msg_doc]
                msgs.find.return_value = mock_cursor
                res = api_whisper_history(str(sid))
                assert res.status_code == 200
                data = res.get_json()
                assert len(data['messages']) == 1
                loaded_msg = data['messages'][0]
                assert loaded_msg['message_type'] == 'image'
                assert 'sample.jpg' in loaded_msg['image_url']
                assert '[Content unavailable' not in loaded_msg['image_url']

    def test_whisper_image_serve_url_defensive(self, app):
        """Verify _whisper_image_serve_url handles duplicate IDs and corrupted data safely."""
        import main as m
        from main import _whisper_image_serve_url
        msg_doc = {
            'image_url': 'gAAAAAB_invalid_ciphertext_dummy',
            'image_public_id': 'gAAAAAB_invalid_ciphertext_dummy',
            'media_encrypted': True,
            'mime_type': 'image/jpeg'
        }
        # With duplicate IDs and invalid ciphertext, it must return '' not /media/[Content unavailable]
        with app.test_request_context():
            url = _whisper_image_serve_url(msg_doc, 'same_id', 'same_id')
            assert url == ''
            assert '[Content unavailable' not in url


class TestWhisperExtend:
    """Tests for extending whisper sessions beyond 120 minutes with mutual consent."""

    def test_request_extend_beyond_120_minutes(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_extend
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        # Session already ran for 120 minutes
        started = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=118)
        expires = started + datetime.timedelta(minutes=120)
        session_doc = {
            '_id': sid,
            'initiator_id': me,
            'recipient_id': partner,
            'status': 'active',
            'started_at': started,
            'expires_at': expires
        }
        with app.test_request_context(json={'action': 'request', 'extra_minutes': 15}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m.socketio, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                res = api_whisper_extend(str(sid))
                assert res.status_code == 200
                data = res.get_json()
                assert data['success'] is True
                assert data['status'] == 'requested'
                assert sess.update_one.call_count == 1
                mock_emit.assert_called_once()
                assert mock_emit.call_args[0][0] == 'whisper_extend_request'

    def test_approve_extend_beyond_120_minutes(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_extend
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        started = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=120)
        expires = started + datetime.timedelta(minutes=120)
        session_doc = {
            '_id': sid,
            'initiator_id': partner,
            'recipient_id': me,
            'status': 'active',
            'started_at': started,
            'expires_at': expires,
            'pending_extension': {
                'requested_by': partner,
                'extra_minutes': 15,
                'at': datetime.datetime.now(datetime.timezone.utc)
            }
        }
        with app.test_request_context(json={'action': 'approve', 'extra_minutes': 15}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m.socketio, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                res = api_whisper_extend(str(sid))
                assert res.status_code == 200
                data = res.get_json()
                assert data['success'] is True
                assert data['extra_minutes'] == 15
                assert 'new_expires_at' in data
                assert data['new_expires_at'].endswith('Z')
                assert sess.update_one.call_count == 1
                assert msgs.update_many.call_count == 1
                assert mock_emit.call_count == 2

    def test_decline_extend(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_extend
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        session_doc = {
            '_id': sid,
            'initiator_id': partner,
            'recipient_id': me,
            'status': 'active',
            'pending_extension': {
                'requested_by': partner,
                'extra_minutes': 15,
                'at': datetime.datetime.now(datetime.timezone.utc)
            }
        }
        with app.test_request_context(json={'action': 'decline'}):
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m.socketio, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                res = api_whisper_extend(str(sid))
                assert res.status_code == 200
                data = res.get_json()
                assert data['success'] is True
                assert data['status'] == 'declined'
                assert sess.update_one.call_count == 1
                mock_emit.assert_called_once()
                assert mock_emit.call_args[0][0] == 'whisper_extend_declined'


class TestWhisperScreenshotAlert:
    """Tests for whisper screenshot alerts and session debounce."""

    def _handlers(self):
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]
        return handlers

    def test_screenshot_alert_printscreen_trigger(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid = ObjectId()
        session_doc = {
            '_id': sid,
            'initiator_id': ObjectId(me),
            'recipient_id': ObjectId(partner),
            'status': 'active',
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
        }
        handlers = self._handlers()
        assert 'handle_whisper_screenshot' in handlers
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                handlers['handle_whisper_screenshot']({
                    'session_id': str(sid),
                    'trigger': 'printscreen'
                })
                # Debounce update timestamp
                assert sess.update_one.call_count == 1
                update_set = sess.update_one.call_args[0][1]['$set']
                assert 'last_screenshot_alert_at' in update_set
                assert update_set['last_screenshot_alert_at'].tzinfo == datetime.timezone.utc

                # System message insertion
                assert msgs.insert_one.call_count == 1
                inserted_msg = msgs.insert_one.call_args[0][0]
                assert inserted_msg['session_id'] == sid
                assert inserted_msg['is_system'] is True
                assert 'desktop PrintScreen' in inserted_msg['content']
                assert inserted_msg['timestamp'].tzinfo == datetime.timezone.utc

                # Fanned out to both rooms with ISO Z timestamp
                assert mock_emit.call_count == 2
                rooms = {c.kwargs.get('room') for c in mock_emit.call_args_list}
                assert rooms == {f'user_{me}', f'user_{partner}'}
                event_name = mock_emit.call_args_list[0].args[0]
                payload = mock_emit.call_args_list[0].args[1]
                assert event_name == 'whisper_screenshot_detected'
                assert payload['content'] == f"{mock_user['username']} captured the screen (desktop PrintScreen)"
                assert payload['timestamp'].endswith('Z')

    def test_screenshot_alert_debounced_within_10_seconds(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid = ObjectId()
        now = datetime.datetime.now(datetime.timezone.utc)
        session_doc = {
            '_id': sid,
            'initiator_id': ObjectId(me),
            'recipient_id': ObjectId(partner),
            'status': 'active',
            'last_screenshot_alert_at': now - datetime.timedelta(seconds=4),
            'expires_at': now + datetime.timedelta(minutes=15)
        }
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                handlers['handle_whisper_screenshot']({
                    'session_id': str(sid),
                    'trigger': 'printscreen'
                })
                # Debounced: no updates, no message insert, no socket emits
                sess.update_one.assert_not_called()
                msgs.insert_one.assert_not_called()
                mock_emit.assert_not_called()

    def test_screenshot_alert_unauthorized_user_ignored(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        initiator = str(ObjectId())
        recipient = str(ObjectId())
        sid = ObjectId()
        session_doc = {
            '_id': sid,
            'initiator_id': ObjectId(initiator),
            'recipient_id': ObjectId(recipient),
            'status': 'active'
        }
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                handlers['handle_whisper_screenshot']({
                    'session_id': str(sid),
                    'trigger': 'printscreen'
                })
                sess.update_one.assert_not_called()
                msgs.insert_one.assert_not_called()
                mock_emit.assert_not_called()

    def test_whisper_screenshot_template_fixes(self):
        """Verify web template contains expectingBlur flag, auto-clear blur duration, and no devtools alert."""
        import os
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 1. Photo picker false-positive fix
        assert 'onclick="triggerWhisperImagePicker()"' in content
        assert 'window._whisperExpectingBlur' in content
        assert 'if (window._whisperExpectingBlur) return;' in content

        # 2. Stuck-blur fix
        assert '_whisperBlurTimer' in content
        assert '_blurWhisperContent(autoClearMs)' in content or '_blurWhisperContent(2500)' in content
        assert '_blurWhisperContent(2500)' in content

        # 3. DevTools notification warning removed
        assert "_fireScreenshotAlert('devtools')" not in content

        # 4. Mobile reload FAB hidden in whisper mode
        assert 'body.whisper-open .mobile-fab' in content
        assert "document.body.classList.add('whisper-open');" in content
        assert "document.body.classList.remove('whisper-open');" in content

        # 5. Whisper reply quote rendering attaches directly to message bubble
        assert 'whisper-reply-quote' in content
        assert 'div.appendChild(quoteDiv);' in content
        assert 'whisperEscapeHtml' in content

    def test_whisper_extend_modal_stacking_order(self):
        """Verify .whisper-modal-overlay has higher z-index than .whisper-overlay so modals appear in front."""
        import os, re
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find z-index for .whisper-modal-overlay
        modal_match = re.search(r'\.whisper-modal-overlay\s*\{[^}]*z-index:\s*(\d+)', content)
        assert modal_match is not None, ".whisper-modal-overlay z-index not found"
        modal_z = int(modal_match.group(1))

        # Find z-index for .whisper-overlay
        overlay_match = re.search(r'\.whisper-overlay\s*\{[^}]*z-index:\s*(\d+)', content)
        assert overlay_match is not None, ".whisper-overlay z-index not found"
        overlay_z = int(overlay_match.group(1))

        # Modal overlay must be above the active whisper overlay
        assert modal_z > overlay_z, f"modal overlay z-index ({modal_z}) must be higher than whisper overlay ({overlay_z})"
        assert modal_z >= 1600

        # Verify extend modal cleanup on session end
        assert "document.getElementById('whisper-extend-modal').classList.remove('active');" in content


class TestWhisperVideoSupport:
    """Tests for video support in whisper and DM sessions."""

    def _handlers(self):
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]
        return handlers

    def test_video_upload_endpoint_success(self, app, auth_client):
        import io
        import main as m
        fake_video_bytes = b"\x00\x00\x00\x18ftypmp42" + b"A" * 100
        data = {
            'video': (io.BytesIO(fake_video_bytes), 'test_video.mp4', 'video/mp4')
        }
        mock_upload_res = {
            'public_id': 'dm_videos/test_vid_123',
            'secure_url': 'https://res.cloudinary.com/demo/raw/upload/test.mp4'
        }
        with patch.object(m.cloudinary.uploader, 'upload', return_value=mock_upload_res):
            res = auth_client.post('/api/messages/upload_video', data=data, content_type='multipart/form-data')
            assert res.status_code == 200
            rj = res.get_json()
            assert rj['success'] is True
            assert rj['resource_type'] == 'video'
            assert rj['public_id'] == 'dm_videos/test_vid_123'
            assert '/media/' in rj['url']

    def test_video_upload_endpoint_size_limit(self, app, auth_client):
        import io
        # 51 MB exceeds 50 MB limit
        large_bytes = b"0" * (51 * 1024 * 1024)
        data = {
            'video': (io.BytesIO(large_bytes), 'big.mp4', 'video/mp4')
        }
        res = auth_client.post('/api/messages/upload_video', data=data, content_type='multipart/form-data')
        assert res.status_code == 400
        assert 'exceeds' in res.get_json()['error']

    def test_video_upload_endpoint_invalid_extension(self, app, auth_client):
        import io
        data = {
            'video': (io.BytesIO(b"malicious content"), 'danger.exe', 'application/x-msdownload')
        }
        res = auth_client.post('/api/messages/upload_video', data=data, content_type='multipart/form-data')
        assert res.status_code == 400
        assert 'Unsupported video format' in res.get_json()['error']

    def test_handle_whisper_message_video(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid = ObjectId()
        session_doc = {
            '_id': sid,
            'initiator_id': ObjectId(me),
            'recipient_id': ObjectId(partner),
            'status': 'active',
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
        }
        handlers = self._handlers()
        assert 'handle_whisper_message' in handlers

        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit, \
                    patch.object(m, 'encrypt_dm', side_effect=lambda val, u1, u2: f"ENC_{val}"):
                sess.find_one.return_value = session_doc
                msgs.insert_one.side_effect = lambda d: d.setdefault('_id', ObjectId())
                video_url = 'https://echowithin.test/media/dm_videos/abc?sig=123'
                handlers['handle_whisper_message']({
                    'session_id': str(sid),
                    'message_type': 'video',
                    'video_url': video_url,
                    'video_public_id': 'dm_videos/abc',
                    'temp_id': 'temp-vid-1'
                })

                msgs.insert_one.assert_called_once()
                inserted_doc = msgs.insert_one.call_args[0][0]
                assert inserted_doc['message_type'] == 'video'
                assert inserted_doc['video_url'] == f"ENC_{video_url}"
                assert inserted_doc['image_url'] == f"ENC_{video_url}"
                assert inserted_doc['content'] == 'ENC_[Video]'
                assert inserted_doc['media_encrypted'] is True

                # Emitted to partner
                partner_emit = None
                for c in mock_emit.call_args_list:
                    if c.args[0] == 'whisper_new_message':
                        partner_emit = c
                        break
                assert partner_emit is not None
                payload = partner_emit.args[1]
                assert payload['message_type'] == 'video'
                assert payload['video_url'] == video_url
                assert payload['content'] == '[Video]'

    def test_whisper_history_returns_video(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_history
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        now = datetime.datetime.now(datetime.timezone.utc)
        session_doc = {
            '_id': sid,
            'initiator_id': me,
            'recipient_id': partner,
            'status': 'active',
            'started_at': now,
            'expires_at': now + datetime.timedelta(minutes=15)
        }
        vid_msg = {
            '_id': ObjectId(),
            'session_id': sid,
            'sender_id': partner,
            'content': '[Video]',
            'timestamp': now,
            'message_type': 'video',
            'video_url': 'gAAAAABsomething',
            'video_public_id': 'gAAAAABpub'
        }
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgc, \
                    patch.object(m, '_whisper_image_serve_url', return_value='https://echowithin.test/fresh_vid.mp4'):
                sess.find_one.return_value = session_doc
                msgc.find.return_value.sort.return_value.limit.return_value = [dict(vid_msg)]
                res = api_whisper_history(str(sid))
                assert res.status_code == 200
                messages = res.get_json()['messages']
                assert len(messages) == 1
                assert messages[0]['message_type'] == 'video'
                assert messages[0]['video_url'] == 'https://echowithin.test/fresh_vid.mp4'

    def test_whisper_cleanup_video(self, app):
        import main as m
        from blueprints.whisper import _cleanup_whisper_session_media
        sid = ObjectId()
        u1, u2 = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': u1, 'recipient_id': u2}
        vid_msg = {
            '_id': ObjectId(),
            'session_id': sid,
            'message_type': 'video',
            'video_public_id': 'dm_videos/test_vid_xyz',
            'media_encrypted': True
        }
        with patch.object(m, 'whisper_sessions_conf') as sess, \
                patch.object(m, 'whisper_messages_conf') as msgs, \
                patch.object(m, 'destroy_cloudinary_media') as mock_destroy:
            sess.find_one.return_value = session_doc
            msgs.find.return_value = [vid_msg]
            _cleanup_whisper_session_media(str(sid), session_doc)
            mock_destroy.assert_called_once_with('dm_videos/test_vid_xyz', resource_type='raw', delivery_type='authenticated')

    def test_serve_encrypted_media_range_stream(self, app, client):
        import main as m
        plain_video = b"0123456789abcdefghijklmnopqrstuvwxyz" # 36 bytes
        mock_req_res = MagicMock()
        mock_req_res.status_code = 200
        mock_req_res.content = b"ENCRYPTED_MEDIA_BYTES"

        with patch('main.media_serve_token_valid', return_value=True), \
                patch('main.generate_signed_cloudinary_url', return_value='https://example.com/raw_vid'), \
                patch('requests.get', return_value=mock_req_res), \
                patch('main.decrypt_media_bytes', return_value=plain_video):
            # Request byte range 0-9
            res = client.get('/media/dm_videos_sample?mime=video/mp4&sig=valid', headers={'Range': 'bytes=0-9'})
            assert res.status_code == 206
            assert res.headers.get('Content-Range') == 'bytes 0-9/36'
            assert res.headers.get('Content-Length') == '10'
            assert res.headers.get('Accept-Ranges') == 'bytes'
            assert res.data == b"0123456789"

    def test_whisper_video_template_artifacts(self):
        import os
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # CSS classes
        assert '.whisper-video-shield' in content
        assert '.whisper-video-fallback' in content

        # Video preview & file picker accept
        assert 'id="whisper-video-preview-vid"' in content
        assert 'accept="image/*,video/*"' in content

        # JS functions
        assert 'createWhisperProtectedVideo' in content
        assert "msg.message_type === 'video'" in content
        assert 'cancelWhisperImage' in content
        assert 'previewVid' in content


class TestRealtimeDeliveryRegressionFixes:
    """Tests verifying real-time delivery and read receipt fixes in DMs and Whisper."""

    def _handlers(self):
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]
        return handlers

    def test_handle_mark_messages_read_success(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user

        me = str(mock_user['_id'])
        partner_id = str(ObjectId())

        handlers = self._handlers()
        assert 'handle_mark_messages_read' in handlers

        with app.test_request_context():
            login_user(User(mock_user))

            with patch.object(m.direct_messages_conf, 'update_many') as mock_update, \
                 patch.object(m.socketio, 'emit') as mock_emit:
                handlers['handle_mark_messages_read']({'partner_id': partner_id})

                mock_update.assert_called_once_with(
                    {
                        'sender_id': ObjectId(partner_id),
                        'recipient_id': ObjectId(me),
                        'is_read': False
                    },
                    {'$set': {'is_read': True}}
                )
                mock_emit.assert_called_once_with(
                    'messages_read',
                    {'reader_id': me, 'sender_id': partner_id},
                    room=f"user_{partner_id}"
                )

    def test_multitab_chat_presence_isolation(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user

        me = str(mock_user['_id'])
        partner1 = str(ObjectId())

        m.active_chat_views.clear()
        m.sid_chat_views.clear()

        handlers = self._handlers()

        # Tab 1: views partner 1 with SID 'tab-1-sid'
        with app.test_request_context() as ctx:
            login_user(User(mock_user))
            ctx.request.sid = 'tab-1-sid'
            handlers['handle_viewing_chat']({'partner_id': partner1})
            assert partner1 in m.active_chat_views[me]
            assert m.sid_chat_views['tab-1-sid']['partner_id'] == partner1

        # Tab 2 (e.g. Arcade game): connects with SID 'game-tab-sid', does not view chat
        with app.test_request_context() as ctx:
            login_user(User(mock_user))
            ctx.request.sid = 'game-tab-sid'
            # Disconnects game tab
            handlers['handle_dm_disconnect']()
            # Crucial fix: Tab 1 chat presence MUST NOT be wiped!
            assert me in m.active_chat_views
            assert partner1 in m.active_chat_views[me]

        # Tab 3: opens partner 1 in second tab with SID 'tab-3-sid'
        with app.test_request_context() as ctx:
            login_user(User(mock_user))
            ctx.request.sid = 'tab-3-sid'
            handlers['handle_viewing_chat']({'partner_id': partner1})

        # Disconnect Tab 1: Tab 3 is still viewing partner 1
        with app.test_request_context() as ctx:
            login_user(User(mock_user))
            ctx.request.sid = 'tab-1-sid'
            handlers['handle_dm_disconnect']()
            assert partner1 in m.active_chat_views[me]

        # Disconnect Tab 3: now no tabs are viewing partner 1
        with app.test_request_context() as ctx:
            login_user(User(mock_user))
            ctx.request.sid = 'tab-3-sid'
            handlers['handle_dm_disconnect']()
            assert me not in m.active_chat_views or partner1 not in m.active_chat_views.get(me, set())

    def test_whisper_presence_and_immediate_read_receipt(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user

        sender_id = mock_user['_id']
        partner_id = ObjectId()
        session_id = ObjectId()

        m.active_chat_views.clear()
        m.sid_chat_views.clear()

        # Partner is actively viewing sender's chat (e.g. from startWhisperSession)
        m.active_chat_views[str(partner_id)] = {str(sender_id)}

        handlers = self._handlers()
        assert 'handle_whisper_message' in handlers

        session_doc = {
            '_id': session_id,
            'initiator_id': sender_id,
            'recipient_id': partner_id,
            'status': 'active',
            'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
        }

        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as mock_sess, \
                 patch.object(m, 'whisper_messages_conf') as mock_msgs, \
                 patch.object(m, 'emit') as mock_emit, \
                 patch.object(m, 'encrypt_dm', return_value='ENC_SECRET'):
                mock_sess.find_one.return_value = session_doc
                mock_msgs.insert_one.side_effect = lambda d: d.setdefault('_id', ObjectId())

                handlers['handle_whisper_message']({
                    'session_id': str(session_id),
                    'content': 'Hello in secret'
                })

                # Check that message was inserted as is_read: True
                assert mock_msgs.insert_one.called
                inserted = mock_msgs.insert_one.call_args[0][0]
                assert inserted['is_read'] is True

                # Check that whisper_read_receipt was emitted immediately to sender
                emitted_events = [call.args[0] for call in mock_emit.mock_calls if len(call.args) > 0]
                assert 'whisper_read_receipt' in emitted_events

    def test_messages_template_realtime_artifacts(self):
        import os
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'messages.html')
        with open(template_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 1. new_dm sends mark_messages_read ack
        assert "emitSocket('mark_messages_read', { partner_id: activeRecipientId });" in content

        # 2. startWhisperSession emits viewing_chat
        assert "emitWhisperSocket('viewing_chat', { partner_id: data.partner_id });" in content

        # 3. whisperSessionEnded emits leave_chat
        assert "emitWhisperSocket('leave_chat', { partner_id: whisperState.partnerId });" in content

        # 4. onSocketConnect re-emits viewing_chat for active whisper
        assert "window.whisperState.active" in content
        assert "emitSocket('viewing_chat', { partner_id: window.whisperState.partnerId });" in content







