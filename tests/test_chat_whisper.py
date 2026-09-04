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


class TestWhisperViewOnceHandler:
    """Tests for the server-enforced view-once state machine (F7, W.6)."""

    def _handlers(self):
        import main as m
        handlers = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                handlers[getattr(call.args[0], '__name__', '')] = call.args[0]
        return handlers

    def _session(self, me, partner, sid):
        return {'_id': sid, 'initiator_id': ObjectId(me),
                'recipient_id': ObjectId(partner), 'status': 'active',
                'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)}

    def test_first_open_starts_destruction_and_reveals_to_opener_only(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        partner = str(ObjectId())
        me = str(mock_user['_id'])
        sid, mid = ObjectId(), ObjectId()
        # I am the recipient opening the partner's view-once photo.
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(partner),
                   'content': '[Photo]', 'message_type': 'image', 'view_once': True,
                   'viewed_by': [], 'view_once_opened_at': None,
                   'image_url': 'https://example.com/img.jpg',
                   'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)}
        handlers = self._handlers()
        assert 'handle_whisper_view_once_open' in handlers
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = self._session(partner, me, sid)
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_view_once_open']({
                    'session_id': str(sid), 'message_id': str(mid)})
                set_doc = msgs.update_one.call_args[0][1]['$set']
                assert me in set_doc['viewed_by']
                assert set_doc['view_once_opened_at'] is not None
                # TTL moves earlier only — never past the session window.
                assert set_doc['expires_at'] <= msg_doc['expires_at']
                emitted = [(c.args[0], c.args[1], c.kwargs.get('room')) for c in mock_emit.call_args_list]
                revealed = [e for e in emitted if e[0] == 'whisper_view_once_revealed']
                assert len(revealed) == 1 and revealed[0][2] == f'user_{me}'
                assert revealed[0][1].get('image_url') == 'https://example.com/img.jpg'
                updates = [e for e in emitted if e[0] == 'whisper_view_once_update']
                assert {u[2] for u in updates} == {f'user_{me}', f'user_{partner}'}
                assert 'image_url' not in updates[0][1]  # seal-broken notice carries no bytes

    def test_sender_preview_does_not_start_destruction(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(me),
                   'content': '[Photo]', 'message_type': 'image', 'view_once': True,
                   'viewed_by': [], 'image_url': 'https://example.com/img.jpg',
                   'expires_at': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)}
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = self._session(me, partner, sid)
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_view_once_open']({
                    'session_id': str(sid), 'message_id': str(mid)})
                msgs.update_one.assert_not_called()
                assert mock_emit.call_count == 1
                assert mock_emit.call_args[0][0] == 'whisper_view_once_revealed'

    def test_open_of_destroyed_message_reports_destroyed(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        # Bytes already $unset server-side.
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(partner),
                   'content': '[Photo]', 'message_type': 'image', 'view_once': True,
                   'viewed_by': [me], 'view_once_destroyed': True}
        handlers = self._handlers()
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = self._session(partner, me, sid)
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_view_once_open']({
                    'session_id': str(sid), 'message_id': str(mid)})
                assert mock_emit.call_args[0][0] == 'whisper_view_once_destroyed'

    def test_burn_destroys_bytes_immediately_and_emits_to_both(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        me = str(mock_user['_id'])
        partner = str(ObjectId())
        sid, mid = ObjectId(), ObjectId()
        session_doc = {'_id': sid, 'initiator_id': ObjectId(partner),
                       'recipient_id': ObjectId(me), 'status': 'active'}
        msg_doc = {'_id': mid, 'session_id': sid, 'sender_id': ObjectId(partner),
                   'content': '[Photo]', 'message_type': 'image', 'view_once': True,
                   'image_url': 'https://example.com/photo.jpg'}
        handlers = self._handlers()
        assert 'handle_whisper_view_once_burn' in handlers
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgs, \
                    patch.object(m, 'emit') as mock_emit:
                sess.find_one.return_value = session_doc
                msgs.find_one.return_value = dict(msg_doc)
                handlers['handle_whisper_view_once_burn']({
                    'session_id': str(sid), 'message_id': str(mid)})
                msgs.update_one.assert_called_once()
                unset_doc = msgs.update_one.call_args[0][1]['$unset']
                assert 'image_url' in unset_doc
                assert msgs.update_one.call_args[0][1]['$set']['view_once_destroyed'] is True
                assert mock_emit.call_count == 2
                rooms = {c.kwargs.get('room') for c in mock_emit.call_args_list}
                assert rooms == {f'user_{partner}', f'user_{me}'}


class TestWhisperHistoryEndpoint:
    """Tests for history parity: reactions, edited flags, view-once withholding (F4/F5/F7)."""

    def test_history_withholds_locked_bytes_but_returns_reactions(self, app, mock_user):
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
        locked_vo = {'_id': ObjectId(), 'session_id': sid, 'sender_id': partner,
                     'content': '[Photo]', 'timestamp': ts, 'message_type': 'image',
                     'view_once': True, 'viewed_by': [],
                     'image_url': 'https://example.com/secret.jpg'}
        reacted_text = {'_id': ObjectId(), 'session_id': sid, 'sender_id': partner,
                        'content': 'hello', 'timestamp': ts, 'message_type': 'text',
                        'reactions': {str(partner): '❤️'}, 'edited': True}
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgc:
                sess.find_one.return_value = session_doc
                msgc.find.return_value.sort.return_value.limit.return_value = [dict(locked_vo), dict(reacted_text)]
                res = api_whisper_history(str(sid))
        assert res.status_code == 200
        out = res.get_json()['messages']
        by_id = {x['id']: x for x in out}
        vo = by_id[str(locked_vo['_id'])]
        # Server enforcement: no bytes for an unopened view-once.
        assert vo['locked'] is True
        assert 'image_url' not in vo
        assert vo['view_once'] is True and vo['destroyed'] is False
        txt = by_id[str(reacted_text['_id'])]
        assert txt['reactions'] == {str(partner): '❤️'}
        assert txt['edited'] is True
        # DM parity: partner messages marked read on fetch.
        assert msgc.update_many.called

    def test_history_reveals_view_once_to_sender(self, app, mock_user):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_history
        me = mock_user['_id']
        partner = ObjectId()
        sid = ObjectId()
        ts = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        session_doc = {'_id': sid, 'initiator_id': me, 'recipient_id': partner,
                       'status': 'active', 'proposed_duration_minutes': 15,
                       'started_at': ts, 'expires_at': ts}
        own_vo = {'_id': ObjectId(), 'session_id': sid, 'sender_id': me,
                  'content': '[Photo]', 'timestamp': ts, 'message_type': 'image',
                  'view_once': True, 'viewed_by': [],
                  'image_url': 'https://example.com/mine.jpg'}
        with app.test_request_context():
            login_user(User(mock_user))
            with patch.object(m, 'whisper_sessions_conf') as sess, \
                    patch.object(m, 'whisper_messages_conf') as msgc:
                sess.find_one.return_value = session_doc
                msgc.find.return_value.sort.return_value.limit.return_value = [dict(own_vo)]
                res = api_whisper_history(str(sid))
        assert res.status_code == 200
        entry = res.get_json()['messages'][0]
        assert entry['locked'] is False
        assert entry['image_url'] == 'https://example.com/mine.jpg'


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
                'handle_viewing_chat', 'handle_leave_chat', 'handle_typing',
                'handle_stop_typing', 'handle_recording_audio', 'handle_stop_recording',
                'handle_join_note', 'handle_leave_note', 'handle_acquire_lock',
                'handle_release_lock', 'handle_note_update', 'handle_discussion_new_comment',
                'handle_send_dm', 'handle_whisper_message', 'handle_whisper_typing',
                'handle_whisper_stop_typing', 'handle_whisper_read',
                'handle_whisper_screenshot', 'handle_whisper_react',
                'handle_whisper_edit', 'handle_whisper_view_once_open',
                'handle_whisper_view_once_burn'
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




