from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
from security import limits

bp = Blueprint('whisper', __name__, template_folder='templates')

# --- Duration options per tier ---
FREE_DURATIONS = [15, 30]
PREMIUM_DURATIONS = [15, 30, 60, 120]
PENDING_INVITE_TIMEOUT_MINUTES = 5


def _utc_iso(dt):
    """Convert a datetime to an ISO string with Z suffix.
    
    Handles both aware and naive datetimes (MongoDB returns naive,
    which are always UTC). JavaScript needs the Z suffix to parse as UTC.
    Without it, new Date() treats the string as local time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.isoformat() + 'Z'
    return dt.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def _send_whisper_dm(sender_oid, recipient_oid, content):
    """Insert a whisper-related system message into the DM chat and emit via SocketIO."""
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    msg_doc = {
        'sender_id': sender_oid,
        'recipient_id': recipient_oid,
        'content': content,
        'encrypted': False,
        'timestamp': now,
        'is_read': False,
        'message_type': 'whisper_system'
    }
    result = m.direct_messages_conf.insert_one(msg_doc)
    payload = {
        'id': str(result.inserted_id),
        'sender_id': str(sender_oid),
        'content': content,
        'timestamp': now.isoformat().replace('+00:00', 'Z'),
        'message_type': 'whisper_system'
    }
    m.socketio.emit('new_dm', payload, room=f"user_{str(recipient_oid)}")


def _expire_stale_pending():
    """Cancel pending invites older than the timeout."""
    import main as m
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=PENDING_INVITE_TIMEOUT_MINUTES)
    result = m.whisper_sessions_conf.update_many(
        {'status': 'pending', 'created_at': {'$lt': cutoff}},
        {'$set': {'status': 'cancelled', 'cancelled_reason': 'timeout'}}
    )
    return result.modified_count


def _get_active_session(user_oid):
    """Return any active whisper session involving this user, or None.
    
    Also auto-expires sessions that have passed their expires_at timestamp.
    """
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    session = m.whisper_sessions_conf.find_one({
        'status': 'active',
        '$or': [
            {'initiator_id': user_oid},
            {'recipient_id': user_oid}
        ]
    })
    if not session:
        return None
    expires_at = session.get('expires_at')
    if expires_at:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if now >= expires_at:
            m.whisper_sessions_conf.update_one(
                {'_id': session['_id']},
                {'$set': {'status': 'expired', 'pending_extension': None}}
            )
            m.whisper_messages_conf.delete_many({'session_id': session['_id']})
            return None
    return session


def _is_participant(session_doc, user_id_str):
    """Check if user is a participant in the whisper session."""
    return user_id_str in (
        str(session_doc['initiator_id']),
        str(session_doc['recipient_id'])
    )


def _get_partner_id(session_doc, user_id_str):
    """Get the other participant's ID string."""
    if str(session_doc['initiator_id']) == user_id_str:
        return str(session_doc['recipient_id'])
    return str(session_doc['initiator_id'])


@bp.route('/api/whisper/invite', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def api_whisper_invite():
    """Create a whisper session invite."""
    import main as m
    try:
        data = request.get_json() or {}
        recipient_id_str = data.get('recipient_id')
        duration = data.get('duration', 15)

        if not recipient_id_str:
            return jsonify({'error': 'Recipient required'}), 400

        if str(current_user.id) == recipient_id_str:
            return jsonify({'error': 'Cannot whisper with yourself'}), 400

        # Validate duration against tier
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        allowed = PREMIUM_DURATIONS if tier == 'premium' else FREE_DURATIONS
        max_duration = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_whisper_duration', 30)

        if duration not in allowed or duration > max_duration:
            return jsonify({'error': f'Invalid duration. Allowed: {allowed}'}), 400

        # Check DM permission
        if not m.can_dm(str(current_user.id), recipient_id_str):
            return jsonify({'error': 'You need accepted DM permission first.'}), 403

        # Check recipient exists and hasn't disabled DMs
        recipient = m.users_conf.find_one({'_id': ObjectId(recipient_id_str)})
        if not recipient:
            return jsonify({'error': 'User not found'}), 404
        if recipient.get('dm_privacy') == 'nobody':
            return jsonify({'error': 'This user has disabled direct messages.'}), 403

        # Check daily session limit
        user_oid = ObjectId(current_user.id)
        today_start = datetime.datetime.now(datetime.timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        daily_limit = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('whisper_sessions_per_day', 3)
        today_count = m.whisper_sessions_conf.count_documents({
            'initiator_id': user_oid,
            'created_at': {'$gte': today_start}
        })
        if today_count >= daily_limit:
            return jsonify({'error': f'Daily whisper limit reached ({daily_limit}/day).'}), 429

        # Check no active session for either user
        if _get_active_session(user_oid):
            return jsonify({'error': 'You already have an active whisper session.'}), 409
        if _get_active_session(ObjectId(recipient_id_str)):
            return jsonify({'error': 'This user is already in a whisper session.'}), 409

        # Expire stale pending invites before checking
        _expire_stale_pending()

        # Check no pending invite between these users
        pending = m.whisper_sessions_conf.find_one({
            'status': 'pending',
            '$or': [
                {'initiator_id': user_oid, 'recipient_id': ObjectId(recipient_id_str)},
                {'initiator_id': ObjectId(recipient_id_str), 'recipient_id': user_oid}
            ]
        })
        if pending:
            return jsonify({'error': 'A whisper invite is already pending.'}), 409

        now = datetime.datetime.now(datetime.timezone.utc)
        session_doc = {
            'initiator_id': user_oid,
            'recipient_id': ObjectId(recipient_id_str),
            'status': 'pending',
            'proposed_duration_minutes': duration,
            'created_at': now,
            'started_at': None,
            'expires_at': None,
            'extensions': []
        }
        result = m.whisper_sessions_conf.insert_one(session_doc)

        # Notify recipient via SocketIO
        m.socketio.emit('whisper_invite_received', {
            'session_id': str(result.inserted_id),
            'from_user_id': str(current_user.id),
            'from_username': current_user.username,
            'duration_minutes': duration
        }, room=f"user_{recipient_id_str}")

        # Push notification
        m.send_push_notification_to_user(
            recipient_id_str,
            f"{current_user.username} wants to start a Whisper",
            f"A private {duration}-minute conversation",
            url=m.url_for('chat.messages_page', user_id=str(current_user.id), _external=True),
            tag=f'whisper-invite-{current_user.id}'
        )

        # DM system message (single — both parties see it from their perspective)
        _send_whisper_dm(
            user_oid, ObjectId(recipient_id_str),
            f'Whisper invite from {current_user.username} — {duration} min'
        )

        return jsonify({
            'success': True,
            'session_id': str(result.inserted_id),
            'duration_minutes': duration
        })

    except Exception as e:
        current_app.logger.error(f"Whisper invite error: {e}")
        return jsonify({'error': 'Failed to send invite'}), 500


@bp.route('/api/whisper/respond/<session_id>', methods=['POST'])
@login_required
def api_whisper_respond(session_id):
    """Accept or decline a whisper invite."""
    import main as m
    try:
        data = request.get_json() or {}
        action = data.get('action')  # 'accept' or 'decline'

        if action not in ('accept', 'decline'):
            return jsonify({'error': 'Invalid action'}), 400

        session_doc = m.whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'recipient_id': ObjectId(current_user.id),
            'status': 'pending'
        })
        if not session_doc:
            return jsonify({'error': 'Invite not found or already responded'}), 404

        initiator_id_str = str(session_doc['initiator_id'])
        now = datetime.datetime.now(datetime.timezone.utc)

        if action == 'decline':
            m.whisper_sessions_conf.update_one(
                {'_id': ObjectId(session_id)},
                {'$set': {'status': 'cancelled'}}
            )
            m.socketio.emit('whisper_decline', {
                'session_id': session_id,
                'by_username': current_user.username
            }, room=f"user_{initiator_id_str}")
            _send_whisper_dm(
                ObjectId(current_user.id), session_doc['initiator_id'],
                f'{current_user.username} declined the whisper invite'
            )
            return jsonify({'success': True, 'status': 'declined'})

        # Accept — start the session
        if _get_active_session(session_doc['initiator_id']):
            return jsonify({'error': 'The initiator is already in another whisper session.'}), 409
        if _get_active_session(session_doc['recipient_id']):
            return jsonify({'error': 'You are already in another whisper session.'}), 409

        duration = session_doc['proposed_duration_minutes']
        expires_at = now + datetime.timedelta(minutes=duration)

        m.whisper_sessions_conf.update_one(
            {'_id': ObjectId(session_id)},
            {'$set': {
                'status': 'active',
                'started_at': now,
                'expires_at': expires_at
            }}
        )

        # Insert start marker system message
        msg_expires = expires_at + datetime.timedelta(minutes=5)
        m.whisper_messages_conf.insert_one({
            'session_id': ObjectId(session_id),
            'sender_id': ObjectId(current_user.id),
            'content': f'Whisper started — {duration} minutes',
            'timestamp': now,
            'expires_at': msg_expires,
            'is_system': True
        })

        payload = {
            'session_id': session_id,
            'started_at': _utc_iso(now),
            'expires_at': _utc_iso(expires_at),
            'duration_minutes': duration,
            'partner_username': current_user.username,
            'partner_id': str(current_user.id)
        }

        # Notify initiator
        initiator_payload = dict(payload)
        initiator = m.users_conf.find_one({'_id': session_doc['initiator_id']}, {'username': 1})
        m.socketio.emit('whisper_accept', initiator_payload, room=f"user_{initiator_id_str}")

        # Notify self (acceptor)
        acceptor_payload = dict(payload)
        acceptor_payload['partner_username'] = initiator['username'] if initiator else 'User'
        acceptor_payload['partner_id'] = initiator_id_str
        m.socketio.emit('whisper_accept', acceptor_payload, room=f"user_{current_user.id}")

        # DM system messages for both parties
        initiator_oid = session_doc['initiator_id']
        recipient_oid = session_doc['recipient_id']
        _send_whisper_dm(initiator_oid, recipient_oid, f'Whisper started — {duration} min')

        return jsonify({'success': True, 'status': 'accepted', **payload})

    except Exception as e:
        current_app.logger.error(f"Whisper respond error: {e}")
        return jsonify({'error': 'Failed to respond'}), 500


@bp.route('/api/whisper/pending', methods=['GET'])
@login_required
def api_whisper_pending():
    """Return any pending whisper invites for the current user."""
    import main as m
    try:
        _expire_stale_pending()
        my_oid = ObjectId(current_user.id)
        incoming = m.whisper_sessions_conf.find_one({
            'recipient_id': my_oid,
            'status': 'pending'
        })
        outgoing = m.whisper_sessions_conf.find_one({
            'initiator_id': my_oid,
            'status': 'pending'
        })
        result = {'has_pending': False}
        if incoming:
            initiator = m.users_conf.find_one({'_id': incoming['initiator_id']}, {'username': 1})
            result = {
                'has_pending': True,
                'direction': 'incoming',
                'session_id': str(incoming['_id']),
                'from_username': initiator['username'] if initiator else 'User',
                'from_user_id': str(incoming['initiator_id']),
                'duration_minutes': incoming['proposed_duration_minutes']
            }
        elif outgoing:
            recipient = m.users_conf.find_one({'_id': outgoing['recipient_id']}, {'username': 1})
            result = {
                'has_pending': True,
                'direction': 'outgoing',
                'session_id': str(outgoing['_id']),
                'to_username': recipient['username'] if recipient else 'User',
                'to_user_id': str(outgoing['recipient_id']),
                'duration_minutes': outgoing['proposed_duration_minutes']
            }
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Whisper pending check error: {e}")
        return jsonify({'has_pending': False})


@bp.route('/api/whisper/extend/<session_id>', methods=['POST'])
@login_required
def api_whisper_extend(session_id):
    """Request or approve a time extension."""
    import main as m
    try:
        data = request.get_json() or {}
        action = data.get('action')  # 'request' or 'approve'
        try:
            extra_minutes = int(data.get('extra_minutes', 15))
            if extra_minutes <= 0 or extra_minutes > 120:
                return jsonify({'error': 'Invalid extra_minutes duration. Must be between 1 and 120 minutes.'}), 400
        except (TypeError, ValueError):
            return jsonify({'error': 'extra_minutes must be an integer.'}), 400

        session_doc = m.whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            return jsonify({'error': 'Session not found or not active'}), 404

        user_id_str = str(current_user.id)
        if not _is_participant(session_doc, user_id_str):
            return jsonify({'error': 'Not a participant'}), 403

        partner_id = _get_partner_id(session_doc, user_id_str)

        # Validate extra_minutes bounds against user tier limit
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        max_duration = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_whisper_duration', 30)

        # Calculate total duration so far
        started_at = session_doc['started_at']
        current_expires = session_doc['expires_at']
        total_so_far = (current_expires - started_at).total_seconds() / 60
        if total_so_far + extra_minutes > max_duration:
            return jsonify({'error': f'Cannot extend beyond {max_duration} minutes total.'}), 400

        if action == 'request':
            # Persist the extension request so only the partner can approve it.
            existing = session_doc.get('pending_extension')
            if existing:
                return jsonify({'error': 'An extension request is already pending. Wait for your partner to approve it.'}), 409
            m.whisper_sessions_conf.update_one(
                {'_id': session_doc['_id']},
                {'$set': {
                    'pending_extension': {
                        'requested_by': ObjectId(user_id_str),
                        'extra_minutes': extra_minutes,
                        'at': datetime.datetime.now(datetime.timezone.utc)
                    }
                }}
            )
            m.socketio.emit('whisper_extend_request', {
                'session_id': session_id,
                'requested_by': user_id_str,
                'requested_by_username': current_user.username,
                'extra_minutes': extra_minutes
            }, room=f"user_{partner_id}")
            return jsonify({'success': True, 'status': 'requested'})

        elif action == 'approve':
            pending_extension = session_doc.get('pending_extension')
            if not pending_extension:
                return jsonify({'error': 'No pending extension request to approve.'}), 409
            # SECURITY: the requester must NOT be allowed to approve their own request.
            if str(pending_extension.get('requested_by')) == user_id_str:
                return jsonify({'error': 'You cannot approve your own extension request.'}), 403
            # Only the partner of the requester may approve.
            if str(pending_extension.get('requested_by')) != partner_id:
                return jsonify({'error': 'Only the partner who received the request can approve it.'}), 403

            now = datetime.datetime.now(datetime.timezone.utc)
            extra_minutes = int(pending_extension.get('extra_minutes', extra_minutes))
            new_expires = current_expires + datetime.timedelta(minutes=extra_minutes)

            # Also extend TTL on whisper messages
            m.whisper_messages_conf.update_many(
                {'session_id': ObjectId(session_id)},
                {'$set': {'expires_at': new_expires + datetime.timedelta(minutes=5)}}
            )

            m.whisper_sessions_conf.update_one(
                {'_id': ObjectId(session_id)},
                {
                    '$set': {'expires_at': new_expires, 'pending_extension': None},
                    '$push': {'extensions': {
                        'requested_by': pending_extension['requested_by'],
                        'approved_by': ObjectId(user_id_str),
                        'extra_minutes': extra_minutes,
                        'at': now
                    }}
                }
            )

            payload = {
                'session_id': session_id,
                'new_expires_at': _utc_iso(new_expires),
                'extra_minutes': extra_minutes
            }
            m.socketio.emit('whisper_extended', payload, room=f"user_{partner_id}")
            m.socketio.emit('whisper_extended', payload, room=f"user_{user_id_str}")
            return jsonify({'success': True, **payload})

        return jsonify({'error': 'Invalid action'}), 400

    except Exception as e:
        current_app.logger.error(f"Whisper extend error: {e}")
        return jsonify({'error': 'Failed to process extension'}), 500


@bp.route('/api/whisper/end/<session_id>', methods=['POST'])
@login_required
def api_whisper_end(session_id):
    """End a whisper session early. Either participant can end it."""
    import main as m
    try:
        session_doc = m.whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id)
        })
        if not session_doc:
            return jsonify({'error': 'Session not found'}), 404

        if session_doc.get('status') == 'expired':
            return jsonify({'success': True, 'already_ended': True})

        user_id_str = str(current_user.id)
        if not _is_participant(session_doc, user_id_str):
            return jsonify({'error': 'Not a participant'}), 403

        partner_id = _get_partner_id(session_doc, user_id_str)

        # Emit "Session ended" via SocketIO for real-time display
        # (Not inserted into whisper_messages since they're all deleted below)
        now = datetime.datetime.now(datetime.timezone.utc)
        ended_msg = f'Session ended by {current_user.username}'
        m.socketio.emit('whisper_new_message', {
            'session_id': session_id,
            'sender_id': user_id_str,
            'content': ended_msg,
            'timestamp': _utc_iso(now),
            'is_system': True
        }, room=f"user_{partner_id}")
        m.socketio.emit('whisper_new_message', {
            'session_id': session_id,
            'sender_id': user_id_str,
            'content': ended_msg,
            'timestamp': _utc_iso(now),
            'is_system': True
        }, room=f"user_{user_id_str}")

        # Delete all whisper messages immediately
        m.whisper_messages_conf.delete_many({'session_id': ObjectId(session_id)})

        # Mark session as cancelled (if still pending) or expired (if active)
        final_status = 'cancelled' if session_doc.get('status') == 'pending' else 'expired'
        m.whisper_sessions_conf.update_one(
            {'_id': ObjectId(session_id)},
            {'$set': {
                'status': final_status,
                'ended_by': ObjectId(user_id_str),
                'expires_at': datetime.datetime.now(datetime.timezone.utc),
                'pending_extension': None
            }}
        )

        m.socketio.emit('whisper_expired', {
            'session_id': session_id,
            'ended_by': current_user.username,
            'reason': 'manual'
        }, room=f"user_{partner_id}")
        m.socketio.emit('whisper_expired', {
            'session_id': session_id,
            'ended_by': current_user.username,
            'reason': 'manual'
        }, room=f"user_{user_id_str}")

        # DM system message
        ender_name = current_user.username
        _send_whisper_dm(
            ObjectId(user_id_str), ObjectId(partner_id),
            f'Whisper session ended by {ender_name}'
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Whisper end error: {e}")
        return jsonify({'error': 'Failed to end session'}), 500


@bp.route('/api/whisper/active')
@login_required
def api_whisper_active():
    """Check if current user has an active or pending whisper session."""
    import main as m
    try:
        user_oid = ObjectId(current_user.id)
        
        # Check active sessions — auto-expires stale ones
        session_doc = _get_active_session(user_oid)
        
        if not session_doc:
            # Check pending invites
            _expire_stale_pending()
            session_doc = m.whisper_sessions_conf.find_one({
                'status': 'pending',
                '$or': [
                    {'initiator_id': user_oid},
                    {'recipient_id': user_oid}
                ]
            })

        if not session_doc:
            return jsonify({'active': False})

        partner_id = _get_partner_id(session_doc, str(current_user.id))
        partner = m.users_conf.find_one({'_id': ObjectId(partner_id)}, {'username': 1})

        result = {
            'active': True,
            'session_id': str(session_doc['_id']),
            'status': session_doc['status'],
            'partner_id': partner_id,
            'partner_username': partner['username'] if partner else 'User',
            'duration_minutes': session_doc['proposed_duration_minutes']
        }

        if session_doc.get('started_at'):
            result['started_at'] = _utc_iso(session_doc['started_at'])
        if session_doc.get('expires_at'):
            result['expires_at'] = _utc_iso(session_doc['expires_at'])

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Whisper active check error: {e}")
        return jsonify({'active': False})


@bp.route('/api/whisper/history/<session_id>')
@login_required
def api_whisper_history(session_id):
    """Fetch messages for an active whisper session (for reconnection)."""
    import main as m
    try:
        session_doc = m.whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            return jsonify({'error': 'Session not found or not active'}), 404

        user_id_str = str(current_user.id)
        if not _is_participant(session_doc, user_id_str):
            return jsonify({'error': 'Not a participant'}), 403

        partner_id = _get_partner_id(session_doc, user_id_str)
        messages = list(m.whisper_messages_conf.find(
            {'session_id': ObjectId(session_id)}
        ).sort('timestamp', 1).limit(500))

        now = datetime.datetime.now(datetime.timezone.utc)

        # Lazy view-once destroy sweep (W.6): messages past their single 60s
        # post-open window lose their bytes now; the TTL index is the backstop.
        # Bytes are $unset server-side — never merely hidden client-side.
        destroyed_ids = []
        for msg in messages:
            if (msg.get('view_once') and msg.get('view_once_opened_at')
                    and 'image_url' in msg and not msg.get('view_once_destroyed')):
                opened_at = msg['view_once_opened_at']
                if opened_at.tzinfo is None:
                    opened_at = opened_at.replace(tzinfo=datetime.timezone.utc)
                grace = getattr(m, 'WHISPER_VIEW_ONCE_GRACE_SECONDS', 60)
                if (now - opened_at).total_seconds() >= grace:
                    m.whisper_messages_conf.update_one(
                        {'_id': msg['_id']},
                        {'$unset': {'image_url': '', 'image_public_id': ''},
                         '$set': {'view_once_destroyed': True}}
                    )
                    msg.pop('image_url', None)
                    msg.pop('image_public_id', None)
                    msg['view_once_destroyed'] = True
                    destroyed_ids.append(str(msg['_id']))
        if destroyed_ids:
            initiator_str = str(session_doc['initiator_id'])
            recipient_str = str(session_doc['recipient_id'])
            for uid in (initiator_str, recipient_str):
                for mid in destroyed_ids:
                    m.socketio.emit('whisper_view_once_destroyed', {
                        'session_id': session_id,
                        'message_id': mid
                    }, room=f"user_{uid}")

        # DM parity (F4): fetching history marks the partner's messages read
        # and notifies them, exactly like DM history does with `messages_read`.
        m.whisper_messages_conf.update_many(
            {'session_id': ObjectId(session_id),
             'sender_id': ObjectId(partner_id),
             'is_read': {'$ne': True}},
            {'$set': {'is_read': True}}
        )
        m.socketio.emit('whisper_read_receipt', {
            'session_id': session_id,
            'reader_id': user_id_str
        }, room=f"user_{partner_id}")

        formatted = []
        for msg in messages:
            content = msg.get('content', '')
            msg_type = msg.get('message_type', 'text')
            is_sender = str(msg['sender_id']) == user_id_str
            if not msg.get('is_system'):
                if content and content.startswith('gAAAAA'):
                    try:
                        content = m.decrypt_dm(content, user_id_str, partner_id)
                    except Exception as err:
                        current_app.logger.warning(f"Whisper message decryption error: {err}")
            entry = {
                'id': str(msg['_id']),
                'sender_id': str(msg['sender_id']),
                'content': content,
                'timestamp': _utc_iso(msg.get('timestamp')),
                'is_system': msg.get('is_system', False),
                'message_type': msg_type,
                # DM parity (F4/F5/F6): per-message read state, edit flag, and
                # reactions (previously omitted, so reactions vanished on reload).
                'is_read': msg.get('is_read', False) if is_sender else True,
                'edited': bool(msg.get('edited', False)),
            }
            if msg.get('reactions'):
                entry['reactions'] = msg['reactions']
            if msg.get('view_once'):
                # Server enforcement (W.6): withhold bytes until opened.
                destroyed = bool(msg.get('view_once_destroyed')) or 'image_url' not in msg
                opened_by_me = user_id_str in (msg.get('viewed_by') or [])
                entry['view_once'] = True
                entry['viewed'] = bool(msg.get('viewed_by'))
                entry['destroyed'] = destroyed
                if not destroyed and (is_sender or opened_by_me):
                    serve = m._whisper_image_serve_url(msg, str(msg['sender_id']), partner_id)
                    if serve:
                        entry['image_url'] = serve
                        entry['locked'] = False
                    else:
                        entry['locked'] = True
                else:
                    entry['locked'] = True
            elif msg_type == 'image' and 'image_url' in msg:
                # DM parity (F5): re-serve fresh signed URLs on every fetch so
                # authenticated Cloudinary URLs never go stale after reload.
                serve = m._whisper_image_serve_url(msg, str(msg['sender_id']), partner_id)
                if serve:
                    entry['image_url'] = serve
            formatted.append(entry)

        return jsonify({'messages': formatted})

    except Exception as e:
        current_app.logger.error(f"Whisper history error: {e}")
        return jsonify({'error': 'Failed to fetch history'}), 500


@bp.route('/api/whisper/durations')
@login_required
def api_whisper_durations():
    """Return allowed whisper durations for the current user's tier."""
    import main as m
    try:
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        durations = PREMIUM_DURATIONS if tier == 'premium' else FREE_DURATIONS
        return jsonify({'durations': durations, 'tier': tier})
    except Exception:
        return jsonify({'durations': FREE_DURATIONS, 'tier': 'free'})


@bp.route('/api/whisper/edit/<message_id>', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def api_whisper_edit(message_id):
    """Edit own whisper text message in place (REST fallback; F6, W.5)."""
    import main as m
    try:
        data = request.get_json() or {}
        new_content = (data.get('content') or '').strip()
        if not new_content:
            return jsonify({'error': 'Content cannot be empty'}), 400
        if len(new_content) > getattr(m, 'WHISPER_MAX_CONTENT_LENGTH', 5000):
            return jsonify({'error': 'Message exceeds maximum length'}), 400

        try:
            msg_oid = ObjectId(message_id)
        except Exception:
            return jsonify({'error': 'Invalid message ID'}), 400

        msg = m.whisper_messages_conf.find_one({'_id': msg_oid})
        if not msg:
            return jsonify({'error': 'Message not found'}), 404

        user_id_str = str(current_user.id)
        if str(msg.get('sender_id')) != user_id_str:
            return jsonify({'error': 'Cannot edit messages sent by another user'}), 403

        if msg.get('message_type') == 'image' or msg.get('is_system'):
            return jsonify({'error': 'Cannot edit image or system messages'}), 400

        session_id = msg.get('session_id')
        session_doc = m.whisper_sessions_conf.find_one({
            '_id': session_id,
            'status': 'active'
        })
        if not session_doc:
            return jsonify({'error': 'Whisper session is no longer active'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = session_doc.get('expires_at')
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
            if now >= expires_at:
                return jsonify({'error': 'Whisper session has expired'}), 400

        # Edit rate guard (min 5s between edits of same message)
        last_edit = msg.get('edited_at')
        if last_edit:
            if last_edit.tzinfo is None:
                last_edit = last_edit.replace(tzinfo=datetime.timezone.utc)
            min_interval = getattr(m, 'WHISPER_EDIT_MIN_INTERVAL_SECONDS', 5)
            if (now - last_edit).total_seconds() < min_interval:
                return jsonify({'error': 'Editing too fast — wait a moment'}), 429

        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])
        partner_id = recipient_str if user_id_str == initiator_str else initiator_str

        encrypted = m.encrypt_dm(new_content, user_id_str, partner_id)
        m.whisper_messages_conf.update_one(
            {'_id': msg_oid},
            {'$set': {'content': encrypted, 'edited': True, 'edited_at': now}}
        )

        payload = {
            'session_id': str(session_id),
            'message_id': str(msg_oid),
            'content': new_content,
            'edited': True
        }
        m.socketio.emit('whisper_message_edited', payload, room=f"user_{partner_id}")
        m.socketio.emit('whisper_message_edited', payload, room=f"user_{user_id_str}")

        return jsonify({'success': True, 'message_id': str(msg_oid), 'content': new_content})
    except Exception as e:
        current_app.logger.error(f"Whisper REST edit error: {e}")
        return jsonify({'error': 'Failed to edit message'}), 500


@bp.route('/api/whisper/view_once/burn/<message_id>', methods=['POST'])
@login_required
def api_whisper_view_once_burn(message_id):
    """Immediately burn a view-once image when closed or dismissed (REST fallback; F7, W.6)."""
    import main as m
    try:
        try:
            msg_oid = ObjectId(message_id)
        except Exception:
            return jsonify({'error': 'Invalid message ID'}), 400

        msg = m.whisper_messages_conf.find_one({'_id': msg_oid})
        if not msg or not msg.get('view_once'):
            return jsonify({'error': 'View-once image not found'}), 404

        session_id = msg.get('session_id')
        session_doc = m.whisper_sessions_conf.find_one({
            '_id': session_id,
            'status': 'active'
        })
        if not session_doc:
            return jsonify({'error': 'Session not active'}), 400

        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])
        if user_id_str not in (initiator_str, recipient_str):
            return jsonify({'error': 'Unauthorized'}), 403

        m.whisper_messages_conf.update_one(
            {'_id': msg_oid},
            {'$unset': {'image_url': '', 'image_public_id': ''},
             '$set': {'view_once_destroyed': True}}
        )

        burned_payload = {'session_id': str(session_id), 'message_id': str(msg_oid)}
        m.socketio.emit('whisper_view_once_destroyed', burned_payload, room=f"user_{initiator_str}")
        m.socketio.emit('whisper_view_once_destroyed', burned_payload, room=f"user_{recipient_str}")

        return jsonify({'success': True, 'message_id': str(msg_oid)})
    except Exception as e:
        current_app.logger.error(f"Whisper REST view-once burn error: {e}")
        return jsonify({'error': 'Failed to burn image'}), 500
