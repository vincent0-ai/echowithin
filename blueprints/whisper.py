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
    """Return any active whisper session involving this user, or None."""
    import main as m
    return m.whisper_sessions_conf.find_one({
        'status': 'active',
        '$or': [
            {'initiator_id': user_oid},
            {'recipient_id': user_oid}
        ]
    })


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
            return jsonify({'success': True, 'status': 'declined'})

        # Accept — start the session
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

        payload = {
            'session_id': session_id,
            'started_at': now.isoformat().replace('+00:00', 'Z'),
            'expires_at': expires_at.isoformat().replace('+00:00', 'Z'),
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
        extra_minutes = data.get('extra_minutes', 15)

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

        # Validate extra_minutes
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
            m.socketio.emit('whisper_extend_request', {
                'session_id': session_id,
                'requested_by': user_id_str,
                'requested_by_username': current_user.username,
                'extra_minutes': extra_minutes
            }, room=f"user_{partner_id}")
            return jsonify({'success': True, 'status': 'requested'})

        elif action == 'approve':
            now = datetime.datetime.now(datetime.timezone.utc)
            new_expires = current_expires + datetime.timedelta(minutes=extra_minutes)

            # Also extend TTL on whisper messages
            m.whisper_messages_conf.update_many(
                {'session_id': ObjectId(session_id)},
                {'$set': {'expires_at': new_expires + datetime.timedelta(minutes=5)}}
            )

            m.whisper_sessions_conf.update_one(
                {'_id': ObjectId(session_id)},
                {
                    '$set': {'expires_at': new_expires},
                    '$push': {'extensions': {
                        'requested_by': ObjectId(data.get('requested_by', user_id_str)),
                        'approved_by': ObjectId(user_id_str),
                        'extra_minutes': extra_minutes,
                        'at': now
                    }}
                }
            )

            payload = {
                'session_id': session_id,
                'new_expires_at': new_expires.isoformat().replace('+00:00', 'Z'),
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
            '_id': ObjectId(session_id),
            'status': {'$in': ['active', 'pending']}
        })
        if not session_doc:
            return jsonify({'error': 'Session not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_participant(session_doc, user_id_str):
            return jsonify({'error': 'Not a participant'}), 403

        partner_id = _get_partner_id(session_doc, user_id_str)

        # Delete all whisper messages immediately
        m.whisper_messages_conf.delete_many({'session_id': ObjectId(session_id)})

        # Mark session as expired
        m.whisper_sessions_conf.update_one(
            {'_id': ObjectId(session_id)},
            {'$set': {
                'status': 'expired',
                'ended_by': ObjectId(user_id_str),
                'expires_at': datetime.datetime.now(datetime.timezone.utc)
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
        session_doc = m.whisper_sessions_conf.find_one({
            'status': {'$in': ['active', 'pending']},
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
            result['started_at'] = session_doc['started_at'].isoformat().replace('+00:00', 'Z')
        if session_doc.get('expires_at'):
            result['expires_at'] = session_doc['expires_at'].isoformat().replace('+00:00', 'Z')

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

        messages = list(m.whisper_messages_conf.find(
            {'session_id': ObjectId(session_id)}
        ).sort('timestamp', 1).limit(500))

        formatted = []
        for msg in messages:
            formatted.append({
                'id': str(msg['_id']),
                'sender_id': str(msg['sender_id']),
                'content': msg.get('content', ''),
                'timestamp': msg['timestamp'].isoformat().replace('+00:00', 'Z'),
                'is_system': msg.get('is_system', False)
            })

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
