from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, json, os, re, secrets
from security import limits, generate_conversation_envelope_keys

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('chat', __name__, template_folder='templates')


@bp.route('/messages')
@login_required
def messages_page():
    import main as m
    current_user_oid = ObjectId(current_user.id)
    pipeline = [
        {'$match': {'$or': [{'sender_id': current_user_oid}, {'recipient_id': current_user_oid}]}},
        {'$sort': {'timestamp': -1}},
        {'$group': {'_id': {'$cond': [{'$eq': ['$sender_id', current_user_oid]}, '$recipient_id', '$sender_id']}, 'last_message': {'$first': '$content'}, 'timestamp': {'$first': '$timestamp'}, 'unread_count': {'$sum': {'$cond': [{'$and': [{'$eq': ['$recipient_id', current_user_oid]}, {'$eq': ['$is_read', False]}]}, 1, 0]}}}},
        {'$sort': {'timestamp': -1}}
    ]
    contacts_raw = list(m.direct_messages_conf.aggregate(pipeline))
    # OPTIMIZATION: Batch-fetch all contact user docs in one query
    # instead of individual find_one() per contact
    _contact_ids = [c['_id'] for c in contacts_raw]
    _contact_users_map = {}
    if _contact_ids:
        for u in m.users_conf.find({'_id': {'$in': _contact_ids}}, {'username': 1, 'profile_image_url': 1, 'last_active': 1}):
            _contact_users_map[u['_id']] = u

    contacts = []
    contact_user_ids = set()
    five_minutes_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    def build_contact_entry(user_info, last_msg, timestamp, unread_count=0):
        is_online = False
        last_active = user_info.get('last_active')
        if last_active and isinstance(last_active, datetime.datetime):
            if last_active.tzinfo is None:
                last_active = last_active.replace(tzinfo=datetime.timezone.utc)
            is_online = last_active >= five_minutes_ago
        return {'user_id': str(user_info['_id']), 'username': user_info['username'], 'profile_image': user_info.get('profile_image_url'), 'last_message': last_msg, 'timestamp': timestamp, 'unread_count': unread_count, 'last_active': (user_info.get('last_active').isoformat() + 'Z').replace('+00:00Z', 'Z') if user_info.get('last_active') else None, 'is_online': is_online}
    for c in contacts_raw:
        user_info = _contact_users_map.get(c['_id'])
        if user_info:
            last_msg = c.get('last_message', '')
            if last_msg and last_msg.startswith('gAAAAA'):
                try:
                    last_msg = m.decrypt_dm(last_msg, str(current_user.id), str(user_info['_id']))
                except Exception:
                    pass
            contacts.append(build_contact_entry(user_info, last_msg, c['timestamp'], c['unread_count']))
            contact_user_ids.add(str(user_info['_id']))
    accepted_permissions = list(m.dm_permissions_conf.find({'status': 'accepted', '$or': [{'requester_id': current_user_oid}, {'target_id': current_user_oid}]}).sort('updated_at', -1))
    for perm in accepted_permissions:
        requester_id_str = str(perm.get('requester_id'))
        target_id_str = str(perm.get('target_id'))
        is_requester = requester_id_str == str(current_user.id)
        other_user_id_str = target_id_str if is_requester else requester_id_str
        if other_user_id_str in contact_user_ids:
            continue
        try:
            other_user_oid = ObjectId(other_user_id_str)
        except Exception:
            continue
        user_info = m.users_conf.find_one({'_id': other_user_oid}, {'username': 1, 'profile_image_url': 1, 'last_active': 1})
        if not user_info:
            continue
        system_preview = f"{user_info['username']} accepted your message request" if is_requester else f"You accepted {user_info['username']}'s message request"
        event_time = perm.get('updated_at') or perm.get('created_at') or datetime.datetime.now(datetime.timezone.utc)
        contacts.append(build_contact_entry(user_info, system_preview, event_time, 0))
        contact_user_ids.add(other_user_id_str)
    contacts.sort(key=lambda c: c.get('timestamp') or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc), reverse=True)
    hidden_partners = set()
    for hc in m.hidden_chats_conf.find({'user_id': current_user_oid}, {'partner_id': 1}):
        hidden_partners.add(str(hc['partner_id']))
    contacts = [c for c in contacts if c['user_id'] not in hidden_partners]
    target_user_id = request.args.get('user_id')
    active_chat = None
    if target_user_id:
        target_oid = None
        try:
            target_oid = ObjectId(target_user_id)
        except Exception:
            pass
        if target_oid and not m.hidden_chats_conf.find_one({'user_id': current_user_oid, 'partner_id': target_oid}):
            active_chat = m.users_conf.find_one({'_id': target_oid}, {'username': 1, 'last_active': 1})
    pending_request_count = m.dm_permissions_conf.count_documents({'target_id': ObjectId(current_user.id), 'status': 'pending'})
    return render_template('messages.html', active_page='messages', contacts=contacts, active_chat=active_chat, pending_request_count=pending_request_count)


@bp.route('/api/messages/history/<other_user_id>')
@login_required
def api_message_history(other_user_id):
    import main as m
    try:
        other_id = ObjectId(other_user_id)
    except Exception:
        return jsonify({'error': 'Invalid user ID'}), 400
    other_user = m.users_conf.find_one({'_id': other_id}, {'username': 1, 'last_active': 1})
    if not other_user:
        return jsonify({'error': 'User not found'}), 404
    if m.hidden_chats_conf.find_one({'user_id': ObjectId(current_user.id), 'partner_id': other_id}):
        return jsonify({'messages': []})
    messages = list(m.direct_messages_conf.find({'$or': [{'sender_id': ObjectId(current_user.id), 'recipient_id': other_id}, {'sender_id': other_id, 'recipient_id': ObjectId(current_user.id)}]}).sort('timestamp', -1).limit(200))
    messages.reverse()
    m.direct_messages_conf.update_many({'sender_id': other_id, 'recipient_id': ObjectId(current_user.id), 'is_read': False}, {'$set': {'is_read': True}})
    formatted_messages = []
    for msg in messages:
        content = msg.get('content', '')
        if msg.get('encrypted') or (content and content.startswith('gAAAAA')):
            try:
                content = m.decrypt_dm(content, str(current_user.id), str(other_id))
            except Exception:
                pass
        msg_data = {'id': str(msg['_id']), 'sender_id': str(msg['sender_id']), 'content': content, 'timestamp': (msg['timestamp'].replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if msg['timestamp'].tzinfo is None else msg['timestamp'].isoformat().replace('+00:00', 'Z')), 'is_read': msg.get('is_read', False), 'message_type': msg.get('message_type', 'text')}
        if 'image_url' in msg:
            raw_img = msg['image_url']
            msg_data['image_url'] = m.decrypt_dm(raw_img, str(current_user.id), str(other_id)) if raw_img and raw_img.startswith('gAAAAA') else raw_img
        if 'reply_to_id' in msg:
            msg_data['reply_to_id'] = str(msg['reply_to_id'])
            raw_rtp = msg.get('reply_to_preview', '')
            msg_data['reply_to_preview'] = m.decrypt_dm(raw_rtp, str(current_user.id), str(other_id)) if raw_rtp and raw_rtp.startswith('gAAAAA') else raw_rtp
            msg_data['reply_to_sender'] = msg.get('reply_to_sender')
        if 'link_preview' in msg:
            lp = msg['link_preview']
            if lp and isinstance(lp, dict):
                u1, u2 = str(current_user.id), str(other_id)
                msg_data['link_preview'] = {'url': m.decrypt_dm(lp.get('url', ''), u1, u2) if lp.get('url', '').startswith('gAAAAA') else lp.get('url', ''), 'title': m.decrypt_dm(lp.get('title', ''), u1, u2) if lp.get('title', '').startswith('gAAAAA') else lp.get('title', ''), 'description': m.decrypt_dm(lp.get('description', ''), u1, u2) if lp.get('description', '').startswith('gAAAAA') else lp.get('description', ''), 'image': m.decrypt_dm(lp.get('image', ''), u1, u2) if lp.get('image', '').startswith('gAAAAA') else lp.get('image', '')}
        if 'reactions' in msg:
            msg_data['reactions'] = msg['reactions']
        formatted_messages.append(msg_data)
        
    # Socket alert for real-time double checkmarks
    m.socketio.emit('messages_read', 
                  {'reader_id': str(current_user.id), 'sender_id': other_user_id}, 
                  room=f"user_{other_user_id}")
                  
    return jsonify({
        'messages': formatted_messages,
        'server_now': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
        'other_user_status': {
            'username': other_user['username'],
            'last_active': (other_user.get('last_active').isoformat() + 'Z').replace('+00:00Z', 'Z') if other_user.get('last_active') else None
        }
    })


@bp.route('/api/messages/unread_count')
@login_required
def api_unread_dm_count():
    import main as m
    count = m.direct_messages_conf.count_documents({'recipient_id': ObjectId(current_user.id), 'is_read': False})
    return jsonify({'count': count})


@bp.route('/api/notifications/badge-counts')
@login_required
def get_badge_counts():
    import main as m
    from blueprints.push import get_unread_notification_count
    user_id_str = str(current_user.id)
    cache_key = f"badge_counts:{user_id_str}"
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached:
                return jsonify(json.loads(cached))
        except Exception:
            pass

    notif_count = 0
    msg_count = 0

    try:
        notif_cache_key = f"unread_notif_count:{user_id_str}"
        notif_from_cache = False
        if m.redis_cache:
            try:
                cached_notif = m.redis_cache.get(notif_cache_key)
                if cached_notif is not None:
                    notif_count = int(cached_notif)
                    notif_from_cache = True
            except Exception:
                pass

        if not notif_from_cache:
            try:
                resp = get_unread_notification_count()
                resp_data = resp.get_json()
                notif_count = resp_data.get('count', 0) if resp_data else 0
            except Exception:
                pass

        msg_count = m.direct_messages_conf.count_documents({
            'recipient_id': ObjectId(user_id_str),
            'is_read': False
        })
    except Exception as e:
        current_app.logger.error(f"Error computing badge counts: {e}")

    result = {'notif_count': notif_count, 'msg_count': msg_count}

    if m.redis_cache:
        try:
            m.redis_cache.setex(cache_key, 30, json.dumps(result))
        except Exception:
            pass

    return jsonify(result)


@bp.route('/api/messages/request/<target_user_id>', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_send_dm_request(target_user_id):
    import main as m
    try:
        target_id = ObjectId(target_user_id)
        sender_id = ObjectId(current_user.id)
        
        if getattr(current_user, 'is_guest', False):
            t_user = m.users_conf.find_one({'_id': target_id}, {'is_demo_bot': 1})
            if t_user and not t_user.get('is_demo_bot'):
                return jsonify({'error': 'Messaging real users is restricted in Tour Mode. Sign up to connect with others!'}), 403

        if str(sender_id) == target_user_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400
        
        target_user = m.users_conf.find_one({'_id': target_id}, {'username': 1, 'dm_privacy': 1})
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        if target_user.get('dm_privacy') == 'nobody':
            return jsonify({'error': 'This user has disabled direct messages.'}), 403

        if m.can_dm(str(sender_id), target_user_id):
            return jsonify({'status': 'already_accepted', 'redirect': url_for('chat.messages_page', user_id=target_user_id)})
        
        existing = m.dm_permissions_conf.find_one({
            '$or': [
                {'requester_id': sender_id, 'target_id': target_id},
                {'requester_id': target_id, 'target_id': sender_id}
            ]
        })
        
        if existing:
            if existing['status'] == 'pending':
                if str(existing['requester_id']) == str(sender_id):
                    return jsonify({'status': 'pending', 'message': 'Request already sent'})
                else:
                    m.dm_permissions_conf.update_one(
                        {'_id': existing['_id']},
                        {'$set': {'status': 'accepted', 'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
                    )
                    return jsonify({'status': 'accepted', 'redirect': url_for('chat.messages_page', user_id=target_user_id)})
            elif existing['status'] == 'accepted':
                return jsonify({'status': 'already_accepted', 'redirect': url_for('chat.messages_page', user_id=target_user_id)})
            elif existing['status'] == 'rejected':
                m.dm_permissions_conf.update_one(
                    {'_id': existing['_id']},
                    {'$set': {'status': 'pending', 'requester_id': sender_id, 'target_id': target_id, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
                )
                m.socketio.emit('dm_request', {
                    'request_id': str(existing['_id']),
                    'from_user_id': str(sender_id),
                    'from_username': current_user.username,
                    'from_avatar': getattr(current_user, 'profile_image_url', None)
                }, room=f"user_{target_user_id}")
                return jsonify({'status': 'pending', 'message': 'Message request sent!'})
        
        now = datetime.datetime.now(datetime.timezone.utc)
        conv_envelope = generate_conversation_envelope_keys()
        result = m.dm_permissions_conf.insert_one({
            'requester_id': sender_id,
            'target_id': target_id,
            'status': 'pending',
            'created_at': now,
            'updated_at': now,
            **conv_envelope
        })
        
        m.socketio.emit('dm_request', {
            'request_id': str(result.inserted_id),
            'from_user_id': str(sender_id),
            'from_username': current_user.username,
            'from_avatar': getattr(current_user, 'profile_image_url', None)
        }, room=f"user_{target_user_id}")
        
        m.send_push_notification_to_user(
            target_user_id,
            f"{current_user.username} wants to message you",
            "Tap to view message request",
            url=url_for('chat.messages_page', _external=True),
            tag=f'dm-request-{current_user.id}'
        )
        
        return jsonify({'status': 'pending', 'message': 'Message request sent!'})
    except Exception as e:
        current_app.logger.error(f"Error sending DM request: {e}")
        return jsonify({'error': 'Failed to send request'}), 400


@bp.route('/api/messages/request/<request_id>/accept', methods=['POST'])
@login_required
def api_accept_dm_request(request_id):
    import main as m
    try:
        req = m.dm_permissions_conf.find_one({'_id': ObjectId(request_id), 'target_id': ObjectId(current_user.id), 'status': 'pending'})
        if not req:
            return jsonify({'error': 'Request not found'}), 404
        
        m.dm_permissions_conf.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'accepted', 'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
        )
        
        requester_id = str(req['requester_id'])
        requester = m.users_conf.find_one({'_id': req['requester_id']}, {'username': 1})
        
        m.socketio.emit('dm_request_accepted', {
            'by_user_id': str(current_user.id),
            'by_username': current_user.username,
            'accepted_at': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        }, room=f"user_{requester_id}")
        
        return jsonify({
            'success': True,
            'user_id': requester_id, 
            'username': requester['username'] if requester else 'Unknown',
            'redirect': url_for('chat.messages_page', user_id=requester_id)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/request/<request_id>/reject', methods=['POST'])
@login_required
def api_reject_dm_request(request_id):
    import main as m
    try:
        req = m.dm_permissions_conf.find_one({'_id': ObjectId(request_id), 'target_id': ObjectId(current_user.id), 'status': 'pending'})
        if not req:
            return jsonify({'error': 'Request not found'}), 404
        
        m.dm_permissions_conf.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'rejected', 'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/requests')
@login_required
def api_list_dm_requests():
    import main as m
    try:
        requests = list(m.dm_permissions_conf.find({
            'target_id': ObjectId(current_user.id),
            'status': 'pending'
        }).sort('created_at', -1))
        
        result = []
        for req in requests:
            user = m.users_conf.find_one({'_id': req['requester_id']}, {'username': 1, 'profile_image_url': 1})
            if user:
                result.append({
                    'request_id': str(req['_id']),
                    'from_user_id': str(req['requester_id']),
                    'from_username': user['username'],
                    'from_avatar': user.get('profile_image_url'),
                    'created_at': req['created_at'].isoformat() + 'Z' if req.get('created_at') and req['created_at'].tzinfo is None else (req['created_at'].isoformat().replace('+00:00', 'Z') if req.get('created_at') else None)
                })
        
        return jsonify({'requests': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/dm_status/<target_user_id>')
@login_required
def api_dm_status(target_user_id):
    import main as m
    try:
        if str(current_user.id) == target_user_id:
            return jsonify({'status': 'self'})
        
        target_id = ObjectId(target_user_id)
        sender_id = ObjectId(current_user.id)
        
        if m.can_dm(str(sender_id), target_user_id):
            return jsonify({'status': 'accepted'})
        
        pending = m.dm_permissions_conf.find_one({
            'requester_id': sender_id,
            'target_id': target_id,
            'status': 'pending'
        })
        if pending:
            return jsonify({'status': 'pending'})
        
        target_user = m.users_conf.find_one({'_id': target_id}, {'dm_privacy': 1})
        if target_user and target_user.get('dm_privacy') == 'nobody':
            return jsonify({'status': 'disabled'})
        
        return jsonify({'status': 'none'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/upload_image', methods=['POST'])
@login_required
def api_upload_dm_image():
    import main as m
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No empty filename'}), 400
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > current_app.config.get('MAX_IMAGE_SIZE', 5 * 1024 * 1024):
            return jsonify({'error': 'Image exceeds 5MB limit'}), 400
        upload_result = m.cloudinary.uploader.upload(
            file, folder='dm_images',
            transformation=[{'width': 1200, 'height': 1200, 'crop': 'limit'}, {'quality': 'auto', 'fetch_format': 'auto'}]
        )
        return jsonify({'success': True, 'url': upload_result.get('secure_url')})
    except Exception as e:
        current_app.logger.error(f'Image upload failed for DM: {e}')
        return jsonify({'error': 'Failed to upload image'}), 500


@bp.route('/api/messages/upload_voice', methods=['POST'])
@login_required
def api_upload_dm_voice():
    import main as m
    if not current_user.get_limit('voice_messages'):
        return jsonify({'error': 'Voice messages are not available', 'upgrade': True}), 403
    if 'voice' not in request.files:
        return jsonify({'error': 'No audio provided'}), 400
    file = request.files['voice']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > 10 * 1024 * 1024:
            return jsonify({'error': 'Voice note exceeds 10MB limit'}), 400
        upload_result = m.cloudinary.uploader.upload(file, folder='dm_voice', resource_type='auto')
        return jsonify({'success': True, 'url': upload_result.get('secure_url')})
    except Exception as e:
        current_app.logger.error(f'Voice upload failed for DM: {e}')
        return jsonify({'error': 'Failed to upload voice note'}), 500


@bp.route('/api/messages/react/<message_id>', methods=['POST'])
@login_required
def api_react_message(message_id):
    import main as m
    try:
        data = request.get_json() or {}
        emoji = data.get('emoji')
        if not emoji:
            return jsonify({'error': 'No emoji provided'}), 400
        msg = m.direct_messages_conf.find_one({'_id': ObjectId(message_id)})
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        user_id_str = str(current_user.id)
        if str(msg['sender_id']) != user_id_str and str(msg['recipient_id']) != user_id_str:
            return jsonify({'error': 'Unauthorized'}), 403
        reactions = msg.get('reactions', {})
        users_for_emoji = reactions.get(emoji, [])
        if user_id_str in users_for_emoji:
            users_for_emoji.remove(user_id_str)
            if not users_for_emoji:
                reactions.pop(emoji, None)
            else:
                reactions[emoji] = users_for_emoji
        else:
            if emoji not in reactions:
                reactions[emoji] = []
            reactions[emoji].append(user_id_str)
        m.direct_messages_conf.update_one({'_id': ObjectId(message_id)}, {'$set': {'reactions': reactions}})
        payload = {'id': message_id, 'reactions': reactions}
        m.socketio.emit('message_reacted', payload, room=f"user_{msg['sender_id']}")
        m.socketio.emit('message_reacted', payload, room=f"user_{msg['recipient_id']}")
        return jsonify({'success': True, 'reactions': reactions})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/search/<other_user_id>', methods=['GET'])
@login_required
def api_search_messages(other_user_id):
    import main as m
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify({'messages': []})
    try:
        other_id = ObjectId(other_user_id)
        messages = list(m.direct_messages_conf.find({
            '$or': [
                {'sender_id': ObjectId(current_user.id), 'recipient_id': other_id},
                {'sender_id': other_id, 'recipient_id': ObjectId(current_user.id)}
            ]
        }).sort('timestamp', 1))
        results = []
        for msg in messages:
            content = msg.get('content', '')
            if msg.get('encrypted') or content.startswith('gAAAAA'):
                try:
                    content = m.decrypt_dm(content, str(msg['sender_id']), str(msg['recipient_id']))
                except Exception:
                    pass
            lp_title = ''
            if msg.get('link_preview') and isinstance(msg['link_preview'], dict):
                raw_title = msg['link_preview'].get('title', '')
                if raw_title and raw_title.startswith('gAAAAA'):
                    try:
                        lp_title = m.decrypt_dm(raw_title, str(msg['sender_id']), str(msg['recipient_id']))
                    except Exception:
                        lp_title = ''
                else:
                    lp_title = raw_title
            if query in content.lower() or (lp_title and query in lp_title.lower()):
                results.append(str(msg['_id']))
            if len(results) >= 50:
                break
        return jsonify({'success': True, 'match_ids': results})
    except Exception as e:
        current_app.logger.error(f'Search API error: {e}')
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/edit/<message_id>', methods=['POST'])
@login_required
def api_edit_message(message_id):
    import main as m
    try:
        data = request.get_json() or {}
        new_content = data.get('content')
        if not new_content:
            return jsonify({'error': 'No content provided'}), 400
        msg = m.direct_messages_conf.find_one({'_id': ObjectId(message_id)})
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        if str(msg['sender_id']) != str(current_user.id):
            return jsonify({'error': 'Unauthorized'}), 403
        recipient_id_str = str(msg['recipient_id'])
        encrypted_content = m.encrypt_dm(new_content, str(current_user.id), recipient_id_str)
        m.direct_messages_conf.update_one(
            {'_id': ObjectId(message_id)},
            {'$set': {'content': encrypted_content, 'edited': True}}
        )
        update_payload = {'id': message_id, 'content': new_content}
        m.socketio.emit('message_edited', update_payload, room=f"user_{recipient_id_str}")
        m.socketio.emit('message_edited', update_payload, room=f"user_{current_user.id}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/delete/<message_id>', methods=['POST'])
@login_required
def api_delete_message(message_id):
    import main as m
    try:
        msg = m.direct_messages_conf.find_one({'_id': ObjectId(message_id)})
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        if str(msg['sender_id']) != str(current_user.id):
            return jsonify({'error': 'Unauthorized'}), 403
        recipient_id_str = str(msg['recipient_id'])
        from utils import backup_before_delete
        backup_before_delete('direct_messages', msg, current_user.id)
        m.direct_messages_conf.delete_one({'_id': ObjectId(message_id)})
        m.socketio.emit('message_deleted', {'id': message_id}, room=f"user_{recipient_id_str}")
        m.socketio.emit('message_deleted', {'id': message_id}, room=f"user_{current_user.id}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/chat/delete/<other_user_id>', methods=['POST'])
@login_required
def api_delete_chat(other_user_id):
    import main as m
    try:
        other_id = ObjectId(other_user_id)
        my_id = ObjectId(current_user.id)
        m.hidden_chats_conf.update_one(
            {'user_id': my_id, 'partner_id': other_id},
            {'$set': {'hidden_at': datetime.datetime.now(datetime.timezone.utc)}},
            upsert=True
        )
        other_also_hidden = m.hidden_chats_conf.find_one({'user_id': other_id, 'partner_id': my_id})
        if other_also_hidden:
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)
            messages = list(m.direct_messages_conf.find({
                '$or': [
                    {'sender_id': my_id, 'recipient_id': other_id},
                    {'sender_id': other_id, 'recipient_id': my_id}
                ]
            }))
            if messages:
                for msg in messages:
                    msg['original_collection'] = 'direct_messages'
                    msg['_id'] = ObjectId()
                    msg['expires_at'] = expires_at
                    msg['deleted_at'] = datetime.datetime.now(datetime.timezone.utc)
                m.deleted_items_conf.insert_many(messages)
            m.direct_messages_conf.delete_many({
                '$or': [
                    {'sender_id': my_id, 'recipient_id': other_id},
                    {'sender_id': other_id, 'recipient_id': my_id}
                ]
            })
            m.hidden_chats_conf.delete_many({
                '$or': [
                    {'user_id': my_id, 'partner_id': other_id},
                    {'user_id': other_id, 'partner_id': my_id}
                ]
            })
            m.socketio.emit('chat_deleted', {'by_id': str(current_user.id), 'target_id': other_user_id}, room=f"user_{current_user.id}")
            m.socketio.emit('chat_deleted', {'by_id': str(current_user.id)}, room=f"user_{other_user_id}")
        else:
            m.socketio.emit('chat_deleted', {'by_id': str(current_user.id), 'target_id': other_user_id}, room=f"user_{current_user.id}")
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/schedule', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_schedule_message():
    import main as m
    try:
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        if not m.is_premium(user_doc):
            return jsonify({'error': 'Scheduled Messages is a Premium feature. Upgrade for just KSH 50/month!', 'upgrade': True}), 403
        data = request.get_json() or {}
        recipient_id_str = data.get('recipient_id')
        content = data.get('content', '')
        scheduled_at_str = data.get('scheduled_at')
        image_url = data.get('image_url')
        reply_to_id = data.get('reply_to_id')
        message_type = data.get('message_type', 'text')
        if not recipient_id_str or not scheduled_at_str:
            return jsonify({'error': 'Missing required fields'}), 400
        if not content and not image_url:
            return jsonify({'error': 'Message cannot be empty'}), 400
        try:
            scheduled_at = datetime.datetime.fromisoformat(scheduled_at_str.replace('Z', '+00:00'))
            if scheduled_at.tzinfo is None:
                scheduled_at = scheduled_at.replace(tzinfo=datetime.timezone.utc)
        except (ValueError, AttributeError):
            return jsonify({'error': 'Invalid date format. Use ISO 8601.'}), 400
        now = datetime.datetime.now(datetime.timezone.utc)
        if scheduled_at <= now + datetime.timedelta(minutes=1):
            return jsonify({'error': 'Scheduled time must be at least 1 minute in the future.'}), 400
        if scheduled_at > now + datetime.timedelta(days=30):
            return jsonify({'error': 'Cannot schedule more than 30 days ahead.'}), 400
        sender_id_str = str(current_user.id)
        if not m.can_dm(sender_id_str, recipient_id_str):
            return jsonify({'error': 'You do not have permission to message this user.'}), 403
        recipient = m.users_conf.find_one({'_id': ObjectId(recipient_id_str)})
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        if recipient.get('dm_privacy') == 'nobody':
            return jsonify({'error': 'This user has disabled direct messages.'}), 403
        pending_count = m.scheduled_messages_conf.count_documents({
            'sender_id': ObjectId(current_user.id), 'status': 'pending'
        })
        if pending_count >= 25:
            return jsonify({'error': 'You have too many scheduled messages. Cancel some first.'}), 429
        reply_to_preview = None
        reply_to_sender = None
        if reply_to_id:
            try:
                parent_msg = m.direct_messages_conf.find_one({'_id': ObjectId(reply_to_id)})
                if parent_msg:
                    parent_sender_id = str(parent_msg['sender_id'])
                    is_me = parent_sender_id == sender_id_str
                    parent_sender = current_user.username if is_me else recipient.get('username', 'User')
                    raw_content = parent_msg.get('content', '')
                    if parent_msg.get('encrypted') or raw_content.startswith('gAAAAA'):
                        try:
                            raw_content = m.decrypt_dm(raw_content, str(parent_msg['sender_id']), str(parent_msg['recipient_id']))
                        except Exception:
                            raw_content = 'Encrypted message'
                    reply_to_sender = parent_sender
                    if parent_msg.get('message_type') == 'image':
                        reply_to_preview = '\U0001f4f8 Photo'
                    else:
                        reply_to_preview = raw_content[:80] + ('...' if len(raw_content) > 80 else '')
            except Exception as e:
                current_app.logger.warning(f'Error fetching reply parent for scheduled msg: {e}')
        link_preview = None
        if message_type == 'text' and content:
            url_match = re.search(r'(https?://[^\s]+)', content)
            if url_match:
                link_preview = m.fetch_link_preview(url_match.group(1))
        encrypted_content = m.encrypt_dm(content, sender_id_str, recipient_id_str) if content else ''
        sched_doc = {
            'sender_id': ObjectId(current_user.id),
            'recipient_id': ObjectId(recipient_id_str),
            'content': encrypted_content,
            'encrypted': True,
            'message_type': message_type,
            'scheduled_at': scheduled_at,
            'status': 'pending',
            'created_at': now
        }
        if image_url:
            sched_doc['image_url'] = m.encrypt_dm(image_url, sender_id_str, recipient_id_str)
        if reply_to_id:
            sched_doc['reply_to_id'] = ObjectId(reply_to_id)
            sched_doc['reply_to_preview'] = m.encrypt_dm(reply_to_preview, sender_id_str, recipient_id_str) if reply_to_preview else reply_to_preview
            sched_doc['reply_to_sender'] = reply_to_sender
        if link_preview:
            sched_doc['link_preview'] = {
                'url': m.encrypt_dm(link_preview.get('url', ''), sender_id_str, recipient_id_str),
                'title': m.encrypt_dm(link_preview.get('title', ''), sender_id_str, recipient_id_str),
                'description': m.encrypt_dm(link_preview.get('description', ''), sender_id_str, recipient_id_str),
                'image': m.encrypt_dm(link_preview.get('image', ''), sender_id_str, recipient_id_str)
            }
        m.scheduled_messages_conf.insert_one(sched_doc)
        return jsonify({
            'success': True,
            'message': 'Message scheduled successfully!',
            'scheduled_message': {
                'id': str(sched_doc['_id']),
                'content': content,
                'scheduled_at': scheduled_at.isoformat().replace('+00:00', 'Z'),
                'status': 'pending',
                'message_type': message_type,
                'image_url': image_url
            }
        })
    except Exception as e:
        current_app.logger.error(f'Error scheduling message: {e}')
        return jsonify({'error': 'Failed to schedule message'}), 400


@bp.route('/api/messages/scheduled/<other_user_id>')
@login_required
def api_list_scheduled_messages(other_user_id):
    import main as m
    try:
        other_id = ObjectId(other_user_id)
        msgs = list(m.scheduled_messages_conf.find({
            'sender_id': ObjectId(current_user.id),
            'recipient_id': other_id,
            'status': 'pending'
        }).sort('scheduled_at', 1))
        result = []
        for msg in msgs:
            content = msg.get('content', '')
            if content and content.startswith('gAAAAA'):
                try:
                    content = m.decrypt_dm(content, str(current_user.id), other_user_id)
                except Exception:
                    pass
            entry = {
                'id': str(msg['_id']),
                'content': content,
                'scheduled_at': msg['scheduled_at'].isoformat() + 'Z' if msg.get('scheduled_at') and msg['scheduled_at'].tzinfo is None else (msg['scheduled_at'].isoformat().replace('+00:00', 'Z') if msg.get('scheduled_at') else None),
                'status': msg['status'],
                'message_type': msg.get('message_type', 'text'),
                'created_at': msg['created_at'].isoformat() + 'Z' if msg.get('created_at') and msg['created_at'].tzinfo is None else (msg['created_at'].isoformat().replace('+00:00', 'Z') if msg.get('created_at') else None)
            }
            if msg.get('image_url'):
                raw_img = msg['image_url']
                entry['image_url'] = m.decrypt_dm(raw_img, str(current_user.id), other_user_id) if raw_img and raw_img.startswith('gAAAAA') else raw_img
            result.append(entry)
        return jsonify({'scheduled_messages': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/schedule/<msg_id>/cancel', methods=['POST'])
@login_required
def api_schedule_cancel(msg_id):
    import main as m
    try:
        obj_id = m.safe_object_id(msg_id)
        if not obj_id:
            return jsonify({'error': 'Invalid message ID'}), 400
        msg = m.scheduled_messages_conf.find_one({
            '_id': obj_id,
            'sender_id': ObjectId(current_user.id),
            'status': 'pending'
        })
        if not msg:
            return jsonify({'error': 'Scheduled message not found or already processed'}), 404
        m.scheduled_messages_conf.update_one(
            {'_id': obj_id},
            {'$set': {'status': 'cancelled', 'cancelled_at': datetime.datetime.now(datetime.timezone.utc)}}
        )
        return jsonify({'success': True, 'message': 'Scheduled message cancelled.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/schedule/<msg_id>/send-now', methods=['POST'])
@login_required
def api_schedule_send_now(msg_id):
    import main as m
    try:
        obj_id = m.safe_object_id(msg_id)
        if not obj_id:
            return jsonify({'error': 'Invalid message ID'}), 400
        msg = m.scheduled_messages_conf.find_one({
            '_id': obj_id,
            'sender_id': ObjectId(current_user.id),
            'status': 'pending'
        })
        if not msg:
            return jsonify({'error': 'Scheduled message not found or already processed'}), 404
        success = m._deliver_scheduled_message(msg)
        if success:
            return jsonify({'success': True, 'message': 'Message sent!'})
        else:
            return jsonify({'error': 'Delivery failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/api/messages/schedule/process', methods=['POST'])
@csrf_exempt
def api_process_scheduled_messages():
    import main as m
    auth_header = request.headers.get('X-Scheduler-Secret', '')
    expected_secret = os.environ.get('SCHEDULER_SECRET') or os.environ.get('SECRET') or current_app.config.get('SECRET_KEY', '')
    if not auth_header or not expected_secret or not secrets.compare_digest(auth_header, expected_secret):
        return jsonify({'error': 'Unauthorized'}), 403
    now = datetime.datetime.now(datetime.timezone.utc)
    due_messages = list(m.scheduled_messages_conf.find({
        'scheduled_at': {'$lte': now}, 'status': 'pending'
    }).limit(50))
    delivered = 0
    failed = 0
    for msg in due_messages:
        if m._deliver_scheduled_message(msg):
            delivered += 1
        else:
            failed += 1
    return jsonify({'delivered': delivered, 'failed': failed, 'total': len(due_messages)})
