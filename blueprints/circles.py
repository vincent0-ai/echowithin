"""Private Trusted Circles for small invited groups."""

import datetime
import hashlib
import json
import re
import secrets

from bson.errors import InvalidId
from bson.objectid import ObjectId
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for, jsonify, make_response
from flask_login import current_user, login_required

from security import encrypt_community_note, decrypt_community_note, parse_iso_utc, limits

bp = Blueprint('circles', __name__, template_folder='templates')

CIRCLE_TYPES = {
    'couple': ('Couple', 'Mood, memories, anniversaries, and a shared journal.'),
    'friends': ('Friends', 'Events, polls, games, and a photo album.'),
    'study': ('Study', 'Goals, schedules, and focus sessions.'),
    'family': ('Family', 'Calendar, announcements, and shared photos.'),
    'hobby': ('Hobby', 'Threads, events, resources, and moderation.'),
    'custom': ('Custom', 'Choose the tools your circle needs.')
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _oid(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        abort(404)


def _get_circle(circle_id):
    import main as m
    circle = m.circles_conf.find_one({'_id': _oid(circle_id)})
    if not circle:
        abort(404)
    user_id = ObjectId(current_user.id)
    if user_id not in circle.get('members', []):
        abort(403)
    return circle




def _role(circle):
    return circle.get('roles', {}).get(str(current_user.id), 'member')


def _redirect(circle_id):
    return redirect(url_for('circles.view_circle', circle_id=circle_id))


def _emit_to_circle(circle, event, payload):
    import main as m
    try:
        if hasattr(m, 'socketio') and m.socketio:
            for member_id in circle.get('members', []):
                m.socketio.emit(event, payload, room=f"user_{member_id}")
    except Exception as e:
        current_app.logger.warning(f"Circle socket emit error: {e}")


@bp.route('/circles')
@login_required
def circles_page():
    import main as m
    user_id = ObjectId(current_user.id)
    circles = list(m.circles_conf.find({'members': user_id}).sort('updated_at', -1))
    for circle in circles:
        circle['member_count'] = len(circle.get('members', []))
        circle['type_label'] = CIRCLE_TYPES.get(circle.get('circle_type', 'custom'), CIRCLE_TYPES['custom'])[0]
    return render_template('circles.html', circles=circles, circle_types=CIRCLE_TYPES, active_page='circles', title='Trusted Circles | EchoWithin')


@bp.route('/circles/create', methods=['POST'])
@login_required
@limits(calls=15, period=60)
def create_circle():
    import main as m
    name = request.form.get('name', '').strip()
    circle_type = request.form.get('circle_type', 'custom').strip().lower()
    if not name or len(name) > 80 or circle_type not in CIRCLE_TYPES:
        flash('Enter a circle name and choose a type.', 'danger')
        return redirect(url_for('circles.circles_page'))
    now = _now()
    result = m.circles_conf.insert_one({
        'name': name,
        'circle_type': circle_type,
        'owner_id': ObjectId(current_user.id),
        'members': [ObjectId(current_user.id)],
        'roles': {str(current_user.id): 'owner'},
        'visibility': 'invite_only',
        'approval_required': request.form.get('approval_required') == '1',
        'muted_by': [],
        'created_at': now,
        'updated_at': now
    })
    return redirect(url_for('circles.view_circle', circle_id=str(result.inserted_id)))


@bp.route('/circle/<circle_id>')
@login_required
def view_circle(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    now = _now()

    posts = list(m.circle_posts_conf.find({
        'circle_id': circle['_id'],
        '$or': [{'expires_at': None}, {'expires_at': {'$exists': False}}, {'expires_at': {'$gt': now}}]
    }).sort([('is_pinned', -1), ('created_at', -1)]).limit(60))

    messages = list(m.circle_messages_conf.find({'circle_id': circle['_id']}).sort('created_at', -1).limit(60))

    # Collect author IDs from posts, comments, and messages for a single batch query
    user_ids_to_fetch = set(circle.get('members', []))
    for p in posts:
        if p.get('author_id'):
            user_ids_to_fetch.add(p['author_id'])
        for c in p.get('comments', []):
            if c.get('author_id'):
                user_ids_to_fetch.add(c['author_id'])
    for msg in messages:
        if msg.get('author_id'):
            user_ids_to_fetch.add(msg['author_id'])

    user_map = {
        u['_id']: u for u in m.users_conf.find(
            {'_id': {'$in': list(user_ids_to_fetch)}},
            {'username': 1, 'profile_image_url': 1}
        )
    }

    current_uid_str = str(current_user.id)
    for post in posts:
        raw_content = decrypt_community_note(post.get('content', ''), circle['_id'])
        try:
            post['payload'] = json.loads(raw_content)
        except (TypeError, json.JSONDecodeError):
            post['payload'] = {'content': raw_content}

        kind = post.get('kind', 'post')
        if kind == 'poll':
            votes = post['payload'].get('votes', {})
            post['my_vote'] = votes.get(current_uid_str)
            total_votes = len(votes)
            options_stats = []
            for idx, opt in enumerate(post['payload'].get('options', [])):
                opt_count = sum(1 for v in votes.values() if v == idx)
                opt_pct = round((opt_count / total_votes) * 100) if total_votes > 0 else 0
                options_stats.append({
                    'index': idx,
                    'text': opt,
                    'count': opt_count,
                    'percent': opt_pct,
                    'is_my_vote': post['my_vote'] == idx
                })
            post['poll_stats'] = {
                'total_votes': total_votes,
                'options': options_stats
            }
        elif kind == 'event':
            attending = post['payload'].get('attending', [])
            post['is_attending'] = current_uid_str in attending
            post['attending_count'] = len(attending)
            post['attending_names'] = [
                user_map[ObjectId(uid)]['username']
                for uid in attending
                if ObjectId(uid) in user_map
            ]

        # Comments
        comments = post.get('comments', [])
        for c in comments:
            c['content'] = decrypt_community_note(c.get('content', ''), circle['_id'])
            c_author = user_map.get(c.get('author_id'))
            c['author_name'] = c_author.get('username', 'Member') if c_author else 'Member'
            c['author_image'] = c_author.get('profile_image_url') if c_author else None
            c['is_mine'] = str(c.get('author_id')) == current_uid_str
        post['comments'] = comments
        post['comments_count'] = len(comments)

        # Reactions
        post['reactions'] = post.get('reactions', {})
        author = user_map.get(post.get('author_id'))
        post['author_name'] = author.get('username', 'Member') if author else 'Member'
        post['author_image'] = author.get('profile_image_url') if author else None
        post['is_mine'] = str(post.get('author_id')) == current_uid_str

    members = [user_map.get(mid) for mid in circle.get('members', []) if mid in user_map]
    game_lobbies = list(m.game_sessions_conf.find(
        {'circle_id': circle['_id'], 'deactivated': {'$ne': True}},
        {'lobby_id': 1, 'title': 1, 'game_type': 1, 'pin': 1, 'expires_at': 1}
    ).sort('created_at', -1).limit(10))

    pinned_message = None
    for message in messages:
        message['content'] = decrypt_community_note(message.get('content', ''), circle['_id'])
        author = user_map.get(message.get('author_id'))
        message['author_name'] = author.get('username', 'Member') if author else 'Member'
        message['author_image'] = author.get('profile_image_url') if author else None
        message['is_mine'] = str(message.get('author_id')) == current_uid_str
        message['reactions'] = message.get('reactions', {})
        if message.get('is_pinned') and not pinned_message:
            pinned_message = message
    messages.reverse()

    # Pending join requests (only join requests from users not yet in circle)
    pending_requests = []
    if _role(circle) in ('owner', 'moderator'):
        raw_reqs = list(m.circle_requests_conf.find({'circle_id': circle['_id'], 'status': 'pending'}))
        for req in raw_reqs:
            if req.get('user_id') in circle.get('members', []):
                continue
            u = m.users_conf.find_one({'_id': req.get('user_id')}, {'username': 1, 'profile_image_url': 1})
            if u:
                req['username'] = u.get('username', 'User')
                req['profile_image_url'] = u.get('profile_image_url')
                pending_requests.append(req)

    return render_template(
        'circle.html',
        circle=circle,
        posts=posts,
        members=members,
        game_lobbies=game_lobbies,
        messages=messages,
        pinned_message=pinned_message,
        pending_requests=pending_requests,
        circle_type=CIRCLE_TYPES.get(circle.get('circle_type', 'custom'), CIRCLE_TYPES['custom']),
        is_owner=str(circle.get('owner_id')) == current_uid_str,
        is_mod=_role(circle) in ('owner', 'moderator'),
        user_role=_role(circle),
        active_page='circles',
        title=f"{circle.get('name', 'Circle')} | EchoWithin"
    )


@bp.route('/circle/<circle_id>/chat', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def create_circle_message(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    is_json = request.is_json
    data = request.get_json(silent=True) or request.form
    content = data.get('content', '').strip()
    reply_to_id = data.get('reply_to_id', '').strip()

    if not content or len(content) > 2000:
        if is_json or request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Message cannot be empty or over 2000 characters.'}), 400
        flash('Write a message first.', 'danger')
        return _redirect(circle_id)

    reply_to = None
    if reply_to_id:
        try:
            parent = m.circle_messages_conf.find_one({'_id': ObjectId(reply_to_id), 'circle_id': circle['_id']})
            if parent:
                parent_author = m.users_conf.find_one({'_id': parent.get('author_id')}, {'username': 1})
                parent_text = decrypt_community_note(parent.get('content', ''), circle['_id'])
                reply_to = {
                    'id': str(parent['_id']),
                    'author_name': parent_author.get('username', 'Member') if parent_author else 'Member',
                    'snippet': parent_text[:80] + ('...' if len(parent_text) > 80 else '')
                }
        except Exception:
            reply_to = None

    now = _now()
    encrypted_content = encrypt_community_note(content, circle['_id'])
    doc = {
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'content': encrypted_content,
        'created_at': now,
        'reactions': {},
        'reply_to': reply_to,
        'edited': False,
        'is_pinned': False
    }
    res = m.circle_messages_conf.insert_one(doc)

    payload = {
        'id': str(res.inserted_id),
        'circle_id': str(circle['_id']),
        'author_id': str(current_user.id),
        'author_name': current_user.username,
        'author_image': getattr(current_user, 'profile_image_url', None),
        'content': content,
        'created_at': now.isoformat().replace('+00:00', 'Z'),
        'created_at_formatted': now.strftime('%H:%M'),
        'reply_to': reply_to,
        'reactions': {}
    }
    _emit_to_circle(circle, 'circle_message_sent', payload)

    if is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': payload})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/chat/<message_id>/edit', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def edit_circle_message(circle_id, message_id):
    import main as m
    circle = _get_circle(circle_id)
    msg = m.circle_messages_conf.find_one({'_id': _oid(message_id), 'circle_id': circle['_id']})
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    if str(msg.get('author_id')) != str(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json(silent=True) or request.form
    new_content = data.get('content', '').strip()
    if not new_content or len(new_content) > 2000:
        return jsonify({'error': 'Invalid content'}), 400

    now = _now()
    m.circle_messages_conf.update_one(
        {'_id': msg['_id']},
        {'$set': {'content': encrypt_community_note(new_content, circle['_id']), 'edited': True, 'edited_at': now}}
    )
    payload = {'id': message_id, 'circle_id': str(circle['_id']), 'content': new_content}
    _emit_to_circle(circle, 'circle_message_edited', payload)

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'content': new_content})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/chat/<message_id>/delete', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def delete_circle_message(circle_id, message_id):
    import main as m
    circle = _get_circle(circle_id)
    msg = m.circle_messages_conf.find_one({'_id': _oid(message_id), 'circle_id': circle['_id']})
    if not msg:
        return jsonify({'error': 'Message not found'}), 404

    is_author = str(msg.get('author_id')) == str(current_user.id)
    is_mod = _role(circle) in ('owner', 'moderator')
    if not (is_author or is_mod):
        return jsonify({'error': 'Unauthorized'}), 403

    m.circle_messages_conf.delete_one({'_id': msg['_id']})
    payload = {'id': message_id, 'circle_id': str(circle['_id'])}
    _emit_to_circle(circle, 'circle_message_deleted', payload)

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/chat/<message_id>/react', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def react_circle_message(circle_id, message_id):
    import main as m
    circle = _get_circle(circle_id)
    msg = m.circle_messages_conf.find_one({'_id': _oid(message_id), 'circle_id': circle['_id']})
    if not msg:
        return jsonify({'error': 'Message not found'}), 404

    data = request.get_json(silent=True) or request.form
    emoji = data.get('emoji', '').strip()
    if not emoji or len(emoji) > 8:
        return jsonify({'error': 'Invalid emoji'}), 400

    user_id_str = str(current_user.id)
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

    m.circle_messages_conf.update_one({'_id': msg['_id']}, {'$set': {'reactions': reactions}})
    payload = {'id': message_id, 'circle_id': str(circle['_id']), 'reactions': reactions}
    _emit_to_circle(circle, 'circle_message_reacted', payload)

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'reactions': reactions})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/chat/<message_id>/pin', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def pin_circle_message(circle_id, message_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        return jsonify({'error': 'Unauthorized'}), 403

    msg = m.circle_messages_conf.find_one({'_id': _oid(message_id), 'circle_id': circle['_id']})
    if not msg:
        return jsonify({'error': 'Message not found'}), 404

    is_pinned = not msg.get('is_pinned', False)
    if is_pinned:
        m.circle_messages_conf.update_many({'circle_id': circle['_id'], 'is_pinned': True}, {'$set': {'is_pinned': False}})
        m.circle_messages_conf.update_one({'_id': msg['_id']}, {'$set': {'is_pinned': True, 'pinned_by': ObjectId(current_user.id), 'pinned_at': _now()}})
    else:
        m.circle_messages_conf.update_one({'_id': msg['_id']}, {'$set': {'is_pinned': False, 'pinned_by': None, 'pinned_at': None}})

    content = decrypt_community_note(msg.get('content', ''), circle['_id'])
    payload = {'id': message_id, 'circle_id': str(circle['_id']), 'is_pinned': is_pinned, 'content': content[:100]}
    _emit_to_circle(circle, 'circle_message_pinned', payload)

    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'is_pinned': is_pinned})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def create_circle_post(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    content = request.form.get('content', '').strip()
    if not content or len(content) > 5000:
        flash('Write a post before sharing.', 'danger')
        return redirect(url_for('circles.view_circle', circle_id=circle_id))
    now = _now()
    expiry = request.form.get('expiry', '').strip()
    expires_at = None
    if expiry in ('1d', '7d', '30d'):
        expires_at = now + datetime.timedelta(days=int(expiry[:-1]))
    m.circle_posts_conf.insert_one({
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'kind': 'post',
        'content': encrypt_community_note(content, circle['_id']),
        'created_at': now,
        'expires_at': expires_at,
        'reactions': {},
        'comments': [],
        'is_pinned': False
    })
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return redirect(url_for('circles.view_circle', circle_id=circle_id))


@bp.route('/circle/<circle_id>/posts/<post_id>/edit', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def edit_circle_post(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    if str(post.get('author_id')) != str(current_user.id):
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json(silent=True) or request.form
    new_content = data.get('content', '').strip()
    if not new_content or len(new_content) > 5000:
        return jsonify({'error': 'Invalid content'}), 400

    now = _now()
    m.circle_posts_conf.update_one(
        {'_id': post['_id']},
        {'$set': {'content': encrypt_community_note(new_content, circle['_id']), 'edited': True, 'updated_at': now}}
    )
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'content': new_content})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/delete', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def delete_circle_post(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    is_author = str(post.get('author_id')) == str(current_user.id)
    is_mod = _role(circle) in ('owner', 'moderator')
    if not (is_author or is_mod):
        return jsonify({'error': 'Unauthorized'}), 403

    m.circle_posts_conf.delete_one({'_id': post['_id']})
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/pin', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def pin_circle_post(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        return jsonify({'error': 'Unauthorized'}), 403

    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    is_pinned = not post.get('is_pinned', False)
    m.circle_posts_conf.update_one(
        {'_id': post['_id']},
        {'$set': {'is_pinned': is_pinned, 'pinned_by': ObjectId(current_user.id) if is_pinned else None, 'pinned_at': _now() if is_pinned else None}}
    )
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'is_pinned': is_pinned})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/react', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def react_circle_post(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    data = request.get_json(silent=True) or request.form
    emoji = data.get('emoji', '').strip()
    if not emoji or len(emoji) > 8:
        return jsonify({'error': 'Invalid emoji'}), 400

    user_id_str = str(current_user.id)
    reactions = post.get('reactions', {})
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

    m.circle_posts_conf.update_one({'_id': post['_id']}, {'$set': {'reactions': reactions}})
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'reactions': reactions})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/comment', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def comment_circle_post(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    data = request.get_json(silent=True) or request.form
    content = data.get('content', '').strip()
    if not content or len(content) > 1000:
        if request.is_json or request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Comment cannot be empty or over 1000 characters.'}), 400
        flash('Comment cannot be empty.', 'danger')
        return _redirect(circle_id)

    now = _now()
    comment_id = str(ObjectId())
    comment_doc = {
        'id': comment_id,
        'author_id': ObjectId(current_user.id),
        'author_name': current_user.username,
        'content': encrypt_community_note(content, circle['_id']),
        'created_at': now
    }
    m.circle_posts_conf.update_one(
        {'_id': post['_id']},
        {'$push': {'comments': comment_doc}, '$set': {'updated_at': now}}
    )
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'comment': {
                'id': comment_id,
                'author_id': str(current_user.id),
                'author_name': current_user.username,
                'author_image': getattr(current_user, 'profile_image_url', None),
                'content': content,
                'created_at': now.isoformat().replace('+00:00', 'Z')
            }
        })
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/comments/<comment_id>/delete', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def delete_circle_post_comment(circle_id, post_id, comment_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id']})
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    target_comment = None
    for c in post.get('comments', []):
        if c.get('id') == comment_id:
            target_comment = c
            break
    if not target_comment:
        return jsonify({'error': 'Comment not found'}), 404

    is_c_author = str(target_comment.get('author_id')) == str(current_user.id)
    is_post_author = str(post.get('author_id')) == str(current_user.id)
    is_mod = _role(circle) in ('owner', 'moderator')
    if not (is_c_author or is_post_author or is_mod):
        return jsonify({'error': 'Unauthorized'}), 403

    m.circle_posts_conf.update_one(
        {'_id': post['_id']},
        {'$pull': {'comments': {'id': comment_id}}, '$set': {'updated_at': _now()}}
    )
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/polls', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def create_poll(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    question = request.form.get('question', '').strip()
    options = [value.strip() for value in request.form.getlist('options') if value.strip()]
    if not question or len(question) > 240 or len(options) < 2 or len(options) > 8:
        flash('Add a question and two to eight options.', 'danger')
        return _redirect(circle_id)
    payload = json.dumps({'question': question, 'options': options, 'votes': {}})
    now = _now()
    m.circle_posts_conf.insert_one({
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'kind': 'poll',
        'content': encrypt_community_note(payload, circle['_id']),
        'created_at': now,
        'expires_at': None,
        'reactions': {},
        'comments': [],
        'is_pinned': False
    })
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/events', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def create_event(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    name = request.form.get('name', '').strip()
    starts_at = request.form.get('starts_at', '').strip()
    if not name or len(name) > 120 or not starts_at:
        flash('Add an event name and time.', 'danger')
        return _redirect(circle_id)
    try:
        starts_at = parse_iso_utc(starts_at).isoformat().replace('+00:00', 'Z')
    except (TypeError, ValueError):
        flash('Choose a valid event time.', 'danger')
        return _redirect(circle_id)
    payload = json.dumps({'name': name, 'starts_at': starts_at, 'attending': []})
    now = _now()
    m.circle_posts_conf.insert_one({
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'kind': 'event',
        'content': encrypt_community_note(payload, circle['_id']),
        'created_at': now,
        'expires_at': None,
        'reactions': {},
        'comments': [],
        'is_pinned': False
    })
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/vote', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def vote_poll(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id'], 'kind': 'poll'})
    if not post:
        abort(404)
    data = request.get_json(silent=True) or request.form
    try:
        option_index = int(data.get('option', ''))
    except (TypeError, ValueError):
        if request.is_json or request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Choose an option.'}), 400
        flash('Choose an option.', 'danger')
        return _redirect(circle_id)
    payload = json.loads(decrypt_community_note(post.get('content', ''), circle['_id']))
    options = payload.get('options', [])
    if option_index < 0 or option_index >= len(options):
        if request.is_json or request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Invalid option.'}), 400
        flash('Choose a valid option.', 'danger')
        return _redirect(circle_id)
    payload.setdefault('votes', {})[str(current_user.id)] = option_index
    m.circle_posts_conf.update_one({'_id': post['_id']}, {'$set': {'content': encrypt_community_note(json.dumps(payload), circle['_id']), 'updated_at': _now()}})
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'my_vote': option_index})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/rsvp', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def rsvp_event(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id'], 'kind': 'event'})
    if not post:
        abort(404)
    payload = json.loads(decrypt_community_note(post.get('content', ''), circle['_id']))
    attending = set(payload.get('attending', []))
    user_id = str(current_user.id)
    if user_id in attending:
        attending.remove(user_id)
    else:
        attending.add(user_id)
    payload['attending'] = sorted(attending)
    m.circle_posts_conf.update_one({'_id': post['_id']}, {'$set': {'content': encrypt_community_note(json.dumps(payload), circle['_id']), 'updated_at': _now()}})
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'is_attending': user_id in attending, 'attending_count': len(attending)})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/games/create')
@login_required
def create_circle_game(circle_id):
    _get_circle(circle_id)
    game_type = request.args.get('type', 'poll')
    return redirect(url_for('game.games_create', circle_id=circle_id, game_type=game_type))


@bp.route('/circle/<circle_id>/invite', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def create_invite(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    role = _role(circle)
    if role not in ('owner', 'moderator'):
        abort(403)
    raw_token = secrets.token_urlsafe(32)
    m.circle_invites_conf.insert_one({
        'circle_id': circle['_id'],
        'token_hash': hashlib.sha256(raw_token.encode()).hexdigest(),
        'created_by': ObjectId(current_user.id),
        'created_at': _now(),
        'expires_at': _now() + datetime.timedelta(days=7),
        'uses': 0,
        'max_uses': 20
    })
    invite_url = url_for('circles.join_circle', token=raw_token, _external=True)
    return render_template('circle_invite.html', circle=circle, invite_url=invite_url, active_page='circles', title='Circle invite | EchoWithin')


@bp.route('/circle/<circle_id>/invite/user', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def invite_username(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    username = request.form.get('username', '').strip().lstrip('@')
    if not username:
        flash('Enter a username to invite.', 'danger')
        return _redirect(circle_id)

    user = m.users_conf.find_one(
        {'username': {'$regex': f'^{re.escape(username)}$', '$options': 'i'}},
        {'_id': 1, 'username': 1}
    )
    if not user:
        flash('User not found.', 'danger')
        return _redirect(circle_id)

    if user['_id'] == ObjectId(current_user.id):
        flash('You are already a member of this Circle.', 'info')
        return _redirect(circle_id)

    if user['_id'] in circle.get('members', []):
        flash(f"{user['username']} is already a member.", 'info')
        return _redirect(circle_id)

    now = _now()
    m.circles_conf.update_one(
        {'_id': circle['_id']},
        {
            '$addToSet': {'members': user['_id']},
            '$set': {f"roles.{user['_id']}": 'member', 'updated_at': now}
        }
    )
    # If the user previously had a pending join request, resolve it
    m.circle_requests_conf.update_one(
        {'circle_id': circle['_id'], 'user_id': user['_id'], 'status': 'pending'},
        {'$set': {'status': 'approved', 'reviewed_at': now, 'reviewed_by': ObjectId(current_user.id)}}
    )
    flash(f"{user['username']} added to the Circle.", 'success')
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/members/search')
@login_required
@limits(calls=60, period=60)
def search_invite_users(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    query = request.args.get('q', '').strip().lstrip('@')
    if not query or len(query) < 1:
        return jsonify({'users': []})
    safe_q = re.escape(query)
    members_set = set(circle.get('members', []))
    users = list(m.users_conf.find(
        {'username': {'$regex': safe_q, '$options': 'i'}, 'is_banned': {'$ne': True}},
        {'username': 1, 'profile_image_url': 1}
    ).limit(8))
    results = [
        {
            'id': str(u['_id']),
            'username': u.get('username'),
            'avatar': u.get('profile_image_url'),
            'is_member': u['_id'] in members_set
        }
        for u in users
    ]
    return jsonify({'users': results})


@bp.route('/circle/join/<token>')
@login_required
def join_circle(token):
    import main as m
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    invite = m.circle_invites_conf.find_one({'token_hash': token_hash})
    now = _now()
    if not invite or invite.get('expires_at') and invite['expires_at'] <= now or invite.get('uses', 0) >= invite.get('max_uses', 20):
        abort(404)
    circle = m.circles_conf.find_one({'_id': invite['circle_id']})
    if not circle:
        abort(404)
    user_id = ObjectId(current_user.id)
    if user_id in circle.get('members', []):
        return redirect(url_for('circles.view_circle', circle_id=str(circle['_id'])))
    if circle.get('approval_required'):
        m.circle_requests_conf.update_one(
            {'circle_id': circle['_id'], 'user_id': user_id},
            {'$setOnInsert': {'circle_id': circle['_id'], 'user_id': user_id, 'status': 'pending', 'created_at': now}},
            upsert=True
        )
        m.circle_invites_conf.update_one({'_id': invite['_id']}, {'$inc': {'uses': 1}})
        return render_template('circle_pending.html', circle=circle, active_page='circles', title='Circle request | EchoWithin')
    m.circles_conf.update_one({'_id': circle['_id']}, {'$addToSet': {'members': user_id}, '$set': {'roles.' + str(user_id): 'member', 'updated_at': now}})
    m.circle_invites_conf.update_one({'_id': invite['_id']}, {'$inc': {'uses': 1}})
    return redirect(url_for('circles.view_circle', circle_id=str(circle['_id'])))


@bp.route('/circle/<circle_id>/requests/<request_id>/approve', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def approve_request(circle_id, request_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    request_doc = m.circle_requests_conf.find_one({'_id': _oid(request_id), 'circle_id': circle['_id'], 'status': 'pending'})
    if not request_doc:
        abort(404)
    now = _now()
    m.circles_conf.update_one({'_id': circle['_id']}, {'$addToSet': {'members': request_doc['user_id']}, '$set': {'roles.' + str(request_doc['user_id']): 'member', 'updated_at': now}})
    m.circle_requests_conf.update_one({'_id': request_doc['_id']}, {'$set': {'status': 'approved', 'reviewed_at': now, 'reviewed_by': ObjectId(current_user.id)}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/requests/<request_id>/deny', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def deny_request(circle_id, request_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    result = m.circle_requests_conf.update_one({'_id': _oid(request_id), 'circle_id': circle['_id'], 'status': 'pending'}, {'$set': {'status': 'denied', 'reviewed_at': _now(), 'reviewed_by': ObjectId(current_user.id)}})
    if not result.matched_count:
        abort(404)
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/members/<member_id>/role', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def change_member_role(circle_id, member_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) != 'owner':
        abort(403)
    member_oid = _oid(member_id)
    if member_oid == circle.get('owner_id') or member_oid not in circle.get('members', []):
        abort(400)
    role = request.form.get('role', 'member')
    if role not in ('moderator', 'member'):
        abort(400)
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'roles.' + str(member_oid): role, 'updated_at': _now()}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/members/<member_id>/remove', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def remove_member(circle_id, member_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    member_oid = _oid(member_id)
    if member_oid == circle.get('owner_id') or member_oid not in circle.get('members', []):
        abort(400)
    if _role(circle) != 'owner' and circle.get('roles', {}).get(str(member_oid)) == 'moderator':
        abort(403)
    m.circles_conf.update_one({'_id': circle['_id']}, {'$pull': {'members': member_oid}, '$unset': {'roles.' + str(member_oid): ''}, '$set': {'updated_at': _now()}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/export')
@login_required
def export_circle(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    posts = list(m.circle_posts_conf.find({'circle_id': circle['_id']}).sort('created_at', 1))
    lines = [f"Circle: {circle.get('name', 'Circle')}", '']
    for post in posts:
        raw = decrypt_community_note(post.get('content', ''), circle['_id'])
        lines.append(f"[{post.get('created_at', '')}] {raw}")
    response = make_response('\n'.join(lines))
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Content-Disposition'] = f"attachment; filename={circle.get('name', 'circle').replace(' ', '_')}.txt"
    return response


@bp.route('/circle/<circle_id>/settings/mute', methods=['POST'])
@login_required
def toggle_mute(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    user_id = ObjectId(current_user.id)
    if user_id in circle.get('muted_by', []):
        m.circles_conf.update_one({'_id': circle['_id']}, {'$pull': {'muted_by': user_id}})
        flash('Circle notifications on.', 'success')
    else:
        m.circles_conf.update_one({'_id': circle['_id']}, {'$addToSet': {'muted_by': user_id}})
        flash('Circle notifications muted.', 'success')
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/leave', methods=['POST'])
@login_required
def leave_circle(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    if str(circle.get('owner_id')) == str(current_user.id):
        flash('Transfer ownership before leaving this circle.', 'danger')
    else:
        m.circles_conf.update_one({'_id': circle['_id']}, {'$pull': {'members': ObjectId(current_user.id)}, '$unset': {'roles.' + str(current_user.id): ''}})
    return redirect(url_for('circles.circles_page'))
