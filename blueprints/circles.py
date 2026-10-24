"""Private Trusted Circles for small invited groups."""

import datetime
import hashlib
import json
import secrets

from bson.errors import InvalidId
from bson.objectid import ObjectId
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for, jsonify, make_response
from flask_login import current_user, login_required

from security import encrypt_community_note, decrypt_community_note, parse_iso_utc

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
    }).sort('created_at', -1).limit(50))
    for post in posts:
        raw_content = decrypt_community_note(post.get('content', ''), circle['_id'])
        try:
            post['payload'] = json.loads(raw_content)
        except (TypeError, json.JSONDecodeError):
            post['payload'] = {'content': raw_content}
        if post.get('kind') == 'poll':
            post['my_vote'] = post['payload'].get('votes', {}).get(str(current_user.id))
        elif post.get('kind') == 'event':
            post['is_attending'] = str(current_user.id) in post['payload'].get('attending', [])
        author = m.users_conf.find_one({'_id': post.get('author_id')}, {'username': 1})
        post['author_name'] = author.get('username', 'Member') if author else 'Member'
    members = list(m.users_conf.find({'_id': {'$in': circle.get('members', [])}}, {'username': 1, 'profile_image_url': 1}))
    game_lobbies = list(m.game_sessions_conf.find(
        {'circle_id': circle['_id'], 'deactivated': {'$ne': True}},
        {'lobby_id': 1, 'title': 1, 'game_type': 1, 'pin': 1, 'expires_at': 1}
    ).sort('created_at', -1).limit(10))
    messages = list(m.circle_messages_conf.find({'circle_id': circle['_id']}).sort('created_at', -1).limit(50))
    for message in messages:
        message['content'] = decrypt_community_note(message.get('content', ''), circle['_id'])
        author = m.users_conf.find_one({'_id': message.get('author_id')}, {'username': 1})
        message['author_name'] = author.get('username', 'Member') if author else 'Member'
    messages.reverse()
    return render_template(
        'circle.html',
        circle=circle,
        posts=posts,
        members=members,
        game_lobbies=game_lobbies,
        messages=messages,
        pending_requests=list(m.circle_requests_conf.find({'circle_id': circle['_id'], 'status': 'pending'})) if _role(circle) in ('owner', 'moderator') else [],
        circle_type=CIRCLE_TYPES.get(circle.get('circle_type', 'custom'), CIRCLE_TYPES['custom']),
        is_owner=str(circle.get('owner_id')) == str(current_user.id),
        active_page='circles',
        title=f"{circle.get('name', 'Circle')} | EchoWithin"
    )


@bp.route('/circle/<circle_id>/chat', methods=['POST'])
@login_required
def create_circle_message(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    content = request.form.get('content', '').strip()
    if not content or len(content) > 2000:
        flash('Write a message first.', 'danger')
        return _redirect(circle_id)
    m.circle_messages_conf.insert_one({
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'content': encrypt_community_note(content, circle['_id']),
        'created_at': _now()
    })
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts', methods=['POST'])
@login_required
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
        'expires_at': expires_at
    })
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return redirect(url_for('circles.view_circle', circle_id=circle_id))


@bp.route('/circle/<circle_id>/polls', methods=['POST'])
@login_required
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
    m.circle_posts_conf.insert_one({'circle_id': circle['_id'], 'author_id': ObjectId(current_user.id), 'kind': 'poll', 'content': encrypt_community_note(payload, circle['_id']), 'created_at': now, 'expires_at': None})
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/events', methods=['POST'])
@login_required
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
    m.circle_posts_conf.insert_one({'circle_id': circle['_id'], 'author_id': ObjectId(current_user.id), 'kind': 'event', 'content': encrypt_community_note(payload, circle['_id']), 'created_at': now, 'expires_at': None})
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/vote', methods=['POST'])
@login_required
def vote_poll(circle_id, post_id):
    import main as m
    circle = _get_circle(circle_id)
    post = m.circle_posts_conf.find_one({'_id': _oid(post_id), 'circle_id': circle['_id'], 'kind': 'poll'})
    if not post:
        abort(404)
    try:
        option_index = int(request.form.get('option', ''))
    except (TypeError, ValueError):
        flash('Choose an option.', 'danger')
        return _redirect(circle_id)
    payload = json.loads(decrypt_community_note(post.get('content', ''), circle['_id']))
    options = payload.get('options', [])
    if option_index < 0 or option_index >= len(options):
        flash('Choose a valid option.', 'danger')
        return _redirect(circle_id)
    payload.setdefault('votes', {})[str(current_user.id)] = option_index
    m.circle_posts_conf.update_one({'_id': post['_id']}, {'$set': {'content': encrypt_community_note(json.dumps(payload), circle['_id']), 'updated_at': _now()}})
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/posts/<post_id>/rsvp', methods=['POST'])
@login_required
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
    return _redirect(circle_id)


@bp.route('/circle/<circle_id>/games/create')
@login_required
def create_circle_game(circle_id):
    _get_circle(circle_id)
    game_type = request.args.get('type', 'poll')
    return redirect(url_for('game.games_create', circle_id=circle_id, game_type=game_type))


@bp.route('/circle/<circle_id>/invite', methods=['POST'])
@login_required
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
def invite_username(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    if _role(circle) not in ('owner', 'moderator'):
        abort(403)
    username = request.form.get('username', '').strip()
    user = m.users_conf.find_one({'username': username}, {'_id': 1})
    if not user or user['_id'] in circle.get('members', []):
        flash('User not found or already a member.', 'danger')
        return _redirect(circle_id)
    now = _now()
    m.circle_requests_conf.update_one(
        {'circle_id': circle['_id'], 'user_id': user['_id']},
        {'$set': {'status': 'pending', 'invited_by': ObjectId(current_user.id), 'created_at': now}},
        upsert=True
    )
    flash('Invitation sent.', 'success')
    return _redirect(circle_id)


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
