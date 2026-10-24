"""Private Trusted Circles for small invited groups."""

import datetime
import hashlib
import secrets

from bson.errors import InvalidId
from bson.objectid import ObjectId
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from security import encrypt_community_note, decrypt_community_note

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
        'created_at': now,
        'updated_at': now
    })
    return redirect(url_for('circles.view_circle', circle_id=str(result.inserted_id)))


@bp.route('/circle/<circle_id>')
@login_required
def view_circle(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    posts = list(m.circle_posts_conf.find({'circle_id': circle['_id']}).sort('created_at', -1).limit(50))
    for post in posts:
        post['content'] = decrypt_community_note(post.get('content', ''), circle['_id'])
        author = m.users_conf.find_one({'_id': post.get('author_id')}, {'username': 1})
        post['author_name'] = author.get('username', 'Member') if author else 'Member'
    members = list(m.users_conf.find({'_id': {'$in': circle.get('members', [])}}, {'username': 1, 'profile_image_url': 1}))
    return render_template(
        'circle.html',
        circle=circle,
        posts=posts,
        members=members,
        circle_type=CIRCLE_TYPES.get(circle.get('circle_type', 'custom'), CIRCLE_TYPES['custom']),
        is_owner=str(circle.get('owner_id')) == str(current_user.id),
        active_page='circles',
        title=f"{circle.get('name', 'Circle')} | EchoWithin"
    )


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
    m.circle_posts_conf.insert_one({
        'circle_id': circle['_id'],
        'author_id': ObjectId(current_user.id),
        'content': encrypt_community_note(content, circle['_id']),
        'created_at': now,
        'expires_at': None
    })
    m.circles_conf.update_one({'_id': circle['_id']}, {'$set': {'updated_at': now}})
    return redirect(url_for('circles.view_circle', circle_id=circle_id))


@bp.route('/circle/<circle_id>/invite', methods=['POST'])
@login_required
def create_invite(circle_id):
    import main as m
    circle = _get_circle(circle_id)
    role = circle.get('roles', {}).get(str(current_user.id))
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
    m.circles_conf.update_one({'_id': circle['_id']}, {'$addToSet': {'members': user_id}, '$set': {'roles.' + str(user_id): 'member', 'updated_at': now}})
    m.circle_invites_conf.update_one({'_id': invite['_id']}, {'$inc': {'uses': 1}})
    return redirect(url_for('circles.view_circle', circle_id=str(circle['_id'])))


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
