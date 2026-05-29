from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets
from security import limits
from config import TIME
bp = Blueprint('', __name__, template_folder='templates')


@bp.route('/communities', methods=['GET'])
@login_required
def communities_page():
    import main as m
    user_communities = list(m.communities_conf.find({'members': ObjectId(current_user.id)}).sort('updated_at', -1))
    for comm in user_communities:
        comm['member_count'] = len(comm.get('members', []))
        comm['note_count'] = m.community_notes_conf.count_documents({'community_id': comm['_id']})
        comm['is_admin'] = str(comm.get('admin_id')) == current_user.id
    discover_communities = list(m.communities_conf.find({'visibility': 'public', 'members': {'$ne': ObjectId(current_user.id)}}).sort('updated_at', -1).limit(20))
    for comm in discover_communities:
        comm['member_count'] = len(comm.get('members', []))
        comm['note_count'] = m.community_notes_conf.count_documents({'community_id': comm['_id']})
    return render_template('communities.html', communities=user_communities, discover_communities=discover_communities)


@bp.route('/community/<community_id>', methods=['GET'])
@login_required
def view_community(community_id):
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        flash('Invalid community ID.', 'danger')
        return redirect(url_for('communities_page'))
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        flash('Community not found.', 'danger')
        return redirect(url_for('communities_page'))
    if community.get('banned'):
        flash('This community has been suspended for violating our community guidelines.', 'danger')
        return redirect(url_for('communities_page'))
    user_id_obj = ObjectId(current_user.id)
    is_member = user_id_obj in community.get('members', [])
    is_admin = str(community.get('admin_id')) == current_user.id
    is_site_admin = getattr(current_user, 'is_admin', False)
    if not is_member and not is_site_admin and community.get('visibility') == 'private':
        flash('You are not a member of this private community.', 'danger')
        return redirect(url_for('communities_page'))
    if is_site_admin and not is_member:
        flash('ADMIN INSPECTION: You are viewing this community as a site administrator.', 'info')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    skip = (page - 1) * per_page
    total_notes = m.community_notes_conf.count_documents({'community_id': comm_obj_id})
    raw_notes = list(m.community_notes_conf.find({'community_id': comm_obj_id}).sort([('score', -1), ('created_at', -1)]).skip(skip).limit(per_page))
    for note in raw_notes:
        note['content'] = m.decrypt_community_note(note.get('content', ''), comm_obj_id)
        if current_user.is_authenticated:
            user_reaction = m.community_reactions_conf.find_one({'note_id': note['_id'], 'user_id': user_id_obj})
            if user_reaction:
                note['user_reaction_type'] = user_reaction.get('reaction_type')
    members = []
    if is_admin:
        member_ids = community.get('members', [])
        members = list(m.users_conf.find({'_id': {'$in': member_ids}}, {'username': 1}))
    return render_template('community_space.html', community=community, notes=raw_notes, is_member=is_member, is_admin=is_admin, members=members, page=page, total_pages=(total_notes + per_page - 1) // per_page)


@bp.route('/api/community/create', methods=['POST'])
@login_required
@limits(calls=5, period=3600)
def api_create_community():
    import main as m
    name = request.form.get('name', '').strip()
    bio = request.form.get('bio', '').strip()
    visibility = request.form.get('visibility', 'private')
    if not name:
        flash('Community name is required.', 'danger')
        return redirect(url_for('communities_page'))
    if len(name) > 50:
        flash('Name must be 50 characters or less.', 'danger')
        return redirect(url_for('communities_page'))
    if len(bio) > 200:
        flash('Bio must be 200 characters or less.', 'danger')
        return redirect(url_for('communities_page'))
    user_id_obj = ObjectId(current_user.id)
    current_count = m.communities_conf.count_documents({'admin_id': user_id_obj})
    max_allowed = current_user.get_limit('max_communities')
    if current_count >= max_allowed:
        flash(f'You have reached your limit of {max_allowed} communities. Upgrade to Premium for more!', 'warning')
        return redirect(url_for('communities_page'))
    invite_code = secrets.token_urlsafe(12)
    new_community = {
        'name': name, 'bio': bio, 'admin_id': user_id_obj, 'members': [user_id_obj],
        'visibility': visibility, 'invite_code': invite_code,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc)
    }
    res = m.communities_conf.insert_one(new_community)
    flash(f'Community "{name}" created successfully!', 'success')
    return redirect(url_for('view_community', community_id=str(res.inserted_id)))


@bp.route('/community/join/<invite_code>', methods=['GET'])
@login_required
def join_community_link(invite_code):
    import main as m
    community = m.communities_conf.find_one({'invite_code': invite_code})
    if not community:
        flash('Invalid or expired invite link.', 'danger')
        return redirect(url_for('communities_page'))
    user_id_obj = ObjectId(current_user.id)
    if user_id_obj in community.get('members', []):
        flash('You are already a member of this community.', 'info')
        return redirect(url_for('view_community', community_id=str(community['_id'])))
    m.communities_conf.update_one({'_id': community['_id']}, {'$addToSet': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    flash(f'Successfully joined {community.get("name")}!', 'success')
    return redirect(url_for('view_community', community_id=str(community['_id'])))


@bp.route('/api/community/join', methods=['POST'])
@login_required
def api_join_community_code():
    import main as m
    invite_code = request.form.get('invite_code', '').strip()
    if 'community/join/' in invite_code:
        invite_code = invite_code.split('community/join/')[-1].strip()
    if not invite_code:
        flash('Please provide an invite code.', 'warning')
        return redirect(url_for('communities_page'))
    return redirect(url_for('join_community_link', invite_code=invite_code))


@bp.route('/api/community/<community_id>/join-public', methods=['POST'])
@login_required
def api_join_public_community(community_id):
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    community = m.communities_conf.find_one({'_id': comm_obj_id, 'visibility': 'public'})
    if not community:
        return jsonify({'error': 'Community not found or not public'}), 404
    user_id_obj = ObjectId(current_user.id)
    if user_id_obj in community.get('members', []):
        return jsonify({'success': True, 'message': 'Already a member'})
    m.communities_conf.update_one({'_id': comm_obj_id}, {'$addToSet': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    return jsonify({'success': True, 'message': 'Joined community'})


@bp.route('/api/community/<community_id>/settings', methods=['POST'])
@login_required
def api_update_community(community_id):
    import main as m
    community = m.communities_conf.find_one({'_id': ObjectId(community_id)})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    if str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    name = request.form.get('name', '').strip()
    bio = request.form.get('bio', '').strip()
    visibility = request.form.get('visibility')
    update = {'updated_at': datetime.datetime.now(datetime.timezone.utc)}
    if name:
        update['name'] = name
    if bio:
        update['bio'] = bio
    if visibility in ('public', 'private'):
        update['visibility'] = visibility
    m.communities_conf.update_one({'_id': ObjectId(community_id)}, {'$set': update})
    flash('Community settings updated.', 'success')
    return redirect(url_for('view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/regenerate-invite', methods=['POST'])
@login_required
def api_regenerate_invite(community_id):
    import main as m
    community = m.communities_conf.find_one({'_id': ObjectId(community_id)})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    if str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    new_code = secrets.token_urlsafe(12)
    m.communities_conf.update_one({'_id': ObjectId(community_id)}, {'$set': {'invite_code': new_code}})
    invite_url = url_for('join_community_link', invite_code=new_code, _external=True)
    if request.headers.get('X-CSRFToken') or request.is_json:
        return jsonify({'success': True, 'invite_url': invite_url, 'invite_code': new_code})
    flash(f'New invite link generated!', 'success')
    return redirect(url_for('view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/leave', methods=['POST'])
@login_required
def api_leave_community(community_id):
    import main as m
    community = m.communities_conf.find_one({'_id': ObjectId(community_id)})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    m.communities_conf.update_one({'_id': ObjectId(community_id)}, {'$pull': {'members': ObjectId(current_user.id)}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    flash('You have left the community.', 'info')
    return redirect(url_for('communities_page'))


@bp.route('/api/community/<community_id>/remove-member', methods=['POST'])
@login_required
def api_remove_member(community_id):
    import main as m
    community = m.communities_conf.find_one({'_id': ObjectId(community_id)})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    if str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    member_id = request.form.get('member_id')
    if not member_id:
        return jsonify({'error': 'Member ID required'}), 400
    m.communities_conf.update_one({'_id': ObjectId(community_id)}, {'$pull': {'members': ObjectId(member_id)}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    flash('Member removed.', 'success')
    return redirect(url_for('view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/note/create', methods=['POST'])
@login_required
def api_create_community_note(community_id):
    import main as m
    community = m.communities_conf.find_one({'_id': ObjectId(community_id)})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    user_id_obj = ObjectId(current_user.id)
    if user_id_obj not in community.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    content = request.form.get('content', '').strip()
    if not content:
        flash('Content is required.', 'danger')
        return redirect(url_for('view_community', community_id=community_id))
    encrypted = m.encrypt_community_note(content, ObjectId(community_id))
    note = {
        'community_id': ObjectId(community_id), 'author_id': user_id_obj,
        'author_name': current_user.username, 'content': encrypted,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'last_activity_at': datetime.datetime.now(datetime.timezone.utc),
        'score': 1, 'view_count': 0
    }
    m.community_notes_conf.insert_one(note)
    m.communities_conf.update_one({'_id': ObjectId(community_id)}, {'$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    flash('Note posted to community!', 'success')
    return redirect(url_for('view_community', community_id=community_id))


@bp.route('/api/community/note/<note_id>/react', methods=['POST'])
@login_required
def api_react_community_note(note_id):
    import main as m
    note = m.community_notes_conf.find_one({'_id': ObjectId(note_id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    community = m.communities_conf.find_one({'_id': note['community_id']})
    if not community or ObjectId(current_user.id) not in community.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
    data = request.get_json() or {}
    reaction_type = data.get('reaction_type', 'like')
    user_id_obj = ObjectId(current_user.id)
    existing = m.community_reactions_conf.find_one({'note_id': ObjectId(note_id), 'user_id': user_id_obj})
    if existing:
        m.community_reactions_conf.delete_one({'_id': existing['_id']})
        score_delta = -1
    else:
        m.community_reactions_conf.insert_one({'note_id': ObjectId(note_id), 'user_id': user_id_obj, 'reaction_type': reaction_type, 'created_at': datetime.datetime.now(datetime.timezone.utc)})
        score_delta = 1
    m.community_notes_conf.update_one({'_id': ObjectId(note_id)}, {'$inc': {'score': score_delta}})
    return jsonify({'success': True, 'reacted': not existing})


@bp.route('/api/community/note/<note_id>/delete', methods=['POST'])
@login_required
def api_delete_community_note(note_id):
    import main as m
    note = m.community_notes_conf.find_one({'_id': ObjectId(note_id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    community = m.communities_conf.find_one({'_id': note['community_id']})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    is_author = str(note.get('author_id')) == current_user.id
    is_admin = str(community.get('admin_id')) == current_user.id
    if not (is_author or is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
    m.community_notes_conf.delete_one({'_id': ObjectId(note_id)})
    m.community_reactions_conf.delete_many({'note_id': ObjectId(note_id)})
    if request.headers.get('X-CSRFToken') or request.is_json:
        return jsonify({'success': True, 'message': 'Note deleted.'})
    flash('Note deleted.', 'success')
    return redirect(url_for('view_community', community_id=str(note['community_id'])))


@bp.route('/share/community-note/<share_id>', methods=['GET'])
def view_shared_community_note(share_id):
    import main as m
    note = m.community_notes_conf.find_one({'share_id': share_id})
    if not note:
        return render_template('shared_note.html', expired=True), 410
    parent_community = m.communities_conf.find_one({'_id': note['community_id']}, {'banned': 1})
    if parent_community and parent_community.get('banned'):
        return render_template('shared_note.html', expired=True), 410
    content = m.decrypt_community_note(note.get('content', ''), note['community_id'])
    m.community_notes_conf.update_one({'_id': note['_id']}, {'$inc': {'view_count': 1}, '$set': {'last_activity_at': datetime.datetime.now(datetime.timezone.utc)}})
    surprise_theme = note.get('surprise_theme', 'none')
    if surprise_theme == 'none' and note.get('share_style') and note.get('share_style') != 'standard':
        surprise_theme = note.get('share_style')
    already_saved = False
    if current_user.is_authenticated:
        already_saved = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'source_note_id': note['_id']}) > 0
    return render_template('shared_community_note.html', content=content, already_saved=already_saved, surprise_theme=surprise_theme, note_id=str(note['_id']), note=note)


@bp.route('/api/community/note/<note_id>/save', methods=['POST'])
@login_required
def api_save_community_note(note_id):
    import main as m
    note = m.community_notes_conf.find_one({'_id': ObjectId(note_id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    community = m.communities_conf.find_one({'_id': note['community_id']})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    content = m.decrypt_community_note(note.get('content', ''), note['community_id'])
    encrypted = m.encrypt_note(content)
    existing = m.personal_posts_conf.find_one({'user_id': ObjectId(current_user.id), 'source_note_id': note['_id']})
    if existing:
        flash('You already have this note saved.', 'info')
    else:
        saved_note = {
            'user_id': ObjectId(current_user.id), 'title': f"From {community.get('name')}",
            'content': encrypted, 'source_note_id': note['_id'],
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'updated_at': datetime.datetime.now(datetime.timezone.utc), 'is_locked': False
        }
        m.personal_posts_conf.insert_one(saved_note)
        flash('Note saved to your personal space!', 'success')
    return redirect(url_for('home'))


@bp.route('/api/community/<community_id>/report', methods=['POST'])
@login_required
def api_report_community(community_id):
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    data = request.get_json() or {}
    reason = data.get('reason', '').strip()
    if not reason or len(reason) < 10:
        return jsonify({'error': 'Please provide a detailed reason (at least 10 characters)'}), 400
    existing = m.community_reports_conf.find_one({'community_id': comm_obj_id, 'reporter_id': ObjectId(current_user.id), 'status': 'pending'})
    if existing:
        return jsonify({'error': 'You have already reported this community. Our team will review it shortly.'}), 400
    report = {
        'community_id': comm_obj_id, 'community_name': community.get('name'),
        'reporter_id': ObjectId(current_user.id), 'reporter_name': current_user.username,
        'reason': reason, 'status': 'pending',
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    m.community_reports_conf.insert_one(report)
    if request.headers.get('X-CSRFToken') or request.is_json:
        return jsonify({'success': True, 'message': 'Report submitted. Our moderation team will review this community.'})
    flash('Report submitted. Our moderation team will review this community.', 'success')
    return redirect(url_for('communities_page'))
