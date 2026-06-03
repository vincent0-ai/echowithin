from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets
from security import limits
from config import TIME
bp = Blueprint('communities', __name__, template_folder='templates')


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
        return redirect(url_for('communities.communities_page'))
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        flash('Community not found.', 'danger')
        return redirect(url_for('communities.communities_page'))
    if community.get('banned'):
        flash('This community has been suspended for violating our community guidelines.', 'danger')
        return redirect(url_for('communities.communities_page'))
    user_id_obj = ObjectId(current_user.id)
    is_member = user_id_obj in community.get('members', [])
    is_admin = str(community.get('admin_id')) == current_user.id
    is_site_admin = getattr(current_user, 'is_admin', False)
    if not is_member and not is_site_admin and community.get('visibility') == 'private':
        flash('You are not a member of this private community.', 'danger')
        return redirect(url_for('communities.communities_page'))
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

    # Fetch active challenge (at most one per community)
    active_challenge = m.community_challenges_conf.find_one({
        'community_id': comm_obj_id,
        'status': 'active'
    })
    if active_challenge:
        active_challenge['entry_count'] = m.community_notes_conf.count_documents({
            'community_id': comm_obj_id,
            'challenge_id': active_challenge['_id']
        })

    # Fetch past (completed) challenges
    past_challenges = list(m.community_challenges_conf.find({
        'community_id': comm_obj_id,
        'status': 'completed'
    }).sort('ended_at', -1).limit(10))

    return render_template('community_space.html', community=community, notes=raw_notes,
                           is_member=is_member, is_admin=is_admin, members=members,
                           page=page, total_pages=(total_notes + per_page - 1) // per_page,
                           active_challenge=active_challenge, past_challenges=past_challenges)


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
        return redirect(url_for('communities.communities_page'))
    if len(name) > 50:
        flash('Name must be 50 characters or less.', 'danger')
        return redirect(url_for('communities.communities_page'))
    if len(bio) > 200:
        flash('Bio must be 200 characters or less.', 'danger')
        return redirect(url_for('communities.communities_page'))
    user_id_obj = ObjectId(current_user.id)
    current_count = m.communities_conf.count_documents({'admin_id': user_id_obj})
    max_allowed = current_user.get_limit('max_communities')
    if current_count >= max_allowed:
        flash(f'You have reached your limit of {max_allowed} communities. Upgrade to Premium for more!', 'warning')
        return redirect(url_for('communities.communities_page'))
    invite_code = secrets.token_urlsafe(12)
    new_community = {
        'name': name, 'bio': bio, 'admin_id': user_id_obj, 'members': [user_id_obj],
        'visibility': visibility, 'invite_code': invite_code,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc)
    }
    res = m.communities_conf.insert_one(new_community)
    flash(f'Community "{name}" created successfully!', 'success')
    return redirect(url_for('communities.view_community', community_id=str(res.inserted_id)))


@bp.route('/community/join/<invite_code>', methods=['GET'])
@login_required
def join_community_link(invite_code):
    import main as m
    community = m.communities_conf.find_one({'invite_code': invite_code})
    if not community:
        flash('Invalid or expired invite link.', 'danger')
        return redirect(url_for('communities.communities_page'))
    user_id_obj = ObjectId(current_user.id)
    if user_id_obj in community.get('members', []):
        flash('You are already a member of this community.', 'info')
        return redirect(url_for('communities.view_community', community_id=str(community['_id'])))
    m.communities_conf.update_one({'_id': community['_id']}, {'$addToSet': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    flash(f'Successfully joined {community.get("name")}!', 'success')
    return redirect(url_for('communities.view_community', community_id=str(community['_id'])))


@bp.route('/api/community/join', methods=['POST'])
@login_required
def api_join_community_code():
    import main as m
    invite_code = request.form.get('invite_code', '').strip()
    if 'community/join/' in invite_code:
        invite_code = invite_code.split('community/join/')[-1].strip()
    if not invite_code:
        flash('Please provide an invite code.', 'warning')
        return redirect(url_for('communities.communities_page'))
    return redirect(url_for('communities.join_community_link', invite_code=invite_code))


@bp.route('/api/community/<community_id>/join-public', methods=['POST'])
@login_required
def api_join_public_community(community_id):
    """Join a public community by ID directly from the discovery page."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id, 'visibility': 'public'})
    if not community:
        flash('Community not found or is not public.', 'danger')
        return redirect(url_for('communities.communities_page'))
        
    user_id_obj = ObjectId(current_user.id)
    
    if user_id_obj not in community.get('members', []):
        m.communities_conf.update_one(
            {'_id': comm_obj_id},
            {
                '$addToSet': {'members': user_id_obj},
                '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}
            }
        )
        flash(f'Successfully joined {community.get("name")}!', 'success')
        
    return redirect(url_for('communities.view_community', community_id=str(comm_obj_id)))


@bp.route('/api/community/<community_id>/settings', methods=['POST'])
@login_required
def api_update_community(community_id):
    """Update community settings (Admin only)."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community or str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    name = request.form.get('name', '').strip()
    bio = request.form.get('bio', '').strip()
    visibility = request.form.get('visibility')
    
    update_data = {'updated_at': datetime.datetime.now(datetime.timezone.utc)}
    if name and len(name) <= 50:
        update_data['name'] = name
    if bio is not None and len(bio) <= 200:
        update_data['bio'] = bio
    if visibility in ['public', 'private']:
        update_data['visibility'] = visibility
        
    m.communities_conf.update_one({'_id': comm_obj_id}, {'$set': update_data})
    flash('Community settings updated.', 'success')
    return redirect(url_for('communities.view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/regenerate-invite', methods=['POST'])
@login_required
def api_regenerate_invite(community_id):
    """Regenerate invite link (Admin only)."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community or str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    new_code = secrets.token_urlsafe(12)
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$set': {'invite_code': new_code}}
    )
    
    flash('Invite link regenerated.', 'success')
    return redirect(url_for('communities.view_community', community_id=str(comm_obj_id)))


@bp.route('/api/community/<community_id>/leave', methods=['POST'])
@login_required
def api_leave_community(community_id):
    """Leave a community."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
        user_id_obj = ObjectId(current_user.id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Not found'}), 404
        
    if str(community.get('admin_id')) == current_user.id:
        flash('Admin cannot leave the community. Delete it instead or transfer ownership (not yet supported).', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))
        
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$pull': {'members': user_id_obj}}
    )
    
    flash('You have left the community.', 'success')
    return redirect(url_for('communities.communities_page'))


@bp.route('/api/community/<community_id>/remove-member', methods=['POST'])
@login_required
def api_remove_member(community_id):
    """Remove a member (Admin only)."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
        member_id = ObjectId(request.form.get('member_id'))
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community or str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
        
    if str(member_id) == current_user.id:
        return jsonify({'error': 'Cannot remove yourself'}), 400
        
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$pull': {'members': member_id}}
    )
    
    flash('Member removed.', 'success')
    return redirect(url_for('communities.view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/note/create', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_create_community_note(community_id):
    """Create a new community note with optional surprise theme and media."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Not found'}), 404
        
    # Must be member
    if ObjectId(current_user.id) not in community.get('members', []):
        return jsonify({'error': 'Not a member'}), 403
        
    content = request.form.get('content', '').strip()
    if not content:
        flash('Note content cannot be empty.', 'warning')
        return redirect(url_for('communities.view_community', community_id=community_id))
        
    max_chars = current_user.get_limit('max_chars_per_note')
    if len(content) > max_chars:
        flash(f'Note exceeds maximum allowed length of {max_chars} characters.', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))
        
    permissions = request.form.get('permissions', 'view')
    surprise_theme = request.form.get('surprise_theme', 'none')
    font_style = request.form.get('font_style', 'standard')
    use_typewriter = request.form.get('use_typewriter') == 'true'
    is_anonymous = request.form.get('is_anonymous') == 'true'

    # Optional: link this note to an active challenge
    challenge_id = None
    challenge_id_str = request.form.get('challenge_id', '').strip()
    if challenge_id_str:
        try:
            challenge_obj_id = ObjectId(challenge_id_str)
            challenge = m.community_challenges_conf.find_one({
                '_id': challenge_obj_id,
                'community_id': comm_obj_id,
                'status': 'active'
            })
            if challenge:
                challenge_id = challenge_obj_id
        except Exception:
            pass
    
    # Parse tags
    tags_str = request.form.get('tags', '')
    tags = [t.strip()[:20] for t in tags_str.split(',') if t.strip()] if tags_str else []
    
    # Handle media uploads (premium gated, same as personal shared notes)
    valentine_photo = None
    valentine_audio = None
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    
    if surprise_theme != 'none':
        photo_file = request.files.get('valentine_photo')
        audio_file = request.files.get('valentine_audio')
        
        has_media = bool((photo_file and photo_file.filename) or (audio_file and audio_file.filename))
        if has_media and not m.is_premium(user_doc):
            flash('Uploading photos and music to surprise notes is a Premium feature.', 'warning')
            # Still allow the note, just skip media
        else:
            if photo_file and photo_file.filename:
                ext = photo_file.filename.rsplit('.', 1)[1].lower() if '.' in photo_file.filename else ''
                if ext in m.ALLOWED_IMAGE_EXTENSIONS:
                    try:
                        upload_result = m.cloudinary.uploader.upload(photo_file, folder="echowithin_community")
                        valentine_photo = upload_result.get('secure_url')
                    except Exception as e:
                        current_app.logger.error(f"Community note photo upload failed: {e}")
            
            if audio_file and audio_file.filename:
                ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''
                if ext in m.ALLOWED_AUDIO_EXTENSIONS:
                    try:
                        audio_file.seek(0)
                        upload_result = m.cloudinary.uploader.upload(audio_file, resource_type="auto", folder="echowithin_community")
                        valentine_audio = upload_result.get('secure_url')
                    except Exception as e:
                        current_app.logger.error(f"Community note audio upload failed: {e}")
    
    # Encrypt content
    encrypted_content = m.encrypt_community_note(content, comm_obj_id)
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Generate random share ID
    share_id = secrets.token_urlsafe(16)
    
    note_data = {
        'community_id': comm_obj_id,
        'author_id': ObjectId(current_user.id),
        'author_name': 'Anonymous' if is_anonymous else current_user.username,
        'is_anonymous': is_anonymous,
        'content': encrypted_content,
        'tags': tags[:5],
        'permissions': permissions,
        'surprise_theme': surprise_theme,
        'font_style': font_style,
        'share_id': share_id,
        'use_typewriter': use_typewriter,
        'valentine_photo': valentine_photo,
        'valentine_audio': valentine_audio,
        'reactions': {'heart': 0, 'fire': 0, 'laugh': 0, 'wow': 0, 'pray': 0},
        'reaction_count': 0,
        'view_count': 0,
        'score': 10.0,
        'created_at': now,
        'updated_at': now,
        'last_activity_at': now
    }
    if challenge_id:
        note_data['challenge_id'] = challenge_id
    
    m.community_notes_conf.insert_one(note_data)
    m.communities_conf.update_one({'_id': comm_obj_id}, {'$set': {'updated_at': now}})

    # Notify other community members about the new note (background)
    try:
        author_obj_id = ObjectId(current_user.id)
        member_ids = community.get('members', [])
        comm_name = community.get('name', 'a community')
        author_display = 'Someone' if is_anonymous else current_user.username
        challenge_label = ''
        if challenge_id:
            ch = m.community_challenges_conf.find_one({'_id': challenge_id})
            if ch:
                challenge_label = f' (Challenge: {ch.get("title", "")})'
        community_url = url_for('communities.view_community', community_id=community_id, _external=True)

        def _send_community_notifs():
            for member_id in member_ids:
                if member_id == author_obj_id:
                    continue
                try:
                    m.send_push_notification_to_user(
                        str(member_id),
                        f'New note in {comm_name}',
                        f'{author_display} posted a note{challenge_label}',
                        url=community_url,
                        tag=f'community-note-{community_id}',
                        extra_data={'type': 'community_note', 'community_id': community_id}
                    )
                except Exception:
                    pass

        m.executor.submit(_send_community_notifs)
    except Exception as notif_err:
        current_app.logger.error(f"Community notification error: {notif_err}")

    flash('Note added successfully.', 'success')
    return redirect(url_for('communities.view_community', community_id=community_id))


@bp.route('/api/community/note/<note_id>/react', methods=['POST'])
@login_required
@limits(calls=60, period=60)
def api_react_community_note(note_id):
    """Toggle a reaction on a community note."""
    import main as m
    try:
        note_obj_id = ObjectId(note_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    data = request.get_json() or {}
    reaction_type = data.get('reaction_type')
    valid_reactions = ['heart', 'fire', 'laugh', 'wow', 'pray']
    
    if reaction_type not in valid_reactions:
        return jsonify({'error': 'Invalid reaction'}), 400
        
    note = m.community_notes_conf.find_one({'_id': note_obj_id})
    if not note:
        return jsonify({'error': 'Not found'}), 404
        
    user_id_obj = ObjectId(current_user.id)
    
    # Check existing reaction
    existing = m.community_reactions_conf.find_one({
        'note_id': note_obj_id,
        'user_id': user_id_obj
    })
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if existing:
        if existing.get('reaction_type') == reaction_type:
            # Remove reaction (toggle off)
            m.community_reactions_conf.delete_one({'_id': existing['_id']})
            # Update counts
            m.community_notes_conf.update_one(
                {'_id': note_obj_id},
                {
                    '$inc': {
                        f'reactions.{reaction_type}': -1,
                        'reaction_count': -1
                    }
                }
            )
            action = 'removed'
        else:
            # Change reaction
            old_type = existing.get('reaction_type')
            m.community_reactions_conf.update_one(
                {'_id': existing['_id']},
                {'$set': {'reaction_type': reaction_type, 'created_at': now}}
            )
            # Update counts
            m.community_notes_conf.update_one(
                {'_id': note_obj_id},
                {
                    '$inc': {
                        f'reactions.{old_type}': -1,
                        f'reactions.{reaction_type}': 1
                    },
                    '$set': {'last_activity_at': now}
                }
            )
            action = 'changed'
    else:
        # Add new reaction
        m.community_reactions_conf.insert_one({
            'note_id': note_obj_id,
            'user_id': user_id_obj,
            'reaction_type': reaction_type,
            'created_at': now
        })
        m.community_notes_conf.update_one(
            {'_id': note_obj_id},
            {
                '$inc': {
                    f'reactions.{reaction_type}': 1,
                    'reaction_count': 1
                },
                '$set': {'last_activity_at': now}
            }
        )
        action = 'added'
        
    # Re-calculate score based on reactions, views, and time decay
    updated_note = m.community_notes_conf.find_one({'_id': note_obj_id})
    if updated_note:
        reactions = updated_note.get('reactions', {})
        total_reactions = sum(reactions.values())
        views = updated_note.get('view_count', 0)
        created = updated_note.get('created_at', now)
        # Ensure created is timezone-aware (older docs may be naive)
        if created.tzinfo is None:
            created = created.replace(tzinfo=datetime.timezone.utc)
        
        # Weighted engagement: reactions(3) + views(0.1)
        import math as math_module
        raw_score = (total_reactions * 3) + (views * 0.1)
        log_score = math_module.log1p(raw_score) * 10
        
        # Time decay: halve score every 7 days
        age_hours = max((now - created).total_seconds() / 3600, 0.1)
        decay = max(1.0 / (1 + (age_hours / 168)), 0.05)
        
        # Recency boost for notes < 6 hours old
        recency_boost = 2.0 if age_hours < 6 else (1.5 if age_hours < 24 else 1.0)
        
        final_score = round(log_score * decay * recency_boost, 2)
        m.community_notes_conf.update_one(
            {'_id': note_obj_id},
            {'$set': {'score': final_score}}
        )
    
    # Fetch updated counts to return
    updated_note = m.community_notes_conf.find_one({'_id': note_obj_id}, {'reactions': 1, 'reaction_count': 1})
    
    return jsonify({
        'success': True,
        'action': action,
        'reactions': updated_note.get('reactions', {}),
        'total': updated_note.get('reaction_count', 0)
    })


@bp.route('/api/community/note/<note_id>/delete', methods=['POST'])
@login_required
def api_delete_community_note(note_id):
    """Delete a community note (Author or Admin only)."""
    import main as m
    try:
        note_obj_id = ObjectId(note_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    note = m.community_notes_conf.find_one({'_id': note_obj_id})
    if not note:
        return jsonify({'error': 'Not found'}), 404
        
    community = m.communities_conf.find_one({'_id': note['community_id']})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
        
    is_author = str(note.get('author_id')) == current_user.id
    is_admin = str(community.get('admin_id')) == current_user.id
    
    if not (is_author or is_admin):
        return jsonify({'error': 'Unauthorized'}), 403
        
    # Delete note and its reactions
    m.community_notes_conf.delete_one({'_id': note_obj_id})
    m.community_reactions_conf.delete_many({'note_id': note_obj_id})
    
    if request.headers.get('X-CSRFToken') or request.is_json:
        return jsonify({'success': True, 'message': 'Note deleted.'})
    
    flash('Note deleted.', 'success')
    return redirect(url_for('communities.view_community', community_id=str(note['community_id'])))


@bp.route('/share/community-note/<share_id>', methods=['GET'])
def view_shared_community_note(share_id):
    """Public view for a shared community note."""
    import main as m
    note = m.community_notes_conf.find_one({'share_id': share_id})
    if not note:
        return render_template('shared_note.html', expired=True), 410
    
    # Check if parent community is banned
    parent_community = m.communities_conf.find_one({'_id': note['community_id']}, {'banned': 1})
    if parent_community and parent_community.get('banned'):
        return render_template('shared_note.html', expired=True), 410
        
    # Decrypt content
    content = m.decrypt_community_note(note.get('content', ''), note['community_id'])
    
    # Increment view count
    m.community_notes_conf.update_one(
        {'_id': note['_id']},
        {
            '$inc': {'view_count': 1},
            '$set': {'last_activity_at': datetime.datetime.now(datetime.timezone.utc)}
        }
    )
    
    surprise_theme = note.get('surprise_theme', 'none')
    # Backward compat: old notes stored 'share_style' instead of 'surprise_theme'
    if surprise_theme == 'none' and note.get('share_style') and note.get('share_style') != 'standard':
        surprise_theme = note.get('share_style')
    
    # Check if current user already saved this community note
    already_saved = False
    if current_user.is_authenticated:
        already_saved = bool(m.personal_posts_conf.find_one({
            'user_id': ObjectId(current_user.id),
            'saved_from_community_note': str(note['_id'])
        }))
    
    return render_template('shared_note.html',
                           share_id=share_id,
                           content=content,
                           permissions='view',
                           note_id=str(note['_id']),
                           updated_at=note.get('updated_at'),
                           created_at=note.get('created_at'),
                           is_owner=False,
                           already_saved=already_saved,
                           has_pending_proposal=False,
                           surprise_theme=surprise_theme,
                           reference='',
                           tags=note.get('tags', []),
                           is_valentine=(surprise_theme != 'none'),
                           valentine_photo=note.get('valentine_photo'),
                           valentine_audio=note.get('valentine_audio'),
                           use_typewriter=note.get('use_typewriter', False),
                           owner_max_chars=m.get_limit(m.users_conf.find_one({'_id': note.get('author_id')}), 'max_chars_per_note'),
                           note_attachments=[],
                           can_upload_media=False,
                           is_community_note=True,
                           community_note_id=str(note['_id']))


@bp.route('/api/community/note/<note_id>/save', methods=['POST'])
@login_required
def api_save_community_note(note_id):
    """Save a community note to user's personal notes."""
    import main as m
    try:
        note_obj_id = ObjectId(note_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
        
    note = m.community_notes_conf.find_one({'_id': note_obj_id})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
        
    user_id_obj = ObjectId(current_user.id)
    
    # Check if already saved
    existing = m.personal_posts_conf.find_one({
        'user_id': user_id_obj,
        'saved_from_community_note': str(note_obj_id)
    })
    if existing:
        return jsonify({'error': 'Already saved', 'already_saved': True}), 409
    
    # Decrypt the community note content
    content = m.decrypt_community_note(note.get('content', ''), note['community_id'])
    
    # Get the community name for reference
    community = m.communities_conf.find_one({'_id': note['community_id']}, {'name': 1})
    comm_name = community.get('name', 'Unknown') if community else 'Unknown'
    
    # Encrypt with user's personal key and save
    encrypted = m.encrypt_note(content, user_id=current_user.id)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    m.personal_posts_conf.insert_one({
        'user_id': user_id_obj,
        'content_owner_id': user_id_obj,
        'content': encrypted,
        'encrypted': True,
        'reference': f'Saved from community: {comm_name} (by {note.get("author_name", "unknown")})',
        'tags': note.get('tags', []),
        'surprise_theme': note.get('surprise_theme', 'none'),
        'saved_from_community_note': str(note_obj_id),
        'created_at': now,
        'updated_at': now
    })
    
    return jsonify({'success': True, 'message': 'Note saved to your personal notes!'})


@bp.route('/api/community/<community_id>/challenge/create', methods=['POST'])
@login_required
@limits(calls=5, period=3600)
def api_create_challenge(community_id):
    """Create a writing challenge/prompt (admin only). One active per community."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community or str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Only one active challenge at a time
    existing = m.community_challenges_conf.find_one({
        'community_id': comm_obj_id,
        'status': 'active'
    })
    if existing:
        flash('There is already an active challenge. End it before starting a new one.', 'warning')
        return redirect(url_for('communities.view_community', community_id=community_id))

    title = request.form.get('challenge_title', '').strip()
    description = request.form.get('challenge_desc', '').strip()
    ends_at_str = request.form.get('challenge_ends_at', '').strip()

    if not title or not ends_at_str:
        flash('Challenge title and end date are required.', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))

    if len(title) > 100:
        title = title[:100]
    if len(description) > 500:
        description = description[:500]

    try:
        ends_at = datetime.datetime.fromisoformat(ends_at_str).replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        flash('Invalid end date format.', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))

    now = datetime.datetime.now(datetime.timezone.utc)
    if ends_at <= now:
        flash('End date must be in the future.', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))

    m.community_challenges_conf.insert_one({
        'community_id': comm_obj_id,
        'title': title,
        'description': description,
        'created_by': ObjectId(current_user.id),
        'created_by_name': current_user.username,
        'status': 'active',
        'created_at': now,
        'ends_at': ends_at,
        'winner_note_id': None,
        'winner_username': None
    })

    # Notify all members about the new challenge (background)
    try:
        admin_obj_id = ObjectId(current_user.id)
        member_ids = community.get('members', [])
        comm_name = community.get('name', 'a community')
        community_url = url_for('communities.view_community', community_id=community_id, _external=True)

        def _send_challenge_notifs():
            for member_id in member_ids:
                if member_id == admin_obj_id:
                    continue
                try:
                    m.send_push_notification_to_user(
                        str(member_id),
                        f'New Challenge in {comm_name}',
                        f'"{title}" — join in and share your response!',
                        url=community_url,
                        tag=f'community-challenge-{community_id}',
                        extra_data={'type': 'community_challenge', 'community_id': community_id}
                    )
                except Exception:
                    pass

        m.executor.submit(_send_challenge_notifs)
    except Exception as notif_err:
        current_app.logger.error(f"Challenge notification error: {notif_err}")

    flash(f'Challenge "{title}" started!', 'success')
    return redirect(url_for('communities.view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/challenge/<challenge_id>/end', methods=['POST'])
@login_required
def api_end_challenge(community_id, challenge_id):
    """End a challenge and pick the winner (highest reaction_count). Admin only."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
        ch_obj_id = ObjectId(challenge_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community or str(community.get('admin_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    challenge = m.community_challenges_conf.find_one({
        '_id': ch_obj_id,
        'community_id': comm_obj_id,
        'status': 'active'
    })
    if not challenge:
        flash('Challenge not found or already ended.', 'danger')
        return redirect(url_for('communities.view_community', community_id=community_id))

    now = datetime.datetime.now(datetime.timezone.utc)

    # Find the entry with the highest reaction_count
    winner = m.community_notes_conf.find_one(
        {'community_id': comm_obj_id, 'challenge_id': ch_obj_id},
        sort=[('reaction_count', -1)]
    )

    winner_note_id = winner['_id'] if winner else None
    winner_username = winner.get('author_name', 'Unknown') if winner else None

    m.community_challenges_conf.update_one(
        {'_id': ch_obj_id},
        {'$set': {
            'status': 'completed',
            'ended_at': now,
            'winner_note_id': winner_note_id,
            'winner_username': winner_username
        }}
    )

    if winner:
        flash(f'Challenge ended! Winner: {winner_username}', 'success')
    else:
        flash('Challenge ended. No entries were submitted.', 'info')
    return redirect(url_for('communities.view_community', community_id=community_id))


@bp.route('/api/community/<community_id>/report', methods=['POST'])
@login_required
@limits(calls=5, period=3600)
def api_report_community(community_id):
    """Submit a report against a community for violations."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    
    # Cannot report your own community
    if str(community.get('admin_id')) == current_user.id:
        return jsonify({'error': 'You cannot report your own community'}), 400
    
    # Check for existing pending report from this user
    existing = m.community_reports_conf.find_one({
        'community_id': comm_obj_id,
        'reporter_id': ObjectId(current_user.id),
        'status': 'pending'
    })
    if existing:
        return jsonify({'error': 'You already have a pending report for this community'}), 409
    
    data = request.get_json() if request.is_json else request.form
    reason = data.get('reason', '').strip()
    details = data.get('details', '').strip()
    
    valid_reasons = ['spam', 'harassment', 'inappropriate', 'hate_speech', 'other']
    if reason not in valid_reasons:
        return jsonify({'error': 'Invalid reason'}), 400
    
    if len(details) > 500:
        details = details[:500]
    
    report = {
        'community_id': comm_obj_id,
        'community_name': community.get('name', ''),
        'reporter_id': ObjectId(current_user.id),
        'reporter_username': current_user.username,
        'reason': reason,
        'details': details,
        'status': 'pending',
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'reviewed_at': None,
        'reviewed_by': None
    }
    
    m.community_reports_conf.insert_one(report)
    
    # Send ntfy notification to admin
    try:
        m.send_ntfy_notification.queue(
            f"Community '{community.get('name')}' reported by {current_user.username} for: {reason}",
            "Community Report", "warning"
        )
    except Exception:
        pass
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Report submitted. Our team will review it.'})
    
    flash('Report submitted. Our team will review it.', 'success')
    return redirect(url_for('communities.view_community', community_id=community_id))
