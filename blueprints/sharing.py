from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, hashlib, secrets
from security import limits
bp = Blueprint('sharing', __name__, template_folder='templates')


@bp.route('/api/share/<share_id>/ping', methods=['POST'])
@login_required
def ping_collaborators(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    if str(share.get('owner_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({'success': True, 'message': 'Collaborators will be notified'})


@bp.route('/personal_post/share/<post_id>', methods=['POST'])
@login_required
def api_create_share(post_id):
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    max_shares = m.get_limit(user_doc, 'max_share_links_per_note')
    active_count = m.note_shares_conf.count_documents({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)})
    if active_count >= max_shares:
        return jsonify({'error': f'You have reached the limit of {max_shares} share links per note. Upgrade to Premium for unlimited sharing!', 'upgrade': True}), 403
    surprise_theme = 'none'
    valentine_photo = None
    valentine_audio = None
    use_typewriter = False
    auto_approve = False
    if request.is_json:
        data = request.get_json() or {}
        permissions = data.get('permissions', 'view')
        expires_in = data.get('expires_in')
        access_code = data.get('access_code')
        surprise_theme = data.get('surprise_theme', 'none')
        is_valentine = data.get('is_valentine', False)
        if is_valentine and surprise_theme == 'none':
            surprise_theme = 'valentine'
        valentine_photo = data.get('valentine_photo')
        valentine_audio = data.get('valentine_audio')
        use_typewriter = data.get('use_typewriter', False)
        auto_approve = data.get('auto_approve', False)
    else:
        permissions = request.form.get('permissions', 'view')
        expires_in = request.form.get('expires_in')
        access_code = request.form.get('access_code')
        surprise_theme = request.form.get('surprise_theme', 'none')
        is_valentine = request.form.get('is_valentine') == 'true'
        if is_valentine and surprise_theme == 'none':
            surprise_theme = 'valentine'
        use_typewriter = request.form.get('use_typewriter') == 'true'
        auto_approve = request.form.get('auto_approve') == 'true'
        if surprise_theme != 'none':
            photo_file = request.files.get('valentine_photo')
            audio_file = request.files.get('valentine_audio')
            has_media = False
            if photo_file and photo_file.filename:
                has_media = True
            if audio_file and audio_file.filename:
                has_media = True
            if has_media and not m.is_premium(user_doc):
                return jsonify({'error': 'Uploading custom photos and music to surprise notes is a Premium feature.', 'upgrade': True}), 403
            if photo_file and photo_file.filename:
                ext = photo_file.filename.rsplit('.', 1)[1].lower() if '.' in photo_file.filename else ''
                if ext in m.ALLOWED_IMAGE_EXTENSIONS:
                    try:
                        upload_result = m.cloudinary.uploader.upload(photo_file, folder="echowithin_valentine")
                        valentine_photo = upload_result.get('secure_url')
                    except Exception as e:
                        current_app.logger.error(f"Valentine photo upload failed: {e}")
            if audio_file and audio_file.filename:
                ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''
                if ext in m.ALLOWED_AUDIO_EXTENSIONS:
                    try:
                        audio_file.seek(0)
                        upload_result = m.cloudinary.uploader.upload(audio_file, resource_type="auto", folder="echowithin_valentine")
                        valentine_audio = upload_result.get('secure_url')
                    except Exception as e:
                        current_app.logger.error(f"Valentine audio upload failed: {e}")
    if permissions not in ['view', 'edit']:
        permissions = 'view'
    access_code_hash = None
    if access_code:
        access_code_hash = m.generate_password_hash(access_code)
    expires_at = None
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_in == '1h':
        expires_at = now + datetime.timedelta(hours=1)
    elif expires_in == '1d':
        expires_at = now + datetime.timedelta(days=1)
    elif expires_in == '7d':
        expires_at = now + datetime.timedelta(days=7)
    share_id = secrets.token_urlsafe(16)
    if surprise_theme != 'none':
        max_surprise = m.get_limit(user_doc, 'max_surprise_notes')
        surprise_count = m.note_shares_conf.count_documents({'owner_id': ObjectId(current_user.id), 'surprise_theme': {'$ne': 'none', '$exists': True}})
        if surprise_count >= max_surprise:
            return jsonify({'error': f'You have reached the limit of {max_surprise} surprise notes.', 'upgrade': True}), 403
    if auto_approve and not m.is_premium(user_doc):
        auto_approve = False
    m.note_shares_conf.insert_one({
        'share_id': share_id, 'note_id': obj_id, 'owner_id': ObjectId(current_user.id),
        'permissions': permissions, 'access_code_hash': access_code_hash,
        'expires_at': expires_at, 'created_at': now, 'surprise_theme': surprise_theme,
        'valentine_photo': m.encrypt_note(valentine_photo, user_id=current_user.id) if valentine_photo else None,
        'valentine_audio': m.encrypt_note(valentine_audio, user_id=current_user.id) if valentine_audio else None,
        'valentine_photo_hash': hashlib.sha256(valentine_photo.encode()).hexdigest() if valentine_photo else None,
        'valentine_audio_hash': hashlib.sha256(valentine_audio.encode()).hexdigest() if valentine_audio else None,
        'use_typewriter': use_typewriter, 'auto_approve': auto_approve
    })
    share_url = url_for('sharing.view_shared_note', share_id=share_id, _external=True)
    return jsonify({'success': True, 'share_url': share_url, 'share_id': share_id})


@bp.route('/share/note/<share_id>', methods=['GET', 'POST'])
@limits(calls=30, period=60)
def view_shared_note(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return render_template('shared_note.html', expired=True), 410
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            m.cleanup_share_media(share)
            m.note_shares_conf.delete_one({'_id': share['_id']})
            return render_template('shared_note.html', expired=True)
    requires_code = bool(share.get('access_code_hash'))
    if requires_code:
        if request.method == 'POST':
            code = request.form.get('access_code')
            if not code or not m.check_password_hash(share['access_code_hash'], code):
                flash('Invalid access code.', 'danger')
                return render_template('shared_note.html', share_id=share_id, requires_code=True)
            session[f'unlocked_{share_id}'] = True
            return redirect(url_for('sharing.view_shared_note', share_id=share_id))
        if not session.get(f'unlocked_{share_id}'):
            return render_template('shared_note.html', share_id=share_id, requires_code=True)
    note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not note:
        return render_template('shared_note.html', expired=True), 410
    note_owner_id = str(share.get('owner_id', note.get('user_id', '')))
    content = m._decrypt_note_record(note, share)
    surprise_theme = share.get('surprise_theme')
    if not surprise_theme:
        surprise_theme = 'valentine' if share.get('is_valentine') else 'none'
    is_owner = current_user.is_authenticated and str(current_user.id) == str(share.get('owner_id', ''))
    if is_owner:
        try:
            m.unlock_notifications_conf.update_many({'share_id': share_id, 'owner_id': share['owner_id'], 'is_read': False}, {'$set': {'is_read': True}})
        except Exception as e:
            current_app.logger.error(f"Failed to mark notifications as read: {e}")
    else:
        try:
            notif_id_key = f'notif_id_{share_id}'
            notif_id = session.get(notif_id_key)
            visitor_name = 'Anonymous visitor'
            visitor_id = None
            if current_user.is_authenticated:
                visitor_id = str(current_user.id)
                fresh_user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'username': 1})
                if fresh_user and fresh_user.get('username'):
                    visitor_name = fresh_user['username']
                else:
                    visitor_name = getattr(current_user, 'username', 'Anonymous visitor')
            if not notif_id:
                res = m.unlock_notifications_conf.insert_one({
                    'share_id': share_id, 'note_id': share['note_id'], 'owner_id': share['owner_id'],
                    'unlocked_by': visitor_id, 'unlocked_by_name': visitor_name,
                    'unlocked_at': datetime.datetime.now(datetime.timezone.utc),
                    'surprise_theme': surprise_theme, 'is_read': False
                })
                session[notif_id_key] = str(res.inserted_id)
            elif current_user.is_authenticated:
                m.unlock_notifications_conf.update_one({'_id': ObjectId(notif_id), 'unlocked_by': None}, {'$set': {'unlocked_by': visitor_id, 'unlocked_by_name': visitor_name}})
                m.unlock_notifications_conf.update_one({'_id': ObjectId(notif_id), 'unlocked_by': visitor_id, 'unlocked_by_name': {'$nin': [visitor_name]}}, {'$set': {'unlocked_by_name': visitor_name}})
                m.unlock_notifications_conf.update_many({'share_id': share_id, 'unlocked_by': visitor_id, 'unlocked_by_name': {'$in': ['Someone', 'Anonymous visitor', 'Unknown', '', None]}}, {'$set': {'unlocked_by_name': visitor_name}})
        except Exception as e:
            current_app.logger.error(f"Failed to handle unlock notification: {e}")
    use_typewriter = share.get('use_typewriter', False)
    already_saved = False
    if current_user.is_authenticated and not is_owner:
        already_saved = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'source_note_id': share['note_id']}) > 0
    has_pending_proposal = False
    if current_user.is_authenticated and not is_owner:
        has_pending_proposal = m.note_versions_conf.count_documents({'note_id': share['note_id'], 'editor_id': ObjectId(current_user.id), 'status': 'pending', 'event_type': 'proposal'}) > 0
    owner_doc = m.users_conf.find_one({'_id': ObjectId(note_owner_id)})
    owner_max_chars = m.get_limit(owner_doc, 'max_chars_per_note')
    raw_attachments = list(m.note_attachments_conf.find({'note_id': note['_id']}).sort('created_at', 1))
    note_attachments_list = []
    for att in raw_attachments:
        decrypted_url = m.decrypt_note(att.get('url'), user_id=note_owner_id)
        if decrypted_url:
            note_attachments_list.append({'id': str(att['_id']), 'file_type': att.get('file_type', 'image'), 'url': decrypted_url, 'filename': att.get('filename', ''), 'uploader_name': att.get('uploader_name', 'Unknown'), 'uploader_id': str(att.get('uploader_id', '')), 'created_at': att.get('created_at', '').isoformat() if isinstance(att.get('created_at'), datetime.datetime) else ''})
    can_upload_media = False
    if current_user.is_authenticated and share['permissions'] == 'edit' and surprise_theme == 'none':
        can_upload_media = current_user.get_limit('note_media_attachments') is True
    return render_template('shared_note.html', share_id=share_id, content=content, permissions=share['permissions'], note_id=str(note['_id']), updated_at=note.get('updated_at'), created_at=note.get('created_at'), is_owner=is_owner, already_saved=already_saved, has_pending_proposal=has_pending_proposal, surprise_theme=surprise_theme, reference=note.get('reference', ''), tags=note.get('tags', []), is_valentine=(surprise_theme != 'none'), valentine_photo=m.decrypt_note(share.get('valentine_photo'), user_id=str(share.get('owner_id', ''))), valentine_audio=m.decrypt_note(share.get('valentine_audio'), user_id=str(share.get('owner_id', ''))), use_typewriter=use_typewriter, owner_max_chars=owner_max_chars, note_attachments=note_attachments_list, can_upload_media=can_upload_media)


@bp.route('/share/note/<share_id>/upload', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_upload_note_attachment(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share or share.get('permissions') != 'edit':
        return jsonify({'error': 'Unauthorized or invalid share'}), 403
    surprise_theme = share.get('surprise_theme', 'none')
    if not surprise_theme:
        surprise_theme = 'valentine' if share.get('is_valentine') else 'none'
    if surprise_theme != 'none':
        return jsonify({'error': 'Attachments not available for surprise notes'}), 400
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file provided'}), 400
    file_type = request.form.get('file_type', 'image')
    filename = file.filename or 'unnamed'
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if file_type == 'image' and ext not in m.ALLOWED_IMAGE_EXTENSIONS + ['webp', 'heic', 'heif']:
        return jsonify({'error': 'Invalid image format'}), 400
    if file_type == 'audio' and ext not in m.ALLOWED_AUDIO_EXTENSIONS:
        return jsonify({'error': 'Invalid audio format'}), 400
    try:
        upload_result = m.cloudinary.uploader.upload(file, resource_type="auto", folder="echowithin_note_attachments")
        raw_url = upload_result.get('secure_url')
        encrypted_url = m.encrypt_note(raw_url, user_id=str(share['owner_id']))
        m.note_attachments_conf.insert_one({
            'note_id': share['note_id'], 'url': encrypted_url,
            'file_type': file_type, 'filename': filename,
            'uploader_id': ObjectId(current_user.id), 'uploader_name': current_user.username,
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })
        return jsonify({'success': True, 'url': raw_url})
    except Exception as e:
        current_app.logger.error(f"Note attachment upload failed: {e}")
        return jsonify({'error': 'Upload failed'}), 500


@bp.route('/share/note/<share_id>/attachments', methods=['GET'])
def api_list_note_attachments(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    raw_attachments = list(m.note_attachments_conf.find({'note_id': share['note_id']}).sort('created_at', 1))
    note_owner_id = str(share.get('owner_id', ''))
    result = []
    for att in raw_attachments:
        decrypted_url = m.decrypt_note(att.get('url'), user_id=note_owner_id)
        if decrypted_url:
            result.append({'id': str(att['_id']), 'file_type': att.get('file_type', 'image'), 'url': decrypted_url, 'filename': att.get('filename', ''), 'uploader_name': att.get('uploader_name', 'Unknown'), 'created_at': att.get('created_at', '').isoformat() if isinstance(att.get('created_at'), datetime.datetime) else ''})
    return jsonify({'attachments': result})


@bp.route('/share/note/<share_id>/attachment/<attachment_id>', methods=['DELETE'])
@login_required
def api_delete_note_attachment(share_id, attachment_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    if str(share.get('owner_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    m.note_attachments_conf.delete_one({'_id': ObjectId(attachment_id)})
    return jsonify({'success': True})


@bp.route('/shared_note/save/<share_id>', methods=['POST'])
@login_required
def api_save_shared_note(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not note:
        return jsonify({'error': 'Original note not found'}), 404
    content = m._decrypt_note_record(note, share)
    encrypted = m.encrypt_note(content)
    existing = m.personal_posts_conf.find_one({'user_id': ObjectId(current_user.id), 'source_note_id': share['note_id']})
    if existing:
        return jsonify({'error': 'Note already saved', 'note_id': str(existing['_id'])}), 409
    saved_note = {
        'user_id': ObjectId(current_user.id), 'title': note.get('title'),
        'content': encrypted, 'source_note_id': share['note_id'],
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc), 'is_locked': False
    }
    result = m.personal_posts_conf.insert_one(saved_note)
    return jsonify({'success': True, 'note_id': str(result.inserted_id)})


@bp.route('/saved_note/view/<note_id>', methods=['GET'])
@login_required
def view_saved_note(note_id):
    import main as m
    saved = m.personal_posts_conf.find_one({'_id': ObjectId(note_id), 'user_id': ObjectId(current_user.id)})
    if not saved:
        abort(404)
    content = m._decrypt_note_record(saved)
    return render_template('view_saved_note.html', content=content, note=saved)


@bp.route('/share/note/<share_id>/edit', methods=['POST'])
@login_required
def api_edit_shared_note(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share or share.get('permissions') != 'edit':
        return jsonify({'error': 'Unauthorized'}), 403
    note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    data = request.get_json() or {}
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Content required'}), 400
    current_content = m._decrypt_note_record(note, share)
    if current_content == new_content:
        return jsonify({'status': 'no_change'})
    note_owner_id = str(share.get('owner_id', ''))
    is_owner = (current_user.is_authenticated and str(current_user.id) == note_owner_id)
    auto_approve = share.get('auto_approve', False)
    editor_is_owner = (str(current_user.id) == note_owner_id)
    if editor_is_owner:
        encrypted = m.encrypt_note(new_content)
        m.personal_posts_conf.update_one({'_id': share['note_id']}, {'$set': {'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
        return jsonify({'status': 'saved', 'is_owner_save': True})
    if auto_approve and m._has_active_auto_approve(share_id, ObjectId(current_user.id)):
        encrypted = m.encrypt_note(new_content)
        m.personal_posts_conf.update_one({'_id': share['note_id']}, {'$set': {'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
        m.note_versions_conf.insert_one({
            'note_id': share['note_id'], 'share_id': share_id,
            'editor_id': ObjectId(current_user.id), 'author_name': current_user.username,
            'content_owner_id': share['owner_id'],
            'event_type': 'snapshot', 'status': 'auto_approved',
            'is_read_by_owner': False, 'is_auto_approved': True,
            'content_snapshot': m.encrypt_note(new_content),
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })
        return jsonify({'status': 'auto_approved'})
    encrypted_new = m.encrypt_note(new_content)
    diff = m.build_unified_diff_text(current_content, new_content)
    m.note_versions_conf.insert_one({
        'note_id': share['note_id'], 'share_id': share_id,
        'editor_id': ObjectId(current_user.id), 'author_name': current_user.username,
        'content_owner_id': share['owner_id'],
        'event_type': 'proposal', 'status': 'pending',
        'is_read_by_owner': False,
        'proposed_content': encrypted_new,
        'diff_text': diff,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })
    return jsonify({'status': 'pending'})


@bp.route('/personal_post/revoke_share/<share_id>', methods=['POST'])
@login_required
def api_revoke_share(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id, 'owner_id': ObjectId(current_user.id)})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    m.cleanup_share_media(share)
    m.note_shares_conf.delete_one({'_id': share['_id']})
    return jsonify({'success': True})


@bp.route('/personal_post/toggle_share_auto_approve/<share_id>', methods=['POST'])
@login_required
def api_toggle_share_auto_approve(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id, 'owner_id': ObjectId(current_user.id)})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    current = share.get('auto_approve', False)
    m.note_shares_conf.update_one({'_id': share['_id']}, {'$set': {'auto_approve': not current}})
    return jsonify({'success': True, 'auto_approve': not current})


@bp.route('/personal_post/shares/<post_id>')
@login_required
def api_get_note_shares(post_id):
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    now = datetime.datetime.now(datetime.timezone.utc)
    shares = []
    for share in m.note_shares_conf.find({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)}).sort('created_at', -1):
        if share.get('expires_at'):
            exp = share['expires_at']
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=datetime.timezone.utc)
            if now > exp:
                continue
        shares.append({'share_id': share['share_id'], 'permissions': share.get('permissions', 'view'), 'surprise_theme': share.get('surprise_theme', 'none'), 'created_at': share['created_at'].isoformat() if share.get('created_at') else None, 'expires_at': share['expires_at'].isoformat() if share.get('expires_at') else None, 'auto_approve': share.get('auto_approve', False)})
    return jsonify({'shares': shares})


@bp.route('/api/share/<share_id>/history')
def api_get_share_history(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    history = list(m.unlock_notifications_conf.find({'share_id': share_id}).sort('unlocked_at', -1).limit(50))
    return jsonify([{'visitor': h.get('unlocked_by_name', 'Anonymous'), 'visited_at': h['unlocked_at'].isoformat() if h.get('unlocked_at') else None} for h in history])


@bp.route('/personal_post/versions/<post_id>')
@login_required
def api_get_note_versions(post_id):
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    versions = list(m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', -1).limit(50))
    return jsonify(versions)


@bp.route('/personal_post/version/restore/<post_id>/<version_id>', methods=['POST'])
@login_required
def api_restore_note_version(post_id, version_id):
    import main as m
    note = m.personal_posts_conf.find_one({'_id': ObjectId(post_id), 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    version = m.note_versions_conf.find_one({'_id': ObjectId(version_id), 'note_id': ObjectId(post_id)})
    if not version:
        return jsonify({'error': 'Version not found'}), 404
    encrypted = m.encrypt_note(version.get('content', ''))
    m.personal_posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    return jsonify({'success': True})


@bp.route('/personal_post/proposal/<version_id>/decision', methods=['POST'])
@login_required
def api_decide_note_proposal(version_id):
    import main as m
    version = m.note_versions_conf.find_one({'_id': ObjectId(version_id)})
    if not version:
        return jsonify({'error': 'Proposal not found'}), 404
    content_owner_id = str(version.get('content_owner_id', ''))
    if content_owner_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    decision = data.get('decision')
    if decision not in ('accept', 'reject'):
        return jsonify({'error': 'Invalid decision'}), 400
    if decision == 'accept':
        proposed = version.get('proposed_content', '')
        encrypted = m.encrypt_note(proposed)
        m.personal_posts_conf.update_one({'_id': version['note_id']}, {'$set': {'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}})
    m.note_versions_conf.update_one({'_id': ObjectId(version_id)}, {'$set': {'status': 'accepted' if decision == 'accept' else 'rejected', 'is_read_by_owner': True}})
    return jsonify({'success': True})


@bp.route('/share/note/<share_id>/comments', methods=['GET'])
def api_get_note_comments(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    comments = list(m.note_discussions_conf.find({'note_id': share['note_id'], 'parent_id': None}).sort('created_at', 1))
    return jsonify([{'id': str(c['_id']), 'author_name': c.get('author_name', 'Anonymous'), 'content': c.get('content', ''), 'created_at': c['created_at'].isoformat() if c.get('created_at') else None} for c in comments])


@bp.route('/share/note/<share_id>/comments', methods=['POST'])
@login_required
def api_post_note_comment(share_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content required'}), 400
    comment = {
        'note_id': share['note_id'], 'share_id': share_id,
        'author_id': ObjectId(current_user.id), 'author_name': current_user.username,
        'content': content, 'parent_id': None,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.note_discussions_conf.insert_one(comment)
    return jsonify({'success': True, 'id': str(result.inserted_id)}), 201


@bp.route('/share/note/<share_id>/comments/<comment_id>/replies', methods=['POST'])
@login_required
def api_post_note_reply(share_id, comment_id):
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404
    parent = m.note_discussions_conf.find_one({'_id': ObjectId(comment_id), 'note_id': share['note_id']})
    if not parent:
        return jsonify({'error': 'Parent comment not found'}), 404
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content required'}), 400
    reply = {
        'note_id': share['note_id'], 'share_id': share_id,
        'author_id': ObjectId(current_user.id), 'author_name': current_user.username,
        'content': content, 'parent_id': ObjectId(comment_id),
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.note_discussions_conf.insert_one(reply)
    return jsonify({'success': True, 'id': str(result.inserted_id)}), 201


@bp.route('/share/note/<share_id>/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_note_comment(share_id, comment_id):
    import main as m
    comment = m.note_discussions_conf.find_one({'_id': ObjectId(comment_id)})
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    if str(comment.get('author_id')) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    m.note_discussions_conf.delete_one({'_id': ObjectId(comment_id)})
    return jsonify({'success': True})
