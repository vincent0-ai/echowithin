from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, hashlib, secrets
from security import limits

bp = Blueprint('sharing', __name__, template_folder='templates')


@bp.route('/api/share/<share_id>/ping', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def ping_collaborators(share_id):
    import main as m
    try:
        share = m.note_shares_conf.find_one({'share_id': share_id})
        if not share:
            return jsonify({'error': 'Share not found'}), 404
        
        # Only owner can ping
        if str(share.get('owner_id')) != current_user.id:
            return jsonify({'error': 'Only the owner can ping collaborators'}), 403
            
        # Check cooldown (1 hour = 3600 seconds)
        cooldown_key = f"ping_cooldown_{share_id}"
        if m.redis_cache:
            if m.redis_cache.get(cooldown_key):
                return jsonify({'error': 'Ping on cooldown. Please wait 1 hour between pings.', 'code': 'cooldown'}), 429
        else:
            # Fallback: check cooldown via session if Redis is unavailable
            last_ping = session.get(cooldown_key)
            if last_ping:
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(last_ping)).total_seconds()
                if elapsed < 3600:
                    return jsonify({'error': 'Ping on cooldown. Please wait 1 hour between pings.', 'code': 'cooldown'}), 429
            
        # Find all users who saved this note
        note_id = share['note_id']
        clones = list(m.personal_posts_conf.find({'source_note_id': note_id}, {'user_id': 1}))
        
        pinged_count = 0
        for clone in clones:
            clone_user_id = str(clone.get('user_id'))
            if clone_user_id != current_user.id:
                share_url = url_for('sharing.view_shared_note', share_id=share_id, _external=True)
                title = "Ping from Note Owner ≡ƒöö"
                body = f"{current_user.username} is reminding you to check the shared note!"
                try:
                    m.send_push_notification_to_user(
                        user_id_str=clone_user_id,
                        title=title,
                        body=body,
                        url=share_url,
                        tag=f"ping_{share_id}",
                        extra_data={'type': 'note_ping', 'share_id': share_id}
                    )
                    pinged_count += 1
                except Exception as notify_err:
                    current_app.logger.error(f"Ping push failed for {clone_user_id}: {notify_err}")
        
        if pinged_count == 0:
            return jsonify({'success': True, 'pinged_count': 0, 'message': 'No collaborators have saved this note yet.'})
                
        # Set cooldown
        if m.redis_cache:
            m.redis_cache.set(cooldown_key, '1', ex=3600)
        else:
            session[cooldown_key] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
        return jsonify({'success': True, 'pinged_count': pinged_count})
        
    except Exception as e:
        current_app.logger.error(f"Error pinging collaborators: {e}")
        return jsonify({'error': 'Something went wrong. Please try again.'}), 500


@bp.route('/personal_post/share/<post_id>', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_create_share(post_id):
    """Generates a share link for a personal note."""
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    # Verify ownership
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    # --- Premium tier enforcement: share link limit ---
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    max_shares = m.get_limit(user_doc, 'max_share_links_per_note')
    active_count = m.note_shares_conf.count_documents({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)})
    if active_count >= max_shares:
        return jsonify({
            'error': f'You have reached the limit of {max_shares} share links per note. Upgrade to Premium for unlimited sharing!',
            'upgrade': True
        }), 403

    # Parse basic share fields — advanced config (surprise theme, media, time capsule)
    # is done via the share settings page after creation.
    if request.is_json:
        data = request.get_json() or {}
        permissions = data.get('permissions', 'view')
        expires_in = data.get('expires_in')
        access_code = data.get('access_code')
        # Backward compat: still accept surprise_theme etc from old clients / API
        surprise_theme = data.get('surprise_theme', 'none')
        use_typewriter = data.get('use_typewriter', False)
        auto_approve = data.get('auto_approve', False)
    else:
        permissions = request.form.get('permissions', 'view')
        expires_in = request.form.get('expires_in')
        access_code = request.form.get('access_code')
        surprise_theme = request.form.get('surprise_theme', 'none')
        use_typewriter = request.form.get('use_typewriter') == 'true'
        auto_approve = request.form.get('auto_approve') == 'true'

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

    # --- Premium tier enforcement: surprise note limit ---
    if surprise_theme != 'none':
        max_surprise = m.get_limit(user_doc, 'max_surprise_notes')
        surprise_count = m.note_shares_conf.count_documents({
            'owner_id': ObjectId(current_user.id),
            'surprise_theme': {'$ne': 'none', '$exists': True}
        })
        if surprise_count >= max_surprise:
            return jsonify({
                'error': f'You have reached the limit of {max_surprise} surprise notes. Upgrade to Premium for unlimited surprises!',
                'upgrade': True
            }), 403

    # --- Premium tier enforcement: auto-approve requires premium ---
    if auto_approve and not m.is_premium(user_doc):
        auto_approve = False

    m.note_shares_conf.insert_one({
        'share_id': share_id,
        'note_id': obj_id,
        'owner_id': ObjectId(current_user.id),
        'permissions': permissions,
        'access_code_hash': access_code_hash,
        'expires_at': expires_at,
        'created_at': now,
        'surprise_theme': surprise_theme,
        'valentine_photo': None,
        'valentine_audio': None,
        'valentine_photo_hash': None,
        'valentine_audio_hash': None,
        'use_typewriter': use_typewriter,
        'auto_approve': auto_approve,
        'unlock_date': None
    })

    share_url = url_for('sharing.view_shared_note', share_id=share_id, _external=True)
    return jsonify({
        'success': True,
        'share_url': share_url,
        'share_id': share_id
    })


@bp.route('/share/note/<share_id>', methods=['GET', 'POST'])
@limits(calls=30, period=60)
def view_shared_note(share_id):
    """Public route to view or edit a shared note."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        # Revoked/deleted shares are removed from DB; show dedicated link-unavailable state
        # instead of the generic site-wide 404 page.
        return render_template('shared_note.html', expired=True), 410

    # Check expiration
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            # Cleanup media before deleting share record
            m.cleanup_share_media(share)
            m.note_shares_conf.delete_one({'_id': share['_id']})
            return render_template('shared_note.html', expired=True)

    # Check if link was deactivated (e.g., free-tier content-change limit exceeded)
    if share.get('deactivated'):
        return render_template('shared_note.html', expired=True), 410

    # Check access code
    requires_code = bool(share.get('access_code_hash'))
    if requires_code:
        if request.method == 'POST':
            code = request.form.get('access_code')
            if not code or not m.check_password_hash(share['access_code_hash'], code):
                flash('Invalid access code.', 'danger')
                return render_template('shared_note.html', share_id=share_id, requires_code=True)
            # Store in session that this share is unlocked
            session[f'unlocked_{share_id}'] = True
            return redirect(url_for('sharing.view_shared_note', share_id=share_id))
        
        if not session.get(f'unlocked_{share_id}'):
            return render_template('shared_note.html', share_id=share_id, requires_code=True)

    # Check Time Capsule unlock date
    unlock_date = share.get('unlock_date')
    is_owner = current_user.is_authenticated and str(current_user.id) == str(share.get('owner_id', ''))
    if unlock_date:
        if unlock_date.tzinfo is None:
            unlock_date = unlock_date.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) < unlock_date and not is_owner:
            surprise_theme = share.get('surprise_theme')
            if not surprise_theme:
                surprise_theme = 'valentine' if share.get('is_valentine') else 'none'
            return render_template('shared_note.html',
                                   share_id=share_id,
                                   capsule_locked=True,
                                   unlock_date=unlock_date.isoformat(),
                                   surprise_theme=surprise_theme,
                                   is_owner=False)

    # Fetch the note
    note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not note:
        # Original note may have been deleted after sharing; treat link as unavailable.
        return render_template('shared_note.html', expired=True), 410

    # Decrypt note content (note belongs to the share owner)
    note_owner_id = str(share.get('owner_id', note.get('user_id', '')))
    content = m._decrypt_note_record(note, share)
    
    # Determine surprise theme (with compatibility for old is_valentine flag)
    surprise_theme = share.get('surprise_theme')
    if not surprise_theme:
        surprise_theme = 'valentine' if share.get('is_valentine') else 'none'
    
    # Record unlock notification for surprise notes (once per session)
    is_owner = current_user.is_authenticated and str(current_user.id) == str(share.get('owner_id', ''))
    
    if is_owner:
        # Mark all unread notifications for this share as read when owner views it
        try:
            m.unlock_notifications_conf.update_many(
                {'share_id': share_id, 'owner_id': share['owner_id'], 'is_read': False},
                {'$set': {'is_read': True}}
            )
        except Exception as e:
            current_app.logger.error(f"Failed to mark notifications as read: {e}")
    else:
        # Record access history for ALL shared notes (standard and surprises)
        try:
            notif_id_key = f'notif_id_{share_id}'
            notif_id = session.get(notif_id_key)
            
            visitor_name = 'Anonymous visitor'
            visitor_id = None
            if current_user.is_authenticated:
                visitor_id = str(current_user.id)
                # Always fetch fresh username from DB to avoid stale cached values
                fresh_user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'username': 1})
                if fresh_user and fresh_user.get('username'):
                    visitor_name = fresh_user['username']
                else:
                    visitor_name = getattr(current_user, 'username', 'Anonymous visitor')
            
            if not notif_id:
                # First time in session: Record notification
                res = m.unlock_notifications_conf.insert_one({
                    'share_id': share_id,
                    'note_id': share['note_id'],
                    'owner_id': share['owner_id'],
                    'unlocked_by': visitor_id,
                    'unlocked_by_name': visitor_name,
                    'unlocked_at': datetime.datetime.now(datetime.timezone.utc),
                    'surprise_theme': surprise_theme,
                    'is_read': False
                })
                # PRIVACY: share_id IS the secret link — never log it in plaintext.
                # Use a short, non-reversible fingerprint for log correlation instead.
                share_fp = hashlib.sha256(share_id.encode('utf-8')).hexdigest()[:10]
                current_app.logger.info(f"Recorded access history for share fp={share_fp} by {visitor_name}")
                session[notif_id_key] = str(res.inserted_id)
                session[f'notified_{share_id}'] = True # Backward compatibility
            elif current_user.is_authenticated:
                # Promotion logic: Update this notification if it was recorded anonymously
                m.unlock_notifications_conf.update_one(
                    {'_id': ObjectId(notif_id), 'unlocked_by': None},
                    {'$set': {'unlocked_by': visitor_id, 'unlocked_by_name': visitor_name}}
                )
                # Also update name on this notification if it was recorded with a stale/generic name
                m.unlock_notifications_conf.update_one(
                    {'_id': ObjectId(notif_id), 'unlocked_by': visitor_id, 'unlocked_by_name': {'$nin': [visitor_name]}},
                    {'$set': {'unlocked_by_name': visitor_name}}
                )
                # Fix any OTHER old records from this user on this share that have generic names
                m.unlock_notifications_conf.update_many(
                    {
                        'share_id': share_id,
                        'unlocked_by': visitor_id,
                        'unlocked_by_name': {'$in': ['Someone', 'Anonymous visitor', 'Unknown', '', None]}
                    },
                    {'$set': {'unlocked_by_name': visitor_name}}
                )
        except Exception as e:
            current_app.logger.error(f"Failed to handle unlock notification: {e}")
    
    use_typewriter = share.get('use_typewriter', False)

    # Check if current user already saved this note
    already_saved = False
    if current_user.is_authenticated and not is_owner:
        already_saved = m.personal_posts_conf.count_documents({
            'user_id': ObjectId(current_user.id),
            'source_note_id': share['note_id']
        }) > 0

    # Check if there is a pending proposal by this user for this note
    has_pending_proposal = False
    if current_user.is_authenticated and not is_owner:
        has_pending_proposal = m.note_versions_conf.count_documents({
            'note_id': share['note_id'],
            'editor_id': ObjectId(current_user.id),
            'status': 'pending',
            'event_type': 'proposal'
        }) > 0

    owner_doc = m.users_conf.find_one({'_id': ObjectId(note_owner_id)})
    owner_max_chars = m.get_limit(owner_doc, 'max_chars_per_note')

    # --- Note Attachments (images & voice notes) ---
    raw_attachments = list(m.note_attachments_conf.find({'note_id': note['_id']}).sort('created_at', 1))
    note_attachments_list = []
    for att in raw_attachments:
        decrypted_url = m.decrypt_note(att.get('url'), user_id=note_owner_id)
        if decrypted_url:
            note_attachments_list.append({
                'id': str(att['_id']),
                'file_type': att.get('file_type', 'image'),
                'url': decrypted_url,
                'filename': att.get('filename', ''),
                'uploader_name': att.get('uploader_name', 'Unknown'),
                'uploader_id': str(att.get('uploader_id', '')),
                'created_at': att.get('created_at', '').isoformat() if isinstance(att.get('created_at'), datetime.datetime) else ''
            })

    # Determine if current user can upload media (premium + edit permission)
    can_upload_media = False
    if current_user.is_authenticated and share['permissions'] == 'edit' and surprise_theme == 'none':
        can_upload_media = current_user.get_limit('note_media_attachments') is True

    return render_template('shared_note.html', 
                           share_id=share_id, 
                           content=content, 
                           permissions=share['permissions'],
                           note_id=str(note['_id']),
                           updated_at=note.get('updated_at'),
                           created_at=note.get('created_at'),
                           is_owner=is_owner,
                           already_saved=already_saved,
                           has_pending_proposal=has_pending_proposal,
                           surprise_theme=surprise_theme,
                           reference=note.get('reference', ''),
                           tags=note.get('tags', []),
                           is_valentine=(surprise_theme != 'none'),
                           valentine_photo=m.decrypt_note(share.get('valentine_photo'), user_id=str(share.get('owner_id', ''))),
                           valentine_audio=m.decrypt_note(share.get('valentine_audio'), user_id=str(share.get('owner_id', ''))),
                           use_typewriter=use_typewriter,
                           owner_max_chars=owner_max_chars,
                           note_attachments=note_attachments_list,
                           can_upload_media=can_upload_media)


# --- Note Attachment APIs (images & voice notes on collaborative notes) ---


@bp.route('/share/note/<share_id>/upload', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_upload_note_attachment(share_id):
    """Upload an image or voice note to a shared collaborative note (premium only)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share or share.get('permissions') != 'edit':
        return jsonify({'error': 'Unauthorized or invalid share'}), 403

    # Check surprise theme ΓÇö attachments only for collaborative notes, not surprises
    surprise_theme = share.get('surprise_theme', 'none')
    if not surprise_theme:
        surprise_theme = 'valentine' if share.get('is_valentine') else 'none'
    if surprise_theme != 'none':
        return jsonify({'error': 'Attachments not available for surprise notes'}), 400

    # Check expiration
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            return jsonify({'error': 'Link expired'}), 410

    # Check access code session
    if share.get('access_code_hash') and not session.get(f'unlocked_{share_id}'):
        return jsonify({'error': 'Access code required'}), 401

    # Premium gate
    if not current_user.get_limit('note_media_attachments'):
        return jsonify({'error': 'Note media attachments require Premium', 'upgrade': True}), 403

    # Check per-note attachment limit
    note_id = share['note_id']
    max_attachments = current_user.get_limit('max_note_attachments') or 20
    existing_count = m.note_attachments_conf.count_documents({'note_id': note_id})
    if existing_count >= max_attachments:
        return jsonify({'error': f'Maximum {max_attachments} attachments per note reached'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'Empty file'}), 400

    # Determine file type
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext in m.ALLOWED_IMAGE_EXTENSIONS:
        file_type = 'image'
        max_size = m.MAX_IMAGE_SIZE  # 5 MB
    elif ext in m.ALLOWED_AUDIO_EXTENSIONS:
        file_type = 'audio'
        max_size = 10 * 1024 * 1024  # 10 MB for audio
    else:
        return jsonify({'error': f'Unsupported file type. Allowed: {", ".join(m.ALLOWED_IMAGE_EXTENSIONS | m.ALLOWED_AUDIO_EXTENSIONS)}'}), 400

    # Check file size
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > max_size:
            limit_mb = max_size // (1024 * 1024)
            return jsonify({'error': f'File exceeds {limit_mb}MB limit'}), 400
    except Exception:
        size = 0

    # Upload to Cloudinary
    try:
        resource_type = 'auto' if file_type == 'audio' else 'image'
        upload_opts = {'folder': 'echowithin_note_media', 'resource_type': resource_type}
        if file_type == 'image':
            upload_opts['transformation'] = [
                {'width': 1600, 'height': 1600, 'crop': 'limit'},
                {'quality': 'auto', 'fetch_format': 'auto'}
            ]
        upload_result = m.cloudinary.uploader.upload(file, **upload_opts)
        plaintext_url = upload_result.get('secure_url')
        public_id = upload_result.get('public_id')
    except Exception as e:
        current_app.logger.error(f"Note attachment upload failed: {e}")
        return jsonify({'error': 'Failed to upload file'}), 500

    # Encrypt URL with note owner's key
    owner_id_str = str(share.get('owner_id', ''))
    encrypted_url = m.encrypt_note(plaintext_url, user_id=owner_id_str) if owner_id_str else plaintext_url
    url_hash = hashlib.sha256(plaintext_url.encode()).hexdigest() if plaintext_url else None

    now = datetime.datetime.now(datetime.timezone.utc)
    sanitized_filename = m.bleach.clean(file.filename[:120], strip=True)
    doc = {
        'note_id': note_id,
        'share_id': share_id,
        'uploader_id': ObjectId(current_user.id),
        'uploader_name': current_user.username,
        'file_type': file_type,
        'url': encrypted_url,
        'url_hash': url_hash,
        'public_id': public_id,
        'filename': sanitized_filename,
        'size_bytes': size,
        'created_at': now
    }
    result = m.note_attachments_conf.insert_one(doc)

    return jsonify({
        'success': True,
        'attachment': {
            'id': str(result.inserted_id),
            'file_type': file_type,
            'url': plaintext_url,
            'filename': sanitized_filename,
            'uploader_name': current_user.username,
            'uploader_id': str(current_user.id),
            'created_at': now.isoformat()
        }
    })


@bp.route('/share/note/<share_id>/attachments', methods=['GET'])
@limits(calls=30, period=60)
def api_list_note_attachments(share_id):
    """List all attachments for a shared note (available to anyone with access)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404

    # Check expiration
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            return jsonify({'error': 'Link expired'}), 410

    # Check access code session
    if share.get('access_code_hash') and not session.get(f'unlocked_{share_id}'):
        return jsonify({'error': 'Access code required'}), 401

    owner_id_str = str(share.get('owner_id', ''))
    raw_attachments = list(m.note_attachments_conf.find({'note_id': share['note_id']}).sort('created_at', 1))
    attachments = []
    for att in raw_attachments:
        decrypted_url = m.decrypt_note(att.get('url'), user_id=owner_id_str)
        if decrypted_url:
            attachments.append({
                'id': str(att['_id']),
                'file_type': att.get('file_type', 'image'),
                'url': decrypted_url,
                'filename': att.get('filename', ''),
                'uploader_name': att.get('uploader_name', 'Unknown'),
                'uploader_id': str(att.get('uploader_id', '')),
                'created_at': att.get('created_at', '').isoformat() if isinstance(att.get('created_at'), datetime.datetime) else ''
            })

    return jsonify({'attachments': attachments})


@bp.route('/share/note/<share_id>/attachment/<attachment_id>', methods=['DELETE'])
@login_required
@limits(calls=10, period=60)
def api_delete_note_attachment(share_id, attachment_id):
    """Delete an attachment from a shared note (owner or uploader only)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404

    obj_id = m.safe_object_id(attachment_id)
    if not obj_id:
        return jsonify({'error': 'Invalid attachment ID'}), 400

    att = m.note_attachments_conf.find_one({'_id': obj_id, 'note_id': share['note_id']})
    if not att:
        return jsonify({'error': 'Attachment not found'}), 404

    # Only note owner or original uploader can delete
    is_owner = str(current_user.id) == str(share.get('owner_id', ''))
    is_uploader = str(current_user.id) == str(att.get('uploader_id', ''))
    if not is_owner and not is_uploader:
        return jsonify({'error': 'Only the note owner or uploader can delete this'}), 403

    # Delete from Cloudinary
    if att.get('public_id'):
        try:
            res_type = 'video' if att.get('file_type') == 'audio' else 'image'
            m.cloudinary.uploader.destroy(att['public_id'], resource_type=res_type)
        except Exception as e:
            current_app.logger.error(f"Failed to delete note attachment from Cloudinary: {e}")

    m.note_attachments_conf.delete_one({'_id': obj_id})
    return jsonify({'success': True})


@bp.route('/shared_note/save/<share_id>', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_save_shared_note(share_id):
    """Clones a shared note into the current user's personal space."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share link not found'}), 404

    # Check expiration
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            return jsonify({'error': 'Link expired'}), 410

    # Check access code session
    if share.get('access_code_hash') and not session.get(f'unlocked_{share_id}'):
        return jsonify({'error': 'Access code required'}), 401

    # Fetch the original note
    original_note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not original_note:
        return jsonify({'error': 'Original note not found'}), 404

    # Prevent duplicate saves ΓÇö check if user already has a clone
    existing_clone = m.personal_posts_conf.find_one({
        'user_id': ObjectId(current_user.id),
        'source_note_id': share['note_id']
    })
    if existing_clone:
        return jsonify({'error': 'You already have this note saved', 'already_saved': True}), 409

    # Clone the note for the current user
    # Note: We track source_note_id to allow original owners to "Delete for Everyone"
    # Re-encrypt with the cloning user's per-user key for data sovereignty
    original_owner_id = str(share.get('owner_id', original_note.get('user_id', '')))
    plaintext = m._decrypt_note_record(original_note, share)
    cloned_encrypted = m.encrypt_note(plaintext, user_id=current_user.id)
    m.personal_posts_conf.insert_one({
        'user_id': ObjectId(current_user.id),
        'content_owner_id': ObjectId(current_user.id),
        'content': cloned_encrypted,
        'encrypted': True,
        'reference': original_note.get('reference', ''),
        'tags': original_note.get('tags', []),
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'source_note_id': share['note_id'],
        'source_share_id': share_id,
        'surprise_theme': share.get('surprise_theme', 'none'),
        'valentine_photo': m.encrypt_note(m.decrypt_note(share.get('valentine_photo'), user_id=str(share.get('owner_id', ''))), user_id=current_user.id) if share.get('valentine_photo') else None,
        'valentine_audio': m.encrypt_note(m.decrypt_note(share.get('valentine_audio'), user_id=str(share.get('owner_id', ''))), user_id=current_user.id) if share.get('valentine_audio') else None,
        'valentine_photo_hash': share.get('valentine_photo_hash'),
        'valentine_audio_hash': share.get('valentine_audio_hash'),
        'use_typewriter': share.get('use_typewriter', False),
        'permissions': share.get('permissions', 'view')
    })

    return jsonify({'success': True, 'message': 'Note saved to your personal space!'})


@bp.route('/saved_note/view/<note_id>', methods=['GET'])
@login_required
@limits(calls=30, period=60)
def view_saved_note(note_id):
    """View a cloned note with its thematic metadata (read-only surprise view)."""
    import main as m
    obj_id = m.safe_object_id(note_id)
    if not obj_id:
        abort(404)
        
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        abort(404)

    content = m._decrypt_note_record(note)
    surprise_theme = note.get('surprise_theme', 'none')
    
    # We render this as a read-only instance of shared_note.html
    return render_template('shared_note.html', 
                           share_id='local', 
                           content=content, 
                           permissions='view', # Cloned surprises are always view-only
                           note_id=str(note['_id']),
                           updated_at=note.get('updated_at'),
                           created_at=note.get('created_at'),
                           is_owner=False,
                           already_saved=True,
                           surprise_theme=surprise_theme,
                           reference=note.get('reference', ''),
                           tags=note.get('tags', []),
                           is_valentine=(surprise_theme != 'none'),
                           valentine_photo=m.decrypt_note(note.get('valentine_photo'), user_id=str(note.get('user_id', ''))),
                           valentine_audio=m.decrypt_note(note.get('valentine_audio'), user_id=str(note.get('user_id', ''))),
                           use_typewriter=note.get('use_typewriter', False),
                           note_attachments=[],
                           can_upload_media=False)


# --- WebSocket Real-time collaboration ---


@bp.route('/share/note/<share_id>/edit', methods=['POST'])
@limits(calls=10, period=60)
def api_edit_shared_note(share_id):
    """Handles shared-note edits with owner review for contributor changes."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share or share['permissions'] != 'edit':
        return jsonify({'error': 'Unauthorized or invalid share'}), 403

    # Authentication is no longer strictly required for proposals, 
    # but guests are always forced into the proposal flow.
    pass

    # Check access code session
    if share.get('access_code_hash') and not session.get(f'unlocked_{share_id}'):
        return jsonify({'error': 'Access code required'}), 401

    # Check expiration
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            return jsonify({'error': 'Link expired'}), 410

    data = request.get_json() or {}
    content = data.get('content')
    edit_summary = (data.get('edit_summary') or '').strip()[:180]
    base_updated_at = m.parse_iso_utc(data.get('base_updated_at'))
    force_apply = bool(data.get('force_apply', False))
    if not content or not content.strip():
        return jsonify({'error': 'Content cannot be empty'}), 400

    owner_id_str = str(share.get('owner_id', ''))
    owner_doc = m.users_conf.find_one({'_id': ObjectId(owner_id_str)})
    max_chars = m.get_limit(owner_doc, 'max_chars_per_note')
    content = content.strip()[:max_chars]

    # Load current note state once for conflict checks/proposals.
    note = m.personal_posts_conf.find_one({'_id': share['note_id']})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    is_owner = current_user.is_authenticated and str(current_user.id) == owner_id_str
    note_updated_at = note.get('updated_at') or note.get('created_at')
    if isinstance(note_updated_at, datetime.datetime) and note_updated_at.tzinfo is None:
        note_updated_at = note_updated_at.replace(tzinfo=datetime.timezone.utc)

    # Encrypt using the note owner's key
    encrypted_content = m.encrypt_note(content, user_id=owner_id_str if owner_id_str else None)

    # Contributor flow: create a pending proposal from the contributor for owner approval.
    # Guests and non-owners without auto-approval ALWAYS create proposals.
    is_user_auto_approved = current_user.is_authenticated and ObjectId(current_user.id) in share.get('auto_approved_users', [])
    can_auto_approve = current_user.is_authenticated and (share.get('auto_approve', False) or is_user_auto_approved)
    
    if not is_owner and not can_auto_approve:
        editor_name = 'Guest'
        editor_id = None
        if current_user.is_authenticated:
            editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)
            editor_id = ObjectId(current_user.id)

        m.note_versions_conf.insert_one({
            'note_id': share['note_id'],
            'share_id': share_id,
            'editor_name': editor_name,
            'editor_id': editor_id,
            'content': note.get('content', ''),
            'base_content': note.get('content', ''),
            'content_owner_id': note.get('content_owner_id', share.get('owner_id')),
            'proposed_content': encrypted_content,
            'encrypted': True,
            'event_type': 'proposal',
            'status': 'pending',
            'edit_summary': edit_summary or 'Proposed changes',
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'is_read_by_owner': False
        })

        # Soft notify owner sessions.
        try:
            m.socketio.emit('note_proposal_created', {
                'share_id': share_id,
                'note_id': str(share['note_id']),
                'editor_name': editor_name,
                'summary': edit_summary or 'Proposed changes'
            }, room=owner_id_str)
        except Exception:
            pass

        # Push notification for owner devices (PWA + native app)
        try:
            if owner_id_str:
                m.send_push_notification_to_user(
                    owner_id_str,
                    f"{editor_name} proposed note changes",
                    (edit_summary or 'A collaborator submitted updates for your review.')[:120],
                    url=url_for('notes.personal_space', _external=True) + '#activity',
                    tag=f'note-proposal-{share["note_id"]}',
                    extra_data={'type': 'note_proposal', 'note_id': str(share['note_id']), 'share_id': share_id}
                )
        except Exception as notify_err:
            current_app.logger.error(f"Failed to send proposal push notification to owner {owner_id_str}: {notify_err}")

        return jsonify({
            'success': True,
            'pending_approval': True,
            'message': 'Changes submitted. The note owner will review and accept/reject them.'
        })

    # Owner flow: conflict-aware apply.
    if base_updated_at and note_updated_at and (note_updated_at > base_updated_at) and not force_apply:
        current_plain = m._decrypt_note_record(note, share)
        return jsonify({
            'error': 'conflict',
            'message': 'This note changed since you opened it. Review and merge before saving.',
            'current_content': current_plain,
            'incoming_content': content,
            'merge_preview': m.build_merge_preview_text(current_plain, content),
            'diff_text': m.build_unified_diff_text(current_plain, content),
            'current_updated_at': note_updated_at.isoformat() if isinstance(note_updated_at, datetime.datetime) else None
        }), 409

    # --- Version Control: snapshot previous content before overwriting ---
    if note and note.get('content'):
        editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)
        editor_id = ObjectId(current_user.id)

        m.note_versions_conf.insert_one({
            'note_id': share['note_id'],
            'share_id': share_id,
            'editor_name': editor_name,
            'editor_id': editor_id,
            'content': note['content'],  # previous encrypted content
            'content_owner_id': note.get('content_owner_id', share.get('owner_id')),
            'encrypted': note.get('encrypted', True),
            'event_type': 'snapshot',
            'status': 'applied',
            'edit_summary': edit_summary or 'Edited via share link',
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'is_read_by_owner': False if not is_owner else True,
            'is_auto_approved': True if not is_owner else False
        })
        
        # Notify owner of auto-approval
        if not is_owner:
            try:
                m.socketio.emit('note_auto_approved', {
                    'share_id': share_id,
                    'note_id': str(share['note_id']),
                    'editor_name': editor_name,
                    'summary': edit_summary or 'Auto-approved edit'
                }, room=owner_id_str)
                
                if owner_id_str:
                    m.send_push_notification_to_user(
                        owner_id_str,
                        f"{editor_name} updated your note",
                        (edit_summary or 'A trusted collaborator applied changes to your note.')[:120],
                        url=url_for('notes.personal_space', _external=True) + '#activity',
                        tag=f'note-auto-{share["note_id"]}',
                        extra_data={'type': 'note_auto_approved', 'note_id': str(share['note_id'])}
                    )
            except Exception as notify_err:
                current_app.logger.error(f"Failed to send auto-approve notifications: {notify_err}")

        # Cap at 50 versions per note
        version_count = m.note_versions_conf.count_documents({'note_id': share['note_id']})
        if version_count > 50:
            oldest = m.note_versions_conf.find({'note_id': share['note_id']}).sort('created_at', 1).limit(version_count - 50)
            for old_ver in oldest:
                m.note_versions_conf.delete_one({'_id': old_ver['_id']})

    now = datetime.datetime.now(datetime.timezone.utc)
    m.personal_posts_conf.update_one(
        {'_id': share['note_id']},
        {'$set': {
            'content': encrypted_content,
            'encrypted': True,
            'content_owner_id': ObjectId(owner_id_str) if owner_id_str else share.get('owner_id'),
            'updated_at': now
        }}
    )

    try:
        m.socketio.emit('note_changed', {'content': content, 'updated_at': now.isoformat()}, room=share_id)
    except Exception:
        pass

    return jsonify({'success': True, 'pending_approval': False, 'updated_at': now.isoformat()})


@bp.route('/personal_post/revoke_share/<share_id>', methods=['POST'])
@login_required
def api_revoke_share(share_id):
    """Revokes a share link."""
    import main as m
    share = m.note_shares_conf.find_one({
        'share_id': share_id,
        'owner_id': ObjectId(current_user.id)
    })
    if share:
        # Cleanup media before deleting share record
        m.cleanup_share_media(share)
        m.note_shares_conf.delete_one({'_id': share['_id']})
        return jsonify({'success': True})
    return jsonify({'error': 'Share link not found or unauthorized'}), 404


@bp.route('/personal_post/toggle_share_auto_approve/<share_id>', methods=['POST'])
@login_required
def api_toggle_share_auto_approve(share_id):
    """Toggles or sets the auto_approve flag for a share link."""
    import main as m
    share = m.note_shares_conf.find_one({
        'share_id': share_id,
        'owner_id': ObjectId(current_user.id)
    })
    if not share:
        return jsonify({'error': 'Share link not found or unauthorized'}), 404
    
    data = request.get_json() or {}
    new_status = bool(data.get('auto_approve', False))
    editor_id = data.get('editor_id')
    
    # Premium tier enforcement: auto-approve requires premium
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    if new_status and not m.is_premium(user_doc):
        return jsonify({'error': 'Auto-approve requires a Premium subscription.', 'upgrade_required': True}), 403

    if editor_id:
        # Toggle auto-approve for a specific collaborator
        if new_status:
            m.note_shares_conf.update_one(
                {'_id': share['_id']},
                {'$addToSet': {'auto_approved_users': ObjectId(editor_id)}}
            )
        else:
            m.note_shares_conf.update_one(
                {'_id': share['_id']},
                {'$pull': {'auto_approved_users': ObjectId(editor_id)}}
            )
    else:
        # Toggle link-wide auto-approve
        m.note_shares_conf.update_one(
            {'_id': share['_id']},
            {'$set': {'auto_approve': new_status}}
        )
    return jsonify({'success': True, 'auto_approve': new_status})


@bp.route('/personal_post/shares/<post_id>')
@login_required
def api_get_note_shares(post_id):
    """Returns all active share links for a note."""
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify([])
    
    shares = list(m.note_shares_conf.find({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)}))
    result = []
    for s in shares:
        result.append({
            '_id': str(s['_id']),
            'share_id': s.get('share_id', ''),
            'note_id': str(s.get('note_id', '')),
            'owner_id': str(s.get('owner_id', '')),
            'permissions': s.get('permissions', 'view'),
            'url': url_for('sharing.view_shared_note', share_id=s.get('share_id', ''), _external=True),
            'expires_at': s['expires_at'].isoformat() if s.get('expires_at') else None,
            'created_at': s['created_at'].isoformat() if s.get('created_at') else None,
            'surprise_theme': s.get('surprise_theme', 'none'),
            'unlock_date': s['unlock_date'].isoformat() if s.get('unlock_date') else None,
        })
    
    return jsonify(result)


@bp.route('/share/settings/<share_id>', methods=['GET'])
@login_required
def share_settings_page(share_id):
    """Full-page settings for a share link (owner only)."""
    import main as m
    share = m.note_shares_conf.find_one({
        'share_id': share_id,
        'owner_id': ObjectId(current_user.id)
    })
    if not share:
        flash('Share link not found or unauthorized.', 'danger')
        return redirect(url_for('notes.personal_space'))

    # Decrypt media URLs for display
    valentine_photo = None
    valentine_audio = None
    if share.get('valentine_photo'):
        try:
            valentine_photo = m.decrypt_note(share['valentine_photo'], user_id=current_user.id)
        except Exception:
            pass
    if share.get('valentine_audio'):
        try:
            valentine_audio = m.decrypt_note(share['valentine_audio'], user_id=current_user.id)
        except Exception:
            pass

    share_url = url_for('sharing.view_shared_note', share_id=share_id, _external=True)

    # Send the UTC ISO string to the template; JS will convert to local
    # for the datetime-local input and convert back to UTC on submit.
    unlock_date_str = ''
    if share.get('unlock_date'):
        ud = share['unlock_date']
        if ud.tzinfo is None:
            ud = ud.replace(tzinfo=datetime.timezone.utc)
        unlock_date_str = ud.isoformat()

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    user_is_premium = m.is_premium(user_doc)

    return render_template('share_settings.html',
                           share=share,
                           share_url=share_url,
                           valentine_photo=valentine_photo,
                           valentine_audio=valentine_audio,
                           unlock_date_str=unlock_date_str,
                           user_is_premium=user_is_premium)


@bp.route('/api/share/<share_id>/settings', methods=['POST'])
@login_required
def api_update_share_settings(share_id):
    """Update advanced share settings (surprise theme, media, time capsule, etc.)."""
    import main as m
    share = m.note_shares_conf.find_one({
        'share_id': share_id,
        'owner_id': ObjectId(current_user.id)
    })
    if not share:
        flash('Share link not found or unauthorized.', 'danger')
        return redirect(url_for('notes.personal_space'))

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    update_fields = {}

    # Surprise theme
    surprise_theme = request.form.get('surprise_theme', share.get('surprise_theme', 'none'))
    if surprise_theme != share.get('surprise_theme', 'none'):
        # Premium limit check when setting a surprise theme
        if surprise_theme != 'none':
            max_surprise = m.get_limit(user_doc, 'max_surprise_notes')
            surprise_count = m.note_shares_conf.count_documents({
                'owner_id': ObjectId(current_user.id),
                'surprise_theme': {'$ne': 'none', '$exists': True},
                '_id': {'$ne': share['_id']}  # exclude current share
            })
            if surprise_count >= max_surprise:
                flash(f'Surprise note limit ({max_surprise}) reached. Upgrade to Premium for unlimited.', 'warning')
                return redirect(url_for('sharing.share_settings_page', share_id=share_id))
    update_fields['surprise_theme'] = surprise_theme

    # Typewriter
    update_fields['use_typewriter'] = request.form.get('use_typewriter') == 'true'

    # Auto-approve
    auto_approve = request.form.get('auto_approve') == 'true'
    if auto_approve and not m.is_premium(user_doc):
        auto_approve = False
    update_fields['auto_approve'] = auto_approve

    # Time Capsule unlock date — the frontend sends a UTC ISO string
    # (converted from the user's local datetime-local input via JS).
    unlock_date_str = request.form.get('unlock_date_utc', '').strip()
    if not unlock_date_str:
        # Fallback: try the raw datetime-local field (old clients / no-JS)
        unlock_date_str = request.form.get('unlock_date', '').strip()
    if unlock_date_str:
        try:
            unlock_date = datetime.datetime.fromisoformat(unlock_date_str)
            if unlock_date.tzinfo is None:
                # Treat naive datetimes as UTC (legacy fallback)
                unlock_date = unlock_date.replace(tzinfo=datetime.timezone.utc)
            else:
                # Convert any tz-aware datetime to UTC for storage
                unlock_date = unlock_date.astimezone(datetime.timezone.utc)
            update_fields['unlock_date'] = unlock_date
        except (ValueError, TypeError):
            flash('Invalid unlock date format.', 'danger')
            return redirect(url_for('sharing.share_settings_page', share_id=share_id))
    else:
        update_fields['unlock_date'] = None

    # Handle media uploads (premium gated)
    if surprise_theme != 'none':
        photo_file = request.files.get('valentine_photo')
        audio_file = request.files.get('valentine_audio')

        has_media = bool((photo_file and photo_file.filename) or (audio_file and audio_file.filename))
        if has_media and not m.is_premium(user_doc):
            flash('Uploading photos and music is a Premium feature.', 'warning')
        else:
            if photo_file and photo_file.filename:
                ext = photo_file.filename.rsplit('.', 1)[1].lower() if '.' in photo_file.filename else ''
                if ext in m.ALLOWED_IMAGE_EXTENSIONS:
                    try:
                        upload_result = m.cloudinary.uploader.upload(photo_file, folder="echowithin_valentine")
                        photo_url = upload_result.get('secure_url')
                        update_fields['valentine_photo'] = m.encrypt_note(photo_url, user_id=current_user.id)
                        update_fields['valentine_photo_hash'] = hashlib.sha256(photo_url.encode()).hexdigest()
                    except Exception as e:
                        current_app.logger.error(f"Share settings photo upload failed: {e}")

            if audio_file and audio_file.filename:
                ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''
                if ext in m.ALLOWED_AUDIO_EXTENSIONS:
                    try:
                        audio_file.seek(0)
                        upload_result = m.cloudinary.uploader.upload(audio_file, resource_type="auto", folder="echowithin_valentine")
                        audio_url = upload_result.get('secure_url')
                        update_fields['valentine_audio'] = m.encrypt_note(audio_url, user_id=current_user.id)
                        update_fields['valentine_audio_hash'] = hashlib.sha256(audio_url.encode()).hexdigest()
                    except Exception as e:
                        current_app.logger.error(f"Share settings audio upload failed: {e}")

    # Clear media if switching back to standard
    if surprise_theme == 'none':
        if share.get('valentine_photo') or share.get('valentine_audio'):
            m.cleanup_share_media(share)
        update_fields['valentine_photo'] = None
        update_fields['valentine_audio'] = None
        update_fields['valentine_photo_hash'] = None
        update_fields['valentine_audio_hash'] = None
        update_fields['use_typewriter'] = False

    m.note_shares_conf.update_one({'_id': share['_id']}, {'$set': update_fields})
    flash('Share settings updated.', 'success')
    return redirect(url_for('sharing.share_settings_page', share_id=share_id))


@bp.route('/api/share/<share_id>/history')
@login_required
def api_get_share_history(share_id):
    """Returns access history for a specific share link (owner only)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id, 'owner_id': ObjectId(current_user.id)})
    if not share:
        return jsonify({'error': 'Unauthorized or invalid share'}), 403
    
    try:
        history = list(m.unlock_notifications_conf.find(
            {'share_id': share_id},
            sort=[('unlocked_at', -1)]
        ).limit(100))
        
        result = []
        for h in history:
            # Ensure we have a timestamp
            ts = h.get('unlocked_at')
            if ts:
                if isinstance(ts, datetime.datetime):
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=datetime.timezone.utc)
                    ts_iso = ts.isoformat().replace('+00:00', 'Z')
                else:
                    ts_iso = str(ts)
            else:
                ts_iso = None

            unlocked_by_name = h.get('unlocked_by_name')
            if not unlocked_by_name or unlocked_by_name in ['Someone', 'Anonymous visitor', 'Unknown']:
                unlocked_by_name = 'Anonymous visitor'
            
            unlocked_by_id = h.get('unlocked_by')
            
            # Always resolve username from DB when we have a user ID (handles stale names, renames, generic fallbacks)
            if unlocked_by_id:
                try:
                    v_user = m.users_conf.find_one({'_id': ObjectId(unlocked_by_id)}, {'username': 1})
                    if v_user and v_user.get('username'):
                        unlocked_by_name = v_user['username']
                except:
                    pass

            result.append({
                '_id': str(h['_id']),
                'unlocked_by_name': unlocked_by_name,
                'unlocked_at': ts_iso,
                'surprise_theme': h.get('surprise_theme', 'none')
            })
        return jsonify(result)
    except Exception as e:
        # PRIVACY: share_id IS the secret link — never log it in plaintext.
        share_fp = hashlib.sha256(str(share_id).encode('utf-8')).hexdigest()[:10]
        current_app.logger.error(f"Error fetching share history for fp={share_fp}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/personal_post/versions/<post_id>')
@login_required
@limits(calls=20, period=60)
def api_get_note_versions(post_id):
    """Returns rich version history for a note (owner only)."""
    import main as m
    obj_id = m.safe_object_id(post_id)
    if not obj_id:
        return jsonify([]), 400

    # Verify ownership
    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    current_plain = m._decrypt_note_record(note)
    versions = list(m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', -1).limit(50))
    # Build a shared candidate list from the note record for decryption fallback
    note_candidates = m._candidate_user_ids(
        note.get('content_owner_id'),
        note.get('user_id'),
        current_user.id
    )

    result = []
    for v in versions:
        event_type = v.get('event_type', 'snapshot')
        status = v.get('status', 'applied')

        row = {
            '_id': str(v['_id']),
            'editor_name': v.get('editor_name', 'Unknown'),
            'event_type': event_type,
            'status': status,
            'edit_summary': v.get('edit_summary', ''),
            'created_at': v['created_at'].replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if v.get('created_at') else None
        }

        # Build per-version candidate list: version-specific IDs first, then note-level fallbacks
        version_candidates = m._candidate_user_ids(
            v.get('content_owner_id'),
            v.get('editor_id'),
            *note_candidates
        )

        if event_type == 'proposal':
            base_plain = v.get('base_content_plain')
            if base_plain is None:
                base_encrypted = v.get('base_content') or v.get('content', '')
                base_plain = (m._decrypt_with_candidate_ids(base_encrypted, version_candidates) if base_encrypted else '') or ''
            proposed_plain = v.get('proposed_content_plain')
            if proposed_plain is None:
                proposed_encrypted = v.get('proposed_content', '')
                proposed_plain = (m._decrypt_with_candidate_ids(proposed_encrypted, version_candidates) if proposed_encrypted else '') or ''
            row.update({
                'base_content': base_plain,
                'proposed_content': proposed_plain,
                'current_content': current_plain,
                'diff_text': m.build_unified_diff_text(base_plain, proposed_plain),
                'can_review': status == 'pending'
            })
        else:
            if not v.get('encrypted', True):
                decrypted = v.get('content', '')
            else:
                decrypted = m._decrypt_with_candidate_ids(v.get('content', ''), version_candidates)
                if decrypted is None:
                    decrypted = '[Content unavailable \u2014 decryption error]'
            row.update({
                'content': decrypted,
                'can_restore': True
            })

        result.append(row)
    return jsonify(result)


@bp.route('/personal_post/version/restore/<post_id>/<version_id>', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_restore_note_version(post_id, version_id):
    """Restore a previous snapshot version for an owned note."""
    import main as m
    obj_id = m.safe_object_id(post_id)
    ver_id = m.safe_object_id(version_id)
    if not obj_id or not ver_id:
        return jsonify({'error': 'Invalid ID'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    version = m.note_versions_conf.find_one({'_id': ver_id, 'note_id': obj_id})
    if not version:
        return jsonify({'error': 'Version not found'}), 404

    if version.get('event_type', 'snapshot') != 'snapshot':
        return jsonify({'error': 'Only snapshot versions can be restored'}), 400

    now = datetime.datetime.now(datetime.timezone.utc)

    # Snapshot current state before restore.
    if note.get('content'):
        m.note_versions_conf.insert_one({
            'note_id': obj_id,
            'share_id': None,
            'editor_name': current_user.username if hasattr(current_user, 'username') else str(current_user.id),
            'editor_id': ObjectId(current_user.id),
            'content': note.get('content', ''),
            'content_owner_id': note.get('content_owner_id', note.get('user_id')),
            'encrypted': True,
            'event_type': 'snapshot',
            'status': 'applied',
            'edit_summary': 'Backup before restore',
            'created_at': now,
            'is_read_by_owner': True
        })

    m.personal_posts_conf.update_one(
        {'_id': obj_id},
        {'$set': {
            'content': version.get('content', ''),
            'encrypted': True,
            'content_owner_id': version.get('content_owner_id', ObjectId(current_user.id)),
            'updated_at': now
        }}
    )

    restore_candidates = m._candidate_user_ids(
        version.get('content_owner_id'),
        note.get('content_owner_id'),
        note.get('user_id'),
        current_user.id
    )
    plain = m._decrypt_with_candidate_ids(version.get('content', ''), restore_candidates) or m.decrypt_note(version.get('content', ''), user_id=str(version.get('content_owner_id') or current_user.id))
    m.index_note_to_typesense(post_id, decrypted_content=plain)

    return jsonify({'success': True, 'content': plain, 'updated_at': now.isoformat()})


@bp.route('/personal_post/proposal/<version_id>/decision', methods=['POST'])
@login_required
@limits(calls=15, period=60)
def api_decide_note_proposal(version_id):
    """Owner accepts/rejects contributor proposals for shared notes."""
    import main as m
    try:
        ver_id = m.safe_object_id(version_id)
        if not ver_id:
            return jsonify({'error': 'Invalid proposal ID'}), 400

        proposal = m.note_versions_conf.find_one({'_id': ver_id})
        if not proposal or proposal.get('event_type') != 'proposal':
            return jsonify({'error': 'Proposal not found'}), 404

        note_id = proposal.get('note_id')
        note = m.personal_posts_conf.find_one({'_id': note_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json() or {}
        action = (data.get('action') or '').strip().lower()
        decision_summary = (data.get('edit_summary') or '').strip()[:180]

        if data.get('auto_approve_subsequent') and proposal.get('share_id') and proposal.get('editor_id'):
            m.note_shares_conf.update_one(
                {'share_id': proposal.get('share_id')},
                {'$addToSet': {'auto_approved_users': ObjectId(proposal['editor_id'])}}
            )

        if proposal.get('status') != 'pending':
            return jsonify({'error': 'Proposal already reviewed'}), 400

        if action == 'reject':
            m.note_versions_conf.update_one(
                {'_id': ver_id},
                {'$set': {
                    'status': 'rejected',
                    'reviewed_at': datetime.datetime.now(datetime.timezone.utc),
                    'reviewed_by': ObjectId(current_user.id),
                    'decision_summary': decision_summary or 'Rejected by owner'
                }}
            )
            
            # Notify contributor
            contributor_id = proposal.get('editor_id')
            if contributor_id:
                m.send_push_notification_to_user(
                    str(contributor_id),
                    "Proposal Rejected",
                    f"Your proposal for note '{note.get('reference', 'Untitled')[:30]}' was rejected.",
                    url=url_for('sharing.view_shared_note', share_id=proposal.get('share_id'), _external=True) if proposal.get('share_id') else None,
                    tag=f'prop-dec-{version_id}'
                )
                
            return jsonify({'success': True, 'status': 'rejected'})

        if action != 'accept':
            return jsonify({'error': 'Invalid action'}), 400

        candidates = m._candidate_user_ids(
            proposal.get('content_owner_id'),
            proposal.get('editor_id'),
            note.get('content_owner_id'),
            note.get('user_id'),
            current_user.id
        )
        current_plain = m._decrypt_note_record(note)
        base_encrypted = proposal.get('base_content') or proposal.get('content', '')
        base_plain = proposal.get('base_content_plain') or (
            m._decrypt_with_candidate_ids(base_encrypted, candidates) if base_encrypted else None
        ) or m.decrypt_note(base_encrypted, user_id=current_user.id)
        
        proposed_encrypted = proposal.get('proposed_content', '')
        proposed_plain = proposal.get('proposed_content_plain') or (
            m._decrypt_with_candidate_ids(proposed_encrypted, candidates) if proposed_encrypted else None
        ) or m.decrypt_note(proposed_encrypted, user_id=current_user.id)

        merged_content = (data.get('merged_content') or '').strip()

        # If note changed since proposal base, require merge content from owner.
        if current_plain != base_plain and not merged_content:
            return jsonify({
                'error': 'conflict',
                'message': 'The note changed after this proposal was created. Review merge preview.',
                'current_content': current_plain,
                'incoming_content': proposed_plain,
                'merge_preview': m.build_merge_preview_text(current_plain, proposed_plain),
                'diff_text': m.build_unified_diff_text(current_plain, proposed_plain)
            }), 409

        max_chars = current_user.get_limit('max_chars_per_note')
        final_plain = (merged_content or proposed_plain).strip()[:max_chars]
        final_encrypted = m.encrypt_note(final_plain, user_id=current_user.id)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Snapshot current note before applying accepted proposal.
        m.note_versions_conf.insert_one({
            'note_id': note_id,
            'share_id': proposal.get('share_id'),
            'editor_name': current_user.username if hasattr(current_user, 'username') else str(current_user.id),
            'editor_id': ObjectId(current_user.id),
            'content': note.get('content', ''),
            'content_owner_id': note.get('content_owner_id', note.get('user_id')),
            'encrypted': True,
            'event_type': 'snapshot',
            'status': 'applied',
            'edit_summary': 'Backup before accepting proposal',
            'created_at': now,
            'is_read_by_owner': True
        })

        m.personal_posts_conf.update_one(
            {'_id': note_id},
            {'$set': {
                'content': final_encrypted,
                'encrypted': True,
                'content_owner_id': ObjectId(current_user.id),
                'updated_at': now
            }}
        )

        m.note_versions_conf.update_one(
            {'_id': ver_id},
            {'$set': {
                'status': 'accepted',
                'reviewed_at': now,
                'reviewed_by': ObjectId(current_user.id),
                'decision_summary': decision_summary or 'Accepted by owner',
                'accepted_content': final_encrypted
            }}
        )

        m.index_note_to_typesense(str(note_id), decrypted_content=final_plain)

        # Notify owner sessions and collaborators in the share room.
        m.socketio.emit('note_changed', {'note_id': str(note_id), 'content': final_plain, 'updated_at': now.isoformat()}, room=str(current_user.id))
        if proposal.get('share_id'):
            m.socketio.emit('note_changed', {'content': final_plain, 'updated_at': now.isoformat()}, room=proposal.get('share_id'))

        # Notify contributor of acceptance
        contributor_id = proposal.get('editor_id')
        if contributor_id:
            try:
                m.send_push_notification_to_user(
                    str(contributor_id),
                    "Proposal Accepted!",
                    f"Your changes for note '{note.get('reference', 'Untitled')[:30]}' were accepted.",
                    url=url_for('sharing.view_shared_note', share_id=proposal.get('share_id'), _external=True) if proposal.get('share_id') else None,
                    tag=f'prop-dec-{version_id}'
                )
            except Exception: pass

        return jsonify({'success': True, 'status': 'accepted', 'content': final_plain, 'updated_at': now.isoformat()})
    except Exception as e:
        current_app.logger.error(f"Failed to process proposal decision {version_id}: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error while reviewing proposal'}), 500


# --- Note Discussion Routes (Login Required) ---


@bp.route('/share/note/<share_id>/comments', methods=['GET'])
@limits(calls=30, period=60)
def api_get_note_comments(share_id):
    """Fetch all comments for a shared note, organized into a recursive tree."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify([]), 404

    # Fetch all comments for this share
    all_comments = list(m.note_discussions_conf.find({
        'share_id': share_id
    }).sort('created_at', 1))  # Sort by time so replies come after parents

    # Build Map for easy lookup and nesting
    comment_map = {}
    roots = []
    
    for c in all_comments:
        c_id = str(c['_id'])
        c_deleted = c.get('deleted', False)
        if c_deleted:
            author_name = '[deleted]'
            author_id = ''
            content = '[deleted]'
        else:
            author_name = c.get('author_name', 'Unknown')
            author_id = str(c.get('author_id', ''))
            content = m.decrypt_note(c['content'], user_id=str(c.get('author_id'))) if c.get('encrypted', False) else c['content']

        comment_map[c_id] = {
            '_id': c_id,
            'author_name': author_name,
            'author_id': author_id,
            'content': content,
            'deleted': c_deleted,
            'created_at': (c['created_at'].replace(tzinfo=datetime.timezone.utc).isoformat() if c.get('created_at') and c['created_at'].tzinfo is None else c['created_at'].isoformat()) if c.get('created_at') else None,
            'replies': []
        }

    for c in all_comments:
        c_id = str(c['_id'])
        p_id = str(c.get('parent_id')) if c.get('parent_id') else None
        
        if p_id and p_id in comment_map:
            comment_map[p_id]['replies'].append(comment_map[c_id])
        else:
            roots.append(comment_map[c_id])

    # Reverse roots so newest top-level comments are first
    roots.reverse()
    
    return jsonify(roots)


@bp.route('/share/note/<share_id>/comments', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_post_note_comment(share_id):
    """Post a new comment on a shared note (login required)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404

    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content or len(content) > 2000:
        return jsonify({'error': 'Comment must be 1-2000 characters'}), 400

    # Sanitize
    content = m.bleach.clean(content, tags=[], strip=True)

    comment = {
        'share_id': share_id,
        'note_id': share['note_id'],
        'author_name': current_user.username if hasattr(current_user, 'username') else 'User',
        'author_id': ObjectId(current_user.id),
        'content': m.encrypt_note(content, user_id=str(current_user.id)),
        'encrypted': True,
        'parent_id': None,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.note_discussions_conf.insert_one(comment)

    # Broadcast to all users watching this note
    m.socketio.emit('discussion_updated', {
        'share_id': share_id,
        'author_name': comment['author_name'],
        'type': 'comment'
    }, room=share_id)

    return jsonify({
        'success': True,
        '_id': str(result.inserted_id),
        'author_name': comment['author_name'],
        'content': content,
        'created_at': comment['created_at'].isoformat()
    })


@bp.route('/share/note/<share_id>/comments/<comment_id>/replies', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_post_note_reply(share_id, comment_id):
    """Reply to a comment on a shared note (login required)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404

    parent_id = m.safe_object_id(comment_id)
    if not parent_id:
        return jsonify({'error': 'Invalid comment ID'}), 400

    parent = m.note_discussions_conf.find_one({'_id': parent_id, 'share_id': share_id})
    if not parent:
        return jsonify({'error': 'Parent comment not found'}), 404

    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content or len(content) > 2000:
        return jsonify({'error': 'Reply must be 1-2000 characters'}), 400

    content = m.bleach.clean(content, tags=[], strip=True)

    reply = {
        'share_id': share_id,
        'note_id': share['note_id'],
        'author_name': current_user.username if hasattr(current_user, 'username') else 'User',
        'author_id': ObjectId(current_user.id),
        'content': m.encrypt_note(content, user_id=str(current_user.id)),
        'encrypted': True,
        'parent_id': parent_id,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.note_discussions_conf.insert_one(reply)

    # Broadcast to all users watching this note
    m.socketio.emit('discussion_updated', {
        'share_id': share_id,
        'author_name': reply['author_name'],
        'type': 'reply'
    }, room=share_id)

    return jsonify({
        'success': True,
        '_id': str(result.inserted_id),
        'author_name': reply['author_name'],
        'content': content,
        'created_at': reply['created_at'].isoformat()
    })


@bp.route('/share/note/<share_id>/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_note_comment(share_id, comment_id):
    """Delete a comment or reply on a shared note (login required)."""
    import main as m
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share not found'}), 404

    target_id = m.safe_object_id(comment_id)
    if not target_id:
        return jsonify({'error': 'Invalid comment ID'}), 400

    comment = m.note_discussions_conf.find_one({'_id': target_id, 'share_id': share_id})
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404

    # Allow delete if user is the comment author
    is_author = str(comment.get('author_id')) == current_user.id
    if not is_author:
        return jsonify({'error': 'Unauthorized to delete this comment'}), 403

    # Check if this comment has replies
    has_replies = m.note_discussions_conf.count_documents({'parent_id': target_id}) > 0

    if has_replies:
        m.note_discussions_conf.update_one(
            {'_id': target_id},
            {'$set': {
                'author_name': '[deleted]',
                'content': m.encrypt_note('[deleted]', user_id=str(current_user.id)) if comment.get('encrypted') else '[deleted]',
                'deleted': True,
                'author_id': None
            }}
        )
    else:
        # Purge completely
        m.note_discussions_conf.delete_one({'_id': target_id})

    # Broadcast deletion
    m.socketio.emit('discussion_updated', {
        'share_id': share_id,
        'type': 'delete',
        'comment_id': comment_id
    }, room=share_id)

    return jsonify({'success': True})
