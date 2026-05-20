import datetime
import secrets
import hashlib
from flask import Blueprint, request, jsonify, session, url_for, make_response
from flask_login import login_required, current_user, login_user, logout_user
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

# Create the API blueprint
api_bp = Blueprint('api_v1', __name__)

# To prevent circular dependency errors, all imports from main are done lazily or
# resolved after the main module finishes loading.
def get_main_globals():
    import main
    return main

# --- Helper functions ---
def safe_obj_id(val):
    try:
        return ObjectId(val)
    except Exception:
        return None

# --- AUTHENTICATION ENDPOINTS ---

@api_bp.route('/register', methods=['POST'])
def api_register():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    agree_terms = data.get("agree_terms", True)

    if not agree_terms:
        return jsonify({'error': 'You must agree to the Terms of Service to create an account.'}), 400

    if not (username and password and email):
        return jsonify({'error': 'Username, email, and password are required.'}), 400

    if m.users_conf.find_one({'username': username}):
        return jsonify({'error': 'This username is already taken.'}), 400

    existing_user_by_email = m.users_conf.find_one({'email': email})
    if existing_user_by_email:
        if existing_user_by_email.get('is_confirmed'):
            return jsonify({'error': 'This email is already registered.'}), 400
        else:
            # Resend confirmation code
            gen_code = str(secrets.randbelow(10**6)).zfill(6)
            hashed = hashlib.sha256(gen_code.encode()).hexdigest()
            code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
            m.auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry}}, upsert=True)
            m.send_code(email, gen_code)
            return jsonify({'success': True, 'confirmed': False, 'email': email, 'message': 'New confirmation code sent.'})

    hashed_password = generate_password_hash(password)
    m.users_conf.insert_one({
        'username': username,
        'email': email,
        'password': hashed_password,
        'is_confirmed': False,
        'is_admin': False,
        'join_date': datetime.datetime.now(datetime.timezone.utc),
        'notification_preference': 'weekly'
    })

    gen_code = str(secrets.randbelow(10**6)).zfill(6)
    hashed = hashlib.sha256(gen_code.encode()).hexdigest()
    code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    m.auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry}}, upsert=True)
    m.send_code(email, gen_code)

    return jsonify({
        'success': True,
        'confirmed': False,
        'email': email,
        'message': 'Account created successfully! Check your email for a confirmation code.'
    })

@api_bp.route('/confirm/<email>', methods=['POST'])
def api_confirm(email):
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    confirm_code = data.get("code", "").strip()

    user = m.users_conf.find_one({"email": email})
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    if user.get('is_confirmed'):
        return jsonify({'error': 'Email is already confirmed.'}), 400

    if not confirm_code:
        return jsonify({'error': 'Please enter the confirmation code.'}), 400

    hashed_obj = m.auth_conf.find_one({'email': email})
    if not hashed_obj:
        return jsonify({'error': 'No confirmation code found for this email.'}), 400

    code_exp = hashed_obj.get('code_expiry')
    if code_exp and code_exp.tzinfo is None:
        code_exp = code_exp.replace(tzinfo=datetime.timezone.utc)
    if code_exp and code_exp < datetime.datetime.now(datetime.timezone.utc):
        return jsonify({'error': 'This confirmation code has expired. Please register again.'}), 400

    if hashed_obj['hashed_code'] == hashlib.sha256(confirm_code.encode()).hexdigest():
        m.users_conf.update_one({'email': email}, {'$set': {'is_confirmed': True}})
        m.auth_conf.delete_one({'email': email})
        return jsonify({'success': True, 'message': 'Email confirmed successfully.'})
    else:
        return jsonify({'error': 'The confirmation code is incorrect.'}), 400

@api_bp.route('/login', methods=['POST'])
def api_login():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember = bool(data.get("remember", True))

    user = m.users_conf.find_one({
        "$or": [
            {"username": username},
            {"email": username}
        ]
    })

    if user and user.get('password') is None:
        return jsonify({'error': 'This account was created with Google. Please use Google Login.'}), 400

    if user and check_password_hash(user["password"], password):
        if not user.get('is_confirmed'):
            return jsonify({'error': 'Please confirm your account first.'}), 400

        if user.get('is_banned'):
            return jsonify({'error': 'Your account has been suspended.'}), 403

        user_obj = m.User(user)
        login_user(user_obj, remember=remember)

        # Clear app lock state on fresh login
        session.pop('app_lock_unlocked_at', None)

        # Generate persistent token for native app session revival
        _app_token = secrets.token_urlsafe(48)
        m.app_tokens_conf.insert_one({
            'token': _app_token,
            'user_id': user['_id'],
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })

        resp = make_response(jsonify({
            'success': True,
            'username': user['username'],
            'email': user['email'],
            'x_app_token': _app_token
        }))
        # Set persistent token as httpOnly cookie
        resp.set_cookie('x_app_token', _app_token, max_age=90*24*3600,
                        httponly=True, secure=True, samesite='Lax')
        return resp
    else:
        return jsonify({'error': 'Wrong details provided.'}), 401

@api_bp.route('/logout', methods=['POST', 'GET'])
def api_logout():
    m = get_main_globals()
    app_token = request.cookies.get('x_app_token') or request.headers.get('Authorization', '').replace('Bearer ', '').strip()
    if app_token:
        m.app_tokens_conf.delete_one({'token': app_token})
    if current_user.is_authenticated:
        m.app_tokens_conf.delete_many({'user_id': ObjectId(current_user.id)})
    logout_user()
    session.pop('oauth_state', None)
    session.pop('oauth_platform', None)
    resp = make_response(jsonify({'success': True, 'message': 'Logged out successfully.'}))
    resp.delete_cookie('x_app_token')
    return resp

# --- NOTES CRUD ENDPOINTS ---

@api_bp.route('/notes', methods=['GET'])
@login_required
def api_get_notes():
    m = get_main_globals()
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(50, max(1, int(request.args.get('per_page', 20))))
    except ValueError:
        page = 1
        per_page = 20

    offset = (page - 1) * per_page
    notes_cursor = m.personal_posts_conf.find({'user_id': ObjectId(current_user.id)}).sort('created_at', -1).skip(offset).limit(per_page)
    notes_list = list(notes_cursor)
    total = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id)})

    formatted_notes = []
    for note in notes_list:
        content_plain = m._decrypt_note_record(note)
        formatted_notes.append({
            'id': str(note['_id']),
            'content': content_plain,
            'reference': note.get('reference', ''),
            'tags': note.get('tags', []),
            'is_locked': note.get('is_locked', False),
            'is_pinned': note.get('is_pinned', False),
            'created_at': note.get('created_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('created_at') else None,
            'updated_at': note.get('updated_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('updated_at') else None
        })

    return jsonify({
        'notes': formatted_notes,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'has_more': (offset + per_page) < total
        }
    })

@api_bp.route('/notes/create', methods=['POST'])
@login_required
def api_create_note():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    reference = data.get('reference', '').strip()[:200]
    tags = data.get('tags', [])

    if not content:
        return jsonify({'error': 'Content cannot be empty.'}), 400

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    max_notes = m.get_limit(user_doc, 'max_notes')
    max_chars = m.get_limit(user_doc, 'max_chars_per_note')
    current_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id)})
    
    if current_count >= max_notes:
        return jsonify({'error': f'You have reached the limit of {max_notes} notes. Upgrade to Premium!'}), 403

    content = content[:max_chars]
    encrypted_content = m.encrypt_note(content, user_id=current_user.id)
    
    result = m.personal_posts_conf.insert_one({
        'user_id': ObjectId(current_user.id),
        'content_owner_id': ObjectId(current_user.id),
        'content': encrypted_content,
        'encrypted': True,
        'reference': reference,
        'tags': tags,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })
    
    m.index_note_to_meili(str(result.inserted_id), decrypted_content=content)
    
    return jsonify({'success': True, 'id': str(result.inserted_id)})

# --- APP LOCK ENDPOINTS ---

@api_bp.route('/app_lock/setup', methods=['POST'])
@login_required
def api_app_lock_setup():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    pin = data.get('pin', '').strip()

    if not pin or not pin.isdigit() or len(pin) != 4:
        return jsonify({'error': 'PIN must be exactly 4 digits.'}), 400

    hashed_pin = generate_password_hash(pin)
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'app_lock_pin_hash': hashed_pin}}
    )
    return jsonify({'success': True, 'message': 'PIN lock set up successfully.'})

@api_bp.route('/app_lock/verify', methods=['POST'])
@login_required
def api_app_lock_verify():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    pin = data.get('pin', '').strip()

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No PIN setup found.'}), 404

    if check_password_hash(user['app_lock_pin_hash'], pin):
        session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Incorrect PIN.'}), 401

@api_bp.route('/app_lock/check_status', methods=['GET'])
@login_required
def api_app_lock_status():
    unlock_ts = session.get('app_lock_unlocked_at')
    if not unlock_ts:
        return jsonify({'unlocked': False})
    
    if unlock_ts.tzinfo is None:
        unlock_ts = unlock_ts.replace(tzinfo=datetime.timezone.utc)
        
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
    if elapsed >= 300:
        session.pop('app_lock_unlocked_at', None)
        return jsonify({'unlocked': False})
        
    return jsonify({'unlocked': True, 'remaining': int(300 - elapsed)})

@api_bp.route('/app_lock/remove', methods=['POST'])
@login_required
def api_app_lock_remove():
    m = get_main_globals()
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$unset': {'app_lock_pin_hash': ''}}
    )
    session.pop('app_lock_unlocked_at', None)
    return jsonify({'success': True, 'message': 'PIN lock removed.'})

# --- PUSH NOTIFICATIONS ---

@api_bp.route('/fcm/register', methods=['POST'])
@login_required
def api_register_fcm():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'error': 'Token cannot be empty.'}), 400

    m.fcm_tokens_conf.update_one(
        {'user_id': ObjectId(current_user.id), 'token': token},
        {'$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}},
        upsert=True
    )
    return jsonify({'success': True, 'message': 'FCM Token registered.'})

@api_bp.route('/fcm/unregister', methods=['POST'])
@login_required
def api_unregister_fcm():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'error': 'Token cannot be empty.'}), 400

    m.fcm_tokens_conf.delete_one({'user_id': ObjectId(current_user.id), 'token': token})
    return jsonify({'success': True, 'message': 'FCM Token unregistered.'})


# --- NOTE SHARING & COLLABORATION ---

@api_bp.route('/notes/shares/<post_id>', methods=['GET'])
@login_required
def api_get_note_shares(post_id):
    m = get_main_globals()
    obj_id = safe_obj_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    shares = list(m.note_shares_conf.find({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)}))
    result = []
    for s in shares:
        result.append({
            'share_id': s.get('share_id'),
            'permissions': s.get('permissions', 'view'),
            'surprise_theme': s.get('surprise_theme', 'none'),
            'use_typewriter': s.get('use_typewriter', False),
            'auto_approve': s.get('auto_approve', False),
            'created_at': s.get('created_at').isoformat() if s.get('created_at') else None,
            'expires_at': s.get('expires_at').isoformat() if s.get('expires_at') else None,
            'has_password': bool(s.get('access_code_hash'))
        })
    return jsonify({'shares': result})

@api_bp.route('/notes/share/<post_id>', methods=['POST'])
@login_required
def api_create_note_share(post_id):
    m = get_main_globals()
    obj_id = safe_obj_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    max_shares = m.get_limit(user_doc, 'max_share_links_per_note')
    active_count = m.note_shares_conf.count_documents({'note_id': obj_id, 'owner_id': ObjectId(current_user.id)})
    if active_count >= max_shares:
        return jsonify({'error': f'You have reached the limit of {max_shares} share links per note.'}), 403

    data = request.get_json(silent=True) or {}
    permissions = data.get('permissions', 'view')
    expires_in = data.get('expires_in')
    access_code = data.get('access_code')
    surprise_theme = data.get('surprise_theme', 'none')
    use_typewriter = data.get('use_typewriter', False)
    auto_approve = data.get('auto_approve', False)

    if permissions not in ['view', 'edit']:
        permissions = 'view'

    access_code_hash = None
    if access_code:
        access_code_hash = generate_password_hash(access_code)

    expires_at = None
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_in == '1h':
        expires_at = now + datetime.timedelta(hours=1)
    elif expires_in == '1d':
        expires_at = now + datetime.timedelta(days=1)
    elif expires_in == '7d':
        expires_at = now + datetime.timedelta(days=7)

    share_id = secrets.token_urlsafe(16)
    
    m.note_shares_conf.insert_one({
        'share_id': share_id,
        'note_id': obj_id,
        'owner_id': ObjectId(current_user.id),
        'permissions': permissions,
        'surprise_theme': surprise_theme,
        'use_typewriter': use_typewriter,
        'auto_approve': auto_approve,
        'access_code_hash': access_code_hash,
        'expires_at': expires_at,
        'created_at': now
    })

    return jsonify({
        'success': True,
        'share_id': share_id,
        'url': url_for('sitemap_legacy_redirect', _external=True) + f'share/note/{share_id}'
    })

@api_bp.route('/notes/revoke_share/<share_id>', methods=['POST'])
@login_required
def api_revoke_note_share(share_id):
    m = get_main_globals()
    result = m.note_shares_conf.delete_one({'share_id': share_id, 'owner_id': ObjectId(current_user.id)})
    if result.deleted_count == 0:
        return jsonify({'error': 'Share link not found or unauthorized'}), 404
    return jsonify({'success': True, 'message': 'Share link revoked.'})


# --- COLLABORATIVE SHARE WORKSPACE (COMMENTS & ATTACHMENTS) ---

@api_bp.route('/notes/share/<share_id>/comments', methods=['GET'])
def api_share_comments(share_id):
    m = get_main_globals()
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share link not found'}), 404

    all_comments = list(m.note_discussions_conf.find({'share_id': share_id}).sort('created_at', 1))
    comment_map = {}
    roots = []
    
    for c in all_comments:
        c_id = str(c['_id'])
        comment_map[c_id] = {
            'id': c_id,
            'author_name': c.get('author_name', 'Unknown'),
            'author_id': str(c.get('author_id', '')),
            'content': m.decrypt_note(c['content']) if c.get('encrypted', False) else c['content'],
            'created_at': c['created_at'].isoformat() if c.get('created_at') else None,
            'replies': []
        }

    for c in all_comments:
        c_id = str(c['_id'])
        p_id = str(c.get('parent_id')) if c.get('parent_id') else None
        if p_id and p_id in comment_map:
            comment_map[p_id]['replies'].append(comment_map[c_id])
        else:
            roots.append(comment_map[c_id])

    roots.reverse()
    return jsonify({'comments': roots})

@api_bp.route('/notes/share/<share_id>/comments', methods=['POST'])
@login_required
def api_add_share_comment(share_id):
    m = get_main_globals()
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share link not found'}), 404

    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    comment_doc = {
        'share_id': share_id,
        'author_id': ObjectId(current_user.id),
        'author_name': current_user.username,
        'content': content,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    m.note_discussions_conf.insert_one(comment_doc)
    return jsonify({'success': True})

@api_bp.route('/notes/share/<share_id>/comments/<comment_id>/replies', methods=['POST'])
@login_required
def api_reply_share_comment(share_id, comment_id):
    m = get_main_globals()
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share link not found'}), 404

    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    parent_obj_id = safe_obj_id(comment_id)
    if not parent_obj_id:
        return jsonify({'error': 'Invalid parent comment ID'}), 400

    comment_doc = {
        'share_id': share_id,
        'parent_id': parent_obj_id,
        'author_id': ObjectId(current_user.id),
        'author_name': current_user.username,
        'content': content,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    m.note_discussions_conf.insert_one(comment_doc)
    return jsonify({'success': True})

@api_bp.route('/notes/share/<share_id>/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_share_comment(share_id, comment_id):
    m = get_main_globals()
    c_obj_id = safe_obj_id(comment_id)
    if not c_obj_id:
        return jsonify({'error': 'Invalid comment ID'}), 400

    result = m.note_discussions_conf.delete_one({
        '_id': c_obj_id,
        'author_id': ObjectId(current_user.id)
    })
    if result.deleted_count == 0:
        return jsonify({'error': 'Comment not found or unauthorized'}), 404
    return jsonify({'success': True})

@api_bp.route('/notes/share/<share_id>/attachments', methods=['GET'])
@login_required
def api_get_share_attachments(share_id):
    m = get_main_globals()
    share = m.note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return jsonify({'error': 'Share link not found'}), 404

    note_id = share['note_id']
    attachments = list(m.note_attachments_conf.find({'note_id': note_id}))
    result = []
    for a in attachments:
        result.append({
            'id': str(a['_id']),
            'filename': a.get('filename'),
            'file_url': a.get('file_url'),
            'file_type': a.get('file_type'),
            'uploaded_by': a.get('uploaded_by_username', 'Unknown'),
            'uploaded_at': a.get('uploaded_at').isoformat() if a.get('uploaded_at') else None
        })
    return jsonify({'attachments': result})


# --- NOTE VERSIONS & COLLABORATIVE PROPOSALS ---

@api_bp.route('/notes/versions/<post_id>', methods=['GET'])
@login_required
def api_get_note_versions(post_id):
    m = get_main_globals()
    obj_id = safe_obj_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    versions = list(m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', -1))
    result = []
    for v in versions:
        result.append({
            'version_id': str(v['_id']),
            'content': m.decrypt_note(v['content']) if v.get('encrypted', False) else v['content'],
            'author_username': v.get('author_username', 'Unknown'),
            'created_at': v.get('created_at').isoformat() if v.get('created_at') else None,
            'is_proposal': v.get('is_proposal', False),
            'status': v.get('status', 'approved'),
            'review_comment': v.get('review_comment', '')
        })
    return jsonify({'versions': result})

@api_bp.route('/notes/version/restore/<post_id>/<version_id>', methods=['POST'])
@login_required
def api_restore_note_version(post_id, version_id):
    m = get_main_globals()
    post_obj_id = safe_obj_id(post_id)
    ver_obj_id = safe_obj_id(version_id)
    if not post_obj_id or not ver_obj_id:
        return jsonify({'error': 'Invalid IDs'}), 400

    note = m.personal_posts_conf.find_one({'_id': post_obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    version = m.note_versions_conf.find_one({'_id': ver_obj_id, 'note_id': post_obj_id})
    if not version:
        return jsonify({'error': 'Version not found'}), 404

    m.personal_posts_conf.update_one(
        {'_id': post_obj_id},
        {'$set': {
            'content': version['content'],
            'updated_at': datetime.datetime.now(datetime.timezone.utc)
        }}
    )
    return jsonify({'success': True, 'message': 'Note restored to specified version.'})

@api_bp.route('/notes/proposal/<version_id>/decision', methods=['POST'])
@login_required
def api_proposal_decision(version_id):
    m = get_main_globals()
    ver_obj_id = safe_obj_id(version_id)
    if not ver_obj_id:
        return jsonify({'error': 'Invalid proposal ID'}), 400

    version = m.note_versions_conf.find_one({'_id': ver_obj_id, 'is_proposal': True})
    if not version:
        return jsonify({'error': 'Proposal not found'}), 404

    note = m.personal_posts_conf.find_one({'_id': version['note_id'], 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Unauthorized to make decisions on this proposal'}), 403

    data = request.get_json(silent=True) or {}
    decision = data.get('decision')  # 'approve' or 'reject'
    comment = data.get('comment', '').strip()

    if decision not in ['approve', 'reject']:
        return jsonify({'error': 'Decision must be approve or reject.'}), 400

    if decision == 'approve':
        m.note_versions_conf.update_one(
            {'_id': ver_obj_id},
            {'$set': {'status': 'approved', 'review_comment': comment, 'reviewed_at': datetime.datetime.now(datetime.timezone.utc)}}
        )
        m.personal_posts_conf.update_one(
            {'_id': version['note_id']},
            {'$set': {
                'content': version['content'],
                'updated_at': datetime.datetime.now(datetime.timezone.utc)
            }}
        )
    else:
        m.note_versions_conf.update_one(
            {'_id': ver_obj_id},
            {'$set': {'status': 'rejected', 'review_comment': comment, 'reviewed_at': datetime.datetime.now(datetime.timezone.utc)}}
        )

    return jsonify({'success': True, 'message': f'Proposal successfully {decision}d.'})


# --- COMMUNITIES & COMMUNITY NOTES ---

@api_bp.route('/communities', methods=['GET'])
@login_required
def api_get_communities():
    m = get_main_globals()
    user_id_obj = ObjectId(current_user.id)
    
    joined = list(m.communities_conf.find({'members': user_id_obj}).sort('updated_at', -1))
    joined_list = []
    for c in joined:
        joined_list.append({
            'id': str(c['_id']),
            'name': c.get('name'),
            'bio': c.get('bio', ''),
            'visibility': c.get('visibility', 'private'),
            'invite_code': c.get('invite_code') if str(c.get('admin_id')) == current_user.id else None,
            'is_admin': str(c.get('admin_id')) == current_user.id,
            'member_count': len(c.get('members', [])),
            'note_count': m.community_notes_conf.count_documents({'community_id': c['_id']})
        })

    discover = list(m.communities_conf.find({
        'visibility': 'public',
        'members': {'$ne': user_id_obj}
    }).sort('updated_at', -1).limit(20))
    discover_list = []
    for c in discover:
        discover_list.append({
            'id': str(c['_id']),
            'name': c.get('name'),
            'bio': c.get('bio', ''),
            'member_count': len(c.get('members', [])),
            'note_count': m.community_notes_conf.count_documents({'community_id': c['_id']})
        })

    return jsonify({
        'joined': joined_list,
        'discoverable': discover_list
    })

@api_bp.route('/community/create', methods=['POST'])
@login_required
def api_create_community():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    bio = data.get('bio', '').strip()
    visibility = data.get('visibility', 'private')

    if not name or len(name) > 50:
        return jsonify({'error': 'Name is required and must be 50 chars or less.'}), 400

    user_id_obj = ObjectId(current_user.id)
    current_count = m.communities_conf.count_documents({'admin_id': user_id_obj})
    max_allowed = m.get_limit(m.users_conf.find_one({'_id': user_id_obj}), 'max_communities')
    
    if current_count >= max_allowed:
        return jsonify({'error': f'Reached limit of {max_allowed} communities.'}), 403

    invite_code = secrets.token_urlsafe(8)
    new_community = {
        'name': name,
        'bio': bio,
        'visibility': visibility,
        'admin_id': user_id_obj,
        'members': [user_id_obj],
        'invite_code': invite_code,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.communities_conf.insert_one(new_community)
    return jsonify({
        'success': True,
        'id': str(result.inserted_id),
        'invite_code': invite_code
    })

@api_bp.route('/community/join', methods=['POST'])
@login_required
def api_join_community_invite():
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    invite_code = data.get('invite_code', '').strip()

    if not invite_code:
        return jsonify({'error': 'Invite code required.'}), 400

    community = m.communities_conf.find_one({'invite_code': invite_code})
    if not community:
        return jsonify({'error': 'Invalid invite code.'}), 404

    user_id_obj = ObjectId(current_user.id)
    if user_id_obj in community.get('members', []):
        return jsonify({'success': True, 'message': 'Already a member.', 'id': str(community['_id'])})

    m.communities_conf.update_one(
        {'_id': community['_id']},
        {'$addToSet': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
    )
    return jsonify({'success': True, 'id': str(community['_id']), 'message': 'Joined community successfully.'})

@api_bp.route('/community/join-public/<community_id>', methods=['POST'])
@login_required
def api_join_community_public(community_id):
    m = get_main_globals()
    comm_obj_id = safe_obj_id(community_id)
    if not comm_obj_id:
        return jsonify({'error': 'Invalid community ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id, 'visibility': 'public'})
    if not community:
        return jsonify({'error': 'Community not found or not public.'}), 404

    user_id_obj = ObjectId(current_user.id)
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$addToSet': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
    )
    return jsonify({'success': True})

@api_bp.route('/community/<community_id>/leave', methods=['POST'])
@login_required
def api_leave_community(community_id):
    m = get_main_globals()
    comm_obj_id = safe_obj_id(community_id)
    if not comm_obj_id:
        return jsonify({'error': 'Invalid community ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Community not found.'}), 404

    if str(community.get('admin_id')) == current_user.id:
        return jsonify({'error': 'Admin cannot leave the community. Delete it instead.'}), 400

    user_id_obj = ObjectId(current_user.id)
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$pull': {'members': user_id_obj}, '$set': {'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
    )
    return jsonify({'success': True})

@api_bp.route('/community/<community_id>/notes', methods=['GET'])
@login_required
def api_get_community_notes(community_id):
    m = get_main_globals()
    comm_obj_id = safe_obj_id(community_id)
    if not comm_obj_id:
        return jsonify({'error': 'Invalid community ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id, 'members': ObjectId(current_user.id)})
    if not community:
        return jsonify({'error': 'Unauthorized or community not found'}), 403

    notes = list(m.community_notes_conf.find({'community_id': comm_obj_id}).sort('created_at', -1))
    result = []
    for n in notes:
        result.append({
            'id': str(n['_id']),
            'title': n.get('title'),
            'content': n.get('content'),
            'author_username': n.get('author_username', 'Unknown'),
            'created_at': n.get('created_at').isoformat() if n.get('created_at') else None
        })
    return jsonify({'notes': result})

@api_bp.route('/community/<community_id>/note/create', methods=['POST'])
@login_required
def api_create_community_note(community_id):
    m = get_main_globals()
    comm_obj_id = safe_obj_id(community_id)
    if not comm_obj_id:
        return jsonify({'error': 'Invalid community ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_obj_id, 'members': ObjectId(current_user.id)})
    if not community:
        return jsonify({'error': 'Unauthorized or community not found'}), 403

    data = request.get_json(silent=True) or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title or not content:
        return jsonify({'error': 'Title and content cannot be empty.'}), 400

    new_note = {
        'community_id': comm_obj_id,
        'title': title,
        'content': content,
        'author_id': ObjectId(current_user.id),
        'author_username': current_user.username,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    result = m.community_notes_conf.insert_one(new_note)
    return jsonify({'success': True, 'id': str(result.inserted_id)})


# --- APP RE-AUTHENTICATION (Persistent Token) ---

@api_bp.route('/app_reauth', methods=['POST'])
def api_app_reauth():
    """Re-authenticate a native app user using a persistent token.
    Accepts token from JSON body, Authorization header, or httpOnly cookie."""
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()

    # Fallback: check Authorization header (Bearer <token>)
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()

    # Fallback: read from X-App-Token header
    if not token:
        token = request.headers.get('X-App-Token', '').strip()

    # Fallback: read from httpOnly cookie
    if not token:
        token = request.cookies.get('x_app_token', '').strip()

    if not token:
        return jsonify({'error': 'No token'}), 400

    doc = m.app_tokens_conf.find_one({'token': token})
    if not doc:
        return jsonify({'error': 'Invalid token'}), 401

    user = m.users_conf.find_one({'_id': doc['user_id']})
    if not user:
        m.app_tokens_conf.delete_one({'_id': doc['_id']})
        return jsonify({'error': 'User not found'}), 401

    if user.get('is_banned'):
        m.app_tokens_conf.delete_many({'user_id': doc['user_id']})
        return jsonify({'error': 'Account suspended'}), 403

    user_obj = m.User(user)
    login_user(user_obj, remember=True)
    return jsonify({'success': True, 'username': user['username']})

