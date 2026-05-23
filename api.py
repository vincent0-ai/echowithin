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
    email = data.get("email", "").strip().lower()
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
    email = email.strip().lower()
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

    print(f"[DEBUG LOGIN] Attempt for username/email: '{username}'", flush=True)

    user = m.users_conf.find_one({
        "$or": [
            {"username": username},
            {"email": username.lower() if "@" in username else username}
        ]
    })

    print(f"[DEBUG LOGIN] User found in DB: {user is not None}", flush=True)

    if user and user.get('password') is None:
        print("[DEBUG LOGIN] User password is None (Google Auth account)", flush=True)
        return jsonify({'error': 'This account was created with Google. Please use Google Login.'}), 400

    if user:
        is_correct = check_password_hash(user["password"], password)
        print(f"[DEBUG LOGIN] Password check result: {is_correct}", flush=True)
        if is_correct:
            if not user.get('is_confirmed'):
                print(f"[DEBUG LOGIN] User '{user['username']}' is not confirmed. Regenerating code and returning unconfirmed status.", flush=True)
                gen_code = str(secrets.randbelow(10**6)).zfill(6)
                hashed = hashlib.sha256(gen_code.encode()).hexdigest()
                code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
                m.auth_conf.update_one({'email': user['email']}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry}}, upsert=True)
                m.send_code(user['email'], gen_code)
                return jsonify({
                    'success': False,
                    'confirmed': False,
                    'email': user['email'],
                    'error': 'Your email is not confirmed. A new verification code has been sent.'
                }), 200

            if user.get('is_banned'):
                print("[DEBUG LOGIN] User is banned", flush=True)
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
            print(f"[DEBUG LOGIN] Login successful. Generated token: {_app_token[:12]}...", flush=True)

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
            print("[DEBUG LOGIN] Password hash mismatch", flush=True)
            return jsonify({'error': 'Wrong details provided.'}), 401
    else:
        print("[DEBUG LOGIN] User not found", flush=True)
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

@api_bp.route('/notes/<note_id>', methods=['GET'])
@login_required
def api_get_note(note_id):
    m = get_main_globals()
    obj_id = safe_obj_id(note_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID.'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found.'}), 404

    content_plain = m._decrypt_note_record(note)
    return jsonify({
        'id': str(note['_id']),
        'content': content_plain,
        'reference': note.get('reference', ''),
        'tags': note.get('tags', []),
        'is_locked': note.get('is_locked', False),
        'is_pinned': note.get('is_pinned', False),
        'created_at': note.get('created_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('created_at') else None,
        'updated_at': note.get('updated_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('updated_at') else None
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

@api_bp.route('/notes/edit/<note_id>', methods=['POST'])
@login_required
def api_edit_note(note_id):
    m = get_main_globals()
    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    reference = data.get('reference', '').strip()[:200]
    tags = data.get('tags', [])
    edit_summary = (data.get('edit_summary') or '').strip()[:180]

    if not content:
        return jsonify({'error': 'Content cannot be empty.'}), 400

    obj_id = safe_obj_id(note_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID.'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized.'}), 404

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    max_chars = m.get_limit(user_doc, 'max_chars_per_note')
    content = content[:max_chars]

    # Snapshot for version control
    if note.get('content'):
        editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)
        m.note_versions_conf.insert_one({
            'note_id': obj_id,
            'share_id': None,
            'editor_name': editor_name,
            'editor_id': ObjectId(current_user.id),
            'content': note['content'],
            'content_owner_id': note.get('content_owner_id', note.get('user_id')),
            'encrypted': note.get('encrypted', True),
            'event_type': 'snapshot',
            'status': 'applied',
            'edit_summary': edit_summary or 'Edited note via App',
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })
        version_count = m.note_versions_conf.count_documents({'note_id': obj_id})
        if version_count > 50:
            oldest = m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', 1).limit(version_count - 50)
            for old_ver in oldest:
                m.note_versions_conf.delete_one({'_id': old_ver['_id']})

    encrypted_content = m.encrypt_note(content, user_id=current_user.id)
    now = datetime.datetime.now(datetime.timezone.utc)
    m.personal_posts_conf.update_one(
        {'_id': obj_id},
        {'$set': {
            'content': encrypted_content,
            'encrypted': True,
            'content_owner_id': ObjectId(current_user.id),
            'reference': reference,
            'tags': tags,
            'updated_at': now
        }}
    )

    m.index_note_to_meili(str(obj_id), decrypted_content=content)

    return jsonify({'success': True, 'id': str(obj_id)})

@api_bp.route('/premium/activate', methods=['POST'])
@login_required
def api_activate_premium():
    m = get_main_globals()
    # Grant premium for 30 days
    new_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'account_tier': 'premium', 'premium_until': new_until}}
    )
    return jsonify({
        'success': True,
        'message': 'Premium activated successfully!',
        'premium_until': new_until.isoformat()
    })

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
    m = get_main_globals()
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    has_pin = bool(user and user.get('app_lock_pin_hash'))

    unlock_ts = session.get('app_lock_unlocked_at')
    if not unlock_ts:
        return jsonify({'unlocked': False, 'has_pin': has_pin})
    
    if unlock_ts.tzinfo is None:
        unlock_ts = unlock_ts.replace(tzinfo=datetime.timezone.utc)
        
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
    if elapsed >= 300:
        session.pop('app_lock_unlocked_at', None)
        return jsonify({'unlocked': False, 'has_pin': has_pin})
        
    return jsonify({'unlocked': True, 'has_pin': has_pin, 'remaining': int(300 - elapsed)})

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

    is_valentine = False
    surprise_theme = 'none'
    valentine_photo = None
    valentine_audio = None
    use_typewriter = False
    auto_approve = False

    if request.is_json:
        data = request.get_json(silent=True) or {}
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
        # Handle multipart/form-data
        permissions = request.form.get('permissions', 'view')
        expires_in = request.form.get('expires_in')
        access_code = request.form.get('access_code')
        surprise_theme = request.form.get('surprise_theme', 'none')
        is_valentine = request.form.get('is_valentine') == 'true'
        if is_valentine and surprise_theme == 'none':
            surprise_theme = 'valentine'
        use_typewriter = request.form.get('use_typewriter') == 'true'
        auto_approve = request.form.get('auto_approve') == 'true'
        
        # Handle file uploads
        if surprise_theme != 'none':
            photo_file = request.files.get('valentine_photo')
            audio_file = request.files.get('valentine_audio')
            
            # --- Premium check for media uploads ---
            has_media = False
            if photo_file and photo_file.filename:
                has_media = True
            if audio_file and audio_file.filename:
                has_media = True
                
            if has_media and not m.is_premium(user_doc):
                return jsonify({
                    'error': 'Uploading custom photos and music to surprise notes is a Premium feature. Upgrade to unlock!',
                    'upgrade': True
                }), 403

            if photo_file and photo_file.filename:
                ext = photo_file.filename.rsplit('.', 1)[1].lower() if '.' in photo_file.filename else ''
                if ext in m.ALLOWED_IMAGE_EXTENSIONS:
                    try:
                        upload_result = m.cloudinary.uploader.upload(photo_file, folder="echowithin_valentine")
                        valentine_photo = upload_result.get('secure_url')
                    except Exception as e:
                        m.app.logger.error(f"Valentine photo upload failed: {e}")

            if audio_file and audio_file.filename:
                ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''
                if ext in m.ALLOWED_AUDIO_EXTENSIONS:
                    try:
                        audio_file.seek(0)
                        upload_result = m.cloudinary.uploader.upload(audio_file, resource_type="auto", folder="echowithin_valentine")
                        valentine_audio = upload_result.get('secure_url')
                    except Exception as e:
                        m.app.logger.error(f"Valentine audio upload failed: {e}")

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
        auto_approve = False  # silently downgrade

    m.note_shares_conf.insert_one({
        'share_id': share_id,
        'note_id': obj_id,
        'owner_id': ObjectId(current_user.id),
        'permissions': permissions,
        'surprise_theme': surprise_theme,
        'valentine_photo': m.encrypt_note(valentine_photo, user_id=current_user.id) if valentine_photo else None,
        'valentine_audio': m.encrypt_note(valentine_audio, user_id=current_user.id) if valentine_audio else None,
        'valentine_photo_hash': hashlib.sha256(valentine_photo.encode()).hexdigest() if valentine_photo else None,
        'valentine_audio_hash': hashlib.sha256(valentine_audio.encode()).hexdigest() if valentine_audio else None,
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
            'content': m.decrypt_note(v['content'], user_id=current_user.id) if v.get('encrypted', False) else v.get('content', ''),
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


@api_bp.route('/notes/toggle_lock/<post_id>', methods=['POST'])
@login_required
def api_toggle_note_lock(post_id):
    m = get_main_globals()
    obj_id = safe_obj_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    new_locked = not note.get('is_locked', False)
    m.personal_posts_conf.update_one(
        {'_id': obj_id},
        {'$set': {'is_locked': new_locked}}
    )
    return jsonify({'success': True, 'is_locked': new_locked})


@api_bp.route('/notes/proposals', methods=['GET'])
@login_required
def api_get_all_proposals():
    m = get_main_globals()
    user_notes = list(m.personal_posts_conf.find(
        {'user_id': ObjectId(current_user.id)},
        {'_id': 1, 'content': 1}
    ))
    note_ids = [n['_id'] for n in user_notes]
    note_map = {str(n['_id']): (m.decrypt_note(n['content']) if isinstance(n.get('content'), bytes) else n.get('content', ''))[:80] for n in user_notes}

    proposals = list(m.note_versions_conf.find({
        'note_id': {'$in': note_ids},
        'is_proposal': True,
        'status': {'$in': ['pending', None]}
    }).sort('created_at', -1))

    result = []
    for p in proposals:
        result.append({
            'version_id': str(p['_id']),
            'note_id': str(p['note_id']),
            'note_preview': note_map.get(str(p['note_id']), 'Unknown note'),
            'content': m.decrypt_note(p['content']) if p.get('encrypted', False) else p.get('content', ''),
            'author_username': p.get('author_username', 'Unknown'),
            'created_at': p.get('created_at').isoformat() if p.get('created_at') else None,
            'status': p.get('status', 'pending')
        })
    return jsonify({'proposals': result})


@api_bp.route('/profile', methods=['GET'])
@login_required
def api_profile():
    m = get_main_globals()
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    is_prem = m.is_premium(user)
    return jsonify({
        'username': user['username'],
        'email': user['email'],
        'account_tier': 'premium' if is_prem else 'free',
        'premium_until': user.get('premium_until').isoformat() if user.get('premium_until') else None,
        'has_pin': bool(user.get('app_lock_pin_hash'))
    })

@api_bp.route('/notes/delete/<note_id>', methods=['POST'])
@login_required
def api_delete_note(note_id):
    m = get_main_globals()
    obj_id = safe_obj_id(note_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID.'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized.'}), 404

    target_ids = [obj_id]
    
    # 1. Cleanup all share links and their media for target notes
    shares = m.note_shares_conf.find({'note_id': {'$in': target_ids}})
    for share in shares:
        m.cleanup_share_media(share)
        m.note_shares_conf.delete_one({'_id': share['_id']})

    # 1.5. Cleanup media from the posts themselves before deleting
    target_posts = m.personal_posts_conf.find({'_id': {'$in': target_ids}})
    for post in target_posts:
        m.cleanup_post_media(post)

    # 2. Cleanup all versions for target notes
    m.note_versions_conf.delete_many({'note_id': {'$in': target_ids}})

    # 3. Cleanup all unlock notifications for target notes
    m.unlock_notifications_conf.delete_many({'note_id': {'$in': target_ids}})

    # 4. Remove from Meilisearch index
    try:
        m.remove_notes_from_meili(target_ids)
    except Exception:
        pass

    # 5. Final: Delete entries from personal_posts_conf
    m.personal_posts_conf.delete_many({'_id': {'$in': target_ids}})

    return jsonify({'success': True, 'message': 'Note deleted successfully.'})



