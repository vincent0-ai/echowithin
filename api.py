import datetime
import secrets
import hashlib
from flask import Blueprint, request, jsonify, session, url_for, make_response
from flask_login import login_required, current_user, login_user, logout_user
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash

# Create the API blueprint
api_bp = Blueprint('api_v1', __name__)
# --- Helper functions ---
def safe_obj_id(val):
    try:
        return ObjectId(val)
    except Exception:
        return None

# --- AUTHENTICATION ENDPOINTS ---

@api_bp.route('/register', methods=['POST'])
def api_register():
    import main as m
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
    import main as m
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
    import main as m
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
    import main as m
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
    import main as m
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
        
        # Calculate if update is available
        source_note_id = note.get('source_note_id')
        update_available = False
        if source_note_id:
            orig = m.personal_posts_conf.find_one({'_id': source_note_id})
            if orig:
                orig_ts = orig.get('updated_at') or orig.get('created_at')
                clone_ts = note.get('updated_at') or note.get('created_at')
                if orig_ts and clone_ts:
                    if orig_ts.tzinfo is None:
                        orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                    if clone_ts.tzinfo is None:
                        clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                    if orig_ts > clone_ts:
                        try:
                            orig_decrypted = m._decrypt_note_record(orig)
                            if content_plain != orig_decrypted:
                                update_available = True
                        except Exception:
                            update_available = True

        formatted_notes.append({
            'id': str(note['_id']),
            'content': content_plain,
            'reference': note.get('reference', ''),
            'tags': note.get('tags', []),
            'is_locked': note.get('is_locked', False),
            'is_pinned': note.get('is_pinned', False),
            'update_available': update_available,
            'source_note_id': str(note['source_note_id']) if note.get('source_note_id') else None,
            'source_share_id': note.get('source_share_id'),
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
    import main as m
    obj_id = safe_obj_id(note_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID.'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found.'}), 404

    content_plain = m._decrypt_note_record(note)
    
    # Calculate if update is available
    source_note_id = note.get('source_note_id')
    update_available = False
    if source_note_id:
        orig = m.personal_posts_conf.find_one({'_id': source_note_id})
        if orig:
            orig_ts = orig.get('updated_at') or orig.get('created_at')
            clone_ts = note.get('updated_at') or note.get('created_at')
            if orig_ts and clone_ts:
                if orig_ts.tzinfo is None:
                    orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                if clone_ts.tzinfo is None:
                    clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                if orig_ts > clone_ts:
                    try:
                        orig_decrypted = m._decrypt_note_record(orig)
                        if content_plain != orig_decrypted:
                            update_available = True
                    except Exception:
                        update_available = True

    return jsonify({
        'id': str(note['_id']),
        'content': content_plain,
        'reference': note.get('reference', ''),
        'tags': note.get('tags', []),
        'is_locked': note.get('is_locked', False),
        'is_pinned': note.get('is_pinned', False),
        'update_available': update_available,
        'source_note_id': str(note['source_note_id']) if note.get('source_note_id') else None,
        'source_share_id': note.get('source_share_id'),
        'created_at': note.get('created_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('created_at') else None,
        'updated_at': note.get('updated_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('updated_at') else None
    })

@api_bp.route('/notes/previews', methods=['POST'])
@login_required
def api_get_note_previews():
    """Batch-decrypt note content for lazy-loading on the notes list page."""
    import main as m
    data = request.get_json(silent=True) or {}
    note_ids = data.get('ids', [])
    if not note_ids or len(note_ids) > 50:
        return jsonify({'error': 'Provide 1-50 note IDs.'}), 400

    obj_ids = []
    for nid in note_ids:
        oid = safe_obj_id(nid)
        if oid:
            obj_ids.append(oid)

    if not obj_ids:
        return jsonify({'previews': {}})

    notes = list(m.personal_posts_conf.find({
        '_id': {'$in': obj_ids},
        'user_id': ObjectId(current_user.id)
    }))

    previews = {}
    for note in notes:
        try:
            content = m._decrypt_note_record(note)
        except Exception:
            content = ''
        previews[str(note['_id'])] = content or ''

    return jsonify({'previews': previews})

@api_bp.route('/notes/create', methods=['POST'])
@login_required
def api_create_note():
    import main as m
    data = request.get_json(silent=True) or {}
    content = data.get('content', '').strip()
    reference = data.get('reference', '').strip()[:200]
    tags = data.get('tags', [])

    if not content:
        return jsonify({'error': 'Content cannot be empty.'}), 400

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    # Safety: if DB lookup fails, fall back to current_user's cached tier
    max_notes = m.get_limit(user_doc, 'max_notes') if user_doc else current_user.get_limit('max_notes')
    max_chars = m.get_limit(user_doc, 'max_chars_per_note') if user_doc else current_user.get_limit('max_chars_per_note')
    current_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id)})
    
    if current_count >= max_notes:
        return jsonify({'error': f'You have reached the limit of {max_notes} notes. Upgrade to Premium!'}), 403

    raw_len = len(content)
    content = content[:max_chars]
    if raw_len > max_chars:
        m.app.logger.warning(f"API note truncated for user {current_user.username} (tier={current_user.account_tier}): {raw_len} -> {max_chars} chars")
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
    
    m.index_note_to_typesense(str(result.inserted_id), decrypted_content=content)
    
    return jsonify({'success': True, 'id': str(result.inserted_id)})

@api_bp.route('/notes/edit/<note_id>', methods=['POST'])
@login_required
def api_edit_note(note_id):
    import main as m
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
    # Safety: if DB lookup fails, fall back to current_user's cached tier
    max_chars = m.get_limit(user_doc, 'max_chars_per_note') if user_doc else current_user.get_limit('max_chars_per_note')
    raw_len = len(content)
    content = content[:max_chars]
    if raw_len > max_chars:
        m.app.logger.warning(f"API edit truncated for user {current_user.username} (tier={current_user.account_tier}): {raw_len} -> {max_chars} chars")

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

    m.index_note_to_typesense(str(obj_id), decrypted_content=content)

    return jsonify({'success': True, 'id': str(obj_id)})

@api_bp.route('/premium/activate', methods=['POST'])
@login_required
def api_activate_premium():
    import main as m
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
    import main as m
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
    import main as m
    data = request.get_json(silent=True) or {}
    pin = data.get('pin', '').strip()

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No PIN setup found.'}), 404

    if check_password_hash(user['app_lock_pin_hash'], pin):
        session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
        return jsonify({'success': True})
    else:
        # SECURITY NOTE: Return 200 with success:false (NOT 401).
        # 401 would trip the Android client's global 401 interceptor and
        # silently sign the user out of the app every time they fat-finger
        # their PIN, which is a brutal UX bug. Wrong-PIN is a validation
        # failure, not an auth failure.
        return jsonify({'success': False, 'error': 'Incorrect PIN.'})

@api_bp.route('/app_lock/check_status', methods=['GET'])
@login_required
def api_app_lock_status():
    import main as m
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
    import main as m
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
    import main as m
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
    import main as m
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'error': 'Token cannot be empty.'}), 400

    m.fcm_tokens_conf.delete_one({'user_id': ObjectId(current_user.id), 'token': token})
    return jsonify({'success': True, 'message': 'FCM Token unregistered.'})


# --- NOTE SHARING & COLLABORATION ---

@api_bp.route('/notes/shares', methods=['GET'])
@login_required
def api_list_all_active_shares():
    """Returns every active share link owned by the current user across all
    of their notes. Used by the Android 'Shared Links' tab so the app does
    not have to loop over every note in the user's library (and silently miss
    shares for notes that are not currently in the local cache).
    Each entry carries enough metadata to render a card without a second
    round-trip (note title, permissions, theme, expiry).
    """
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    shares = list(m.note_shares_conf.find({
        'owner_id': ObjectId(current_user.id),
        '$or': [
            {'expires_at': None},
            {'expires_at': {'$exists': False}},
            {'expires_at': {'$gt': now}},
        ],
    }).sort('created_at', -1))

    if not shares:
        return jsonify({'shares': [], 'count': 0})

    note_ids = list({s['note_id'] for s in shares if s.get('note_id') is not None})
    notes_cursor = m.personal_posts_conf.find(
        {'_id': {'$in': note_ids}, 'user_id': ObjectId(current_user.id)},
        {'_id': 1, 'content': 1}
    )
    note_map = {}
    for n in notes_cursor:
        try:
            plain = m.decrypt_note(n['content'], user_id=current_user.id) if n.get('content') else ''
        except Exception:
            plain = ''
        first_line = (plain or '').splitlines()[0].strip() if plain else ''
        note_map[n['_id']] = (first_line[:80] if first_line else 'Untitled note')

    result = []
    for s in shares:
        result.append({
            'share_id': s.get('share_id'),
            'note_id': str(s['note_id']) if s.get('note_id') else None,
            'note_title': note_map.get(s.get('note_id'), 'Untitled note'),
            'permissions': s.get('permissions', 'view'),
            'surprise_theme': s.get('surprise_theme', 'none'),
            'use_typewriter': bool(s.get('use_typewriter', False)),
            'auto_approve': bool(s.get('auto_approve', False)),
            'created_at': s.get('created_at').isoformat() if s.get('created_at') else None,
            'expires_at': s.get('expires_at').isoformat() if s.get('expires_at') else None,
            'has_password': bool(s.get('access_code_hash')),
        })
    return jsonify({'shares': result, 'count': len(result)})


@api_bp.route('/notes/shares/<post_id>', methods=['GET'])
@login_required
def api_get_note_shares(post_id):
    import main as m
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
    import main as m
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
        'url': url_for('sharing.view_shared_note', share_id=share_id, _external=True)
    })

@api_bp.route('/notes/revoke_share/<share_id>', methods=['POST'])
@login_required
def api_revoke_note_share(share_id):
    import main as m
    result = m.note_shares_conf.delete_one({'share_id': share_id, 'owner_id': ObjectId(current_user.id)})
    if result.deleted_count == 0:
        return jsonify({'error': 'Share link not found or unauthorized'}), 404
    return jsonify({'success': True, 'message': 'Share link revoked.'})


# --- COLLABORATIVE SHARE WORKSPACE (COMMENTS & ATTACHMENTS) ---

@api_bp.route('/notes/share/<share_id>/attachments', methods=['GET'])
@login_required
def api_get_share_attachments(share_id):
    import main as m
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
    import main as m
    obj_id = safe_obj_id(post_id)
    if not obj_id:
        return jsonify({'error': 'Invalid note ID'}), 400

    note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found or unauthorized'}), 404

    current_plain = m._decrypt_note_record(note)
    versions = list(m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', -1).limit(50))
    note_candidates = m._candidate_user_ids(
        note.get('content_owner_id'),
        note.get('user_id'),
        current_user.id
    )

    result = []
    for v in versions:
        event_type = v.get('event_type', 'snapshot')
        status = v.get('status', 'applied')

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
            decrypted = proposed_plain
        else:
            if not v.get('encrypted', True):
                decrypted = v.get('content', '')
            else:
                decrypted = m._decrypt_with_candidate_ids(v.get('content', ''), version_candidates)
                if decrypted is None:
                    decrypted = '[Content unavailable — decryption error]'

        result.append({
            'version_id': str(v['_id']),
            'content': decrypted,
            'author_username': v.get('editor_name', v.get('author_username', 'Unknown')),
            'created_at': v['created_at'].replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if v.get('created_at') else None,
            'is_proposal': event_type == 'proposal',
            'status': 'pending' if status == 'pending' else ('approved' if status == 'accepted' else 'rejected'),
            'review_comment': v.get('edit_summary', v.get('review_comment', ''))
        })
    return jsonify({'versions': result})

@api_bp.route('/notes/version/restore/<post_id>/<version_id>', methods=['POST'])
@login_required
def api_restore_note_version(post_id, version_id):
    import main as m
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

    if version.get('event_type', 'snapshot') != 'snapshot':
        return jsonify({'error': 'Only snapshot versions can be restored'}), 400

    now = datetime.datetime.now(datetime.timezone.utc)
    if note.get('content'):
        m.note_versions_conf.insert_one({
            'note_id': post_obj_id,
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
        {'_id': post_obj_id},
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

    return jsonify({'success': True, 'message': 'Note restored to specified version.'})

@api_bp.route('/notes/proposal/<version_id>/decision', methods=['POST'])
@login_required
def api_proposal_decision(version_id):
    import main as m
    ver_obj_id = safe_obj_id(version_id)
    if not ver_obj_id:
        return jsonify({'error': 'Invalid proposal ID'}), 400

    proposal = m.note_versions_conf.find_one({'_id': ver_obj_id})
    if not proposal or proposal.get('event_type') != 'proposal':
        return jsonify({'error': 'Proposal not found'}), 404

    note_id = proposal.get('note_id')
    note = m.personal_posts_conf.find_one({'_id': note_id, 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json(silent=True) or {}
    decision = data.get('decision')  # 'approve' or 'reject'
    comment = data.get('comment', '').strip()

    if decision not in ['approve', 'accept', 'reject']:
        return jsonify({'error': 'Decision must be approve/accept or reject.'}), 400

    decision_mapped = 'accept' if decision in ('approve', 'accept') else 'reject'
    now = datetime.datetime.now(datetime.timezone.utc)

    if decision_mapped == 'accept':
        proposed = proposal.get('proposed_content', '')
        # Encrypt with the note owner's key
        encrypted = m.encrypt_note(m._decrypt_with_candidate_ids(proposed, m._candidate_user_ids(proposal.get('content_owner_id'), proposal.get('editor_id'), current_user.id)) or proposed, user_id=current_user.id)
        
        m.personal_posts_conf.update_one(
            {'_id': note_id},
            {'$set': {
                'content': encrypted,
                'encrypted': True,
                'content_owner_id': ObjectId(current_user.id),
                'updated_at': now
            }}
        )
        
        note_candidates = m._candidate_user_ids(note.get('content_owner_id'), note.get('user_id'), current_user.id)
        version_candidates = m._candidate_user_ids(proposal.get('content_owner_id'), proposal.get('editor_id'), *note_candidates)
        final_plain = m._decrypt_with_candidate_ids(proposed, version_candidates) or m.decrypt_note(proposed, user_id=str(proposal.get('content_owner_id') or current_user.id))
        m.index_note_to_typesense(str(note_id), decrypted_content=final_plain)

        # Broadcast update
        try:
            m.socketio.emit('note_changed', {'content': final_plain}, room=proposal.get('share_id'))
        except Exception:
            pass

    m.note_versions_conf.update_one(
        {'_id': ver_obj_id},
        {'$set': {
            'status': 'accepted' if decision_mapped == 'accept' else 'rejected',
            'review_comment': comment or 'Reviewed proposal',
            'is_read_by_owner': True,
            'reviewed_at': now
        }}
    )

    return jsonify({'success': True, 'message': f'Proposal successfully {decision_mapped}ed.'})



# --- APP RE-AUTHENTICATION (Persistent Token) ---

@api_bp.route('/app_reauth', methods=['POST'])
def api_app_reauth():
    """Re-authenticate a native app user using a persistent token.
    Accepts token from JSON body, Authorization header, or httpOnly cookie."""
    import main as m
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
    import main as m
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
    import main as m
    user_notes = list(m.personal_posts_conf.find(
        {'user_id': ObjectId(current_user.id)},
        {'_id': 1, 'content': 1}
    ))
    note_ids = [n['_id'] for n in user_notes]
    note_map = {str(n['_id']): (m.decrypt_note(n['content'], user_id=current_user.id) if isinstance(n.get('content'), (str, bytes)) else n.get('content', ''))[:80] for n in user_notes}

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
            'content': m.decrypt_note(p['content'], user_id=current_user.id) if p.get('encrypted', False) else p.get('content', ''),
            'author_username': p.get('author_username', 'Unknown'),
            'created_at': p.get('created_at').isoformat() if p.get('created_at') else None,
            'status': p.get('status', 'pending')
        })
    return jsonify({'proposals': result})


@api_bp.route('/profile', methods=['GET'])
@login_required
def api_profile():
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    is_prem = m.is_premium(user)
    is_trial = m.is_on_trial(user)
    trial_days = m.get_trial_days_remaining(user)
    return jsonify({
        'username': user['username'],
        'email': user['email'],
        'account_tier': 'premium' if is_prem else 'free',
        'premium_until': user.get('premium_until').isoformat() if user.get('premium_until') else None,
        'has_pin': bool(user.get('app_lock_pin_hash')),
        'is_trial': is_trial,
        'trial_days_remaining': trial_days
    })


# --- ACTIVITY / NOTIFICATIONS ---

@api_bp.route('/posts/my-commented', methods=['GET'])
@login_required
def api_my_commented_activity():
    """Recent community/blog activity relevant to the current user
    (posts they commented on, replied to, or that reacted to their
    content). Powers the Android Activity tab. The exact shape mirrors
    the NotificationDto the Android client already expects, so no client
    schema change is needed.
    """
    import main as m
    try:
        user_oid = ObjectId(current_user.id)
        user_comments = list(m.comments_conf.find(
            {'user_id': user_oid, 'is_deleted': False}
        ).sort('created_at', -1).limit(50))

        notifications = []
        for c in user_comments:
            slug = c.get('post_slug')
            if not slug:
                continue
            post = m.posts_conf.find_one({'slug': slug}, {'title': 1, 'author_id': 1, 'timestamp': 1})
            if not post:
                continue
            author = m.users_conf.find_one({'_id': post.get('author_id')}, {'username': 1}) if post.get('author_id') else None
            last_activity = c.get('created_at') or post.get('timestamp') or datetime.datetime.now(datetime.timezone.utc)
            last_activity_iso = last_activity.isoformat() if hasattr(last_activity, 'isoformat') else str(last_activity)

            # Upsert a per-(user, comment) read-flag row so we can answer
            # "is this notification unread?" with a single find_one AND
            # so mark-all-read has a stable target to update.
            try:
                m.activity_read_conf.update_one(
                    {'user_id': user_oid, 'comment_id': c['_id']},
                    {'$setOnInsert': {
                        'user_id': user_oid,
                        'comment_id': c['_id'],
                        'read_at': None,
                        'created_at': datetime.datetime.now(datetime.timezone.utc),
                    }},
                    upsert=True
                )
            except Exception:
                pass

            read_flag_doc = m.activity_read_conf.find_one({'user_id': user_oid, 'comment_id': c['_id']})
            is_unread = read_flag_doc is not None and read_flag_doc.get('read_at') is None
            notifications.append({
                '_id': str(c['_id']),
                'title': post.get('title', 'Untitled post'),
                'content': c.get('content', '')[:200],
                'author': author.get('username', 'Unknown') if author else 'Unknown',
                'timestamp': last_activity_iso,
                'has_unread': is_unread,
                'activity_type': 'comment',
                'share_id': None,
                'surprise_theme': 'none',
            })
        unread_count = sum(1 for n in notifications if n['has_unread'])
        return jsonify({'posts': notifications, 'unread_count': unread_count})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'posts': [], 'unread_count': 0, 'error': str(e)}), 200


@api_bp.route('/notifications/badge-counts', methods=['GET'])
@login_required
def api_badge_counts():
    import main as m
    try:
        user_oid = ObjectId(current_user.id)
        notif_count = m.activity_read_conf.count_documents({'user_id': user_oid, 'read_at': None}) if False else 0
    except Exception:
        notif_count = 0
    return jsonify({'notif_count': notif_count, 'msg_count': 0})


@api_bp.route('/posts/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_posts_read():
    """Marks every community activity notification as read for the
    current user. Idempotent: safe to call on every Activity-tab
    visit. Returns the number of items marked so the client can show
    a 'N items cleared' toast.
    """
    import main as m
    try:
        user_oid = ObjectId(current_user.id)
        # Mark every previously-unread activity_read_conf row for this user.
        result = m.activity_read_conf.update_many(
            {'user_id': user_oid, 'read_at': None},
            {'$set': {'read_at': datetime.datetime.now(datetime.timezone.utc)}},
            upsert=False
        )
        return jsonify({'success': True, 'marked': result.modified_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 200


@api_bp.route('/activity/mark_read', methods=['POST'])
@login_required
def api_mark_all_proposals_read():
    """Marks every pending collaboration proposal as read for the
    current user. (The proposals stay 'pending' on the server; we
    only mark the local read flag so the badge clears on the device.)
    """
    import main as m
    try:
        user_oid = ObjectId(current_user.id)
        user_note_ids = [n['_id'] for n in m.personal_posts_conf.find({'user_id': user_oid}, {'_id': 1})]
        result = m.note_versions_conf.update_many(
            {'note_id': {'$in': user_note_ids}, 'is_proposal': True, 'read_at': None},
            {'$set': {'read_at': datetime.datetime.now(datetime.timezone.utc)}}
        )
        return jsonify({'success': True, 'marked': result.modified_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 200


@api_bp.route('/notes/delete/<note_id>', methods=['POST'])
@login_required
def api_delete_note(note_id):
    import main as m
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

    # 4. Remove from Typesense index
    try:
        m.remove_notes_from_typesense(target_ids)
    except Exception:
        pass

    # 5. Final: Delete entries from personal_posts_conf
    m.personal_posts_conf.delete_many({'_id': {'$in': target_ids}})

    return jsonify({'success': True, 'message': 'Note deleted successfully.'})

@api_bp.route('/notes/dedup', methods=['POST'])
@login_required
def api_dedup_notes():
    """
    One-shot duplicate-note cleanup. Earlier Android builds (pre-v1.7.1)
    could re-push already-synced notes as new CREATEs when the local sync
    flag got reset on logout, which left the user with two copies of the
    same note. This endpoint groups the user's notes by their decrypted
    content and, for each group of 2+, keeps the OLDEST and deletes the
    rest (plus their shares / versions / Typesense entries).

    Query params:
        confirm=true   Actually perform the deletions. Without this flag the
                       endpoint runs in dry-run mode and just returns the
                       groups that *would* be removed.
    """
    import main as m

    confirm = (request.args.get('confirm', '').lower() == 'true')
    user_id = ObjectId(current_user.id)

    # 1. Fetch all notes owned by the current user
    user_notes = list(m.personal_posts_conf.find({'user_id': user_id}))
    if not user_notes:
        return jsonify({'success': True, 'removed_count': 0, 'kept_count': 0, 'groups': []})

    # 2. Decrypt + normalize content for grouping
    def normalize(text):
        if not text:
            return ''
        # collapse all whitespace, strip, lowercase — so trivial differences
        # (trailing newlines, double spaces) don't spawn false "duplicates"
        return ' '.join(text.split()).strip().lower()

    decrypted = {}
    for n in user_notes:
        raw = n.get('content', '')
        plain = raw
        if n.get('encrypted'):
            try:
                plain = m.decrypt_note(raw, user_id=str(user_id))
            except Exception:
                # If we can't decrypt, skip this note from dedup — better
                # safe than accidentally deleting an unreadable note.
                continue
        decrypted[n['_id']] = (normalize(plain), plain)

    # 3. Group by normalized content
    groups_by_key = {}
    for nid, (key, _) in decrypted.items():
        groups_by_key.setdefault(key, []).append(nid)

    # Build a lookup from note id to its full document (used by the sort
    # below to compare created_at). Defined BEFORE the loop so the lambda
    # can close over it.
    user_notes_by_id = {n['_id']: n for n in user_notes}

    # 4. For each group with 2+ notes, keep oldest, mark rest for deletion
    groups_summary = []
    ids_to_delete = []
    epoch_floor = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    for key, ids in groups_by_key.items():
        if len(ids) < 2:
            continue
        # Sort by created_at ascending — oldest is index 0
        sorted_ids = sorted(
            ids,
            key=lambda i: user_notes_by_id[i].get('created_at') or epoch_floor
        )
        kept_id = sorted_ids[0]
        removed_ids = sorted_ids[1:]
        groups_summary.append({
            'kept_id': str(kept_id),
            'removed_ids': [str(i) for i in removed_ids],
            'removed_count': len(removed_ids)
        })
        ids_to_delete.extend(removed_ids)

    if not confirm:
        return jsonify({
            'success': True,
            'dry_run': True,
            'removed_count': len(ids_to_delete),
            'kept_count': len(groups_summary),
            'groups': groups_summary
        })

    if not ids_to_delete:
        return jsonify({
            'success': True,
            'removed_count': 0,
            'kept_count': 0,
            'groups': []
        })

    # 5. Cleanup shares / versions / unlock-notifications / Typesense /
    # personal_posts_conf for the marked duplicates — same housekeeping the
    # normal delete endpoint does.
    shares = m.note_shares_conf.find({'note_id': {'$in': ids_to_delete}})
    for share in shares:
        m.cleanup_share_media(share)
        m.note_shares_conf.delete_one({'_id': share['_id']})

    target_posts = m.personal_posts_conf.find({'_id': {'$in': ids_to_delete}})
    for post in target_posts:
        m.cleanup_post_media(post)

    m.note_versions_conf.delete_many({'note_id': {'$in': ids_to_delete}})
    m.unlock_notifications_conf.delete_many({'note_id': {'$in': ids_to_delete}})

    try:
        m.remove_notes_from_typesense(ids_to_delete)
    except Exception:
        pass

    m.personal_posts_conf.delete_many({'_id': {'$in': ids_to_delete}})

    m.app.logger.info(
        f"Dedup for user {current_user.username}: removed {len(ids_to_delete)} duplicates "
        f"across {len(groups_summary)} groups"
    )

    return jsonify({
        'success': True,
        'removed_count': len(ids_to_delete),
        'kept_count': len(groups_summary),
        'groups': groups_summary
    })


@api_bp.route('/notes/<note_id>/sync', methods=['POST'])
@login_required
def api_sync_note(note_id):
    import main as m
    try:
        obj_id = safe_obj_id(note_id)
        if not obj_id:
            return jsonify({'error': 'Invalid note ID'}), 400

        # Find the cloned note owned by current user
        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Note not found or unauthorized'}), 404

        source_note_id = note.get('source_note_id')
        source_share_id = note.get('source_share_id')
        if not source_note_id:
            return jsonify({'error': 'This note is not a saved copy — nothing to sync'}), 400

        # Verify the share still exists and grants edit permission
        if source_share_id:
            share = m.note_shares_conf.find_one({'share_id': source_share_id})
            if not share:
                return jsonify({'error': 'The original share link no longer exists'}), 404
            if share.get('permissions') != 'edit':
                return jsonify({'error': 'You need edit permission to sync with the original'}), 403
            # Check expiration
            if share.get('expires_at'):
                expires_at = share['expires_at']
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
                if datetime.datetime.now(datetime.timezone.utc) > expires_at:
                    return jsonify({'error': 'The share link has expired'}), 410
        else:
            return jsonify({'error': 'No share link associated with this copy'}), 400

        # Fetch the original note
        original_note = m.personal_posts_conf.find_one({'_id': source_note_id})
        if not original_note:
            return jsonify({'error': 'Original note no longer exists', 'code': 'original_missing'}), 410

        now = datetime.datetime.now(datetime.timezone.utc)
        editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)

        # Determine sync direction by comparing last-modified timestamps
        clone_modified = note.get('updated_at') or note.get('created_at') or now
        original_modified = original_note.get('updated_at') or original_note.get('created_at') or now
        # Ensure timezone-aware comparison
        if clone_modified.tzinfo is None:
            clone_modified = clone_modified.replace(tzinfo=datetime.timezone.utc)
        if original_modified.tzinfo is None:
            original_modified = original_modified.replace(tzinfo=datetime.timezone.utc)

        # Check if content is actually different by comparing decrypted plaintexts
        clone_decrypted = m._decrypt_note_record(note)
        original_decrypted = m._decrypt_note_record(original_note, share)
        if clone_decrypted == original_decrypted:
            return jsonify({
                'success': True,
                'content': clone_decrypted,
                'direction': 'none',
                'message': 'Already in sync.'
            })

        if clone_modified > original_modified:
            # --- PUSH: Clone is newer → push clone's content to the original ---
            original_owner_id = str(original_note.get('user_id', ''))
            is_owner_of_original = str(current_user.id) == original_owner_id

            auto_approved_users = share.get('auto_approved_users', [])
            is_user_auto_approved = ObjectId(current_user.id) in auto_approved_users

            if not is_owner_of_original and not share.get('auto_approve', False) and not is_user_auto_approved:
                # Contributor flow: create a pending proposal instead of overwriting.
                m.note_versions_conf.insert_one({
                    'note_id': source_note_id,
                    'share_id': source_share_id,
                    'editor_name': editor_name + ' (Sync)',
                    'editor_id': ObjectId(current_user.id),
                    'content': original_note.get('content', ''),
                    'base_content': original_note.get('content', ''),
                    'content_owner_id': ObjectId(original_owner_id),
                    'proposed_content': note.get('content'),
                    'encrypted': True,
                    'event_type': 'proposal',
                    'status': 'pending',
                    'edit_summary': 'Synced changes from my saved copy',
                    'created_at': now,
                    'is_read_by_owner': False
                })
                
                # Notify original owner sessions.
                try:
                    m.socketio.emit('note_proposal_created', {
                        'share_id': source_share_id,
                        'note_id': str(source_note_id),
                        'editor_name': editor_name,
                        'summary': 'Synced changes from a saved copy'
                    }, room=original_owner_id)
                except Exception:
                    pass

                # Push notification for owner devices
                try:
                    if original_owner_id:
                        m.send_push_notification_to_user(
                            original_owner_id,
                            f"{editor_name} proposed note changes",
                            "A collaborator submitted updates for your review.",
                            url=url_for('personal_space', _external=True) + '#activity',
                            tag=f'note-proposal-{source_note_id}',
                            extra_data={'type': 'note_proposal', 'note_id': str(source_note_id), 'share_id': source_share_id}
                        )
                except Exception as notify_err:
                    m.app.logger.error(f"Failed to send proposal push notification to owner {original_owner_id}: {notify_err}")

                return jsonify({
                    'success': True,
                    'pending_approval': True,
                    'message': 'Changes submitted to the note owner for review.'
                })

            # Owner flow: direct push permitted.
            if original_note.get('content'):
                m.note_versions_conf.insert_one({
                    'note_id': source_note_id,
                    'share_id': source_share_id,
                    'editor_name': editor_name + ' (sync push)',
                    'editor_id': ObjectId(current_user.id),
                    'content': original_note['content'],
                    'content_owner_id': original_note.get('content_owner_id', original_note.get('user_id')),
                    'encrypted': original_note.get('encrypted', True),
                    'created_at': now,
                    'is_read_by_owner': False if not is_owner_of_original else True,
                    'is_auto_approved': True if not is_owner_of_original else False,
                    'event_type': 'snapshot'
                })
                
                if not is_owner_of_original:
                    try:
                        m.socketio.emit('note_auto_approved', {
                            'share_id': source_share_id,
                            'note_id': str(source_note_id),
                            'editor_name': editor_name,
                            'summary': 'Auto-synced changes from a saved copy'
                        }, room=original_owner_id)
                    except Exception:
                        pass
                version_count = m.note_versions_conf.count_documents({'note_id': source_note_id})
                if version_count > 50:
                    oldest = m.note_versions_conf.find({'note_id': source_note_id}).sort('created_at', 1).limit(version_count - 50)
                    for old_ver in oldest:
                        m.note_versions_conf.delete_one({'_id': old_ver['_id']})

            # Push clone content to original — re-encrypt with original owner's key
            # to prevent decryption failures when content_owner_id doesn't match the key.
            push_decrypted = m._decrypt_note_record(note, share)
            push_encrypted = m.encrypt_note(push_decrypted, user_id=original_owner_id) if push_decrypted and push_decrypted != '[Content unavailable \u2014 decryption error]' else note.get('content')
            push_owner_id = ObjectId(original_owner_id) if (push_decrypted and push_decrypted != '[Content unavailable \u2014 decryption error]') else note.get('content_owner_id', note.get('user_id'))
            m.personal_posts_conf.update_one(
                {'_id': source_note_id},
                {'$set': {
                    'content': push_encrypted,
                    'encrypted': True,
                    'content_owner_id': push_owner_id,
                    'reference': note.get('reference', ''),
                    'tags': note.get('tags', []),
                    'updated_at': now
                }}
            )

            # Re-index original in Typesense
            decrypted = push_decrypted if (push_decrypted and push_decrypted != '[Content unavailable \u2014 decryption error]') else m._decrypt_note_record(note, share)
            m.index_note_to_typesense(str(source_note_id), decrypted_content=decrypted)

            # Broadcast update to participants in the share room
            m.socketio.emit('note_changed', {'content': decrypted}, room=source_share_id)

            return jsonify({
                'success': True,
                'content': decrypted,
                'direction': 'push',
                'message': 'Your changes have been pushed to the original note.'
            })
        else:
            # --- PULL: Original is newer → pull original's content to the clone ---
            if note.get('content'):
                m.note_versions_conf.insert_one({
                    'note_id': obj_id,
                    'share_id': None,
                    'editor_name': editor_name + ' (sync pull)',
                    'editor_id': ObjectId(current_user.id),
                    'content': note['content'],
                    'content_owner_id': note.get('content_owner_id', note.get('user_id')),
                    'encrypted': note.get('encrypted', True),
                    'created_at': now
                })
                version_count = m.note_versions_conf.count_documents({'note_id': obj_id})
                if version_count > 50:
                    oldest = m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', 1).limit(version_count - 50)
                    for old_ver in oldest:
                        m.note_versions_conf.delete_one({'_id': old_ver['_id']})

            # Pull original content to clone — re-encrypt with clone owner's key
            # to prevent decryption failures when clone owner differs from original owner.
            pull_decrypted = m._decrypt_note_record(original_note, share)
            pull_encrypted = m.encrypt_note(pull_decrypted, user_id=str(current_user.id)) if pull_decrypted and pull_decrypted != '[Content unavailable \u2014 decryption error]' else original_note.get('content')
            pull_owner_id = ObjectId(current_user.id) if (pull_decrypted and pull_decrypted != '[Content unavailable \u2014 decryption error]') else original_note.get('content_owner_id', original_note.get('user_id'))
            m.personal_posts_conf.update_one(
                {'_id': obj_id},
                {'$set': {
                    'content': pull_encrypted,
                    'encrypted': True,
                    'content_owner_id': pull_owner_id,
                    'reference': original_note.get('reference', ''),
                    'tags': original_note.get('tags', []),
                    'updated_at': now
                }}
            )

            # Re-index clone in Typesense
            decrypted = pull_decrypted if (pull_decrypted and pull_decrypted != '[Content unavailable \u2014 decryption error]') else m._decrypt_note_record(original_note, share)
            m.index_note_to_typesense(note_id, decrypted_content=decrypted)

            # Broadcast to other sessions of the SAME USER
            m.socketio.emit('note_changed', {
                'note_id': note_id, 
                'content': decrypted,
                'reference': original_note.get('reference', ''),
                'tags': original_note.get('tags', [])
            }, room=str(current_user.id))

            return jsonify({
                'success': True,
                'content': decrypted,
                'direction': 'pull',
                'message': 'Note updated with latest changes from the original.'
            })
    except Exception as e:
        m.app.logger.error(f"Error syncing note {note_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500




