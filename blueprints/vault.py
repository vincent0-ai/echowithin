"""Private Media Vault — PIN-protected encrypted media storage.

Entry point: long-press on own profile photo.
First use: set a 4-digit PIN.
Subsequent: enter PIN to unlock, auto-locks after inactivity.
"""
from flask import (
    Blueprint, request, jsonify, render_template, redirect,
    url_for, session, current_app, abort
)
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
import os
import hashlib
import hmac as _hmac
import secrets
import cloudinary
import cloudinary.uploader
import database
from config import (
    VAULT_PIN_LENGTH, VAULT_AUTO_LOCK_MINUTES, VAULT_MAX_FILE_SIZE,
    VAULT_KDF_ITERATIONS, TIER_LIMITS, CLOUDINARY_RAW_UPLOAD_LIMIT,
    VIDEO_COMPRESSION_TIMEOUT, get_env_variable
)
from security import (
    limits, _get_user_fernet, encrypt_media_bytes, build_media_serve_url,
    brute_force_check, brute_force_record_failure, brute_force_clear,
    _bf_get_client_ip, mask_email
)

bp = Blueprint('vault', __name__, template_folder='templates')


# ---------------------------------------------------------------------------
# PIN helpers
# ---------------------------------------------------------------------------

def _hash_pin(pin: str, salt: bytes = None) -> tuple:
    """Hash a vault PIN using PBKDF2-HMAC-SHA256. Returns (hash_hex, salt)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    elif isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')
    else:
        salt = bytes(salt)
    iterations = VAULT_KDF_ITERATIONS
    dk = hashlib.pbkdf2_hmac('sha256', pin.encode('utf-8'), salt, iterations)
    return dk.hex(), salt


def _verify_pin(pin: str, stored_hash: str, salt: bytes) -> bool:
    """Constant-time compare of a PIN against the stored hash."""
    import hmac as _hmac
    if not stored_hash or salt is None:
        return False
    computed, _ = _hash_pin(pin, salt)
    return _hmac.compare_digest(computed, stored_hash)


def _get_user_oid():
    """Get the current_user ObjectId."""
    uid = getattr(current_user, 'id', None)
    if isinstance(uid, ObjectId):
        return uid
    return ObjectId(uid)


def _vault_unlocked() -> bool:
    """Check if the vault is unlocked in the current session and hasn't timed out."""
    if not session.get('vault_unlocked'):
        return False
    if session.get('vault_unlocked_user_id') != str(current_user.id):
        return False
    unlock_time = session.get('vault_unlock_time')
    if not unlock_time:
        return False
    timeout = VAULT_AUTO_LOCK_MINUTES * 60
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    if now - unlock_time > timeout:
        session.pop('vault_unlocked', None)
        session.pop('vault_unlock_time', None)
        session.pop('vault_unlocked_user_id', None)
        return False
    # Refresh the unlock time on each access (sliding window)
    session['vault_unlock_time'] = now
    return True


def _require_vault_unlocked():
    """Abort 403 if vault is not unlocked."""
    if not _vault_unlocked():
        abort(403, description='Vault is locked')


# ---------------------------------------------------------------------------
# PIN management routes
# ---------------------------------------------------------------------------

@bp.route('/api/vault/status', methods=['GET'])
@login_required
@limits(calls=30, period=60)
def vault_status():
    """Check if vault PIN is set up and whether it's currently unlocked."""
    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'vault_pin_hash': 1}
    )
    has_pin = bool(user and user.get('vault_pin_hash'))
    return jsonify({
        'has_pin': has_pin,
        'unlocked': _vault_unlocked() if has_pin else False,
    })


@bp.route('/api/vault/setup-pin', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def vault_setup_pin():
    """Set up the vault PIN for the first time."""
    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'vault_pin_hash': 1}
    )
    if user and user.get('vault_pin_hash'):
        return jsonify({'error': 'Vault PIN already set'}), 400

    data = request.get_json(silent=True) or {}
    pin = str(data.get('pin', '')).strip()
    confirm = str(data.get('confirm', '')).strip()

    if len(pin) != VAULT_PIN_LENGTH or not pin.isdigit():
        return jsonify({'error': f'PIN must be {VAULT_PIN_LENGTH} digits'}), 400
    if pin != confirm:
        return jsonify({'error': 'PINs do not match'}), 400

    pin_hash, salt = _hash_pin(pin)
    now = datetime.datetime.now(datetime.timezone.utc)
    database.users_conf.update_one(
        {'_id': _get_user_oid()},
        {'$set': {
            'vault_pin_hash': pin_hash,
            'vault_pin_salt': salt,
            'vault_pin_set_at': now,
        }}
    )

    # Auto-unlock after setup
    session['vault_unlocked'] = True
    session['vault_unlock_time'] = now.timestamp()
    session['vault_unlocked_user_id'] = str(current_user.id)

    return jsonify({'success': True})


@bp.route('/api/vault/unlock', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def vault_unlock():
    """Unlock the vault with the PIN."""
    bf_ip = _bf_get_client_ip()
    user_id_str = str(current_user.id)
    tier, cnt, retry, ttl = brute_force_check('vault_pin', user_id_str, bf_ip)
    if tier == 'lockout':
        resp = jsonify({'error': 'Too many attempts. Try again in a few minutes.', 'retry_after': retry})
        resp.headers['Retry-After'] = str(retry)
        resp.headers['X-BruteForce-Tier'] = 'lockout'
        return resp, 429
    if tier == 'friction':
        resp = jsonify({'error': 'Too many attempts. Try again shortly.', 'retry_after': retry})
        resp.headers['Retry-After'] = str(retry)
        resp.headers['X-BruteForce-Tier'] = 'friction'
        return resp, 429

    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'vault_pin_hash': 1, 'vault_pin_salt': 1}
    )
    if not user or not user.get('vault_pin_hash'):
        return jsonify({'error': 'Vault PIN not set up'}), 400

    data = request.get_json(silent=True) or {}
    pin = str(data.get('pin', '')).strip()

    if not _verify_pin(pin, user['vault_pin_hash'], user.get('vault_pin_salt')):
        new_cnt, new_tier, new_retry, new_ttl = brute_force_record_failure('vault_pin', user_id_str, bf_ip)
        if new_tier == 'lockout':
            resp = jsonify({'error': 'Too many attempts. Try again in a few minutes.', 'retry_after': new_retry})
            resp.headers['Retry-After'] = str(new_retry)
            resp.headers['X-BruteForce-Tier'] = 'lockout'
            return resp, 429
        if new_tier == 'friction':
            resp = jsonify({'error': 'Too many attempts. Try again shortly.', 'retry_after': new_retry})
            resp.headers['Retry-After'] = str(new_retry)
            resp.headers['X-BruteForce-Tier'] = 'friction'
            return resp, 429
        return jsonify({'error': 'Incorrect PIN'}), 403

    brute_force_clear('vault_pin', user_id_str, bf_ip)
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    session['vault_unlocked'] = True
    session['vault_unlock_time'] = now
    session['vault_unlocked_user_id'] = user_id_str

    return jsonify({'success': True})


@bp.route('/api/vault/lock', methods=['POST'])
@login_required
def vault_lock():
    """Lock the vault (clear session)."""
    session.pop('vault_unlocked', None)
    session.pop('vault_unlock_time', None)
    session.pop('vault_unlocked_user_id', None)
    return jsonify({'success': True})


@bp.route('/api/vault/change-pin', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def vault_change_pin():
    """Change the vault PIN (requires current PIN)."""
    _require_vault_unlocked()

    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'vault_pin_hash': 1, 'vault_pin_salt': 1}
    )
    if not user or not user.get('vault_pin_hash'):
        return jsonify({'error': 'Vault PIN not set up'}), 400

    data = request.get_json(silent=True) or {}
    current_pin = str(data.get('current_pin', '')).strip()
    new_pin = str(data.get('new_pin', '')).strip()
    confirm = str(data.get('confirm', '')).strip()

    if not _verify_pin(current_pin, user['vault_pin_hash'], user.get('vault_pin_salt')):
        return jsonify({'error': 'Current PIN is incorrect'}), 403

    if len(new_pin) != VAULT_PIN_LENGTH or not new_pin.isdigit():
        return jsonify({'error': f'New PIN must be {VAULT_PIN_LENGTH} digits'}), 400
    if new_pin != confirm:
        return jsonify({'error': 'New PINs do not match'}), 400

    pin_hash, salt = _hash_pin(new_pin)
    now = datetime.datetime.now(datetime.timezone.utc)
    database.users_conf.update_one(
        {'_id': _get_user_oid()},
        {'$set': {
            'vault_pin_hash': pin_hash,
            'vault_pin_salt': salt,
            'vault_pin_set_at': now,
        }}
    )

    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# PIN reset via email
# ---------------------------------------------------------------------------

@bp.route('/api/vault/forgot-pin', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def vault_forgot_pin():
    """Send a 6-digit verification code to the user's email for vault PIN reset."""
    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'email': 1, 'vault_pin_hash': 1}
    )
    if not user or not user.get('vault_pin_hash'):
        return jsonify({'error': 'No vault PIN is set on this account'}), 400
    email = user.get('email')
    if not email:
        return jsonify({'error': 'No email address associated with this account'}), 400

    # Generate a 6-digit code, hash it, store with 15-minute expiry
    gen_code = str(secrets.randbelow(10**6)).zfill(6)
    hashed_code = hashlib.sha256(gen_code.encode()).hexdigest()
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)

    database.auth_conf.update_one(
        {'email': email},
        {'$set': {
            'vault_pin_reset_code': hashed_code,
            'vault_pin_reset_expiry': expiry,
            'vault_pin_reset_attempts': 0
        }},
        upsert=True
    )

    # Send the code via email
    try:
        from notifications import _get_mail
        from flask_mail import Message as MailMessage
        sender = f"EchoWithin <{get_env_variable('MAIL_USERNAME')}>"
        msg = MailMessage(
            subject="EchoWithin Vault PIN Reset",
            sender=sender,
            recipients=[email]
        )
        msg.html = render_template('vault_pin_reset_email.html', code=gen_code)
        msg.body = (f"Your EchoWithin Vault PIN reset code is: {gen_code}\n\n"
                    f"This code expires in 15 minutes. If you didn't request this, "
                    f"please ignore this email.")
        _get_mail().send(msg)
        current_app.logger.info('Vault PIN reset code sent to masked account.')
    except Exception as e:
        current_app.logger.error(f'Failed to send vault PIN reset email: {e}')
        return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500

    masked = mask_email(email)
    return jsonify({'success': True, 'masked_email': masked,
                    'message': 'Verification code sent to your email.'})


@bp.route('/api/vault/reset-pin', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def vault_reset_pin():
    """Verify the emailed code and set a new vault PIN."""
    bf_ip = _bf_get_client_ip()
    user_id_str = str(current_user.id)
    tier, cnt, retry, ttl = brute_force_check('vault_pin_reset', user_id_str, bf_ip)
    if tier == 'lockout':
        resp = jsonify({'error': 'Too many attempts. Try again in a few minutes.', 'retry_after': retry})
        resp.headers['Retry-After'] = str(retry)
        resp.headers['X-BruteForce-Tier'] = 'lockout'
        return resp, 429

    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip()
    new_pin = str(data.get('new_pin', '')).strip()
    confirm = str(data.get('confirm', '')).strip()

    if not code:
        return jsonify({'error': 'Verification code is required'}), 400
    if not new_pin or len(new_pin) != VAULT_PIN_LENGTH or not new_pin.isdigit():
        return jsonify({'error': f'New PIN must be exactly {VAULT_PIN_LENGTH} digits'}), 400
    if new_pin != confirm:
        return jsonify({'error': 'PINs do not match'}), 400

    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'email': 1, 'vault_pin_hash': 1}
    )
    if not user or not user.get('vault_pin_hash'):
        return jsonify({'error': 'No vault PIN is set'}), 400
    email = user.get('email')
    if not email:
        return jsonify({'error': 'No email on this account'}), 400

    # Look up the stored reset code
    auth_record = database.auth_conf.find_one(
        {'email': email, 'vault_pin_reset_code': {'$exists': True}}
    )
    if not auth_record:
        return jsonify({'error': 'No reset request found. Please request a new code.'}), 400

    # Check expiry
    expiry = auth_record.get('vault_pin_reset_expiry')
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expiry:
            database.auth_conf.update_one(
                {'email': email},
                {'$unset': {'vault_pin_reset_code': '', 'vault_pin_reset_expiry': ''}}
            )
            return jsonify({'error': 'Reset code has expired. Please request a new one.'}), 400

    # Limit online guessing attempts before invalidating the code
    MAX_VAULT_PIN_RESET_ATTEMPTS = 10
    attempts = int(auth_record.get('vault_pin_reset_attempts', 0) or 0)
    if attempts >= MAX_VAULT_PIN_RESET_ATTEMPTS:
        database.auth_conf.update_one(
            {'email': email},
            {'$unset': {'vault_pin_reset_code': '', 'vault_pin_reset_expiry': ''}}
        )
        return jsonify({'error': 'Too many failed attempts. Please request a new code.'}), 429

    # Verify the code — constant-time comparison of digests
    hashed_input = hashlib.sha256(code.encode()).hexdigest()
    if not _hmac.compare_digest(hashed_input, auth_record.get('vault_pin_reset_code', '')):
        database.auth_conf.update_one({'email': email}, {'$inc': {'vault_pin_reset_attempts': 1}})
        new_cnt, new_tier, new_retry, new_ttl = brute_force_record_failure(
            'vault_pin_reset', user_id_str, bf_ip
        )
        if new_tier == 'lockout':
            resp = jsonify({'error': 'Too many attempts. Try again in a few minutes.', 'retry_after': new_retry})
            resp.headers['Retry-After'] = str(new_retry)
            resp.headers['X-BruteForce-Tier'] = 'lockout'
            return resp, 429
        if new_tier == 'friction':
            resp = jsonify({'error': 'Too many attempts. Try again shortly.', 'retry_after': new_retry})
            resp.headers['Retry-After'] = str(new_retry)
            resp.headers['X-BruteForce-Tier'] = 'friction'
            return resp, 429
        return jsonify({'error': 'Incorrect verification code'}), 403

    # Success — clear brute force
    brute_force_clear('vault_pin_reset', user_id_str, bf_ip)

    # Code is valid — update the PIN
    pin_hash, salt = _hash_pin(new_pin)
    now = datetime.datetime.now(datetime.timezone.utc)
    database.users_conf.update_one(
        {'_id': _get_user_oid()},
        {'$set': {
            'vault_pin_hash': pin_hash,
            'vault_pin_salt': salt,
            'vault_pin_set_at': now,
        }}
    )

    # Clean up the used code
    database.auth_conf.update_one(
        {'email': email},
        {'$unset': {'vault_pin_reset_code': '', 'vault_pin_reset_expiry': '',
                    'vault_pin_reset_attempts': ''}}
    )

    # Auto-unlock the session
    session['vault_unlocked'] = True
    session['vault_unlock_time'] = now.timestamp()
    session['vault_unlocked_user_id'] = user_id_str

    return jsonify({'success': True, 'message': 'Vault PIN has been reset successfully.'})


# ---------------------------------------------------------------------------
# Vault page
# ---------------------------------------------------------------------------

@bp.route('/vault')
@login_required
def vault_page():
    """Render the vault page. If PIN not set, redirect to profile."""
    user = database.users_conf.find_one(
        {'_id': _get_user_oid()},
        {'vault_pin_hash': 1}
    )
    if not user or not user.get('vault_pin_hash'):
        return redirect(url_for('profile.profile', username=current_user.username))

    tier = getattr(current_user, 'account_tier', 'free')
    max_items = TIER_LIMITS.get(tier, TIER_LIMITS['free']).get('max_vault_items', 20)

    return render_template('vault.html',
        active_page='vault',
        vault_unlocked=_vault_unlocked(),
        max_items=max_items,
        max_file_size=VAULT_MAX_FILE_SIZE,
    )


# ---------------------------------------------------------------------------
# Media upload / list / delete / serve
# ---------------------------------------------------------------------------

@bp.route('/api/vault/upload', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def vault_upload():
    """Upload a media item to the vault."""
    _require_vault_unlocked()

    # Check tier limits
    tier = getattr(current_user, 'account_tier', 'free')
    max_items = TIER_LIMITS.get(tier, TIER_LIMITS['free']).get('max_vault_items', 20)
    current_count = database.vault_items_conf.count_documents({'user_id': _get_user_oid()})
    if current_count >= max_items:
        return jsonify({'error': f'Vault limit reached ({max_items} items). Upgrade to premium for more.'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Size check
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > VAULT_MAX_FILE_SIZE:
        return jsonify({'error': f'File exceeds {VAULT_MAX_FILE_SIZE // (1024 * 1024)}MB limit'}), 400

    # Determine media type
    mime = (file.mimetype or 'application/octet-stream').split(';')[0].strip().lower()
    if mime.startswith('image/'):
        media_type = 'image'
    elif mime.startswith('video/'):
        media_type = 'video'
    else:
        media_type = 'document'

    raw_bytes = file.read()

    # Compress videos exceeding Cloudinary raw limit
    if media_type == 'video':
        cloud_limit = CLOUDINARY_RAW_UPLOAD_LIMIT
        if len(raw_bytes) > cloud_limit:
            try:
                from video_utils import compress_video_if_needed
                raw_bytes, mime = compress_video_if_needed(
                    raw_bytes, cloud_limit,
                    timeout=VIDEO_COMPRESSION_TIMEOUT,
                    temp_dir=current_app.config.get('TEMP_UPLOAD_FOLDER', 'temp_uploads'),
                )
            except Exception as e:
                current_app.logger.warning(f'Vault video compression failed: {e}')

    try:
        encrypted_bytes = encrypt_media_bytes(raw_bytes)
        upload_result = cloudinary.uploader.upload(
            encrypted_bytes,
            folder='vault_items',
            resource_type='raw',
            type='authenticated'
        )
    except Exception as e:
        current_app.logger.error(f'Vault upload failed: {e}')
        return jsonify({'error': 'Upload failed'}), 500

    public_id = upload_result.get('public_id', '')

    # Encrypt filename with per-user Fernet
    original_filename = file.filename or 'unnamed'
    try:
        user_fernet = _get_user_fernet(str(current_user.id))
        filename_enc = user_fernet.encrypt(original_filename.encode('utf-8')).decode('utf-8')
    except Exception:
        filename_enc = ''

    # Encrypt optional notes
    notes_raw = (request.form.get('notes', '') or '')[:2000]
    notes_enc = ''
    if notes_raw:
        try:
            if not user_fernet:
                user_fernet = _get_user_fernet(str(current_user.id))
            notes_enc = user_fernet.encrypt(notes_raw.encode('utf-8')).decode('utf-8')
        except Exception:
            notes_enc = ''

    # Get thumbnail from request (client-generated base64) and encrypt it
    thumbnail_raw = request.form.get('thumbnail', '')[:8000]
    thumbnail_enc = ''
    if thumbnail_raw:
        try:
            if not user_fernet:
                user_fernet = _get_user_fernet(str(current_user.id))
            thumbnail_enc = user_fernet.encrypt(thumbnail_raw.encode('utf-8')).decode('utf-8')
        except Exception:
            thumbnail_enc = ''

    now = datetime.datetime.now(datetime.timezone.utc)
    doc = {
        'user_id': _get_user_oid(),
        'cloudinary_public_id': public_id,
        'filename_enc': filename_enc,
        'notes_enc': notes_enc,
        'mime_type': mime[:200],
        'media_type': media_type,
        'file_size': size,
        'thumbnail_data': thumbnail_enc,
        'created_at': now,
        'updated_at': now,
    }
    result = database.vault_items_conf.insert_one(doc)

    return jsonify({
        'success': True,
        'item_id': str(result.inserted_id),
        'media_type': media_type,
    })


@bp.route('/api/vault/items', methods=['GET'])
@login_required
@limits(calls=30, period=60)
def vault_items():
    """List vault items (paginated, filterable)."""
    _require_vault_unlocked()

    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(50, request.args.get('per_page', 20, type=int))
    skip = (page - 1) * per_page

    # Build query filter
    query = {'user_id': _get_user_oid()}
    media_type_filter = request.args.get('type', '').strip().lower()
    if media_type_filter in ('image', 'video', 'document'):
        query['media_type'] = media_type_filter

    sort_param = request.args.get('sort', 'newest').strip().lower()
    if sort_param == 'recent':
        # Last 7 days only
        seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
        query['created_at'] = {'$gte': seven_days_ago}
        sort_dir = -1
    elif sort_param == 'oldest':
        sort_dir = 1
    else:
        sort_dir = -1  # newest first (default)

    cursor = database.vault_items_conf.find(
        query,
        {'cloudinary_public_id': 0}  # don't expose raw IDs to frontend
    ).sort('created_at', sort_dir).skip(skip).limit(per_page)

    total = database.vault_items_conf.count_documents(query)
    # Total across all types (for storage usage bar)
    total_all = database.vault_items_conf.count_documents({'user_id': _get_user_oid()})

    # Decrypt filenames, notes, and thumbnails
    items = []
    try:
        user_fernet = _get_user_fernet(str(current_user.id))
    except Exception:
        user_fernet = None

    for doc in cursor:
        filename = ''
        if user_fernet and doc.get('filename_enc'):
            try:
                filename = user_fernet.decrypt(doc['filename_enc'].encode('utf-8')).decode('utf-8')
            except Exception:
                filename = 'encrypted_file'

        # Decrypt notes
        notes = ''
        if user_fernet and doc.get('notes_enc'):
            try:
                notes = user_fernet.decrypt(doc['notes_enc'].encode('utf-8')).decode('utf-8')
            except Exception:
                notes = ''

        # Decrypt thumbnail — graceful fallback for legacy plaintext thumbnails
        thumbnail = ''
        raw_thumb = doc.get('thumbnail_data', '')
        if raw_thumb and user_fernet:
            try:
                thumbnail = user_fernet.decrypt(raw_thumb.encode('utf-8')).decode('utf-8')
            except Exception:
                # Legacy plaintext thumbnail or corrupted data — show as-is if it
                # looks like a data URL, otherwise discard
                if isinstance(raw_thumb, str) and raw_thumb.startswith('data:'):
                    thumbnail = raw_thumb
                else:
                    thumbnail = ''

        created_at = doc.get('created_at')
        if created_at:
            created_at = created_at.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')

        items.append({
            'id': str(doc['_id']),
            'filename': filename,
            'notes': notes,
            'mime_type': doc.get('mime_type', ''),
            'media_type': doc.get('media_type', 'document'),
            'file_size': doc.get('file_size', 0),
            'thumbnail': thumbnail,
            'created_at': created_at,
        })

    return jsonify({
        'items': items,
        'total': total,
        'total_all': total_all,
        'page': page,
        'per_page': per_page,
        'has_more': skip + per_page < total,
    })


@bp.route('/api/vault/items/<item_id>', methods=['DELETE'])
@login_required
@limits(calls=20, period=60)
def vault_delete_item(item_id):
    """Delete a vault item."""
    _require_vault_unlocked()

    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'error': 'Invalid item ID'}), 400

    doc = database.vault_items_conf.find_one({
        '_id': obj_id,
        'user_id': _get_user_oid()
    })
    if not doc:
        return jsonify({'error': 'Item not found'}), 404

    # Delete from Cloudinary
    public_id = doc.get('cloudinary_public_id')
    if public_id:
        try:
            cloudinary.uploader.destroy(public_id, resource_type='raw', type='authenticated')
        except Exception as e:
            current_app.logger.warning(f'Vault Cloudinary delete failed: {e}')

    database.vault_items_conf.delete_one({'_id': obj_id})

    return jsonify({'success': True})


@bp.route('/api/vault/items/<item_id>/notes', methods=['PATCH'])
@login_required
@limits(calls=20, period=60)
def vault_update_notes(item_id):
    """Update the encrypted notes for a vault item."""
    _require_vault_unlocked()

    try:
        obj_id = ObjectId(item_id)
    except Exception:
        return jsonify({'error': 'Invalid item ID'}), 400

    doc = database.vault_items_conf.find_one({
        '_id': obj_id,
        'user_id': _get_user_oid()
    })
    if not doc:
        return jsonify({'error': 'Item not found'}), 404

    data = request.get_json(silent=True) or {}
    notes_raw = str(data.get('notes', '')).strip()[:2000]

    notes_enc = ''
    if notes_raw:
        try:
            user_fernet = _get_user_fernet(str(current_user.id))
            notes_enc = user_fernet.encrypt(notes_raw.encode('utf-8')).decode('utf-8')
        except Exception:
            return jsonify({'error': 'Encryption failed'}), 500

    now = datetime.datetime.now(datetime.timezone.utc)
    database.vault_items_conf.update_one(
        {'_id': obj_id},
        {'$set': {'notes_enc': notes_enc, 'updated_at': now}}
    )

    return jsonify({'success': True})


@bp.route('/api/vault/items/bulk-delete', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def vault_bulk_delete():
    """Delete multiple vault items at once (max 50)."""
    _require_vault_unlocked()

    data = request.get_json(silent=True) or {}
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'No item IDs provided'}), 400
    ids = ids[:50]  # Cap at 50

    obj_ids = []
    for item_id in ids:
        try:
            obj_ids.append(ObjectId(item_id))
        except Exception:
            continue

    if not obj_ids:
        return jsonify({'error': 'No valid item IDs'}), 400

    # Fetch all matching docs owned by this user
    docs = list(database.vault_items_conf.find({
        '_id': {'$in': obj_ids},
        'user_id': _get_user_oid()
    }))

    deleted = 0
    for doc in docs:
        public_id = doc.get('cloudinary_public_id')
        if public_id:
            try:
                cloudinary.uploader.destroy(public_id, resource_type='raw', type='authenticated')
            except Exception as e:
                current_app.logger.warning(f'Vault bulk delete Cloudinary failure: {e}')
        database.vault_items_conf.delete_one({'_id': doc['_id']})
        deleted += 1

    return jsonify({'success': True, 'deleted': deleted})


@bp.route('/api/vault/serve/<item_id>')
@login_required
def vault_serve_item(item_id):
    """Serve a decrypted vault media item via capability URL."""
    _require_vault_unlocked()

    try:
        obj_id = ObjectId(item_id)
    except Exception:
        abort(400)

    doc = database.vault_items_conf.find_one({
        '_id': obj_id,
        'user_id': _get_user_oid()
    })
    if not doc:
        abort(404)

    public_id = doc.get('cloudinary_public_id')
    mime_type = doc.get('mime_type', 'application/octet-stream')

    if not public_id:
        abort(404)

    serve_url = build_media_serve_url(public_id, mime_type)
    if not serve_url:
        abort(500)

    return redirect(serve_url)
