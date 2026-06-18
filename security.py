import base64
import json
import hashlib
import datetime
import difflib
import os
import re
import secrets as _secrets
from functools import wraps
from urllib.parse import urlparse, urljoin

from flask import request, flash, redirect, url_for
from flask_login import current_user
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ratelimit import limits as _limits_base, RateLimitException
from config import BYPASS_RATE_LIMIT, _NOTES_KDF_ITERATIONS, _NOTES_V1_SALT, get_env_variable, FIREBASE_AVAILABLE
import database
from cachetools import TTLCache

_APP = None

def _get_app():
    global _APP
    if _APP is None:
        import main
        _APP = main.app
    return _APP

_notes_fernet = None


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def is_same_origin_request():
    """Validate mutating API calls come from this same origin.

    This protects CSRF-exempt JSON endpoints used by service workers.
    """
    origin = request.headers.get('Origin', '').strip()
    referer = request.headers.get('Referer', '').strip()
    host = request.host

    if origin:
        origin_host = urlparse(origin).netloc
        if origin_host and origin_host != host:
            return False

    if referer:
        referer_host = urlparse(referer).netloc
        if referer_host and referer_host != host:
            return False

    return True


def parse_iso_utc(value):
    """Parse an ISO datetime string into an aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    try:
        normalized = value.replace('Z', '+00:00')
        dt = datetime.datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def build_unified_diff_text(original_text, updated_text, context=3, max_lines=500):
    """Build a compact unified diff string for previewing note changes."""
    old_lines = (original_text or '').splitlines()
    new_lines = (updated_text or '').splitlines()
    diff_lines = list(difflib.unified_diff(old_lines, new_lines, fromfile='current', tofile='incoming', lineterm='', n=context))
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ['... (diff truncated)']
    return '\n'.join(diff_lines)


def build_merge_preview_text(current_text, incoming_text):
    """Provide a starter merge text with conflict markers when two edits diverge."""
    current_text = current_text or ''
    incoming_text = incoming_text or ''
    if current_text == incoming_text:
        return current_text
    return (
        '<<<<<<< CURRENT\n'
        f'{current_text}\n'
        '=======\n'
        f'{incoming_text}\n'
        '>>>>>>> INCOMING'
    )


def get_active_achievements(user_id):
    """Returns a list of achievement keys for the given user_id based on latest winners."""
    user_id_str = str(user_id)
    cached_winners = database.weekly_winners_cache.get('latest')

    if cached_winners is None:
        latest = database.weekly_winners_conf.find_one(sort=[('week_end', -1)])
        if latest:
            cached_winners = latest.get('winners', {})
            database.weekly_winners_cache['latest'] = cached_winners
        else:
            cached_winners = {}
            database.weekly_winners_cache['latest'] = {}

    achievements = []
    if cached_winners:
        if cached_winners.get('most_active') and str(cached_winners['most_active']['_id']) == user_id_str:
            achievements.append('most_active')
        if cached_winners.get('most_engager') and str(cached_winners['most_engager']['_id']) == user_id_str:
            achievements.append('most_engager')
        if cached_winners.get('top_contributor') and str(cached_winners['top_contributor']['_id']) == user_id_str:
            achievements.append('top_contributor')
        if cached_winners.get('top_writer') and str(cached_winners['top_writer']['_id']) == user_id_str:
            achievements.append('top_writer')
        if cached_winners.get('top_noter') and str(cached_winners['top_noter']['_id']) == user_id_str:
            achievements.append('top_noter')
        if cached_winners.get('top_sharer') and str(cached_winners['top_sharer']['_id']) == user_id_str:
            achievements.append('top_sharer')
        if cached_winners.get('top_reader') and str(cached_winners['top_reader']['_id']) == user_id_str:
            achievements.append('top_reader')

    return achievements


def limits(calls, period):
    """Conditional rate limiter that respects BYPASS_RATE_LIMIT for testing."""
    if BYPASS_RATE_LIMIT:
        def noop_decorator(func):
            return func
        return noop_decorator
    return _limits_base(calls=calls, period=period)


# --- Encryption utilities for personal notes ---
# v2: Per-user key derivation with increased iterations (OWASP 2024 recommendation).
# Backward-compatible: falls back to v1 global key for notes encrypted before the upgrade.

def _derive_fernet_key(secret_bytes: bytes, salt: bytes, iterations: int = _NOTES_KDF_ITERATIONS):
    """Derives a Fernet-compatible key from arbitrary secret material."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_bytes))


# -- v1 global key (kept for decryption of legacy notes) --
def _get_notes_encryption_key():
    """Legacy v1 key: global key derived from SECRET_KEY with fixed salt."""
    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    return _derive_fernet_key(secret, _NOTES_V1_SALT, iterations=100000)


def get_notes_fernet():
    """Returns v1 Fernet instance (for legacy decrypt only)."""
    global _notes_fernet
    if _notes_fernet is None:
        _notes_fernet = Fernet(_get_notes_encryption_key())
    return _notes_fernet


# -- v2 per-user key derivation & caching --

def _get_user_fernet(user_id: str) -> Fernet:
    """Per-user Fernet instance. Derives key from SECRET_KEY + user_id salt."""
    cached = database._user_fernet_cache.get(user_id)
    if cached:
        return cached
    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    # Per-user salt: combines fixed namespace + user_id for uniqueness
    salt = f'echowithin_notes_v2_{user_id}'.encode()
    key = _derive_fernet_key(secret, salt, _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    database._user_fernet_cache[user_id] = f
    return f


def warm_user_fernet(user_id: str):
    """Pre-derive and cache the Fernet key for a user.
    
    Call on login to avoid the ~200ms PBKDF2 cold-derivation cost
    when the user first navigates to /personal_space.
    Also warms the v3 key if the user has been migrated.
    """
    _get_user_fernet(str(user_id))
    # Also warm v3 if available (no-op if user hasn't been migrated)
    try:
        _get_user_fernet_v3(str(user_id))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# v3 ENVELOPE ENCRYPTION
# ---------------------------------------------------------------------------
# Each user gets a random DEK (Data Encryption Key) encrypted by a KEK
# (Key Encryption Key) derived from SECRET_KEY. The encrypted DEK and a
# random salt are stored in the user document.
#
# Threat model improvement:
#   - DB breach alone → attacker gets encrypted DEKs, no plaintext
#   - SECRET_KEY leak alone → attacker needs the DB to get encrypted DEKs
#   - Both together → still need both pieces (vs today: SECRET_KEY alone)
#
# The KEK is derived from SECRET_KEY with a fixed namespace salt.
# The DEK is a random 32-byte key, never derived from SECRET_KEY.
# A random 32-byte salt per user adds uniqueness to the derived Fernet key.
# ---------------------------------------------------------------------------

_KEK_CACHE = {}  # module-level singleton cache for KEK Fernet


def _get_kek() -> Fernet:
    """Master Key Encryption Key — derived from SECRET_KEY with a fixed namespace salt.
    
    This is used ONLY to wrap/unwrap user DEKs, never to encrypt content directly.
    """
    if 'instance' in _KEK_CACHE:
        return _KEK_CACHE['instance']
    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    key = _derive_fernet_key(secret, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    _KEK_CACHE['instance'] = f
    return f


def generate_user_envelope_keys() -> dict:
    """Generate a random DEK + salt for a new user.
    
    Returns a dict ready to be merged into the user document:
        {
            'encryption_key_enc': str,   # DEK encrypted by KEK (Fernet token)
            'encryption_salt': str,      # random salt, base64-encoded
            'encryption_version': 3
        }
    """
    dek_raw = _secrets.token_bytes(32)
    salt_raw = _secrets.token_bytes(32)
    encrypted_dek = _get_kek().encrypt(dek_raw).decode('utf-8')
    return {
        'encryption_key_enc': encrypted_dek,
        'encryption_salt': base64.urlsafe_b64encode(salt_raw).decode('utf-8'),
        'encryption_version': 3
    }


def _decrypt_dek(encrypted_dek: str) -> bytes:
    """Decrypt a user's DEK from the stored Fernet token."""
    return _get_kek().decrypt(encrypted_dek.encode('utf-8'))


def _encrypt_dek(dek_raw: bytes) -> str:
    """Encrypt a DEK with the current KEK for storage."""
    return _get_kek().encrypt(dek_raw).decode('utf-8')


def _get_user_fernet_v3(user_id: str):
    """v3 per-user Fernet using envelope encryption.
    
    The key is derived from the user's random DEK + random salt.
    Both are stored (DEK encrypted) in the user document.
    Returns None if the user hasn't been migrated to v3 yet.
    """
    cached = database._user_fernet_v3_cache.get(user_id)
    if cached is not None:
        return cached if cached != '__none__' else None

    user_doc = database.users_conf.find_one(
        {'_id': ObjectId(user_id)},
        {'encryption_key_enc': 1, 'encryption_salt': 1, 'encryption_version': 1}
    )
    if not user_doc or not user_doc.get('encryption_key_enc'):
        database._user_fernet_v3_cache[user_id] = '__none__'
        return None

    try:
        dek_raw = _decrypt_dek(user_doc['encryption_key_enc'])
        salt = base64.urlsafe_b64decode(user_doc['encryption_salt'])
        key = _derive_fernet_key(dek_raw, salt, _NOTES_KDF_ITERATIONS)
        f = Fernet(key)
        database._user_fernet_v3_cache[user_id] = f
        return f
    except Exception as e:
        _get_app().logger.error(f"Failed to derive v3 Fernet for user {user_id}: {e}")
        database._user_fernet_v3_cache[user_id] = '__none__'
        return None


# -- v3 DM envelope encryption --

def generate_conversation_envelope_keys() -> dict:
    """Generate a random DEK for a new DM conversation.
    
    Returns a dict to be merged into the dm_permissions document:
        {
            'conversation_key_enc': str,  # conversation DEK encrypted by KEK
            'dm_encryption_version': 3
        }
    """
    dek_raw = _secrets.token_bytes(32)
    encrypted_dek = _get_kek().encrypt(dek_raw).decode('utf-8')
    return {
        'conversation_key_enc': encrypted_dek,
        'dm_encryption_version': 3
    }


def _get_dm_fernet_v3(user1_id: str, user2_id: str):
    """v3 DM Fernet using envelope encryption.
    
    Looks up the conversation's encrypted DEK from dm_permissions.
    Returns None if the conversation hasn't been migrated to v3.
    """
    uids = sorted([str(user1_id), str(user2_id)])
    conv_id = f"{uids[0]}_{uids[1]}"

    cached = database._dm_fernet_v3_cache.get(conv_id)
    if cached is not None:
        return cached if cached != '__none__' else None

    # Find the dm_permissions doc for this conversation
    perm_doc = database.dm_permissions_conf.find_one(
        {
            '$or': [
                {'requester_id': ObjectId(uids[0]), 'target_id': ObjectId(uids[1])},
                {'requester_id': ObjectId(uids[1]), 'target_id': ObjectId(uids[0])}
            ]
        },
        {'conversation_key_enc': 1, 'dm_encryption_version': 1}
    )
    if not perm_doc or not perm_doc.get('conversation_key_enc'):
        database._dm_fernet_v3_cache[conv_id] = '__none__'
        return None

    try:
        dek_raw = _decrypt_dek(perm_doc['conversation_key_enc'])
        # Use a deterministic salt from the conversation ID for the Fernet key derivation
        salt = f'echowithin_dm_v3_{conv_id}'.encode()
        key = _derive_fernet_key(dek_raw, salt, _NOTES_KDF_ITERATIONS)
        f = Fernet(key)
        database._dm_fernet_v3_cache[conv_id] = f
        return f
    except Exception as e:
        _get_app().logger.error(f"Failed to derive v3 DM Fernet for conversation {conv_id}: {e}")
        database._dm_fernet_v3_cache[conv_id] = '__none__'
        return None


def _get_dm_fernet(user1_id: str, user2_id: str) -> Fernet:
    """Derives a unique Fernet key for a conversation between two users."""
    # Deterministic order ensures both users derive the same key
    uids = sorted([str(user1_id), str(user2_id)])
    conv_id = f"{uids[0]}_{uids[1]}"

    cached = database._dm_fernet_cache.get(conv_id)
    if cached:
        return cached

    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    # Salt combines fixed namespace + the unique pair IDs
    salt = f'echowithin_dm_v1_{conv_id}'.encode()
    key = _derive_fernet_key(secret, salt, iterations=_NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    database._dm_fernet_cache[conv_id] = f
    return f


def encrypt_dm(content, user1_id, user2_id):
    if not content: return content
    try:
        # Try v3 (envelope encryption) first
        f_v3 = _get_dm_fernet_v3(user1_id, user2_id)
        if f_v3:
            return f_v3.encrypt(content.encode('utf-8')).decode('utf-8')
        # Fall back to v2
        f = _get_dm_fernet(user1_id, user2_id)
        return f.encrypt(content.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"DM Encryption error: {e}")
        raise  # Never silently fall back to plaintext


def decrypt_dm(encrypted_content, user1_id, user2_id):
    if not encrypted_content: return encrypted_content
    # Try v3 first (envelope encryption)
    f_v3 = _get_dm_fernet_v3(user1_id, user2_id)
    if f_v3:
        try:
            return f_v3.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
        except Exception:
            pass  # Fall through to v2
    # Try v2 DM-specific key
    try:
        f = _get_dm_fernet(user1_id, user2_id)
        return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception:
        # Fallback to plaintext for legacy messages
        return encrypted_content


def encrypt_note(content, user_id=None):
    """Encrypts note content. Uses v3 envelope key if available, else v2 per-user key."""
    if not content:
        return content
    try:
        if user_id:
            # Try v3 (envelope encryption) first
            f_v3 = _get_user_fernet_v3(str(user_id))
            if f_v3:
                return f_v3.encrypt(content.encode('utf-8')).decode('utf-8')
            # Fall back to v2
            f = _get_user_fernet(str(user_id))
        else:
            f = get_notes_fernet()
        encrypted = f.encrypt(content.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"Error encrypting note: {e}")
        raise  # Never silently fall back to plaintext


def decrypt_note(encrypted_content, user_id=None):
    """Decrypts note content. Tries v3 → v2 → v1 in order (backward-compatible)."""
    if not encrypted_content or encrypted_content == '[Content unavailable \u2014 decryption error]':
        return encrypted_content
    # Try v3 first (envelope encryption)
    if user_id:
        f_v3 = _get_user_fernet_v3(str(user_id))
        if f_v3:
            try:
                return f_v3.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
            except Exception:
                pass  # Fall through to v2
    # Try v2 per-user key
    if user_id:
        try:
            f = _get_user_fernet(str(user_id))
            return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
        except Exception:
            pass  # Fall through to v1
    # Try v1 global key (backward compatibility)
    try:
        f = get_notes_fernet()
        return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception as e:
        # Last resort: might be a legacy unencrypted note (pre-encryption era).
        # Only return raw content if it looks like valid UTF-8 text, not ciphertext.
        if encrypted_content and not encrypted_content.startswith('gAAAAA'):
            _get_app().logger.debug(f"Returning legacy unencrypted note content")
            return encrypted_content
        _get_app().logger.warning(f"Note decryption failed for all key versions")
        return '[Content unavailable \u2014 decryption error]'


def _candidate_user_ids(*values):
    candidates = []
    seen = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, ObjectId):
            value = str(value)
        value = str(value).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        candidates.append(value)
    return candidates


def _decrypt_with_candidate_ids(encrypted_content, candidate_user_ids):
    if not encrypted_content:
        return encrypted_content
    for candidate_user_id in candidate_user_ids:
        uid_str = str(candidate_user_id)
        # Try v3 (envelope encryption) first
        try:
            f_v3 = _get_user_fernet_v3(uid_str)
            if f_v3:
                return f_v3.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
        except Exception:
            pass
        # Try v2 (deterministic PBKDF2)
        try:
            f = _get_user_fernet(uid_str)
            return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
        except Exception:
            continue
    # Try v1 global key
    try:
        return get_notes_fernet().decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception:
        if encrypted_content and not encrypted_content.startswith('gAAAAA'):
            return encrypted_content
        return None


def _note_decryption_candidates(note, share=None):
    candidates = []
    seen = set()

    def add_value(value):
        if value is None:
            return
        if isinstance(value, ObjectId):
            value = str(value)
        value = str(value).strip()
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)

    current = note
    depth = 0
    while current and depth < 4:
        add_value(current.get('content_owner_id'))
        add_value(current.get('user_id'))
        add_value(current.get('owner_id'))
        add_value(current.get('source_owner_id'))
        add_value(current.get('saved_from_owner_id'))
        # OPTIMIZATION: Use pre-fetched original_doc if available (avoids DB round-trip)
        prefetched = current.get('original_doc')
        if prefetched:
            current = prefetched
        else:
            source_note_id = current.get('source_note_id')
            if not source_note_id:
                break
            current = database.personal_posts_conf.find_one(
                {'_id': source_note_id},
                {'content_owner_id': 1, 'user_id': 1, 'owner_id': 1, 'source_owner_id': 1, 'saved_from_owner_id': 1, 'source_note_id': 1}
            )
        depth += 1

    if share:
        add_value(share.get('owner_id'))
        add_value(share.get('source_owner_id'))

    return candidates


# ---------------------------------------------------------------------------
# DECRYPTION CACHE LAYER
# ---------------------------------------------------------------------------
# Cache decrypted note content in Redis so we don't re-decrypt on every page load.
# The cache is invalidated whenever a note is edited or its encryption changes.
# TTL: 300 seconds (5 minutes) — long enough for most browsing sessions.

_CACHE_DECRYPT_TTL = 300

def _decrypted_cache_key(note_id):
    return f"decrypted_note:{note_id}"

def _invalidate_decrypted_cache(note_id):
    """Remove the decrypted cache entry for a note when it's edited."""
    note_id_str = str(note_id) if not isinstance(note_id, str) else note_id
    try:
        if note_id_str in database._decrypted_notes_memory_cache:
            del database._decrypted_notes_memory_cache[note_id_str]
    except Exception:
        pass
    if database.redis_cache:
        try:
            database.redis_cache.delete(_decrypted_cache_key(note_id_str))
        except Exception:
            pass

def _decrypt_note_record(note, share=None, max_preview_chars=None):
    """
    Decrypt a note record, optionally caching the result in both an in-memory
    cache and Redis to avoid re-decryption on every page load.
    
    If max_preview_chars is set, only decrypt the first N characters and
    truncate with '...' — useful for list views where full content isn't needed.
    """
    note_id = note.get('_id')
    note_id_str = str(note_id) if note_id else None

    # 1. Check in-memory and Redis caches
    decrypted_content = None
    if note_id_str:
        try:
            decrypted_content = database._decrypted_notes_memory_cache.get(note_id_str)
        except Exception:
            pass
        
        if decrypted_content is None and database.redis_cache:
            try:
                cached = database.redis_cache.get(_decrypted_cache_key(note_id_str))
                if cached is not None:
                    decrypted_content = cached.decode('utf-8')
                    try:
                        database._decrypted_notes_memory_cache[note_id_str] = decrypted_content
                    except Exception:
                        pass
            except Exception:
                pass

    if decrypted_content is not None:
        if max_preview_chars and len(decrypted_content) > max_preview_chars:
            return decrypted_content[:max_preview_chars] + '...'
        return decrypted_content

    # 2. Perform the actual decryption
    candidates = _note_decryption_candidates(note, share)
    decrypted = _decrypt_with_candidate_ids(note.get('content', ''), candidates)
    if decrypted is None:
        return '[Content unavailable \u2014 decryption error]'

    # 3. Cache the FULL decrypted content
    if note_id_str:
        try:
            database._decrypted_notes_memory_cache[note_id_str] = decrypted
        except Exception:
            pass
        if database.redis_cache:
            try:
                database.redis_cache.setex(
                    _decrypted_cache_key(note_id_str),
                    _CACHE_DECRYPT_TTL,
                    decrypted
                )
            except Exception:
                pass

    # 4. Apply preview truncation if requested
    if max_preview_chars and len(decrypted) > max_preview_chars:
        preview = decrypted[:max_preview_chars] + '...'
    else:
        preview = decrypted

    return preview


# --- Community Encryption Utilities ---

# Community encryption version:
#   v1: 100,000 iterations (legacy)
#   v2: 480,000 iterations (OWASP 2024)

def _get_community_fernet(community_id, iterations=None):
    """
    Derive a community-specific encryption key based on the community ID.
    This ensures that community notes are encrypted but all members can read them.
    """
    community_id_str = str(community_id)
    iters = iterations or _NOTES_KDF_ITERATIONS  # Default to 480K (v2)
    cache_key = f"{community_id_str}_i{iters}"
    
    # Check cache
    cached = database._community_fernet_v2_cache.get(cache_key)
    if cached:
        return cached
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=community_id_str.encode('utf-8'),
        iterations=iters
    )
    base_secret = _get_app().secret_key.encode('utf-8') if isinstance(_get_app().secret_key, str) else _get_app().secret_key
    key = base64.urlsafe_b64encode(kdf.derive(base_secret))
    f = Fernet(key)
    database._community_fernet_v2_cache[cache_key] = f
    return f


def _get_community_fernet_legacy(community_id):
    """Legacy community Fernet with 100K iterations (for decrypting old notes)."""
    return _get_community_fernet(community_id, iterations=100000)


def encrypt_community_note(plaintext, community_id):
    if not plaintext:
        return plaintext
    try:
        f = _get_community_fernet(community_id)  # Uses 480K iterations (v2)
        return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"Failed to encrypt community note: {e}")
        raise  # Never silently fall back to plaintext


def decrypt_community_note(ciphertext, community_id):
    if not ciphertext:
        return ciphertext
    try:
        # Check if it's actually a Fernet token (starts with gAAAAA...)
        if not (isinstance(ciphertext, str) and ciphertext.startswith('gAAAAA')):
            return ciphertext
        # Try v2 (480K iterations) first
        try:
            f = _get_community_fernet(community_id)
            return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
        except Exception:
            pass
        # Fall back to v1 (100K iterations) for legacy community notes
        f_legacy = _get_community_fernet_legacy(community_id)
        return f_legacy.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"Failed to decrypt community note: {e}")
        return ciphertext


def safe_object_id(id_string):
    """Safely parse a string to ObjectId, returning None if invalid."""
    if not id_string:
        return None
    try:
        return ObjectId(id_string)
    except Exception:
        return None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('pages.dashboard'))
        # Audit log every admin action
        _get_app().logger.info(
            'ADMIN_ACTION',
            extra={'admin_user_id': current_user.id, 'endpoint': request.endpoint, 'method': request.method}
        )
        return f(*args, **kwargs)
    return decorated_function


def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = kwargs.get('post_id')
        if not post_id:
            # This case should ideally not be reached if routes are set up correctly
            flash("Post ID is missing.", "danger")
            return redirect(url_for('pages.home'))

        post = database.posts_conf.find_one({'_id': ObjectId(post_id)})

        # Check if post exists and if the current user is the author
        if not post or str(post.get('author_id')) != current_user.id:
            flash("You are not authorized to perform this action.", "danger")
            return redirect(url_for('blog.blog'))

        return f(*args, **kwargs)
    return decorated_function

# Expose the cache invalidation helper at module level
def invalidate_note_decryption_cache(note_id):
    """Public helper to invalidate the decryption cache for a note."""
    _invalidate_decrypted_cache(note_id)