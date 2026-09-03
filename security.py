import base64
import json
import hashlib
import datetime
import difflib
import os
import re
import hmac
import time as _time
import secrets as _secrets
import threading
from functools import wraps
from urllib.parse import urlparse, urljoin, quote

from flask import request, flash, redirect, url_for
from flask_login import current_user
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ratelimit import RateLimitException
from config import BYPASS_RATE_LIMIT, _NOTES_KDF_ITERATIONS, _NOTES_V1_SALT, get_env_variable, FIREBASE_AVAILABLE
import database
from cachetools import TTLCache

_APP = None

# Per-IP in-memory rate-limit fallback store: key -> (window_start, count)
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_MEMORY = {}

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
    """Conditional rate limiter that respects BYPASS_RATE_LIMIT for testing.

    SECURITY: rate limiting is enforced PER-CLIENT-IP using a fixed-window
    Redis counter (with an in-memory fallback). This replaces the previous
    implementation that used the `ratelimit` package's single shared counter
    per function, which meant one client exhausting the budget caused 429s
    for every user on the platform (cross-user DoS).
    """
    if BYPASS_RATE_LIMIT:
        def noop_decorator(func):
            return func
        return noop_decorator

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ip = _bf_get_client_ip()
            key = "rl:%s.%s:%s" % (func.__module__, func.__name__, ip)
            window = int(_time.time() // period)
            try:
                if database.redis_cache is not None:
                    rkey = "%s:%d" % (key, window)
                    pipe = database.redis_cache.pipeline()
                    pipe.incr(rkey)
                    pipe.expire(rkey, period + 1)
                    count = pipe.execute()[0]
                    if count > calls:
                        period_remaining = period - (_time.time() % period)
                        raise RateLimitException('too many calls', period_remaining)
                    return func(*args, **kwargs)
            except RateLimitException:
                raise
            except Exception:
                # Redis unavailable -> fall back to in-memory counting below.
                pass
            # In-memory fallback (per-process). Sliding window per client IP.
            with _RATE_LIMIT_LOCK:
                now = _time.time()
                window_start = now - now % period
                entry = _RATE_LIMIT_MEMORY.get(key)
                if entry is None or entry[0] != window_start:
                    _RATE_LIMIT_MEMORY[key] = (window_start, 1)
                    entry = _RATE_LIMIT_MEMORY[key]
                else:
                    entry = (window_start, entry[1] + 1)
                    _RATE_LIMIT_MEMORY[key] = entry
                if entry[1] > calls:
                    period_remaining = period - (now % period)
                    raise RateLimitException('too many calls', period_remaining)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Brute-force graduated protection — account+IP scoped, Redis-backed
# ---------------------------------------------------------------------------
# Implements the plan from IMPLEMENTATION_PLAN.md §2/§5.
# 1-3: no friction, 4-5: friction (immediate 429 + Retry-After, no sleep),
# 6+: soft lockout (minutes). Never IP-alone, never account-alone.
# Recovery via email (forgot_password) uses a different key space.
# ---------------------------------------------------------------------------

_BF_MEMORY = {}
_BF_MEMORY_LOCK = threading.Lock()

_BF_CONFIG = {
    'login':      {'window': 900, 'lockout': 600, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'confirm':    {'window': 900, 'lockout': 900, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'pin':        {'window': 600, 'lockout': 900, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'pin_reset':  {'window': 600, 'lockout': 900, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'share':      {'window': 900, 'lockout': 600, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'delete':     {'window': 900, 'lockout': 900, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
    'contact':    {'window': 900, 'lockout': 600, 'friction_at': 4, 'lockout_at': 6, 'retry_4': 2, 'retry_5': 4},
}


def _bf_get_client_ip():
    """Client IP respecting ProxyFix / X-Forwarded-For (same logic as auth._record_login_session)."""
    try:
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd and ',' in fwd:
            return fwd.split(',')[0].strip()
        if fwd:
            return fwd.strip()
    except Exception:
        pass
    return request.remote_addr or 'unknown'


def _bf_normalize_account(value):
    if not value:
        return '__unknown__'
    v = str(value).strip().lower()
    # keep safe chars for Redis key, replace pipe/newline
    v = v.replace('|', '_').replace('\n', '_').replace('\r', '_')[:120]
    return v or '__unknown__'


def _bf_hash_for_log(value):
    try:
        return hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:12]
    except Exception:
        return 'unknown'


def _bf_key(kind, account, ip):
    acct = _bf_normalize_account(account)
    # share_id is high-entropy; hash it for log privacy but keep raw for key uniqueness (truncate)
    # Do not hash the key itself — keep it deterministic for INCR.
    safe_acct = re.sub(r'[^a-zA-Z0-9._\-@]', '_', acct)[:80]
    safe_ip = re.sub(r'[^0-9a-fA-F.:]', '_', str(ip))[:45]
    return f"bf:{kind}:{safe_acct}|{safe_ip}"


def _bf_redis_available():
    return database.redis_cache is not None


def _bf_get_count_and_ttl(kind, account, ip):
    """Return (count, ttl_seconds) for the current window. 0/0 if none."""
    cfg = _BF_CONFIG.get(kind, _BF_CONFIG['login'])
    key = _bf_key(kind, account, ip)
    try:
        if _bf_redis_available():
            cnt = database.redis_cache.get(key)
            if cnt is None:
                return 0, 0
            # redis-py returns bytes/str depending on decode_responses
            count = int(cnt) if isinstance(cnt, (int, float)) else int(str(cnt).strip())
            ttl = database.redis_cache.ttl(key)
            if ttl is None or ttl < 0:
                ttl = cfg['window']
            return count, int(ttl)
    except Exception:
        pass
    # in-memory fallback
    with _BF_MEMORY_LOCK:
        entry = _BF_MEMORY.get(key)
        if not entry:
            return 0, 0
        count, expire_at = entry
        now = _time.time()
        if now >= expire_at:
            _BF_MEMORY.pop(key, None)
            return 0, 0
        return count, int(expire_at - now)
    return 0, 0


def _bf_incr(kind, account, ip):
    """INCR the account+IP counter and return (new_count, ttl_remaining)."""
    cfg = _BF_CONFIG.get(kind, _BF_CONFIG['login'])
    key = _bf_key(kind, account, ip)
    window = cfg['window']
    lockout = cfg['lockout']
    try:
        if _bf_redis_available():
            # Use pipeline: INCR + TTL handling
            # We need to know if this is first incr to set window TTL
            pipe = database.redis_cache.pipeline()
            pipe.incr(key)
            pipe.ttl(key)
            new_count, ttl = pipe.execute()
            new_count = int(new_count)
            # ttl after incr: -1 means no expire was set
            if ttl == -1 or ttl is None or ttl < 0:
                # first hit — set window expiry
                database.redis_cache.expire(key, window)
                ttl = window
            # On lockout threshold, extend TTL to lockout duration
            if new_count >= cfg['lockout_at']:
                # extend to lockout if not already longer
                # we set expire to lockout from now (soft lockout minutes, not hours)
                database.redis_cache.expire(key, lockout)
                ttl = lockout
                # also emit lockout log once (caller will log too, but ensure)
            return new_count, int(ttl) if ttl and ttl > 0 else lockout
    except Exception as e:
        try:
            _get_app().logger.warning(f"brute_force_redis_unavailable kind={kind} error={e}", extra={'event': 'brute_force_redis_unavailable', 'kind': kind})
        except Exception:
            pass
    # in-memory fallback
    with _BF_MEMORY_LOCK:
        now = _time.time()
        entry = _BF_MEMORY.get(key)
        if not entry or now >= entry[1]:
            new_count = 1
            expire_at = now + window
        else:
            new_count = entry[0] + 1
            expire_at = entry[1]
            if new_count >= cfg['lockout_at']:
                expire_at = now + lockout
        _BF_MEMORY[key] = (new_count, expire_at)
        ttl = int(expire_at - now)
        return new_count, ttl if ttl > 0 else lockout
    return 1, window


def _bf_clear(kind, account, ip):
    """Clear the counter on success (so 2 fails + success resets)."""
    key = _bf_key(kind, account, ip)
    try:
        if _bf_redis_available():
            database.redis_cache.delete(key)
            return
    except Exception:
        pass
    with _BF_MEMORY_LOCK:
        _BF_MEMORY.pop(key, None)


def _bf_tier_for_count(kind, count):
    cfg = _BF_CONFIG.get(kind, _BF_CONFIG['login'])
    if count >= cfg['lockout_at']:
        return 'lockout'
    if count >= cfg['friction_at']:
        return 'friction'
    return 'ok'


def _bf_retry_after(kind, count):
    cfg = _BF_CONFIG.get(kind, _BF_CONFIG['login'])
    if count == 4:
        return cfg['retry_4']
    if count == 5:
        return cfg['retry_5']
    if count >= cfg['lockout_at']:
        return cfg['lockout']
    return 0


def brute_force_check(kind, account, ip=None):
    """
    Check current tier without incrementing.
    Returns (tier, count, retry_after, ttl).
    tier in ('ok','friction','lockout')
    """
    ip = ip or _bf_get_client_ip()
    count, ttl = _bf_get_count_and_ttl(kind, account, ip)
    tier = _bf_tier_for_count(kind, count)
    retry = _bf_retry_after(kind, count) if tier != 'ok' else 0
    # For lockout, retry is ttl remaining (more accurate)
    if tier == 'lockout' and ttl > 0:
        retry = ttl
    return tier, count, retry, ttl


def brute_force_record_failure(kind, account, ip=None):
    """
    Record a failure and return (new_count, tier, retry_after, ttl).
    Caller should map tier to response.
    """
    ip = ip or _bf_get_client_ip()
    new_count, ttl = _bf_incr(kind, account, ip)
    tier = _bf_tier_for_count(kind, new_count)
    retry = _bf_retry_after(kind, new_count) if tier != 'ok' else 0
    if tier == 'lockout' and ttl > 0:
        retry = ttl
    # monitoring hook — distinct from normal failed logins
    try:
        acct_hash = _bf_hash_for_log(account) if kind != 'share' else hashlib.sha256(str(account).encode()).hexdigest()[:10]
        if tier == 'friction':
            _get_app().logger.warning(
                f"brute_force_friction kind={kind} account_hash={acct_hash} ip={ip} count={new_count} retry_after={retry}",
                extra={'event': 'brute_force_friction', 'kind': kind, 'account_hash': acct_hash, 'ip': ip, 'count': new_count, 'retry_after': retry}
            )
        elif tier == 'lockout':
            _get_app().logger.warning(
                f"brute_force_lockout kind={kind} account_hash={acct_hash} ip={ip} count={new_count} ttl={ttl}",
                extra={'event': 'brute_force_lockout', 'kind': kind, 'account_hash': acct_hash, 'ip': ip, 'count': new_count, 'retry_after': ttl}
            )
    except Exception:
        pass
    return new_count, tier, retry, ttl


def brute_force_clear(kind, account, ip=None):
    """Public clear helper to call on success."""
    ip = ip or _bf_get_client_ip()
    _bf_clear(kind, account, ip)


def _bf_is_locked(kind, account, ip=None):
    tier, count, retry, ttl = brute_force_check(kind, account, ip)
    return tier == 'lockout', retry, count


def _bf_log_login_failed(account, ip, count, tier):
    try:
        _get_app().logger.info(
            f"login_failed account_hash={_bf_hash_for_log(account)} ip={ip} count={count} tier={tier}",
            extra={'event': 'login_failed', 'kind': 'login', 'account_hash': _bf_hash_for_log(account), 'ip': ip, 'count': count, 'tier': tier}
        )
    except Exception:
        pass


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


def _get_bond_fernet(bond_id: str) -> Fernet:
    """Per-bond Fernet instance. Derives key from SECRET_KEY + bond_id salt."""
    cached = database._bond_fernet_cache.get(bond_id)
    if cached:
        return cached
    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    salt = f'echowithin_bonds_v1_{bond_id}'.encode()
    key = _derive_fernet_key(secret, salt, _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    database._bond_fernet_cache[bond_id] = f
    return f


def encrypt_bond_data(content: str, bond_id: str) -> str:
    """Encrypts bond content (journal entries, QotD answers, goals, etc.) using per-bond key."""
    if not content:
        return content
    try:
        f = _get_bond_fernet(str(bond_id))
        return f.encrypt(content.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"Error encrypting bond data for bond {bond_id}: {e}")
        raise


def decrypt_bond_data(encrypted_content: str, bond_id: str) -> str:
    """Decrypts bond content using per-bond key. Falls back to raw text if legacy/unencrypted."""
    if not encrypted_content:
        return encrypted_content
    try:
        f = _get_bond_fernet(str(bond_id))
        return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception:
        # If decryption fails and text doesn't look like Fernet ciphertext, return raw (legacy/plaintext)
        if not encrypted_content.startswith('gAAAAA'):
            return encrypted_content
        _get_app().logger.warning(f"Bond data decryption failed for bond {bond_id}")
        return '[Content unavailable — decryption error]'


def _get_form_fernet(form_id: str) -> Fernet:
    """Per-form Fernet — encrypted at rest with server-held key (not E2E). Reuses per-bond pattern."""
    cached = database._form_fernet_cache.get(str(form_id))
    if cached:
        return cached
    secret = _get_app().config["SECRET_KEY"].encode() if isinstance(_get_app().config["SECRET_KEY"], str) else _get_app().config["SECRET_KEY"]
    salt = f'echowithin_forms_v1_{form_id}'.encode()
    key = _derive_fernet_key(secret, salt, _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    database._form_fernet_cache[str(form_id)] = f
    return f


def encrypt_form_response(plaintext: str, form_id: str) -> str:
    """Encrypt a single form answer value at rest (per-form key)."""
    if not plaintext:
        return plaintext
    try:
        f = _get_form_fernet(str(form_id))
        return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _get_app().logger.error(f"Error encrypting form response {form_id}: {e}")
        raise


def decrypt_form_response(ciphertext: str, form_id: str) -> str:
    """Decrypt a form answer value. Falls back to plaintext if not Fernet."""
    if not ciphertext:
        return ciphertext
    try:
        f = _get_form_fernet(str(form_id))
        return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception:
        if not ciphertext.startswith('gAAAAA'):
            return ciphertext
        _get_app().logger.warning(f"Form response decryption failed for form {form_id}")
        return '[Unavailable]'


def generate_signed_cloudinary_url(public_id: str, resource_type: str = 'image', delivery_type: str = 'authenticated', expires_in: int = 900) -> str:
    """Generates a short-lived signed Cloudinary URL for private/authenticated assets.

    URLs expire after ``expires_in`` seconds (default 15 minutes). Because stored
    URLs can expire, callers MUST store the ``public_id`` alongside and re-sign at
    read/serve time via :func:`re_sign_cloudinary_url`.
    """
    if not public_id:
        return ''
    try:
        import time
        import cloudinary.utils
        signed_url, _ = cloudinary.utils.cloudinary_url(
            public_id,
            resource_type=resource_type or 'image',
            type=delivery_type or 'authenticated',
            sign_url=True,
            secure=True,
            expires_at=int(time.time()) + max(60, int(expires_in))
        )
        return signed_url
    except Exception as e:
        _get_app().logger.error(f"Failed to generate signed Cloudinary URL for {public_id}: {e}")
        return ''


def re_sign_cloudinary_url(public_id, resource_type='image', delivery_type='authenticated', expires_in=900, fallback_url=''):
    """Returns a fresh signed URL for a private Cloudinary asset.

    Falls back to ``fallback_url`` (e.g. a stored legacy URL) if no ``public_id``
    is available or signing fails. Never raises.
    """
    if public_id:
        signed = generate_signed_cloudinary_url(public_id, resource_type=resource_type or 'image', delivery_type=delivery_type or 'authenticated', expires_in=expires_in)
        if signed:
            return signed
    return fallback_url or ''


# ---------------------------------------------------------------------------
# SERVER-SIDE MEDIA ENCRYPTION-AT-REST
# ---------------------------------------------------------------------------
# Threat model: Cloudinary account holders / Cloudinary staff must NOT be able
# to read private media (even through the Cloudinary portal). All private media
# is therefore encrypted with a server-side key BEFORE upload to Cloudinary and
# stored there as opaque `raw` ciphertext. Media is served back through a Flask
# proxy endpoint that fetches the ciphertext, decrypts it, and streams it with
# the correct MIME type.
#
# The proxy uses a short-lived HMAC-signed capability URL (validated with
# SECRET_KEY), so possession of a URL grants access only until it expires —
# mirroring the expiring signed-Cloudinary-URL behaviour for legacy assets.
# ---------------------------------------------------------------------------

_MEDIA_FERNET_CACHE = {}


def _get_media_fernet():
    """Fernet instance used to encrypt/decrypt private media bytes at rest."""
    if 'instance' in _MEDIA_FERNET_CACHE:
        return _MEDIA_FERNET_CACHE['instance']
    app = _get_app()
    secret = app.config["SECRET_KEY"].encode() if isinstance(app.config["SECRET_KEY"], str) else app.config["SECRET_KEY"]
    key = _derive_fernet_key(secret, b'echowithin_media_at_rest_v1', _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    _MEDIA_FERNET_CACHE['instance'] = f
    return f


def encrypt_media_bytes(data):
    """Encrypts raw media bytes for storage. Accepts bytes/bytearray or a file-like object."""
    if data is None:
        return None
    if hasattr(data, 'read'):
        data = data.read()
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        data = str(data).encode('utf-8')
    return _get_media_fernet().encrypt(data)


def decrypt_media_bytes(token_bytes):
    """Decrypts media ciphertext bytes. Returns plaintext bytes. Raises on tamper."""
    if token_bytes is None:
        raise ValueError('No media ciphertext provided')
    if isinstance(token_bytes, bytearray):
        token_bytes = bytes(token_bytes)
    return _get_media_fernet().decrypt(token_bytes)


def _media_signature(public_id, expires_at):
    """HMAC-SHA256 capability signature for the media proxy URL."""
    app = _get_app()
    secret = app.config["SECRET_KEY"].encode() if isinstance(app.config["SECRET_KEY"], str) else app.config["SECRET_KEY"]
    msg = (f"{public_id}|{int(expires_at)}").encode('utf-8')
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]


def build_media_serve_url(public_id, mime_type='application/octet-stream', expires_in=900):
    """Builds a short-lived capability URL for the encrypted-media proxy.

    Must be called inside an active request/app context (uses ``url_for``).
    Returns '' on failure.
    """
    if not public_id:
        return ''
    try:
        expires_at = int(_time.time()) + max(60, int(expires_in))
        sig = _media_signature(public_id, expires_at)
        return url_for('serve_encrypted_media', public_id=public_id, mime=quote(str(mime_type or 'application/octet-stream')), expires=expires_at, sig=sig, _external=True)
    except Exception as e:
        _get_app().logger.error(f"Failed to build media serve URL for {public_id}: {e}")
        return ''


def media_serve_token_valid(public_id, expires_at, sig):
    """Validates a media proxy capability token (expiry + HMAC)."""
    try:
        expires_at = int(expires_at)
    except (TypeError, ValueError):
        return False
    if _time.time() > expires_at:
        return False
    if not sig or not public_id:
        return False
    expected = _media_signature(public_id, expires_at)
    return hmac.compare_digest(expected, sig)


def is_media_proxy_url(url):
    """True if the URL points at our encrypted-media proxy (not a Cloudinary URL)."""
    if not url:
        return False
    return '/media/' in url or '/__media/' in url




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


def _invalidate_user_fernet_v3(user_id: str):
    """Remove the v3 Fernet cache entry for a user.

    Call this after setting encryption_key_enc on a user document
    (e.g. during a background migration from v2 to v3) so the next
    encrypt/decrypt operation re-derives the Fernet from the fresh DEK.
    """
    uid = str(user_id)
    database._user_fernet_v3_cache.pop(uid, None)


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


def _invalidate_dm_fernet_v3(user1_id: str, user2_id: str):
    """Remove the v3 DM Fernet cache entry for a conversation.

    Call this after setting conversation_key_enc on a dm_permissions document
    so the next encrypt/decrypt operation re-derives the Fernet from the fresh DEK.
    """
    uids = sorted([str(user1_id), str(user2_id)])
    conv_id = f"{uids[0]}_{uids[1]}"
    database._dm_fernet_v3_cache.pop(conv_id, None)


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
    except Exception as e:
        if isinstance(encrypted_content, str) and encrypted_content.startswith('gAAAAA'):
            _get_app().logger.warning(f"DM Decryption failed for user pair ({user1_id}, {user2_id}): {e}")
            return '[Content unavailable \u2014 decryption error]'
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


def _cache_encrypt_value(plain_text):
    """Encrypt cached plaintext before storing in Redis (defense at rest)."""
    try:
        return get_notes_fernet().encrypt(plain_text.encode('utf-8'))
    except Exception:
        return plain_text.encode('utf-8')


def _cache_decrypt_value(cipher_bytes):
    """Decrypt a Redis-cached note value. Returns plaintext or None on failure."""
    try:
        if cipher_bytes is None:
            return None
        return get_notes_fernet().decrypt(cipher_bytes).decode('utf-8')
    except Exception:
        # Fall back: value may be a legacy unencrypted cache entry.
        try:
            return cipher_bytes.decode('utf-8')
        except Exception:
            return None

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
                    decrypted_content = _cache_decrypt_value(cached)
                    if decrypted_content is not None:
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
                    _cache_encrypt_value(decrypted)
                )
            except Exception:
                pass

    # 4. Apply preview truncation if requested
    if max_preview_chars and len(decrypted) > max_preview_chars:
        preview = decrypted[:max_preview_chars] + '...'
    else:
        preview = decrypted

    return preview


def _decrypt_note_metadata(note, share=None):
    """Decrypt reference and tags fields of a note record in-place."""
    if not note or not isinstance(note, dict):
        return note
    candidates = _note_decryption_candidates(note, share)

    ref = note.get('reference')
    if ref and isinstance(ref, str) and ref.startswith('gAAAAA'):
        dec_ref = _decrypt_with_candidate_ids(ref, candidates)
        if dec_ref is not None:
            note['reference'] = dec_ref

    tags = note.get('tags')
    if tags and isinstance(tags, list):
        dec_tags = []
        for t in tags:
            if t and isinstance(t, str) and t.startswith('gAAAAA'):
                dec_t = _decrypt_with_candidate_ids(t, candidates)
                dec_tags.append(dec_t if dec_t is not None else t)
            else:
                dec_tags.append(t)
        note['tags'] = dec_tags
    return note



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
        if not current_user.is_authenticated:
            flash("You must be logged in to perform this action.", "danger")
            return redirect(url_for('pages.dashboard'))
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


def hash_app_token(token):
    """Return the SHA-256 digest of an app token.

    SECURITY: app tokens are stored hashed at rest (never plaintext) so a
    database read cannot be used to impersonate a mobile session. Legacy
    plaintext-stored tokens remain valid until they expire naturally.
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_app_token(user_id, token=None):
    """Create a new app token document storing ONLY the hash.

    Returns the raw token (to hand to the client) and inserts a document
    with the hashed form. Legacy lookups (models.load_user_from_request)
    match against both `token_hash` and the old `token` field.
    """
    import database as _db
    raw = token or _secrets.token_urlsafe(48)
    doc = {
        'token_hash': hash_app_token(raw),
        'user_id': user_id,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
    }
    # Only store the legacy plaintext field when we are explicitly migrating
    # an existing token; new tokens are hash-only.
    if token is not None:
        doc['token'] = raw
    _db.app_tokens_conf.insert_one(doc)
    return raw