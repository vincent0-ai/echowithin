import datetime
from bson.objectid import ObjectId
from flask_login import UserMixin, current_user
from flask import request
from cachetools import TTLCache
from config import TIER_LIMITS, PREMIUM_TRIAL_DAYS
from database import users_conf, app_tokens_conf, user_loader_cache, redis_cache
from security import get_user_tier, is_on_trial, get_trial_days_remaining


class User(UserMixin):
    def __init__(self, user_data):
        # Store user-specific properties
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.is_admin = user_data.get('is_admin', False)
        self._is_active = user_data.get('is_confirmed', False)
        # Track when user last checked their activity tab
        self.last_activity_check = user_data.get('last_activity_check')
        # Email notification preference: 'immediate', 'weekly', or 'none'
        self.notification_preference = user_data.get('notification_preference', 'weekly')
        # Premium tier
        self._user_data_tier = user_data  # cache for tier resolution
        self.account_tier = get_user_tier(user_data)

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_premium(self):
        return self.account_tier == 'premium'

    @property
    def is_trial(self):
        return is_on_trial(self._user_data_tier)

    @property
    def trial_days_remaining(self):
        return get_trial_days_remaining(self._user_data_tier)

    def get_limit(self, limit_name):
        return TIER_LIMITS.get(self.account_tier, TIER_LIMITS['free']).get(limit_name)

    def get_admin(self):
        return self.is_admin


def load_user(user_id):
    """Load user with caching to avoid DB query on every request.

    Flask-Login calls this on EVERY request for authenticated users.
    Without caching, this causes massive DB load and slow response times.
    Cache TTL of 30 seconds balances performance with data freshness.
    """
    cache_key = f"user:{user_id}"

    # Try cache first
    cached_user = user_loader_cache.get(cache_key)
    if cached_user is not None:
        # Return cached User object (or None if cached as missing)
        return cached_user if cached_user != '__none__' else None

    # Cache miss - query database
    user_data = users_conf.find_one({"_id": ObjectId(user_id)})

    if user_data:
        user_obj = User(user_data)
        user_loader_cache[cache_key] = user_obj
        return user_obj
    else:
        # Cache the "not found" result too to avoid repeated queries
        user_loader_cache[cache_key] = '__none__'
        return None


def load_user_from_request(req):
    """Authenticate API requests using a persistent app token.

    The Android app sends an X-App-Token header (or Bearer token) instead
    of browser session cookies. This callback lets Flask-Login transparently
    authenticate those requests. Website users are unaffected because they
    never send these headers — they rely on the session-based user_loader.
    """
    if req.path == '/api/messages/schedule/process':
        return None

    # 1. Check X-App-Token header (preferred for native apps)
    token = req.headers.get('X-App-Token', '').strip()
    token_src = "X-App-Token header"

    # 2. Fallback: Authorization: Bearer <token>
    if not token:
        auth_header = req.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            token_src = "Authorization Bearer header"

    # 3. Fallback: httpOnly cookie set during login
    if not token:
        token = req.cookies.get('x_app_token', '').strip()
        token_src = "x_app_token cookie"

    if not token:
        # Don't log normal web requests that have no tokens
        if req.path.startswith('/api/') and req.path != '/api/messages/schedule/process':
            print(f"[DEBUG REQ_LOADER] Path: {req.path}. No token found in headers or cookies.", flush=True)
        return None

    print(f"[DEBUG REQ_LOADER] Path: {req.path}. Token found in {token_src}: '{token[:12]}...'", flush=True)

    doc = app_tokens_conf.find_one({'token': token})
    if not doc:
        print(f"[DEBUG REQ_LOADER] Token '{token[:12]}...' NOT found in app_tokens collection.", flush=True)
        return None

    print(f"[DEBUG REQ_LOADER] Token document found for user_id: {doc.get('user_id')}", flush=True)

    user_data = users_conf.find_one({'_id': doc['user_id']})
    if not user_data:
        print(f"[DEBUG REQ_LOADER] User with ID {doc['user_id']} not found in users collection.", flush=True)
        return None

    if user_data.get('is_banned'):
        print(f"[DEBUG REQ_LOADER] User '{user_data.get('username')}' is banned.", flush=True)
        return None

    print(f"[DEBUG REQ_LOADER] User authenticated successfully: '{user_data.get('username')}'", flush=True)
    return User(user_data)
