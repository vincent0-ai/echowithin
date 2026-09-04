
try:
    from gevent import monkey
    monkey.patch_all()
except ImportError:
    pass

# Patch gevent socket sendall & WSGIHandler write/sendall to handle Python 3.12 string/bytes compatibility
try:
    import gevent.socket
    _orig_socket_sendall = gevent.socket.socket.sendall
    def _patched_socket_sendall(self, data, *args, **kwargs):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return _orig_socket_sendall(self, data, *args, **kwargs)
    gevent.socket.socket.sendall = _patched_socket_sendall
except Exception:
    pass

try:
    import gevent._socketcommon
    _orig_sc_sendall = gevent._socketcommon.socket.sendall
    def _patched_sc_sendall(self, data, *args, **kwargs):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return _orig_sc_sendall(self, data, *args, **kwargs)
    gevent._socketcommon.socket.sendall = _patched_sc_sendall
except Exception:
    pass

try:
    import gevent.pywsgi
    _orig_pywsgi_write = gevent.pywsgi.WSGIHandler.write
    def _patched_pywsgi_write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return _orig_pywsgi_write(self, data)
    gevent.pywsgi.WSGIHandler.write = _patched_pywsgi_write

    _orig_pywsgi_sendall = gevent.pywsgi.WSGIHandler._sendall
    def _patched_pywsgi_sendall(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return _orig_pywsgi_sendall(self, data)
    gevent.pywsgi.WSGIHandler._sendall = _patched_pywsgi_sendall
except Exception:
    pass

try:
    import geventwebsocket.handler
    _orig_gws_write = geventwebsocket.handler.WebSocketHandler.write
    def _patched_gws_write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return _orig_gws_write(self, data)
    geventwebsocket.handler.WebSocketHandler.write = _patched_gws_write
except Exception:
    pass

import datetime
import hashlib
import random
import re
import sys
import time
import threading

from flask import Flask, g, request, jsonify, render_template, url_for, redirect, session, flash, make_response, Response, send_from_directory, send_file, abort
import logging
import math
import redis
import bleach
import base64
from flask_rq2 import RQ
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
from flask_mail import Mail, Message
from concurrent.futures import ThreadPoolExecutor
import database
import os
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.son import SON
from ratelimit import limits as _limits_base, RateLimitException
from security import (is_safe_url, is_same_origin_request, parse_iso_utc,
    build_unified_diff_text, build_merge_preview_text, get_active_achievements,
    limits, safe_object_id, admin_required, owner_required,
    _derive_fernet_key, _get_notes_encryption_key, get_notes_fernet,
    _get_user_fernet, _get_dm_fernet, encrypt_dm, decrypt_dm,
    encrypt_note, decrypt_note, encrypt_bond_data, decrypt_bond_data, generate_signed_cloudinary_url, re_sign_cloudinary_url, _candidate_user_ids,
    encrypt_media_bytes, decrypt_media_bytes, build_media_serve_url, media_serve_token_valid, is_media_proxy_url,
    _decrypt_with_candidate_ids, _note_decryption_candidates,
    _decrypt_note_record, _decrypt_note_metadata, _get_community_fernet,
    encrypt_community_note, decrypt_community_note,
    invalidate_note_decryption_cache,
    generate_user_envelope_keys, generate_conversation_envelope_keys,
    _get_user_fernet_v3, _get_dm_fernet_v3, _encrypt_dek, _decrypt_dek)
from utils import (linkify_filter, _linkify_target_blank, markdown_filter,
    from_timestamp_filter, to_iso_filter, to_local_filter, localtime_filter,
    optimize_cloudinary_url, extract_cloudinary_public_id,
    cleanup_share_media, cleanup_post_media,
    get_user_tier, get_limit, is_premium, is_on_trial, get_trial_days_remaining,
    _note_to_typesense_doc, _is_ios_web_push_subscription,
    _remove_stale_push_subscription, index_note_to_typesense,
    remove_note_from_typesense, remove_notes_from_typesense,
    reindex_user_notes_to_typesense, _post_to_typesense_doc,
    index_post_to_typesense, reindex_all_posts_to_typesense,
    reindex_all_notes_to_typesense,
    comment_count_cache, get_batch_comment_counts, prepare_posts,
    get_public_posts_filter, calculate_hot_score, _serialize_comment, _get_user_badge_count,
    _invalidate_badge_cache, _has_active_auto_approve,
    can_dm, fetch_link_preview, _deliver_scheduled_message,
    _nlp_suggest_tags, get_zen_quote, is_blocked_by)
from models import User, load_user, load_user_from_request
# Import and register blueprints
from blueprints.pages import bp as pages_bp
from blueprints.auth import bp as auth_bp
from blueprints.push import bp as push_bp
from blueprints.payments import bp as payments_bp
from blueprints.profile import bp as profile_bp
from blueprints.blog import bp as blog_bp
from blueprints.notes import bp as notes_bp
from blueprints.sharing import bp as sharing_bp
from blueprints.chat import bp as chat_bp
from blueprints.communities import bp as communities_bp
from blueprints.admin import bp as admin_bp
from blueprints.whisper import bp as whisper_bp
from blueprints.bonds import bp as bonds_bp
from blueprints.forms import bp as forms_bp
from blueprints.game import bp as game_bp
from api import api_bp

from notifications import (send_code, send_reset_code, send_account_deletion_code, send_new_post_notifications,
    send_weekly_newsletter, send_push_notification_to_user,
    send_admin_broadcast_push, send_push_notifications_for_new_post,
    send_fcm_notification_to_user, send_fcm_notifications_batch,
    send_push_notification_for_comment, process_image_for_nsfw,
    send_log_email_job, send_ntfy_notification)
import secrets
from cachetools import cached, TTLCache
import requests
from werkzeug.utils import secure_filename
import hmac
from slugify import slugify
import cloudinary
import cloudinary.uploader
import json
from logging.handlers import RotatingFileHandler
import markdown
import html
import difflib
from pythonjsonlogger import jsonlogger
from requests_oauthlib import OAuth2Session
from werkzeug.middleware.proxy_fix import ProxyFix
# Typesense full-text search — see typesense_client.py
from PIL import Image
from io import BytesIO
from pywebpush import webpush, WebPushException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse, urljoin

from config import (clean_xml_text, get_env_variable, ENGAGEMENT_WEIGHTS,
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, UPLOAD_FOLDER,
    ALLOWED_IMAGE_EXTENSIONS, ALLOWED_VIDEO_EXTENSIONS, ALLOWED_AUDIO_EXTENSIONS,
    ALLOWED_DOCUMENT_EXTENSIONS,
    MAX_VIDEO_SIZE, MAX_IMAGE_SIZE, TEMP_UPLOAD_FOLDER,
    VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY, REDIS_HOST, REDIS_PORT, REDIS_PASSWORD,
    TIME, BYPASS_RATE_LIMIT, _NOTES_KDF_ITERATIONS, _NOTES_V1_SALT,
    TIER_LIMITS, PREMIUM_TRIAL_DAYS, PREMIUM_PRICE_KSH,
    PREDEFINED_TAGS, _TAG_KEYWORDS, FIREBASE_AVAILABLE)



# --- Global Configurations & shared state ---

# Shared thread pool for background tasks (avoids overhead of creating new pools)
executor = ThreadPoolExecutor(max_workers=10)

app = Flask(__name__)
csrf = CSRFProtect(app)

# Register all blueprints
app.register_blueprint(pages_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(push_bp)
app.register_blueprint(payments_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(blog_bp)
app.register_blueprint(notes_bp)
app.register_blueprint(sharing_bp)
app.register_blueprint(chat_bp)
app.register_blueprint(communities_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(whisper_bp)
app.register_blueprint(bonds_bp)
app.register_blueprint(forms_bp)
app.register_blueprint(game_bp)
app.register_blueprint(api_bp, url_prefix='/api/v1')


@app.route('/media/<path:public_id>')
def serve_encrypted_media(public_id):
    """Streams decrypted private media fetched from Cloudinary raw storage.

    The URL carries a short-lived HMAC capability token (see security.build_media_serve_url).
    Media is encrypted at rest with a server-side key before upload, so Cloudinary
    account holders/staff can never read the plaintext content.
    """
    # SECURITY: validate/allowlist the served MIME type instead of echoing the
    # caller-supplied value verbatim (stored-XSS hardening under CSP).
    _mime_allowlist = {
        'image/jpeg': ('.jpg', '.jpeg'),
        'image/png': ('.png',),
        'image/gif': ('.gif',),
        'image/webp': ('.webp',),
        'audio/mpeg': ('.mp3',),
        'audio/ogg': ('.ogg', '.oga'),
        'audio/wav': ('.wav',),
        'audio/webm': ('.webm',),
        'audio/mp4': ('.m4a',),
        'video/mp4': ('.mp4',),
        'video/webm': ('.webm',),
        'application/pdf': ('.pdf',),
        'text/plain': ('.txt',),
        'application/octet-stream': (),
    }
    requested_mime = (request.args.get('mime') or 'application/octet-stream').split(';')[0].strip().lower()
    mime = requested_mime if requested_mime in _mime_allowlist else 'application/octet-stream'
    expires = request.args.get('expires', type=int)
    sig = request.args.get('sig', '')
    if not media_serve_token_valid(public_id, expires, sig):
        return abort(403)
    try:
        signed_raw = generate_signed_cloudinary_url(public_id, resource_type='raw', delivery_type='authenticated')
        if not signed_raw:
            app.logger.error(f"No Cloudinary raw URL available for encrypted media {public_id}")
            return abort(404)
        r = requests.get(signed_raw, timeout=30)
        if r.status_code != 200:
            app.logger.error(f"Cloudinary fetch failed for encrypted media {public_id}: HTTP {r.status_code}")
            return abort(404)
        plain = decrypt_media_bytes(r.content)
    except Exception as e:
        app.logger.error(f"Media serve error for {public_id}: {e}")
        return abort(404)
    resp = Response(plain, mimetype=mime)
    resp.headers['Cache-Control'] = 'private, max-age=300'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Content-Disposition'] = 'inline'
    return resp

# CSRF exemptions — these routes accept external/API requests without CSRF tokens
csrf.exempt(api_bp)  # Entire API blueprint (mobile app, external clients)
# Individual views that receive requests without CSRF tokens (webhooks, mobile, external)
csrf.exempt(app.view_functions['auth.confirm'])
csrf.exempt(app.view_functions['auth.app_reauth'])
csrf.exempt(app.view_functions['push.subscribe_push'])
csrf.exempt(app.view_functions['push.unsubscribe_push'])
csrf.exempt(app.view_functions['payments.paystack_webhook'])
csrf.exempt(app.view_functions['notes.api_mark_activity_read'])
csrf.exempt(app.view_functions['chat.api_process_scheduled_messages'])
csrf.exempt(app.view_functions['pages.unsubscribe'])
csrf.exempt(app.view_functions['forms.submit_form'])


@app.route('/api/csrf-token')
@login_required
def get_csrf_token():
    """Lightweight endpoint returning a fresh CSRF token.

    Used by the client-side auto-refresh module in base.html so that
    long-lived pages always have a valid token without scraping entire
    HTML pages.  GET-only, requires authentication.
    """
    from flask_wtf.csrf import generate_csrf
    return jsonify({'csrf_token': generate_csrf()})


# Register template filters
app.add_template_filter(linkify_filter, 'linkify')
app.add_template_filter(markdown_filter, 'markdown')
app.add_template_filter(from_timestamp_filter, 'from_timestamp')
app.add_template_filter(to_iso_filter, 'to_iso')
app.add_template_filter(to_local_filter, 'to_local')
app.add_template_filter(localtime_filter, 'localtime')

# --- Request-ID logging filter ---
class RequestIDFilter(logging.Filter):
    def filter(self, record):
        try:
            record.request_id = getattr(g, 'request_id', '-')
        except RuntimeError:
            record.request_id = '-'
        return True

@app.before_request
def set_request_id():
    g.request_id = secrets.token_hex(8)

@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)

@app.before_request
def start_request_timer():
    g._request_start = time.time()

@app.after_request
def log_request_time(response):
    elapsed = (time.time() - getattr(g, '_request_start', time.time())) * 1000
    if elapsed > 500:
        app.logger.warning(f"SLOW REQUEST: {request.method} {request.path} -> {elapsed:.0f}ms")
    response.headers['X-Response-Time'] = f"{elapsed:.0f}ms"
    return response

# --- Periodic global state cleanup ---
_last_state_cleanup = {'at': 0}

@app.before_request
def cleanup_stale_global_state():
    now_ts = time.time()
    if now_ts - _last_state_cleanup['at'] < 300:
        return
    _last_state_cleanup['at'] = now_ts

    for user_id, partners in list(active_chat_views.items()):
        if not partners:
            active_chat_views.pop(user_id, None)

    for share_id in list(active_note_viewers.keys()):
        if not active_note_viewers[share_id]:
            active_note_viewers.pop(share_id, None)

    for share_id, lock_data in list(note_locks.items()):
        lock_age = now_ts - lock_data.get('timestamp', now_ts)
        if lock_age > 180:
            try:
                socketio.emit('lock_released', {'share_id': share_id}, room=share_id)
            except Exception:
                pass
            note_locks.pop(share_id, None)

    for lobby_id in list(active_game_players.keys()):
        if not active_game_players[lobby_id]:
            active_game_players.pop(lobby_id, None)
# Restrict CORS to the canonical domain (prevents Cross-Site WebSocket Hijacking)
_ALLOWED_ORIGINS = os.environ.get('SOCKETIO_ALLOWED_ORIGINS', 'https://echowithin.xyz,https://blog.echowithin.xyz,https://staging.echowithin.xyz').split(',')
socketio = SocketIO(cors_allowed_origins=_ALLOWED_ORIGINS, async_mode='gevent')

# Use ProxyFix to handle headers from reverse proxies (like Render)
# This is important for url_for to generate correct https links.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

if not app.debug:
    log_file_path = 'echowithin.log'
    file_handler = RotatingFileHandler(log_file_path, maxBytes=1024 * 1024 * 10, backupCount=5)

    # Set the logging level (e.g., INFO, WARNING, ERROR)
    file_handler.setLevel(logging.INFO)

    # Define the format for the log messages
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d %(request_id)s'
    )
    file_handler.setFormatter(formatter)

    # Add the handler to the app's logger
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.addFilter(RequestIDFilter())
    app.logger.info('EchoWithin application startup')

login_manager = LoginManager(app)
login_manager.user_loader(load_user)
login_manager.request_loader(load_user_from_request)
login_manager.login_view = 'auth.login'  # snyk:disable=security-issue

# Return JSON 401 for API/mobile requests instead of redirecting to the login page
@login_manager.unauthorized_handler
def unauthorized_api():
    """Return JSON 401 for API/native-app requests, redirect for web browser requests."""
    is_api = (request.is_json
            or request.headers.get('X-App-Token')
            or request.path.startswith('/api/'))
    
    # PRIVACY: gate the raw-path debug print to non-production environments.
    # The path itself can include secret share_ids (e.g. /share/<token>) and other
    # sensitive identifiers — never echo it into production logs.
    if app.debug:
        print(f"[DEBUG UNAUTHORIZED] Path: {request.path}, is_json: {request.is_json}, X-App-Token header present: {request.headers.get('X-App-Token') is not None}, is_api: {is_api}", flush=True)
    
    if is_api:
        return jsonify({'error': 'Authentication required. Please log in.'}), 401
    # Standard web browser flow — redirect to login page
    return redirect(url_for('auth.login'))


# Secure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent client-side JS from accessing the cookie
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true' # Only send cookie over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protection against CSRF

# Configure permanent session lifetime for "Remember Me"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=14)

# Flask-Login "Remember Me" cookie settings - CRITICAL for PWA persistence
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=14)
app.config['REMEMBER_COOKIE_SECURE'] = app.config['SESSION_COOKIE_SECURE']  # Only send over HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True  # Prevent JS access
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['REMEMBER_COOKIE_REFRESH_EACH_REQUEST'] = True  # Extend cookie on each visit
app.config['REMEMBER_COOKIE_NAME'] = 'echowithin_remember'  # Custom name for remember cookie

# Session cookie name - helps with PWA cookie isolation
app.config['SESSION_COOKIE_NAME'] = 'echowithin_session'

# CSRF token lifetime: tie tokens to the session instead of a fixed clock.
# Without this, Flask-WTF defaults to 3600s and tokens baked into rendered
# HTML expire server-side while the user is still on the page, causing
# "Network Error" on every form/AJAX submit after ~1 hour of idle time.
app.config['WTF_CSRF_TIME_LIMIT'] = None  # valid for full session lifetime

# Make all sessions permanent by default for better PWA experience
@app.before_request
def make_session_permanent():
    session.permanent = True

# Ensure all external URLs are generated with https
app.config['PREFERRED_URL_SCHEME'] = 'https'




# Setup the secret key
app.config["SECRET_KEY"] = get_env_variable('SECRET')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Temporary Uploads for Background Processing ---
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER
os.makedirs(TEMP_UPLOAD_FOLDER, exist_ok=True)


# --- Cloudinary Configuration ---
cloudinary.config(cloud_name = get_env_variable('CLOUDINARY_CLOUD_NAME'), api_key = get_env_variable('CLOUDINARY_API_KEY'), api_secret = get_env_variable('CLOUDINARY_API_SECRET'))

# --- VAPID Configuration for Web Push Notifications ---
# Generate these keys using: vapid --gen or use an online generator
# Store the private key securely and share the public key with clients
_vapid_sub_raw = os.environ.get('VAPID_SUBJECT', '').strip()
if _vapid_sub_raw and (_vapid_sub_raw.startswith('mailto:') or _vapid_sub_raw.startswith('https://')):
    _vapid_sub = _vapid_sub_raw
else:
    mail_sender = os.environ.get('MAIL_USERNAME', 'admin@echowithin.xyz').strip()
    if '@' in mail_sender:
        _vapid_sub = f"mailto:{mail_sender}"
    else:
        _vapid_sub = 'mailto:admin@echowithin.xyz'
        if _vapid_sub_raw:
            app.logger.warning(
                "Invalid VAPID_SUBJECT format. Use mailto:you@example.com or https://yourdomain"
            )
VAPID_CLAIMS = {"sub": _vapid_sub}

# --- Firebase Admin SDK Configuration for FCM (Native App Push) ---
# This is separate from web push - it's for the native Android/iOS apps
# Can load credentials from:
#   1. FIREBASE_CREDENTIALS env var (JSON string - recommended for production)
#   2. FIREBASE_SERVICE_ACCOUNT env var pointing to a file path
#   3. Default file: firebase-service-account.json
FIREBASE_INITIALIZED = False
if FIREBASE_AVAILABLE:
    import firebase_admin
    from firebase_admin import credentials
    firebase_creds_json = os.environ.get('FIREBASE_CREDENTIALS', '').strip()
    firebase_service_account = os.environ.get('FIREBASE_SERVICE_ACCOUNT', 'firebase-service-account.json')
    
    try:
        if firebase_creds_json:
            # If the string doesn't start with '{', assume it's base64 encoded
            if not firebase_creds_json.strip().startswith('{'):
                import base64
                try:
                    firebase_creds_json = base64.b64decode(firebase_creds_json).decode('utf-8')
                except Exception as b_err:
                    app.logger.warning(f'Failed to base64 decode FIREBASE_CREDENTIALS: {b_err}')
                    
            # Load from environment variable (JSON string)
            cred_dict = json.loads(firebase_creds_json, strict=False)
            
            if cred_dict.get('private_key'):
                # Make sure real newlines are used instead of escaped literal strings if flattened
                cred_dict['private_key'] = cred_dict['private_key'].replace('\\n', '\n')
                
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            FIREBASE_INITIALIZED = True
            app.logger.info('Firebase Admin SDK initialized from FIREBASE_CREDENTIALS env var')
        elif os.path.exists(firebase_service_account):
            # Load from file
            cred = credentials.Certificate(firebase_service_account)
            firebase_admin.initialize_app(cred)
            FIREBASE_INITIALIZED = True
            app.logger.info('Firebase Admin SDK initialized from file')
        else:
            app.logger.debug('Firebase credentials not found, FCM notifications disabled')
    except json.JSONDecodeError as e:
        app.logger.warning(f'Invalid JSON in FIREBASE_CREDENTIALS env var: {e}')
    except Exception as e:
        app.logger.warning(f'Failed to initialize Firebase Admin SDK: {e}')


app.config['MAIL_SERVER'] = get_env_variable('MAIL_SERVER')
app.config['MAIL_PORT'] = int(get_env_variable('MAIL_PORT'))
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = get_env_variable('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = get_env_variable('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = get_env_variable('MAIL_USERNAME')

# Format with password
redis_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"

app.config['RQ_REDIS_URL'] = redis_url


def _sanitize_redis_url(url):
    """Redact the password from a redis:// URL before it reaches logs/traces."""
    if not url:
        return url
    return re.sub(r'(redis://)([^:@/]+:)([^@/]+)@', r'\1\2<redacted>@', url)


# Initialize Flask-RQ2 AFTER redis URL is configured
# This must happen after RQ_REDIS_URL is set, otherwise it defaults to localhost:6379
rq = RQ(app)

# Create Redis client for caching (separate from RQ)
try:
    redis_cache = redis.Redis(
        host=REDIS_HOST,
        port=int(REDIS_PORT),
        password=REDIS_PASSWORD,
        decode_responses=True,
        socket_connect_timeout=5
    )
    redis_cache.ping()  # Test connection
    app.logger.info('Redis cache connection established')
    if REDIS_PASSWORD:
        socketio_redis_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
    else:
        socketio_redis_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/0"
    socketio.init_app(app, message_queue=socketio_redis_url)
    app.logger.info('Socket.IO initialized with Redis message queue')
except Exception as e:
    app.logger.warning(f'Redis cache not available, using in-memory cache: {_sanitize_redis_url(str(e))}')
    redis_cache = None
    socketio.init_app(app)
    app.logger.info('Socket.IO initialized in fallback in-memory mode')

# In-memory cache fallback for pinned announcements (60 second TTL)
_pinned_announcement_cache = TTLCache(maxsize=1, ttl=60)

mail = Mail(app)

if BYPASS_RATE_LIMIT:
    app.logger.warning('Rate limiting is BYPASSED — development mode only!')

# --- Performance caching (in-memory with TTL) ---
# Profile stats cache: stores post/comment counts per user (30 second TTL)
profile_stats_cache = TTLCache(maxsize=256, ttl=30)
# Profile posts cache: stores paginated posts per user (30 second TTL)
profile_posts_cache = TTLCache(maxsize=256, ttl=30)
# View post related posts cache (2 minute TTL)
related_posts_cache = TTLCache(maxsize=128, ttl=120)
# View post comment stats cache (30 second TTL)
post_comment_stats_cache = TTLCache(maxsize=256, ttl=30)
# Community stats cache for home page (60 second TTL)
community_stats_cache = TTLCache(maxsize=1, ttl=60)
# Blog feed cache (60 second TTL - balanced freshness/performance)
blog_feed_cache = TTLCache(maxsize=1, ttl=60)
# User loader cache - CRITICAL for performance (30 second TTL)
# This caches user objects to avoid DB query on every single request
user_loader_cache = TTLCache(maxsize=512, ttl=30)
# Weekly winners cache: stores the most recent winners (1 hour TTL)
weekly_winners_cache = TTLCache(maxsize=1, ttl=3600)




# MongoDB connection with connection pooling for better performance
# maxPoolSize: Maximum number of connections in the pool
# minPoolSize: Minimum number of connections to maintain
# serverSelectionTimeoutMS: How long to wait for server selection
client = MongoClient(
    get_env_variable('MONGODB_CONNECTION'),
    maxPoolSize=20,  # Increased pool size for 4GB RAM VPS with 16 workers
    minPoolSize=4,   # Keep minimum connections ready
    serverSelectionTimeoutMS=5000,  # 5 second timeout
    connectTimeoutMS=10000,  # 10 second connection timeout
    socketTimeoutMS=30000,   # 30 second socket timeout
)
db = client['echowithin_db']
users_conf = db['users']
posts_conf = db['posts']
logs_conf = db['logs']
auth_conf = db['auth']
announcements_conf = db['announcements']
comments_conf = db['comments']
personal_posts_conf = db['personal_posts']
note_shares_conf = db['note_shares']
note_versions_conf = db['note_versions']
note_discussions_conf = db['note_discussions']
push_subscriptions_conf = db['push_subscriptions']
fcm_tokens_conf = db['fcm_tokens']  # FCM tokens for native app push notifications
direct_messages_conf = db['direct_messages']
newsletter_conf = db['newsletter_subs']
user_post_views_conf = db['user_post_views']
unlock_notifications_conf = db['unlock_notifications']
weekly_winners_conf = db['weekly_winners']
app_tokens_conf = db['app_tokens']  # Persistent auth tokens for native app session revival
app_updates_conf = db['app_updates']

# --- Forms (public share-link data collection) ---
forms_conf = db['forms']
form_responses_conf = db['form_responses']

# --- Game Lobbies (2+ players, anytime — poll/trivia/wyr/ttal/story/caption) ---
game_sessions_conf = db['game_sessions']
game_votes_conf = db['game_votes']
game_submissions_conf = db['game_submissions']  # TTAL statements, captions

# --- User Login Sessions (Active Sessions & Login History) ---
user_sessions_conf = db['user_sessions']
user_sessions_conf.create_index('user_id')
user_sessions_conf.create_index('session_token', unique=True)
user_sessions_conf.create_index('last_active', expireAfterSeconds=30 * 24 * 3600)  # Auto-expire after 30 days

# Sync update manifest between DB and static file on startup
# Keeps the latest version (by versionCode) in both places
def sync_update_manifest():
    try:
        import json
        import os

        # 1. Load DB manifest
        db_manifest = app_updates_conf.find_one({'key': 'latest'}) or {}
        db_code = db_manifest.get('versionCode', 0)

        # 2. Load static file manifest
        static_path = os.path.join(app.static_folder, 'update-manifest.json')
        static_code = 0
        static_manifest = {}
        if os.path.exists(static_path):
            try:
                with open(static_path, 'r', encoding='utf-8') as f:
                    static_manifest = json.load(f)
                static_code = static_manifest.get('versionCode', 0)
            except Exception as e:
                app.logger.warning(f"Failed to read static update manifest: {e}")

        # 3. Compare and sync to latest
        if static_code > db_code:
            # Static is newer -> write to DB
            if static_manifest:
                app_updates_conf.update_one(
                    {'key': 'latest'},
                    {'$set': {
                        'versionCode': static_manifest.get('versionCode'),
                        'versionName': static_manifest.get('versionName'),
                        'apkUrl': static_manifest.get('apkUrl'),
                        'changelog': static_manifest.get('changelog', ''),
                        'sha256': static_manifest.get('sha256', '')
                    }},
                    upsert=True
                )
                app.logger.info(f"Update manifest synced: static v{static_manifest.get('versionName')} (code {static_code}) -> DB")
        elif db_code > static_code:
            # DB is newer -> write to static file
            if db_manifest:
                try:
                    with open(static_path, 'w', encoding='utf-8') as f:
                        json.dump({
                            'versionCode': db_manifest.get('versionCode'),
                            'versionName': db_manifest.get('versionName'),
                            'apkUrl': db_manifest.get('apkUrl'),
                            'changelog': db_manifest.get('changelog', ''),
                            'sha256': db_manifest.get('sha256', '')
                        }, f, indent=2)
                    app.logger.info(f"Update manifest synced: DB v{db_manifest.get('versionName')} (code {db_code}) -> static")
                except Exception as e:
                    app.logger.warning(f"Failed to write static update manifest: {e}")
        elif db_code > 0:
            app.logger.info(f"Update manifest in sync: v{db_manifest.get('versionName')} (code {db_code})")
    except Exception as e:
        app.logger.warning(f"Update manifest sync failed: {e}")

sync_update_manifest()

# --- Community Notes Collections ---
communities_conf = db['communities']
community_notes_conf = db['community_notes']
community_reactions_conf = db['community_reactions']
community_reports_conf = db['community_reports']
post_reports_conf = db['post_reports']
community_challenges_conf = db['community_challenges']
community_polls_conf = db['community_polls']
community_poll_votes_conf = db['community_poll_votes']
community_resources_conf = db['community_resources']
community_checkins_conf = db['community_checkins']
community_premium_vouchers_conf = db['community_premium_vouchers']
community_memberships_conf = db['community_memberships']

# --- Direct Messaging Performance Indexes ---
direct_messages_conf.create_index([('sender_id', 1), ('recipient_id', 1), ('timestamp', -1)])
direct_messages_conf.create_index([('recipient_id', 1), ('is_read', 1)])
direct_messages_conf.create_index([('recipient_id', 1), ('timestamp', -1)])

# --- DM Permissions (Message Request System) ---
dm_permissions_conf = db['dm_permissions']
dm_permissions_conf.create_index([('requester_id', 1), ('target_id', 1)], unique=True)
dm_permissions_conf.create_index([('target_id', 1), ('status', 1)])

# --- Scheduled Messages ---
scheduled_messages_conf = db['scheduled_messages']
scheduled_messages_conf.create_index([('scheduled_at', 1), ('status', 1)])
scheduled_messages_conf.create_index([('sender_id', 1), ('status', 1)])

# --- Note Attachments (images & voice notes on shared/collaborative notes) ---
note_attachments_conf = db['note_attachments']
note_attachments_conf.create_index([('note_id', 1), ('created_at', 1)])

# --- Comment Votes ---
comment_votes_conf = db['comment_votes']
comment_votes_conf.create_index([('comment_id', 1), ('user_id', 1)], unique=True)

# --- Activities (notifications feed) ---
activities_conf = db['activities']
activities_conf.create_index([('user_id', 1), ('created_at', -1)])
activities_conf.create_index([('user_id', 1), ('is_read', 1)])

# --- Activity read-state (used by the Android 'mark all as read' button) ---
# One row per (user, comment) or (user, note_version) that the device has
# marked as read. `read_at` is null while the row is unacknowledged so
# `update_many({'read_at': None}, {'$set': {'read_at': now}})` can flip them
# in a single round-trip.
activity_read_conf = db['activity_read']
activity_read_conf.create_index([('user_id', 1), ('comment_id', 1)], unique=True, sparse=True)
activity_read_conf.create_index([('user_id', 1), ('read_at', 1)])

# --- Whisper Mode Collections ---
whisper_sessions_conf = db['whisper_sessions']
whisper_sessions_conf.create_index([('initiator_id', 1), ('status', 1)])
whisper_sessions_conf.create_index([('recipient_id', 1), ('status', 1)])
whisper_sessions_conf.create_index('expires_at', expireAfterSeconds=86400)  # cleanup 24h after expiry

whisper_messages_conf = db['whisper_messages']
whisper_messages_conf.create_index([('session_id', 1), ('timestamp', 1)])
whisper_messages_conf.create_index('expires_at', expireAfterSeconds=0)  # auto-delete at expires_at

# --- Bonds Collections ---
bonds_conf = db['bonds']
bonds_conf.create_index([('user_a_id', 1), ('user_b_id', 1), ('status', 1)])
bonds_conf.create_index([('user_a_id', 1), ('status', 1)])
bonds_conf.create_index([('user_b_id', 1), ('status', 1)])
bonds_conf.create_index('requested_by')

bond_goals_conf = db['bond_goals']
bond_goals_conf.create_index([('bond_id', 1), ('status', 1)])
bond_goals_conf.create_index([('bond_id', 1), ('created_at', -1)])

bond_journal_conf = db['bond_journal']
bond_journal_conf.create_index([('bond_id', 1), ('created_at', -1)])

bond_moods_conf = db['bond_moods']
bond_moods_conf.create_index([('bond_id', 1), ('date', 1), ('user_id', 1)], unique=True)

bond_qotd_conf = db['bond_qotd']
bond_qotd_conf.create_index([('bond_id', 1), ('date', 1)], unique=True)

bond_habits_conf = db['bond_habits']
bond_habits_conf.create_index([('bond_id', 1), ('archived', 1)])

bond_countdowns_conf = db['bond_countdowns']
bond_countdowns_conf.create_index([('bond_id', 1), ('archived', 1)])

# --- Bond Shared Calendar (Aggregated & Custom Events) ---
bond_events_conf = db['bond_events']
bond_events_conf.create_index([('bond_id', 1), ('start_date', 1), ('archived', 1)])
bond_events_conf.create_index([('created_by', 1)])

# --- Bond Shared Album (Photo Memories) ---
bond_album_photos_conf = db['bond_album_photos']
bond_album_photos_conf.create_index([('bond_id', 1), ('uploaded_at', -1)])

# --- Bond Bucket List ---
bond_bucketlist_conf = db['bond_bucketlist']
bond_bucketlist_conf.create_index([('bond_id', 1), ('status', 1)])

# --- Bond Media Recommendations ---
bond_recommendations_conf = db['bond_recommendations']
bond_recommendations_conf.create_index([('bond_id', 1), ('created_at', -1)])

# --- Bond Quick Pulse (anytime check-in) ---
bond_pulses_conf = db['bond_pulses']
bond_pulses_conf.create_index([('bond_id', 1), ('created_at', -1)])

# --- Community Question Bank (AI-generated QotD reuse across bonds) ---
community_questions_conf = db['community_questions']
community_questions_conf.create_index('bond_type')
community_questions_conf.create_index('question_hash', unique=True)

# Soft-delete for DMs — one row per (user, partner) means user hid the chat
hidden_chats_conf = db['hidden_chats']
hidden_chats_conf.create_index([('user_id', 1), ('partner_id', 1)], unique=True)

deleted_items_conf = db['deleted_items']
deleted_items_conf.create_index('expires_at', expireAfterSeconds=0)

# --- Paystack payment grants (idempotency + audit for premium activation) ---
payment_grants_conf = db['payment_grants']
payment_grants_conf.create_index('reference', unique=True)
payment_grants_conf.create_index('user_id')

# In-memory tracker for active chat views (user_id -> set of partner_ids they're viewing)
# Used to suppress push notifications when recipient is already in the chat
active_chat_views = {}

# In-memory tracker for shared note viewers (share_id -> {user_id: {name, avatar, id}})
# Used for real-time "Studying Now" presence avatars
active_note_viewers = {}

# In-memory edit locks for shared notes (share_id -> {user_id, user_name, timestamp})
# Prevents concurrent editing conflicts during Bible study sessions
note_locks = {}

# In-memory game lobby presence (lobby_id -> {user_id: {name, avatar, id}})
# Mirrors active_note_viewers pattern — 30 max via game logic, no persistence
active_game_players = {}
try:
    import database as _db_game
    _db_game.active_game_players = active_game_players
except Exception:
    pass


# Create index for push subscriptions to ensure unique endpoints per user
push_subscriptions_conf.create_index([('user_id', 1), ('endpoint', 1)], unique=True)
newsletter_conf.create_index('email', unique=True)
users_conf.create_index('username')
user_post_views_conf.create_index([('user_id', 1), ('post_id', 1)], unique=True)

# Personal space performance indexes — eliminates full-collection scans
personal_posts_conf.create_index([('user_id', 1), ('created_at', -1)])
personal_posts_conf.create_index([('source_note_id', 1), ('user_id', 1)])
personal_posts_conf.create_index([('user_id', 1), ('is_locked', 1), ('created_at', -1)])
note_shares_conf.create_index([('owner_id', 1), ('note_id', 1)])

# Ensure a text index exists on the posts collection for search functionality
posts_conf.create_index([('title', 'text'), ('content', 'text')])

# --- Performance indexes for faster queries ---
# Index for reactions lookups (personalized feed)
posts_conf.create_index([('reactions.heart', 1)])
posts_conf.create_index([('reactions.wow', 1)])
# Index for author lookups
posts_conf.create_index('author_id')
# Index for timestamp sorting (most common sort)
posts_conf.create_index([('timestamp', -1)])
# Compound index for tag filtering with timestamp sort
posts_conf.create_index([('tags', 1), ('timestamp', -1)])
# Index for comments lookups by post slug
comments_conf.create_index('post_slug')
# Index for comments by author
comments_conf.create_index('author_id')
# Compound index for engagement-based sorting (hot/top posts)
posts_conf.create_index([('likes_count', -1), ('timestamp', -1)])
posts_conf.create_index([('view_count', -1)])
# Compound index for view dedup checks in logs (type + post_id + user_identifier + timestamp)
logs_conf.create_index([('type', 1), ('post_id', 1), ('user_identifier', 1), ('timestamp', -1)])
# Index for note versions and discussions
note_versions_conf.create_index([('note_id', 1), ('created_at', -1)])
note_discussions_conf.create_index([('share_id', 1), ('created_at', -1)])
# TTL index to auto-expire app tokens after 90 days
app_tokens_conf.create_index('created_at', expireAfterSeconds=90*24*3600)
# Unique 'token' index MUST be sparse: new app tokens store only a hash
# (no plaintext 'token' field). A non-sparse unique index indexes missing
# fields as null, so only ONE hash-only token could ever be inserted
# (E11000 duplicate key { token: null }). Sparse exempts hash-only docs
# while still enforcing uniqueness among legacy plaintext tokens.
try:
    _tok_indexes = {idx['name']: idx for idx in app_tokens_conf.list_indexes()}
    _tok_old = _tok_indexes.get('token_1')
    if _tok_old and not _tok_old.get('sparse'):
        app_tokens_conf.drop_index('token_1')
except Exception:
    pass
app_tokens_conf.create_index('token', unique=True, sparse=True)
# Enforce uniqueness on the hashed token for hash-only app tokens.
try:
    app_tokens_conf.create_index('token_hash', unique=True, sparse=True)
except Exception:
    pass
app_tokens_conf.create_index('user_id')

# --- Community Notes Performance Indexes ---
communities_conf.create_index('admin_id')
communities_conf.create_index('invite_code', unique=True, sparse=True)
communities_conf.create_index([('members', 1)])
community_notes_conf.create_index([('community_id', 1), ('created_at', -1)])
community_notes_conf.create_index([('community_id', 1), ('score', -1)])
community_notes_conf.create_index('author_id')
community_reactions_conf.create_index([('note_id', 1), ('user_id', 1)], unique=True)
community_reactions_conf.create_index([('note_id', 1)])
community_reports_conf.create_index([('community_id', 1), ('status', 1)])
community_reports_conf.create_index('reporter_id')
post_reports_conf.create_index([('post_id', 1), ('status', 1)])
post_reports_conf.create_index('reporter_id')
post_reports_conf.create_index('created_at')
# One report per user per post — prevents spam + race duplicates (AUDIT F1/F2).
post_reports_conf.create_index([('post_id', 1), ('reporter_id', 1)], unique=True)
community_challenges_conf.create_index([('community_id', 1), ('status', 1)])
community_polls_conf.create_index([('community_id', 1), ('status', 1), ('created_at', -1)])
community_poll_votes_conf.create_index([('poll_id', 1), ('user_id', 1)], unique=True)
community_resources_conf.create_index([('community_id', 1), ('created_at', -1)])
community_checkins_conf.create_index([('community_id', 1), ('created_at', -1)])
community_premium_vouchers_conf.create_index('code', unique=True)
community_premium_vouchers_conf.create_index([('community_id', 1), ('active', 1)])

# --- Forms ---
forms_conf.create_index('share_id', unique=True, sparse=True)
forms_conf.create_index([('owner_id', 1), ('created_at', -1)])
form_responses_conf.create_index([('form_id', 1), ('submitted_at', -1)])
form_responses_conf.create_index([('share_id', 1), ('submitted_at', -1)])

# --- Game Lobbies (2+ players, anytime) ---
game_sessions_conf.create_index('lobby_id', unique=True, sparse=True)
game_sessions_conf.create_index([('host_id', 1), ('created_at', -1)])
# NOTE: Not unique — TTAL guesses create multiple docs per user per lobby.
# Application-level duplicate checks handle poll/trivia/wyr one-vote-per-user.
try:
    game_votes_conf.drop_index('lobby_id_1_user_id_1')
except Exception:
    pass
game_votes_conf.create_index([('lobby_id', 1), ('user_id', 1)])
game_votes_conf.create_index([('lobby_id', 1), ('submitted_at', -1)])
game_submissions_conf.create_index([('lobby_id', 1), ('user_id', 1), ('type', 1)], unique=True)
game_submissions_conf.create_index([('lobby_id', 1), ('type', 1)])

# --- Performance: Additional compound indexes for common query patterns ---
comments_conf.create_index([('post_slug', 1), ('is_deleted', 1), ('created_at', -1)])
comments_conf.create_index([('parent_id', 1), ('author_id', 1)])
posts_conf.create_index([('is_pinned', 1), ('pinned_at', -1)])
unlock_notifications_conf.create_index([('owner_id', 1), ('unlocked_at', -1)])
note_shares_conf.create_index('share_id', unique=True, sparse=True)

# Populate database module globals so other modules can import them
database.client = client
database.db = db
database.users_conf = users_conf
database.posts_conf = posts_conf
database.logs_conf = logs_conf
database.auth_conf = auth_conf
database.announcements_conf = announcements_conf
database.comments_conf = comments_conf
database.personal_posts_conf = personal_posts_conf
database.note_shares_conf = note_shares_conf
database.note_versions_conf = note_versions_conf
database.note_discussions_conf = note_discussions_conf
database.push_subscriptions_conf = push_subscriptions_conf
database.fcm_tokens_conf = fcm_tokens_conf
database.direct_messages_conf = direct_messages_conf
database.newsletter_conf = newsletter_conf
database.user_post_views_conf = user_post_views_conf
database.unlock_notifications_conf = unlock_notifications_conf
database.weekly_winners_conf = weekly_winners_conf
database.app_tokens_conf = app_tokens_conf
database.user_sessions_conf = user_sessions_conf
database.app_updates_conf = app_updates_conf
database.communities_conf = communities_conf
database.community_notes_conf = community_notes_conf
database.community_reactions_conf = community_reactions_conf
database.community_reports_conf = community_reports_conf
database.post_reports_conf = post_reports_conf
database.community_challenges_conf = community_challenges_conf
database.community_polls_conf = community_polls_conf
database.community_poll_votes_conf = community_poll_votes_conf
database.community_resources_conf = community_resources_conf
database.community_checkins_conf = community_checkins_conf
database.community_premium_vouchers_conf = community_premium_vouchers_conf
database.community_memberships_conf = community_memberships_conf
database.dm_permissions_conf = dm_permissions_conf
database.scheduled_messages_conf = scheduled_messages_conf
database.note_attachments_conf = note_attachments_conf
database.comment_votes_conf = comment_votes_conf
database.activities_conf = activities_conf
database.activity_read_conf = activity_read_conf
database.whisper_sessions_conf = whisper_sessions_conf
database.whisper_messages_conf = whisper_messages_conf
database.bonds_conf = bonds_conf
database.bond_goals_conf = bond_goals_conf
database.bond_journal_conf = bond_journal_conf
database.bond_moods_conf = bond_moods_conf
database.bond_qotd_conf = bond_qotd_conf
database.bond_habits_conf = bond_habits_conf
database.bond_countdowns_conf = bond_countdowns_conf
database.bond_events_conf = bond_events_conf
database.bond_album_photos_conf = bond_album_photos_conf
database.bond_bucketlist_conf = bond_bucketlist_conf
database.bond_recommendations_conf = bond_recommendations_conf
database.bond_pulses_conf = bond_pulses_conf
database.hidden_chats_conf = hidden_chats_conf
database.forms_conf = forms_conf
database.form_responses_conf = form_responses_conf
database.game_sessions_conf = game_sessions_conf
database.game_votes_conf = game_votes_conf
database.game_submissions_conf = game_submissions_conf


def purge_guest_user_data(guest_id_str):
    """Purge all ephemeral data for a guest tour session."""
    try:
        g_oid = safe_object_id(guest_id_str)
        if not g_oid:
            return
        user_doc = users_conf.find_one({'_id': g_oid, 'is_guest': True})
        if not user_doc:
            return

        # 0. Clear in-memory & Redis user loader caches
        user_loader_cache.pop(f"user:{guest_id_str}", None)
        if redis_cache:
            try:
                redis_cache.delete(f"last_active:{guest_id_str}")
            except Exception:
                pass
        
        # 1. Notes & shares
        personal_posts_conf.delete_many({'user_id': g_oid})
        note_shares_conf.delete_many({'$or': [{'owner_id': g_oid}, {'user_id': g_oid}]})
        
        # 2. Bonds & partner data
        bonds = list(bonds_conf.find({'$or': [{'user_a_id': g_oid}, {'user_b_id': g_oid}]}))
        for b in bonds:
            p_id = b['user_b_id'] if b['user_a_id'] == g_oid else b['user_a_id']
            users_conf.delete_one({'_id': p_id, 'is_demo_bot': True})
            user_loader_cache.pop(f"user:{str(p_id)}", None)

        bonds_conf.delete_many({'$or': [{'user_a_id': g_oid}, {'user_b_id': g_oid}]})
        bond_goals_conf.delete_many({'proposed_by': g_oid})
        bond_journal_conf.delete_many({'user_id': g_oid})
        bond_moods_conf.delete_many({'user_id': g_oid})
        bond_habits_conf.delete_many({'created_by': g_oid})
        bond_countdowns_conf.delete_many({'created_by': g_oid})
        bond_events_conf.delete_many({'created_by': g_oid})
        bond_album_photos_conf.delete_many({'uploaded_by': g_oid})
        bond_bucketlist_conf.delete_many({'proposed_by': g_oid})
        bond_recommendations_conf.delete_many({'recommended_by': g_oid})
        bond_pulses_conf.delete_many({'user_id': g_oid})

        # 3. Messages & Communities
        direct_messages_conf.delete_many({'$or': [{'sender_id': g_oid}, {'recipient_id': g_oid}]})
        dm_permissions_conf.delete_many({'$or': [{'requester_id': g_oid}, {'target_id': g_oid}]})
        community_memberships_conf.delete_many({'user_id': g_oid})

        # 4. User record
        users_conf.delete_one({'_id': g_oid})
        app.logger.info(f"Purged guest tour session: {guest_id_str}")
    except Exception as e:
        app.logger.error(f"Error purging guest user data: {e}")


def cleanup_expired_guest_sessions():
    """Background cleanup for guest sessions older than 20 minutes."""
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        twenty_mins_ago = now - datetime.timedelta(minutes=20)

        # Query for expired guest sessions with guest_expires_at <= now
        expired_guests = list(users_conf.find(
            {'is_guest': True, 'guest_expires_at': {'$exists': True, '$ne': None, '$lt': now}},
            {'_id': 1}
        ))
        # Fallback query: guests missing guest_expires_at created > 20 mins ago
        orphaned_guests = list(users_conf.find(
            {'is_guest': True, 'guest_expires_at': None, 'join_date': {'$lt': twenty_mins_ago}},
            {'_id': 1}
        ))

        all_expired_ids = set(str(g['_id']) for g in (expired_guests + orphaned_guests))
        for guest_id_str in all_expired_ids:
            purge_guest_user_data(guest_id_str)
        
        if all_expired_ids:
            app.logger.info(f"Purged {len(all_expired_ids)} expired guest session(s).")
    except Exception as e:
        app.logger.error(f"Error during expired guest cleanup: {e}")
database.deleted_items_conf = deleted_items_conf
database.payment_grants_conf = payment_grants_conf
database.redis_cache = redis_cache

# --- Encryption utilities for personal notes ---
# v2: Per-user key derivation with increased iterations (OWASP 2024 recommendation).
# Backward-compatible: falls back to v1 global key for notes encrypted before the upgrade.



# --- Community Encryption Utilities ---



# --- Typesense setup for fast full-text search ---
# Import Typesense client module (shared between main.py and api.py)
import typesense_client as _t
_t.start_init()

# Typesense state — always resolved from _t.<attr> to avoid stale capture at import




_last_guest_cleanup_time = 0

@app.before_request
def check_guest_expiration():
    """Ensure expired guest tour sessions are invalidated and purged immediately on any user request."""
    if current_user.is_authenticated and getattr(current_user, 'is_guest', False):
        if getattr(current_user, 'is_guest_expired', False):
            guest_id = str(current_user.id)
            logout_user()
            session.clear()
            purge_guest_user_data(guest_id)
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'guest_session_expired',
                    'message': 'Your 20-minute guest tour session has expired.'
                }), 401
            flash('Your 20-minute interactive tour session has expired.', 'info')
            return redirect(url_for('auth.login'))


@app.before_request
def periodic_guest_cleanup():
    """Periodically trigger background guest session cleanup every 60 seconds on incoming web traffic."""
    global _last_guest_cleanup_time
    now_ts = time.time()
    if now_ts - _last_guest_cleanup_time > 60:
        _last_guest_cleanup_time = now_ts
        try:
            executor.submit(cleanup_expired_guest_sessions)
        except Exception:
            cleanup_expired_guest_sessions()


@app.before_request
def update_last_active():
    """Update a user's last active timestamp with debouncing (every 5 minutes) to reduce DB load."""
    # Skip high-frequency polling and background endpoints — they don't represent meaningful user activity
    # /api/notifications/unread-count is called by the service worker on push events (user may be asleep)
    # /api/push/ covers subscription status checks
    # /api/sessions covers the active sessions validation check
    if request.path.startswith(('/api/messages/unread_count', '/api/notifications/badge-counts',
                                '/api/notifications/unread-count', '/api/push/',
                                '/api/sessions', '/socket.io/', '/static/', '/favicon.ico')):
        return
    if current_user.is_authenticated:
        user_id = current_user.id
        cache_key = f"last_active:{user_id}"

        # Check if we recently updated (within 5 minutes)
        should_update = True
        if redis_cache:
            try:
                if redis_cache.exists(cache_key):
                    should_update = False
            except Exception:
                pass  # Redis error, fall through to DB check

        if not should_update:
            # Skip DB queries entirely if recently updated
            return

        # Fetch the full user document to check for ban status
        user_doc = users_conf.find_one({'_id': ObjectId(user_id)}, {'is_banned': 1})

        # If user is banned, log them out immediately.
        if user_doc and user_doc.get('is_banned'):
            logout_user()
            flash('Your account has been suspended. Please contact support.', 'danger')
            return redirect(url_for('auth.login'))

        # Update last active time and set cache to prevent frequent updates
        if user_doc:
            users_conf.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': {'last_active': datetime.datetime.now(datetime.timezone.utc)}}
            )
            # Set cache key with 5 minute expiry to debounce updates
            # (5 minutes is the industry standard for "active now" — Discord, Slack, etc.)
            if redis_cache:
                try:
                    redis_cache.setex(cache_key, 300, '1')  # 300 seconds = 5 minutes
                except Exception:
                    pass


@app.before_request
def enforce_canonical_domain_and_https():
    # Skip for API calls and static assets — they're already on the canonical domain
    # and don't benefit from a redirect (saves CPU on high-frequency polling endpoints)
    if request.path.startswith(('/api/', '/static/', '/favicon.ico', '/socket.io/')):
        return

    host = request.headers.get('X-Forwarded-Host', request.host)
    scheme = request.headers.get('X-Forwarded-Proto', request.scheme)

    canonical_host = os.environ.get("CANONICAL_HOST", "echowithin.xyz")
    canonical_scheme = "https"

    needs_redirect = False

    # Fix host (remove www)
    if host != canonical_host:
        host = canonical_host
        needs_redirect = True

    # Fix scheme
    if scheme != canonical_scheme:
        scheme = canonical_scheme
        needs_redirect = True

    if needs_redirect:
        new_url = f"{scheme}://{host}{request.full_path}"
        return redirect(new_url, code=301)


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection (legacy but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions policy (restrict features)
    # Note: microphone is NOT blocked here so the PWA can request it for voice messages (user consent via browser prompt)
    response.headers['Permissions-Policy'] = 'geolocation=()'
    # HSTS - enforce HTTPS (1 year) with preload
    # Emit on every HTTPS response (including /api, /static, /socket.io),
    # not just when request.is_secure is set by the WSGI server, because
    # reverse-proxied requests carry the real scheme in X-Forwarded-Proto.
    effective_scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
    if request.is_secure or effective_scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # Content-Security-Policy — mitigates XSS, data injection, and click-jacking
    # NOTE: nonce infrastructure (g.csp_nonce, context processor, base.html nonce
    # attributes) is in place for a staged migration to nonce-based CSP.
    # Set CSP_STRICT_NONCES=true in production once ALL inline scripts in EVERY
    # template include nonce="{{ csp_nonce }}" AND inline event handlers
    # (onclick, onsubmit etc.) are replaced with addEventListener.
    _use_nonces = os.environ.get('CSP_STRICT_NONCES', '').lower() in ('1', 'true', 'yes')
    if _use_nonces:
        nonce = getattr(g, 'csp_nonce', '')
        script_src = (
            f"'self' 'nonce-{nonce}' https://cdn.socket.io https://cdn.jsdelivr.net "
            f"https://cdnjs.cloudflare.com https://js.stripe.com https://www.googletagmanager.com"
        ) if nonce else (
            "'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com https://js.stripe.com https://www.googletagmanager.com"
        )
    else:
        script_src = (
            "'self' 'unsafe-inline' https://cdn.socket.io https://cdn.jsdelivr.net "
            "https://cdnjs.cloudflare.com https://js.stripe.com https://www.googletagmanager.com"
        )
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"script-src {script_src}; "
        "worker-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://maxcdn.bootstrapcdn.com; "
        "img-src 'self' https: data:; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com; "
        "media-src 'self' https://res.cloudinary.com; "
        "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com wss://echowithin.xyz https://cdn.socket.io https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self' https://accounts.google.com;"
    )

    # Prevent indexing of private/auth routes without triggering GSC blocked warnings
    noindex_paths = ('/admin', '/api', '/logout', '/login', '/register', '/dashboard', '/messages', '/personal_space', '/shared/', '/search', '/profile_settings', '/reset_password', '/create_post', '/edit_post')
    if getattr(request, 'path', '').startswith(noindex_paths):
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'

    # --- Static asset caching ---
    if request.path.startswith('/static/'):
        # Immutable assets (fonts, logos, images) — cache for 1 year
        if any(request.path.endswith(ext) for ext in ('.woff', '.woff2', '.ttf', '.eot', '.png', '.ico', '.svg')):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        else:
            # CSS/JS — cache for 1 hour, revalidate after
            response.headers['Cache-Control'] = 'public, max-age=3600, must-revalidate'

    return response




@app.context_processor
def inject_pinned_announcement():
    """Makes the pinned announcement available to all templates (cached for 60s).
    
    PERF: Check in-memory cache FIRST (zero-latency, per-process) before Redis.
    This saves ~1ms per request by avoiding a Redis round-trip when the cache is warm.
    """
    cache_key = 'pinned_announcement'

    # Try in-memory cache FIRST (zero-latency)
    cached_val = _pinned_announcement_cache.get(cache_key)
    if cached_val is not None:
        # We store a sentinel '__none__' for "no announcement" to distinguish from cache miss
        return dict(pinned_announcement=None if cached_val == '__none__' else cached_val)

    # Try Redis cache second
    if redis_cache:
        try:
            cached = redis_cache.get(cache_key)
            if cached:
                if cached == b'__none__' or cached == '__none__':
                    _pinned_announcement_cache[cache_key] = '__none__'
                    return dict(pinned_announcement=None)
                parsed = json.loads(cached)
                _pinned_announcement_cache[cache_key] = parsed
                return dict(pinned_announcement=parsed)
        except Exception:
            pass

    # Fetch from DB (cache miss on both levels)
    pinned_announcement = announcements_conf.find_one({'is_pinned': True})

    # Cache the result in both layers
    if pinned_announcement:
        cache_doc = {k: str(v) if isinstance(v, ObjectId) else v for k, v in pinned_announcement.items()}
        _pinned_announcement_cache[cache_key] = cache_doc
        if redis_cache:
            try:
                redis_cache.setex(cache_key, 60, json.dumps(cache_doc, default=str))
            except Exception:
                pass
    else:
        _pinned_announcement_cache[cache_key] = '__none__'
        if redis_cache:
            try:
                redis_cache.setex(cache_key, 60, '__none__')
            except Exception:
                pass

    return dict(pinned_announcement=pinned_announcement)

## Remark42 removed: internal comments will be used instead.

@app.context_processor
def inject_template_globals():
    """Makes common variables available to all templates."""
    ctx = {
        'current_year': datetime.date.today().year,
        'now': datetime.datetime.now(datetime.timezone.utc),
        'TIER_LIMITS': TIER_LIMITS,
        'PREMIUM_PRICE_KSH': PREMIUM_PRICE_KSH,
        'csp_nonce': getattr(g, 'csp_nonce', ''),
    }
    from flask import has_request_context
    if has_request_context() and current_user and getattr(current_user, 'is_authenticated', False):
        ctx['user_is_premium'] = current_user.is_premium
        ctx['user_is_trial'] = current_user.is_trial
        ctx['user_tier'] = current_user.account_tier
        ctx['trial_days_remaining'] = current_user.trial_days_remaining
        ctx['user_max_notes'] = current_user.get_limit('max_notes')
        ctx['user_max_chars'] = current_user.get_limit('max_chars_per_note')
        ctx['user_max_shares'] = current_user.get_limit('max_share_links_per_note')
        ctx['user_max_communities'] = current_user.get_limit('max_communities')
        # Theme preference for dark mode
        # PERF: served from the cached User object (no DB round-trip per request)
        ctx['theme_preference'] = getattr(current_user, 'theme_preference', 'light')
    else:
        ctx['user_is_premium'] = False
        ctx['user_is_trial'] = False
        ctx['user_tier'] = 'free'
        ctx['trial_days_remaining'] = 0
        ctx['user_max_notes'] = TIER_LIMITS['free']['max_notes']
        ctx['user_max_chars'] = TIER_LIMITS['free']['max_chars_per_note']
        ctx['user_max_shares'] = TIER_LIMITS['free']['max_share_links_per_note']
        ctx['user_max_communities'] = TIER_LIMITS['free']['max_communities']
    return ctx


@rq.job
def reindex_typesense_job():
    """Background job to reindex all posts into Typesense."""
    try:
        total = reindex_all_posts_to_typesense()
        app.logger.info(f'Typesense posts reindex job finished ({total} docs)')
    except Exception as e:
        app.logger.error(f'Typesense reindex job failed: {e}', exc_info=True)




@rq.job
def process_post_media(post_id_str, temp_image_paths, temp_video_path):
    """
    Background job to upload media to Cloudinary, update the post,
    and trigger subsequent jobs.
    """
    app.logger.info(f"Starting media processing job for post {post_id_str}")
    image_urls = []
    image_public_ids = []
    video_url = None
    video_public_id = None

    try:
        # 1. Resize (simple) and upload Images
        for path in temp_image_paths:
            try:
                # Resize image to max width/height while preserving aspect ratio to save bandwidth/storage
                try:
                    with Image.open(path) as im:
                        # Convert PNG with transparency to RGB if necessary for JPEG optimization
                        im_format = im.format
                        max_size = (1600, 1600)
                        im.thumbnail(max_size, Image.Resampling.LANCZOS)
                        # Overwrite temp file with optimized WebP version (~30% smaller than JPEG)
                        if im.mode in ("RGBA", "LA"):
                            # Preserve transparency for formats that support it
                            im.save(path, format='WEBP', quality=80, method=6)
                        else:
                            im = im.convert('RGB')
                            im.save(path, format='WEBP', quality=80, method=6)
                except Exception as ie:
                    app.logger.debug(f"Image resize/optimize skipped for {path}: {ie}")

                upload_result = cloudinary.uploader.upload(path, folder="echowithin_posts")
                url = optimize_cloudinary_url(upload_result.get('secure_url'))
                pid = upload_result.get('public_id')
                if url: image_urls.append(url)
                if pid: image_public_ids.append(pid)
            except Exception as e:
                app.logger.error(f"Cloudinary image upload failed for {path} in job for post {post_id_str}: {e}")

        # 2. Upload Video
        if temp_video_path:
            try:
                upload_result = cloudinary.uploader.upload(
                    temp_video_path,
                    resource_type='video',
                    folder='echowithin_posts',
                    eager=[{"quality": "auto", "fetch_format": "mp4"}],
                    eager_async=True
                )
                video_url = optimize_cloudinary_url(upload_result.get('secure_url'))
                video_public_id = upload_result.get('public_id')
            except Exception as e:
                app.logger.error(f"Cloudinary video upload failed for {temp_video_path} in job for post {post_id_str}: {e}")

        # 3. Update Post in DB
        update_data = {
            'image_urls': image_urls,
            'image_public_ids': image_public_ids,
            'video_url': video_url,
            'video_public_id': video_public_id,
            'status': 'published', # Mark post as fully processed
            'image_status': 'safe' if image_urls else 'none',
            'video_status': 'uploaded' if video_url else 'none',
        }
        # For backward compatibility
        if image_urls:
            update_data['image_url'] = image_urls[0]
            update_data['image_public_id'] = image_public_ids[0]

        posts_conf.update_one({'_id': ObjectId(post_id_str)}, {'$set': update_data})
        app.logger.info(f"Successfully processed media and updated post {post_id_str}")

        # Index post into Typesense after media processing so image fields are present
        try:
            if _t.ts_posts:
                index_post_to_typesense(post_id_str)
                app.logger.info(f"Indexed post {post_id_str} to Typesense after media processing")
        except Exception as e:
            app.logger.error(f"Failed to index post {post_id_str} after media processing: {e}")

        # 4. Trigger subsequent jobs (NSFW check, notifications)
        if image_urls:
            # Check all uploaded images for NSFW content
            for url, pid in zip(image_urls, image_public_ids):
                try:
                    process_image_for_nsfw.queue(post_id_str, url, pid)
                    app.logger.info(f"Enqueued NSFW check job for post {post_id_str} on image {pid}")
                except redis.exceptions.ConnectionError as e:
                    app.logger.warning(f"Redis connection failed. Falling back to thread for NSFW check. Error: {e}")
                    with app.app_context():
                        executor.submit(process_image_for_nsfw, post_id_str, url, pid)
                except Exception as e:
                    app.logger.error(f"Failed to enqueue NSFW job for post {post_id_str} on image {pid}: {e}")

        try:
            send_new_post_notifications.queue(post_id_str)
            app.logger.info(f"Enqueued notification job for post {post_id_str}")
        except redis.exceptions.ConnectionError as e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for notifications. Error: {e}")
            with app.app_context():
                executor.submit(send_new_post_notifications, post_id_str)
        except Exception as e:
            app.logger.error(f"Failed to enqueue notification job for post {post_id_str}: {e}", exc_info=True)

    except Exception as e:
        app.logger.error(f"Error in process_post_media job for {post_id_str}: {e}", exc_info=True)
        # Mark post as failed
        posts_conf.update_one({'_id': ObjectId(post_id_str)}, {'$set': {'status': 'processing_failed'}})
    finally:
        # 5. Cleanup temporary files
        for path in temp_image_paths:
            if os.path.exists(path):
                os.remove(path)
        if temp_video_path and os.path.exists(temp_video_path):
            os.remove(temp_video_path)
        app.logger.info(f"Cleaned up temporary files for post {post_id_str}")


def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return
        return f(*args, **kwargs)
    return wrapped


def _note_share_access(share_id):
    """Return the share doc if a logged-in user may access this note room.

    The share_id doubles as the secret link, but rooms must still only be
    joinable when the share actually exists and hasn't expired/deactivated,
    otherwise any authenticated user could join rooms for guessed share_ids.
    """
    if not share_id:
        return None
    share = note_shares_conf.find_one({'share_id': share_id})
    if not share:
        return None
    if share.get('deactivated'):
        return None
    if share.get('expires_at'):
        expires_at = share['expires_at']
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expires_at:
            return None
    return share


# --- WebSocket Real-time collaboration ---
@socketio.on('join_note')
@authenticated_only
def handle_join_note(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    user_name = getattr(current_user, 'username', 'Anonymous')
    user_id = str(current_user.id)
    
    if share_id:
        # SECURITY: only allow joining the room if the share exists and hasn't
        # expired or been deactivated (share_id doubles as the secret link).
        share = _note_share_access(share_id)
        if not share:
            emit('join_note_denied', {'message': 'This shared note is no longer available.'}, room=request.sid)
            return
        join_room(share_id)
        
        # Track presence
        if share_id not in active_note_viewers:
            active_note_viewers[share_id] = {}
        
        active_note_viewers[share_id][user_id] = {
            'name': user_name,
            'avatar': getattr(current_user, 'profile_image_url', None),
            'id': user_id
        }
        
        # Broadcast updated presence list
        emit('presence_update', {'users': list(active_note_viewers[share_id].values())}, room=share_id)
        
        # Check if note is currently locked
        lock_info = note_locks.get(share_id)
        if lock_info:
            emit('lock_status', lock_info, room=request.sid)
            
        # PRIVACY: share_id IS the secret link — never log it in plaintext.
        share_fp = hashlib.sha256(str(share_id).encode('utf-8')).hexdigest()[:10]
        app.logger.info(f"User {user_name} joined note room: fp={share_fp}")

@socketio.on('leave_note')
@authenticated_only
def handle_leave_note(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    user_id = str(current_user.id)
    
    if share_id:
        leave_room(share_id)
        if share_id in active_note_viewers:
            active_note_viewers[share_id].pop(user_id, None)
            emit('presence_update', {'users': list(active_note_viewers[share_id].values())}, room=share_id)
            
        # If this user held the lock, release it
        lock_info = note_locks.get(share_id)
        if lock_info and lock_info.get('user_id') == user_id:
            note_locks.pop(share_id, None)
            emit('lock_released', {'share_id': share_id}, room=share_id)
            
        # PRIVACY: share_id IS the secret link — never log it in plaintext.
        share_fp = hashlib.sha256(str(share_id).encode('utf-8')).hexdigest()[:10]
        app.logger.info(f"User left note room: fp={share_fp}")

@socketio.on('acquire_lock')
@authenticated_only
def handle_acquire_lock(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    user_name = getattr(current_user, 'username', 'Anonymous')
    user_id = str(current_user.id)
    
    if not share_id: return

    # SECURITY: only holders with edit permission (or the owner) may acquire
    # the edit lock; view-only collaborators must not be able to lock a note.
    share = _note_share_access(share_id)
    if not share:
        emit('lock_denied', {'message': 'This shared note is no longer available.'}, room=request.sid)
        return
    if str(share.get('owner_id', '')) != user_id and share.get('permissions') != 'edit':
        emit('lock_denied', {'message': 'You have view-only access to this note.'}, room=request.sid)
        return

    now = time.time()
    existing_lock = note_locks.get(share_id)
    
    # If lock exists and hasn't expired (3 mins)
    if existing_lock and (now - existing_lock['timestamp'] < 180) and existing_lock['user_id'] != user_id:
        emit('lock_denied', {
            'message': f"Note is currently being edited by {existing_lock['user_name']}",
            'user_name': existing_lock['user_name']
        })
        return

    # Grant lock
    lock_info = {
        'user_id': user_id,
        'user_name': user_name,
        'timestamp': now,
        'share_id': share_id
    }
    note_locks[share_id] = lock_info
    emit('lock_acquired', lock_info, room=share_id)

@socketio.on('release_lock')
@authenticated_only
def handle_release_lock(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    user_id = str(current_user.id)
    
    if not share_id: return
    if _note_share_access(share_id) is None:
        return
    if share_id in note_locks and note_locks[share_id]['user_id'] == user_id:
        note_locks.pop(share_id)
        emit('lock_released', {'share_id': share_id}, room=share_id)

@socketio.on('note_update')
@authenticated_only
def handle_note_update(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    content = data.get('content')
    user_id = str(current_user.id)
    if share_id and content:
        # SECURITY: view-only users must not broadcast content edits. Only the
        # owner or edit-permission holders may push note changes to the room.
        share = _note_share_access(share_id)
        if not share:
            return
        if str(share.get('owner_id', '')) != user_id and share.get('permissions') != 'edit':
            emit('note_update_denied', {'message': 'You have view-only access to this note.'}, room=request.sid)
            return
        # Broadcast the update to others in the same room
        emit('note_changed', {'content': content}, room=share_id, include_self=False)

@socketio.on('discussion_new_comment')
@authenticated_only
def handle_discussion_new_comment(data=None, *args, **kwargs):
    if not data or not isinstance(data, dict):
        return
    share_id = data.get('share_id')
    comment_data = data.get('comment')
    if not share_id or not comment_data:
        return
    # SECURITY: verify caller can access this share before broadcasting.
    share = _note_share_access(share_id)
    if not share:
        emit('discussion_error', {'message': 'Share not found or access denied.'}, room=request.sid)
        return
    emit('discussion_updated', {'comment': comment_data}, room=share_id, include_self=False)


# --- Game Lobbies (2+ players, anytime — poll/trivia on-demand) ---
def _game_access(lobby_id):
    if not lobby_id:
        return None
    lobby = game_sessions_conf.find_one({'lobby_id': lobby_id})
    if not lobby:
        return None
    if lobby.get('deactivated'):
        return None
    if lobby.get('expires_at'):
        exp = lobby['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return None
    return lobby

@socketio.on('join_game')
@authenticated_only
def handle_join_game(data=None, *args, **kwargs):
    lobby_id = (data or {}).get('lobby_id') if isinstance(data, dict) else None
    lobby = _game_access(lobby_id)
    if not lobby:
        emit('game_error', {'message': 'Lobby not found or expired.'}, room=request.sid)
        return
    # 2+ players guard: max 30
    players = active_game_players.get(lobby_id, {})
    if len(players) >= 30 and str(current_user.id) not in players:
        emit('game_error', {'message': 'Lobby full (30 max).'}, room=request.sid)
        return
    join_room(lobby_id)
    # track presence like active_note_viewers
    user_id = str(current_user.id)
    players[user_id] = {'name': current_user.username, 'avatar': getattr(current_user, 'profile_image_url', None), 'id': user_id}
    active_game_players[lobby_id] = players
    emit('game_presence_update', {'players': list(players.values()), 'count': len(players)}, room=lobby_id)

@socketio.on('leave_game')
@authenticated_only
def handle_leave_game(data=None, *args, **kwargs):
    lobby_id = (data or {}).get('lobby_id') if isinstance(data, dict) else None
    if not lobby_id:
        return
    user_id = str(current_user.id)
    leaving = request.sid
    # leave room
    try:
        leave_room(lobby_id)
    except: pass
    players = active_game_players.get(lobby_id, {})
    if user_id in players:
        players.pop(user_id, None)
        if players:
            active_game_players[lobby_id] = players
            emit('game_presence_update', {'players': list(players.values()), 'count': len(players)}, room=lobby_id)
        else:
            active_game_players.pop(lobby_id, None)


# --- Direct Messaging (DM) Functionality ---

@socketio.on('join_inbox')
@authenticated_only
def handle_join_inbox(data=None, *args, **kwargs):
    """Each user joins their own private room for real-time DM delivery."""
    user_room = f"user_{current_user.id}"
    join_room(user_room)
    # PRIVACY: user_room embeds the user's ObjectId. Keep this at DEBUG to avoid
    # leaking PII (username + internal id mapping) in production logs.
    app.logger.debug(f"User {current_user.username} joined private inbox room")







@socketio.on('viewing_chat')
@authenticated_only
def handle_viewing_chat(data=None, *args, **kwargs):
    """Track that the user is actively viewing a specific chat for notification suppression."""
    if not data or not isinstance(data, dict):
        return
    partner_id = data.get('partner_id')
    if partner_id:
        user_id = str(current_user.id)
        if user_id not in active_chat_views:
            active_chat_views[user_id] = set()
        active_chat_views[user_id].add(partner_id)

@socketio.on('leave_chat')
@authenticated_only
def handle_leave_chat(data=None, *args, **kwargs):
    """User left a specific chat view."""
    if not data or not isinstance(data, dict):
        return
    partner_id = data.get('partner_id')
    if partner_id:
        user_id = str(current_user.id)
        if user_id in active_chat_views:
            active_chat_views[user_id].discard(partner_id)

@socketio.on('disconnect')
def handle_dm_disconnect(*args, **kwargs):
    """Clean up active chat and note presence on disconnect."""
    user_id = str(current_user.id) if current_user.is_authenticated else request.sid
    
    if current_user.is_authenticated:
        active_chat_views.pop(user_id, None)
    
    # Cleanup note presence
    for share_id, viewers in list(active_note_viewers.items()):
        if user_id in viewers:
            viewers.pop(user_id, None)
            emit('presence_update', {'users': list(viewers.values())}, room=share_id)
            
            # Release lock if they held it
            if share_id in note_locks and note_locks[share_id]['user_id'] == user_id:
                note_locks.pop(share_id)
                emit('lock_released', {'share_id': share_id}, room=share_id)

    # Cleanup game lobby presence (2+ players, anytime)
    for lobby_id, players in list(active_game_players.items()):
        if user_id in players:
            players.pop(user_id, None)
            if players:
                active_game_players[lobby_id] = players
                emit('game_presence_update', {'players': list(players.values()), 'count': len(players)}, room=lobby_id)
            else:
                active_game_players.pop(lobby_id, None)


@socketio.on('send_dm')
@authenticated_only
def handle_send_dm(data=None, *args, **kwargs):
    """
    Handles sending a direct message via Socket.IO.
    Data expected: { 'recipient_id': '...', 'content': '...', 'reply_to_id': '...', 'image_url': '...', 'message_type': 'text|image' }
    """
    if not data or not isinstance(data, dict):
        return
    recipient_id_str = data.get('recipient_id')
    content = data.get('content', '')
    reply_to_id = data.get('reply_to_id')
    image_url = data.get('image_url')
    image_public_id = data.get('image_public_id')
    image_resource_type = data.get('image_resource_type', 'image')
    mime_type = data.get('mime_type')
    media_encrypted = is_media_proxy_url(image_url)
    message_type = data.get('message_type', 'text')
    
    if not recipient_id_str or (not content and not image_url):
        return
    
    try:
        recipient_id = ObjectId(recipient_id_str)
        sender_id_str = str(current_user.id)

        # Check DM permission
        if not can_dm(sender_id_str, recipient_id_str):
            emit('dm_error', {
                'error': 'You need to send a message request first. This user has not accepted your request yet.'
            }, room=f"user_{sender_id_str}")
            return

        # Check if recipient has DMs disabled
        recipient = users_conf.find_one({'_id': recipient_id})
        if not recipient:
            return
        if recipient.get('dm_privacy') == 'nobody':
            emit('dm_error', {
                'error': 'This user has disabled direct messages.'
            }, room=f"user_{sender_id_str}")
            return

        # Handle Reply Previews
        reply_to_preview = None
        reply_to_sender = None
        if reply_to_id:
            try:
                parent_msg = direct_messages_conf.find_one({'_id': ObjectId(reply_to_id)})
                if parent_msg:
                    parent_sender_id = str(parent_msg['sender_id'])
                    is_me = parent_sender_id == sender_id_str
                    parent_sender = current_user.username if is_me else recipient.get('username', 'User')
                    
                    raw_content = parent_msg.get('content', '')
                    if parent_msg.get('encrypted') or raw_content.startswith('gAAAAA'):
                        try:
                            # Decrypt it to cache the preview
                            user1 = str(parent_msg['sender_id'])
                            user2 = str(parent_msg['recipient_id'])
                            raw_content = decrypt_dm(raw_content, user1, user2)
                        except Exception:
                            raw_content = "Encrypted message"
                            
                    reply_to_sender = parent_sender
                    
                    if parent_msg.get('message_type') == 'image':
                        reply_to_preview = "📸 Photo"
                    else:
                        reply_to_preview = raw_content[:80] + ('...' if len(raw_content) > 80 else '')
            except Exception as e:
                app.logger.warning(f"Error fetching reply parent message: {e}")

        # Handle Link Previews
        link_preview = None
        if message_type == 'text' and content:
            url_match = re.search(r'(https?://[^\s]+)', content)
            if url_match:
                link_preview = fetch_link_preview(url_match.group(1))

        # Encrypt DM content before saving
        encrypted_content = encrypt_dm(content, sender_id_str, recipient_id_str) if content else ''

        recipient_viewing = active_chat_views.get(recipient_id_str, set())
        is_actively_reading = sender_id_str in recipient_viewing

        message_doc = {
            'sender_id': ObjectId(current_user.id),
            'recipient_id': recipient_id,
            'content': encrypted_content,
            'encrypted': True,
            'timestamp': datetime.datetime.now(datetime.timezone.utc),
            'is_read': is_actively_reading,
            'message_type': message_type
        }
        
        if image_url: message_doc['image_url'] = encrypt_dm(image_url, sender_id_str, recipient_id_str)
        if media_encrypted:
            message_doc['media_encrypted'] = True
            message_doc['mime_type'] = mime_type or ('audio/webm' if message_type == 'audio' else 'image/jpeg')
        if image_public_id:
            message_doc['image_public_id'] = encrypt_dm(str(image_public_id), sender_id_str, recipient_id_str)
            message_doc['image_resource_type'] = 'video' if message_type == 'audio' else 'image'
        if reply_to_id:
            message_doc['reply_to_id'] = ObjectId(reply_to_id)
            message_doc['reply_to_preview'] = encrypt_dm(reply_to_preview, sender_id_str, recipient_id_str) if reply_to_preview else reply_to_preview
            message_doc['reply_to_sender'] = reply_to_sender
        if link_preview:
            message_doc['link_preview'] = {
                'url': encrypt_dm(link_preview.get('url', ''), sender_id_str, recipient_id_str),
                'title': encrypt_dm(link_preview.get('title', ''), sender_id_str, recipient_id_str),
                'description': encrypt_dm(link_preview.get('description', ''), sender_id_str, recipient_id_str),
                'image': encrypt_dm(link_preview.get('image', ''), sender_id_str, recipient_id_str)
            }
        
        # Save to DB
        direct_messages_conf.insert_one(message_doc)
        
        # Un-hide conversation for the recipient if they had deleted it
        hidden_chats_conf.delete_one({'user_id': recipient_id, 'partner_id': ObjectId(current_user.id)})
        
        # Broadcast payload
        payload = {
            'id': str(message_doc['_id']),
            'sender_id': sender_id_str,
            'recipient_id': recipient_id_str,
            'sender_username': current_user.username,
            'content': content,
            'timestamp': message_doc['timestamp'].isoformat(),
            'is_read': is_actively_reading,
            'message_type': message_type
        }
        if image_url:
            if is_media_proxy_url(image_url):
                payload['image_url'] = image_url
                payload['media_encrypted'] = True
            else:
                fresh_image_url = re_sign_cloudinary_url(
                    image_public_id,
                    resource_type='video' if message_type == 'audio' else 'image',
                    delivery_type='authenticated',
                    fallback_url=image_url
                )
                payload['image_url'] = fresh_image_url
            payload['image_public_id'] = image_public_id or ''
        if reply_to_id:
            payload['reply_to_id'] = str(reply_to_id)
            payload['reply_to_preview'] = reply_to_preview
            payload['reply_to_sender'] = reply_to_sender
        if link_preview: payload['link_preview'] = link_preview

        # Broadcast to recipient's private room
        recipient_room = f"user_{recipient_id_str}"
        emit('new_dm', payload, room=recipient_room)

        # Confirm to sender with ID
        payload['temp_id'] = data.get('temp_id')
        emit('message_confirmed', payload, room=f"user_{sender_id_str}")
        
        if is_actively_reading:
            # Alert sender that the message was read instantly
            emit('messages_read', 
                 {'reader_id': recipient_id_str, 'sender_id': sender_id_str}, 
                 room=f"user_{sender_id_str}")
        else:
            # Send push notification only if recipient is NOT actively viewing this chat
            push_body = "📸 Photo" if message_type == 'image' else content[:100] + ('...' if len(content) > 100 else '')
            send_push_notification_to_user(
                recipient_id_str,
                f"New message from {current_user.username}",
                push_body,
                url=url_for('chat.messages_page', _external=True),
                tag=f'dm-{current_user.id}'
            )
        
        # Invalidate the recipient's badge cache so the next poll picks up the new DM
        _invalidate_badge_cache(recipient_id_str)

        # Interactive Demo Bot: auto-reply for Maya_DemoPartner
        recipient_user = users_conf.find_one({'_id': recipient_id})
        if recipient_user and (recipient_user.get('is_demo_bot') or recipient_user.get('username', '').startswith('Maya_DemoPartner')):
            def _bot_reply_task(sub_sender_id_str, sub_recipient_id_str, sub_recipient_id, sub_recipient_username):
                socketio.emit('user_typing', {'sender_id': sub_recipient_id_str}, room=f"user_{sub_sender_id_str}")
                time.sleep(1.2)
                socketio.emit('user_stop_typing', {'sender_id': sub_recipient_id_str}, room=f"user_{sub_sender_id_str}")
                with app.app_context():
                    bot_replies = [
                        "Thanks for reaching out! I'm your interactive demo partner. Try checking out our shared Bond space, logging today's mood, or answering today's daily question!",
                        "Hey! I'm right here exploring EchoWithin with you. Have you tried checking out the shared habit tracker or setting up app lock?",
                        "So glad we are testing this together! You can also check out our shared countdowns and journal memory lane under Bonds.",
                        "I love testing out EchoWithin's features with you! Everything in this demo session is private and isolated to your tour.",
                        "You can try sending self-destructing messages in Whisper mode, or creating a shared note!"
                    ]
                    reply_text = random.choice(bot_replies)
                    bot_now = datetime.datetime.now(datetime.timezone.utc)
                    enc_content = encrypt_dm(reply_text, sub_recipient_id_str, sub_sender_id_str)
                    bot_msg_doc = {
                        'sender_id': sub_recipient_id,
                        'recipient_id': ObjectId(sub_sender_id_str),
                        'content': enc_content,
                        'encrypted': True,
                        'timestamp': bot_now,
                        'is_read': False,
                        'message_type': 'text'
                    }
                    direct_messages_conf.insert_one(bot_msg_doc)
                    bot_payload = {
                        'id': str(bot_msg_doc['_id']),
                        'sender_id': sub_recipient_id_str,
                        'recipient_id': sub_sender_id_str,
                        'sender_username': 'Maya (Demo Partner)',
                        'content': reply_text,
                        'timestamp': (bot_now.isoformat() + 'Z').replace('+00:00Z', 'Z'),
                        'is_read': False,
                        'message_type': 'text'
                    }
                    socketio.emit('new_dm', bot_payload, room=f"user_{sub_sender_id_str}")

            socketio.start_background_task(_bot_reply_task, sender_id_str, recipient_id_str, recipient_id, recipient_user.get('username', 'Maya_DemoPartner'))
        
    except Exception as e:
        app.logger.error(f"Error sending DM via socket: {e}")

@socketio.on('typing')
@authenticated_only
def handle_typing(data=None, *args, **kwargs):
    """Broadcasts that the current user is typing to the recipient."""
    if not data or not isinstance(data, dict):
        return
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_id_str = str(recipient_id)
        recipient_room = f"user_{recipient_id_str}"
        emit('user_typing', {
            'sender_id': str(current_user.id),
            'username': current_user.username
        }, room=recipient_room)

@socketio.on('stop_typing')
@authenticated_only
def handle_stop_typing(data=None, *args, **kwargs):
    """Broadcasts that the user has stopped typing."""
    if not data or not isinstance(data, dict):
        return
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_id_str = str(recipient_id)
        recipient_room = f"user_{recipient_id_str}"
        emit('user_stop_typing', {
            'sender_id': str(current_user.id)
        }, room=recipient_room)

@socketio.on('recording_audio')
@authenticated_only
def handle_recording_audio(data=None, *args, **kwargs):
    """Broadcasts that the current user is recording a voice note."""
    if not data or not isinstance(data, dict):
        return
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_room = f"user_{str(recipient_id)}"
        emit('recording_audio', {
            'sender_id': str(current_user.id),
            'username': current_user.username
        }, room=recipient_room)

@socketio.on('stop_recording')
@authenticated_only
def handle_stop_recording(data=None, *args, **kwargs):
    """Broadcasts that the user stopped recording."""
    if not data or not isinstance(data, dict):
        return
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_room = f"user_{str(recipient_id)}"
        emit('stop_recording', {
            'sender_id': str(current_user.id)
        }, room=recipient_room)


# --- Whisper Mode SocketIO Events ---

@socketio.on('whisper_message')
@authenticated_only
def handle_whisper_message(data=None, *args, **kwargs):
    """Handle sending a message within an active whisper session.
    
    Supports text and image messages. Image URLs are encrypted at rest
    just like text content, and auto-delete with the session TTL.
    """
    if not data or not isinstance(data, dict):
        return
    session_id = data.get('session_id')
    content = data.get('content', '').strip()
    message_type = data.get('message_type', 'text')  # 'text' or 'image'
    image_url = data.get('image_url', '').strip()
    image_public_id = (data.get('image_public_id') or '').strip()
    mime_type = (data.get('mime_type') or '')[:200]
    reply_to_id = (data.get('reply_to') or '').strip()

    # Require content for text messages, image_url for image messages
    if not session_id:
        return
    if message_type == 'image' and not image_url:
        return
    if message_type == 'text' and not content:
        return
    if len(content) > 5000:
        emit('whisper_error', {'error': 'Message too long (max 5000 characters)'}, room=f"user_{current_user.id}")
        return

    try:
        session_doc = whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            emit('whisper_error', {'error': 'Session not active'}, room=f"user_{current_user.id}")
            return

        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])

        if user_id_str not in (initiator_str, recipient_str):
            return

        # Check if session has expired
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = session_doc.get('expires_at')
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
            if now >= expires_at:
                # Session expired — clean up
                whisper_messages_conf.delete_many({'session_id': ObjectId(session_id)})
                whisper_sessions_conf.update_one(
                    {'_id': ObjectId(session_id)},
                    {'$set': {'status': 'expired'}}
                )
                emit('whisper_expired', {'session_id': session_id, 'reason': 'timeout'},
                     room=f"user_{initiator_str}")
                emit('whisper_expired', {'session_id': session_id, 'reason': 'timeout'},
                     room=f"user_{recipient_str}")
                # Insert single DM system message (from initiator to recipient)
                now_str = now.isoformat().replace('+00:00', 'Z')
                end_content = 'Whisper session ended (timeout)'
                d = {'sender_id': ObjectId(initiator_str), 'recipient_id': ObjectId(recipient_str), 'content': end_content, 'encrypted': False, 'timestamp': now, 'is_read': False, 'message_type': 'whisper_system'}
                r = direct_messages_conf.insert_one(d)
                dm_payload = {'id': str(r.inserted_id), 'sender_id': initiator_str, 'content': end_content, 'timestamp': now_str, 'message_type': 'whisper_system'}
                emit('new_dm', dm_payload, room=f"user_{initiator_str}")
                emit('new_dm', dm_payload, room=f"user_{recipient_str}")
                return

        partner_id = recipient_str if user_id_str == initiator_str else initiator_str

        # Store message encrypted at rest with TTL
        msg_expires = expires_at + datetime.timedelta(minutes=5) if expires_at else now + datetime.timedelta(hours=1)

        # Encrypt content (text or image URL)
        if message_type == 'image':
            encrypted_image_url = encrypt_dm(image_url, user_id_str, partner_id)
            encrypted_content = encrypt_dm(content or '[Photo]', user_id_str, partner_id)
        else:
            encrypted_image_url = None
            encrypted_content = encrypt_dm(content, user_id_str, partner_id)

        # DM parity (F4): initialize read state explicitly instead of relying
        # on `$ne: True` matching a missing field.
        partner_viewing = active_chat_views.get(partner_id, set())
        is_actively_viewing = user_id_str in partner_viewing

        msg_doc = {
            'session_id': ObjectId(session_id),
            'sender_id': ObjectId(current_user.id),
            'content': encrypted_content,
            'timestamp': now,
            'expires_at': msg_expires,
            'is_system': False,
            'is_read': is_actively_viewing,
            'message_type': message_type
        }
        if encrypted_image_url:
            msg_doc['image_url'] = encrypted_image_url
        if image_public_id:
            msg_doc['image_public_id'] = encrypt_dm(image_public_id, user_id_str, partner_id)
        if is_media_proxy_url(image_url):
            msg_doc['media_encrypted'] = True
            msg_doc['mime_type'] = mime_type or 'image/jpeg'
        elif mime_type:
            msg_doc['mime_type'] = mime_type
        # Reply-to threading
        if reply_to_id:
            try:
                reply_msg = whisper_messages_conf.find_one({
                    '_id': ObjectId(reply_to_id),
                    'session_id': ObjectId(session_id)
                })
                if reply_msg:
                    msg_doc['reply_to'] = ObjectId(reply_to_id)
                    # Store a preview of the replied-to message for rendering
                    reply_content = reply_msg.get('content', '')
                    if reply_content and reply_content.startswith('gAAAAA'):
                        try:
                            reply_content = decrypt_dm(reply_content, user_id_str, partner_id)
                        except Exception:
                            reply_content = '[Message]'
                    msg_doc['reply_preview'] = (reply_content or '[Photo]')[:80]
                    reply_sender_id = str(reply_msg.get('sender_id', ''))
                    msg_doc['reply_sender_id'] = reply_sender_id
            except Exception:
                pass  # Invalid reply_to ID, skip silently
        whisper_messages_conf.insert_one(msg_doc)

        payload = {
            'id': str(msg_doc['_id']),
            'session_id': session_id,
            'sender_id': user_id_str,
            'content': content or '[Photo]',
            'timestamp': now.isoformat().replace('+00:00', 'Z'),
            'temp_id': data.get('temp_id'),
            'message_type': message_type,
            'is_read': is_actively_viewing
        }
        if message_type == 'image':
            payload['image_url'] = image_url
        # Include reply context in payload
        if msg_doc.get('reply_to'):
            payload['reply_to'] = str(msg_doc['reply_to'])
            payload['reply_preview'] = msg_doc.get('reply_preview', '')
            payload['reply_sender_id'] = msg_doc.get('reply_sender_id', '')

        emit('whisper_new_message', payload, room=f"user_{partner_id}")
        # Confirmation for sender (same payload — client resolves reply labels from reply_sender_id)
        confirm_payload = dict(payload)
        emit('whisper_message_confirmed', confirm_payload, room=f"user_{user_id_str}")

        if is_actively_viewing:
            emit('whisper_read_receipt', {
                'session_id': session_id,
                'reader_id': partner_id
            }, room=f"user_{user_id_str}")
        else:
            # DM parity (F4): redacted push only — never the ephemeral content
            # (push bodies are minimized repo-wide; see DISCOVERY §3.9).
            try:
                send_push_notification_to_user(
                    partner_id,
                    f"New whisper from {current_user.username}",
                    "A self-destructing message is waiting — open Whisper to view it",
                    url=url_for('chat.messages_page', _external=True),
                    tag=f'whisper-msg-{session_id}'
                )
            except Exception as push_err:
                app.logger.warning(f"Whisper push failed: {push_err}")

    except Exception as e:
        app.logger.error(f"Whisper message error: {e}")


@socketio.on('whisper_typing')
@authenticated_only
def handle_whisper_typing(data=None, *args, **kwargs):
    """Broadcast whisper typing indicator."""
    if not data or not isinstance(data, dict):
        return
    partner_id = data.get('partner_id')
    if partner_id:
        emit('whisper_user_typing', {
            'sender_id': str(current_user.id),
            'username': current_user.username
        }, room=f"user_{partner_id}")


@socketio.on('whisper_stop_typing')
@authenticated_only
def handle_whisper_stop_typing(data=None, *args, **kwargs):
    """Broadcast whisper stop typing."""
    if not data or not isinstance(data, dict):
        return
    partner_id = data.get('partner_id')
    if partner_id:
        emit('whisper_user_stop_typing', {
            'sender_id': str(current_user.id)
        }, room=f"user_{partner_id}")


@socketio.on('whisper_read')
@authenticated_only
def handle_whisper_read(data=None, *args, **kwargs):
    """Mark whisper messages as read and notify the sender."""
    if not data or not isinstance(data, dict):
        return
    session_id = data.get('session_id')
    if not session_id:
        return
    try:
        session_doc = whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            return
        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])
        if user_id_str not in (initiator_str, recipient_str):
            return
        partner_id = recipient_str if user_id_str == initiator_str else initiator_str
        # Mark unread messages from partner as read
        whisper_messages_conf.update_many(
            {
                'session_id': ObjectId(session_id),
                'sender_id': ObjectId(partner_id),
                'is_read': {'$ne': True}
            },
            {'$set': {'is_read': True}}
        )
        emit('whisper_read_receipt', {
            'session_id': session_id,
            'reader_id': user_id_str
        }, room=f"user_{partner_id}")
    except Exception as e:
        app.logger.error(f"Whisper read error: {e}")


@socketio.on('whisper_screenshot_alert')
@authenticated_only
def handle_whisper_screenshot(data=None, *args, **kwargs):
    """Alert both parties of potential screenshot activity."""
    if not data or not isinstance(data, dict):
        return
    session_id = data.get('session_id')
    if not session_id:
        return
    try:
        session_doc = whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            return

        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])

        if user_id_str not in (initiator_str, recipient_str):
            return

        partner_id = recipient_str if user_id_str == initiator_str else initiator_str
        now = datetime.datetime.now(datetime.timezone.utc)

        # 10s debounce per session to prevent alert spam
        last_alert = session_doc.get('last_screenshot_alert_at')
        if last_alert:
            if last_alert.tzinfo is None:
                last_alert = last_alert.replace(tzinfo=datetime.timezone.utc)
            if (now - last_alert).total_seconds() < 10:
                return

        whisper_sessions_conf.update_one(
            {'_id': session_doc['_id']},
            {'$set': {'last_screenshot_alert_at': now}}
        )

        trigger = data.get('trigger', 'unknown')
        trigger_labels = {
            'printscreen': 'captured the screen (desktop PrintScreen)',
            'keyboard_shortcut': 'used a screenshot keyboard shortcut',
            'visibility_change': 'switched away from the app',
            'window_blur': 'switched to another window'
        }
        label = trigger_labels.get(trigger, 'may have captured the screen')
        content = f'{current_user.username} {label}'

        # Store as system message
        expires_at = session_doc.get('expires_at')
        msg_expires = expires_at + datetime.timedelta(minutes=5) if expires_at else now + datetime.timedelta(hours=1)
        msg_oid = ObjectId()
        msg_doc = {
            '_id': msg_oid,
            'session_id': ObjectId(session_id),
            'sender_id': ObjectId(current_user.id),
            'content': content,
            'timestamp': now,
            'expires_at': msg_expires,
            'is_system': True
        }
        whisper_messages_conf.insert_one(msg_doc)

        alert_payload = {
            'session_id': session_id,
            'username': current_user.username,
            'content': content,
            'timestamp': now.isoformat().replace('+00:00', 'Z'),
            'id': str(msg_oid)
        }
        emit('whisper_screenshot_detected', alert_payload, room=f"user_{partner_id}")
        emit('whisper_screenshot_detected', alert_payload, room=f"user_{user_id_str}")

    except Exception as e:
        app.logger.error(f"Whisper screenshot alert error: {e}")


@socketio.on('whisper_react')
@authenticated_only
def handle_whisper_react(data=None, *args, **kwargs):
    """Handle emoji reaction on a whisper message."""
    if not data or not isinstance(data, dict):
        return
    session_id = data.get('session_id')
    message_id = data.get('message_id')
    emoji = data.get('emoji', '')
    if not session_id or not message_id or not emoji:
        return
    try:
        session_doc = whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            return
        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])
        if user_id_str not in (initiator_str, recipient_str):
            return
        partner_id = recipient_str if user_id_str == initiator_str else initiator_str
        # Store reaction on the message (ephemeral, deleted with session)
        whisper_messages_conf.update_one(
            {'_id': ObjectId(message_id), 'session_id': ObjectId(session_id)},
            {'$set': {f'reactions.{user_id_str}': emoji}}
        )
        # DM parity (F5): fan out to BOTH rooms so the reactor's own echo
        # reconciles too (previously only the partner was notified).
        reaction_payload = {
            'session_id': session_id,
            'message_id': message_id,
            'emoji': emoji,
            'reactor_id': user_id_str
        }
        emit('whisper_reaction', reaction_payload, room=f"user_{partner_id}")
        emit('whisper_reaction', reaction_payload, room=f"user_{user_id_str}")
    except Exception as e:
        app.logger.error(f"Whisper react error: {e}")


# Minimum gap between edits of the same message (anti-spam / covert-channel).
WHISPER_EDIT_MIN_INTERVAL_SECONDS = 5
WHISPER_MAX_CONTENT_LENGTH = 5000


def _whisper_image_serve_url(msg_doc, user_id_str, partner_id):
    """Resolve a whisper image message to a fresh, viewable URL (DM parity, F5).

    Mirrors the DM history logic in `blueprints/chat.py:api_message_history`:
    media-proxy bytes are re-served via capability URL, legacy Cloudinary
    `authenticated` assets are re-signed, otherwise the stored URL is used.
    Returns '' when the bytes were destroyed (view-once) or undecryptable.
    """
    try:
        raw_img = msg_doc.get('image_url', '')
        plain_url = decrypt_dm(raw_img, user_id_str, partner_id) if raw_img and raw_img.startswith('gAAAAA') else raw_img
        raw_pub = msg_doc.get('image_public_id', '')
        plain_pub = decrypt_dm(raw_pub, user_id_str, partner_id) if raw_pub and raw_pub.startswith('gAAAAA') else raw_pub
        if msg_doc.get('media_encrypted') and plain_pub:
            return build_media_serve_url(plain_pub, msg_doc.get('mime_type', 'application/octet-stream')) or plain_url
        if plain_pub:
            return re_sign_cloudinary_url(plain_pub, resource_type='image', delivery_type='authenticated', fallback_url=plain_url) or plain_url
        return plain_url or ''
    except Exception as e:
        app.logger.warning(f"Whisper image serve-URL error: {e}")
        return ''


@socketio.on('whisper_edit')
@authenticated_only
def handle_whisper_edit(data=None, *args, **kwargs):
    """Edit own whisper text message in place (F6, semantics in W.5).

    Overwrites the ciphertext, sets `edited`, keeps NO history, and does NOT
    touch `expires_at` — the self-destruct window is fixed at session scope so
    rapid-fire edits cannot smuggle content past it.
    """
    if not data or not isinstance(data, dict):
        return
    session_id = data.get('session_id')
    message_id = data.get('message_id')
    new_content = (data.get('content') or '').strip()
    if not session_id or not message_id or not new_content:
        return
    if len(new_content) > WHISPER_MAX_CONTENT_LENGTH:
        emit('whisper_error', {'error': 'Message too long (max 5000 characters)'}, room=f"user_{current_user.id}")
        return
    try:
        session_doc = whisper_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'status': 'active'
        })
        if not session_doc:
            emit('whisper_error', {'error': 'Session not active'}, room=f"user_{current_user.id}")
            return
        user_id_str = str(current_user.id)
        initiator_str = str(session_doc['initiator_id'])
        recipient_str = str(session_doc['recipient_id'])
        if user_id_str not in (initiator_str, recipient_str):
            return
        try:
            msg_oid = ObjectId(message_id)
        except Exception:
            return
        msg = whisper_messages_conf.find_one({
            '_id': msg_oid,
            'session_id': ObjectId(session_id)
        })
        if not msg or msg.get('is_system'):
            return
        if str(msg.get('sender_id')) != user_id_str:
            emit('whisper_error', {'error': 'You can only edit your own messages'}, room=f"user_{user_id_str}")
            return
        if msg.get('message_type') != 'text':
            emit('whisper_error', {'error': 'Only text messages can be edited'}, room=f"user_{user_id_str}")
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        last_edit = msg.get('edited_at')
        if last_edit:
            if last_edit.tzinfo is None:
                last_edit = last_edit.replace(tzinfo=datetime.timezone.utc)
            if (now - last_edit).total_seconds() < WHISPER_EDIT_MIN_INTERVAL_SECONDS:
                emit('whisper_error', {'error': 'Editing too fast — wait a moment'}, room=f"user_{user_id_str}")
                return
        partner_id = recipient_str if user_id_str == initiator_str else initiator_str
        encrypted = encrypt_dm(new_content, user_id_str, partner_id)
        whisper_messages_conf.update_one(
            {'_id': msg_oid},
            {'$set': {'content': encrypted, 'edited': True, 'edited_at': now}}
        )
        payload = {
            'session_id': session_id,
            'message_id': str(msg_oid),
            'content': new_content,
            'edited': True
        }
        emit('whisper_message_edited', payload, room=f"user_{partner_id}")
        emit('whisper_message_edited', payload, room=f"user_{user_id_str}")
    except Exception as e:
        app.logger.error(f"Whisper edit error: {e}")




# Handles any possible errors

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(RateLimitException)
def handle_ratelimit_exception(e):
    """Custom handler for rate limit exceeded exceptions."""
    period_remaining = math.ceil(e.period_remaining)
    # Monitoring hook: distinct event from normal failed logins (PLAN §5)
    try:
        # Use X-Forwarded-For aware IP for correct attribution behind ProxyFix
        fwd = request.headers.get('X-Forwarded-For', '')
        ip = fwd.split(',')[0].strip() if fwd and ',' in fwd else (fwd.strip() if fwd else request.remote_addr)
        app.logger.warning(
            f"rate_limit_exceeded endpoint={request.endpoint} ip={ip} remaining={period_remaining}",
            extra={'event': 'rate_limit_exceeded', 'endpoint': str(request.endpoint), 'ip': str(ip), 'period_remaining': period_remaining}
        )
    except Exception:
        app.logger.warning(f"Rate limit exceeded for IP {request.remote_addr}. Blocked for {period_remaining} seconds.")
    return render_template('429.html', period_remaining=period_remaining), 429

@app.errorhandler(OSError)
def handle_client_disconnect(e):
    """Gracefully handle client disconnects mid-request (truncated uploads).

    When gevent reports 'unexpected end of file while reading request',
    the client dropped the connection (network glitch, user navigated away,
    mobile browser suspended). This is NOT a server bug and should not
    trigger 500 ntfy alerts.
    """
    if 'unexpected end of file' in str(e).lower():
        app.logger.info(f"Client disconnected mid-request on {request.path}: {e}")
        is_api = (request.is_json
                  or request.headers.get('X-App-Token')
                  or request.path.startswith('/api/'))
        if is_api:
            return jsonify({'error': 'Upload interrupted. Please try again.'}), 499
        return render_template("500.html"), 499
    # For any other OSError, fall through to the normal 500 handler
    raise e

@app.errorhandler(500)
def internal_server_error(e):
    """Handler for 500 errors, sends an ntfy notification."""
    try:
        # Log the original error first
        app.logger.error(f"Internal Server Error on {request.path}: {e}", exc_info=True)
        # Redact sensitive path components (share IDs, media public_ids, tokens)
        # before the path leaves the platform via ntfy.
        _redacted_path = re.sub(
            r'(/(?:share/note|uploads?|uploads_enc|personal_post)/)[^/\s]+',
            r'\1<redacted>',
            request.path
        )
        _redacted_path = re.sub(r'(/api/)[^/]+', r'\1<id>', _redacted_path)
        _redacted_message = f"A 500 error occurred on endpoint {_redacted_path}. Check logs for details."
        try:
            send_ntfy_notification.queue(_redacted_message, "Application Error (500)", "warning")
        except redis.exceptions.ConnectionError as ntfy_e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for 500 error ntfy notification. Error: {ntfy_e}")
            with app.app_context():
                executor.submit(send_ntfy_notification, _redacted_message, "Application Error (500)", "warning")
        except Exception as ntfy_e:
            app.logger.error(f"Failed to enqueue ntfy notification for 500 error: {ntfy_e}")
    except Exception as log_e:
        print(f"CRITICAL: Failed to log 500 error: {log_e}", file=sys.stderr)
    return render_template("500.html"), 500