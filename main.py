
from gevent import monkey
monkey.patch_all()

import datetime
import re

from flask import Flask, g, request, jsonify, render_template, url_for, redirect, session, flash, make_response, send_from_directory, send_file, abort
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
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.son import SON
from ratelimit import limits as _limits_base, RateLimitException
from security import (is_safe_url, is_same_origin_request, parse_iso_utc,
    build_unified_diff_text, build_merge_preview_text, get_active_achievements,
    limits, safe_object_id, admin_required, owner_required,
    _derive_fernet_key, _get_notes_encryption_key, get_notes_fernet,
    _get_user_fernet, _get_dm_fernet, encrypt_dm, decrypt_dm,
    encrypt_note, decrypt_note, _candidate_user_ids,
    _decrypt_with_candidate_ids, _note_decryption_candidates,
    _decrypt_note_record, _get_community_fernet,
    encrypt_community_note, decrypt_community_note)
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
    calculate_hot_score, _serialize_comment, _get_user_badge_count,
    _invalidate_badge_cache, _has_active_auto_approve,
    can_dm, fetch_link_preview, _deliver_scheduled_message,
    _nlp_suggest_tags, get_zen_quote)
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
from api import api_bp

from notifications import (send_code, send_reset_code, send_new_post_notifications,
    send_weekly_newsletter, send_push_notification_to_user,
    send_admin_broadcast_push, send_push_notifications_for_new_post,
    send_fcm_notification_to_user, send_fcm_notifications_batch,
    send_push_notification_for_comment, process_image_for_nsfw,
    send_log_email_job, send_ntfy_notification, check_image_for_nsfw)
import secrets
from jigsawstack import JigsawStack
from cachetools import cached, TTLCache
import time
import requests
from werkzeug.utils import secure_filename
import hashlib
import hmac
from slugify import slugify
import cloudinary
import cloudinary.uploader
import json
from logging.handlers import RotatingFileHandler
import markdown
import re
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
app.register_blueprint(api_bp)

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
        if lock_age > 300:
            try:
                socketio.emit('lock_released', {'share_id': share_id}, room=share_id)
            except Exception:
                pass
            note_locks.pop(share_id, None)
# Restrict CORS to the canonical domain (prevents Cross-Site WebSocket Hijacking)
_ALLOWED_ORIGINS = os.environ.get('SOCKETIO_ALLOWED_ORIGINS', 'https://echowithin.xyz,https://blog.echowithin.xyz').split(',')
socketio = SocketIO(app, cors_allowed_origins=_ALLOWED_ORIGINS, async_mode='gevent')

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
login_manager.login_view = 'login'  # snyk:disable=security-issue

# Return JSON 401 for API/mobile requests instead of redirecting to the login page
@login_manager.unauthorized_handler
def unauthorized_api():
    """Return JSON 401 for API/native-app requests, redirect for web browser requests."""
    is_api = (request.is_json
            or request.headers.get('X-App-Token')
            or request.path.startswith('/api/'))
    
    print(f"[DEBUG UNAUTHORIZED] Path: {request.path}, is_json: {request.is_json}, X-App-Token header present: {request.headers.get('X-App-Token') is not None}, is_api: {is_api}", flush=True)
    
    if is_api:
        return jsonify({'error': 'Authentication required. Please log in.'}), 401
    # Standard web browser flow — redirect to login page
    return redirect(url_for('login'))


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

# Make all sessions permanent by default for better PWA experience
@app.before_request
def make_session_permanent():
    session.permanent = True

# Ensure all external URLs are generated with https
app.config['PREFERRED_URL_SCHEME'] = 'https'




# Setup the secret key
app.config["SECRET_KEY"] = get_env_variable('SECRET')

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
except Exception as e:
    app.logger.warning(f'Redis cache not available, using in-memory cache: {e}')
    redis_cache = None

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
# Blog feed cache (15 second TTL - short to maintain freshness/randomness)
blog_feed_cache = TTLCache(maxsize=1, ttl=15)
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

# --- Community Notes Collections ---
communities_conf = db['communities']
community_notes_conf = db['community_notes']
community_reactions_conf = db['community_reactions']
community_reports_conf = db['community_reports']

# --- Direct Messaging Performance Indexes ---
direct_messages_conf.create_index([('sender_id', 1), ('recipient_id', 1), ('timestamp', -1)])
direct_messages_conf.create_index([('recipient_id', 1), ('is_read', 1)])

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

# In-memory tracker for active chat views (user_id -> set of partner_ids they're viewing)
# Used to suppress push notifications when recipient is already in the chat
active_chat_views = {}

# In-memory tracker for shared note viewers (share_id -> {user_id: {name, avatar, id}})
# Used for real-time "Studying Now" presence avatars
active_note_viewers = {}

# In-memory edit locks for shared notes (share_id -> {user_id, user_name, timestamp})
# Prevents concurrent editing conflicts during Bible study sessions
note_locks = {}


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
app_tokens_conf.create_index('token', unique=True)
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
database.app_updates_conf = app_updates_conf
database.communities_conf = communities_conf
database.community_notes_conf = community_notes_conf
database.community_reactions_conf = community_reactions_conf
database.community_reports_conf = community_reports_conf
database.dm_permissions_conf = dm_permissions_conf
database.scheduled_messages_conf = scheduled_messages_conf
database.note_attachments_conf = note_attachments_conf
database.redis_cache = redis_cache

# --- Encryption utilities for personal notes ---
# v2: Per-user key derivation with increased iterations (OWASP 2024 recommendation).
# Backward-compatible: falls back to v1 global key for notes encrypted before the upgrade.



# --- Community Encryption Utilities ---



# --- Typesense setup for fast full-text search ---
# Import Typesense client module (shared between main.py and api.py)
import typesense_client as _t

# Typesense state — always resolved from _t.<attr> to avoid stale capture at import




@app.before_request
def update_last_active():
    """Update a user's last active timestamp with debouncing (every 5 minutes) to reduce DB load."""
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
            return redirect(url_for('login'))

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

    canonical_host = "echowithin.xyz"
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
    if request.is_secure:
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
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "media-src 'self' https://res.cloudinary.com; "
        "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com wss://echowithin.xyz https://cdn.socket.io https://cdn.jsdelivr.net; "
        "frame-ancestors 'self'; "
        "base-uri 'self'; "
        "form-action 'self' https://accounts.google.com;"
    )

    # Prevent indexing of private/auth routes without triggering GSC blocked warnings
    noindex_paths = ('/admin', '/api', '/logout', '/login', '/register', '/dashboard', '/messages', '/personal_space', '/shared/', '/search', '/profile_settings', '/reset_password', '/create_post', '/edit_post')
    if getattr(request, 'path', '').startswith(noindex_paths):
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'

    return response




@app.context_processor
def inject_pinned_announcement():
    """Makes the pinned announcement available to all templates (cached for 60s)."""
    cache_key = 'pinned_announcement'

    # Try Redis cache first
    if redis_cache:
        try:
            cached = redis_cache.get(cache_key)
            if cached:
                if cached == '__none__':
                    return dict(pinned_announcement=None)
                return dict(pinned_announcement=json.loads(cached))
        except Exception:
            pass

    # Try in-memory cache
    if cache_key in _pinned_announcement_cache:
        return dict(pinned_announcement=_pinned_announcement_cache[cache_key])

    # Fetch from DB
    pinned_announcement = announcements_conf.find_one({'is_pinned': True})

    # Cache the result
    if redis_cache:
        try:
            if pinned_announcement:
                # Convert ObjectId to string for JSON serialization
                cache_doc = {k: str(v) if isinstance(v, ObjectId) else v for k, v in pinned_announcement.items()}
                redis_cache.setex(cache_key, 60, json.dumps(cache_doc, default=str))
            else:
                redis_cache.setex(cache_key, 60, '__none__')
        except Exception:
            pass

    _pinned_announcement_cache[cache_key] = pinned_announcement
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










































def send_fcm_notification_to_user(user_id_str, title, body, url=None, data=None):
    """Send FCM notification to all registered devices for a user (native app).
    
    This is called alongside web push to ensure both browser and native app users
    receive notifications.
    """
    if not FIREBASE_INITIALIZED:
        return 0
    
    try:
        # Get all FCM tokens for this user
        tokens = list(fcm_tokens_conf.find({'user_id': ObjectId(user_id_str)}))
        if not tokens:
            return 0
        
        # Get the user's current unread count for the badge
        badge_count = _get_user_badge_count(user_id_str)

        sent_count = 0
        for token_doc in tokens:
            try:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=body,
                    ),
                    data={
                        'url': url or '/',
                        'click_action': url or '/',  # URL to open when clicked
                        **(data or {})
                    },
                    token=token_doc['token'],
                    android=messaging.AndroidConfig(
                        priority='high',
                        notification=messaging.AndroidNotification(
                            icon='ic_stat_notification',
                            color='#3e2217',
                            channel_id='default',
                            notification_count=badge_count,
                        ),
                    ),
                    apns=messaging.APNSConfig(
                        headers={'apns-priority': '10'},
                        payload=messaging.APNSPayload(
                            aps=messaging.Aps(
                                alert=messaging.ApsAlert(
                                    title=title,
                                    body=body
                                ),
                                badge=badge_count,
                                sound='default',
                                mutable_content=True,
                            ),
                        ),
                    ),
                )
                messaging.send(message)
                sent_count += 1
            except messaging.UnregisteredError:
                # Token is invalid, remove it
                fcm_tokens_conf.delete_one({'_id': token_doc['_id']})
                app.logger.debug(f"Removed invalid FCM token for user {user_id_str}")
            except Exception as e:
                app.logger.error(f"FCM send error for user {user_id_str}: {e}")
        
        return sent_count
    except Exception as e:
        app.logger.error(f"Error in send_fcm_notification_to_user: {e}")
        return 0


def send_fcm_notifications_batch(tokens_list, title, body, url=None, data=None):
    """Send FCM notifications to multiple tokens at once (for broadcast notifications)."""
    if not FIREBASE_INITIALIZED or not tokens_list:
        return 0
    
    try:
        messages = []
        for token_doc in tokens_list:
            # Get per-user badge count for targeted notifications
            token_user_id = token_doc.get('user_id')
            badge_count = _get_user_badge_count(str(token_user_id)) if token_user_id else 1

            messages.append(messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data={
                    'url': url or '/',
                    'click_action': url or '/',
                    **(data or {})
                },
                token=token_doc['token'],
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        icon='ic_stat_notification',
                        color='#3e2217',
                        channel_id='default',
                        notification_count=badge_count,
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={'apns-priority': '10'},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(
                                title=title,
                                body=body
                            ),
                            badge=badge_count,
                            sound='default',
                            mutable_content=True,
                        ),
                    ),
                ),
            ))
        
        # Send in batches of 500 (FCM limit)
        sent_count = 0
        for i in range(0, len(messages), 500):
            batch = messages[i:i+500]
            response = messaging.send_each(batch)
            sent_count += response.success_count
            
            # Remove failed tokens
            for idx, send_response in enumerate(response.responses):
                if not send_response.success:
                    if hasattr(send_response, 'exception') and isinstance(send_response.exception, messaging.UnregisteredError):
                        fcm_tokens_conf.delete_one({'_id': tokens_list[i + idx]['_id']})
        
        return sent_count
    except Exception as e:
        app.logger.error(f"Error in send_fcm_notifications_batch: {e}")
        return 0











# ----------------- Search endpoints -----------------


# ----------------- Admin analytics -----------------



















@rq.job
def reindex_typesense_job():
    """Background job to reindex all posts into Typesense."""
    try:
        total = reindex_all_posts_to_typesense()
        app.logger.info(f'Typesense posts reindex job finished ({total} docs)')
    except Exception as e:
        app.logger.error(f'Typesense reindex job failed: {e}', exc_info=True)
















@rq.job
def send_log_email_job():
    """
    A background job that sends the contents of the log file via email
    and then rotates the log file.
    """
    log_file_path = 'echowithin.log'
    if not os.path.exists(log_file_path) or os.path.getsize(log_file_path) == 0:
        app.logger.info("Log file is empty or does not exist. Skipping email.")
        return

    try:
        with app.app_context():
            developer_email = get_env_variable('MY_EMAIL')
            msg = Message(
                subject=f"EchoWithin Weekly Log Report - {datetime.date.today().isoformat()}",
                sender=get_env_variable('MAIL_USERNAME'),
                recipients=[developer_email]
            )
            msg.body = "Attached is the latest log file from the EchoWithin application."

            with open(log_file_path, 'rb') as f:
                msg.attach(
                    "echowithin.log",
                    "text/plain",
                    f.read()
                )

            mail.send(msg)
            app.logger.info(f"Log file email sent to {developer_email}.")
    except Exception as e:
        app.logger.error(f"Failed to send log file email: {e}", exc_info=True)


@rq.job
def send_ntfy_notification(message, title, tags=""):
    """Sends a push notification to an ntfy topic as a background job."""
    # Use os.environ.get to avoid raising an exception when not configured
    ntfy_topic = os.environ.get('NTFY_TOPIC')
    if not ntfy_topic:
        app.logger.info("NTFY_TOPIC not set, skipping notification.")
        return

    try:
        headers = {}
        if title:
            headers['Title'] = title
        if tags:
            headers['Tags'] = tags

        # Optional basic auth for ntfy (if the topic requires auth)
        ntfy_user = os.environ.get('NTFY_USERNAME')
        ntfy_pass = os.environ.get('NTFY_PASSWORD')
        auth = (ntfy_user, ntfy_pass) if ntfy_user and ntfy_pass else None

        resp = requests.post(
            f"https://ntfy.sh/{ntfy_topic}",
            data=message.encode('utf-8'),
            headers=headers,
            timeout=5,
            auth=auth
        )

        if resp.ok:
            app.logger.info(f"Successfully sent ntfy notification to topic: {ntfy_topic} (status {resp.status_code})")
        else:
            app.logger.error(f"ntfy send failed for topic {ntfy_topic}: status={resp.status_code}, body={resp.text}")
    except Exception as e:
        app.logger.error(f"Failed to send ntfy notification: {e}", exc_info=True)





































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







# --- Push Notification Subscription Endpoints ---


















































# ---------------- Paystack Integration ----------------











# --- Pinning post API is removed ---
































# ----------------- App Lock & Note Locking -----------------












# ----------------- Note Sharing Endpoints -----------------






# --- Note Attachment APIs (images & voice notes on collaborative notes) ---











# --- WebSocket Real-time collaboration ---
@socketio.on('join_note')
def handle_join_note(data):
    share_id = data.get('share_id')
    user_name = data.get('user_name', 'Anonymous')
    user_id = str(current_user.id) if current_user.is_authenticated else request.sid
    
    if share_id:
        join_room(share_id)
        
        # Track presence
        if share_id not in active_note_viewers:
            active_note_viewers[share_id] = {}
        
        active_note_viewers[share_id][user_id] = {
            'name': user_name,
            'avatar': getattr(current_user, 'profile_image_url', None) if current_user.is_authenticated else None,
            'id': user_id
        }
        
        # Broadcast updated presence list
        emit('presence_update', {'users': list(active_note_viewers[share_id].values())}, room=share_id)
        
        # Check if note is currently locked
        lock_info = note_locks.get(share_id)
        if lock_info:
            emit('lock_status', lock_info, room=request.sid)
            
        app.logger.info(f"User {user_name} joined note room: {share_id}")

@socketio.on('leave_note')
def handle_leave_note(data):
    share_id = data.get('share_id')
    user_id = str(current_user.id) if current_user.is_authenticated else request.sid
    
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
            
        app.logger.info(f"User left note room: {share_id}")

@socketio.on('acquire_lock')
def handle_acquire_lock(data):
    share_id = data.get('share_id')
    user_name = data.get('user_name', 'Anonymous')
    user_id = str(current_user.id) if current_user.is_authenticated else request.sid
    
    if not share_id: return

    now = time.time()
    existing_lock = note_locks.get(share_id)
    
    # If lock exists and hasn't expired (10 mins)
    if existing_lock and (now - existing_lock['timestamp'] < 600) and existing_lock['user_id'] != user_id:
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
def handle_release_lock(data):
    share_id = data.get('share_id')
    user_id = str(current_user.id) if current_user.is_authenticated else request.sid
    
    if share_id in note_locks and note_locks[share_id]['user_id'] == user_id:
        note_locks.pop(share_id)
        emit('lock_released', {'share_id': share_id}, room=share_id)

@socketio.on('note_update')
def handle_note_update(data):
    share_id = data.get('share_id')
    content = data.get('content')
    if share_id and content:
        # Broadcast the update to others in the same room
        emit('note_changed', {'content': content}, room=share_id, include_self=False)

@socketio.on('discussion_new_comment')
def handle_discussion_new_comment(data):
    share_id = data.get('share_id')
    comment_data = data.get('comment')
    if share_id and comment_data:
        emit('discussion_updated', {'comment': comment_data}, room=share_id, include_self=False)


# --- Direct Messaging (DM) Functionality ---

@socketio.on('join_inbox')
@login_required
def handle_join_inbox():
    """Each user joins their own private room for real-time DM delivery."""
    user_room = f"user_{current_user.id}"
    join_room(user_room)
    app.logger.info(f"User {current_user.username} joined private inbox room: {user_room}")







@socketio.on('viewing_chat')
@login_required
def handle_viewing_chat(data):
    """Track that the user is actively viewing a specific chat for notification suppression."""
    partner_id = data.get('partner_id')
    if partner_id:
        user_id = str(current_user.id)
        if user_id not in active_chat_views:
            active_chat_views[user_id] = set()
        active_chat_views[user_id].add(partner_id)

@socketio.on('leave_chat')
@login_required
def handle_leave_chat(data):
    """User left a specific chat view."""
    partner_id = data.get('partner_id')
    if partner_id:
        user_id = str(current_user.id)
        if user_id in active_chat_views:
            active_chat_views[user_id].discard(partner_id)

@socketio.on('disconnect')
def handle_dm_disconnect():
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


@socketio.on('send_dm')
@login_required
def handle_send_dm(data):
    """
    Handles sending a direct message via Socket.IO.
    Data expected: { 'recipient_id': '...', 'content': '...', 'reply_to_id': '...', 'image_url': '...', 'message_type': 'text|image' }
    """
    recipient_id_str = data.get('recipient_id')
    content = data.get('content', '')
    reply_to_id = data.get('reply_to_id')
    image_url = data.get('image_url')
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
        
        # Broadcast payload
        payload = {
            'id': str(message_doc['_id']),
            'sender_id': sender_id_str,
            'sender_username': current_user.username,
            'content': content,
            'timestamp': message_doc['timestamp'].isoformat(),
            'is_read': is_actively_reading,
            'message_type': message_type
        }
        if image_url: payload['image_url'] = image_url
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
                url=url_for('messages_page', _external=True),
                tag=f'dm-{current_user.id}'
            )
        
        # Invalidate the recipient's badge cache so the next poll picks up the new DM
        _invalidate_badge_cache(recipient_id_str)
        
    except Exception as e:
        app.logger.error(f"Error sending DM via socket: {e}")

@socketio.on('typing')
@login_required
def handle_typing(data):
    """Broadcasts that the current user is typing to the recipient."""
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_id_str = str(recipient_id)
        recipient_room = f"user_{recipient_id_str}"
        emit('user_typing', {
            'sender_id': str(current_user.id),
            'username': current_user.username
        }, room=recipient_room)

@socketio.on('stop_typing')
@login_required
def handle_stop_typing(data):
    """Broadcasts that the user has stopped typing."""
    recipient_id = data.get('recipient_id')
    if recipient_id:
        recipient_id_str = str(recipient_id)
        recipient_room = f"user_{recipient_id_str}"
        emit('user_stop_typing', {
            'sender_id': str(current_user.id)
        }, room=recipient_room)
















# --- DM Request System Endpoints ---











# --- Scheduled Messages ---






























# --- Note Discussion Routes (Login Required) ---





























# =====================================================
# SEO: Sitemap and Robots.txt
# =====================================================






# Handles any possible errors

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(RateLimitException)
def handle_ratelimit_exception(e):
    """Custom handler for rate limit exceeded exceptions."""
    period_remaining = math.ceil(e.period_remaining)
    app.logger.warning(f"Rate limit exceeded for IP {request.remote_addr}. Blocked for {period_remaining} seconds.")
    return render_template('429.html', period_remaining=period_remaining), 429

@app.errorhandler(500)
def internal_server_error(e):
    """Handler for 500 errors, sends an ntfy notification."""
    try:
        # Log the original error first
        app.logger.error(f"Internal Server Error on {request.path}: {e}", exc_info=True)
        try:
            send_ntfy_notification.queue(f"A 500 error occurred on endpoint {request.path}. Check logs for details.", "Application Error (500)", "warning")
        except redis.exceptions.ConnectionError as ntfy_e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for 500 error ntfy notification. Error: {ntfy_e}")
            with app.app_context():
                executor.submit(send_ntfy_notification, f"A 500 error occurred on endpoint {request.path}. Check logs for details.", "Application Error (500)", "warning")
        except Exception as ntfy_e:
            app.logger.error(f"Failed to enqueue ntfy notification for 500 error: {ntfy_e}")
    except Exception as log_e:
        print(f"CRITICAL: Failed to log 500 error: {log_e}", file=sys.stderr)
    return render_template("500.html"), 500# ==============================================================================
# COMMUNITY NOTES API ROUTES
# ==============================================================================

















# ==============================================================================
# COMMUNITY REPORTING & ADMIN MODERATION
# ==============================================================================


















