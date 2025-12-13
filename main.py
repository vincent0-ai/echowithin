import datetime
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash, make_response, send_from_directory, abort
import logging
import math
import redis
import bleach
from flask_rq2 import RQ
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from flask_mail import Mail, Message
from concurrent.futures import ThreadPoolExecutor
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from bson.son import SON
from ratelimit import limits, RateLimitException
from dotenv import load_dotenv
import secrets
from jigsawstack import JigsawStack
from cachetools import cached, TTLCache
import time
import requests
from werkzeug.utils import secure_filename
import hashlib
from slugify import slugify
import cloudinary
import cloudinary.uploader
import json
from logging.handlers import RotatingFileHandler
import markdown
from pythonjsonlogger import jsonlogger
from requests_oauthlib import OAuth2Session
from werkzeug.middleware.proxy_fix import ProxyFix
from meilisearch import Client as MeiliClient
from PIL import Image
from io import BytesIO

app = Flask(__name__)

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
        '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d'
    )
    file_handler.setFormatter(formatter)
    
    # Add the handler to the app's logger
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('EchoWithin application startup')

login_manager = LoginManager(app)
rq = RQ(app)
login_manager.login_view = 'login'  # snyk:disable=security-issue

# Secure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent client-side JS from accessing the cookie
app.config['SESSION_COOKIE_SECURE'] = True # Only send cookie over HTTPS (set to True in production)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protection against CSRF

# Configure permanent session lifetime for "Remember Me"
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)
# Load environment variables from .env file

# Ensure all external URLs are generated with https
app.config['PREFERRED_URL_SCHEME'] = 'https'
load_dotenv()



def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        message = f"Expected environment variable '{name}' not set."
        raise Exception(message)

# Google OAuth configuration
GOOGLE_CLIENT_ID = get_env_variable('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = get_env_variable('GOOGLE_CLIENT_SECRET')

# Setup the secret key
app.config["SECRET_KEY"] = get_env_variable('SECRET')

# Configuration for file uploads (now handled by Cloudinary)
# UPLOAD_FOLDER is kept for backward compatibility with old posts.
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg', 'mov'}
MAX_VIDEO_SIZE = 10 * 1024 * 1024  # 10 MB limit for uploaded videos
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Temporary Uploads for Background Processing ---
TEMP_UPLOAD_FOLDER = 'temp_uploads'
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER
os.makedirs(TEMP_UPLOAD_FOLDER, exist_ok=True)


# --- Cloudinary Configuration ---
cloudinary.config(cloud_name = get_env_variable('CLOUDINARY_CLOUD_NAME'), api_key = get_env_variable('CLOUDINARY_API_KEY'), api_secret = get_env_variable('CLOUDINARY_API_SECRET'))

app.config['MAIL_SERVER'] = get_env_variable('MAIL_SERVER')
app.config['MAIL_PORT'] = int(get_env_variable('MAIL_PORT'))
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = get_env_variable('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = get_env_variable('MAIL_PASSWORD')  

# Configure Redis connection for RQ background jobs
REDIS_HOST = get_env_variable('REDIS_HOST')
REDIS_PORT = get_env_variable('REDIS_PORT')
REDIS_PASSWORD = get_env_variable('REDIS_PASSWORD') # Password can be optional

# Format with password 
redis_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"

app.config['RQ_REDIS_URL'] = redis_url
mail = Mail(app)

TIME = int(get_env_variable('TIME'))


client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
db = client['echowithin_db']
users_conf = db['users']
posts_conf = db['posts']
logs_conf = db['logs']
auth_conf = db['auth']
announcements_conf = db['announcements']
comments_conf = db['comments']
personal_posts_conf = db['personal_posts']

# Ensure a text index exists on the posts collection for search functionality
posts_conf.create_index([('title', 'text'), ('content', 'text')])

# --- Meilisearch setup for fast full-text search ---
MEILI_URL = get_env_variable('MEILI_URL')
MEILI_MASTER_KEY = get_env_variable('MEILI_MASTER_KEY')
meili_client = None
meili_index = None
if MEILI_URL and MEILI_MASTER_KEY:
    try:
        meili_client = MeiliClient(MEILI_URL, MEILI_MASTER_KEY)
        # create or get posts index
        try:
            # Try to get an existing Index object
            meili_index = meili_client.get_index('posts')
        except Exception:
            # If the index does not exist, create it. Some Meili client versions
            # return a TaskInfo dict from create_index; ensure we obtain an Index
            try:
                meili_client.create_index(uid='posts', options={'primaryKey': 'id'})
            except Exception as ce:
                app.logger.debug(f'create_index returned error (continuing): {ce}')
            # Obtain the Index object (this method returns an Index wrapper)
            try:
                meili_index = meili_client.index('posts')
            except Exception as ie:
                app.logger.error(f'Failed to obtain Meili index object: {ie}')
                meili_index = None

        # Configure searchable and filterable attributes (these methods return tasks; we don't chain them)
        try:
            if hasattr(meili_index, 'update_searchable_attributes'):
                meili_index.update_searchable_attributes(['title', 'content'])
            else:
                app.logger.debug('meili_index missing update_searchable_attributes; skipping')
        except Exception as e:
            app.logger.debug(f'Failed to update searchable attributes: {e}')
        try:
            if hasattr(meili_index, 'update_filterable_attributes'):
                meili_index.update_filterable_attributes(['author_username', 'tags', 'created_at'])
                meili_index.update_filterable_attributes(['id', 'author_username', 'tags', 'created_at'])
            else:
                app.logger.debug('meili_index missing update_filterable_attributes; skipping')
        except Exception as e:
            app.logger.debug(f'Failed to update filterable attributes: {e}')
        
        # Configure typo tolerance: allow up to 2 typos for queries
        try:
            if hasattr(meili_index, 'update_typo_tolerance'):
                meili_index.update_typo_tolerance({
                    'enabled': True,
                    'minWordSizeForTypos': {'oneTypo': 5, 'twoTypos': 9}
                })
                app.logger.debug('Typo tolerance configured: 1 typo for words ≥5 chars, 2 typos for words ≥9 chars')
            else:
                app.logger.debug('meili_index missing update_typo_tolerance; skipping')
        except Exception as e:
            app.logger.debug(f'Failed to configure typo tolerance: {e}')
        
        # Configure ranking rules: prioritize relevance, then recency
        try:
            if hasattr(meili_index, 'update_ranking_rules'):
                meili_index.update_ranking_rules([
                    'sort',
                    'words',
                    'typo',
                    'proximity',
                    'attribute',
                    'exactness',
                    'created_at:desc'  # Most recent posts ranked higher
                ])
                app.logger.debug('Ranking rules configured: relevance-based with recency boost')
            else:
                app.logger.debug('meili_index missing update_ranking_rules; skipping')
        except Exception as e:
            app.logger.debug(f'Failed to configure ranking rules: {e}')
        
        # Configure sortable attributes for user-initiated sorting
        try:
            if hasattr(meili_index, 'update_sortable_attributes'):
                meili_index.update_sortable_attributes(['created_at', 'title'])
                app.logger.debug('Sortable attributes configured: created_at, title')
            else:
                app.logger.debug('meili_index missing update_sortable_attributes; skipping')
        except Exception as e:
            app.logger.debug(f'Failed to configure sortable attributes: {e}')
        app.logger.info('Connected to Meilisearch and configured index `posts`.')
    except Exception as e:
        app.logger.error(f'Failed to initialize Meilisearch client: {e}')


def _post_to_meili_doc(post_doc: dict) -> dict:
    """Convert a MongoDB post document to Meilisearch document shape."""
    return {
        'id': str(post_doc.get('_id')),
        'title': post_doc.get('title', ''),
        'content': post_doc.get('content', ''),
        'slug': post_doc.get('slug'),
        'author_id': str(post_doc.get('author_id')) if post_doc.get('author_id') else None,
        'author_username': post_doc.get('author_username') or post_doc.get('author', ''),
        'tags': post_doc.get('tags', []),
        # Store created_at as a Unix timestamp for efficient filtering/sorting
        'created_at': int((post_doc.get('created_at') or post_doc.get('timestamp') or datetime.datetime.now(datetime.timezone.utc)).timestamp()),
    }


def index_post_to_meili(post_id: str):
    """Index a single post into Meilisearch. Safe no-op if Meili not configured."""
    if not meili_index:
        return False
    try:
        post = posts_conf.find_one({'_id': ObjectId(post_id)})
        if not post:
            return False
        doc = _post_to_meili_doc(post)
        meili_index.add_documents([doc])
        return True
    except Exception as e:
        app.logger.error(f'Error indexing post {post_id} to Meili: {e}')
        return False


def reindex_all_posts_to_meili(batch_size: int = 1000):
    """Reindex all posts into Meilisearch in batches."""
    if not meili_index:
        raise RuntimeError('Meilisearch not configured')
    # Atlas tiers disallow noCursorTimeout cursors. Use paginated reads
    # based on `_id` ranges to avoid long-lived server-side cursors.
    try:
        last_id = None
        while True:
            query = {} if last_id is None else {"_id": {"$gt": last_id}}
            docs = list(posts_conf.find(query).sort("_id", 1).limit(batch_size))
            if not docs:
                break
            meili_index.add_documents([_post_to_meili_doc(p) for p in docs], primary_key='id')
            last_id = docs[-1]["_id"]
    except Exception as e:
        app.logger.error(f'Error during reindex_all_posts_to_meili: {e}')
        raise

@app.template_filter('linkify')
def linkify_filter(text):
    """A Jinja2 filter to turn URLs in text into clickable links."""
    return bleach.linkify(text)

@app.template_filter('from_timestamp')
def from_timestamp_filter(timestamp):
    """A Jinja2 filter to convert a Unix timestamp to a datetime object."""
    try:
        return datetime.datetime.fromtimestamp(int(timestamp), tz=datetime.timezone.utc)
    except (ValueError, TypeError):
        return timestamp # Return original value if conversion fails


class User(UserMixin):
    def __init__(self, user_data):
        # Store user-specific properties
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.is_admin = user_data.get('is_admin', False)
        self._is_active = user_data.get('is_confirmed', False)

    @property
    def is_active(self):
        return self._is_active

    def get_admin(self):
        return self.is_admin

@app.before_request
def update_last_active():
    """Update a user's last active timestamp on each request."""
    if current_user.is_authenticated:
        # Fetch the full user document to check for ban status
        user_doc = users_conf.find_one({'_id': ObjectId(current_user.id)})

        # If user is banned, log them out immediately.
        if user_doc and user_doc.get('is_banned'):
            logout_user()
            flash('Your account has been suspended. Please contact support.', 'danger')
            # Redirect to login to prevent further access to authenticated routes
            return redirect(url_for('login'))
        
        # If user is not banned, update their last active time
        if user_doc:
            users_conf.update_one({'_id': user_doc['_id']}, {'$set': {'last_active': datetime.datetime.now(datetime.timezone.utc)}})


@app.before_request
def enforce_canonical_domain_and_https():
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


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = kwargs.get('post_id')
        if not post_id:
            # This case should ideally not be reached if routes are set up correctly
            flash("Post ID is missing.", "danger")
            return redirect(url_for('home'))

        post = posts_conf.find_one({'_id': ObjectId(post_id)})

        # Check if post exists and if the current user is the author
        if not post or str(post.get('author_id')) != current_user.id:
            flash("You are not authorized to perform this action.", "danger")
            return redirect(url_for('blog'))

        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_pinned_announcement():
    """Makes the pinned announcement available to all templates."""
    pinned_announcement = announcements_conf.find_one({'is_pinned': True})
    return dict(pinned_announcement=pinned_announcement)

## Remark42 removed: internal comments will be used instead.

@app.context_processor
def inject_current_year():
    """Makes the current year available to all templates."""
    return {'current_year': datetime.date.today().year}


@login_manager.user_loader
def load_user(user_id):
    user_data = users_conf.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

def check_image_for_nsfw(image_path):
    """
    Checks an image for NSFW content using the Sightengine API.
    Returns True if NSFW, False otherwise. This has been updated to use JigsawStack.
    """
    try:
        # Initialize the JigsawStack client
        client = JigsawStack(api_key=get_env_variable('JIGSAW_API_KEY'))
        
        # Perform the NSFW check using the SDK
        # The SDK handles opening and sending the file
        response = client.image.nsfw(image_path=image_path)
        
        # The response is a Pydantic model, access the result like this:
        return response.nsfw.is_nsfw

    except Exception as e:
        # Catch exceptions from the JigsawStack library (e.g., API errors, network issues)
        app.logger.error(f"Error calling JigsawStack API via SDK: {e}")
        return False # Fail open on API error, assuming the image is safe


@rq.job
def process_image_for_nsfw(post_id, image_url, public_id):
    """
    This function runs as a background job to check an image for NSFW content.
    It uses JigsawStack for NSFW detection and updates the post status.
    """
    app.logger.info(f"Starting NSFW check job for post {post_id} on image URL: {image_url}")

    try:
        # Use JigsawStack for NSFW detection via API
        api_response = requests.post(
            'https://api.jigsawstack.com/v1/ai/nsfw',
            json={"image_url": image_url},
            headers={"x-api-key": get_env_variable('JIGSAW_API_KEY')}
        )
        if api_response.status_code == 200:
            data = api_response.json()
            is_nsfw = data.get('nsfw', {}).get('is_nsfw', False)
        else:
            is_nsfw = False

        if is_nsfw:
            app.logger.warning(f"NSFW content detected in {public_id} for post {post_id}. Tagging image and updating post.")
            cloudinary.uploader.add_tag('nsfw', [public_id])
            posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'image_status': 'removed_nsfw'}})
        else:
            app.logger.info(f"Image {public_id} for post {post_id} is safe. Updating post status.")
            posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'image_status': 'safe'}})
    except Exception as e:
        app.logger.error(f"Error during NSFW check job for post {post_id}: {e}")
        # Fail open: assume safe
        posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'image_status': 'safe'}})



def send_code(email, gen_code=None, retries=3, delay=2):
    for attempt in range(retries):
        try:
            msg = Message(
                subject="Your EchoWithin Verification Code",
                sender=get_env_variable('MAIL_USERNAME'),
                recipients=[email]
            )
            msg.html = render_template("verify.html", code=gen_code)
            mail.send(msg)
            app.logger.info(f"Verification email sent to {email}")
            return True
        except Exception as e:
            app.logger.error(f"Attempt {attempt+1} failed to send email to {email}: {e}")
            time.sleep(delay)
    else:
        app.logger.error(f"Failed to send verification email to {email} after {retries} attempts.")

def send_reset_code(email, reset_token=None, retries=3, delay=2):
    for attempt in range(retries):
        try:
            msg = Message(
                subject="EchoWithin Password Reset",
                sender=get_env_variable('MAIL_USERNAME'),
                recipients=[email]
            )
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            msg.html = render_template("reset_email.html", reset_url=reset_url)
            mail.send(msg)
            app.logger.info(f"Password reset email sent to {email}")
            return True
        except Exception as e:
            app.logger.error(f"Attempt {attempt+1} failed to send reset email to {email}: {e}")
            time.sleep(delay)
    else:
        app.logger.error(f"Failed to send password reset email to {email} after {retries} attempts.")


@rq.job
def send_new_post_notifications(post_id_str):
    """Sends new post notification emails to opted-in users as a background job."""
    try:
        post = posts_conf.find_one({'_id': ObjectId(post_id_str)})
        if not post:
            app.logger.error(f"Post {post_id_str} not found for notification job")
            return

        # Build absolute URL for the post
        with app.app_context():
            try:
                post_url = url_for('view_post', slug=post.get('slug'), _external=True)
            except RuntimeError:
                base_url = os.environ.get('FLASK_URL', 'https://echowithin.xyz')
                post_url = f"{base_url}/post/{post.get('slug')}"

            subject = f"New post on EchoWithin: {post.get('title')}"

            recipients_cursor = users_conf.find(
                {'is_confirmed': True, '$or': [{'notify_new_posts': True}, {'notify_new_posts': {'$exists': False}}]},
                {'email': 1, 'username': 1}
            )

            for u in recipients_cursor:
                try:
                    recipient_email = u.get('email')
                    recipient_name = u.get('username') or ''
                    msg = Message(
                        subject=subject,
                        sender=get_env_variable('MAIL_USERNAME'),
                        recipients=[recipient_email]
                    )
                    msg.html = render_template('new_post_notification.html', post=post, post_url=post_url, recipient_name=recipient_name)
                    mail.send(msg)
                    app.logger.info(f"Sent new-post notification to {recipient_email} for post {post_id_str}")
                except Exception as e:
                    app.logger.error(f"Failed to send new-post email to {u.get('email')}: {e}")
    except Exception as e:
        app.logger.error(f"Error in send_new_post_notifications job for {post_id_str}: {e}", exc_info=True)


# Cache counts for 5 minutes
comment_count_cache = TTLCache(maxsize=512, ttl=300)
@cached(comment_count_cache)
def get_batch_comment_counts(post_urls: tuple) -> dict:
    """Return a mapping from post slug (extracted from URL) to internal comment counts.

    This queries the local `comments` collection once for all given slugs.
    """
    counts_map = {}
    try:
        # Extract slugs from the provided URLs by splitting on '/post/'
        slugs = []
        for u in post_urls:
            if '/post/' in u:
                slugs.append(u.split('/post/')[-1])

        if not slugs:
            return counts_map

        pipeline = [
            {'$match': {'post_slug': {'$in': slugs}, 'is_deleted': False}},
            {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}}
        ]
        agg = list(comments_conf.aggregate(pipeline))
        for doc in agg:
            counts_map[doc['_id']] = doc.get('count', 0)
    except Exception as e:
        app.logger.warning(f"Could not fetch batch comment counts from internal collection: {e}")
    return counts_map


# ----------------- Search endpoints -----------------
@app.route('/search')
def search():
    query = request.args.get('q', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    tags_filter = request.args.getlist('tags')
    author_filter = request.args.get('author')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    # Sorting option: 'relevance' (default), 'newest', 'oldest', 'title_asc', 'title_desc'
    sort = request.args.get('sort', 'relevance')

    results = []
    total = 0
    if meili_index and (query or tags_filter or author_filter or date_from or date_to):
        try:
            # Build Meilisearch filter expression if any filters provided
            filter_expr = None
            filter_clauses = []
            if tags_filter:
                # Filter out empty strings that might come from the form
                tag_clauses = [f'tags = "{t}"' for t in tags_filter if t]
                if tag_clauses:
                    filter_clauses.append('(' + ' OR '.join(tag_clauses) + ')')
            if author_filter: # Only add filter if author is not an empty string
                filter_clauses.append(f'author_username = "{author_filter}"')
            if date_from:
                try:
                    # Convert YYYY-MM-DD to start-of-day timestamp
                    dt_from = datetime.datetime.strptime(date_from, '%Y-%m-%d')
                    filter_clauses.append(f'created_at >= {int(dt_from.timestamp())}')
                except ValueError: pass # Ignore invalid date formats
            if date_to:
                try:
                    # Convert YYYY-MM-DD to end-of-day timestamp
                    dt_to = datetime.datetime.strptime(date_to, '%Y-%m-%d') + datetime.timedelta(days=1, seconds=-1)
                    filter_clauses.append(f'created_at <= {int(dt_to.timestamp())}')
                except ValueError: pass # Ignore invalid date formats
            if filter_clauses:
                filter_expr = ' AND '.join(filter_clauses)

            search_params = {
                'limit': per_page,
                'offset': (page - 1) * per_page,
                'attributesToHighlight': ['title', 'content'], # Highlight matches in these fields
                'attributesToCrop': ['content'], # Create a snippet from the 'content' field
                'cropLength': 40, # Number of words to keep around the match
                'cropMarker': '...', # Text to indicate the content is cropped
                'highlightPreTag': '<span class="highlighted-match">',
                'highlightPostTag': '</span>'
            }
            if filter_expr:
                search_params['filter'] = filter_expr
            
            # Apply sorting
            if sort == 'newest':
                search_params['sort'] = ['created_at:desc']
            elif sort == 'oldest':
                search_params['sort'] = ['created_at:asc']
            elif sort == 'title_asc':
                search_params['sort'] = ['title:asc']
            elif sort == 'title_desc':
                search_params['sort'] = ['title:desc']
            # 'relevance' is default (no sort param needed)

            search_result = meili_index.search(query, search_params)
            total = search_result.get('estimatedTotalHits', search_result.get('nbHits', 0))
            hits = search_result.get('hits', [])
            for h in hits:
                # Prefer the highlighted/formatted fields when available
                formatted = h.get('_formatted', {})
                title_html = formatted.get('title') or h.get('title')
                excerpt = formatted.get('content') or h.get('content', '')[:300]
                results.append({
                    'id': h.get('id'),
                    'title': title_html,
                    'slug': h.get('slug'),
                    'author': h.get('author_username'),
                    'created_at': datetime.datetime.fromtimestamp(h.get('created_at'), tz=datetime.timezone.utc) if h.get('created_at') else None,
                    'excerpt': excerpt
                })
        except Exception as e:
            app.logger.error(f'Meili search error: {e}')
    else:
        # Fallback to simple Mongo search (very limited)
        if query:
            cursor = posts_conf.find({'$text': {'$search': query}}, {'score': {'$meta': 'textScore'}}).sort([('score', {'$meta': 'textScore'})]).limit(per_page)
            for p in cursor:
                results.append({'id': str(p.get('_id')), 'title': p.get('title'), 'slug': p.get('slug'), 'author': p.get('author'), 'created_at': p.get('timestamp'), 'excerpt': p.get('content', '')[:300]})
            total = len(results)

    # Provide available tags and authors for filter UI
    try:
        available_tags = sorted([t for t in posts_conf.distinct('tags') if t])
    except Exception:
        available_tags = []
    try:
        available_authors = sorted([u.get('username') for u in users_conf.find({}, {'username':1}) if u.get('username')])
    except Exception:
        available_authors = []

    return render_template('search_results.html', query=query, results=results, total=total, page=page, per_page=per_page, available_tags=available_tags, available_authors=available_authors, selected_tags=tags_filter, selected_author=author_filter, date_from=date_from, date_to=date_to, sort=sort)


# ----------------- Admin analytics -----------------
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')


@app.route('/admin/metrics')
@login_required
@admin_required
def admin_metrics():
    # Posts per day for last 30 days
    try:
        days = int(request.args.get('days', 30))
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=days)

        pipeline_posts = [
            {'$match': {'created_at': {'$gte': start}}},
            {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}}, 'count': {'$sum': 1}}},
            {'$sort': SON([('_id', 1)])}
        ]
        posts_per_day = list(posts_conf.aggregate(pipeline_posts))

        pipeline_comments = [
            {'$match': {'created_at': {'$gte': start}, 'is_deleted': False}},
            {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}}, 'count': {'$sum': 1}}},
            {'$sort': SON([('_id', 1)])}
        ]
        comments_per_day = list(comments_conf.aggregate(pipeline_comments))

        total_users = users_conf.count_documents({'is_confirmed': True})
        active_users = users_conf.count_documents({'last_active': {'$gte': start}})

        top_posts = list(comments_conf.aggregate([
            {'$match': {'is_deleted': False, 'post_slug': {'$ne': None}}},
            {'$group': {'_id': '$post_slug', 'comment_count': {'$sum': 1}}},
            {'$sort': {'comment_count': -1}},
            {'$limit': 10},
            {'$lookup': {
                'from': 'posts',
                'localField': '_id',
                'foreignField': 'slug',
                'as': 'post_details'
            }},
            {'$unwind': '$post_details'},
            {'$project': {'slug': '$_id', 'count': '$comment_count', 'title': '$post_details.title', '_id': 0}}
        ]))
        
        return jsonify({
            'posts_per_day': posts_per_day,
            'comments_per_day': comments_per_day,
            'total_users': total_users,
            'active_users': active_users,
            'top_posts_by_comments': top_posts
        })
    except Exception as e:
        app.logger.error(f'Error building admin metrics: {e}')
        return jsonify({'error': 'failed to compute metrics'}), 500

@app.route('/admin/active_users')
@login_required
@admin_required
def admin_active_users():
    """API endpoint to get users active in the last 5 minutes."""
    try:
        # Define "active" as having made a request in the last 5 minutes
        five_minutes_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        
        active_users_cursor = users_conf.find(
            {'last_active': {'$gte': five_minutes_ago}},
            {'username': 1, 'last_active': 1, '_id': 0} # Projection
        ).sort('last_active', -1)
        
        active_users_list = list(active_users_cursor)
        
        for user in active_users_list:
            user['last_active'] = user['last_active'].strftime('%H:%M %d-%m-%Y')

        return jsonify({'active_users': active_users_list})
    except Exception as e:
        app.logger.error(f'Error fetching real-time active users: {e}')
        return jsonify({'error': 'failed to fetch active users'}), 500

@app.route('/admin/export_csv')
@login_required
@admin_required
def admin_export_csv():
    metric = request.args.get('metric', 'posts_per_day')
    days = int(request.args.get('days', 30))
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=days)

    import csv
    output = []
    if metric == 'posts_per_day':
        pipeline = [
            {'$match': {'created_at': {'$gte': start}}},
            {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}}, 'count': {'$sum': 1}}},
            {'$sort': SON([('_id', 1)])}
        ]
        rows = list(posts_conf.aggregate(pipeline))
        output.append(['date', 'posts'])
        for r in rows:
            output.append([r['_id'], r['count']])
    else:
        return jsonify({'error': 'unsupported metric'}), 400

    # Build CSV
    si = []
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    for row in output:
        writer.writerow(row)
    csv_data = buf.getvalue()
    resp = make_response(csv_data)
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename="{metric}.csv"'
    return resp


@app.route('/admin/traffic')
@login_required
@admin_required
def admin_traffic():
    """Return basic traffic metrics aggregated from `logs_conf` (visits, top IPs)."""
    try:
        days = int(request.args.get('days', 30))
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=days)

        pipeline_visits = [
            {'$match': {'timestamp': {'$gte': start}}},
            {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}}, 'count': {'$sum': 1}}},
            {'$sort': SON([('_id', 1)])}
        ]
        visits_per_day = list(logs_conf.aggregate(pipeline_visits))

        # Top IPs
        top_ips = list(logs_conf.aggregate([
            {'$match': {'timestamp': {'$gte': start}}},
            {'$group': {'_id': '$ip', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]))

        return jsonify({'visits_per_day': visits_per_day, 'top_ips': top_ips})
    except Exception as e:
        app.logger.error(f'Error building admin traffic: {e}')
        return jsonify({'error': 'failed to compute traffic metrics'}), 500


@app.route('/admin/reindex_meili', methods=['POST'])
@login_required
@admin_required
def admin_reindex_meili():
    if not meili_index:
        return jsonify({'error': 'Meilisearch not configured'}), 500
    try:
        # Enqueue reindex as an RQ background job to avoid blocking the request
        try:
            reindex_meili_job.queue()
            return jsonify({'status': 'queued', 'message': 'Reindex queued as background job'})
        except Exception:
            # Fallback: run synchronously if enqueuing fails
            reindex_all_posts_to_meili()
            return jsonify({'status': 'completed', 'message': 'Reindex completed (synchronous fallback)'})
    except Exception as e:
        app.logger.error(f'Error reindexing: {e}')
        return jsonify({'error': 'reindex failed'}), 500


@rq.job
def reindex_meili_job():
    """Background job to reindex all posts into Meilisearch."""
    try:
        reindex_all_posts_to_meili()
        app.logger.info('Meilisearch reindex job finished')
    except Exception as e:
        app.logger.error(f'Meilisearch reindex job failed: {e}', exc_info=True)

    return counts_map


@app.route('/feed.xml')
def feed():
    """RSS feed (RSS 2.0) for recent published posts."""
    try:
        posts = list(posts_conf.find({'status': 'published'}).sort('created_at', -1).limit(50))
        items = []
        for p in posts:
            pub_date = p.get('timestamp') or p.get('created_at')
            items.append({
                'title': p.get('title'),
                'link': url_for('view_post', slug=p.get('slug'), _external=True),
                'guid': str(p.get('_id')),
                'pubDate': p.get('created_at').strftime('%a, %d %b %Y %H:%M:%S GMT') if p.get('created_at') else '',
                'pubDate': pub_date.strftime('%a, %d %b %Y %H:%M:%S GMT') if pub_date else '',
                'description': (p.get('content') or '')[:400]
            })
        return render_template('feed.xml', items=items), 200, {'Content-Type': 'application/rss+xml; charset=utf-8'}
    except Exception as e:
        app.logger.error(f'Failed to build RSS feed: {e}')
        abort(500)


@app.route('/sitemap.xml')
def sitemap():
    """Dynamically generate sitemap using `sitemap_template.xml`."""
    try:
        pages = []
        # Static routes
        static_paths = ['home', 'blog', 'about', 'terms']
        for p in static_paths:
            try:
                pages.append({'loc': url_for(p, _external=True), 'lastmod': datetime.datetime.now(datetime.timezone.utc).date().isoformat(), 'changefreq': 'weekly', 'priority': '0.7'})
            except Exception:
                pass

        # Posts
        for post in posts_conf.find({'status': 'published'}, {'slug': 1, 'created_at': 1}).sort('created_at', -1).limit(5000):
            pages.append({'loc': url_for('view_post', slug=post.get('slug'), _external=True), 'lastmod': post.get('created_at').date().isoformat() if post.get('created_at') else datetime.datetime.now(datetime.timezone.utc).date().isoformat(), 'changefreq': 'monthly', 'priority': '0.6'})
            last_mod = post.get('created_at') or post.get('timestamp')
            pages.append({'loc': url_for('view_post', slug=post.get('slug'), _external=True), 'lastmod': last_mod.date().isoformat() if last_mod else datetime.datetime.now(datetime.timezone.utc).date().isoformat(), 'changefreq': 'monthly', 'priority': '0.6'})

        return render_template('sitemap_template.xml', pages=pages), 200, {'Content-Type': 'application/xml; charset=utf-8'}
    except Exception as e:
        app.logger.error(f'Failed to build sitemap: {e}')
        abort(500)

def prepare_posts(posts):
    """
    Add `url` and `comment_count` fields to each post.
    Designed to work with Remark42 batch comment count retrieval.
    """
    if not posts:
        return []

    # ---- Step 1: Build canonical URLs and deduplicate them ----
    urls = set()
    for post in posts:
        post_url = url_for("view_post", slug=post.get("slug"), _external=True)
        post["url"] = post_url
        urls.add(post_url)

    # ---- Step 2: Batch-retrieve comment counts from internal comments collection ----
    counts_map = get_batch_comment_counts(tuple(sorted(urls)))

    # ---- Step 3: Assign comment counts back into posts ----
    for post in posts:
        # Extract slug to look up counts_map (we stored counts by slug)
        slug = post.get('slug')
        # get_batch_comment_counts used slugs as keys; ensure counts_map is not None
        post["comment_count"] = counts_map.get(slug, 0) if counts_map else 0

    return posts


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

@app.route('/register', methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if username and password and email:
            # 1. Check if username is already taken
            if users_conf.find_one({'username': username}):
                flash("This username is already taken. Please choose a different one.", "danger")
                return redirect(url_for('register', form='register'))

            # 2. Check if email is already registered
            existing_user_by_email = users_conf.find_one({'email': email})
            if existing_user_by_email:
                # If the user is already confirmed, direct them to login
                if existing_user_by_email.get('is_confirmed'):
                    flash("This email is already registered. Please log in.", "info")
                    return redirect(url_for('login'))
                else:
                    # If not confirmed, resend the confirmation code
                    flash("This email is already registered but not confirmed. We've sent you a new confirmation code.", "info")
                    gen_code = str(secrets.randbelow(10**6)).zfill(6)
                    hashed = hashlib.sha256(gen_code.encode()).hexdigest()
                    auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed}}, upsert=True)
                    send_code(email, gen_code)
                    return redirect(url_for("confirm", email=email))

            # 3. If both username and email are new, create the new user
            hashed_password = generate_password_hash(password)
            users_conf.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'is_confirmed': False, # Set to False to require email confirmation
                'is_admin': False,
                'join_date': datetime.datetime.now()
                , 'notify_new_posts': True
            })

            # --- Send email confirmation ---
            gen_code = str(secrets.randbelow(10**6)).zfill(6)
            hashed = hashlib.sha256(gen_code.encode()).hexdigest()
            auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed}}, upsert=True)
            send_code(email, gen_code)
            
            flash("Account created successfully! Please check your email for a confirmation code.", "success")

            # --- Send ntfy notification for new user ---
            try:
                send_ntfy_notification.queue(f"User '{username}' has registered.", "New User on EchoWithin", "partying_face")
            except redis.exceptions.ConnectionError as e:
                app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {e}")
                with app.app_context():
                    ThreadPoolExecutor().submit(send_ntfy_notification, f"User '{username}' has registered.", "New User on EchoWithin", "partying_face")
            except Exception as e:
                app.logger.error(f"Failed to enqueue ntfy notification for new user '{username}': {e}")

            return redirect(url_for("confirm", email=email))
        else:
            flash('Username and password are required', "danger")
    return render_template("auth.html", active_page='register', form='register')
    
@app.route("/confirm/<email>", methods=['GET', 'POST']) # snyk:disable=security-issue
@limits(calls=15, period=TIME)
def confirm(email):
    user = users_conf.find_one({"email": email})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("register"))
    if user.get('is_confirmed'):
        flash("Your email is already confirmed. Please login.", "info")
        return redirect(url_for("login"))
    if request.method == 'POST':
        confirm_code = request.form.get("code")
        if confirm_code:
            hashed_obj = auth_conf.find_one({'email': email})
            if hashed_obj and hashed_obj['hashed_code'] == hashlib.sha256(confirm_code.encode()).hexdigest():
                users_conf.update_one(
                    {'email': email},
                    {'$set': {'is_confirmed': True}}
                )
                auth_conf.delete_one({'email': email})  # Clean up auth_conf after confirmation
                flash("Your email has been confirmed successfully. Please login.", "success")
                return redirect(url_for("login"))
            else:
                flash("The confirmation code is incorrect.", "danger")
        else:
            flash("Please enter the confirmation code.", "danger")
    return render_template("confirm.html", email=email, active_page='confirm')
            
        
                    

@app.route("/login", methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def login():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember") == "on" # Check if the "Remember Me" box was checked
        
        user = users_conf.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            if not user.get('is_confirmed'):
                flash('Please confirm your account first', "danger")
                return redirect(url_for('login'))

            # Check if the user is banned
            if user.get('is_banned'):
                logout_user()
                flash('Your account has been suspended. Please contact support.', 'danger')
                return redirect(url_for('login'))
                
            
            user_obj = User(user)
            login_user(user_obj, remember=remember) # Pass the remember flag to login_user
            if current_user.is_admin and current_user.is_authenticated:
                flash('You have logged in as admin', 'success')
                return redirect(url_for('home'))
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(request.args.get('next') or url_for('home'))
        else:
            flash("Wrong details provided", "danger")
    return render_template("auth.html", active_page='login', form='login')

@app.route('/google_login')
def google_login():
    # Define the scopes required to access user's email and profile information
    scope = ['openid', 'email', 'profile']
    google = OAuth2Session(GOOGLE_CLIENT_ID, scope=scope, redirect_uri=url_for('google_callback', _external=True))
    authorization_url, state = google.authorization_url(
        'https://accounts.google.com/o/oauth2/auth',
        prompt='consent' # Force the consent screen to be shown on first login.
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/google_callback')
def google_callback():
    # If state is not in session, it's a possible replay attack or the user
    # has already completed the flow. Redirect to login to be safe.
    if 'oauth_state' not in session:
        flash("Authentication session expired or was already used. Please try logging in again.", "warning")
        return redirect(url_for('login'))

    # Pop the state from the session immediately to prevent reuse (e.g., in a PWA/browser race condition)
    oauth_state = session.pop('oauth_state', None)

    # Recreate the session with the same redirect_uri to fetch the token
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        state=oauth_state,
        redirect_uri=url_for('google_callback', _external=True))
    try:
        token = google.fetch_token(
            'https://oauth2.googleapis.com/token',
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url
        )
    except Exception as e:
        app.logger.error(f"Failed to fetch Google OAuth token: {e}", exc_info=True)
        flash("Authentication failed. Please try again.", "danger")
        return redirect(url_for('login'))
    google = OAuth2Session(GOOGLE_CLIENT_ID, token=token)
    response = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
    user_info = response.json()

    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])

    # Check if a user with this email already exists
    user = users_conf.find_one({'email': email})
    if user:
        # If the user exists and is confirmed, log them in directly.
        if not user.get('is_confirmed'):
            flash("Your account is not confirmed. Please check your email for a confirmation link or register again to receive a new one.", "warning")
            return redirect(url_for('login'))
        
        # Check if the user is banned
        if user.get('is_banned'):
                logout_user()
                flash('Your account has been suspended. Please contact support.', 'danger')
                return redirect(url_for('login'))
                
            
        user_obj = User(user)
        # Use 'remember=True' to persist the session across browser restarts
        login_user(user_obj, remember=True)
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for('home'))
    else:
        # New user, create account
        # Store Google info in session and redirect to a completion page
        session['google_signup_info'] = {
            'email': email,
            'name': name
        }
        return redirect(url_for('google_signup'))

@app.route('/google_signup', methods=['GET', 'POST'])
def google_signup():
    if 'google_signup_info' not in session:
        flash("No Google sign-up data found. Please try signing in with Google again.", "warning")
        return redirect(url_for('login'))

    google_info = session['google_signup_info']
    email = google_info['email']

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('google_signup.html', email=email, suggested_username=username)

        if users_conf.find_one({'username': username}):
            flash("This username is already taken. Please choose another.", "danger")
            return render_template('google_signup.html', email=email, suggested_username=username)

        hashed_password = generate_password_hash(password)
        users_conf.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'is_confirmed': True,
            'is_admin': False,
            'join_date': datetime.datetime.now(),
            'notify_new_posts': True
        })

        # --- Send ntfy notification for new user from Google signup ---
        try:
            ntfy_message = f"User '{username}' has registered via Google."
            send_ntfy_notification.queue(ntfy_message, "New User on EchoWithin", "partying_face")
        except redis.exceptions.ConnectionError as e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {e}")
            with app.app_context():
                ThreadPoolExecutor().submit(send_ntfy_notification, ntfy_message, "New User on EchoWithin", "partying_face")
        except Exception as e:
            app.logger.error(f"Failed to enqueue ntfy notification for new Google user '{username}': {e}")

        # Clean up session
        session.pop('google_signup_info', None)

        # Log the new user in
        user = users_conf.find_one({'email': email})
        user_obj = User(user)
        login_user(user_obj)
        flash(f"Account created successfully! Welcome, {username}!", "success")
        return redirect(url_for('home'))

    # For GET request, suggest a username
    suggested_username = google_info['name'].replace(' ', '_').lower()
    return render_template('google_signup.html', email=email, suggested_username=suggested_username)

@app.route('/')
@app.route('/dashboard')
def dashboard():
    page_title = "Welcome to EchoWithin"
    page_description = "EchoWithin is a modern platform for sharing and discussing ideas. Join the conversation today."
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template("dashboard.html", active_page='dashboard', title=page_title, description=page_description)

@app.route('/home')
@login_required
def home():
    page_title = f"Home - {current_user.username}"
    page_description = "Your personal dashboard on EchoWithin. Create new posts and engage with the community."

    # --- Community Stats ---
    total_members = users_conf.count_documents({})
    total_posts = posts_conf.count_documents({})

    # --- Most Active Member Calculation ---
    most_active_pipeline = [
        {"$group": {"_id": "$author", "post_count": {"$sum": 1}}},
        {"$sort": {"post_count": -1}},
        {"$limit": 1}
    ]
    most_active_result = list(posts_conf.aggregate(most_active_pipeline))
    most_active_member = most_active_result[0] if most_active_result else None

    # --- Hot Posts Calculation (Optimized with Aggregation Pipeline) ---
    hot_posts = []
    try:
        seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
        
        # This pipeline performs the entire hot post calculation in the database.
        hot_posts_pipeline = [
            # 1. Find recent posts
            {'$match': {'created_at': {'$gte': seven_days_ago}}},
            # 2. Join with comments collection to get comment counts
            {'$lookup': {
                'from': 'comments',
                'localField': 'slug',
                'foreignField': 'post_slug',
                'as': 'comments'
            }},
            # 3. Add fields for calculation
            {'$addFields': {
                'comment_count': {'$size': '$comments'},
                'age_in_hours': {
                    '$divide': [
                        {'$subtract': ["$$NOW", '$created_at']},
                        3600000 # milliseconds in an hour
                    ]
                }
            }},
            # 4. Calculate the hot score
            {'$addFields': {
                'hot_score': {
                    '$divide': [
                        {'$add': [{'$multiply': ['$comment_count', 5]}, {'$ifNull': ['$view_count', 0]}]},
                        {'$pow': [{'$add': ['$age_in_hours', 2]}, 1.8]}
                    ]
                }
            }},
            # 5. Sort by score and limit to the top 5
            {'$sort': {'hot_score': -1}},
            {'$limit': 5}
        ]
        hot_posts = list(posts_conf.aggregate(hot_posts_pipeline))
        with app.app_context():
            hot_posts = prepare_posts(hot_posts) # Adds 'url' to each post

        # Fallback for new sites: if not enough hot posts, show latest posts.
        if len(hot_posts) < 5:
            app.logger.info("Not enough hot posts found, falling back to latest posts for homepage.")
            latest_posts_cursor = posts_conf.find({}).sort('timestamp', -1).limit(3)
            with app.app_context():
                # Overwrite hot_posts with the latest posts
                hot_posts = prepare_posts(list(latest_posts_cursor))

    except Exception as e:
        app.logger.error(f"Failed to calculate hot posts: {e}")
        hot_posts = []
    return render_template("home.html", username=current_user.username, active_page='home', 
                           title=page_title, description=page_description,
                           total_members=total_members, total_posts=total_posts,
                           most_active_member=most_active_member, hot_posts=hot_posts)

@app.route("/blog")
def blog():
    # --- Search Logic ---
    query = request.args.get('query', None)
    if query:
        # If there's a search query, perform the search and return only search results.
        search_filter = { "$text": { "$search": query } }
        page = request.args.get('page', 1, type=int)
        posts_per_page = 5
        total_posts = posts_conf.count_documents(search_filter)
        total_pages = math.ceil(total_posts / posts_per_page)
        skip = (page - 1) * posts_per_page
        search_results = list(posts_conf.find(search_filter).sort('timestamp', -1).skip(skip).limit(posts_per_page))
        with app.app_context():
            search_results = prepare_posts(search_results)
        
        page_title = f"Search results for '{query}'"
        page_description = f"Displaying search results for '{query}' on EchoWithin."
        return render_template("blog.html", posts=search_results, active_page='blog', page=page, total_pages=total_pages, query=query, title=page_title, description=page_description)

    # --- Default Blog Page Logic (No Search) ---

    # 1. Fetch Latest Posts (sorted by creation/update time)
    latest_posts_cursor = posts_conf.find({}).sort('timestamp', -1).limit(5)
    with app.app_context():
        latest_posts_prepared = prepare_posts(list(latest_posts_cursor))

    page_title = "Blog - EchoWithin"
    page_description = "Explore the latest posts and discussions from the EchoWithin community."
    return render_template("blog.html", latest_posts=latest_posts_prepared, active_page='blog', title=page_title, description=page_description)

@app.route("/blog/all")
@login_required
def all_posts():
    """Displays a paginated list of all blog posts."""
    selected_tag = request.args.get('tag', None)
    page = request.args.get('page', 1, type=int)
    posts_per_page = 5

    # Build the filter query
    filter_query = {}
    if selected_tag:
        filter_query['tags'] = selected_tag

    total_posts = posts_conf.count_documents(filter_query)
    total_pages = math.ceil(total_posts / posts_per_page)

    skip = (page - 1) * posts_per_page

    # Fetch a slice of all posts for the current page, sorted by newest first
    posts = list(posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page))
    with app.app_context():
        posts = prepare_posts(posts)

    # Get all unique tags for the dropdown
    all_tags = posts_conf.distinct('tags')

    if selected_tag:
        page_title = f"Posts tagged '{selected_tag}' - EchoWithin"
        page_description = f"Browse all posts tagged with '{selected_tag}'."
    else:
        page_title = "All Posts - EchoWithin"
        page_description = "Browse through all posts from the EchoWithin community."

    return render_template("all_posts.html", posts=posts, active_page='blog', page=page, total_pages=total_pages, title=page_title, description=page_description, all_tags=sorted(all_tags), selected_tag=selected_tag)


@app.route('/api/posts')
def get_all_posts_json():
    """Returns all posts as a JSON object for client-side rendering."""
    try:
        # Fetch all posts with necessary fields
        all_posts = list(posts_conf.find({}, {'_id': 1, 'title': 1, 'slug': 1, 'content': 1, 'author': 1, 'author_id': 1, 'timestamp': 1, 'image_url': 1, 'image_urls': 1, 'image_public_ids': 1, 'image_status': 1, 'video_url': 1}))
        
        # Convert ObjectId and datetime to strings and add the post URL
        for post in all_posts:
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            # Format timestamp to be consistent with server-rendered posts
            post['timestamp'] = post['timestamp'].strftime('%b %d, %Y at %I:%M %p')
            post['url'] = url_for('view_post', slug=post['slug'], _external=True)

        return jsonify(all_posts)
    except Exception as e:
        app.logger.error(f"Error in get_all_posts_json: {e}")
        return jsonify({"error": "Could not retrieve posts"}), 500


def calculate_hot_score(post, comment_count):
    """
    Calculates a 'hot' score for a post based on comments, views, and age.
    A higher score means the post is 'hotter'.
    """
    post_time = post.get('created_at') or post.get('timestamp')
    if not post_time:
        return 0

    # Ensure post_time is timezone-aware for correct calculation
    if post_time.tzinfo is None:
        post_time = post_time.replace(tzinfo=datetime.timezone.utc)

    age_in_hours = (datetime.datetime.now(datetime.timezone.utc) - post_time).total_seconds() / 3600
    views = post.get('view_count', 0)
    
    # Simple scoring: comments are weighted more heavily than views.
    # The score decays over time using a gravity factor in the denominator.
    score = (comment_count * 5) + views
    return score / ((age_in_hours + 2) ** 1.8) # Gravity factor

@app.route('/api/posts/top-by-comments')
def get_top_posts_json():
    """Return top posts sorted by internal comment counts."""
    try:
        # Aggregate comment counts per post_slug
        pipeline = [
            {'$match': {'is_deleted': False}},
            {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 20}
        ]
        agg = list(comments_conf.aggregate(pipeline))
        results = []
        for doc in agg:
            slug = doc['_id']
            post = posts_conf.find_one({'slug': slug}, {'_id': 1, 'title':1, 'slug':1, 'content':1, 'author':1, 'author_id':1, 'timestamp':1, 'image_url':1, 'image_urls':1, 'image_public_ids':1, 'image_status':1, 'video_url':1})
            if not post:
                continue
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            post['timestamp'] = post['timestamp'].strftime('%b %d, %Y at %I:%M %p') if post.get('timestamp') else None
            post['url'] = url_for('view_post', slug=post['slug'], _external=True)
            post['comment_count'] = doc.get('count', 0)
            results.append(post)
        return jsonify(results)
    except Exception as e:
        app.logger.error(f"Error in get_top_posts_json: {e}")
        return jsonify({'error': 'Could not retrieve top posts'}), 500


@app.route('/api/posts/hot')
def get_hot_posts_json():
    """Return 'hot' posts using a ranking algorithm."""
    try:
        # Fetch recent posts to calculate scores on (e.g., last 7 days)
        seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
        recent_posts = list(posts_conf.find(
            {'created_at': {'$gte': seven_days_ago}},
            {'_id': 1, 'title':1, 'slug':1, 'content':1, 'author':1, 'author_id':1, 'timestamp':1, 'created_at': 1, 'view_count': 1, 'image_url':1, 'image_urls':1}
        ))

        # Get comment counts for these posts
        slugs = [p['slug'] for p in recent_posts if p.get('slug')]
        comment_counts = {doc['_id']: doc.get('count', 0) for doc in comments_conf.aggregate([
            {'$match': {'post_slug': {'$in': slugs}, 'is_deleted': False}},
            {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}}
        ])}

        # Calculate hot score for each post
        scored_posts = []
        for post in recent_posts:
            comment_count = comment_counts.get(post['slug'], 0)
            post['hot_score'] = calculate_hot_score(post, comment_count)
            post['comment_count'] = comment_count
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            post['timestamp'] = (post.get('created_at') or post.get('timestamp')).strftime('%b %d, %Y at %I:%M %p')
            post['url'] = url_for('view_post', slug=post['slug'], _external=True)
            scored_posts.append(post)

        # Sort by hot score and return top 20
        scored_posts.sort(key=lambda p: p['hot_score'], reverse=True)
        return jsonify(scored_posts[:20])
    except Exception as e:
        app.logger.error(f"Error in get_hot_posts_json: {e}")
        return jsonify({'error': 'Could not retrieve hot posts'}), 500

@app.route('/api/posts/related')
@login_required
def get_related_posts_json():
    """
    Returns posts related to a user's activity, finding posts that share
    tags with posts the user has either authored or commented on.
    """
    try:
        interest_tags = set()

        # 1. Find tags from posts the current user has authored.
        user_posts = posts_conf.find({'author_id': ObjectId(current_user.id)}, {'tags': 1})
        for post in user_posts:
            interest_tags.update(post.get('tags', []))

        # 2. Find tags from posts the current user has commented on.
        commented_post_slugs = comments_conf.distinct('post_slug', {'author_id': ObjectId(current_user.id)})
        if commented_post_slugs:
            commented_on_posts = posts_conf.find(
                {'slug': {'$in': commented_post_slugs}},
                {'tags': 1}
            )
            for post in commented_on_posts:
                interest_tags.update(post.get('tags', []))

        if not interest_tags:
            return jsonify([])

        # 3. Find recent posts that have these tags but are not from the current user.
        related_posts_cursor = posts_conf.find(
            {'tags': {'$in': list(interest_tags)}, 'author_id': {'$ne': ObjectId(current_user.id)}},
            {'_id': 1, 'title':1, 'slug':1, 'content':1, 'author':1, 'author_id':1, 'timestamp':1, 'image_url':1, 'image_urls':1, 'video_url':1}
        ).sort('timestamp', -1).limit(10)

        related_posts = list(related_posts_cursor)
        for post in related_posts:
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            post['timestamp'] = post['timestamp'].strftime('%b %d, %Y at %I:%M %p') if post.get('timestamp') else None
            post['url'] = url_for('view_post', slug=post['slug'], _external=True)
            post['comment_count'] = comments_conf.count_documents({'post_slug': post['slug'], 'is_deleted': False})

        return jsonify(related_posts)
    except Exception as e:
        app.logger.error(f"Error in get_related_posts_json for user {current_user.id}: {e}")
        return jsonify({'error': 'Could not retrieve related posts'}), 500

@app.route('/api/posts/<post_id>/status')
def get_post_status(post_id):
    """Returns the processing status and media URLs for a given post."""
    try:
        post = posts_conf.find_one(
            {'_id': ObjectId(post_id)},
            {
                'status': 1,
                'image_urls': 1,
                'video_url': 1,
                'image_status': 1,
                'video_status': 1,
                'title': 1 # For alt text
            }
        )
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Convert ObjectId to string for JSON serialization
        post['_id'] = str(post['_id'])

        return jsonify(post)
    except Exception as e:
        app.logger.error(f"Error fetching status for post {post_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/create_post', methods=['GET'])
@login_required
def create_post():
    """Renders the page for creating a new post."""
    page_title = "Create a New Post - EchoWithin"
    page_description = "Share your ideas, experiences, and perspectives with the EchoWithin community."
    return render_template("create_post.html", active_page='blog', title=page_title, description=page_description)

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
                        # Overwrite temp file with optimized version
                        if im.mode in ("RGBA", "LA"):
                            # Preserve transparency for formats that support it
                            im.save(path, format=im_format, optimize=True)
                        else:
                            # Save as JPEG-like optimization when possible
                            im = im.convert('RGB')
                            im.save(path, format='JPEG', quality=85, optimize=True)
                except Exception as ie:
                    app.logger.debug(f"Image resize/optimize skipped for {path}: {ie}")

                upload_result = cloudinary.uploader.upload(path, folder="echowithin_posts")
                url = upload_result.get('secure_url')
                pid = upload_result.get('public_id')
                if url: image_urls.append(url)
                if pid: image_public_ids.append(pid)
            except Exception as e:
                app.logger.error(f"Cloudinary image upload failed for {path} in job for post {post_id_str}: {e}")

        # 2. Upload Video
        if temp_video_path:
            try:
                upload_result = cloudinary.uploader.upload(temp_video_path, resource_type='video', folder='echowithin_posts')
                video_url = upload_result.get('secure_url')
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

        # Index post into Meilisearch after media processing so image fields are present
        try:
            if meili_index:
                # Index synchronously here (it's quick); if you prefer, enqueue an RQ job instead
                index_post_to_meili(post_id_str)
                app.logger.info(f"Indexed post {post_id_str} to Meilisearch after media processing")
        except Exception as e:
            app.logger.error(f"Failed to index post {post_id_str} after media processing: {e}")

        # 4. Trigger subsequent jobs (NSFW check, notifications)
        if image_urls:
            try:
                # Check the first image for NSFW content
                process_image_for_nsfw.queue(post_id_str, image_urls[0], image_public_ids[0])
                app.logger.info(f"Enqueued NSFW check job for post {post_id_str}")
            except redis.exceptions.ConnectionError as e:
                app.logger.warning(f"Redis connection failed. Falling back to thread for NSFW check. Error: {e}")
                with app.app_context():
                    ThreadPoolExecutor().submit(process_image_for_nsfw, post_id_str, image_urls[0], image_public_ids[0])
            except Exception as e:
                app.logger.error(f"Failed to enqueue NSFW job for post {post_id_str}: {e}")

        try:
            send_new_post_notifications.queue(post_id_str)
            app.logger.info(f"Enqueued notification job for post {post_id_str}")
        except redis.exceptions.ConnectionError as e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for notifications. Error: {e}")
            with app.app_context():
                ThreadPoolExecutor().submit(send_new_post_notifications, post_id_str)
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

@app.route("/post", methods=['POST', 'GET'])
@login_required
def post():
    if request.method=="POST":
        title=request.form.get("title")
        content=request.form.get("content")
        tags = request.form.getlist("tags") # Use getlist for multi-select
        # Support multiple image uploads from the form input named 'images'
        images_files = request.files.getlist('images') if request.files else []
        # Support image alt texts via form input `image_alts[]` (optional)
        image_alts = request.form.getlist('image_alts') if request.form else []
        video_file = request.files.get('video')

        temp_image_paths = []
        temp_video_path = None

        if title and content:  
            # Create a unique slug for SEO-friendly URLs
            base_slug = slugify(title)
            slug = base_slug
            counter = 1
            while posts_conf.find_one({'slug': slug}):
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            # Save files temporarily for background processing
            for img_file in images_files:
                if img_file and img_file.filename and '.' in img_file.filename and img_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                    filename = secure_filename(f"{secrets.token_hex(8)}-{img_file.filename}")
                    path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], filename)
                    img_file.save(path)
                    temp_image_paths.append(path)

            if video_file and video_file.filename and '.' in video_file.filename and video_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS:
                try:
                    stream = video_file.stream
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    stream.seek(0)
                    if size <= MAX_VIDEO_SIZE:
                        filename = secure_filename(f"{secrets.token_hex(8)}-{video_file.filename}")
                        path = os.path.join(app.config['TEMP_UPLOAD_FOLDER'], filename)
                        video_file.save(path)
                        temp_video_path = path
                except Exception: pass # Fail silently on size check error

            # Ensure we have an image_alts list matching any images (fill placeholders if missing)
            normalized_alts = []
            for i in range(len(images_files)):
                try:
                    alt = image_alts[i].strip()
                except Exception:
                    alt = ''
                if not alt:
                    alt = f"{title} image {i+1}"
                normalized_alts.append(alt)

            new_post_data = {
                'author_id': ObjectId(current_user.id),
                'slug': slug,
                'title': title,
                'content': content,
                'tags': tags,
                'author': current_user.username,
                'status': 'processing_media' if temp_image_paths or temp_video_path else 'published',
                'view_count': 0, # Initialize view count
                'timestamp': datetime.datetime.now(datetime.timezone.utc),
                'image_alts': normalized_alts,
            }
            result = posts_conf.insert_one(new_post_data)
            post_id_str = str(result.inserted_id)

            # Enqueue the media processing job if there are files
            if temp_image_paths or temp_video_path:
                try:
                    process_post_media.queue(post_id_str, temp_image_paths, temp_video_path)
                    app.logger.info(f"Enqueued media processing job for post {post_id_str}")
                except redis.exceptions.ConnectionError as e:
                    app.logger.warning(f"Redis connection failed. Falling back to thread for media processing. Error: {e}")
                    # Fallback: Run the job in a background thread
                    with app.app_context():
                        ThreadPoolExecutor().submit(process_post_media, post_id_str, temp_image_paths, temp_video_path)
                except Exception as e: # Catch other potential errors
                    app.logger.error(f"Failed to process media for post {post_id_str}: {e}")
                    # If enqueuing fails for a non-connection reason, delete the post to avoid orphans
                    posts_conf.delete_one({'_id': ObjectId(post_id_str)})
                    flash("Could not create post due to a server issue. Please try again.", "danger")
                    return redirect(url_for("blog"))
            else: # If no media, enqueue notifications directly
                try:
                    send_new_post_notifications.queue(post_id_str)
                    app.logger.info(f"Enqueued notification job for post {post_id_str}")
                except redis.exceptions.ConnectionError as e:
                    app.logger.warning(f"Redis connection failed. Falling back to thread for notifications. Error: {e}")
                    with app.app_context():
                        ThreadPoolExecutor().submit(send_new_post_notifications, post_id_str)
                except Exception as e:
                    app.logger.error(f"Failed to enqueue notification job for post {post_id_str}: {e}")
                # If no media, index immediately
                try:
                    if meili_index:
                        index_post_to_meili(post_id_str)
                except Exception as e:
                    app.logger.debug(f"Meili index skipped for {post_id_str}: {e}")

            # --- Send ntfy notification for new post ---
            try:
                ntfy_message = f"\"{title}\" by {current_user.username}"
                send_ntfy_notification.queue(ntfy_message, "New Post Created", "tada")
            except redis.exceptions.ConnectionError as e:
                app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {e}")
                with app.app_context():
                    ThreadPoolExecutor().submit(send_ntfy_notification, ntfy_message, "New Post Created", "tada")
            except Exception as e:
                app.logger.error(f"Failed to enqueue ntfy notification for new post: {e}")

            flash("Post created successfully!", "success")
        else:
            flash("Title and content cannot be empty.", "danger")
    return redirect(url_for("blog"))
    
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serves locally uploaded files for backward compatibility."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/post/<slug>')
def view_post(slug):
    post = posts_conf.find_one({'slug': slug})
    if not post:
        flash("Post not found.", "danger")
        return redirect(url_for('blog'))

    # Convert post content from Markdown to HTML
    # The 'fenced_code' extension is crucial for handling code blocks (```)
    # The 'nl2br' extension converts newlines to <br> tags, preserving line breaks.
    post['content'] = markdown.markdown(post.get('content', ''), extensions=['fenced_code', 'nl2br'])

    # --- Fetch Related Posts using Meilisearch ---
    related_posts = []
    if meili_index:
        try:
            # Enhanced Related Posts Logic:
            # Search for posts with similar tags and title, then filter out the current post.
            post_id_str = str(post['_id'])
            search_query = post.get('title', '')
            search_params = {
                'limit': 4, # Fetch 4 to have a buffer in case the original post is in the results
                'filter': f'id != {post_id_str}' # Exclude the current post from results
            }

            # If the post has tags, add them to the search query for better relevance.
            if post.get('tags'):
                tags_str = " ".join(post.get('tags'))
                search_query = f"{tags_str} {search_query}"

            search_result = meili_index.search(search_query, search_params)
            hits = search_result.get('hits', [])
            # Since we filtered in the query, we can just take the top 3 hits.
            related_posts = hits[:3]

            # Convert timestamp back to a datetime object for use in the template.
            for p in related_posts:
                if p.get('created_at'):
                    p['created_at'] = datetime.datetime.fromtimestamp(p['created_at'], tz=datetime.timezone.utc)
        except Exception as e:
            app.logger.error(f"Failed to get similar posts for {post_id_str}: {e}")

    # Add comment count and fetch recent comments
    try:
        comment_count = comments_conf.count_documents({'post_slug': slug, 'is_deleted': False})
        # Pagination: load first page of comments for server-render
        comment_page = 1
        per_page = 10
        # Load visible comments for this page (not deleted)
        comments = list(comments_conf.find({'post_slug': slug, 'is_deleted': False}).sort('created_at', 1).skip((comment_page-1)*per_page).limit(per_page))
        # Compute reply counts for the post (group by parent_id across the whole post)
        reply_counts = {}
        try:
            pipeline = [
                {'$match': {'post_slug': slug, 'is_deleted': False, 'parent_id': {'$ne': None}}},
                {'$group': {'_id': '$parent_id', 'count': {'$sum': 1}}}
            ]
            agg = list(comments_conf.aggregate(pipeline))
            for doc in agg:
                reply_counts[str(doc['_id'])] = doc.get('count', 0)
        except Exception as e:
            app.logger.debug(f"Failed to compute reply counts for post {slug}: {e}")

        # Ensure that if a visible comment refers to a deleted parent, we fetch that parent
        try:
            parent_ids = [c.get('parent_id') for c in comments if c.get('parent_id')]
            # parent_ids may be ObjectId instances; filter and fetch any missing parent docs
            missing_parent_ids = []
            if parent_ids:
                for pid in parent_ids:
                    # if parent not in our current comments list, we'll fetch it
                    if not any((str(c.get('_id')) == str(pid)) for c in comments):
                        missing_parent_ids.append(pid)
            if missing_parent_ids:
                parents = list(comments_conf.find({'_id': {'$in': missing_parent_ids}}))
                # Append parent placeholders so replies have their parent present in DOM
                # Avoid duplicates
                existing_ids = set(str(c.get('_id')) for c in comments)
                for p in parents:
                    if str(p.get('_id')) not in existing_ids:
                        comments.append(p)
                # Keep comments ordered by created_at
                comments.sort(key=lambda x: x.get('created_at') or datetime.datetime.min)
        except Exception as e:
            app.logger.debug(f"Failed to fetch missing parent comments for post {slug}: {e}")
        has_more = comment_count > comment_page * per_page
    except Exception as e:
        app.logger.error(f"Failed to load comments for post {slug}: {e}")
        comment_count = 0
        comments = []
        comment_page = 1
        per_page = 10
        has_more = False

    page_title = post.get('title', 'View Post')
    page_description = (post.get('content', '')[:155] + '...') if len(post.get('content', '')) > 155 else post.get('content', '')

    is_saved = False
    if current_user.is_authenticated:
        u = users_conf.find_one({'_id': ObjectId(current_user.id)}, {'saved_posts': 1})
        if u and post['_id'] in u.get('saved_posts', []):
            is_saved = True

    # Prepare SEO meta fields
    meta_url = url_for('view_post', slug=slug, _external=True)
    meta_image = None
    if post.get('image_urls'):
        meta_image = post.get('image_urls')[0]
    elif post.get('image_url'):
        meta_image = post.get('image_url')

    # JSON-LD structured data for the post
    try:
        jsonld = {
            "@context": "https://schema.org",
            "@type": "BlogPosting",
            "headline": post.get('title'),
            "image": [meta_image] if meta_image else [],
            "author": {
                "@type": "Person",
                "name": post.get('author')
            },
            "datePublished": post.get('timestamp').isoformat() if post.get('timestamp') else None,
            "url": meta_url,
            "description": page_description
        }
        jsonld_str = json.dumps(jsonld)
    except Exception:
        jsonld_str = ''

    return render_template('view_post.html', post=post, comments=comments, comment_count=comment_count, comment_page=comment_page, per_page=per_page, has_more=has_more, active_page='blog', title=page_title, description=page_description, reply_counts=reply_counts, meta_image=meta_image, meta_url=meta_url, meta_jsonld=jsonld_str, related_posts=related_posts, is_saved=is_saved)


@app.route('/api/posts/<post_id>/view', methods=['POST'])
def api_record_post_view(post_id):
    """Increment the view count for a post once per user per day.

    This endpoint is intended to be called by client-side JS when a user first
    visits the view_post page. It ensures that each user only increments the 
    view count once per day, regardless of how they arrive at the post (clicking title,
    comment button, or direct access).
    """
    try:
        # If user is not authenticated, use a guest identifier
        user_identifier = str(current_user.id) if current_user.is_authenticated else request.remote_addr
        
        # Get today's date at midnight (start of day)
        now = datetime.datetime.now()
        today_start = datetime.datetime(now.year, now.month, now.day)
        today_end = today_start + datetime.timedelta(days=1)
        
        # Check if this user has already viewed this post today
        view_record = logs_conf.find_one({
            'type': 'post_view',
            'post_id': ObjectId(post_id),
            'user_identifier': user_identifier,
            'timestamp': {'$gte': today_start, '$lt': today_end}
        })
        
        # Only increment if they haven't viewed it today
        if not view_record:
            # Record the view in logs
            logs_conf.insert_one({
                'type': 'post_view',
                'post_id': ObjectId(post_id),
                'user_identifier': user_identifier,
                'timestamp': datetime.datetime.now()
            })
            
            # Atomically increment the view count on the post
            res = posts_conf.update_one({'_id': ObjectId(post_id)}, {'$inc': {'view_count': 1}})
        
        # Fetch the latest count
        post = posts_conf.find_one({'_id': ObjectId(post_id)}, {'view_count': 1})
        view_count = post.get('view_count', 0) if post else 0
        return jsonify({'success': True, 'view_count': view_count})
    except Exception as e:
        app.logger.error(f"Failed to record view for post {post_id}: {e}")
        return jsonify({'success': False, 'error': 'Failed to record view'}), 500


def _serialize_comment(doc):
    return {
        'id': str(doc.get('_id')),
        'post_slug': doc.get('post_slug'),
        'author_id': str(doc.get('author_id')) if doc.get('author_id') else None,
        'author_username': doc.get('author_username'),
        'content': doc.get('content'),
        'created_at': doc.get('created_at').isoformat() if doc.get('created_at') else None,
        'edited_at': doc.get('edited_at').isoformat() if doc.get('edited_at') else None,
        'is_deleted': doc.get('is_deleted', False),
        'parent_id': str(doc.get('parent_id')) if doc.get('parent_id') else None,
    }


@app.route('/api/posts/<slug>/comments', methods=['GET', 'POST'])
def api_post_comments(slug):
    if request.method == 'GET':
        try:
            # Pagination support
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            if per_page <= 0: per_page = 10
            if page <= 0: page = 1

            total = comments_conf.count_documents({'post_slug': slug, 'is_deleted': False})
            cursor = comments_conf.find({'post_slug': slug, 'is_deleted': False}).sort('created_at', 1).skip((page-1)*per_page).limit(per_page)
            comments = [ _serialize_comment(c) for c in cursor ]
            has_more = total > page * per_page
            return jsonify({'comments': comments, 'total': total, 'page': page, 'per_page': per_page, 'has_more': has_more})
        except Exception as e:
            app.logger.error(f"Failed to list comments for {slug}: {e}")
            return jsonify({'error': 'Could not retrieve comments'}), 500

    # POST -> create new comment
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401

    content = request.form.get('content') or (request.json and request.json.get('content'))
    parent_id_str = request.form.get('parent_id') or (request.json and request.json.get('parent_id'))
    # Attach parent_id if provided (replying to a comment)
    if not content or not content.strip():
        return jsonify({'error': 'Empty comment'}), 400

    comment = {
        'post_slug': slug,
        'post_id': None,
        'author_id': ObjectId(current_user.id),
        'author_username': current_user.username,
        'content': content.strip(),
        'created_at': datetime.datetime.now(),
        'is_deleted': False,
        'parent_id': None,
    }
    # Fill in parent_id if provided
    if parent_id_str:
        try:
            comment['parent_id'] = ObjectId(parent_id_str)
        except Exception:
            comment['parent_id'] = None

    # Fill post_id for easier querying
    try:
        p = posts_conf.find_one({'slug': slug}, {'_id': 1})
        if p:
            comment['post_id'] = p.get('_id')
    except Exception:
        pass
    try:
        res = comments_conf.insert_one(comment)
        comment['_id'] = res.inserted_id
        # Invalidate cached comment counts so lists update immediately
        try:
            comment_count_cache.clear()
        except Exception:
            pass
        return jsonify(_serialize_comment(comment)), 201
    except Exception as e:
        app.logger.error(f"Failed to insert comment for {slug}: {e}")
        return jsonify({'error': 'Failed to create comment'}), 500


@app.route('/api/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_comment(comment_id):
    try:
        comment = comments_conf.find_one({'_id': ObjectId(comment_id)})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Allow deletion by author or admin
        if str(comment.get('author_id')) != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Not authorized'}), 403

        # Check if the comment has replies
        has_replies = comments_conf.count_documents({'parent_id': ObjectId(comment_id), 'is_deleted': False}) > 0

        if has_replies:
            # Soft-delete: keep the comment as a placeholder for replies, but clear its content.
            comments_conf.update_one(
                {'_id': ObjectId(comment_id)},
                {'$set': {
                    'is_deleted': True,
                    'content': '[deleted]',
                    'author_username': '[deleted]'
                }}
            )
        else:
            # Hard-delete: no replies, so we can remove it completely.
            comments_conf.delete_one({'_id': ObjectId(comment_id)})

        try:
            comment_count_cache.clear()
        except Exception:
            pass
        return jsonify({'status': 'deleted'})
    except Exception as e:
        app.logger.error(f"Failed to delete comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to delete comment'}), 500


@app.route('/api/comments/<comment_id>', methods=['PUT', 'PATCH'])
@login_required
def api_edit_comment(comment_id):
    """Edit a comment. Only the author or an admin may edit."""
    content = None
    if request.json:
        content = request.json.get('content')
    else:
        content = request.form.get('content')

    if not content or not content.strip():
        return jsonify({'error': 'Empty content'}), 400

    try:
        comment = comments_conf.find_one({'_id': ObjectId(comment_id)})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Permission: author or admin
        if str(comment.get('author_id')) != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Not authorized'}), 403

        comments_conf.update_one({'_id': ObjectId(comment_id)}, {'$set': {'content': content.strip(), 'edited_at': datetime.datetime.now()}})
        updated = comments_conf.find_one({'_id': ObjectId(comment_id)})
        try:
            comment_count_cache.clear()
        except Exception:
            pass
        return jsonify(_serialize_comment(updated))
    except Exception as e:
        app.logger.error(f"Failed to edit comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to edit comment'}), 500

@app.route('/edit_post/<post_id>', methods=['GET'])
@app.route('/api/comments/<comment_id>/vote', methods=['POST'])
@login_required
def api_vote_comment(comment_id):
    """Upvote or remove an upvote from a comment."""
    try:
        user_id = ObjectId(current_user.id)
        comment_oid = ObjectId(comment_id)

        # Find the comment to ensure it exists
        comment = comments_conf.find_one({'_id': comment_oid}, {'author_id': 1, 'upvoted_by': 1})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Users cannot vote on their own comments
        if comment.get('author_id') == user_id:
            return jsonify({'error': 'You cannot vote on your own comment'}), 403

        # Check if the user has already upvoted this comment
        is_already_voted = user_id in (comment.get('upvoted_by') or [])

        if is_already_voted:
            # Remove the upvote (un-vote)
            update_result = comments_conf.update_one(
                {'_id': comment_oid},
                {'$pull': {'upvoted_by': user_id}, '$inc': {'upvote_count': -1}}
            )
        else:
            # Add the upvote
            update_result = comments_conf.update_one(
                {'_id': comment_oid},
                {'$addToSet': {'upvoted_by': user_id}, '$inc': {'upvote_count': 1}}
            )

        new_count = comments_conf.find_one({'_id': comment_oid}, {'upvote_count': 1}).get('upvote_count', 0)
        return jsonify({'status': 'success', 'upvote_count': new_count, 'voted': not is_already_voted})
    except Exception as e:
        app.logger.error(f"Failed to vote on comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to process vote'}), 500

@app.route('/edit_post/<post_id>', methods=['GET'])
@login_required
@owner_required
def edit_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    action = request.args.get('action')

    # The decorator handles the ownership check.
    # We only need to check if the action is 'edit'.
    if action != 'edit':
        return redirect(url_for('view_post', slug=post.get('slug')))

    page_title = f"Edit: {post.get('title')}"
    page_description = f"Edit the post titled '{post.get('title')}' on EchoWithin."
    
    return render_template('edit_post.html', post=post, active_page='blog', 
                           action=action, title=page_title, description=page_description,
                           )

@app.route('/update_post/<post_id>', methods=['POST'])
@login_required
@owner_required
def update_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    title = request.form.get("title")
    content = request.form.get("content")
    tags = request.form.getlist("tags") # Use getlist for multi-select
    # Support multiple images on update via 'images' input
    images_files = request.files.getlist('images') if request.files else []
    video_file = request.files.get('video')
    image_url = post.get('image_url') # Keep old image by default
    image_public_id = post.get('image_public_id')
    image_urls = post.get('image_urls', []) if post else []
    image_public_ids = post.get('image_public_ids', []) if post else []
    video_url = post.get('video_url')
    video_public_id = post.get('video_public_id')
    slug = post.get('slug') # Keep old slug by default
    image_status = post.get('image_status', 'none')
    video_status = post.get('video_status', 'none')

    if title and content:
        # Handle image replacement
        # If new images were provided, replace existing images (delete old public_ids and upload new ones)
        if images_files and any(f and f.filename for f in images_files):
            try:
                # Delete old images from Cloudinary if exists (support list or single)
                old_publics = []
                if isinstance(image_public_id, list):
                    old_publics = image_public_id
                elif image_public_id:
                    old_publics = [image_public_id]
                elif image_public_ids:
                    old_publics = image_public_ids
                for pid in old_publics:
                    try:
                        cloudinary.uploader.destroy(pid)
                    except Exception:
                        app.logger.debug(f"Failed to delete old Cloudinary image {pid}")

                # Upload new images
                new_urls = []
                new_publics = []
                for img_file in images_files:
                    if not img_file or not img_file.filename:
                        continue
                    if '.' not in img_file.filename:
                        continue
                    ext = img_file.filename.rsplit('.', 1)[1].lower()
                    if ext not in ALLOWED_IMAGE_EXTENSIONS:
                        continue
                    upload_result = cloudinary.uploader.upload(img_file, folder="echowithin_posts")
                    url = upload_result.get('secure_url')
                    pid = upload_result.get('public_id')
                    if url:
                        new_urls.append(url)
                    if pid:
                        new_publics.append(pid)

                # Update the variables used to save back to DB
                if new_urls:
                    image_urls = new_urls
                    image_url = new_urls[0]
                if new_publics:
                    image_public_ids = new_publics
                    image_public_id = new_publics[0]
                image_status = 'safe'
                # Enqueue NSFW check for each new image (fire-and-forget)
                try:
                    for url, pid in zip(new_urls, new_publics):
                        process_image_for_nsfw.queue(post_id, url, pid)
                except Exception as e:
                    app.logger.debug(f"Failed to enqueue NSFW checks for updated images: {e}")
            except Exception as e:
                # --- Send ntfy notification for NSFW content ---
                try:
                    message = f"NSFW content detected in post '{post.get('title')}' by {post.get('author')}. Image has been flagged."
                    send_ntfy_notification.queue(message, "NSFW Content Detected", "see_no_evil")
                except redis.exceptions.ConnectionError as ntfy_e:
                    app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {ntfy_e}")
                    with app.app_context():
                        ThreadPoolExecutor().submit(send_ntfy_notification, message, "NSFW Content Detected", "see_no_evil")
                except Exception as ntfy_e:
                    app.logger.error(f"Failed to enqueue ntfy notification for NSFW content: {ntfy_e}")

                app.logger.error(f"Cloudinary upload/delete failed during update: {e}")

        # Handle video replacement
        if video_file and video_file.filename != '' and '.' in video_file.filename:
            video_ext = video_file.filename.rsplit('.', 1)[1].lower()
            if video_ext not in ALLOWED_VIDEO_EXTENSIONS:
                flash('Unsupported video format. Allowed: mp4, webm, ogg, mov', 'danger')
                return redirect(url_for('view_post', slug=slug))
            try:
                # Determine size
                stream = video_file.stream
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(0)
            except Exception:
                size = None

            if size is not None and size > MAX_VIDEO_SIZE:
                flash('Video exceeds maximum allowed size of 10 MB.', 'danger')
                return redirect(url_for('view_post', slug=slug))

            try:
                # Delete old video if exists
                if video_public_id:
                    cloudinary.uploader.destroy(video_public_id, resource_type='video')

                upload_result = cloudinary.uploader.upload(video_file, resource_type='video', folder='echowithin_posts')
                video_url = upload_result.get('secure_url')
                video_public_id = upload_result.get('public_id')
                video_status = 'uploaded'
            except Exception as e:
                app.logger.error(f"Cloudinary video upload/delete failed during update: {e}")

        # If the title has changed, generate a new slug
        if title != post.get('title'):
            base_slug = slugify(title)
            new_slug = base_slug
            counter = 1
            # Ensure the new slug is unique
            while posts_conf.find_one({'slug': new_slug, '_id': {'$ne': post['_id']}}):
                new_slug = f"{base_slug}-{counter}"
                counter += 1
            slug = new_slug

        posts_conf.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {
                'title': title,
                'content': content,
                'tags': tags,
                'image_url': image_url,
                'image_public_id': image_public_id,
                'image_urls': image_urls,
                'image_public_ids': image_public_ids,
                'image_status': image_status,
                'video_url': video_url,
                'video_public_id': video_public_id,
                'video_status': video_status,
                'slug': slug,
                'edited_at': datetime.datetime.now(),
            }}
        )
        # Re-index the post in Meilisearch to reflect the changes
        try:
            if meili_index:
                index_post_to_meili(post_id)
        except Exception as e:
            app.logger.error(f"Failed to re-index post {post_id} after update: {e}")
        flash("Post updated successfully!", "success")
        return redirect(url_for('blog', slug=slug))
    else:
        flash("Title and content cannot be empty.", "danger")
    return redirect(url_for('view_post', slug=slug))

@app.route('/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post_to_delete = posts_conf.find_one({'_id': ObjectId(post_id)})

    # Explicitly check for ownership before deleting
    if not post_to_delete or str(post_to_delete.get('author_id')) != current_user.id:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('blog'))
    
    # Delete the image from Cloudinary if it exists
    if post_to_delete.get('image_public_id'):
        try:
            cloudinary.uploader.destroy(post_to_delete['image_public_id'])
        except Exception as e:
            app.logger.error(f"Failed to delete Cloudinary image {post_to_delete.get('image_public_id')}: {e}")

    # Delete the video from Cloudinary if it exists
    if post_to_delete.get('video_public_id'):
        try:
            cloudinary.uploader.destroy(post_to_delete['video_public_id'], resource_type='video')
        except Exception as e:
            app.logger.error(f"Failed to delete Cloudinary video {post_to_delete.get('video_public_id')}: {e}")

    posts_conf.delete_one({'_id': ObjectId(post_id)})

    flash('Post deleted successfully.', 'success')
    return redirect(url_for('blog'))

@app.route('/admin/posts')
@login_required
@admin_required
def admin_posts():
    query = request.args.get('query')
    # Pagination logic
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10 # Show more posts on admin page

    if query:
        search_filter = {'$text': {'$search': query}}
        total_posts = posts_conf.count_documents(search_filter)
    else:
        search_filter = {}
        total_posts = posts_conf.count_documents(search_filter)

    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page

    # Fetch posts and prepare them with comment counts
    posts_cursor = posts_conf.find(search_filter).sort('timestamp', -1).skip(skip).limit(posts_per_page)
    with app.app_context():
        posts = prepare_posts(list(posts_cursor))

    return render_template("admin_posts.html", posts=posts, active_page='admin_posts', page=page, total_pages=total_pages, query=query)

@app.route('/admin/delete_post/<post_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_post(post_id):
    try:
        post_to_delete = posts_conf.find_one({'_id': ObjectId(post_id)})
        if post_to_delete:
            if post_to_delete.get('image_public_id'):
                try:
                    cloudinary.uploader.destroy(post_to_delete['image_public_id'])
                except Exception as e:
                    app.logger.error(f"Admin failed to delete Cloudinary image {post_to_delete.get('image_public_id')}: {e}")
            if post_to_delete.get('video_public_id'):
                try:
                    cloudinary.uploader.destroy(post_to_delete.get('video_public_id'), resource_type='video')
                except Exception as e:
                    app.logger.error(f"Admin failed to delete Cloudinary video {post_to_delete.get('video_public_id')}: {e}")
        result = posts_conf.delete_one({'_id': ObjectId(post_id)})

        if result.deleted_count == 1:
            flash('Post deleted successfully by admin.', 'success')
        else:
            flash('Post not found.', 'warning')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    return redirect(url_for('admin_posts'))



@app.route('/admin/announcements', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_announcements():
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            announcements_conf.insert_one({
                'content': content,
                'author_id': ObjectId(current_user.id),
                'author_username': current_user.username,
                'created_at': datetime.datetime.now(),
                'is_pinned': False
            })
            flash('Announcement created successfully.', 'success')
        else:
            flash('Announcement content cannot be empty.', 'danger')
        return redirect(url_for('admin_announcements'))

    announcements = announcements_conf.find().sort('created_at', -1)
    return render_template('admin_announcements.html', announcements=announcements, active_page='admin_announcements')

@app.route('/admin/announcements/pin/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def pin_announcement(announcement_id):
    try:
        def _pin_transaction(session):
            # This logic runs as an atomic transaction.
            # 1. Unpin any currently pinned announcement.
            announcements_conf.update_many({'is_pinned': True}, {'$set': {'is_pinned': False}}, session=session)
            # 2. Pin the new one.
            announcements_conf.update_one({'_id': ObjectId(announcement_id)}, {'$set': {'is_pinned': True}}, session=session)

        # Start a client session for transaction
        with client.start_session() as session:
            session.with_transaction(_pin_transaction)
        flash('Announcement has been pinned.', 'success')
    except Exception as e:
        app.logger.error(f"Error pinning announcement {announcement_id}: {e}")
        flash('An error occurred while pinning the announcement.', 'danger')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/announcements/unpin/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def unpin_announcement(announcement_id):
    result = announcements_conf.update_one({'_id': ObjectId(announcement_id), 'is_pinned': True}, {'$set': {'is_pinned': False}})
    if result.modified_count > 0:
        flash('Announcement has been unpinned.', 'success')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/announcements/delete/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def delete_announcement(announcement_id):
    announcements_conf.delete_one({'_id': ObjectId(announcement_id)})
    flash('Announcement deleted.', 'success')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    query = request.args.get('query')
    if query:
        # Search for users by username or email (case-insensitive)
        # Using $regex for case-insensitivity in PyMongo
        users = users_conf.find({
            "$or": [
                {"username": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}}
            ]
        }).sort('username', 1)
    else:
        users = users_conf.find().sort('username', 1)
    
    return render_template('admin_users.html', title="Manage Users", users=list(users), query=query)

@app.route('/admin/users/ban/<user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    user_to_ban = users_conf.find_one({'_id': ObjectId(user_id)})
    if not user_to_ban:
        abort(404)
    if str(user_to_ban['_id']) == current_user.id:
        flash("You cannot ban yourself.", "danger")
        return redirect(url_for('admin_users'))
    
    users_conf.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_banned': True}})
    flash(f"User '{user_to_ban.get('username')}' has been banned.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/unban/<user_id>', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    user_to_unban = users_conf.find_one({'_id': ObjectId(user_id)})
    if not user_to_unban:
        abort(404)
    users_conf.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_banned': False}})
    flash(f"User '{user_to_unban.get('username')}' has been unbanned.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = users_conf.find_one({'_id': ObjectId(user_id)})
    if not user_to_delete:
        abort(404)
    if str(user_to_delete['_id']) == current_user.id:
        flash("You cannot delete yourself.", "danger")
        return redirect(url_for('admin_users'))
    
    # Also delete all posts by this user
    posts_conf.delete_many({'author_id': ObjectId(user_id)})
    
    username = user_to_delete.get('username')
    users_conf.delete_one({'_id': ObjectId(user_id)})
    
    flash(f"User '{username}' and all their posts have been permanently deleted.", "success")
    return redirect(url_for('admin_users'))

@app.route('/about')
def about():
    page_title = "About EchoWithin"
    page_description = "Learn more about EchoWithin, our mission, and the team behind the platform."
    return render_template("about.html", title=page_title, description=page_description)


@app.route('/terms')
def terms():
    page_title = "Terms and Conditions"
    page_description = "Terms and Conditions for using EchoWithin."
    return render_template('terms.html', title=page_title, description=page_description)

@app.route('/profile/<username>')
def profile(username):
    # Find the user by username
    user = users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    # --- Pagination for user posts ---
    page = request.args.get('page', 1, type=int)
    posts_per_page = 5 # Or another number
    filter_query = {'author_id': user['_id']}

    total_posts = posts_conf.count_documents(filter_query)
    total_comments = comments_conf.count_documents({'author_id': user['_id'], 'is_deleted': False})
    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page

    # Find posts by this user's ID with pagination
    user_posts_cursor = posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page)
    with app.app_context():
        user_posts = prepare_posts(list(user_posts_cursor))

    page_title = f"Profile: {user['username']}"
    page_description = f"View the profile and posts by {user['username']} on EchoWithin."

    return render_template('profile.html',
                           user=user,
                           user_posts=user_posts,
                           title=page_title,
                           description=page_description,
                           active_page='profile',
                           page=page,
                           total_pages=total_pages,
                           total_posts=total_posts,
                           total_comments=total_comments)


@app.route('/profile/<username>/settings', methods=['GET', 'POST'])
@login_required
def profile_settings(username):
    # Only allow users to access their own settings
    if username != current_user.username:
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for('home'))

    user = users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        update_data = {}

        # Update bio
        update_data['bio'] = request.form.get('bio', '').strip()

        # Handle profile picture removal
        if request.form.get('remove_profile_picture'):
            if user.get('profile_image_public_id'):
                try:
                    # Delete old profile image from Cloudinary
                    cloudinary.uploader.destroy(user['profile_image_public_id'], resource_type="image")
                except Exception as e:
                    app.logger.error(f"Cloudinary avatar deletion failed for user {username}: {e}")
            
            # Unset the fields in the database
            update_data['profile_image_url'] = None
            update_data['profile_image_public_id'] = None


        # Handle profile image upload
        profile_image_file = request.files.get('profile_image')
        if profile_image_file and profile_image_file.filename:
            if '.' in profile_image_file.filename and profile_image_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                try:
                    # Delete old profile image from Cloudinary if it exists
                    if user.get('profile_image_public_id') and not request.form.get('remove_profile_picture'):
                        cloudinary.uploader.destroy(user['profile_image_public_id'], resource_type="image")

                    # Upload new image
                    upload_result = cloudinary.uploader.upload(profile_image_file, folder="echowithin_avatars")
                    update_data['profile_image_url'] = upload_result.get('secure_url')
                    update_data['profile_image_public_id'] = upload_result.get('public_id')
                except Exception as e:
                    app.logger.error(f"Cloudinary avatar upload failed for user {username}: {e}")
                    flash("There was an error uploading your profile picture.", "danger")
            else:
                flash("Invalid image format. Please use png, jpg, jpeg, or gif.", "danger")

        # Handle notification preference
        notify_val = request.form.get('notify_new_posts')
        update_data['notify_new_posts'] = True if notify_val in ('1', 'true', 'on') else False

        if update_data:
            try:
                users_conf.update_one({'_id': user['_id']}, {'$set': update_data})
                flash('Settings updated successfully!', 'success')
            except Exception as e:
                app.logger.error(f"Failed to update settings for {username}: {e}")
                flash('Failed to update settings. Please try again later.', 'danger')

        # Redirect back to the settings page to see the changes
        return redirect(url_for('profile_settings', username=username))

    # For GET, render settings page
    return render_template('profile_settings.html', user=user, active_page='profile', title=f"Settings - {user.get('username')}")

@app.route('/personal_space')
@login_required
def personal_space():
    """Renders the user's personal space with saved posts and personal notes."""
    user = users_conf.find_one({'_id': ObjectId(current_user.id)})
    
    # Fetch saved posts
    saved_post_ids = user.get('saved_posts', [])
    saved_posts = []
    if saved_post_ids:
        # Filter out any IDs that might not exist anymore
        saved_posts_cursor = posts_conf.find({'_id': {'$in': saved_post_ids}})
        saved_posts = list(saved_posts_cursor)
        with app.app_context():
            saved_posts = prepare_posts(saved_posts)
            
    # Fetch personal posts (notes)
    personal_posts = list(personal_posts_conf.find({'user_id': ObjectId(current_user.id)}).sort('created_at', -1))
    
    page_title = "My Personal Space"
    page_description = "Your private collection of saved posts and personal notes."
    
    return render_template('personal_space.html', saved_posts=saved_posts, personal_posts=personal_posts, active_page='personal_space', title=page_title, description=page_description)

@app.route('/post/<post_id>/toggle_save', methods=['POST'])
@login_required
def toggle_save_post(post_id):
    """Toggles the saved status of a post for the current user."""
    try:
        post_oid = ObjectId(post_id)
        post = posts_conf.find_one({'_id': post_oid})
        if not post:
            if request.is_json:
                return jsonify({'error': 'Post not found'}), 404
            flash('Post not found.', 'danger')
            return redirect(url_for('home'))
            
        user_id = ObjectId(current_user.id)
        user = users_conf.find_one({'_id': user_id})
        saved_posts = user.get('saved_posts', [])
        
        is_saved = False
        if post_oid in saved_posts:
            users_conf.update_one({'_id': user_id}, {'$pull': {'saved_posts': post_oid}})
            is_saved = False
        else:
            users_conf.update_one({'_id': user_id}, {'$addToSet': {'saved_posts': post_oid}})
            is_saved = True
            
        if request.is_json:
            return jsonify({'saved': is_saved})
            
        flash('Post saved!' if is_saved else 'Post removed from saved.', 'success')
        return redirect(request.referrer or url_for('view_post', slug=post['slug']))
    except Exception as e:
        app.logger.error(f"Error toggling save for post {post_id}: {e}")
        if request.is_json:
            return jsonify({'error': 'Internal error'}), 500
        flash('An error occurred.', 'danger')
        return redirect(url_for('home'))

@app.route('/personal_post/create', methods=['POST'])
@login_required
def create_personal_post():
    """Creates a new personal note/post."""
    content = request.form.get('content')
    if content and content.strip():
        personal_posts_conf.insert_one({
            'user_id': ObjectId(current_user.id),
            'content': content.strip(),
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })
        flash('Personal note added.', 'success')
    else:
        flash('Content cannot be empty.', 'danger')
    return redirect(url_for('personal_space'))

@app.route('/personal_post/delete/<post_id>', methods=['POST'])
@login_required
def delete_personal_post(post_id):
    """Deletes a personal note/post."""
    try:
        personal_posts_conf.delete_one({
            '_id': ObjectId(post_id),
            'user_id': ObjectId(current_user.id)
        })
        flash('Personal note deleted.', 'success')
    except Exception as e:
        app.logger.error(f"Error deleting personal post {post_id}: {e}")
        flash('Could not delete note.', 'danger')
    return redirect(url_for('personal_space'))

@app.route('/contact', methods=['POST'])
@limits(calls=5, period=60) 
def contact_developer():
    if request.method == 'POST':
        name = request.form.get('name')
        sender_email = request.form.get('email')
        subject = request.form.get('subject')
        message_body = request.form.get('message')

        if not all([name, sender_email, subject, message_body]):
            flash("Please fill out all fields in the contact form.", "danger")
            return redirect(url_for('about'))

        try:
            msg = Message(
                subject=f"EchoWithin Contact Form: {subject}",
                sender=get_env_variable('MAIL_USERNAME'), # Your app's email
                recipients=[get_env_variable('MY_EMAIL')] # Your personal email
            )
            # Set the reply-to header so you can reply directly to the user
            msg.reply_to = sender_email
            msg.body = f"You have a new message from {name} ({sender_email}):\n\n{message_body}"
            mail.send(msg)
            flash("Your message has been sent successfully. Thank you!", "success")
        except Exception as e:
            app.logger.error(f"Failed to send contact form email: {e}")
            flash("Sorry, there was an error sending your message. Please try again later.", "danger")
    return redirect(url_for('about'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limits(calls=5, period=TIME)
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            user = users_conf.find_one({'email': email})
            if user:
                reset_token = secrets.token_urlsafe(32)
                hashed_token = hashlib.sha256(reset_token.encode()).hexdigest()
                expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
                auth_conf.update_one(
                    {'email': email},
                    {'$set': {'reset_token': hashed_token, 'reset_expiry': expiry}},
                    upsert=True
                )
                send_reset_code(email, reset_token)
                flash("If an account with that email exists, we've sent you a password reset link.", "info")
            else:
                flash("If an account with that email exists, we've sent you a password reset link.", "info")
        else:
            flash("Please enter your email address.", "danger")
    return render_template('forgot_password.html', active_page='forgot_password')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limits(calls=10, period=TIME)
def reset_password(token):
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    auth_record = auth_conf.find_one({'reset_token': hashed_token})
    if not auth_record or auth_record.get('reset_expiry') < datetime.datetime.now():
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for('forgot_password'))

    # Get the user who is resetting their password
    user_to_update = users_conf.find_one({'email': auth_record['email']})

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if username and password and confirm_password:
            # Check if the new username is already taken by another user
            existing_user = users_conf.find_one({'username': username})
            if existing_user and existing_user['email'] != auth_record['email']:
                flash("That username is already taken. Please choose a different one.", "danger")
                return render_template('reset_password.html', token=token, active_page='reset_password')

            if password == confirm_password:
                hashed_password = generate_password_hash(password)
                users_conf.update_one(
                    {'email': auth_record['email']},
                    {'$set': {
                        'username': username,
                        'password': hashed_password
                    }}
                )
                # Also update username in all their posts
                posts_conf.update_many({'author_id': user_to_update['_id']}, {'$set': {'author': username}})
                auth_conf.delete_one({'reset_token': hashed_token})
                flash("Your password has been reset successfully. Please login.", "success")
                return redirect(url_for('login'))
            else:
                flash("Passwords do not match.", "danger")
        else:
            flash("Please fill in all fields.", "danger") # snyk:disable=security-issue
    return render_template('reset_password.html', token=token, active_page='reset_password', current_username=user_to_update.get('username'))

@app.route('/favicon.ico')
def favicon():
    """Serves the favicon."""
    favicon_path = os.path.join(app.root_path, 'static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    else:
        # If no favicon exists, return a 204 No Content response to prevent 404 errors in the log.
        return '', 204

@app.route('/logout')
def logout():
    logout_user() # Use Flask-Login to properly log the user out
    flash('You have been logged out.', 'info')
    return redirect(url_for('dashboard'))


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
                ThreadPoolExecutor().submit(send_ntfy_notification, f"A 500 error occurred on endpoint {request.path}. Check logs for details.", "Application Error (500)", "warning")
        except Exception as ntfy_e:
            app.logger.error(f"Failed to enqueue ntfy notification for 500 error: {ntfy_e}")
    except Exception as log_e:
        print(f"CRITICAL: Failed to log 500 error: {log_e}", file=sys.stderr)
    return render_template("500.html"), 500