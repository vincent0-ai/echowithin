import datetime
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash, make_response, send_from_directory
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

# Allow OAuthlib to work with insecure transport for local development.
# This MUST be removed in production.
#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from ratelimit import limits, RateLimitException
from dotenv import load_dotenv
import secrets
from jigsawstack import JigsawStack
import time
import requests
from werkzeug.utils import secure_filename
import hashlib
from slugify import slugify
import cloudinary
import cloudinary.uploader
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from requests_oauthlib import OAuth2Session
from werkzeug.middleware.proxy_fix import ProxyFix

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
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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

# Ensure a text index exists on the posts collection for search functionality
posts_conf.create_index([('title', 'text'), ('content', 'text')])

@app.template_filter('linkify')
def linkify_filter(text):
    """A Jinja2 filter to turn URLs in text into clickable links."""
    return bleach.linkify(text)


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
def redirect_www_to_non_www():
    """Redirects www requests to non-www to ensure canonical URLs."""
    if request.host.startswith('www.'):
        new_host = request.host.replace('www.', '', 1)
        new_url = request.url.replace(request.host, new_host, 1)
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
    ntfy_topic = get_env_variable('NTFY_TOPIC')
    if not ntfy_topic:
        app.logger.info("NTFY_TOPIC not set, skipping notification.")
        return

    try:
        headers = {}
        if title:
            headers['Title'] = title
        if tags:
            headers['Tags'] = tags

        requests.post(
            f"https://ntfy.sh/{ntfy_topic}",
            data=message.encode('utf-8'),
            headers=headers
        )
    except Exception as e:
        app.logger.error(f"Failed to send ntfy notification: {e}", exc_info=True)

@app.route('/register', methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        client_ip = request.remote_addr
        logs_conf.insert_one({
        'ip' : client_ip,
        'username': username,
        'timestamp' : datetime.datetime.now().strftime("%B %d, %Y %I:%M %p") 
        })
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
            except Exception as e:
                app.logger.error(f"Failed to enqueue ntfy notification for new user: {e}")

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
        
        client_ip = request.remote_addr
        logs_conf.insert_one({
        'ip' : client_ip,
        'username': username,
        'timestamp' : datetime.datetime.now().strftime("%B %d, %Y %I:%M %p") 
        })

        user = users_conf.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            if not user.get('is_confirmed'):
                flash('Please confirm your account first', "danger")
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
    return render_template("auth.html", active_page='login')

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
    # Recreate the session with the same redirect_uri to fetch the token
    google = OAuth2Session(
        GOOGLE_CLIENT_ID,
        state=session.get('oauth_state'),
        redirect_uri=url_for('google_callback', _external=True))
    token = google.fetch_token(
        'https://oauth2.googleapis.com/token',
        client_secret=GOOGLE_CLIENT_SECRET,
        authorization_response=request.url
    )
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

    # Fetch trending posts (e.g., 5 most recent posts)
    trending_posts = list(posts_conf.find({}).sort('timestamp', -1).limit(5))

    # Get Remark42 config for comment counters
    remark42_host = get_env_variable('REMARK42_HOST')
    remark42_site_id = get_env_variable('REMARK42_SITE_ID')
 
    return render_template("home.html", username=current_user.username, active_page='home', 
                           title=page_title, description=page_description,
                           total_members=total_members, total_posts=total_posts,
                           most_active_member=most_active_member, trending_posts=trending_posts, 
                           remark42_host=remark42_host, remark42_site_id=remark42_site_id)

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
        search_results = posts_conf.find(search_filter).sort('timestamp', -1).skip(skip).limit(posts_per_page)
        
        page_title = f"Search results for '{query}'"
        page_description = f"Displaying search results for '{query}' on EchoWithin."
        return render_template("blog.html", posts=search_results, active_page='blog', page=page, total_pages=total_pages, query=query, title=page_title, description=page_description)

    # --- Default Blog Page Logic (No Search) ---

    # 1. Fetch Latest Posts (sorted by creation/update time)
    latest_posts = list(posts_conf.find({}).sort('timestamp', -1).limit(5))

    page_title = "Blog - EchoWithin"
    page_description = "Explore the latest posts and discussions from the EchoWithin community."
    remark42_host = get_env_variable('REMARK42_HOST')
    remark42_site_id = get_env_variable('REMARK42_SITE_ID')
    return render_template("blog.html", latest_posts=latest_posts, active_page='blog', title=page_title, description=page_description, remark42_host=remark42_host, remark42_site_id=remark42_site_id)

@app.route("/blog/all")
@login_required
def all_posts():
    """Displays a paginated list of all blog posts."""
    page = request.args.get('page', 1, type=int)
    posts_per_page = 5

    total_posts = posts_conf.count_documents({})
    total_pages = math.ceil(total_posts / posts_per_page)

    skip = (page - 1) * posts_per_page

    # Fetch a slice of all posts for the current page, sorted by newest first
    posts = posts_conf.find({}).sort('timestamp', -1).skip(skip).limit(posts_per_page)

    page_title = "All Posts - EchoWithin"
    page_description = "Browse through all posts from the EchoWithin community."
    return render_template("all_posts.html", posts=posts, active_page='blog', page=page, total_pages=total_pages, title=page_title, description=page_description)


@app.route('/create_post', methods=['GET'])
@login_required
def create_post():
    """Renders the page for creating a new post."""
    page_title = "Create a New Post - EchoWithin"
    page_description = "Share your ideas, experiences, and perspectives with the EchoWithin community."
    return render_template("create_post.html", active_page='blog', title=page_title, description=page_description)


@app.route("/post", methods=['POST'])
@login_required
def post():
    if request.method=="POST":
        title=request.form.get("title")
        content=request.form.get("content")
        image_file = request.files.get('image')
        video_file = request.files.get('video')
        image_url = None
        image_public_id = None
        video_url = None
        video_public_id = None


        if title and content:  
            # Create a unique slug for SEO-friendly URLs
            base_slug = slugify(title)
            slug = base_slug
            counter = 1
            while posts_conf.find_one({'slug': slug}):
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            # Handle image upload
            if image_file and image_file.filename != '' and '.' in image_file.filename and \
               image_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
                try:
                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(image_file, folder="echowithin_posts")
                    image_url = upload_result.get('secure_url')
                    image_public_id = upload_result.get('public_id')
                except Exception as e:
                    app.logger.error(f"Cloudinary upload failed: {e}")
                    flash("There was an error uploading the image.", "danger")
                    return redirect(url_for("blog"))

            # Handle video upload (enforce extension and size limit)
            if video_file and video_file.filename != '' and '.' in video_file.filename:
                video_ext = video_file.filename.rsplit('.', 1)[1].lower()
                if video_ext not in ALLOWED_VIDEO_EXTENSIONS:
                    flash('Unsupported video format. Allowed: mp4, webm, ogg, mov', 'danger')
                    return redirect(url_for('blog'))
                try:
                    # Determine size of uploaded file safely
                    stream = video_file.stream
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    stream.seek(0)
                except Exception:
                    size = None

                if size is not None and size > MAX_VIDEO_SIZE:
                    flash('Video exceeds maximum allowed size of 10 MB.', 'danger')
                    return redirect(url_for('blog'))

                try:
                    upload_result = cloudinary.uploader.upload(video_file, resource_type='video', folder='echowithin_posts')
                    video_url = upload_result.get('secure_url')
                    video_public_id = upload_result.get('public_id')
                except Exception as e:
                    app.logger.error(f"Cloudinary video upload failed: {e}")
                    flash("There was an error uploading the video.", "danger")
                    return redirect(url_for('blog'))

            new_post_data = {
                'author_id': ObjectId(current_user.id),
                'slug': slug,
                'title': title,
                'content': content,
                'author': current_user.username,
                'image_url': image_url,
                'image_public_id': image_public_id,
                'image_status': 'safe' if image_url else 'none', # Optimistically assume safe
                'video_url': video_url,
                'video_public_id': video_public_id,
                'video_status': 'uploaded' if video_url else 'none',
                'timestamp': datetime.datetime.now(),
            }
            result = posts_conf.insert_one(new_post_data)

            # If an image was uploaded, enqueue the background NSFW check
            if image_url and image_public_id:
                try:
                    job = process_image_for_nsfw.queue(str(result.inserted_id), image_url, image_public_id) # snyk:disable=disable-command-line-argument-injection
                    app.logger.info(f"Enqueued NSFW check job {job.id} for post {result.inserted_id}") # snyk:disable=disable-command-line-argument-injection
                except redis.exceptions.ConnectionError as e:
                    app.logger.warning(f"Redis connection failed. Falling back to thread for NSFW check job. Error: {e}")
                    # Fallback: Run the job in a background thread
                    with app.app_context():
                        ThreadPoolExecutor().submit(process_image_for_nsfw, str(result.inserted_id), image_url, image_public_id)

            # Enqueue background notification task to RQ
            try:
                post_id_str = str(result.inserted_id)
                job = send_new_post_notifications.queue(post_id_str) # snyk:disable=disable-command-line-argument-injection
                app.logger.info(f"Enqueued notification job {job.id} for post {post_id_str}") # snyk:disable=disable-command-line-argument-injection
            except redis.exceptions.ConnectionError as e:
                app.logger.warning(f"Redis connection failed. Falling back to thread for notification job. Error: {e}")
                # Fallback: Run the job in a background thread
                with app.app_context():
                    ThreadPoolExecutor().submit(send_new_post_notifications, post_id_str)
            
            # --- Send ntfy notification for new post ---
            try:
                ntfy_message = f"\"{title}\" by {current_user.username}"
                send_ntfy_notification.queue(ntfy_message, "New Post Created", "tada")
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
    page_title = post.get('title')
    # Generate a short description from the content
    page_description = (post.get('content', '')[:155] + '...') if len(post.get('content', '')) > 155 else post.get('content', '')
    # Get Remark42 config from environment variables
    remark42_host = get_env_variable('REMARK42_HOST')
    remark42_site_id = get_env_variable('REMARK42_SITE_ID')
    return render_template('edit_post.html', 
                           post=post, 
                           active_page='blog', 
                           action='comment', 
                           title=page_title, 
                           description=page_description,
                           remark42_host=remark42_host,
                           remark42_site_id=remark42_site_id)

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
    
    # Get Remark42 config from environment variables to ensure it's available in the template
    remark42_host = get_env_variable('REMARK42_HOST')
    remark42_site_id = get_env_variable('REMARK42_SITE_ID')

    return render_template('edit_post.html', post=post, active_page='blog', 
                           action=action, title=page_title, description=page_description,
                           remark42_host=remark42_host,
                           remark42_site_id=remark42_site_id)

@app.route('/update_post/<post_id>', methods=['POST'])
@login_required
@owner_required
def update_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    title = request.form.get("title")
    content = request.form.get("content")
    image_file = request.files.get('image')
    video_file = request.files.get('video')
    image_url = post.get('image_url') # Keep old image by default
    image_public_id = post.get('image_public_id')
    video_url = post.get('video_url')
    video_public_id = post.get('video_public_id')
    slug = post.get('slug') # Keep old slug by default
    image_status = post.get('image_status', 'none')
    video_status = post.get('video_status', 'none')

    if title and content:
        # Handle image replacement
        if image_file and image_file.filename != '' and '.' in image_file.filename and \
           image_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS:
            try:
                # Delete the old image from Cloudinary if it exists
                if image_public_id:
                    cloudinary.uploader.destroy(image_public_id)

                # Upload the new image
                upload_result = cloudinary.uploader.upload(image_file, folder="echowithin_posts")
                image_url = upload_result.get('secure_url')
                image_public_id = upload_result.get('public_id')
                image_status = 'safe' # Optimistically assume safe
                # Enqueue the background NSFW check for the new image
                try:
                    job = process_image_for_nsfw.queue(post_id, image_url, image_public_id)
                    app.logger.info(f"Enqueued NSFW check job {job.id} for updated post {post_id}")
                except Exception as e:
                    app.logger.error(f"Failed to enqueue NSFW check job on update: {e}", exc_info=True)
            except Exception as e:
                # --- Send ntfy notification for NSFW content ---
                try:
                    message = f"NSFW content detected in post '{post.get('title')}' by {post.get('author')}. Image has been flagged."
                    send_ntfy_notification.queue(message, "NSFW Content Detected", "see_no_evil")
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
                'image_url': image_url,
                'image_public_id': image_public_id,
                'image_status': image_status,
                'video_url': video_url,
                'video_public_id': video_public_id,
                'video_status': video_status,
                'slug': slug,
                'timestamp': datetime.datetime.now(),
            }}
        )
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
    # Pagination logic
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10 # Show more posts on admin page

    total_posts = posts_conf.count_documents({})
    total_pages = math.ceil(total_posts / posts_per_page)

    skip = (page - 1) * posts_per_page

    # Fetch all posts, sorted by newest first
    posts = posts_conf.find({}).sort('timestamp', -1).skip(skip).limit(posts_per_page)
    
    return render_template("admin_posts.html", posts=posts, active_page='admin_posts', page=page, total_pages=total_pages)

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

@app.route('/about')
def about():
    page_title = "About EchoWithin"
    page_description = "Learn more about EchoWithin, our mission, and the team behind the platform."
    return render_template("about.html", title=page_title, description=page_description)

@app.route('/profile/<username>')
@login_required
def profile(username):
    # --- Authorization Check ---
    # Ensure the logged-in user can only access their own profile.
    if username != current_user.username:
        flash("You are not authorized to view this profile.", "danger")
        return redirect(url_for('profile', username=current_user.username))

    # Find the user by username
    user = users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    # Find all posts by this user's ID
    user_posts = list(posts_conf.find({'author_id': user['_id']}).sort('timestamp', -1))
    
    page_title = f"Profile: {user['username']}"
    page_description = f"View the profile and posts by {user['username']} on EchoWithin."

    return render_template('profile.html', 
                           user=user, 
                           user_posts=user_posts,
                           title=page_title, 
                           description=page_description,
                           active_page='profile')


@app.route('/profile/<username>/notifications', methods=['POST'])
@login_required
def update_notifications(username):
    # Only allow users to update their own settings
    if username != current_user.username:
        flash("You are not authorized to update this profile.", "danger")
        return redirect(url_for('profile', username=current_user.username))

    user = users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    # Checkbox posts 'notify_new_posts' when checked
    notify_val = request.form.get('notify_new_posts')
    notify_flag = True if notify_val in ('1', 'true', 'on') else False

    try:
        users_conf.update_one({'_id': user['_id']}, {'$set': {'notify_new_posts': notify_flag}})
        flash('Notification preferences updated.', 'success')
    except Exception as e:
        app.logger.error(f"Failed to update notification preference for {username}: {e}")
        flash('Failed to update preferences. Please try again later.', 'danger')

    return redirect(url_for('profile', username=username))


@app.route('/profile/<username>/settings', methods=['GET', 'POST'])
@login_required
def profile_settings(username):
    # Only allow users to access their own settings
    if username != current_user.username:
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for('profile', username=current_user.username))

    user = users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        notify_val = request.form.get('notify_new_posts')
        notify_flag = True if notify_val in ('1', 'true', 'on') else False
        try:
            users_conf.update_one({'_id': user['_id']}, {'$set': {'notify_new_posts': notify_flag}})
            flash('Settings updated.', 'success')
        except Exception as e:
            app.logger.error(f"Failed to update settings for {username}: {e}")
            flash('Failed to update settings. Please try again later.', 'danger')
        return redirect(url_for('profile_settings', username=username))

    # For GET, render settings page
    return render_template('profile_settings.html', user=user, active_page='profile', title=f"Settings - {user.get('username')}")

@app.route('/contact', methods=['POST'])
@limits(calls=5, period=TIME) 
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
    app.logger.error(f"Internal Server Error: {e}", exc_info=True)
    try:
        send_ntfy_notification.queue(f"A 500 error occurred on endpoint {request.path}. Check logs for details.", "Application Error (500)", "warning")
    except Exception as ntfy_e:
        app.logger.error(f"Failed to enqueue ntfy notification for 500 error: {ntfy_e}")
    return render_template("500.html"), 500

@app.route('/sitemap.xml')
def sitemap():
    """Generate sitemap.xml for search engines."""
    pages = []
    ten_days_ago = (datetime.datetime.now() - datetime.timedelta(days=10)).date().isoformat()
    now = datetime.datetime.now()
    one_week_ago = (now - datetime.timedelta(days=7)).date().isoformat()

    # Static pages
    static_urls = [url_for('dashboard', _external=True), url_for('about', _external=True), url_for('login', _external=True), url_for('register', _external=True)]
    for url in static_urls:
        pages.append({'loc': url, 'lastmod': ten_days_ago, 'changefreq': 'weekly'})
        pages.append({'loc': url, 'lastmod': one_week_ago, 'changefreq': 'weekly', 'priority': '0.8'})

    # Add the main blog page with high priority
    blog_url = url_for('blog', _external=True)
    pages.append({'loc': blog_url, 'lastmod': now.date().isoformat(), 'changefreq': 'daily', 'priority': '0.9'})

    # Dynamic pages (blog posts)
    # This assumes you have implemented slugs as suggested above
    posts = posts_conf.find({}, {"slug": 1, "timestamp": 1}).sort('timestamp', -1)
    for post in posts:
        if 'slug' in post:
            url = url_for('view_post', slug=post['slug'], _external=True)
            pages.append({'loc': url, 'lastmod': post['timestamp'].date().isoformat(), 'changefreq': 'daily'})
            post_time = post['timestamp']
            
            # Calculate priority based on how recent the post is.
            # Newer posts get higher priority.
            days_since_update = (now - post_time).days
            if days_since_update < 7:
                priority = '1.0' # Very recent
            elif days_since_update < 30:
                priority = '0.9' # Recent
            else:
                priority = '0.7' # Older
            pages.append({'loc': url, 'lastmod': post_time.date().isoformat(), 'changefreq': 'daily', 'priority': priority})

    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"
    return response
