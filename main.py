import datetime
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash, make_response, send_from_directory
import logging
import math
import redis
from flask_rq2 import RQ
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user 
from functools import wraps
from flask_mail import Mail, Message 
import os
from pymongo import MongoClient
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

app = Flask(__name__)

# --- Logging Setup ---
if not app.debug:
    file_handler = RotatingFileHandler('echowithin.log', maxBytes=1024 * 1024 * 10, backupCount=5)
    
    # Set the logging level (e.g., INFO, WARNING, ERROR)
    file_handler.setLevel(logging.INFO)
    
    # Define the format for the log messages
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
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
app.config['SESSION_COOKIE_SECURE'] = False # Only send cookie over HTTPS (set to False in local dev if not using HTTPS)
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

# Setup the secret key
app.config["SECRET_KEY"] = get_env_variable('SECRET')

# Configuration for file uploads (now handled by Cloudinary)
# UPLOAD_FOLDER is kept for backward compatibility with old posts.
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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
app.config['RQ_REDIS_URL'] = get_env_variable('REDIS_URL') # 

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
def process_image_for_nsfw(post_id_str, image_url, public_id):
    """
    This function runs in the background to check an image for NSFW content.
    It now uses the image URL from Cloudinary.
    """
    # Imports must be inside the function for the RQ worker
    from main import app, posts_conf
    from bson.objectid import ObjectId
    import cloudinary.uploader

    with app.app_context():
        post_id = ObjectId(post_id_str)
        app.logger.info(f"Starting NSFW check for post {post_id} on image URL: {image_url}")

        # Cloudinary's built-in NSFW detection is more efficient
        # We tell Cloudinary to check the already uploaded image.
        response = cloudinary.uploader.explicit(public_id, type="upload", moderation="aws_rek")
        is_nsfw = response.get("moderation", [{}])[0].get("status") == "rejected"

        if is_nsfw:
            app.logger.warning(f"NSFW content detected in {public_id} for post {post_id}. Tagging as NSFW.")
            cloudinary.uploader.add_tag('nsfw', [public_id])
            posts_conf.update_one({'_id': post_id}, {'$set': {'image_status': 'removed_nsfw'}})
        else:
            app.logger.info(f"Image {public_id} for post {post_id} is safe.")
            posts_conf.update_one({'_id': post_id}, {'$set': {'image_status': 'safe'}})



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
                sender='echowithin@echowithin.xyz',
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
                'is_confirmed': True, # Set to True to bypass email confirmation
                'is_admin': False,
                'join_date': datetime.datetime.now()
            })

            # --- Email confirmation is now bypassed ---
            # gen_code = str(secrets.randbelow(10**6)).zfill(6)
            # hashed = hashlib.sha256(gen_code.encode()).hexdigest()
            # auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed}}, upsert=True)
            # send_code(email, gen_code)
            
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash('Username and password are required', "danger")
    return render_template("auth.html", active_page='register')
    
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

    # Calculate total comments
    total_comments_pipeline = [
        {'$match': {'comments': {'$exists': True, '$ne': []}}},
        {'$project': {'comment_count': {'$size': '$comments'}}},
        {'$group': {'_id': None, 'total': {'$sum': '$comment_count'}}}
    ]
    total_comments_result = list(posts_conf.aggregate(total_comments_pipeline))
    total_comments = total_comments_result[0]['total'] if total_comments_result else 0

    # Find the most active member (by post count)
    most_active_member_pipeline = [
        {'$group': {'_id': '$author', 'post_count': {'$sum': 1}}},
        {'$sort': {'post_count': -1}},
        {'$limit': 1}
    ]
    most_active_member_result = list(posts_conf.aggregate(most_active_member_pipeline))
    most_active_member = most_active_member_result[0] if most_active_member_result else None

    # Find trending posts (most commented) using an aggregation pipeline
    trending_posts = list(posts_conf.aggregate([
        {
            '$project': {
                'title': 1,
                'slug': 1,
                'comment_count': {'$size': {'$ifNull': ['$comments', []]}} # snyk:disable=nosql-injection
            }
        },
        {'$sort': {'comment_count': -1}},
        {'$limit': 3}
    ]))

    return render_template("home.html", username=current_user.username, active_page='home', 
                           title=page_title, description=page_description,
                           total_members=total_members, total_posts=total_posts,
                           total_comments=total_comments, most_active_member=most_active_member,
                           trending_posts=trending_posts)

@app.route("/blog")
def blog():
    # Search logic
    query = request.args.get('query', None)
    search_filter = {}
    if query:
        # Using regex for a case-insensitive search on title and content
        # Use a text index for much faster searching
        search_filter = { "$text": { "$search": query } }

    # Pagination logic
    page = request.args.get('page', 1, type=int)
    posts_per_page = 5 # You can adjust this number

    # Get total number of posts to calculate total pages
    total_posts = posts_conf.count_documents(search_filter)
    total_pages = math.ceil(total_posts / posts_per_page)

    # Calculate the number of documents to skip
    skip = (page - 1) * posts_per_page

    # Fetch a slice of posts for the current page, sorted by newest first
    posts = posts_conf.find(search_filter).sort('timestamp', -1).skip(skip).limit(posts_per_page)

    page_title = "Blog - EchoWithin"
    page_description = "Explore the latest posts and discussions from the EchoWithin community."
    return render_template("blog.html", posts=posts, active_page='blog', page=page, total_pages=total_pages, query=query, title=page_title, description=page_description)

@app.route("/post", methods=['POST'])
@login_required
def post():
    if request.method=="POST":
        title=request.form.get("title")
        content=request.form.get("content")
        image_file = request.files.get('image')
        image_url = None
        image_public_id = None


        if title and content:  
            # Create a unique slug for SEO-friendly URLs
            base_slug = slugify(title)
            slug = base_slug
            counter = 1
            while posts_conf.find_one({'slug': slug}):
                slug = f"{base_slug}-{counter}"
                counter += 1
            
            if image_file and image_file.filename != '' and '.' in image_file.filename and \
               image_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                try:
                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(image_file, folder="echowithin_posts")
                    image_url = upload_result.get('secure_url')
                    image_public_id = upload_result.get('public_id')
                except Exception as e:
                    app.logger.error(f"Cloudinary upload failed: {e}")
                    flash("There was an error uploading the image.", "danger")
                    return redirect(url_for("blog"))

            new_post_data = {
                'author_id': ObjectId(current_user.id),
                'slug': slug,
                'title': title,
                'content': content,
                'author': current_user.username,
                'image_url': image_url,
                'image_public_id': image_public_id,
                'image_status': 'processing' if image_url else 'none', # Add image status
                'timestamp': datetime.datetime.now(),
            }
            result = posts_conf.insert_one(new_post_data)

            # If an image was uploaded, queue the background job for NSFW check
            if image_url and image_public_id:
                post_id_str = str(result.inserted_id)
                process_image_for_nsfw.queue(post_id_str, image_url, image_public_id)

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
    return render_template('edit_post.html', post=post, active_page='blog', action='comment', title=page_title, description=page_description)

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
    return render_template('edit_post.html', post=post, active_page='blog', action=action, title=page_title, description=page_description)

@app.route('/update_post/<post_id>', methods=['POST'])
@login_required
@owner_required
def update_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    title = request.form.get("title")
    content = request.form.get("content")
    image_file = request.files.get('image')
    image_url = post.get('image_url') # Keep old image by default
    image_public_id = post.get('image_public_id')
    slug = post.get('slug') # Keep old slug by default
    image_status = post.get('image_status', 'none')

    if title and content:
        if image_file and image_file.filename != '' and '.' in image_file.filename and \
           image_file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
            try:
                # Delete the old image from Cloudinary if it exists
                if image_public_id:
                    cloudinary.uploader.destroy(image_public_id)

                # Upload the new image
                upload_result = cloudinary.uploader.upload(image_file, folder="echowithin_posts")
                image_url = upload_result.get('secure_url')
                image_public_id = upload_result.get('public_id')
                image_status = 'processing'
                # Queue the background job for the new image
                process_image_for_nsfw.queue(post_id, image_url, image_public_id)
            except Exception as e:
                app.logger.error(f"Cloudinary upload/delete failed during update: {e}")

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
                'slug': slug,
                'timestamp': datetime.datetime.now(),
            }}
        )
        flash("Post updated successfully!", "success")
        return redirect(url_for('blog', slug=slug))
    else:
        flash("Title and content cannot be empty.", "danger")
    return redirect(url_for('view_post', slug=slug))

@app.route('/add_comment/<post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})
    if post:
        content = request.form.get("content")
        stance = request.form.get("stance")
        if content and stance:
            posts_conf.update_one(
                {'_id': ObjectId(post_id)},
                {
                    '$push': {
                        'comments': {
                            'comment_id': ObjectId(),
                            'author': current_user.username,
                            'content': content,
                            'stance': stance
                        }
                    },
                    '$set': {
                        'timestamp': datetime.datetime.now()
                    }
                }
            )
            flash("Comment added successfully!", "success")
            return redirect(url_for('blog', slug=post.get('slug', '')))
        else:
            flash("Comment and stance cannot be empty.", "danger")
    return redirect(url_for('view_post', slug=post.get('slug', '')))

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
        cloudinary.uploader.destroy(post_to_delete['image_public_id'])

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
        if post_to_delete and post_to_delete.get('image_public_id'):
            try:
                cloudinary.uploader.destroy(post_to_delete['image_public_id'])
            except Exception as e:
                app.logger.error(f"Admin failed to delete Cloudinary image {post_to_delete['image_public_id']}: {e}")
        result = posts_conf.delete_one({'_id': ObjectId(post_id)})

        if result.deleted_count == 1:
            flash('Post deleted successfully by admin.', 'success')
        else:
            flash('Post not found.', 'warning')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    return redirect(url_for('admin_posts'))

@app.route('/admin/delete_comment/<post_id>/<comment_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_comment(post_id, comment_id):
    try:
        result = posts_conf.update_one(
            {'_id': ObjectId(post_id)},
            {'$pull': {'comments': {'comment_id': ObjectId(comment_id)}}}
        )
        if result.modified_count == 1:
            flash('Comment deleted successfully by admin.', 'success')
        else:
            flash('Comment not found or already deleted.', 'warning')
    except Exception as e:
        flash(f'An error occurred while deleting the comment: {e}', 'danger')
    
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
    # Unpin any currently pinned announcement
    announcements_conf.update_many({'is_pinned': True}, {'$set': {'is_pinned': False}})
    # Pin the new one
    announcements_conf.update_one({'_id': ObjectId(announcement_id)}, {'$set': {'is_pinned': True}})
    flash('Announcement has been pinned.', 'success')
    return redirect(url_for('admin_announcements'))

@app.route('/admin/announcements/unpin/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def unpin_announcement(announcement_id):
    announcements_conf.update_one({'_id': ObjectId(announcement_id)}, {'$set': {'is_pinned': False}})
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

@app.route('/logout')
def logout():
    logout_user() # Use Flask-Login to properly log the user out
    flash('You have been logged out.', 'info')
    return redirect(url_for('dashboard'))


# Handles any possible errors

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("dashboard")), 404

@app.errorhandler(RateLimitException)
def handle_ratelimit_exception(e):
    """Custom handler for rate limit exceeded exceptions."""
    period_remaining = math.ceil(e.period_remaining)
    app.logger.warning(f"Rate limit exceeded for IP {request.remote_addr}. Blocked for {period_remaining} seconds.")
    return render_template('429.html', period_remaining=period_remaining), 429

@app.route('/sitemap.xml')
def sitemap():
    """Generate sitemap.xml for search engines."""
    pages = []
    ten_days_ago = (datetime.datetime.now() - datetime.timedelta(days=10)).date().isoformat()

    # Static pages
    static_urls = [url_for('dashboard', _external=True), url_for('about', _external=True), url_for('login', _external=True), url_for('register', _external=True)]
    for url in static_urls:
        pages.append({'loc': url, 'lastmod': ten_days_ago, 'changefreq': 'weekly'})

    # Dynamic pages (blog posts)
    # This assumes you have implemented slugs as suggested above
    posts = posts_conf.find({}, {"slug": 1, "timestamp": 1}).sort('timestamp', -1)
    for post in posts:
        if 'slug' in post:
            url = url_for('view_post', slug=post['slug'], _external=True)
            pages.append({'loc': url, 'lastmod': post['timestamp'].date().isoformat(), 'changefreq': 'daily'})

    sitemap_xml = render_template('sitemap_template.xml', pages=pages)
    response = make_response(sitemap_xml)
    response.headers["Content-Type"] = "application/xml"
    return response
