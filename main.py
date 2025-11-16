# Import necessary modules needed
import datetime
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash
import math
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from ratelimit import limits
from dotenv import load_dotenv

 # Initialise Flask
app = Flask(__name__)

#Initialise the Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # snyk:disable=security-issue

# Secure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent client-side JS from accessing the cookie
app.config['SESSION_COOKIE_SECURE'] = False # Only send cookie over HTTPS (set to False in local dev if not using HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protection against CSRF

# Initialise the env
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

TIME = int(get_env_variable('TIME'))


#setup and initialise the mongodb databases
client = MongoClient('localhost', 27017)
db = client['hotspot']
users_conf = db['users']
posts_conf = db['posts']
logs_conf = db['logs']



# This class represents a user. Flask-Login uses it to manage the user's session.
###################### START #################################
class User(UserMixin):
    def __init__(self, user_data):
        # Store user-specific properties
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.is_admin = user_data.get('is_admin', False)
        self._is_active = user_data.get('is_confirmed', False)

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

@login_manager.user_loader
def load_user(user_id):
    user_data = users_conf.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None
######################## STOP ####################################

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
            existing_user = users_conf.find_one({'$or': [{'username': username}, {'email': email}]})
            if existing_user:
                flash("Try using a different username or email", "danger")
                return redirect(url_for('register'))
            else:
                password = generate_password_hash(password)
                users_conf.insert_one({
                    'username' : username,
                    'email': email,
                    'password' : password,
                    'is_confirmed': False,
                    'is_admin': False
                })

                flash("Please wait as your details are being confirmed", "info")
                return redirect(url_for("login"))
        else:
            flash('Username and password are required', "danger")
    return render_template("auth.html", active_page='register')
    


@app.route("/login", methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def login():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        client_ip = request.remote_addr
        logs_conf.insert_one({
        'ip' : client_ip,
        'username': username,
        'timestamp' : datetime.datetime.now().strftime("%B %d, %Y %I:%M %p") 
        })

        user = users_conf.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            if not user.get('is_confirmed'):
                flash('Please wait as your details are being confirmed', "danger")
                return redirect(url_for('login'))
                
            
            user_obj = User(user)
            login_user(user_obj) 
            if current_user.is_admin and current_user.is_authenticated:
                flash('You have logged in as admin', 'success')
                return redirect(url_for('admin_posts'))
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(request.args.get('next') or url_for('home'))
        else:
            flash("Wrong details provided", "danger")
    return render_template("auth.html", active_page='login')

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template("dashboard.html", active_page='dashboard')

@app.route('/home')
@login_required
def home():
    return render_template("home.html", username=current_user.username, active_page='home')

@app.route("/blog")
@login_required
def blog():
    # Search logic
    query = request.args.get('query', None)
    search_filter = {}
    if query:
        # Using regex for a case-insensitive search on title and content
        search_filter = {
            "$or": [
                {"title": {"$regex": query, "$options": "i"}},
                {"content": {"$regex": query, "$options": "i"}}
            ]
        }

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
    return render_template("blog.html", posts=posts, active_page='blog', page=page, total_pages=total_pages, query=query)

@app.route("/post", methods=['POST'])
@login_required
def post():
    if request.method=="POST":
        title=request.form.get("title")
        content=request.form.get("content")
        if title and content:  
            posts_conf.insert_one({
                'author_id': ObjectId(current_user.id),
                'title': title,
                'content': content,
                'author': current_user.username,
                'timestamp': datetime.datetime.now(),
            })
            flash("Post created successfully!", "success")
        else:
            flash("Title and content cannot be empty.", "danger")
    return redirect(url_for("blog"))
    

@app.route('/edit_post/<post_id>', methods=['GET'])
@login_required
def edit_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    if not post:
        flash("Post not found.", "danger")
        return redirect(url_for('blog'))

    # Ensure the current user is the author of the post
    if post.get('author') != current_user.username:
        flash("You are not authorized to edit this post.", "danger")
        return redirect(url_for('blog'))

    return render_template('edit_post.html', post=post, active_page='blog')

@app.route('/update_post/<post_id>', methods=['POST'])
@login_required
def update_post(post_id):
    post = posts_conf.find_one({'_id': ObjectId(post_id)})

    if not post or post.get('author') != current_user.username:
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for('blog'))

    title = request.form.get("title")
    content = request.form.get("content")

    if title and content:
        posts_conf.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {
                'title': title,
                'content': content,
                'timestamp': datetime.datetime.now(),
            }}
        )
        flash("Post updated successfully!", "success")
    else:
        flash("Title and content cannot be empty.", "danger")
    
    return redirect(url_for('blog'))

@app.route('/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    posts_conf.delete_one({'_id': ObjectId(post_id), 'author_id': ObjectId(current_user.id)})
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
        result = posts_conf.delete_one({'_id': ObjectId(post_id)})
        if result.deleted_count == 1:
            flash('Post deleted successfully by admin.', 'success')
        else:
            flash('Post not found.', 'warning')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    return redirect(url_for('admin_posts'))
@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/logout')
def logout():
    logout_user() # Use Flask-Login to properly log the user out
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Handles any possible errors

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("dashboard")), 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
