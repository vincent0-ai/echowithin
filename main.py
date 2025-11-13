# Import necessary modules needed
import datetime
from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash
from flask_login import LoginManager, UserMixin
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from flask_mail import Mail, Message
from ratelimit import limits
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv

 # Initialise Flask
app = Flask(__name__)

#Initialise the Login Manager
login_manager = LoginManager(app)

# Initialise the env
load_dotenv()

#setup the secret key
app.config["SECRET_KEY"] = os.getenv('SECRET')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['TIME'] = os.getenv('TIME')
mail = Mail(app)

# Initialise serializer for token generation
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


#setup and initialise the mongodb databases
client = MongoClient('localhost', 27017)
db = client['hotspot']
users_conf = db['users']
posts_conf = db['posts']
logs_conf = db['logs']



# Currently i don't know what this class and the next function is doing.
# I just figured out that it is essential for the program to run.
###################### START #################################
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]

@login_manager.user_loader
def load_user(user_id):
    user_data = users_conf.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None
######################## STOP ####################################

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        if username and password and email:
            existing_user = users_conf.find_one({'$or': [{'username': username}, {'email': email}]})
            if existing_user:
                flash("Try using a different username", "danger")
                return redirect(url_for('register'))
            else:
                password = generate_password_hash(password)
                users_conf.insert_one({
                    'username' : username,
                    'email': email,
                    'password' : password,
                    'is_confirmed': False,
                    'confirmed_on': None
                })

                # Send confirmation email
                token = s.dumps(email, salt='email-confirm')
                confirm_url = url_for('confirm_email', token=token, _external=True)
                html = render_template('activate.html', confirm_url=confirm_url)
                msg = Message('Confirm Your Email - EchoWithin', sender=MAIL_USERNAME, recipients=[email])
                msg.html = html
                mail.send(msg)

                flash("A confirmation email has been sent to your email address. Please confirm to log in.", "info")
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
        'ip' : client_ip 
        })

        user = users_conf.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            if not user.get('is_confirmed'):
                flash('Please confirm your email address first!', 'warning')
                return redirect(url_for('login'))
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('home'))
        else:
            flash("Wrong details provided", "danger")
    return render_template("auth.html", active_page='login')

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600) # Token expires in 1 hour
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
        return redirect(url_for('resend_confirmation'))
    except:
        flash('The confirmation link is invalid.', 'danger')
        return redirect(url_for('register'))

    user = users_conf.find_one_and_update(
        {'email': email},
        {'$set': {'is_confirmed': True, 'confirmed_on': datetime.datetime.now()}}
    )

    flash('Your account has been confirmed! Please log in.', 'success')
    return redirect(url_for('login'))


@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        username=session.get('username')
        return redirect(url_for('home'))
    return render_template("dashboard.html", active_page='dashboard')

@app.route('/home')
def home():
    if 'user_id' in session:
        username=session.get('username')
        return render_template("home.html", username=username, active_page='home')
    return redirect(url_for("dashboard"))

@app.route("/blog")
def blog():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    posts = posts_conf.find()
    return render_template("blog.html", posts=posts, active_page='blog')

@app.route("/post", methods=['POST'])
def post():
    if 'user_id' in session:
        if request.method=="POST":
            title=request.form.get("title")
            content=request.form.get("content")
            username=session.get('username')
            if title and content:  
                posts_conf.insert_one({
                    'title': title,
                    'content': content,
                    'author': username,
                    'timestamp': datetime.datetime.now().strftime("%B %d, %Y %I:%M %p")
                })
                flash("Post created successfully!", "success")
            else:
                flash("Title and content cannot be empty.", "danger")
        return redirect(url_for("blog"))
    return redirect(url_for("login"))
    

@app.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if request.method == 'POST':
        email = request.form.get('email')
        user = users_conf.find_one({'email': email})

        if user and not user.get('is_confirmed'):
            token = s.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('activate.html', confirm_url=confirm_url)
            msg = Message('Confirm Your Email - EchoWithin', sender=MAIL_USERNAME, recipients=email)
            msg.html = html
            mail.send(msg)
            flash('A new confirmation email has been sent.', 'info')
            return redirect(url_for('login'))
        elif user and user.get('is_confirmed'):
            flash('Your account is already confirmed. Please log in.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.', 'danger')
    return render_template('resend_confirmation.html', active_page='resend')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Handles any possible errors

@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for("dashboard")), 404



if __name__ == "__main__":
    app.run(debug=True)
