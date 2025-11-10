# Import necessary modules needed

from flask import Flask, request, jsonify, render_template, url_for, redirect, session, flash
from flask_login import LoginManager, UserMixin, login_required, logout_user, current_user
import os
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from secret import SECRET 

 # Initialise Flask
app = Flask(__name__)

#Initialise the Login Manager
login_manager = LoginManager(app)

#setup the secret key
app.config["SECRET_KEY"] = SECRET

#setup and initialise the mongodb database
client = MongoClient('localhost', 27017)
db = client['hotspot']
users_conf = db['users']



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
        password = request.form.get("password")
        if username and password:
            user = users_conf.find_one({'username': username})
            if user:
                flash("Try using a different username", "danger")
                return render_template("auth.html")
            else:
                password = generate_password_hash(password)
                user = users_conf.insert_one({
                    'username' : username,
                    'password' : password
                })
                flash("Proceed to log in", "success")
            return redirect(url_for("login"))
        else:
            flash('Username and password are required', "danger")
            return render_template("auth.html")
    return render_template("auth.html")
    


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        
        user = users_conf.find_one({"username": username})
        if user and password and check_password_hash(user["password"], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            return redirect(url_for('home'))
        else:
            flash("Wrong details provided", "danger")
    return render_template("auth.html")


@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        username=session.get('username')
        return render_template("home.html", username=username)
    return render_template("dashboard.html")

@app.route('/home')
def home():
    if 'user_id' in session:
        username=session.get('username')
        return render_template("home.html", username=username)
    return redirect(url_for("dashboard"))

@app.route("/blog")
def blog():
    if 'user_id' not in session:
        return redirect(url_for("login"))
    return render_template("blog.html")


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
