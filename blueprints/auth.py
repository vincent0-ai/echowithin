from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app, make_response
from flask_login import login_required, current_user, login_user, logout_user
from bson.objectid import ObjectId
import datetime, hashlib, secrets, os
from security import limits, warm_user_fernet
from config import TIME

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('auth', __name__, template_folder='templates')


@bp.route('/register', methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def register():
    import main as m
    next_url = request.args.get('next')
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        if not username or not email or not password:
            flash("All fields are required", "danger")
            return redirect(url_for('auth.register'))
        if len(username) < 2 or len(password) < 6:
            flash("Username must be at least 2 characters and password at least 6 characters.", "danger")
            return redirect(url_for('auth.register'))
        if m.users_conf.find_one({"$or": [{"email": email}, {"username": username}]}):
            flash("Email or username already exists.", "danger")
            return redirect(url_for('auth.register'))
        hashed_password = m.generate_password_hash(password)
        m.users_conf.insert_one({
            "username": username,
            "email": email,
            "password": hashed_password,
            "is_confirmed": False,
            "join_date": datetime.datetime.now(datetime.timezone.utc),
            "notification_preference": 'weekly'
        })
        
        gen_code = str(secrets.randbelow(10**6)).zfill(6)
        hashed = hashlib.sha256(gen_code.encode()).hexdigest()
        code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
        m.auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry}}, upsert=True)
        m.send_code(email, gen_code)
        
        flash("Confirmation email sent. Please confirm your email to log in.", "success")
        return redirect(url_for('auth.confirm', email=email))
    return render_template("auth.html", active_page='register', form='register')


@bp.route("/confirm/<email>", methods=['GET', 'POST'])
def confirm(email):
    import main as m
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not code:
            error = "Verification code is required."
        else:
            hashed_obj = m.auth_conf.find_one({'email': email})
            if not hashed_obj:
                error = 'No confirmation code found for this email.'
            else:
                code_exp = hashed_obj.get('code_expiry')
                if code_exp and code_exp.tzinfo is None:
                    code_exp = code_exp.replace(tzinfo=datetime.timezone.utc)
                if code_exp and code_exp < datetime.datetime.now(datetime.timezone.utc):
                    error = 'This confirmation code has expired.'
                elif hashed_obj['hashed_code'] == hashlib.sha256(code.encode()).hexdigest():
                    m.users_conf.update_one({"email": email}, {"$set": {"is_confirmed": True}})
                    m.auth_conf.delete_one({"email": email})
                    flash("Email confirmed! You can now log in.", "success")
                    return redirect(url_for('auth.login'))
                else:
                    error = 'Invalid verification code.'
    return render_template("confirm.html", email=email, error=error)


@bp.route("/login", methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def login():
    import main as m
    next_url = request.args.get('next')
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember")
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for('auth.login'))
        user_data = m.users_conf.find_one({"$or": [{"email": username}, {"username": username}]})
        if user_data:
            if not user_data.get('is_confirmed'):
                gen_code = str(secrets.randbelow(10**6)).zfill(6)
                hashed = hashlib.sha256(gen_code.encode()).hexdigest()
                code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
                m.auth_conf.update_one({'email': user_data['email']}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry}}, upsert=True)
                m.send_code(user_data['email'], gen_code)
                flash("Email not confirmed. A new confirmation code has been sent.", "warning")
                return redirect(url_for('auth.confirm', email=user_data['email']))
            if user_data.get('is_banned'):
                flash("Your account has been suspended.", "danger")
                return redirect(url_for('auth.login'))
            if m.check_password_hash(user_data['password'], password):
                user_obj = m.User(user_data)
                login_user(user_obj, remember=remember)
                warm_user_fernet(str(user_data['_id']))  # Pre-derive Fernet key for notes
                m.users_conf.update_one({'_id': user_data['_id']}, {'$set': {'last_active': datetime.datetime.now(datetime.timezone.utc)}})
                cache_key = f"user:{user_data['_id']}"
                m.user_loader_cache.pop(cache_key, None)
                flash('Login successful!', 'success')
                if next_url and m.is_safe_url(next_url):
                    return redirect(next_url)
                return redirect(url_for('pages.home'))
        flash("Invalid username/email or password", "danger")
    return render_template('auth.html', active_page='login', form='login')


@bp.route('/google_login')
@limits(calls=10, period=TIME)
def google_login():
    import main as m
    scope = ['openid', 'email', 'profile']
    platform = request.args.get('platform', 'desktop')
    if platform != 'mobile' and 'EchoWithinApp' in request.headers.get('User-Agent', ''):
        platform = 'mobile'
    session['oauth_platform'] = platform
    google = m.OAuth2Session(m.GOOGLE_CLIENT_ID, scope=scope, redirect_uri=url_for('auth.google_callback', _external=True, _scheme='https'))
    authorization_url, state = google.authorization_url('https://accounts.google.com/o/oauth2/auth', prompt='consent')
    session['oauth_state'] = state
    if m.redis_cache:
        try:
            m.redis_cache.setex(f"oauth_state:{state}", 600, "1")
        except Exception as e:
            current_app.logger.warning(f"Failed to backup OAuth state in Redis: {e}")
    if platform == 'mobile':
        if m.redis_cache:
            try:
                m.redis_cache.setex(f"oauth_platform:{state}", 600, 'mobile')
            except Exception:
                pass
    next_url = request.args.get('next')
    if next_url:
        session['oauth_next'] = next_url
        if m.redis_cache:
            try:
                m.redis_cache.setex(f"oauth_next:{state}", 600, next_url)
            except Exception:
                pass
    return redirect(authorization_url)


@bp.route('/google_callback')
def google_callback():
    import main as m
    state_from_url = request.args.get('state')
    if state_from_url and m.redis_cache:
        try:
            platform_saved = m.redis_cache.get(f"oauth_platform:{state_from_url}")
            if platform_saved:
                if isinstance(platform_saved, bytes):
                    platform_saved = platform_saved.decode('utf-8')
                session['oauth_platform'] = platform_saved
            if 'oauth_state' not in session and m.redis_cache.exists(f"oauth_state:{state_from_url}"):
                session['oauth_state'] = state_from_url
            if 'oauth_next' not in session:
                next_url_saved = m.redis_cache.get(f"oauth_next:{state_from_url}")
                if next_url_saved:
                    if isinstance(next_url_saved, bytes):
                        next_url_saved = next_url_saved.decode('utf-8')
                    session['oauth_next'] = next_url_saved
        except Exception as e:
            current_app.logger.warning(f"Error checking Redis for recovery: {e}")
    if current_user.is_authenticated:
        platform = session.get('oauth_platform')
        if platform == 'mobile':
            if 'EchoWithinApp' in request.headers.get('User-Agent', ''):
                session.pop('oauth_platform', None)
                return redirect(url_for('pages.home'))
            otlt_token = secrets.token_urlsafe(32)
            if m.redis_cache:
                try:
                    m.redis_cache.setex(f"mobile_auth:{otlt_token}", 300, str(current_user.id))
                    https_deep_link = url_for('auth.mobile_auth', token=otlt_token, _external=True, _scheme='https')
                    custom_scheme_url = f"echowithin://open?path=/mobile_auth&token={otlt_token}"
                    return render_template('mobile_redirect.html', deep_link_url=custom_scheme_url, https_deep_link=https_deep_link, fallback_url=url_for('pages.home', _external=True))
                except Exception as e:
                    current_app.logger.error(f"Failed to store OTLT in Redis for authenticated user: {e}")
        return redirect(url_for('pages.home'))
    if 'oauth_state' not in session:
        flash("Authentication session expired (session mismatch). Please try logging in again.", "warning")
        return redirect(url_for('auth.login'))
    oauth_state = session.get('oauth_state')
    google = m.OAuth2Session(m.GOOGLE_CLIENT_ID, state=oauth_state, redirect_uri=url_for('auth.google_callback', _external=True, _scheme='https'))
    try:
        auth_response_url = request.url.replace('http://', 'https://', 1) if request.url.startswith('http://') else request.url
        token = google.fetch_token('https://oauth2.googleapis.com/token', client_secret=m.GOOGLE_CLIENT_SECRET, authorization_response=auth_response_url)
    except Exception as e:
        current_app.logger.error(f"Failed to fetch Google OAuth token: {e}", exc_info=True)
        session.pop('oauth_state', None)
        if state_from_url and m.redis_cache:
            try:
                m.redis_cache.delete(f"oauth_state:{state_from_url}")
                m.redis_cache.delete(f"oauth_platform:{state_from_url}")
            except Exception:
                pass
        flash("Authentication failed. Please try again.", "danger")
        return redirect(url_for('auth.login'))
    session.pop('oauth_state', None)
    if state_from_url and m.redis_cache:
        try:
            m.redis_cache.delete(f"oauth_state:{state_from_url}")
            m.redis_cache.delete(f"oauth_platform:{state_from_url}")
            m.redis_cache.delete(f"oauth_next:{state_from_url}")
        except Exception:
            pass
    google = m.OAuth2Session(m.GOOGLE_CLIENT_ID, token=token)
    response = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
    user_info = response.json()
    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])
    user = m.users_conf.find_one({'email': email})
    if user:
        if not user.get('is_confirmed'):
            flash("Your account is not confirmed. Please check your email.", "warning")
            return redirect(url_for('auth.login'))
        if user.get('is_banned'):
            logout_user()
            flash('Your account has been suspended. Please contact support.', 'danger')
            return redirect(url_for('auth.login'))
        user_obj = m.User(user)
        login_user(user_obj, remember=True)
        warm_user_fernet(str(user['_id']))  # Pre-derive Fernet key for notes
        flash(f"Welcome back, {user['username']}!", "success")
        platform = session.get('oauth_platform')
        if platform == 'mobile':
            if 'EchoWithinApp' in request.headers.get('User-Agent', ''):
                session.pop('oauth_platform', None)
                return redirect(url_for('pages.home'))
            otlt_token = secrets.token_urlsafe(32)
            if m.redis_cache:
                try:
                    m.redis_cache.setex(f"mobile_auth:{otlt_token}", 300, str(user['_id']))
                    https_deep_link = url_for('auth.mobile_auth', token=otlt_token, _external=True, _scheme='https')
                    custom_scheme_url = f"echowithin://open?path=/mobile_auth&token={otlt_token}"
                    return render_template('mobile_redirect.html', deep_link_url=custom_scheme_url, https_deep_link=https_deep_link, fallback_url=url_for('pages.home', _external=True))
                except Exception as e:
                    current_app.logger.error(f"Failed to store OTLT in Redis: {e}")
            return render_template('mobile_redirect.html', deep_link_url="echowithin://open?path=/home", https_deep_link=url_for('pages.home', _external=True, _scheme='https'), fallback_url=url_for('pages.home', _external=True))
        next_url = session.pop('oauth_next', None)
        if not next_url or not m.is_safe_url(next_url):
            next_url = url_for('pages.home')
        return redirect(next_url)
    else:
        base_username = name.replace(' ', '_').lower()
        username = base_username
        counter = 1
        while m.users_conf.find_one({'username': username}):
            username = f"{base_username}{counter}"
            counter += 1
        m.users_conf.insert_one({
            'username': username,
            'email': email,
            'password': None,
            'is_confirmed': True,
            'is_admin': False,
            'join_date': datetime.datetime.now(datetime.timezone.utc),
            'notification_preference': 'weekly',
            'google_signup': True
        })
        try:
            ntfy_message = f"User '{username}' has registered via Google."
            m.send_ntfy_notification.queue(ntfy_message, "New User on EchoWithin", "partying_face")
        except Exception as e:
            try:
                with current_app.app_context():
                    m.executor.submit(m.send_ntfy_notification, ntfy_message, "New User on EchoWithin", "partying_face")
            except Exception:
                pass
        user = m.users_conf.find_one({'email': email})
        user_obj = m.User(user)
        login_user(user_obj, remember=True)
        warm_user_fernet(str(user['_id']))  # Pre-derive Fernet key for notes
        flash(f"Account created successfully! Welcome, {username}!", "success")
        platform = session.pop('oauth_platform', None)
        if platform == 'mobile':
            if 'EchoWithinApp' in request.headers.get('User-Agent', ''):
                return redirect(url_for('pages.home'))
            otlt_token = secrets.token_urlsafe(32)
            if m.redis_cache:
                try:
                    m.redis_cache.setex(f"mobile_auth:{otlt_token}", 300, str(user['_id']))
                    https_deep_link = url_for('auth.mobile_auth', token=otlt_token, _external=True, _scheme='https')
                    custom_scheme_url = f"echowithin://open?path=/mobile_auth&token={otlt_token}"
                    return render_template('mobile_redirect.html', deep_link_url=custom_scheme_url, https_deep_link=https_deep_link, fallback_url=url_for('pages.home', _external=True))
                except Exception as e:
                    current_app.logger.error(f"Failed to store OTLT in Redis (signup): {e}")
            return render_template('mobile_redirect.html', deep_link_url="echowithin://open?path=/home", https_deep_link=url_for('pages.home', _external=True, _scheme='https'), fallback_url=url_for('pages.home', _external=True))
        next_url = session.pop('oauth_next', None)
        if not next_url or not m.is_safe_url(next_url):
            next_url = url_for('pages.home')
        return redirect(next_url)


@bp.route('/logout')
def logout():
    import main as m
    app_token = request.cookies.get('x_app_token')
    if app_token:
        m.app_tokens_conf.delete_one({'token': app_token})
    if current_user.is_authenticated:
        m.app_tokens_conf.delete_many({'user_id': ObjectId(current_user.id)})
    logout_user()
    session.pop('oauth_state', None)
    session.pop('oauth_platform', None)
    flash('You have been logged out.', 'info')
    resp = redirect(url_for('pages.dashboard'))
    resp.delete_cookie('x_app_token')
    return resp


@bp.route('/forgot_password', methods=['GET', 'POST'])
@limits(calls=10, period=TIME)
def forgot_password():
    import main as m
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            user = m.users_conf.find_one({'email': email})
            if user:
                reset_token = secrets.token_urlsafe(32)
                hashed_token = hashlib.sha256(reset_token.encode()).hexdigest()
                expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                m.auth_conf.update_one(
                    {'email': email},
                    {'$set': {'reset_token': hashed_token, 'reset_expiry': expiry}},
                    upsert=True
                )
                m.send_reset_code(email, reset_token)
                flash("We've sent a password reset link to your email. Please check your inbox (and spam folder).", "success")
                return redirect(url_for('auth.login'))
            else:
                flash("If an account with that email exists, we've sent you a password reset link.", "info")
                return redirect(url_for('auth.login'))
        else:
            flash("Please enter your email address.", "danger")
    return render_template('forgot_password.html', active_page='forgot_password')


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    import main as m
    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    auth_record = m.auth_conf.find_one({'reset_token': hashed_token})
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    reset_expiry = auth_record.get('reset_expiry') if auth_record else None
    if reset_expiry and reset_expiry.tzinfo is None:
        reset_expiry = reset_expiry.replace(tzinfo=datetime.timezone.utc)
    if not auth_record or not reset_expiry or reset_expiry < now_utc:
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for('auth.forgot_password'))
    user_to_update = m.users_conf.find_one({'email': auth_record['email']})
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if username and password and confirm_password:
            existing_user = m.users_conf.find_one({'username': username})
            if existing_user and existing_user['email'] != auth_record['email']:
                flash("That username is already taken. Please choose a different one.", "danger")
                return render_template('reset_password.html', token=token, active_page='reset_password')
            if password == confirm_password:
                hashed_password = m.generate_password_hash(password)
                m.users_conf.update_one(
                    {'email': auth_record['email']},
                    {'$set': {'username': username, 'password': hashed_password}}
                )
                m.posts_conf.update_many({'author_id': user_to_update['_id']}, {'$set': {'author': username}})
                m.auth_conf.delete_one({'reset_token': hashed_token})
                flash("Your password has been reset successfully. Please login.", "success")
                return redirect(url_for('auth.login'))
            else:
                flash("Passwords do not match.", "danger")
        else:
            flash("Please fill in all fields.", "danger")
    return render_template('reset_password.html', token=token, active_page='reset_password', current_username=user_to_update.get('username'))


@bp.route('/mobile_auth')
def mobile_auth():
    import main as m
    token = request.args.get('token')
    if not token:
        current_app.logger.warning("Mobile auth attempted without token.")
        return redirect(url_for('auth.login'))
    if not m.redis_cache:
        current_app.logger.error("Mobile auth failed: Redis not available.")
        return redirect(url_for('auth.login'))
    try:
        user_id = m.redis_cache.get(f"mobile_auth:{token}")
        if user_id:
            if isinstance(user_id, bytes):
                user_id = user_id.decode('utf-8')
            m.redis_cache.delete(f"mobile_auth:{token}")
            session.pop('oauth_platform', None)
            user = m.users_conf.find_one({'_id': ObjectId(user_id)})
            if user:
                user_obj = m.User(user)
                login_user(user_obj, remember=True)
                warm_user_fernet(str(user['_id']))  # Pre-derive Fernet key for notes
                _app_token = secrets.token_urlsafe(48)
                m.app_tokens_conf.insert_one({
                    'token': _app_token,
                    'user_id': user['_id'],
                    'created_at': datetime.datetime.now(datetime.timezone.utc)
                })
                current_app.logger.info(f"Successfully bridged mobile session for user {user['username']} via OTLT.")
                flash(f"Welcome back to the app, {user['username']}!", "success")
                resp = redirect(url_for('pages.home'))
                resp.set_cookie('x_app_token', _app_token, max_age=90*24*3600, httponly=True, secure=True, samesite='Lax')
                return resp
            else:
                current_app.logger.warning(f"Mobile auth token valid but user {user_id} not found.")
        else:
            current_app.logger.warning(f"Expired or invalid mobile auth token: {token[:8]}...")
    except Exception as e:
        current_app.logger.error(f"Error during mobile auth bridged login: {e}")
    flash("Login session expired. Please try again.", "warning")
    return redirect(url_for('auth.login'))


@bp.route('/api/app_reauth', methods=['POST'])
@csrf_exempt
@limits(calls=10, period=60)
def app_reauth():
    import main as m
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    if not token:
        token = request.cookies.get('x_app_token', '').strip()
    if not token:
        return jsonify({'error': 'No token'}), 400
    doc = m.app_tokens_conf.find_one({'token': token})
    if not doc:
        return jsonify({'error': 'Invalid token'}), 401
    user = m.users_conf.find_one({'_id': doc['user_id']})
    if not user:
        m.app_tokens_conf.delete_one({'_id': doc['_id']})
        return jsonify({'error': 'User not found'}), 401
    if user.get('is_banned'):
        m.app_tokens_conf.delete_many({'user_id': doc['user_id']})
        return jsonify({'error': 'Account suspended'}), 403
    user_obj = m.User(user)
    login_user(user_obj, remember=True)
    warm_user_fernet(str(user['_id']))  # Pre-derive Fernet key for notes
    return jsonify({'success': True, 'username': user['username']})
