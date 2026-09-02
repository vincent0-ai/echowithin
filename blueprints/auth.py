from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app, make_response
from flask_login import login_required, current_user, login_user, logout_user
from bson.objectid import ObjectId
import datetime, hashlib, secrets, os, hmac
from security import limits, warm_user_fernet, generate_user_envelope_keys, hash_app_token, create_app_token
from config import TIME

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('auth', __name__, template_folder='templates')


# --- Session Tracking Helpers ---

def _geolocate_ip(ip):
    """Approximate city/country from IP using free ip-api.com (no API key needed).
    Called once per login, well within the 45 req/min free tier limit."""
    if not ip or ip in ('127.0.0.1', '::1', 'localhost'):
        return {'city': 'Local', 'country': ''}
    try:
        import urllib.request, json as _json
        resp = urllib.request.urlopen(
            f'http://ip-api.com/json/{ip}?fields=city,country,countryCode',
            timeout=3
        )
        data = _json.loads(resp.read())
        return {
            'city': data.get('city', ''),
            'country': data.get('countryCode', ''),
            'country_name': data.get('country', '')
        }
    except Exception:
        return {'city': '', 'country': ''}


def _parse_device_info(ua):
    """Extract a human-readable device description from User-Agent string."""
    ua_lower = (ua or '').lower()
    # Browser detection
    browser = 'Unknown Browser'
    if 'echowithinapp' in ua_lower:
        browser = 'EchoWithin App'
    elif 'edg/' in ua_lower:
        browser = 'Edge'
    elif 'opr/' in ua_lower or 'opera' in ua_lower:
        browser = 'Opera'
    elif 'chrome' in ua_lower and 'safari' in ua_lower:
        browser = 'Chrome'
    elif 'firefox' in ua_lower:
        browser = 'Firefox'
    elif 'safari' in ua_lower:
        browser = 'Safari'
    # OS detection
    os_name = 'Unknown OS'
    if 'android' in ua_lower:
        os_name = 'Android'
    elif 'iphone' in ua_lower:
        os_name = 'iPhone'
    elif 'ipad' in ua_lower:
        os_name = 'iPad'
    elif 'windows' in ua_lower:
        os_name = 'Windows'
    elif 'mac os' in ua_lower or 'macintosh' in ua_lower:
        os_name = 'macOS'
    elif 'linux' in ua_lower:
        os_name = 'Linux'
    return f'{browser} on {os_name}'


def _record_login_session(user_id, login_method='password'):
    """Records a new session entry in user_sessions on every login.
    Stores IP, user agent, device info, approximate location, and a unique
    session token that is saved in the Flask session cookie for revocation."""
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    ua_string = request.headers.get('User-Agent', 'Unknown')
    device_info = _parse_device_info(ua_string)

    # Generate a unique session token and store in Flask session
    session_token = secrets.token_urlsafe(32)
    session['ew_session_token'] = session_token

    # Approximate location from IP (async-safe, non-blocking with 3s timeout)
    location = _geolocate_ip(ip)

    try:
        m.user_sessions_conf.insert_one({
            'user_id': ObjectId(user_id),
            'session_token': session_token,
            'ip_address': ip,
            'user_agent': ua_string,
            'device_info': device_info,
            'location': location,
            'login_method': login_method,
            'logged_in_at': now,
            'last_active': now,
        })
    except Exception as e:
        current_app.logger.warning(f"Failed to record login session: {e}")

    # Update last_login on user document
    try:
        m.users_conf.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': now, 'last_login_ip': ip}}
        )
    except Exception:
        pass


def _user_is_guest(user):
    if not user or not user.is_authenticated:
        return False
    return getattr(user, 'is_guest', False) or session.get('is_guest_tour', False)


@bp.route('/register', methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def register():
    import main as m
    if current_user.is_authenticated and not _user_is_guest(current_user):
        return redirect(url_for('pages.home'))

    next_url = request.args.get('next')
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not email or not password:
            flash("All fields are required", "danger")
            return redirect(url_for('auth.register', next=next_url) if next_url else url_for('auth.register'))
        if len(username) < 2 or len(password) < 6:
            flash("Username must be at least 2 characters and password at least 6 characters.", "danger")
            return redirect(url_for('auth.register', next=next_url) if next_url else url_for('auth.register'))

        is_guest_session = _user_is_guest(current_user)
        guest_id = ObjectId(current_user.id) if is_guest_session else None

        # Check existing user credentials (excluding current guest user if converting)
        dup_query = {"$or": [{"email": email}, {"username": username}]}
        if guest_id:
            dup_query["_id"] = {"$ne": guest_id}

        if m.users_conf.find_one(dup_query):
            flash("Email or username already exists.", "danger")
            return redirect(url_for('auth.register', next=next_url) if next_url else url_for('auth.register'))

        hashed_password = m.generate_password_hash(password)

        if is_guest_session and guest_id:
            m.users_conf.update_one(
                {'_id': guest_id},
                {'$set': {
                    "username": username,
                    "email": email,
                    "password": hashed_password,
                    "is_confirmed": False,
                    "guest_expires_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
                }}
            )
        else:
            envelope_keys = generate_user_envelope_keys()
            m.users_conf.insert_one({
                "username": username,
                "email": email,
                "password": hashed_password,
                "is_confirmed": False,
                "join_date": datetime.datetime.now(datetime.timezone.utc),
                "notification_preference": 'weekly',
                **envelope_keys
            })

        gen_code = str(secrets.randbelow(10**6)).zfill(6)
        hashed = hashlib.sha256(gen_code.encode()).hexdigest()
        code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
        m.auth_conf.update_one({'email': email}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry, 'attempt_count': 0}}, upsert=True)
        m.send_code(email, gen_code)

        flash("Confirmation code sent to your email. Please verify to activate your account.", "info")
        return redirect(url_for('auth.confirm', email=email, next=next_url) if next_url else url_for('auth.confirm', email=email))
    return render_template("auth.html", active_page='register', form='register')


@bp.route("/confirm/<email>", methods=['GET', 'POST'])
@limits(calls=20, period=60)
def confirm(email):
    import main as m
    next_url = request.args.get('next')
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
                MAX_CONFIRM_ATTEMPTS = 10
                attempts = int(hashed_obj.get('attempt_count', 0) or 0)
                if attempts >= MAX_CONFIRM_ATTEMPTS:
                    error = 'Too many failed attempts. Please request a new code.'
                else:
                    code_exp = hashed_obj.get('code_expiry')
                    if code_exp and code_exp.tzinfo is None:
                        code_exp = code_exp.replace(tzinfo=datetime.timezone.utc)
                    if code_exp and code_exp < datetime.datetime.now(datetime.timezone.utc):
                        error = 'This confirmation code has expired.'
                    elif hmac.compare_digest(hashed_obj['hashed_code'], hashlib.sha256(code.encode()).hexdigest()):
                        m.users_conf.update_one(
                            {"email": email},
                            {"$set": {
                                "is_confirmed": True,
                                "is_guest": False,
                                "guest_expires_at": None
                            }}
                        )
                        m.auth_conf.delete_one({"email": email})
                        user_data = m.users_conf.find_one({"email": email})
                        if user_data:
                            user_obj = m.User(user_data)
                            login_user(user_obj, remember=True)
                            session.pop('is_guest_tour', None)
                            warm_user_fernet(str(user_data['_id']))
                            _record_login_session(str(user_data['_id']), 'password')
                        flash("Email confirmed! Your account is active and ready.", "success")
                        if next_url and m.is_safe_url(next_url):
                            return redirect(next_url)
                        return redirect(url_for('notes.personal_space'))
                    else:
                        m.auth_conf.update_one({'email': email}, {'$inc': {'attempt_count': 1}})
                        error = 'Invalid verification code.'
    return render_template("confirm.html", email=email, error=error)


@bp.route("/login", methods=['GET', 'POST'])
@limits(calls=15, period=TIME)
def login():
    import main as m
    if current_user.is_authenticated and not _user_is_guest(current_user):
        return redirect(url_for('pages.home'))

    next_url = request.args.get('next')
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        remember = request.form.get("remember") in ("true", "on", "1", "True")
        if not username or not password:
            flash("Username and password required.", "danger")
            return redirect(url_for('auth.login'))
        user_data = m.users_conf.find_one({"$or": [{"email": username}, {"username": username}]})
        if user_data:
            if not user_data.get('is_confirmed'):
                gen_code = str(secrets.randbelow(10**6)).zfill(6)
                hashed = hashlib.sha256(gen_code.encode()).hexdigest()
                code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
                m.auth_conf.update_one({'email': user_data['email']}, {'$set': {'hashed_code': hashed, 'code_expiry': code_expiry, 'attempt_count': 0}}, upsert=True)
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
                _record_login_session(str(user_data['_id']), 'password')
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
        _record_login_session(str(user['_id']), 'google')
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
        envelope_keys = generate_user_envelope_keys()
        m.users_conf.insert_one({
            'username': username,
            'email': email,
            'password': None,
            'is_confirmed': True,
            'is_admin': False,
            'join_date': datetime.datetime.now(datetime.timezone.utc),
            'notification_preference': 'weekly',
            'google_signup': True,
            **envelope_keys
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
        _record_login_session(str(user['_id']), 'google')
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
        # SECURITY: delete by hash (with legacy plaintext fallback).
        token_hash = hash_app_token(app_token)
        m.app_tokens_conf.delete_many({'$or': [{'token_hash': token_hash}, {'token': app_token}]})
    if current_user.is_authenticated:
        if _user_is_guest(current_user):
            m.purge_guest_user_data(str(current_user.id))
        m.app_tokens_conf.delete_many({'user_id': ObjectId(current_user.id)})
        # Remove the current session record
        token = session.get('ew_session_token')
        if token:
            try:
                m.user_sessions_conf.delete_one({'session_token': token})
            except Exception:
                pass
    logout_user()
    session.pop('oauth_state', None)
    session.pop('oauth_platform', None)
    session.pop('is_guest_tour', None)
    session.pop('ew_session_token', None)
    flash('You have been logged out.', 'info')
    resp = redirect(url_for('pages.dashboard'))
    resp.delete_cookie('x_app_token')
    return resp


@bp.route('/forgot_password', methods=['GET', 'POST'])
@limits(calls=10, period=TIME)
def forgot_password():
    import main as m
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
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
            flash("If an account with that email exists, we've sent a password reset link to your email.", "info")
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
    if not user_to_update:
        flash("The user account associated with this reset token no longer exists.", "danger")
        return redirect(url_for('auth.login'))
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
                _record_login_session(str(user['_id']), 'mobile_app')
                _app_token = create_app_token(user['_id'])
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
    # SECURITY: match by hashed token with legacy plaintext fallback.
    token_hash = hash_app_token(token)
    doc = m.app_tokens_conf.find_one({'$or': [{'token_hash': token_hash}, {'token': token}]})
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
    _record_login_session(str(user['_id']), 'app_token')
    return jsonify({'success': True, 'username': user['username']})


@bp.route('/tour')
@limits(calls=10, period=60)
def start_guest_tour():
    """Start an instant, isolated guest tour session with pre-filled demo data."""
    import main as m
    
    if _user_is_guest(current_user):
        flash("Resuming your interactive tour session!", "info")
        return redirect(url_for('notes.personal_space'))
    
    if current_user.is_authenticated:
        flash("You are already logged into an active account.", "info")
        return redirect(url_for('pages.home'))
        
    now = datetime.datetime.now(datetime.timezone.utc)
    guest_token = secrets.token_hex(4)
    username = f"Explorer_{guest_token}"
    email = f"guest_{guest_token}@tour.echowithin.internal"
    
    envelope_keys = generate_user_envelope_keys()
    
    guest_doc = {
        'username': username,
        'email': email,
        'password': m.generate_password_hash(secrets.token_urlsafe(16)),
        'is_confirmed': True,
        'is_guest': True,
        'guest_expires_at': now + datetime.timedelta(minutes=20),
        'join_date': now,
        'notification_preference': 'weekly',
        **envelope_keys
    }
    
    res = m.users_conf.insert_one(guest_doc)
    guest_id = res.inserted_id
    guest_id_str = str(guest_id)
    
    # Warm up Fernet encryption keys for guest
    warm_user_fernet(guest_id_str)
    
    # --- 1. Pre-fill Demo Notes ---
    def _insert_demo_note(content, reference='', tags=None):
        g_oid = ObjectId(guest_id_str)
        enc = m.encrypt_note(content, user_id=guest_id_str)
        res = m.personal_posts_conf.insert_one({
            'user_id': g_oid,
            'content_owner_id': g_oid,
            'content': enc,
            'encrypted': True,
            'reference': reference,
            'tags': tags or [],
            'created_at': now
        })
        return str(res.inserted_id)

    note1_content = (
        "# Welcome to EchoWithin\n\n"
        "This is your private, end-to-end encrypted personal space.\n\n"
        "### Key Features to Explore:\n"
        "* **Encryption at Rest**: Notes are secured with per-user Fernet envelope keys.\n"
        "* **App Lock PIN**: Click Set Up PIN to lock confidential notes.\n"
        "* **Surprise Note Sharing**: Share themed notes with music and animations.\n"
        "* **Rich Formatting**: Markdown, tags, checklists, and code blocks."
    )
    _insert_demo_note(note1_content, reference="Getting Started", tags=["Welcome", "Privacy", "Guide"])
    
    note2_content = (
        "## Sensitive Note Demo\n\n"
        "This note demonstrates confidential storage. Try clicking the Lock button or setting an App Lock PIN."
    )
    n2_id = _insert_demo_note(note2_content, reference="Confidential", tags=["PIN-Protected", "Security"])
    m.personal_posts_conf.update_one({'_id': ObjectId(n2_id)}, {'$set': {'is_locked': True}})
    
    note3_content = (
        "## Surprise Link Demo Note\n\n"
        "Surprise a friend or partner. Turn any note into an interactive surprise link complete with music, animations, and photos."
    )
    _insert_demo_note(note3_content, reference="Surprise Idea", tags=["Surprise", "Sharing"])
    
    # --- 2. Pre-fill Per-Guest Disposable Demo Partner & Active Bond ---
    p_env = generate_user_envelope_keys()
    p_res = m.users_conf.insert_one({
        'username': f"Maya_DemoPartner_{guest_token}",
        'email': f"maya_{guest_token}@tour.echowithin.internal",
        'password': m.generate_password_hash(secrets.token_urlsafe(16)),
        'is_confirmed': True,
        'is_demo_bot': True,
        'is_guest': True,
        'guest_expires_at': now + datetime.timedelta(minutes=20),
        'join_date': now,
        **p_env
    })
    partner_id = p_res.inserted_id
        
    section_names = ['mood','qotd','journal','goals','habits','insights','album','bucketlist','recommendations','pulses','countdowns']
    init_sections = {s: now for s in section_names}
    bond_res = m.bonds_conf.insert_one({
        'user_a_id': guest_id,
        'user_b_id': partner_id,
        'status': 'active',
        'bond_type': 'friendship',
        'label': 'Shared Bond Space (Best Friends)',
        'created_at': now - datetime.timedelta(days=14),
        'accepted_at': now - datetime.timedelta(days=14),
        'streak_count': 5,
        'last_streak_date': now,
        'section_activity': init_sections,
        'last_viewed': {str(guest_id): dict(init_sections), str(partner_id): dict(init_sections)}
    })
    bond_id = bond_res.inserted_id
    bond_id_str = str(bond_id)
    
    # Demo Goal
    enc_goal_title = m.encrypt_bond_data("Save $1,000 for Summer Getaway", bond_id_str)
    enc_goal_desc = m.encrypt_bond_data("Joint savings fund for our vacation.", bond_id_str)
    m.bond_goals_conf.insert_one({
        'bond_id': bond_id,
        'title': enc_goal_title,
        'description': enc_goal_desc,
        'category': 'Travel',
        'target_value': 1000,
        'current_value': 450,
        'unit': '$',
        'proposed_by': partner_id,
        'status': 'active',
        'created_at': now - datetime.timedelta(days=7),
        'encrypted': True,
        'milestones': [
            {'title': 'Book hotel flights', 'completed': True},
            {'title': 'Reserve rental car', 'completed': False}
        ],
        'check_ins': [
            {'user_id': str(partner_id), 'value': 250, 'note': 'Saved initial deposit', 'at': (now - datetime.timedelta(days=5)).isoformat()},
            {'user_id': guest_id_str, 'value': 200, 'note': 'Added my contribution!', 'at': (now - datetime.timedelta(days=2)).isoformat()}
        ]
    })
    
    # Demo Journal Entry
    enc_journal = m.encrypt_bond_data("Looking forward to exploring new places together!", bond_id_str)
    m.bond_journal_conf.insert_one({
        'bond_id': bond_id,
        'user_id': partner_id,
        'content': enc_journal,
        'encrypted': True,
        'created_at': now - datetime.timedelta(days=1)
    })
    
    # Demo Habit
    enc_habit = m.encrypt_bond_data("30 min Evening Walk Together", bond_id_str)
    m.bond_habits_conf.insert_one({
        'bond_id': bond_id,
        'title': enc_habit,
        'encrypted': True,
        'created_by': partner_id,
        'created_at': now - datetime.timedelta(days=3),
        'archived': False,
        'logs': {
            now.date().isoformat(): {
                str(partner_id): {'completed': True, 'completed_at': now}
            }
        }
    })
    
    # --- 3. Pre-fill Demo Message Thread & DM Permission ---
    bot_username = f"Maya_DemoPartner_{guest_token}"
    m.dm_permissions_conf.insert_one({
        'requester_id': guest_id,
        'target_id': partner_id,
        'status': 'accepted',
        'created_at': now,
        'updated_at': now
    })
    m.direct_messages_conf.insert_one({
        'sender_id': partner_id,
        'recipient_id': guest_id,
        'sender_username': bot_username,
        'recipient_username': username,
        'content': "Welcome to EchoWithin tour mode. Feel free to explore our shared Bond space, notes, and features!",
        'timestamp': now - datetime.timedelta(minutes=5),
        'is_read': False,
        'encrypted': False
    })
    
    # Authenticate guest
    guest_doc['_id'] = guest_id
    user_obj = m.User(guest_doc)
    login_user(user_obj)
    session['is_guest_tour'] = True
    
    flash("Welcome to Tour Mode. You are in an isolated demo session.", "success")
    return redirect(url_for('notes.personal_space'))


# --- Active Sessions API ---

def _format_session_dt(val):
    """Format a datetime value as ISO string with Z suffix per Rule 7."""
    if val is None:
        return None
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=datetime.timezone.utc)
        return val.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    return str(val)


@bp.route('/api/sessions')
@login_required
@csrf_exempt
def api_list_sessions():
    """List all active sessions for the current user."""
    import main as m
    if _user_is_guest(current_user):
        return jsonify({'sessions': [], 'last_login': None})

    current_token = session.get('ew_session_token', '')
    sessions_cursor = m.user_sessions_conf.find(
        {'user_id': ObjectId(current_user.id)}
    ).sort('last_active', -1)

    sessions = []
    for s in sessions_cursor:
        loc = s.get('location') or {}
        location_str = ''
        if loc.get('city') and loc.get('country'):
            location_str = f"{loc['city']}, {loc['country']}"
        elif loc.get('city'):
            location_str = loc['city']
        elif loc.get('country'):
            location_str = loc['country']

        sessions.append({
            'id': str(s['_id']),
            'device_info': s.get('device_info', 'Unknown device'),
            'location': location_str,
            'ip_address': s.get('ip_address', ''),
            'login_method': s.get('login_method', 'unknown'),
            'logged_in_at': _format_session_dt(s.get('logged_in_at')),
            'last_active': _format_session_dt(s.get('last_active')),
            'is_current': s.get('session_token', '') == current_token
        })

    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    last_login = _format_session_dt(user_doc.get('last_login')) if user_doc else None

    return jsonify({'sessions': sessions, 'last_login': last_login})


@bp.route('/api/sessions/revoke', methods=['POST'])
@login_required
@csrf_exempt
def api_revoke_session():
    """Revoke a specific session by its _id. Cannot revoke the current session."""
    import main as m
    data = request.get_json() or {}
    session_id = data.get('session_id', '').strip()
    if not session_id:
        return jsonify({'error': 'session_id is required'}), 400

    try:
        doc = m.user_sessions_conf.find_one({
            '_id': ObjectId(session_id),
            'user_id': ObjectId(current_user.id)
        })
    except Exception:
        return jsonify({'error': 'Invalid session ID'}), 400

    if not doc:
        return jsonify({'error': 'Session not found'}), 404

    current_token = session.get('ew_session_token', '')
    if doc.get('session_token') == current_token:
        return jsonify({'error': 'Cannot revoke your current session. Use logout instead.'}), 400

    m.user_sessions_conf.delete_one({'_id': doc['_id']})
    return jsonify({'success': True})


@bp.route('/api/sessions/revoke_all', methods=['POST'])
@login_required
@csrf_exempt
def api_revoke_all_sessions():
    """Revoke all sessions except the current one."""
    import main as m
    current_token = session.get('ew_session_token', '')
    result = m.user_sessions_conf.delete_many({
        'user_id': ObjectId(current_user.id),
        'session_token': {'$ne': current_token}
    })
    return jsonify({'success': True, 'revoked_count': result.deleted_count})


# --- Session Validation (before_app_request) ---
# When a user revokes a session from another device, we need to force-logout
# the revoked session on its next request. This hook checks if the session
# token still exists in MongoDB. Uses Redis TTL cache (60s) to minimize DB hits.

@bp.before_app_request
def _validate_session_token():
    """Check that the current session token hasn't been revoked.
    Only runs for authenticated non-guest users."""
    if not current_user.is_authenticated:
        return
    if _user_is_guest(current_user):
        return

    import main as m
    token = session.get('ew_session_token')

    # If restored via remember-me cookie without token in session, link to most recent device session
    if not token:
        ua_string = request.headers.get('User-Agent', 'Unknown')
        latest_sess = m.user_sessions_conf.find_one(
            {'user_id': ObjectId(current_user.id), 'user_agent': ua_string},
            sort=[('last_active', -1)]
        )
        if latest_sess and latest_sess.get('session_token'):
            token = latest_sess['session_token']
            session['ew_session_token'] = token

    if not token:
        return

    # Check revocation cache
    cache_key = f"sess_valid:{token}"
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached == b'0':
                # Session was revoked — force logout
                logout_user()
                session.clear()
                flash('Your session was ended from another device.', 'info')
                return redirect(url_for('auth.login'))
        except Exception:
            pass

    # Check MongoDB if valid status is not cached
    if not (m.redis_cache and m.redis_cache.get(cache_key) == b'1'):
        doc = m.user_sessions_conf.find_one({'session_token': token}, {'_id': 1})
        if doc:
            if m.redis_cache:
                try:
                    m.redis_cache.setex(cache_key, 60, '1')
                except Exception:
                    pass
        else:
            if m.redis_cache:
                try:
                    m.redis_cache.setex(cache_key, 300, '0')
                except Exception:
                    pass
            logout_user()
            session.clear()
            flash('Your session was ended from another device.', 'info')
            return redirect(url_for('auth.login'))

    # Update last_active periodically (every 5 min) to keep session TTL fresh
    _update_key = f"sess_la:{token}"
    should_update = True
    if m.redis_cache:
        try:
            if m.redis_cache.get(_update_key):
                should_update = False
            else:
                m.redis_cache.setex(_update_key, 300, '1')
        except Exception:
            pass

    if should_update:
        try:
            m.user_sessions_conf.update_one(
                {'session_token': token},
                {'$set': {'last_active': datetime.datetime.now(datetime.timezone.utc)}}
            )
        except Exception:
            pass
        if m.redis_cache:
            try:
                m.redis_cache.setex(cache_key, 60, '0')
            except Exception:
                pass
        logout_user()
        session.clear()
        flash('Your session was ended from another device.', 'info')
        return redirect(url_for('auth.login'))
