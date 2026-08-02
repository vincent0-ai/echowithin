from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, abort, current_app
from flask_login import login_required, current_user, login_user
from bson.objectid import ObjectId
import datetime, math, json, os, hashlib, secrets
from security import limits
from config import TIME
bp = Blueprint('profile', __name__, template_folder='templates')

# PUBLIC_PROFILE_PROJECTION: explicit allowlist of fields exposed on the
# public profile page. New sensitive user fields will NOT be auto-exposed
# because this is an allowlist (not a denylist). Tier fields are included so
# get_user_tier() can compute premium status for the UI crown badge.
PUBLIC_PROFILE_PROJECTION = {
    '_id': 1, 'username': 1, 'bio': 1, 'bio_encrypted': 1,
    'profile_image_url': 1, 'join_date': 1, 'dm_privacy': 1,
    'is_admin': 1, 'account_tier': 1, 'premium_until': 1
}


@bp.route('/profile/<username>')
def profile(username):
    import main as m
    user = m.users_conf.find_one({'username': username}, PUBLIC_PROFILE_PROJECTION)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('pages.home'))
    user_id = user['_id']
    user_search_query = request.args.get('user_q', '').strip()
    user_search_results = []
    if user_search_query:
        search_projection = PUBLIC_PROFILE_PROJECTION
        safe_query = m.re.escape(user_search_query)
        user_search_cursor = m.users_conf.find(
            {'username': {'$regex': safe_query, '$options': 'i'}},
            search_projection
        ).sort('username', 1).limit(10)
        user_search_results = [candidate for candidate in user_search_cursor if str(candidate.get('_id')) != str(user_id)]
        # Decrypt bio for each search result (bio is stored encrypted at rest)
        for candidate in user_search_results:
            if candidate.get('bio_encrypted') and candidate.get('bio'):
                candidate['bio'] = m.decrypt_note(candidate['bio'], user_id=str(candidate['_id']))
    page = request.args.get('page', 1, type=int)
    posts_per_page = 5
    stats_cache_key = f"profile_stats:{user_id}"
    cached_stats = m.profile_stats_cache.get(stats_cache_key)
    if cached_stats:
        total_posts = cached_stats['total_posts']
        total_comments = cached_stats['total_comments']
    else:
        filter_query = {'author_id': user_id}
        total_posts = m.posts_conf.count_documents(filter_query)
        total_comments = m.comments_conf.count_documents({'author_id': user_id, 'is_deleted': False})
        m.profile_stats_cache[stats_cache_key] = {'total_posts': total_posts, 'total_comments': total_comments}
    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page
    posts_cache_key = f"profile_posts:{user_id}:page{page}"
    cached_posts = m.profile_posts_cache.get(posts_cache_key)
    if cached_posts:
        user_posts = cached_posts
    else:
        filter_query = {'author_id': user_id}
        user_posts_cursor = m.posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page)
        with current_app.app_context():
            user_posts = m.prepare_posts(list(user_posts_cursor))
        m.profile_posts_cache[posts_cache_key] = user_posts
    page_title = f"Profile: {user['username']}"
    page_description = f"View the profile and posts by {user['username']} on EchoWithin."
    dm_status = 'guest'
    if current_user.is_authenticated:
        if str(current_user.id) == str(user_id):
            dm_status = 'self'
        elif m.can_dm(str(current_user.id), str(user_id)):
            dm_status = 'accepted'
        else:
            pending = m.dm_permissions_conf.find_one({'requester_id': ObjectId(current_user.id), 'target_id': user_id, 'status': 'pending'})
            if pending:
                dm_status = 'pending'
            elif user.get('dm_privacy') == 'nobody':
                dm_status = 'disabled'
            else:
                dm_status = 'none'
    # Bond status
    bond_status = {'status': 'none'}
    if current_user.is_authenticated and str(current_user.id) != str(user_id):
        from blueprints.bonds import _get_bond_status_between, BOND_TYPES
        bond_status = _get_bond_status_between(ObjectId(current_user.id), user_id)
    else:
        from blueprints.bonds import BOND_TYPES
    # Decrypt bio if encrypted
    if user.get('bio_encrypted') and user.get('bio'):
        user['bio'] = m.decrypt_note(user['bio'], user_id=str(user['_id']))
    return render_template('profile.html', user=user, user_posts=user_posts, title=page_title, description=page_description, active_page='profile', page=page, total_pages=total_pages, total_posts=total_posts, total_comments=total_comments, user_achievements=m.get_active_achievements(user_id), dm_status=dm_status, bond_status=bond_status, bond_types=BOND_TYPES, user_search_query=user_search_query, user_search_results=user_search_results, profile_is_premium=(m.get_user_tier(user) == 'premium'))


@bp.route('/profile/<username>/posts')
def user_posts_page(username):
    import main as m
    user = m.users_conf.find_one({'username': username}, PUBLIC_PROFILE_PROJECTION)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('pages.home'))
    user_id = user['_id']
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10
    total_posts = m.posts_conf.count_documents({'author_id': user_id})
    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page
    user_posts_cursor = m.posts_conf.find({'author_id': user_id}).sort('timestamp', -1).skip(skip).limit(posts_per_page)
    with current_app.app_context():
        user_posts = m.prepare_posts(list(user_posts_cursor))
    page_title = f"All posts by {user['username']} - EchoWithin"
    page_description = f"Browse all community posts written by {user['username']} on EchoWithin."
    return render_template('user_posts.html', user=user, posts=user_posts, title=page_title, description=page_description, page=page, total_pages=total_pages, total_posts=total_posts, now=datetime.datetime.now(datetime.timezone.utc))


@bp.route('/api/profile/theme', methods=['POST'])
@login_required
def update_theme():
    import main as m
    data = request.get_json(silent=True) or {}
    theme = data.get('theme', 'light')
    if theme not in ('light', 'dark'):
        theme = 'light'
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'theme_preference': theme}}
    )
    # Invalidate the cached User object so the new theme applies immediately
    try:
        m.user_loader_cache.pop(f"user:{current_user.id}", None)
    except Exception:
        pass
    return jsonify(success=True)


@bp.route('/profile/<username>/settings', methods=['GET', 'POST'])
@login_required
def profile_settings(username):
    import main as m
    if username != current_user.username:
        flash("You are not authorized to access this page.", "danger")
        return redirect(url_for('pages.home'))
    user = m.users_conf.find_one({'username': username})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('pages.home'))
    if request.method == 'POST':
        update_data = {}
        new_username = request.form.get('username', '').strip()
        if new_username and new_username != username:
            import re
            if not re.match(r'^[a-zA-Z0-9_]{3,30}$', new_username):
                flash("Username must be 3-30 characters and contain only letters, numbers, and underscores.", "danger")
                return redirect(url_for('profile.profile_settings', username=username))
            if m.users_conf.find_one({'username': new_username}):
                flash("That username is already taken. Please choose a different one.", "danger")
                return redirect(url_for('profile.profile_settings', username=username))
            update_data['username'] = new_username
            m.posts_conf.update_many({'author_id': user['_id']}, {'$set': {'author': new_username}})
        raw_bio = request.form.get('bio', '').strip()
        update_data['bio'] = m.encrypt_note(raw_bio, user_id=str(user['_id'])) if raw_bio else ''
        update_data['bio_encrypted'] = True
        if request.form.get('remove_profile_picture'):
            if user.get('profile_image_public_id'):
                try:
                    m.cloudinary.uploader.destroy(user['profile_image_public_id'], resource_type="image")
                except Exception as e:
                    current_app.logger.error(f"Cloudinary avatar deletion failed for user {username}: {e}")
            update_data['profile_image_url'] = None
            update_data['profile_image_public_id'] = None
        profile_image_file = request.files.get('profile_image')
        if profile_image_file and profile_image_file.filename:
            if '.' in profile_image_file.filename and profile_image_file.filename.rsplit('.', 1)[1].lower() in m.ALLOWED_IMAGE_EXTENSIONS:
                try:
                    if user.get('profile_image_public_id') and not request.form.get('remove_profile_picture'):
                        m.cloudinary.uploader.destroy(user['profile_image_public_id'], resource_type="image")
                    upload_result = m.cloudinary.uploader.upload(profile_image_file, folder="echowithin_avatars")
                    update_data['profile_image_url'] = upload_result.get('secure_url')
                    update_data['profile_image_public_id'] = upload_result.get('public_id')
                except Exception as e:
                    current_app.logger.error(f"Cloudinary avatar upload failed for user {username}: {e}")
                    flash("There was an error uploading your profile picture.", "danger")
            else:
                flash("Invalid image format. Please use png, jpg, jpeg, or gif.", "danger")
        notification_pref = request.form.get('notification_preference')
        if notification_pref in ('immediate', 'weekly', 'none'):
            update_data['notification_preference'] = notification_pref
        dm_privacy = request.form.get('dm_privacy')
        if dm_privacy in ('everyone', 'nobody'):
            update_data['dm_privacy'] = dm_privacy
        if update_data:
            try:
                m.users_conf.update_one({'_id': user['_id']}, {'$set': update_data})
                if 'username' in update_data:
                    m.user_loader_cache.pop(f"user:{current_user.id}", None)
                    fresh_user = m.users_conf.find_one({'_id': user['_id']})
                    if fresh_user:
                        login_user(m.User(fresh_user), remember=True)
                flash('Settings updated successfully!', 'success')
            except Exception as e:
                current_app.logger.error(f"Failed to update settings for {username}: {e}")
                flash('Failed to update settings. Please try again later.', 'danger')
        redirect_username = update_data.get('username', username)
        return redirect(url_for('profile.profile_settings', username=redirect_username))
    # Decrypt bio if encrypted for settings form pre-fill
    if user.get('bio_encrypted') and user.get('bio'):
        user['bio'] = m.decrypt_note(user['bio'], user_id=str(user['_id']))
    return render_template('profile_settings.html', user=user, active_page='profile', title=f"Settings - {user.get('username')}")


@bp.route('/profile/<username>/export_data', methods=['POST'])
@login_required
@limits(calls=3, period=TIME)
def export_data(username):
    import main as m
    if username != current_user.username:
        abort(403)
    user = m.users_conf.find_one({'username': username})
    if not user:
        abort(404)
    user_id = user['_id']
    export = {
        'account': {
            'username': user.get('username'),
            'email': user.get('email'),
            'bio': m.decrypt_note(user.get('bio', ''), user_id=str(user['_id'])) if user.get('bio_encrypted') else user.get('bio', ''),
            'join_date': str(user.get('join_date', '')),
            'notification_preference': user.get('notification_preference', 'weekly'),
            'profile_image_url': user.get('profile_image_url'),
            'blog_tagline': user.get('blog_tagline', ''),
            'blog_url': user.get('blog_url', ''),
            'blog_url_label': user.get('blog_url_label', ''),
            'social_links': user.get('social_links', {}),
        },
        'posts': [],
        'comments': [],
        'personal_notes': [],
        'saved_post_ids': [str(pid) for pid in user.get('saved_posts', [])],
    }
    for post in m.posts_conf.find({'author': user.get('username')}):
        export['posts'].append({'id': str(post['_id']), 'title': post.get('title', ''), 'content': post.get('content', ''), 'created_at': str(post.get('created_at', '')), 'tags': post.get('tags', [])})
    for comment in m.comments_conf.find({'author_id': user_id}):
        export['comments'].append({'id': str(comment['_id']), 'post_id': str(comment.get('post_id', '')), 'content': comment.get('content', ''), 'created_at': str(comment.get('created_at', ''))})
    for note in m.personal_posts_conf.find({'user_id': user_id}):
        export['personal_notes'].append({'id': str(note['_id']), 'title': note.get('title', ''), 'content': m._decrypt_note_record(note), 'created_at': str(note.get('created_at', '')), 'updated_at': str(note.get('updated_at', ''))})
    data = json.dumps(export, indent=2, ensure_ascii=False)
    response = make_response(data)
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename=echowithin_data_{username}.json'
    return response


@bp.route('/profile/<username>/request_delete_code', methods=['POST'])
@login_required
@limits(calls=5, period=TIME)
def request_delete_code(username):
    import main as m
    if username != current_user.username:
        return jsonify({'error': 'Unauthorized'}), 403
    user = m.users_conf.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    is_google_only = user.get('google_signup') and not user.get('password')
    if not is_google_only:
        password = request.form.get('password', '') or (request.json or {}).get('password', '')
        if not password or not m.check_password_hash(user['password'], password):
            return jsonify({'error': 'Incorrect password. Account deletion code not sent.'}), 400
    else:
        confirm = request.form.get('confirm_delete', '') or (request.json or {}).get('confirm_delete', '')
        if confirm != 'DELETE':
            return jsonify({'error': 'Please type DELETE to confirm.'}), 400

    gen_code = str(secrets.randbelow(10**6)).zfill(6)
    hashed = hashlib.sha256(gen_code.encode()).hexdigest()
    code_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
    
    m.auth_conf.update_one(
        {'email': user['email'], 'type': 'delete_account'},
        {'$set': {
            'hashed_code': hashed,
            'code_expiry': code_expiry,
            'user_id': user['_id']
        }},
        upsert=True
    )
    
    sent = m.send_account_deletion_code(user['email'], gen_code)
    if not sent:
        return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500

    return jsonify({
        'success': True,
        'message': f'Verification code sent to {user["email"]}. Enter the code below to complete deletion.'
    })


@bp.route('/profile/<username>/delete_account', methods=['POST'])
@login_required
@limits(calls=5, period=TIME)
def delete_account(username):
    import main as m
    if username != current_user.username:
        abort(403)
    user = m.users_conf.find_one({'username': username})
    if not user:
        abort(404)

    is_google_only = user.get('google_signup') and not user.get('password')
    if not is_google_only:
        password = request.form.get('password', '')
        if not password or not m.check_password_hash(user['password'], password):
            flash('Incorrect password. Account deletion cancelled.', 'danger')
            return redirect(url_for('profile.profile_settings', username=username))
    else:
        confirm = request.form.get('confirm_delete', '')
        if confirm != 'DELETE':
            flash('Please confirm deletion. Account deletion cancelled.', 'danger')
            return redirect(url_for('profile.profile_settings', username=username))

    code = (request.form.get('verification_code') or '').strip()
    if not code:
        flash('Verification code is required to delete your account.', 'danger')
        return redirect(url_for('profile.profile_settings', username=username))

    auth_doc = m.auth_conf.find_one({'email': user['email'], 'type': 'delete_account'})
    if not auth_doc:
        flash('No deletion request found. Please request a verification code first.', 'danger')
        return redirect(url_for('profile.profile_settings', username=username))

    code_exp = auth_doc.get('code_expiry')
    if code_exp and code_exp.tzinfo is None:
        code_exp = code_exp.replace(tzinfo=datetime.timezone.utc)

    if code_exp and code_exp < datetime.datetime.now(datetime.timezone.utc):
        flash('Verification code has expired. Please request a new code.', 'danger')
        return redirect(url_for('profile.profile_settings', username=username))

    if auth_doc.get('hashed_code') != hashlib.sha256(code.encode()).hexdigest():
        flash('Invalid verification code. Please check your email and try again.', 'danger')
        return redirect(url_for('profile.profile_settings', username=username))

    m.auth_conf.delete_one({'_id': auth_doc['_id']})

    user_id = user['_id']
    app_token = request.cookies.get('x_app_token')
    if app_token:
        from security import hash_app_token
        token_hash = hash_app_token(app_token)
        m.app_tokens_conf.delete_many({'$or': [{'token_hash': token_hash}, {'token': app_token}]})
    # GDPR-complete cascade: every collection owned by this user is removed.
    m.cascade_delete_user_data(user_id)
    m.logout_user()
    flash('Your account has been permanently deleted.', 'info')
    resp = redirect(url_for('pages.dashboard'))
    resp.delete_cookie('x_app_token')
    return resp


@bp.route('/api/users/block', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_block_user():
    """Block a user: prevents them from DM-ing you, bonding with you, or interacting."""
    import main as m
    data = request.get_json(silent=True) or {}
    target_id = data.get('user_id')
    if not target_id:
        return jsonify({'error': 'User ID required'}), 400
    target_oid = ObjectId(target_id)
    my_oid = ObjectId(current_user.id)
    if target_oid == my_oid:
        return jsonify({'error': 'You cannot block yourself.'}), 400
    target = m.users_conf.find_one({'_id': target_oid}, {'username': 1})
    if not target:
        return jsonify({'error': 'User not found'}), 404
    m.users_conf.update_one(
        {'_id': my_oid},
        {'$addToSet': {'blocked_user_ids': target_oid}}
    )
    # Also revoke any accepted DM permission / pending request to/from them.
    m.dm_permissions_conf.delete_many({
        '$or': [
            {'requester_id': my_oid, 'target_id': target_oid},
            {'requester_id': target_oid, 'target_id': my_oid}
        ]
    })
    m._invalidate_badge_cache(str(current_user.id))
    return jsonify({'success': True, 'blocked': target.get('username', '')})


@bp.route('/api/users/unblock', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_unblock_user():
    """Unblock a previously blocked user."""
    import main as m
    data = request.get_json(silent=True) or {}
    target_id = data.get('user_id')
    if not target_id:
        return jsonify({'error': 'User ID required'}), 400
    target_oid = ObjectId(target_id)
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$pull': {'blocked_user_ids': target_oid}}
    )
    return jsonify({'success': True})


@bp.route('/api/users/blocked')
@login_required
@limits(calls=30, period=60)
def api_list_blocked():
    """List the current user's blocked users."""
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'blocked_user_ids': 1})
    blocked_ids = user.get('blocked_user_ids') or [] if user else []
    result = []
    for bid in blocked_ids:
        u = m.users_conf.find_one({'_id': bid}, {'username': 1, 'profile_image_url': 1})
        if u:
            result.append({'user_id': str(bid), 'username': u.get('username', ''), 'profile_image_url': u.get('profile_image_url', '')})
    return jsonify({'blocked': result})
