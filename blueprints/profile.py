from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, abort, current_app
from flask_login import login_required, current_user, login_user
from bson.objectid import ObjectId
import datetime, math, json, os
from security import limits
from config import TIME
bp = Blueprint('profile', __name__, template_folder='templates')


@bp.route('/profile/<username>')
def profile(username):
    import main as m
    user = m.users_conf.find_one({'username': username}, {'password': 0, 'email': 0, 'notification_preference': 0, 'last_active': 0})
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('pages.home'))
    user_id = user['_id']
    user_search_query = request.args.get('user_q', '').strip()
    user_search_results = []
    if user_search_query:
        search_projection = {'password': 0, 'email': 0, 'notification_preference': 0, 'last_active': 0}
        safe_query = m.re.escape(user_search_query)
        user_search_cursor = m.users_conf.find(
            {'username': {'$regex': safe_query, '$options': 'i'}},
            search_projection
        ).sort('username', 1).limit(10)
        user_search_results = [candidate for candidate in user_search_cursor if str(candidate.get('_id')) != str(user_id)]
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
        from blueprints.bonds import _get_bond_status_between
        bond_status = _get_bond_status_between(ObjectId(current_user.id), user_id)
    return render_template('profile.html', user=user, user_posts=user_posts, title=page_title, description=page_description, active_page='profile', page=page, total_pages=total_pages, total_posts=total_posts, total_comments=total_comments, user_achievements=m.get_active_achievements(user_id), dm_status=dm_status, bond_status=bond_status, user_search_query=user_search_query, user_search_results=user_search_results, profile_is_premium=(m.get_user_tier(user) == 'premium'))


@bp.route('/profile/<username>/posts')
def user_posts_page(username):
    import main as m
    user = m.users_conf.find_one({'username': username}, {'password': 0, 'email': 0, 'notification_preference': 0, 'last_active': 0})
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
        update_data['bio'] = request.form.get('bio', '').strip()
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
            'bio': user.get('bio', ''),
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
    user_id = user['_id']
    app_token = request.cookies.get('x_app_token')
    if app_token:
        m.app_tokens_conf.delete_one({'token': app_token})
    m.app_tokens_conf.delete_many({'user_id': user_id})
    m.fcm_tokens_conf.delete_many({'user_id': user_id})
    m.push_subscriptions_conf.delete_many({'user_id': user_id})
    m.personal_posts_conf.delete_many({'user_id': user_id})
    m.note_shares_conf.delete_many({'$or': [{'owner_id': user_id}, {'collaborator_ids': user_id}]})
    m.dm_permissions_conf.delete_many({'$or': [{'requester_id': user_id}, {'target_id': user_id}]})
    m.direct_messages_conf.delete_many({'$or': [{'sender_id': user_id}, {'recipient_id': user_id}]})
    m.scheduled_messages_conf.delete_many({'sender_id': user_id})
    m.note_versions_conf.delete_many({'author_id': user_id})
    m.note_discussions_conf.delete_many({'author_id': user_id})
    m.newsletter_conf.delete_many({'email': user.get('email')})
    m.communities_conf.update_many({'admin_id': user_id}, {'$set': {'admin_id': None}})
    m.communities_conf.update_many({}, {'$pull': {'members': user_id, 'moderators': user_id}})
    m.community_notes_conf.delete_many({'author_id': user_id})
    m.community_reactions_conf.delete_many({'user_id': user_id})
    m.users_conf.delete_one({'_id': user_id})
    m.logout_user()
    flash('Your account has been permanently deleted. We are sorry to see you go.', 'info')
    resp = redirect(url_for('pages.dashboard'))
    resp.delete_cookie('x_app_token')
    return resp
