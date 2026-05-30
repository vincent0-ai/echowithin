from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from bson.son import SON
import datetime, os, json, csv
from io import StringIO
from urllib.parse import urljoin
from security import admin_required
bp = Blueprint('admin', __name__, template_folder='templates')


@bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    import main as m
    file_manifest = None
    manifest_path = os.path.join(current_app.static_folder, 'update-manifest.json')
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                file_manifest = json.load(f)
        except Exception as e:
            current_app.logger.error(f"Failed to read update manifest from file: {e}")
    db_manifest = m.app_updates_conf.find_one({'key': 'latest'})
    if file_manifest:
        should_sync = False
        if not db_manifest:
            should_sync = True
        else:
            file_code = file_manifest.get('versionCode', 0)
            db_code = db_manifest.get('versionCode', 0)
            if file_code > db_code:
                should_sync = True
        if should_sync:
            m.app_updates_conf.update_one({'key': 'latest'}, {'$set': {'versionCode': file_manifest.get('versionCode'), 'versionName': file_manifest.get('versionName'), 'apkUrl': file_manifest.get('apkUrl'), 'changelog': file_manifest.get('changelog')}}, upsert=True)
            db_manifest = m.app_updates_conf.find_one({'key': 'latest'})
    manifest = db_manifest or file_manifest
    return render_template('admin_dashboard.html', manifest=manifest)


@bp.route('/admin/upload_apk', methods=['POST'])
@login_required
@admin_required
def admin_upload_apk():
    import main as m
    try:
        version_code_str = request.form.get('version_code')
        version_name = request.form.get('version_name')
        changelog = request.form.get('changelog')
        apk_file = request.files.get('apk_file')
        if not version_code_str or not version_name or not changelog or not apk_file:
            flash("All fields are required!", "danger")
            return redirect(url_for('admin.admin_dashboard'))
        downloads_dir = os.path.join(current_app.static_folder, 'downloads')
        os.makedirs(downloads_dir, exist_ok=True)
        apk_path = os.path.join(downloads_dir, 'app-debug.apk')
        apk_file.save(apk_path)
        apk_url = url_for('static', filename='downloads/app-debug.apk', _external=True)
        manifest_payload = {"versionCode": int(version_code_str), "versionName": version_name, "apkUrl": apk_url, "changelog": changelog}
        manifest_path = os.path.join(current_app.static_folder, 'update-manifest.json')
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest_payload, f, indent=2)
        m.app_updates_conf.update_one({'key': 'latest'}, {'$set': {'versionCode': int(version_code_str), 'versionName': version_name, 'apkUrl': apk_url, 'changelog': changelog}}, upsert=True)
        flash("Android OTA app update published successfully!", "success")
    except Exception as e:
        current_app.logger.error(f"Failed to upload APK and write manifest: {e}")
        flash(f"Error publishing update: {str(e)}", "danger")
    return redirect(url_for('admin.admin_dashboard'))


@bp.route('/admin/metrics')
@login_required
@admin_required
def admin_metrics():
    import main as m
    try:
        days = int(request.args.get('days', 30))
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=days)
        pipeline_posts = [{'$match': {'timestamp': {'$gte': start}}}, {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}}, 'count': {'$sum': 1}}}, {'$sort': SON([('_id', 1)])}]
        posts_per_day = list(m.posts_conf.aggregate(pipeline_posts))
        pipeline_comments = [{'$match': {'created_at': {'$gte': start}, 'is_deleted': False}}, {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$created_at'}}, 'count': {'$sum': 1}}}, {'$sort': SON([('_id', 1)])}]
        comments_per_day = list(m.comments_conf.aggregate(pipeline_comments))
        total_users = m.users_conf.count_documents({'is_confirmed': True})
        active_users = m.users_conf.count_documents({'last_active': {'$gte': start}})
        top_posts = list(m.comments_conf.aggregate([
            {'$match': {'is_deleted': False, 'post_slug': {'$ne': None}}},
            {'$group': {'_id': '$post_slug', 'comment_count': {'$sum': 1}}},
            {'$sort': {'comment_count': -1}}, {'$limit': 10},
            {'$lookup': {'from': 'posts', 'localField': '_id', 'foreignField': 'slug', 'as': 'post_details'}},
            {'$unwind': '$post_details'},
            {'$project': {'slug': '$_id', 'count': '$comment_count', 'title': '$post_details.title', '_id': 0}}
        ]))
        return jsonify({'posts_per_day': posts_per_day, 'comments_per_day': comments_per_day, 'total_users': total_users, 'active_users': active_users, 'top_posts_by_comments': top_posts})
    except Exception as e:
        current_app.logger.error(f'Error building admin metrics: {e}')
        return jsonify({'error': 'failed to compute metrics'}), 500


@bp.route('/admin/active_users')
@login_required
@admin_required
def admin_active_users():
    import main as m
    try:
        five_minutes_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        active_users_cursor = m.users_conf.find({'last_active': {'$gte': five_minutes_ago}}, {'username': 1, 'last_active': 1, '_id': 0}).sort('last_active', -1)
        active_users_list = list(active_users_cursor)
        for user in active_users_list:
            user['last_active'] = user['last_active'].strftime('%H:%M %d-%m-%Y')
        return jsonify({'active_users': active_users_list})
    except Exception as e:
        current_app.logger.error(f'Error fetching real-time active users: {e}')
        return jsonify({'error': 'failed to fetch active users'}), 500


@bp.route('/admin/export_csv')
@login_required
@admin_required
def admin_export_csv():
    import main as m
    metric = request.args.get('metric', 'posts')
    days = request.args.get('days')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    now = datetime.datetime.now(datetime.timezone.utc)
    if start_date and end_date:
        try:
            start = datetime.datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
            end = datetime.datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=datetime.timezone.utc)
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
    elif days:
        days = int(days)
        start = now - datetime.timedelta(days=days)
        end = now
    else:
        start = now - datetime.timedelta(days=30)
        end = now
    output = []
    if metric == 'posts':
        posts = list(m.posts_conf.find({'timestamp': {'$gte': start, '$lte': end}}, {'_id': 1, 'title': 1, 'slug': 1, 'content': 1, 'author': 1, 'timestamp': 1, 'view_count': 1, 'likes_count': 1, 'comment_count': 1}).sort('timestamp', -1))
        output.append(['id', 'title', 'slug', 'author', 'date', 'content', 'views', 'likes', 'comments'])
        for p in posts:
            timestamp = p.get('timestamp')
            date_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else ''
            content = (p.get('content') or '').replace('\n', ' ').replace('\r', '')
            output.append([str(p.get('_id', '')), p.get('title', ''), p.get('slug', ''), p.get('author', ''), date_str, content, p.get('view_count', 0), p.get('likes_count', 0), p.get('comment_count', 0)])
    else:
        return jsonify({'error': 'unsupported metric'}), 400
    buf = StringIO()
    writer = csv.writer(buf)
    for row in output:
        writer.writerow(row)
    csv_data = buf.getvalue()
    resp = make_response(csv_data)
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename="posts_export.csv"'
    return resp


@bp.route('/admin/traffic')
@login_required
@admin_required
def admin_traffic():
    import main as m
    try:
        days = int(request.args.get('days', 30))
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=days)
        pipeline_visits = [{'$match': {'timestamp': {'$gte': start}}}, {'$group': {'_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}}, 'count': {'$sum': 1}}}, {'$sort': SON([('_id', 1)])}]
        visits_per_day = list(m.logs_conf.aggregate(pipeline_visits))
        top_ips = list(m.logs_conf.aggregate([{'$match': {'timestamp': {'$gte': start}}}, {'$group': {'_id': '$ip', 'count': {'$sum': 1}}}, {'$sort': {'count': -1}}, {'$limit': 10}]))
        return jsonify({'visits_per_day': visits_per_day, 'top_ips': top_ips})
    except Exception as e:
        current_app.logger.error(f'Error building admin traffic: {e}')
        return jsonify({'error': 'failed to compute traffic metrics'}), 500


@bp.route('/admin/system_health')
@login_required
@admin_required
def admin_system_health():
    import main as m
    health = {}
    try:
        if m._t.ts_client:
            m._t._check_typesense_health(m._t.ts_client)
            posts_docs = 0
            notes_docs = 0
            try:
                if m._t.ts_posts:
                    posts_stats = m._t._ts_collection_stats('posts')
                    posts_docs = posts_stats.get('num_documents', 0)
            except Exception:
                pass
            try:
                if m._t.ts_notes:
                    notes_stats = m._t._ts_collection_stats('personal_notes')
                    notes_docs = notes_stats.get('num_documents', 0)
            except Exception:
                pass
            health['typesense'] = {'status': 'healthy', 'posts_docs': posts_docs, 'notes_docs': notes_docs}
        else:
            health['typesense'] = {'status': 'not_configured'}
    except Exception as e:
        health['typesense'] = {'status': 'error', 'detail': str(e)}
    try:
        m.redis_cache.ping()
        info = m.redis_cache.info(section='memory')
        health['redis'] = {'status': 'healthy', 'used_memory_human': info.get('used_memory_human', '?'), 'connected_clients': m.redis_cache.info(section='clients').get('connected_clients', '?')}
    except Exception as e:
        health['redis'] = {'status': 'error', 'detail': str(e)}
    try:
        from rq import Queue as RQQueue
        redis_conn = m.redis.from_url(current_app.config.get('RQ_REDIS_URL', ''))
        q = RQQueue(connection=redis_conn)
        failed_q = RQQueue('failed', connection=redis_conn)
        health['rq'] = {'status': 'healthy', 'queued_jobs': len(q), 'failed_jobs': len(failed_q)}
    except Exception as e:
        health['rq'] = {'status': 'error', 'detail': str(e)}
    try:
        atlas_uri = os.environ.get('ATLAS_MONGODB_CONNECTION', '').strip()
        if atlas_uri:
            from pymongo import MongoClient as _MC
            atlas_client = _MC(atlas_uri, serverSelectionTimeoutMS=5000)
            meta = atlas_client['echowithin_db']['_backup_meta'].find_one({'_id': 'last_backup'})
            atlas_client.close()
            if meta and meta.get('timestamp'):
                ts = meta['timestamp']
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                age_min = (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds() / 60
                health['backup'] = {'status': 'healthy' if age_min < 420 else 'stale', 'last_backup': ts.isoformat(), 'minutes_ago': round(age_min)}
            else:
                health['backup'] = {'status': 'no_backup_found'}
        else:
            health['backup'] = {'status': 'not_configured'}
    except Exception as e:
        health['backup'] = {'status': 'error', 'detail': str(e)}
    try:
        health['communities'] = {'status': 'healthy', 'total': m.communities_conf.count_documents({}), 'pending_reports': m.community_reports_conf.count_documents({'status': 'pending'})}
    except Exception as e:
        health['communities'] = {'status': 'error', 'detail': str(e)}
    return jsonify(health)


@bp.route('/admin/reindex_typesense', methods=['POST'])
@login_required
@admin_required
def admin_reindex_typesense():
    import main as m
    if not m._t.ts_posts:
        return jsonify({'error': 'Typesense not configured'}), 500
    try:
        try:
            m.reindex_typesense_job.queue()
            return jsonify({'status': 'queued', 'message': 'Reindex queued as background job'})
        except Exception:
            m.reindex_all_posts_to_typesense()
            return jsonify({'status': 'completed', 'message': 'Reindex completed (synchronous fallback)'})
    except Exception as e:
        current_app.logger.error(f'Error reindexing: {e}')
        return jsonify({'error': 'reindex failed'}), 500


@bp.route('/admin/reindex_notes_typesense', methods=['POST'])
@login_required
@admin_required
def admin_reindex_notes_typesense():
    import main as m
    if not m._t.ts_notes:
        return jsonify({'error': 'Typesense notes not configured'}), 500
    try:
        total = m.reindex_all_notes_to_typesense()
        return jsonify({'status': 'completed', 'total': total})
    except Exception as e:
        current_app.logger.error(f'Notes Typesense reindex failed: {e}')
        return jsonify({'error': str(e)}), 500


@bp.route('/admin/posts')
@login_required
@admin_required
def admin_posts():
    import main as m
    page = request.args.get('page', 1, type=int)
    per_page = 20
    skip = (page - 1) * per_page
    total = m.posts_conf.count_documents({})
    posts = list(m.posts_conf.find({}).sort('timestamp', -1).skip(skip).limit(per_page))
    return render_template('admin_posts.html', posts=posts, page=page, total_pages=(total + per_page - 1) // per_page, total=total)


@bp.route('/admin/delete_post/<post_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_post(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if post:
        m.posts_conf.delete_one({'_id': post['_id']})
        m.comments_conf.delete_many({'post_slug': post.get('slug')})
        flash('Post deleted.', 'success')
    else:
        flash('Post not found.', 'danger')
    return redirect(url_for('admin.admin_posts'))


@bp.route('/admin/posts/pin/<post_id>', methods=['POST'])
@login_required
@admin_required
def admin_pin_post(post_id):
    import main as m
    pinned_count = m.posts_conf.count_documents({'is_pinned': True})
    if pinned_count >= 3:
        flash('Maximum 3 pinned posts allowed. Unpin one first.', 'warning')
    else:
        m.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'is_pinned': True, 'pinned_at': datetime.datetime.now(datetime.timezone.utc)}})
        flash('Post pinned.', 'success')
    return redirect(url_for('admin.admin_posts'))


@bp.route('/admin/posts/unpin/<post_id>', methods=['POST'])
@login_required
@admin_required
def admin_unpin_post(post_id):
    import main as m
    m.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$unset': {'is_pinned': '', 'pinned_at': ''}})
    flash('Post unpinned.', 'success')
    return redirect(url_for('admin.admin_posts'))


@bp.route('/admin/announcements', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_announcements():
    import main as m
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if title and content:
            m.announcements_conf.insert_one({
                'title': title, 'content': content,
                'created_at': datetime.datetime.now(datetime.timezone.utc),
                'is_pinned': False
            })
            flash('Announcement created.', 'success')
        else:
            flash('Title and content required.', 'danger')
        return redirect(url_for('admin.admin_announcements'))
    announcements = list(m.announcements_conf.find({}).sort('created_at', -1))
    return render_template('admin_announcements.html', announcements=announcements)


@bp.route('/admin/push/send', methods=['POST'])
@login_required
@admin_required
def admin_send_push():
    import main as m
    title = request.form.get('title')
    body = request.form.get('body')
    url = request.form.get('url', url_for('pages.home', _external=True))
    if not title or not body:
        flash('Title and body are required.', 'danger')
        return redirect(url_for('admin.admin_announcements'))
    try:
        m.send_admin_broadcast_push(title, body, url)
        flash('Broadcast push notification sent!', 'success')
    except Exception as e:
        current_app.logger.error(f"Failed to send broadcast push: {e}")
        flash('Failed to send push notification.', 'danger')
    return redirect(url_for('admin.admin_announcements'))


@bp.route('/admin/announcements/pin/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def pin_announcement(announcement_id):
    import main as m
    m.announcements_conf.update_one({'_id': ObjectId(announcement_id)}, {'$set': {'is_pinned': True}})
    flash('Announcement pinned.', 'success')
    return redirect(url_for('admin.admin_announcements'))


@bp.route('/admin/announcements/unpin/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def unpin_announcement(announcement_id):
    import main as m
    m.announcements_conf.update_one({'_id': ObjectId(announcement_id)}, {'$set': {'is_pinned': False}})
    flash('Announcement unpinned.', 'success')
    return redirect(url_for('admin.admin_announcements'))


@bp.route('/admin/announcements/delete/<announcement_id>', methods=['POST'])
@login_required
@admin_required
def delete_announcement(announcement_id):
    import main as m
    m.announcements_conf.delete_one({'_id': ObjectId(announcement_id)})
    flash('Announcement deleted.', 'success')
    return redirect(url_for('admin.admin_announcements'))


@bp.route('/admin/premium_users')
@login_required
@admin_required
def admin_premium_users():
    import main as m
    query = request.args.get('query')
    projection = {'password': 0, 'email_verification_token': 0, 'reset_password_token': 0}
    if query:
        users = m.users_conf.find({
            '$or': [
                {'username': {'$regex': query, '$options': 'i'}},
                {'email': {'$regex': query, '$options': 'i'}}
            ]
        }, projection).sort('username', 1)
    else:
        now = datetime.datetime.now(datetime.timezone.utc)
        users = m.users_conf.find({
            '$or': [
                {'account_tier': 'premium', 'premium_until': {'$gte': now}},
                {'account_tier': 'premium', 'premium_until': {'$exists': False}},
                {'account_tier': 'premium', 'premium_until': None}
            ]
        }, projection).sort('username', 1)
    user_list = list(users)
    for u in user_list:
        if u.get('premium_until') and u['premium_until'].tzinfo is None:
            u['premium_until'] = u['premium_until'].replace(tzinfo=datetime.timezone.utc)
    return render_template('admin_premium_users.html', title='Manage Premium Users', users=user_list, query=query)


@bp.route('/admin/premium/grant/<user_id>', methods=['POST'])
@login_required
@admin_required
def grant_premium(user_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(user_id)})
    if user:
        m.users_conf.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'account_tier': 'premium', 'premium_until': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)}}
        )
        flash(f'Premium granted to {user.get("username")} for 365 days.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.admin_premium_users'))


@bp.route('/admin/premium/revoke/<user_id>', methods=['POST'])
@login_required
@admin_required
def revoke_premium(user_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(user_id)})
    if user:
        m.users_conf.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'account_tier': 'free', 'premium_until': None}}
        )
        flash(f'Premium revoked from {user.get("username")}.', 'info')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.admin_premium_users'))


@bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    import main as m
    page = request.args.get('page', 1, type=int)
    per_page = 20
    skip = (page - 1) * per_page
    total = m.users_conf.count_documents({})
    users = list(m.users_conf.find({}).sort('join_date', -1).skip(skip).limit(per_page))
    return render_template('admin_users.html', users=users, page=page, total_pages=(total + per_page - 1) // per_page, total=total)


@bp.route('/admin/users/ban/<user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(user_id)})
    if user:
        m.users_conf.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_banned': True}})
        m.app_tokens_conf.delete_many({'user_id': ObjectId(user_id)})
        flash(f'User {user.get("username")} banned.', 'warning')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.admin_users'))


@bp.route('/admin/users/unban/<user_id>', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(user_id)})
    if user:
        m.users_conf.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_banned': False}})
        flash(f'User {user.get("username")} unbanned.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.admin_users'))


@bp.route('/admin/users/delete/<user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(user_id)})
    if user:
        m.users_conf.delete_one({'_id': ObjectId(user_id)})
        flash(f'User {user.get("username")} deleted.', 'info')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.admin_users'))


@bp.route('/admin/communities')
@login_required
@admin_required
def admin_communities():
    """Admin page to manage all communities and view reports."""
    import main as m
    page = request.args.get('page', 1, type=int)
    per_page = 25
    skip = (page - 1) * per_page
    
    # Get filter
    filter_type = request.args.get('filter', 'all')  # all, reported, banned
    query = {}
    if filter_type == 'reported':
        # Communities with pending reports
        reported_ids = m.community_reports_conf.distinct('community_id', {'status': 'pending'})
        query = {'_id': {'$in': reported_ids}}
    elif filter_type == 'banned':
        query = {'banned': True}
    
    total = m.communities_conf.count_documents(query)
    communities_list = list(m.communities_conf.find(query).sort('updated_at', -1).skip(skip).limit(per_page))
    
    # Enrich with stats
    for comm in communities_list:
        comm['member_count'] = len(comm.get('members', []))
        comm['note_count'] = m.community_notes_conf.count_documents({'community_id': comm['_id']})
        comm['pending_reports'] = m.community_reports_conf.count_documents({
            'community_id': comm['_id'],
            'status': 'pending'
        })
        comm['total_reports'] = m.community_reports_conf.count_documents({'community_id': comm['_id']})
        # Get admin username
        admin_user = m.users_conf.find_one({'_id': comm.get('admin_id')}, {'username': 1})
        comm['admin_username'] = admin_user.get('username', 'Unknown') if admin_user else 'Unknown'
    
    total_pending = m.community_reports_conf.count_documents({'status': 'pending'})
    
    return render_template('admin_communities.html',
                          communities=communities_list,
                          page=page,
                          total_pages=(total + per_page - 1) // per_page,
                          total_communities=total,
                          total_pending_reports=total_pending,
                          filter_type=filter_type)


@bp.route('/api/admin/community/<community_id>/ban', methods=['POST'])
@login_required
@admin_required
def api_admin_ban_community(community_id):
    """Ban a community — sets banned flag, removes from discover."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$set': {
            'banned': True,
            'banned_at': datetime.datetime.now(datetime.timezone.utc),
            'banned_by': ObjectId(current_user.id)
        }}
    )
    
    # Mark all pending reports for this community as reviewed
    m.community_reports_conf.update_many(
        {'community_id': comm_obj_id, 'status': 'pending'},
        {'$set': {
            'status': 'reviewed',
            'reviewed_at': datetime.datetime.now(datetime.timezone.utc),
            'reviewed_by': ObjectId(current_user.id)
        }}
    )
    
    flash(f'Community "{community.get("name")}" has been banned.', 'success')
    return redirect(url_for('admin.admin_communities'))


@bp.route('/api/admin/community/<community_id>/unban', methods=['POST'])
@login_required
@admin_required
def api_admin_unban_community(community_id):
    """Unban a previously banned community."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    m.communities_conf.update_one(
        {'_id': comm_obj_id},
        {'$unset': {'banned': '', 'banned_at': '', 'banned_by': ''}}
    )
    
    flash('Community has been unbanned.', 'success')
    return redirect(url_for('admin.admin_communities'))


@bp.route('/api/admin/community/<community_id>/delete', methods=['POST'])
@login_required
@admin_required
def api_admin_delete_community(community_id):
    """Permanently delete a community and all its data."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    community = m.communities_conf.find_one({'_id': comm_obj_id})
    if not community:
        return jsonify({'error': 'Community not found'}), 404
    
    comm_name = community.get('name', 'Unknown')
    
    # Delete all community notes
    note_ids = [n['_id'] for n in m.community_notes_conf.find({'community_id': comm_obj_id}, {'_id': 1})]
    if note_ids:
        m.community_reactions_conf.delete_many({'note_id': {'$in': note_ids}})
    m.community_notes_conf.delete_many({'community_id': comm_obj_id})
    
    # Delete all reports
    m.community_reports_conf.delete_many({'community_id': comm_obj_id})
    
    # Delete the community
    m.communities_conf.delete_one({'_id': comm_obj_id})
    
    flash(f'Community "{comm_name}" and all its data has been permanently deleted.', 'success')
    return redirect(url_for('admin.admin_communities'))


@bp.route('/api/admin/community/<community_id>/reports', methods=['GET'])
@login_required
@admin_required
def api_admin_community_reports(community_id):
    """View all reports for a specific community."""
    import main as m
    try:
        comm_obj_id = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    reports = list(m.community_reports_conf.find({'community_id': comm_obj_id}).sort('created_at', -1))
    
    result = []
    for r in reports:
        result.append({
            'id': str(r['_id']),
            'reporter_username': r.get('reporter_username', 'Unknown'),
            'reason': r.get('reason', ''),
            'details': r.get('details', ''),
            'status': r.get('status', 'pending'),
            'created_at': r['created_at'].isoformat() if r.get('created_at') else '',
            'reviewed_at': r['reviewed_at'].isoformat() if r.get('reviewed_at') else None
        })
    
    return jsonify({'success': True, 'reports': result})


@bp.route('/api/admin/reports/<report_id>/dismiss', methods=['POST'])
@login_required
@admin_required
def api_admin_dismiss_report(report_id):
    """Dismiss a specific community report."""
    import main as m
    try:
        report_obj_id = ObjectId(report_id)
    except Exception:
        return jsonify({'error': 'Invalid ID'}), 400
    
    result = m.community_reports_conf.update_one(
        {'_id': report_obj_id},
        {'$set': {
            'status': 'dismissed',
            'reviewed_at': datetime.datetime.now(datetime.timezone.utc),
            'reviewed_by': ObjectId(current_user.id)
        }}
    )
    
    if result.modified_count == 0:
        return jsonify({'error': 'Report not found'}), 404
    
    return jsonify({'success': True, 'message': 'Report dismissed'})

