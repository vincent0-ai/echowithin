from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, send_from_directory, send_file, abort, current_app
from flask_login import login_required, current_user
import datetime, os, json, hashlib, math, re
from urllib.parse import urlparse, urljoin
from bson.objectid import ObjectId
from security import limits
from config import get_env_variable

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('pages', __name__, template_folder='templates')


@bp.route('/')
@bp.route('/dashboard')
def dashboard():
    import main as m
    page_title = "EchoWithin - Secure Notes, Collaboration & Community"
    page_description = "EchoWithin is a modern platform for secure private notes, collaborative idea sharing, and surprise themed notes with photos and music. Join our community to organize your thoughts and let your voice echo within."
    meta_image = url_for('static', filename='og-image.png', _external=True)
    if current_user.is_authenticated:
        return redirect(url_for('pages.home'))
    return render_template("dashboard.html", active_page='dashboard', title=page_title, description=page_description, meta_image=meta_image)


@bp.route('/home')
@login_required
def home():
    import main as m
    page_title = f"Home - {current_user.username}"
    page_description = "Your personal dashboard on EchoWithin. Create new posts and engage with the community."
    cached_community = m.community_stats_cache.get('community_stats')
    if cached_community:
        total_members = cached_community['total_members']
        total_posts = cached_community['total_posts']
        most_active_member = cached_community['most_active_member']
        active_now = cached_community.get('active_now', 1)
    else:
        total_members = m.users_conf.count_documents({'is_confirmed': True})
        # OPTIMIZATION: Use estimated_document_count for posts (O(1) metadata lookup vs O(N) scan)
        total_posts = m.posts_conf.estimated_document_count()
        most_active_pipeline = [
            {"$group": {"_id": "$author", "post_count": {"$sum": 1}}},
            {"$sort": {"post_count": -1}},
            {"$limit": 1}
        ]
        most_active_result = list(m.posts_conf.aggregate(most_active_pipeline))
        most_active_member = most_active_result[0] if most_active_result else None
        five_minutes_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        active_now = m.users_conf.count_documents({'last_active': {'$gte': five_minutes_ago}})
        active_now = max(1, active_now)
        m.community_stats_cache['community_stats'] = {'total_members': total_members, 'total_posts': total_posts, 'most_active_member': most_active_member, 'active_now': active_now}
    hot_posts = []
    cache_key = 'home_hot_posts'
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached:
                hot_posts = json.loads(cached)
        except Exception:
            pass
    if not hot_posts:
        try:
            thirty_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
            hot_posts_pipeline = [
                {'$match': {'timestamp': {'$gte': thirty_days_ago}}},
                {'$lookup': {'from': 'comments', 'let': {'post_slug': '$slug'}, 'pipeline': [{'$match': {'$expr': {'$eq': ['$post_slug', '$$post_slug']}, 'is_deleted': {'$ne': True}}}, {'$count': 'count'}], 'as': 'comment_data'}},
                {'$addFields': {'comment_count': {'$ifNull': [{'$arrayElemAt': ['$comment_data.count', 0]}, 0]}, 'likes_safe': {'$ifNull': ['$likes_count', 0]}, 'shares_safe': {'$ifNull': ['$share_count', 0]}, 'views_safe': {'$ifNull': ['$view_count', 0]}, 'age_in_hours': {'$divide': [{'$subtract': ["$$NOW", '$timestamp']}, 3600000]}}},
                {'$addFields': {'raw_engagement': {'$add': [{'$multiply': ['$comment_count', m.ENGAGEMENT_WEIGHTS['comment']]}, {'$multiply': ['$likes_safe', m.ENGAGEMENT_WEIGHTS['reaction']]}, {'$multiply': ['$shares_safe', m.ENGAGEMENT_WEIGHTS['share']]}, {'$multiply': ['$views_safe', m.ENGAGEMENT_WEIGHTS['view']]}]}, 'recency_boost': {'$switch': {'branches': [{'case': {'$lt': ['$age_in_hours', 2]}, 'then': 1.5}, {'case': {'$lt': ['$age_in_hours', 6]}, 'then': 1.2}], 'default': 1.0}}}},
                {'$addFields': {'engagement_score': {'$multiply': [{'$ln': {'$add': ['$raw_engagement', 1]}}, 10]}}},
                {'$addFields': {'hot_score': {'$multiply': ['$recency_boost', {'$divide': [{'$add': ['$engagement_score', 1]}, {'$pow': [{'$add': ['$age_in_hours', 8]}, 1.2]}]}]}}},
                {'$sort': {'hot_score': -1}},
                {'$limit': 20}
            ]
            hot_posts_candidates = list(m.posts_conf.aggregate(hot_posts_pipeline))
            author_count = {}
            hot_posts = []
            for post in hot_posts_candidates:
                author_id = str(post.get('author_id', ''))
                author_count[author_id] = author_count.get(author_id, 0) + 1
                if author_count[author_id] <= 2:
                    hot_posts.append(post)
                    if len(hot_posts) >= 5:
                        break
            with current_app.app_context():
                hot_posts = m.prepare_posts(hot_posts)
            if len(hot_posts) == 0:
                latest_posts_cursor = m.posts_conf.find({}).sort('timestamp', -1).limit(5)
                with current_app.app_context():
                    hot_posts = m.prepare_posts(list(latest_posts_cursor))
            if m.redis_cache and hot_posts:
                try:
                    m.redis_cache.setex(cache_key, 120, json.dumps(hot_posts, default=str))
                except Exception:
                    pass
        except Exception as e:
            current_app.logger.error(f"Failed to calculate hot posts: {e}")
    def _mix_home_posts(hot_posts_list, fresh_posts_list, max_posts=5, max_posts_per_author=2):
        mixed_posts = []
        seen_post_ids = set()
        author_counts = {}
        def try_add_post(post_doc):
            post_id = str(post_doc.get('_id') or post_doc.get('id') or '')
            if not post_id or post_id in seen_post_ids:
                return
            author_id = str(post_doc.get('author_id') or '')
            if author_id and author_counts.get(author_id, 0) >= max_posts_per_author:
                return
            mixed_posts.append(post_doc)
            seen_post_ids.add(post_id)
            if author_id:
                author_counts[author_id] = author_counts.get(author_id, 0) + 1
        hot_index = 0
        fresh_index = 0
        while len(mixed_posts) < max_posts and (hot_index < len(hot_posts_list) or fresh_index < len(fresh_posts_list)):
            if hot_index < len(hot_posts_list):
                try_add_post(hot_posts_list[hot_index])
                hot_index += 1
                if len(mixed_posts) >= max_posts:
                    break
            if fresh_index < len(fresh_posts_list):
                try_add_post(fresh_posts_list[fresh_index])
                fresh_index += 1
                if len(mixed_posts) >= max_posts:
                    break
        for post_doc in hot_posts_list[hot_index:]:
            if len(mixed_posts) >= max_posts:
                break
            try_add_post(post_doc)
        for post_doc in fresh_posts_list[fresh_index:]:
            if len(mixed_posts) >= max_posts:
                break
            try_add_post(post_doc)
        return mixed_posts[:max_posts]
    fresh_posts = []
    fresh_cache_key = 'home_fresh_posts'
    if m.redis_cache:
        try:
            cached_fresh = m.redis_cache.get(fresh_cache_key)
            if cached_fresh:
                fresh_posts = json.loads(cached_fresh)
        except Exception:
            pass
    if not fresh_posts:
        try:
            recent_cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
            recent_posts_cursor = m.posts_conf.find({'timestamp': {'$gte': recent_cutoff}}).sort('timestamp', -1).limit(10)
            with current_app.app_context():
                fresh_posts = m.prepare_posts(list(recent_posts_cursor))
            if m.redis_cache and fresh_posts:
                try:
                    m.redis_cache.setex(fresh_cache_key, 30, json.dumps(fresh_posts, default=str))
                except Exception:
                    pass
        except Exception as e:
            current_app.logger.debug(f"Failed to load fresh homepage posts: {e}")
    hot_posts = _mix_home_posts(hot_posts, fresh_posts)
    user_oid = ObjectId(current_user.id)
    user_id_str = str(current_user.id)
    # PERF: Cache per-user counts in Redis (60s TTL) to avoid count_documents on every load
    note_count = None
    user_community_count = None
    if m.redis_cache:
        try:
            cached_nc = m.redis_cache.get(f'home_note_count:{user_id_str}')
            cached_cc = m.redis_cache.get(f'home_community_count:{user_id_str}')
            if cached_nc is not None:
                note_count = int(cached_nc)
            if cached_cc is not None:
                user_community_count = int(cached_cc)
        except Exception:
            pass
    if note_count is None:
        note_count = m.personal_posts_conf.count_documents({'user_id': user_oid})
        if m.redis_cache:
            try:
                m.redis_cache.setex(f'home_note_count:{user_id_str}', 60, str(note_count))
            except Exception:
                pass
    if user_community_count is None:
        user_community_count = m.communities_conf.count_documents({'members': user_oid})
        if m.redis_cache:
            try:
                m.redis_cache.setex(f'home_community_count:{user_id_str}', 60, str(user_community_count))
            except Exception:
                pass
    return render_template("home.html", username=current_user.username, active_page='home', title=page_title, description=page_description, meta_image=url_for('static', filename='og-image.png', _external=True), total_members=total_members, total_posts=total_posts, most_active_member=most_active_member, hot_posts=hot_posts, note_count=note_count, user_community_count=user_community_count, active_now=active_now)


@bp.route('/search')
def search():
    import main as m
    query = request.args.get('q', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    tags_filter = request.args.getlist('tags')
    author_filter = request.args.get('author')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    sort = request.args.get('sort', 'relevance')
    results = []
    total = 0
    if m._t.ts_posts and (query or tags_filter or author_filter or date_from or date_to):
        try:
            filter_clauses = []
            if tags_filter:
                tag_terms = [f'tags:={t}' for t in tags_filter if t]
                if tag_terms:
                    filter_clauses.append('(' + ' || '.join(tag_terms) + ')')
            if author_filter:
                _safe_author = re.sub(r'[^a-zA-Z0-9_\-]', '', author_filter)
                filter_clauses.append(f'author_username:={_safe_author}')
            if date_from:
                try:
                    dt_from = datetime.datetime.strptime(date_from, '%Y-%m-%d')
                    filter_clauses.append(f'created_at:>={int(dt_from.timestamp())}')
                except ValueError:
                    pass
            if date_to:
                try:
                    dt_to = datetime.datetime.strptime(date_to, '%Y-%m-%d') + datetime.timedelta(days=1, seconds=-1)
                    filter_clauses.append(f'created_at:<={int(dt_to.timestamp())}')
                except ValueError:
                    pass
            filter_expr = ' && '.join(filter_clauses) if filter_clauses else ''
            search_params = {'q': query or '*', 'query_by': 'title,content', 'per_page': per_page, 'page': page, 'highlight_full_fields': 'title,content', 'highlight_start_tag': '<span class="highlighted-match">', 'highlight_end_tag': '</span>'}
            if filter_expr:
                search_params['filter_by'] = filter_expr
            if sort == 'newest':
                search_params['sort_by'] = 'created_at:desc'
            elif sort == 'oldest':
                search_params['sort_by'] = 'created_at:asc'
            elif sort == 'title_asc':
                search_params['sort_by'] = 'title:asc'
            elif sort == 'title_desc':
                search_params['sort_by'] = 'title:desc'
            search_result = m._t._ts_search('posts', search_params)
            total = search_result.get('found', 0)
            hits = search_result.get('hits', [])
            for h in hits:
                doc = h.get('document', h)
                highlights = h.get('highlights', [])
                title_html = doc.get('title', '')
                excerpt = doc.get('content', '')[:300]
                for hl in highlights:
                    if hl.get('field') == 'title' and hl.get('snippet'):
                        title_html = hl['snippet']
                    if hl.get('field') == 'content' and hl.get('snippet'):
                        excerpt = hl['snippet']
                results.append({'id': doc.get('id'), 'title': title_html, 'slug': doc.get('slug'), 'author': doc.get('author_username'), 'created_at': datetime.datetime.fromtimestamp(doc.get('created_at'), tz=datetime.timezone.utc) if doc.get('created_at') else None, 'excerpt': excerpt})
        except Exception as e:
            current_app.logger.error(f'Typesense search error: {e}')
    else:
        if query:
            cursor = m.posts_conf.find({'$text': {'$search': query}}, {'score': {'$meta': 'textScore'}}).sort([('score', {'$meta': 'textScore'})]).limit(per_page)
            for p in cursor:
                results.append({'id': str(p.get('_id')), 'title': p.get('title'), 'slug': p.get('slug'), 'author': p.get('author'), 'created_at': p.get('timestamp'), 'excerpt': p.get('content', '')[:300]})
            total = len(results)
    try:
        available_tags = sorted([t for t in m.posts_conf.distinct('tags') if t])
    except Exception:
        available_tags = []
    try:
        available_authors = sorted([u.get('username') for u in m.users_conf.find({}, {'username': 1}) if u.get('username')])
    except Exception:
        available_authors = []
    return render_template('search_results.html', query=query, results=results, total=total, page=page, per_page=per_page, available_tags=available_tags, available_authors=available_authors, selected_tags=tags_filter, selected_author=author_filter, date_from=date_from, date_to=date_to, sort=sort)


@bp.route('/offline')
def offline():
    return render_template("offline.html", title="Offline - EchoWithin")


@bp.route('/about')
def about():
    page_title = "About EchoWithin - Secure Personal Notes & Community"
    page_description = "Learn how EchoWithin empowers you with secure personal notes, collaborative features, and surprise themed notes with photos and music to share with loved ones."
    return render_template("about.html", title=page_title, description=page_description)


@bp.route('/terms')
def terms():
    return render_template('terms.html', title="Terms and Conditions", description="Terms and Conditions for using EchoWithin.")


@bp.route('/faq')
def faq():
    return render_template('faq.html', title="FAQ - EchoWithin", description="Frequently asked questions about using EchoWithin.")


@bp.route('/feed.xml')
def feed():
    import main as m
    try:
        posts = list(m.posts_conf.find({'status': 'published'}).sort('created_at', -1).limit(50))
        items = []
        for p in posts:
            pub_date = p.get('timestamp') or p.get('created_at')
            items.append({'title': p.get('title'), 'link': url_for('blog.view_post', slug=p.get('slug'), _external=True), 'guid': str(p.get('_id')), 'pubDate': pub_date.strftime('%a, %d %b %Y %H:%M:%S GMT') if pub_date else '', 'description': (p.get('content') or '')[:400]})
        return render_template('feed.xml', items=items), 200, {'Content-Type': 'application/rss+xml; charset=utf-8'}
    except Exception as e:
        current_app.logger.error(f'Failed to build RSS feed: {e}')
        abort(500)


@bp.route('/api/quote')
def get_quote_api():
    import main as m
    return jsonify(m.get_zen_quote())


@bp.route('/service-worker.js')
def service_worker():
    response = send_from_directory('static', 'service-worker.js')
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Service-Worker-Allowed'] = '/'
    return response


@bp.route('/.well-known/assetlinks.json')
def android_assetlinks():
    import json
    assetlinks = [{"relation": ["delegate_permission/common.handle_all_urls"], "target": {"namespace": "android_app", "package_name": "xyz.echowithin.app", "sha256_cert_fingerprints": ["EE:89:BD:8D:85:44:66:17:40:74:46:6B:57:15:AB:56:81:CE:40:99:21:D2:59:72:12:FE:4B:B9:5B:DC:E7:5E"]}}]
    response = make_response(json.dumps(assetlinks))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response


@bp.route('/download/note-app.apk')
def download_note_app_apk():
    import main as m
    apk_path = os.path.join(current_app.static_folder, 'downloads', 'app-debug.apk')
    if not os.path.exists(apk_path):
        abort(404)
    return send_file(apk_path, mimetype='application/vnd.android.package-archive', as_attachment=True, download_name='echowithin-note-app.apk', conditional=True)


@bp.route('/static/update-manifest.json')
def serve_update_manifest():
    import main as m
    try:
        db_manifest = m.app_updates_conf.find_one({'key': 'latest'})
        if db_manifest:
            return jsonify({"versionCode": db_manifest.get('versionCode'), "versionName": db_manifest.get('versionName'), "apkUrl": db_manifest.get('apkUrl'), "changelog": db_manifest.get('changelog')})
    except Exception as e:
        current_app.logger.error(f"Error querying update manifest from DB: {e}")
    manifest_path = os.path.join(current_app.static_folder, 'update-manifest.json')
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
        except Exception:
            pass
    return jsonify({"error": "Manifest not found"}), 404


@bp.route('/share-target', methods=['GET'])
@login_required
def share_target():
    shared_title = request.args.get('title', '')
    shared_text = request.args.get('text', '')
    shared_url = request.args.get('url', '')
    return redirect(url_for('pages.create_post', shared_title=shared_title, shared_text=shared_text, shared_url=shared_url))


@bp.route('/create_post', methods=['GET'])
@login_required
def create_post():
    page_title = "Create a New Post - EchoWithin"
    page_description = "Share your ideas, experiences, and perspectives with the EchoWithin community."
    shared_title = request.args.get('shared_title', '')
    shared_text = request.args.get('shared_text', '')
    shared_url = request.args.get('shared_url', '')
    return render_template("create_post.html", active_page='blog', title=page_title, description=page_description, shared_title=shared_title, shared_text=shared_text, shared_url=shared_url)


@bp.route('/contact', methods=['POST'])
def contact_developer():
    import main as m
    if request.method == 'POST':
        name = request.form.get('name')
        sender_email = request.form.get('email')
        subject = request.form.get('subject')
        message_body = request.form.get('message')
        if not all([name, sender_email, subject, message_body]):
            flash("Please fill out all fields in the contact form.", "danger")
            return redirect(url_for('pages.about'))
        try:
            msg = m.Message(subject=f"EchoWithin Contact Form: {subject}", sender=m.get_env_variable('MAIL_USERNAME'), recipients=[m.get_env_variable('MY_EMAIL')])
            msg.reply_to = sender_email
            msg.body = f"You have a new message from {name} ({sender_email}):\n\n{message_body}"
            m.mail.send(msg)
            flash("Your message has been sent successfully. Thank you!", "success")
        except Exception as e:
            current_app.logger.error(f"Failed to send contact form email: {e}")
            flash("Sorry, there was an error sending your message. Please try again later.", "danger")
    return redirect(url_for('pages.about'))


@bp.route('/favicon.ico')
def favicon():
    import main as m
    favicon_path = os.path.join(current_app.root_path, 'static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory(os.path.join(current_app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    else:
        return '', 204


@bp.route('/sitemap_index.xml')
def sitemap_index():
    import main as m
    cache_key = 'sitemap_index_xml'
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached:
                if isinstance(cached, bytes):
                    cached = cached.decode('utf-8')
                response = make_response(cached)
                response.headers['Content-Type'] = 'application/xml; charset=utf-8'
                response.headers['Cache-Control'] = 'public, max-age=3600'
                return response
        except Exception as e:
            current_app.logger.warning(f"Sitemap cache hit error: {e}")
    base_url = request.url_root.rstrip('/')
    if current_app.config.get('PREFERRED_URL_SCHEME') == 'https' or not current_app.debug:
        base_url = base_url.replace('http://', 'https://')
    from html import escape
    today = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    static_pages = [('/', 1.0, 'daily'), ('/blog', 0.9, 'hourly'), ('/about', 0.5, 'monthly'), ('/faq', 0.5, 'monthly'), ('/terms', 0.3, 'yearly')]
    for path, priority, changefreq in static_pages:
        xml_parts.append(f'  <url><loc>{escape(m.clean_xml_text(base_url + path))}</loc><lastmod>{today}</lastmod><changefreq>{changefreq}</changefreq><priority>{priority}</priority></url>')
    try:
        sample_post = m.posts_conf.find_one({}) or {}
        posts_query = {'status': 'published'} if 'status' in sample_post else {}
        posts = m.posts_conf.find(posts_query, {'slug': 1, 'timestamp': 1, 'edited_at': 1}).sort('timestamp', -1).limit(50000)
        for post in posts:
            slug = post.get('slug')
            if not slug:
                continue
            if re.match(r'^post-[0-9a-f]{8,}$', slug):
                continue
            lastmod = post.get('edited_at') or post.get('timestamp')
            lastmod_str = ''
            if lastmod and hasattr(lastmod, 'strftime'):
                lastmod_str = f'<lastmod>{lastmod.strftime("%Y-%m-%d")}</lastmod>'
            full_url = f"{base_url}/post/{slug}"
            xml_parts.append(f'  <url><loc>{escape(m.clean_xml_text(full_url))}</loc>{lastmod_str}<changefreq>weekly</changefreq><priority>0.7</priority></url>')
    except Exception as e:
        current_app.logger.error(f"Error generating sitemap posts: {e}")
    xml_parts.append('</urlset>')
    sitemap_xml = '\n'.join(xml_parts)
    if m.redis_cache:
        try:
            m.redis_cache.setex(cache_key, 3600, sitemap_xml)
        except Exception as e:
            current_app.logger.warning(f"Sitemap cache set error: {e}")
    response = make_response(sitemap_xml)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@bp.route('/api/admin/clear-sitemap-cache', methods=['POST'])
@login_required
def api_clear_sitemap_cache():
    import main as m
    if m.redis_cache:
        m.redis_cache.delete('sitemap_index_xml')
        return jsonify({'success': True, 'message': 'Sitemap cache cleared'})
    return jsonify({'error': 'Redis not available'}), 503


@bp.route('/robots.txt')
def robots():
    robots_txt = """User-agent: *
Allow: /
Disallow: /admin
Disallow: /api/
Disallow: /login
Disallow: /register
Disallow: /logout
Disallow: /dashboard
Disallow: /messages
Disallow: /personal_space
Disallow: /shared/
Disallow: /search
Disallow: /profile_settings
Disallow: /create_post
Disallow: /edit_post
Disallow: /reset_password

# Sitemap
Sitemap: https://echowithin.xyz/sitemap_index.xml
"""
    response = make_response(robots_txt)
    response.headers['Content-Type'] = 'text/plain'
    return response


@bp.route('/sitemap.xml')
def sitemap_legacy_redirect():
    return redirect(url_for('pages.sitemap_index'), code=301)


@bp.route('/unsubscribe/<email>/<token>', methods=['GET', 'POST'])
@csrf_exempt
@limits(calls=5, period=60)
def unsubscribe(email, token):
    import main as m
    if not email or not token:
        return render_template('unsubscribe_result.html', success=False, message="Invalid unsubscribe request.")
    secret = current_app.config["SECRET_KEY"]
    expected_token = hashlib.sha256(f"{secret}{email}unsubscribe".encode()).hexdigest()
    if token != expected_token:
        return render_template('unsubscribe_result.html', success=False, message="Invalid or expired unsubscribe link.")
    m.users_conf.update_one({'email': email}, {'$set': {'notification_preference': 'none'}})
    m.newsletter_conf.delete_one({'email': email})
    if request.method == 'POST':
        return jsonify({'success': True, 'message': 'Unsubscribed successfully'})
    return render_template('unsubscribe_result.html', success=True, message=f"You have been successfully unsubscribed from all EchoWithin automated emails for {email}.")


@bp.route('/api/newsletter/subscribe', methods=['POST'])
@limits(calls=5, period=60)
def api_newsletter_subscribe():
    import main as m
    email = request.json.get('email')
    if not email or '@' not in email:
        return jsonify({'error': 'Invalid email address'}), 400
    try:
        m.newsletter_conf.insert_one({'email': email, 'subscribed_at': datetime.datetime.now(datetime.timezone.utc), 'ip': request.remote_addr})
        return jsonify({'success': True, 'message': 'Successfully subscribed to the newsletter!'})
    except m.DuplicateKeyError:
        return jsonify({'success': True, 'message': 'You are already subscribed!'})
    except Exception as e:
        current_app.logger.error(f"Newsletter subscription error: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500
