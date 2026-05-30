from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, send_from_directory, abort, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from bson.son import SON
import datetime, math, json, random, os, re
bp = Blueprint('blog', __name__, template_folder='templates')


@bp.route("/blog")
def blog():
    import main as m
    query = request.args.get('query', None)
    if query:
        search_filter = {"$text": {"$search": query}}
        page = request.args.get('page', 1, type=int)
        posts_per_page = 10
        total_posts = m.posts_conf.count_documents(search_filter)
        total_pages = math.ceil(total_posts / posts_per_page)
        skip = (page - 1) * posts_per_page
        search_results = list(m.posts_conf.find(search_filter).sort('timestamp', -1).skip(skip).limit(posts_per_page))
        with current_app.app_context():
            search_results = m.prepare_posts(search_results)
        page_title = f"Search results for '{query}'"
        page_description = f"Displaying search results for '{query}' on EchoWithin."
        return render_template("blog.html", posts=search_results, active_page='blog', page=page, total_pages=total_pages, query=query, title=page_title, description=page_description)
    cached_feed = m.blog_feed_cache.get('main')
    if cached_feed:
        latest_posts_prepared = cached_feed
    else:
        total_posts_count = m.posts_conf.count_documents({})
        pinned_posts = list(m.posts_conf.find({'is_pinned': True}).sort('pinned_at', -1))
        pinned_ids = [p['_id'] for p in pinned_posts]
        if total_posts_count <= 10:
            other_posts = list(m.posts_conf.find({'_id': {'$nin': pinned_ids}}).sort('timestamp', -1))
            random.shuffle(other_posts)
            all_posts_list = pinned_posts + other_posts
            with current_app.app_context():
                latest_posts_prepared = m.prepare_posts(all_posts_list)
        else:
            now = datetime.datetime.now(datetime.timezone.utc)
            one_month_ago = now - datetime.timedelta(days=30)
            recent_posts = list(m.posts_conf.find({'_id': {'$nin': pinned_ids}}).sort('timestamp', -1).limit(2))
            recent_ids = [p['_id'] for p in recent_posts]
            month_posts = list(m.posts_conf.find({'_id': {'$nin': pinned_ids + recent_ids}, 'timestamp': {'$gte': one_month_ago}}).sort('timestamp', -1).limit(20))
            if len(month_posts) > 4:
                month_weights = []
                for mp in month_posts:
                    eng = (mp.get('likes_count', 0) or 0) + (mp.get('comment_count', 0) or 0) * 2 + (mp.get('share_count', 0) or 0)
                    month_weights.append(max(eng, 1))
                month_selection = random.choices(month_posts, weights=month_weights, k=4)
                seen_ids = set()
                deduped = []
                for mp in month_selection:
                    if mp['_id'] not in seen_ids:
                        seen_ids.add(mp['_id'])
                        deduped.append(mp)
                month_selection = deduped
            else:
                month_selection = month_posts
            month_ids = [p['_id'] for p in month_selection]
            excluded_ids = pinned_ids + recent_ids + month_ids
            posts_needed = 10 - len(recent_posts) - len(month_selection)
            older_posts = list(m.posts_conf.aggregate([
                {'$match': {'_id': {'$nin': excluded_ids}}},
                {'$addFields': {'_eng_weight': {'$add': [{'$ifNull': ['$likes_count', 0]}, {'$multiply': [{'$ifNull': ['$share_count', 0]}, 2]}, 1]}}},
                {'$sample': {'size': max(posts_needed * 3, 3)}}
            ]))
            older_posts.sort(key=lambda p: p.get('_eng_weight', 1), reverse=True)
            if len(older_posts) > posts_needed:
                top_half = older_posts[:max(len(older_posts) // 2, posts_needed)]
                older_posts = random.sample(top_half, min(posts_needed, len(top_half)))
            for p in older_posts:
                p.pop('_eng_weight', None)
            mixed_posts = recent_posts + month_selection + older_posts
            random.shuffle(mixed_posts)
            combined_posts = pinned_posts + mixed_posts
            with current_app.app_context():
                latest_posts_prepared = m.prepare_posts(combined_posts)
        m.blog_feed_cache['main'] = latest_posts_prepared
    page_title = "EchoWithin Blog - Community & Collaboration"
    page_description = "Explore the latest posts, collaborative discussions, and ideas from the EchoWithin community."
    return render_template("blog.html", latest_posts=latest_posts_prepared, active_page='blog', title=page_title, description=page_description)


@bp.route("/blog/all")
@login_required
def all_posts():
    import main as m
    selected_tag = request.args.get('tag', None)
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10
    filter_query = {}
    if selected_tag:
        filter_query = {'tags': selected_tag}
    total_posts = m.posts_conf.count_documents(filter_query)
    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page
    all_posts_cursor = m.posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page)
    with current_app.app_context():
        posts = m.prepare_posts(list(all_posts_cursor))
    available_tags = sorted([t for t in m.posts_conf.distinct('tags') if t])
    return render_template('all_posts.html', posts=posts, active_page='blog', page=page, total_pages=total_pages, selected_tag=selected_tag, available_tags=available_tags, title=f"All Posts - Page {page} - EchoWithin", description="Browse all blog posts.")


@bp.route('/api/posts')
def get_all_posts_json():
    import main as m
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10
    skip = (page - 1) * posts_per_page
    total = m.posts_conf.count_documents({})
    posts = list(m.posts_conf.find({}).sort('timestamp', -1).skip(skip).limit(posts_per_page))
    with current_app.app_context():
        posts = m.prepare_posts(posts)
    return jsonify({'posts': [{'_id': str(p['_id']), 'title': p.get('title'), 'slug': p.get('slug'), 'author': p.get('author'), 'timestamp': p.get('timestamp').isoformat() if p.get('timestamp') else None, 'likes_count': p.get('likes_count', 0), 'comment_count': p.get('comment_count', 0)} for p in posts], 'total': total, 'page': page, 'total_pages': math.ceil(total / posts_per_page)})


@bp.route('/api/posts/top-by-comments')
def get_top_posts_json():
    import main as m
    try:
        limit = min(int(request.args.get('limit', 10)), 50)
    except (ValueError, TypeError):
        limit = 10
    pipeline = [
        {'$match': {'is_deleted': False, 'post_slug': {'$ne': None}}},
        {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': limit},
        {'$lookup': {'from': 'posts', 'localField': '_id', 'foreignField': 'slug', 'as': 'post'}},
        {'$unwind': '$post'},
        {'$project': {'slug': '$_id', 'count': 1, 'title': '$post.title', '_id': 0}}
    ]
    top_posts = list(m.comments_conf.aggregate(pipeline))
    return jsonify(top_posts)


@bp.route('/api/posts/hot')
def get_hot_posts_json():
    import main as m
    try:
        limit = min(int(request.args.get('limit', 10)), 50)
    except (ValueError, TypeError):
        limit = 10
    now = datetime.datetime.now(datetime.timezone.utc)
    thirty_days_ago = now - datetime.timedelta(days=30)
    pipeline = [
        {'$match': {'timestamp': {'$gte': thirty_days_ago}}},
        {'$lookup': {'from': 'comments', 'let': {'post_slug': '$slug'}, 'pipeline': [{'$match': {'$expr': {'$eq': ['$post_slug', '$$post_slug']}, 'is_deleted': {'$ne': True}}}, {'$count': 'count'}], 'as': 'comment_data'}},
        {'$addFields': {'comment_count': {'$ifNull': [{'$arrayElemAt': ['$comment_data.count', 0]}, 0]}, 'likes_safe': {'$ifNull': ['$likes_count', 0]}, 'shares_safe': {'$ifNull': ['$share_count', 0]}, 'views_safe': {'$ifNull': ['$view_count', 0]}, 'age_in_hours': {'$divide': [{'$subtract': ["$$NOW", '$timestamp']}, 3600000]}}},
        {'$addFields': {'engagement_score': {'$multiply': [{'$ln': {'$add': [{'$add': [{'$multiply': ['$comment_count', m.ENGAGEMENT_WEIGHTS['comment']]}, {'$multiply': ['$likes_safe', m.ENGAGEMENT_WEIGHTS['reaction']]}, {'$multiply': ['$shares_safe', m.ENGAGEMENT_WEIGHTS['share']]}, {'$multiply': ['$views_safe', m.ENGAGEMENT_WEIGHTS['view']]}]}, 1]}}, 10]}}},
        {'$addFields': {'hot_score': {'$divide': [{'$add': ['$engagement_score', 1]}, {'$pow': [{'$add': ['$age_in_hours', 8]}, 1.2]}]}}},
        {'$sort': {'hot_score': -1}},
        {'$limit': limit}
    ]
    hot_posts = list(m.posts_conf.aggregate(pipeline))
    with current_app.app_context():
        hot_posts = m.prepare_posts(hot_posts)
    return jsonify(hot_posts)


@bp.route('/api/posts/my-commented')
@login_required
def get_my_commented_posts_json():
    import main as m
    try:
        user_id = ObjectId(current_user.id)
        
        # Get user's posts that have at least 1 comment
        pipeline = [
            # 1. Match user's posts
            {'$match': {'author_id': user_id}},
            # 2. Lookup comments for each post
            {'$lookup': {
                'from': 'comments',
                'localField': 'slug',
                'foreignField': 'post_slug',
                'as': 'post_comments'
            }},
            # 3. Filter to only posts with comments
            {'$match': {'post_comments.0': {'$exists': True}}},
            # 4. Add fields for comment count and latest comment time
            {'$addFields': {
                'comment_count': {'$size': '$post_comments'},
                'latest_comment_at': {'$max': '$post_comments.created_at'},
                'author_last_viewed': {'$ifNull': ['$author_last_viewed', datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)]}
            }},
            # 5. Add has_unread flag (comments newer than author's last view)
            {'$addFields': {
                'has_unread': {'$gt': ['$latest_comment_at', '$author_last_viewed']}
            }},
            # 6. Sort by latest comment activity
            {'$sort': {'latest_comment_at': -1}},
            # 7. Limit results
            {'$limit': 15},
            # 8. Project only needed fields
            {'$project': {
                'post_comments': 0  # Exclude the full comments array
            }}
        ]
        
        posts = list(m.posts_conf.aggregate(pipeline))
        
        # Calculate total unread count for badge
        unread_count = sum(1 for p in posts if p.get('has_unread', False))
        
        # Format posts for JSON response
        result_posts = []
        for post in posts:
            post_data = {
                '_id': str(post['_id']),
                'title': post.get('title', ''),
                'slug': post.get('slug', ''),
                'url': url_for('blog.view_post', slug=post.get('slug', '')),
                'content': (post.get('content', '')[:150] + '...') if len(post.get('content', '')) > 150 else post.get('content', ''),
                'author': post.get('author', ''),
                'author_id': str(post.get('author_id', '')),
                'timestamp': post.get('timestamp').strftime('%b %d, %Y') if post.get('timestamp') else '',
                'image_url': post.get('image_url'),
                'image_urls': post.get('image_urls', []),
                'video_url': post.get('video_url'),
                'comment_count': post.get('comment_count', 0),
                'likes_count': post.get('likes_count', 0),
                'share_count': post.get('share_count', 0),
                'has_unread': post.get('has_unread', False),
                'latest_comment_at': post.get('latest_comment_at').isoformat() if post.get('latest_comment_at') else None,
                'reactions': post.get('reactions', {})
            }
            result_posts.append(post_data)
        
        return jsonify({
            'posts': result_posts,
            'unread_count': unread_count
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in get_my_commented_posts_json: {e}")
        return jsonify({'error': 'Could not retrieve posts'}), 500


@bp.route('/api/posts/mark-all-read', methods=['POST'])
@login_required
def mark_all_comments_read():
    import main as m
    m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'last_activity_check': datetime.datetime.now(datetime.timezone.utc), 'activity_check_per_post': {}}})
    return jsonify({'success': True})


@bp.route('/api/posts/related')
def get_related_posts_json():
    import main as m
    post_id = request.args.get('post_id')
    slug = request.args.get('slug')
    if not post_id and not slug:
        return jsonify({'error': 'post_id or slug required'}), 400
    obj_id = m.safe_object_id(post_id)
    post = m.posts_conf.find_one({'_id': obj_id} if obj_id else {'slug': slug})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    tags = post.get('tags', [])
    if tags:
        related = list(m.posts_conf.find({'tags': {'$in': tags}, '_id': {'$ne': post['_id']}}).sort('timestamp', -1).limit(4))
    else:
        related = list(m.posts_conf.find({'_id': {'$ne': post['_id']}}).sort('timestamp', -1).limit(4))
    with current_app.app_context():
        related = m.prepare_posts(related)
    return jsonify(related)


@bp.route('/api/posts/<post_id>/status')
def get_post_status(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)}, {'status': 1})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    return jsonify({'status': post.get('status', 'unknown')})


@bp.route("/post", methods=['POST', 'GET'])
@login_required
def post():
    import main as m
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        tags = request.form.getlist("tags")
        image_urls = []
        temp_image_paths = []
        temp_video_path = None
        if not title or not content:
            flash("Title and content are required.", "danger")
            return redirect(url_for('pages.create_post'))
        slug = m.slugify(title)
        original_slug = slug
        counter = 1
        while m.posts_conf.find_one({'slug': slug}):
            slug = f"{original_slug}-{counter}"
            counter += 1
        tag_list = [t.strip().lower() for t in tags if t.strip()]
        result = m.posts_conf.insert_one({
            'title': title, 'content': content, 'slug': slug, 'author': current_user.username, 'author_id': ObjectId(current_user.id), 'timestamp': datetime.datetime.now(datetime.timezone.utc), 'tags': tag_list, 'image_urls': [], 'image_status': 'none', 'video_status': 'none', 'status': 'processing', 'likes_count': 0, 'share_count': 0, 'view_count': 0
        })
        post_id_str = str(result.inserted_id)
        m.index_post_to_typesense(post_id_str)
        m.process_post_media.queue(post_id_str, [], None)
        return redirect(url_for('blog.view_post', slug=slug))
    return redirect(url_for('pages.create_post'))


@bp.route('/uploads/<filename>')
def uploaded_file(filename):
    import main as m
    return send_from_directory(m.UPLOAD_FOLDER, filename)


@bp.route('/post/<slug>')
def view_post(slug):
    import main as m
    post = m.posts_conf.find_one({'slug': slug})
    if not post:
        abort(404)
    comments_list = list(m.comments_conf.find({'post_slug': slug, 'is_deleted': {'$ne': True}}).sort('created_at', 1))
    user_reaction = None
    is_saved = False
    is_owner = False
    if current_user.is_authenticated:
        user_id_obj = ObjectId(current_user.id)
        reaction = m.comments_conf.find_one({'post_slug': slug, 'author_id': user_id_obj, 'reaction_type': {'$exists': True}})
        if reaction:
            user_reaction = reaction.get('reaction_type')
        is_owner = str(post.get('author_id')) == current_user.id
        user_data = m.users_conf.find_one({'_id': user_id_obj}, {'saved_posts': 1})
        if user_data and post['_id'] in user_data.get('saved_posts', []):
            is_saved = True
    return render_template('view_post.html', post=post, comments=comments_list, user_reaction=user_reaction, is_saved=is_saved, is_owner=is_owner, title=f"{post['title']} - EchoWithin", description=post.get('content', '')[:200])


@bp.route('/api/posts/<post_id>/view', methods=['POST'])
def api_record_post_view(post_id):
    import main as m
    m.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$inc': {'view_count': 1}})
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)}, {'view_count': 1})
    view_count = post.get('view_count', 0) if post else 0
    return jsonify({'success': True, 'view_count': view_count})


@bp.route('/api/posts/<slug>/comments', methods=['GET', 'POST'])
@login_required
def api_post_comments(slug):
    import main as m
    if request.method == 'GET':
        comments_list = list(m.comments_conf.find({'post_slug': slug, 'is_deleted': {'$ne': True}}).sort('created_at', 1))
        return jsonify([m._serialize_comment(c) for c in comments_list])
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    parent_id = data.get('parent_id')
    if not content:
        return jsonify({'error': 'Content required'}), 400
    comment = {
        'post_slug': slug, 'author_id': ObjectId(current_user.id), 'author': current_user.username, 'content': content, 'created_at': datetime.datetime.now(datetime.timezone.utc), 'is_deleted': False, 'parent_id': ObjectId(parent_id) if parent_id else None
    }
    result = m.comments_conf.insert_one(comment)
    m.posts_conf.update_one({'slug': slug}, {'$inc': {'comment_count': 1}})
    comment['_id'] = result.inserted_id
    return jsonify(m._serialize_comment(comment)), 201


@bp.route('/api/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_comment(comment_id):
    import main as m
    comment = m.comments_conf.find_one({'_id': ObjectId(comment_id)})
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    if str(comment['author_id']) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    m.comments_conf.update_one({'_id': ObjectId(comment_id)}, {'$set': {'is_deleted': True}})
    return jsonify({'success': True})


@bp.route('/api/comments/<comment_id>', methods=['PUT', 'PATCH'])
@login_required
def api_edit_comment(comment_id):
    import main as m
    comment = m.comments_conf.find_one({'_id': ObjectId(comment_id)})
    if not comment:
        return jsonify({'error': 'Comment not found'}), 404
    if str(comment['author_id']) != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content required'}), 400
    m.comments_conf.update_one({'_id': ObjectId(comment_id)}, {'$set': {'content': content, 'edited_at': datetime.datetime.now(datetime.timezone.utc)}})
    return jsonify({'success': True})


@bp.route('/api/comments/<comment_id>/vote', methods=['POST'])
@login_required
def api_vote_comment(comment_id):
    import main as m
    data = request.get_json() or {}
    vote_type = data.get('vote_type')
    if vote_type not in ('upvote', 'downvote'):
        return jsonify({'error': 'Invalid vote type'}), 400
    existing = m.comment_votes_conf.find_one({'comment_id': ObjectId(comment_id), 'user_id': ObjectId(current_user.id)})
    if existing:
        if existing.get('vote_type') == vote_type:
            m.comment_votes_conf.delete_one({'_id': existing['_id']})
            return jsonify({'success': True, 'action': 'removed'})
        else:
            m.comment_votes_conf.update_one({'_id': existing['_id']}, {'$set': {'vote_type': vote_type}})
            return jsonify({'success': True, 'action': 'changed'})
    m.comment_votes_conf.insert_one({'comment_id': ObjectId(comment_id), 'user_id': ObjectId(current_user.id), 'vote_type': vote_type, 'created_at': datetime.datetime.now(datetime.timezone.utc)})
    return jsonify({'success': True, 'action': 'added'})


@bp.route('/edit_post/<post_id>', methods=['GET'])
@login_required
def edit_post(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        abort(404)
    if str(post.get('author_id')) != current_user.id:
        flash("You can only edit your own posts.", "danger")
        return redirect(url_for('blog.view_post', slug=post.get('slug')))
    return render_template('create_post.html', post=post, active_page='blog', title=f"Editing: {post.get('title')} - EchoWithin", description="Edit your post.")


@bp.route('/update_post/<post_id>', methods=['POST'])
@login_required
def update_post(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        abort(404)
    if str(post.get('author_id')) != current_user.id:
        flash("You can only edit your own posts.", "danger")
        return redirect(url_for('blog.view_post', slug=post.get('slug')))
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    tags = request.form.getlist('tags')
    old_slug = post.get('slug')
    new_slug = m.slugify(title) if title else old_slug
    if new_slug != old_slug:
        counter = 1
        original_slug = new_slug
        while m.posts_conf.find_one({'slug': new_slug, '_id': {'$ne': post['_id']}}):
            new_slug = f"{original_slug}-{counter}"
            counter += 1
    m.posts_conf.update_one(
        {'_id': post['_id']},
        {'$set': {'title': title, 'content': content, 'slug': new_slug, 'tags': [t.strip().lower() for t in tags if t.strip()], 'edited_at': datetime.datetime.now(datetime.timezone.utc)}}
    )
    m.index_post_to_typesense(post_id)
    flash('Post updated successfully!', 'success')
    return redirect(url_for('blog.view_post', slug=new_slug))


@bp.route('/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        abort(404)
    if str(post.get('author_id')) != current_user.id:
        flash("You can only delete your own posts.", "danger")
    else:
        m.posts_conf.delete_one({'_id': post['_id']})
        m.comments_conf.delete_many({'post_slug': post.get('slug')})
        flash('Post deleted.', 'success')
    return redirect(url_for('blog.blog'))


@bp.route('/post/<post_id>/react', methods=['POST'])
@login_required
def toggle_reaction_post(post_id):
    import main as m
    data = request.get_json() or {}
    emoji = data.get('emoji', '')
    existing = m.comments_conf.find_one({'post_id': ObjectId(post_id), 'author_id': ObjectId(current_user.id), 'reaction_type': {'$exists': True}})
    if existing:
        if existing.get('reaction_type') == emoji:
            m.comments_conf.delete_one({'_id': existing['_id']})
            return jsonify({'action': 'removed'})
        else:
            m.comments_conf.update_one({'_id': existing['_id']}, {'$set': {'reaction_type': emoji, 'created_at': datetime.datetime.now(datetime.timezone.utc)}})
            return jsonify({'action': 'changed'})
    m.comments_conf.insert_one({'post_id': ObjectId(post_id), 'author_id': ObjectId(current_user.id), 'author': current_user.username, 'reaction_type': emoji, 'created_at': datetime.datetime.now(datetime.timezone.utc)})
    return jsonify({'action': 'added'})


@bp.route('/post/<post_id>/toggle_save', methods=['POST'])
@login_required
def toggle_save_post(post_id):
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'saved_posts': 1})
    post_obj_id = ObjectId(post_id)
    if user and post_obj_id in user.get('saved_posts', []):
        m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$pull': {'saved_posts': post_obj_id}})
        return jsonify({'saved': False})
    else:
        m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$addToSet': {'saved_posts': post_obj_id}})
        return jsonify({'saved': True})


@bp.route('/post/<post_id>/share', methods=['POST'])
@login_required
def share_post(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    m.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$inc': {'share_count': 1}})
    share_url = url_for('blog.view_post', slug=post.get('slug'), _external=True)
    return jsonify({'share_url': share_url})


@bp.route('/api/post/<post_id>/share-data')
def get_share_data(post_id):
    import main as m
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    return jsonify({'title': post.get('title', ''), 'description': post.get('content', '')[:200], 'url': url_for('blog.view_post', slug=post.get('slug'), _external=True)})
