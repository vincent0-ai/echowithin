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
    """Displays a paginated list of all blog posts with optimized performance."""
    import main as m
    selected_tag = request.args.get('tag', None)
    page = request.args.get('page', 1, type=int)
    posts_per_page = 10

    # Build the filter query
    filter_query = {}
    if selected_tag:
        filter_query['tags'] = selected_tag

    total_posts = m.posts_conf.count_documents(filter_query)
    total_pages = math.ceil(total_posts / posts_per_page)
    skip = (page - 1) * posts_per_page

    posts = []

    # When tag is selected, use simple efficient query
    if selected_tag:
        filtered_posts = list(m.posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page))
        with current_app.app_context():
            posts = m.prepare_posts(filtered_posts)
    elif current_user.is_authenticated:
        # --- OPTIMIZED personalized feed ---
        user_id = ObjectId(current_user.id)
        user_id_str = str(current_user.id)

        # Try to get cached interest profile from Redis (cache for 5 minutes)
        cache_key = f"user_interests:{user_id_str}"
        cached_interests = None
        if m.redis_cache:
            try:
                cached_data = m.redis_cache.get(cache_key)
                if cached_data:
                    cached_interests = json.loads(cached_data)
            except Exception:
                pass

        tag_scores = {}
        author_scores = {}

        if cached_interests:
            tag_scores = cached_interests.get('tags', {})
            author_scores = cached_interests.get('authors', {})
        else:
            # Build interest profile with limited queries
            WEIGHT_LIKED = 3.0
            WEIGHT_SAVED = 4.0

            # Get user's liked and saved posts in ONE query via user document
            user_doc = m.users_conf.find_one({'_id': user_id}, {'saved_posts': 1})
            saved_ids = user_doc.get('saved_posts', []) if user_doc else []

            # Combine interacted + saved lookup in one query (limit to 100 most recent for performance)
            interest_query = {'$or': [
                {'reactions.heart': user_id_str},
                {'reactions.wow': user_id_str},
                {'reactions.insightful': user_id_str},
                {'reactions.laugh': user_id_str},
                {'reactions.sad': user_id_str},
                {'_id': {'$in': saved_ids[:50]}}  # Limit saved posts lookup
            ]}
            interest_posts = list(m.posts_conf.find(interest_query, {'tags': 1, 'author_id': 1, 'reactions': 1}).limit(100))

            for p in interest_posts:
                # Check if user reacted (any reaction type)
                has_reacted = False
                reactions_dict = p.get('reactions', {})
                if isinstance(reactions_dict, dict):
                    for uids in reactions_dict.values():
                        if user_id_str in uids:
                            has_reacted = True
                            break
                is_saved = p.get('_id') in saved_ids
                weight = (WEIGHT_LIKED if has_reacted else 0) + (WEIGHT_SAVED if is_saved else 0)

                for t in p.get('tags', []):
                    tag_scores[t] = tag_scores.get(t, 0) + weight
                a = p.get('author_id')
                if a and str(a) != user_id_str:
                    author_scores[str(a)] = author_scores.get(str(a), 0) + weight

            # Cache the interest profile
            if m.redis_cache and (tag_scores or author_scores):
                try:
                    m.redis_cache.setex(cache_key, 300, json.dumps({'tags': tag_scores, 'authors': author_scores}))
                except Exception:
                    pass

        if not tag_scores and not author_scores:
            # Cold-start: authenticated user with no interaction history
            # Show top-by-engagement posts instead of plain timestamp sort
            import random
            import math as math_module

            cold_pool = list(m.posts_conf.find(filter_query).sort('timestamp', -1).limit(30))
            now_cold = datetime.datetime.now(datetime.timezone.utc)
            for p in cold_pool:
                likes = p.get('likes_count', 0) or 0
                shares = p.get('share_count', 0) or 0
                eng = (likes * 3) + (shares * 4)
                p_time = p.get('timestamp')
                recency_mult = 1.0
                if p_time:
                    if p_time.tzinfo is None:
                        p_time = p_time.replace(tzinfo=datetime.timezone.utc)
                    days_old = (now_cold - p_time).total_seconds() / 86400
                    recency_mult = max(0.3, 1.0 - (math_module.log1p(days_old) / 10))
                p['_cold_score'] = eng * recency_mult
            cold_pool.sort(key=lambda x: x.get('_cold_score', 0), reverse=True)
            page_posts = cold_pool[skip : skip + posts_per_page]
            for p in page_posts:
                p.pop('_cold_score', None)

            with current_app.app_context():
                posts = m.prepare_posts(page_posts)
        else:
            # Fetch a larger pool of recent posts for global personalization
            # Dynamic pool size ensures pagination beyond page 5 works correctly
            pool_size = max(50, skip + posts_per_page)
            
            # Use simple find().sort().limit() for the pool
            pool_cursor = m.posts_conf.find(filter_query).sort('timestamp', -1).limit(pool_size)
            all_pool_posts = list(pool_cursor)
            
            # Build set of slugs for batch comment counting (avoid unnecessary URL generation)
            slugs_for_counts = [p.get('slug') for p in all_pool_posts if p.get('slug')]
            counts_map = {}
            if slugs_for_counts:
                pipeline = [
                    {'$match': {'post_slug': {'$in': slugs_for_counts}, 'is_deleted': False}},
                    {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}}
                ]
                for doc in m.comments_conf.aggregate(pipeline):
                    counts_map[doc['_id']] = doc.get('count', 0)
            
            # Score ALL posts in the pool
            now = datetime.datetime.now(datetime.timezone.utc)
            for p in all_pool_posts:
                # Inject comment count early for scoring
                p['comment_count'] = counts_map.get(p.get('slug'), 0)
                
                score = 0.0
                # Tag matching
                for t in p.get('tags', []):
                    if t in tag_scores:
                        score += tag_scores[t] * 2
                # Author matching
                aid = str(p.get('author_id', ''))
                if aid in author_scores:
                    score += author_scores[aid] * 3
                # Engagement score (capped)
                likes = p.get('likes_count', 0) or 0
                comments = p['comment_count']
                engagement = (comments * m.ENGAGEMENT_WEIGHTS['comment']) + (likes * m.ENGAGEMENT_WEIGHTS['reaction'])
                score += min(engagement, 30)
                # Recency boost
                post_time = p.get('timestamp')
                if post_time:
                    if post_time.tzinfo is None:
                        post_time = post_time.replace(tzinfo=datetime.timezone.utc)
                    hours_old = (now - post_time).total_seconds() / 3600
                    recency = max(0, 1 - (hours_old / (24 * 7)))
                    score += recency * 5
                p['_score'] = score

            # Sort entire pool by score
            all_pool_posts.sort(key=lambda x: x.get('_score', 0), reverse=True)
            
            # Select the specific page from the sorted pool
            page_posts = all_pool_posts[skip : skip + posts_per_page]
            
            with current_app.app_context():
                posts = m.prepare_posts(page_posts)
    else:
        # Anonymous users: simple timestamp-sorted feed with slight randomization
        import random

        # Efficient paginated query
        page_posts = list(m.posts_conf.find(filter_query).sort('timestamp', -1).skip(skip).limit(posts_per_page))

        # Light shuffle for variety (keep first 2 fixed)
        if len(page_posts) > 2:
            top_two = page_posts[:2]
            rest = page_posts[2:]
            random.shuffle(rest)
            page_posts = top_two + rest

        with current_app.app_context():
            posts = m.prepare_posts(page_posts)

    # Get all unique tags for the dropdown (cached)
    tags_cache_key = 'all_post_tags'
    all_tags = None
    if m.redis_cache:
        try:
            cached_tags = m.redis_cache.get(tags_cache_key)
            if cached_tags:
                all_tags = json.loads(cached_tags)
        except Exception:
            pass

    if all_tags is None:
        all_tags = m.posts_conf.distinct('tags')
        if m.redis_cache:
            try:
                m.redis_cache.setex(tags_cache_key, 300, json.dumps(all_tags))
            except Exception:
                pass

    if selected_tag:
        page_title = f"Posts tagged '{selected_tag}' - EchoWithin"
        page_description = f"Browse all posts tagged with '{selected_tag}'."
    else:
        page_title = "All Posts - EchoWithin"
        page_description = "Browse through all posts from the EchoWithin community."

    return render_template("all_posts.html", posts=posts, active_page='blog', page=page, total_pages=total_pages, title=page_title, description=page_description, all_tags=sorted([t for t in all_tags if t is not None]), selected_tag=selected_tag)


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
    """
    Returns text posts relevant to the user's activity:
    1. Posts AUTHORED by the user that have comments.
    2. Posts AUTHORED BY OTHERS where someone replied to the user's comment.

    Sorted by most recent relevant activity.
    Unread status is determined by User.last_activity_check.
    """
    import main as m
    try:
        user_id = ObjectId(current_user.id)

        # Get the timestamp when user last clicked "Mark all as read" (or default to old date)
        # IMPORTANT: Query directly from DB to avoid stale cached values in current_user
        user_doc = m.users_conf.find_one({'_id': user_id}, {'last_activity_check': 1})
        last_check = user_doc.get('last_activity_check') if user_doc else None
        if not last_check:
            # Default to 30 days ago if never checked, to avoid marking everything since beginning of time as unread
            last_check = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)

        if last_check.tzinfo is None:
            last_check = last_check.replace(tzinfo=datetime.timezone.utc)

        # --- 1. Fetch User's Own Posts with Comments ---
        # (Same logic as before, but unread logic changes)
        # --- 1. Fetch User's Own Posts with Comments ---
        # (Hybrid logic: unread if newer than global check AND newer than author_last_viewed)
        own_posts_pipeline = [
            {'$match': {'author_id': user_id}},
            {'$lookup': {
                'from': 'comments',
                'let': {'post_slug': '$slug', 'owner_id': '$author_id'},
                'pipeline': [
                    {'$match': {
                        '$expr': {
                            '$and': [
                                {'$eq': ['$post_slug', '$$post_slug']},
                                {'$ne': ['$is_deleted', True]},
                                # CRITICAL: Exclude the post author's own comments from unread calculation
                                {'$ne': ['$author_id', '$$owner_id']}
                            ]
                        }
                    }},
                    {'$sort': {'created_at': -1}}
                ],
                'as': 'post_comments'
            }},
            # Only include posts that have comments from OTHER users
            {'$match': {'post_comments.0': {'$exists': True}}},
            {'$addFields': {
                'comment_count': {'$size': '$post_comments'},
                'latest_activity': {'$max': '$post_comments.created_at'},
            }},
            # IMPORTANT: Sort by latest activity BEFORE limiting
            {'$sort': {'latest_activity': -1}},
            {'$limit': 50}
        ]
        own_posts = list(m.posts_conf.aggregate(own_posts_pipeline))

        for p in own_posts:
            p['activity_type'] = 'comment_on_my_post'

        # --- 2. Fetch Posts where others replied to User's comments ---
        # A. Find all comment IDs authored by current user
        my_comments = list(m.comments_conf.find({'author_id': user_id}, {'_id': 1}))
        my_comment_ids = [c['_id'] for c in my_comments]

        relevant_replies = []
        if my_comment_ids:
            # B. Find replies to those comments (where author is NOT me)
            pipeline_replies = [
                {'$match': {
                    'parent_id': {'$in': my_comment_ids},
                    'author_id': {'$ne': user_id},
                    'is_deleted': {'$ne': True}
                }},
                {'$sort': {'created_at': -1}},
                {'$group': {
                    '_id': '$post_slug',
                    'latest_reply': {'$first': '$created_at'},
                    'reply_count': {'$sum': 1}
                }}
            ]
            replies_grouped = list(m.comments_conf.aggregate(pipeline_replies))

            # C. Fetch the actual posts with comment counts
            slugs = [g['_id'] for g in replies_grouped]
            if slugs:
                # Use aggregation to fetch posts AND count their comments
                replies_pipeline = [
                    {'$match': {'slug': {'$in': slugs}}},
                    {'$lookup': {
                        'from': 'comments',
                        'let': {'post_slug': '$slug'},
                        'pipeline': [
                            {'$match': {
                                '$expr': {'$eq': ['$post_slug', '$$post_slug']},
                                'is_deleted': {'$ne': True}
                            }},
                            {'$count': 'count'}
                        ],
                        'as': 'comment_count_data'
                    }},
                    {'$addFields': {
                        'comment_count': {'$ifNull': [{'$arrayElemAt': ['$comment_count_data.count', 0]}, 0]}
                    }}
                ]
                reply_posts_cursor = m.posts_conf.aggregate(replies_pipeline)
                reply_map = {g['_id']: g for g in replies_grouped}

                for p in reply_posts_cursor:
                    # Only include if it's NOT my own post (already covered above)
                    if str(p.get('author_id')) == current_user.id:
                        continue

                    reply_data = reply_map.get(p['slug'])
                    p['latest_activity'] = reply_data['latest_reply']
                    p['activity_type'] = 'reply_to_my_comment'
                    # p['extra_info'] = f"{reply_data['reply_count']} new replies"
                    relevant_replies.append(p)

        # --- 3. Fetch Surprise Unlock Notifications ---
        unlock_notifs = list(m.unlock_notifications_conf.find(
            {'owner_id': ObjectId(current_user.id)},
            sort=[('unlocked_at', -1)],
            limit=20
        ))
        
        unlock_activities = []
        for notif in unlock_notifs:
            u_name = notif.get('unlocked_by_name', 'Someone')
            u_id = notif.get('unlocked_by')
            if u_id:
                try:
                    v_user = m.users_conf.find_one({'_id': ObjectId(u_id)}, {'username': 1})
                    if v_user and v_user.get('username'):
                        u_name = v_user['username']
                except: pass

            unlock_activities.append({
                '_id': notif['_id'],
                'note_id': notif.get('note_id'),
                'activity_type': 'surprise_unlocked',
                'latest_activity': notif['unlocked_at'],
                'share_id': notif.get('share_id'),
                'unlocked_by_name': u_name,
                'surprise_theme': notif.get('surprise_theme', 'none'),
                'is_read': notif.get('is_read', False),
                'unlocked_at': notif['unlocked_at']
            })

        # --- 4. Merge and Sort ---
        all_activities = own_posts + relevant_replies + unlock_activities

        # Sort by latest activity descending
        all_activities.sort(key=lambda x: x.get('latest_activity', datetime.datetime.min), reverse=True)

        # Limit to 20 items
        all_activities = all_activities[:20]

        # --- 5. Fetch Per-User View Timestamps ---
        post_ids = [post['_id'] for post in all_activities if post.get('activity_type') != 'surprise_unlocked']
        user_views = list(m.user_post_views_conf.find({
            'user_id': user_id,
            'post_id': {'$in': post_ids}
        }))
        user_view_map = {v['post_id']: v['last_viewed'] for v in user_views}

        # --- 6. Process for JSON Response ---
        unread_count = 0
        result_posts = []

        for post in all_activities:
            # Handle surprise unlock notifications separately
            if post.get('activity_type') == 'surprise_unlocked':
                activity_time = post.get('unlocked_at')
                if activity_time and activity_time.tzinfo is None:
                    activity_time = activity_time.replace(tzinfo=datetime.timezone.utc)
                
                is_unread = not post.get('is_read', False)
                if is_unread:
                    # Also check against last_check
                    if activity_time and activity_time > last_check:
                        unread_count += 1
                    else:
                        is_unread = False
                
                theme_labels = {
                    'valentine': 'Valentine',
                    'birthday': 'Birthday',
                    'anniversary': 'Anniversary',
                    'celebration': 'Celebration'
                }
                theme = post.get('surprise_theme', 'none')
                theme_label = theme_labels.get(theme, 'Surprise')
                
                u_name = post.get('unlocked_by_name', 'Someone')
                u_id = post.get('unlocked_by') # unlock_activities dict has the ID if we include it
                
                # Fetch original note title if possible
                note_title = "Shared note"
                if post.get('note_id'):
                    note = m.personal_posts_conf.find_one({'_id': post['note_id']})
                    if note:
                        ref = note.get('reference', '').strip()
                        if ref:
                            note_title = ref
                        else:
                            try:
                                decrypted = m._decrypt_note_record(note)
                                if decrypted:
                                    first_half = decrypted[:50].split('\n')[0].replace('#', '').strip()
                                    note_title = first_half if first_half else "Shared note"
                            except Exception:
                                note_title = "Encrypted note"
                            
                if theme == 'none':
                    title_text = f"Note accessed: {note_title}"
                    content_text = f"{u_name} viewed your note"
                else:
                    title_text = f"{theme_label} surprise unlocked"
                    content_text = f"{u_name} opened your {theme_label} surprise note"
                
                # For processed post data, let's just ensure we have the name
                
                post_data = {
                    '_id': str(post['_id']),
                    'activity_type': 'surprise_unlocked',
                    'has_unread': is_unread,
                    'share_id': post.get('share_id'),
                    'unlocked_by_name': u_name,
                    'surprise_theme': theme,
                    'theme_label': theme_label,
                    'unlocked_at': activity_time.isoformat() if activity_time else None,
                    'latest_comment_at': activity_time.isoformat() if activity_time else None,
                    'title': title_text,
                    'url': url_for('sharing.view_shared_note', share_id=post.get('share_id')) if post.get('share_id') else '#',
                    'content': content_text,
                    'author': u_name,
                    'slug': '',
                    'author_id': str(u_id) if u_id else '',
                    'timestamp': activity_time.strftime('%b %d, %Y') if activity_time else '',
                    'image_url': None,
                    'image_urls': [],
                    'video_url': None,
                    'comment_count': 0,
                    'likes_count': 0,
                    'share_count': 0,
                    'reactions': {}
                }
                result_posts.append(post_data)
                continue
            # Determine unread status
            activity_time = post.get('latest_activity')
            if activity_time and activity_time.tzinfo is None:
                activity_time = activity_time.replace(tzinfo=datetime.timezone.utc)

            # Determine the threshold time for this specific post
            # Threshold is the LATER of: global mark-all-read OR this specific post's last view by user
            post_last_viewed = user_view_map.get(post['_id'])
            
            # Legacy fallback: for own posts, check the old field if new one doesn't exist yet
            if not post_last_viewed and str(post.get('author_id')) == current_user.id:
                post_last_viewed = post.get('author_last_viewed')

            if post_last_viewed and post_last_viewed.tzinfo is None:
                post_last_viewed = post_last_viewed.replace(tzinfo=datetime.timezone.utc)

            threshold = last_check
            if post_last_viewed:
                threshold = max(last_check, post_last_viewed)

            # It's unread if the activity is newer than the threshold
            is_unread = False
            post_unread_count = 0
            
            # For own posts, we have the list of comments from the aggregation
            post_comments = post.get('post_comments', [])
            if post_comments:
                for c in post_comments:
                    c_time = c.get('created_at')
                    if c_time:
                        if c_time.tzinfo is None:
                            c_time = c_time.replace(tzinfo=datetime.timezone.utc)
                        if c_time > threshold:
                            is_unread = True
                            post_unread_count += 1
            else:
                # For replies (or posts without post_comments data), fallback to simple activity_time check
                if activity_time and activity_time > threshold:
                    is_unread = True
                    # In this case we just count it as 1 unread activity for now
                    post_unread_count = 1
            
            unread_count += post_unread_count


            post_data = {
                '_id': str(post['_id']),
                'title': post.get('title', ''),
                'slug': post.get('slug', ''),
                'url': url_for('blog.view_post', slug=post.get('slug', '')),
                'content': (post.get('content', '')[:100] + '...') if len(post.get('content', '')) > 100 else post.get('content', ''),
                'author': post.get('author', ''), # This is the POST author
                'author_id': str(post.get('author_id', '')),
                'timestamp': post.get('timestamp').strftime('%b %d, %Y') if post.get('timestamp') else '',
                'image_url': post.get('image_url'),
                'image_urls': post.get('image_urls', []),
                'video_url': post.get('video_url'),
                'comment_count': post.get('comment_count', 0), # Total comments on post
                'likes_count': post.get('likes_count', 0),
                'share_count': post.get('share_count', 0),
                'has_unread': is_unread,
                'activity_type': post.get('activity_type', 'comment'),
                'latest_comment_at': post.get('latest_activity').isoformat() if post.get('latest_activity') else None,
                'reactions': post.get('reactions', {})
            }
            result_posts.append(post_data)

        response = jsonify({
            'posts': result_posts,
            'unread_count': unread_count,
            'last_checked': last_check.isoformat()
        })
        # Add headers to prevent caching
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except Exception as e:
        current_app.logger.error(f"Error in get_my_commented_posts_json: {e}", exc_info=True)
        return jsonify({'error': 'Could not retrieve posts'}), 500


@bp.route('/api/posts/mark-all-read', methods=['POST'])
@login_required
def mark_all_comments_read():
    """
    Updates the current user's last_activity_check timestamp to now.
    This effectively marks all current activity as read.
    """
    import main as m
    try:
        user_id = ObjectId(current_user.id)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Start with current time as the marker
        leap_marker = now

        # 1. Check for latest relevant comments on user's own posts
        user_posts = list(m.posts_conf.find({'author_id': user_id}, {'slug': 1}))
        user_post_slugs = [p['slug'] for p in user_posts]

        if user_post_slugs:
            latest_comment = m.comments_conf.find_one(
                {'post_slug': {'$in': user_post_slugs}, 'author_id': {'$ne': user_id}, 'is_deleted': {'$ne': True}},
                projection={'created_at': 1},
                sort=[('created_at', -1)]
            )
            if latest_comment and latest_comment.get('created_at'):
                lc_time = latest_comment['created_at']
                if lc_time.tzinfo is None: lc_time = lc_time.replace(tzinfo=datetime.timezone.utc)
                if lc_time > leap_marker:
                    leap_marker = lc_time

        # 2. Check for latest replies to user's comments
        my_comments = list(m.comments_conf.find({'author_id': user_id}, {'_id': 1}))
        my_comment_ids = [c['_id'] for c in my_comments]

        if my_comment_ids:
            latest_reply = m.comments_conf.find_one(
                {'parent_id': {'$in': my_comment_ids}, 'author_id': {'$ne': user_id}, 'is_deleted': {'$ne': True}},
                projection={'created_at': 1},
                sort=[('created_at', -1)]
            )
            if latest_reply and latest_reply.get('created_at'):
                lr_time = latest_reply['created_at']
                if lr_time.tzinfo is None: lr_time = lr_time.replace(tzinfo=datetime.timezone.utc)
                if lr_time > leap_marker:
                    leap_marker = lr_time

        # Update the user's marker
        # Add a 1ms offset to ensure we definitely mark the 'latest' as read
        # MongoDB stores dates with millisecond precision
        m.users_conf.update_one(
            {'_id': user_id},
            {'$set': {'last_activity_check': leap_marker + datetime.timedelta(milliseconds=1)}}
        )
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Error in mark_all_comments_read: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


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
def api_post_comments(slug):
    import main as m
    import redis
    if request.method == 'GET':
        try:
            # Pagination support
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            if per_page <= 0: per_page = 10
            if page <= 0: page = 1

            total = m.comments_conf.count_documents({'post_slug': slug, 'is_deleted': False})
            cursor = m.comments_conf.find({'post_slug': slug, 'is_deleted': False}).sort('created_at', 1).skip((page-1)*per_page).limit(per_page)
            comments_list = list(cursor)
            
            # Recursive parent fetching for API to ensure consistency
            processed_comment_ids = set(str(c['_id']) for c in comments_list)
            while True:
                parents_to_fetch = []
                for c in comments_list:
                    parent_id = c.get('parent_id')
                    if parent_id and str(parent_id) not in processed_comment_ids:
                        parents_to_fetch.append(parent_id)
                if not parents_to_fetch:
                    break
                new_parents = list(m.comments_conf.find({'_id': {'$in': parents_to_fetch}}))
                if not new_parents:
                    break
                for p in new_parents:
                    p_id_str = str(p['_id'])
                    if p_id_str not in processed_comment_ids:
                        comments_list.append(p)
                        processed_comment_ids.add(p_id_str)
                comments_list.sort(key=lambda x: x.get('created_at') or datetime.datetime.min)

            # Compute reply counts for the serialized set
            all_ids = [c['_id'] for c in comments_list]
            reply_pipeline = [
                {'$match': {'parent_id': {'$in': all_ids}, 'is_deleted': False}},
                {'$group': {'_id': '$parent_id', 'count': {'$sum': 1}}}
            ]
            reply_agg = list(m.comments_conf.aggregate(reply_pipeline))
            r_counts = {str(doc['_id']): doc['count'] for doc in reply_agg}

            comments = [ m._serialize_comment(c, r_counts) for c in comments_list ]
            has_more = total > page * per_page
            return jsonify({'comments': comments, 'total': total, 'page': page, 'per_page': per_page, 'has_more': has_more})
        except Exception as e:
            current_app.logger.error(f"Failed to list comments for {slug}: {e}")
            return jsonify({'error': 'Could not retrieve comments'}), 500

    # POST -> create new comment
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401

    content = request.form.get('content') or (request.json and request.json.get('content'))
    parent_id_str = request.form.get('parent_id') or (request.json and request.json.get('parent_id'))
    if not content or not content.strip():
        return jsonify({'error': 'Empty comment'}), 400

    comment = {
        'post_slug': slug,
        'post_id': None,
        'author_id': ObjectId(current_user.id),
        'author_username': current_user.username,
        'content': content.strip(),
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'is_deleted': False,
        'parent_id': None,
    }
    # Fill in parent_id if provided
    if parent_id_str:
        try:
            comment['parent_id'] = ObjectId(parent_id_str)
        except Exception:
            comment['parent_id'] = None

    # Fill post_id for easier querying
    try:
        p = m.posts_conf.find_one({'slug': slug}, {'_id': 1})
        if p:
            comment['post_id'] = p.get('_id')
    except Exception:
        pass
    try:
        res = m.comments_conf.insert_one(comment)
        comment['_id'] = res.inserted_id
        comment_id_str = str(res.inserted_id)

        # Invalidate cached comment counts so lists update immediately
        try:
            m.comment_count_cache.clear()
        except Exception:
            pass

        # Invalidate post author's badge cache so their unread count updates
        try:
            post_doc = m.posts_conf.find_one({'slug': slug}, {'author_id': 1})
            if post_doc and str(post_doc.get('author_id')) != current_user.id:
                m._invalidate_badge_cache(str(post_doc['author_id']))
            # If replying to someone else's comment, invalidate that comment author too
            if parent_id_str:
                parent_comment = m.comments_conf.find_one({'_id': ObjectId(parent_id_str)}, {'author_id': 1})
                if parent_comment and str(parent_comment.get('author_id')) != current_user.id:
                    m._invalidate_badge_cache(str(parent_comment['author_id']))
        except Exception:
            pass

        # --- Send push notification to post author ---
        try:
            from notifications import send_push_notification_for_comment
            send_push_notification_for_comment.queue(comment_id_str, slug)
            current_app.logger.debug(f"Enqueued push notification for comment {comment_id_str}")
        except redis.exceptions.ConnectionError as e:
            current_app.logger.warning(f"Redis connection failed. Falling back to thread for comment push notification. Error: {e}")
            from notifications import send_push_notification_for_comment
            with current_app.app_context():
                m.executor.submit(send_push_notification_for_comment, comment_id_str, slug)
        except Exception as e:
            current_app.logger.error(f"Failed to enqueue push notification for comment: {e}")

        return jsonify(m._serialize_comment(comment)), 201
    except Exception as e:
        current_app.logger.error(f"Failed to create comment for {slug}: {e}")
        return jsonify({'error': 'Failed to create comment'}), 500


@bp.route('/api/comments/<comment_id>', methods=['DELETE'])
@login_required
def api_delete_comment(comment_id):
    import main as m
    try:
        comment = m.comments_conf.find_one({'_id': ObjectId(comment_id)})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Allow deletion by author or admin
        if str(comment.get('author_id')) != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Not authorized'}), 403

        # Absolute Hard-Delete Policy: All comments and their sub-replies are purged.
        m.comments_conf.delete_many({
            '$or': [
                {'_id': ObjectId(comment_id)},
                {'parent_id': ObjectId(comment_id)}
            ]
        })

        try:
            m.comment_count_cache.clear()
        except Exception:
            pass
        return jsonify({'status': 'deleted'})
    except Exception as e:
        current_app.logger.error(f"Failed to delete comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to delete comment'}), 500


@bp.route('/api/comments/<comment_id>', methods=['PUT', 'PATCH'])
@login_required
def api_edit_comment(comment_id):
    """Edit a comment. Only the author or an admin may edit."""
    import main as m
    content = None
    if request.json:
        content = request.json.get('content')
    else:
        content = request.form.get('content')

    if not content or not content.strip():
        return jsonify({'error': 'Empty content'}), 400

    try:
        comment = m.comments_conf.find_one({'_id': ObjectId(comment_id)})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Permission: author or admin
        if str(comment.get('author_id')) != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Not authorized'}), 403

        m.comments_conf.update_one({'_id': ObjectId(comment_id)}, {'$set': {'content': content.strip(), 'edited_at': datetime.datetime.now(datetime.timezone.utc)}})
        updated = m.comments_conf.find_one({'_id': ObjectId(comment_id)})
        try:
            m.comment_count_cache.clear()
        except Exception:
            pass
        return jsonify(m._serialize_comment(updated))
    except Exception as e:
        current_app.logger.error(f"Failed to edit comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to edit comment'}), 500


@bp.route('/api/comments/<comment_id>/vote', methods=['POST'])
@login_required
def api_vote_comment(comment_id):
    """Upvote or remove an upvote from a comment."""
    import main as m
    try:
        user_id = ObjectId(current_user.id)
        comment_oid = ObjectId(comment_id)

        # Find the comment to ensure it exists
        comment = m.comments_conf.find_one({'_id': comment_oid}, {'author_id': 1, 'upvoted_by': 1})
        if not comment:
            return jsonify({'error': 'Comment not found'}), 404

        # Users cannot vote on their own comments
        if comment.get('author_id') == user_id:
            return jsonify({'error': 'You cannot vote on your own comment'}), 403

        # Check if the user has already upvoted this comment
        is_already_voted = user_id in (comment.get('upvoted_by') or [])

        if is_already_voted:
            # Remove the upvote (un-vote)
            update_result = m.comments_conf.update_one(
                {'_id': comment_oid},
                {'$pull': {'upvoted_by': user_id}, '$inc': {'upvote_count': -1}}
            )
        else:
            # Add the upvote
            update_result = m.comments_conf.update_one(
                {'_id': comment_oid},
                {'$addToSet': {'upvoted_by': user_id}, '$inc': {'upvote_count': 1}}
            )

        new_count = m.comments_conf.find_one({'_id': comment_oid}, {'upvote_count': 1}).get('upvote_count', 0)
        return jsonify({'status': 'success', 'upvote_count': new_count, 'voted': not is_already_voted})
    except Exception as e:
        current_app.logger.error(f"Failed to vote on comment {comment_id}: {e}")
        return jsonify({'error': 'Failed to process vote'}), 500


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
