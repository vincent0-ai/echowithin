from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, send_from_directory, abort, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from bson.son import SON
import datetime, math, json, random, os, re
bp = Blueprint('blog', __name__, template_folder='templates')


def get_latest_posts_feed():
    import main as m
    cached_feed = m.blog_feed_cache.get('main')
    if cached_feed:
        return cached_feed

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
    return latest_posts_prepared



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
    latest_posts_prepared = get_latest_posts_feed()
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
    try:
        # Fetch all posts with necessary fields
        all_posts = list(m.posts_conf.find({}, {
            '_id': 1, 'title': 1, 'slug': 1, 'content': 1, 'author': 1, 
            'author_id': 1, 'timestamp': 1, 'image_url': 1, 'image_urls': 1, 
            'image_public_ids': 1, 'image_status': 1, 'video_url': 1, 
            'likes_count': 1, 'share_count': 1, 'reactions': 1, 'is_pinned': 1
        }))
        
        # Convert ObjectId and datetime to strings and add the post URL
        for post in all_posts:
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            if post.get('timestamp'):
                # Ensure it's timezone-aware if naive
                t = post['timestamp']
                if t.tzinfo is None:
                    t = t.replace(tzinfo=datetime.timezone.utc)
                # Format to local-like timezone format if needed or original format
                post['timestamp'] = t.strftime('%b %d, %Y at %I:%M %p')
            post['url'] = url_for('blog.view_post', slug=post['slug'], _external=True)
            
        return jsonify(all_posts)
    except Exception as e:
        current_app.logger.error(f"Error in get_all_posts_json: {e}")
        return jsonify({"error": "Could not retrieve posts"}), 500


@bp.route('/api/posts/top-by-comments')
def get_top_posts_json():
    import main as m
    import math as math_module
    
    # Check Redis cache first (cache for 2 minutes)
    cache_key = 'top_posts_by_engagement'
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached:
                return jsonify(json.loads(cached))
        except Exception:
            pass

    try:
        # Use aggregation pipeline for efficient server-side processing
        pipeline = [
            # Stage 1: Project only needed fields
            {'$project': {
                '_id': 1, 'title': 1, 'slug': 1, 'content': 1, 'author': 1, 'author_id': 1,
                'timestamp': 1, 'image_url': 1, 'image_urls': 1, 'image_public_ids': 1,
                'image_status': 1, 'video_url': 1, 'likes_count': 1,
                'share_count': 1, 'view_count': 1, 'reactions': 1, 'is_pinned': 1
            }},
            # Stage 2: Lookup comment counts
            {'$lookup': {
                'from': 'comments',
                'let': {'slug': '$slug'},
                'pipeline': [
                    {'$match': {'$expr': {'$eq': ['$post_slug', '$$slug']}, 'is_deleted': False}},
                    {'$count': 'count'}
                ],
                'as': 'comment_data'
            }},
            # Stage 3: Add computed fields
            {'$addFields': {
                'comment_count': {'$ifNull': [{'$arrayElemAt': ['$comment_data.count', 0]}, 0]},
                'likes_safe': {'$ifNull': ['$likes_count', 0]},
                'shares_safe': {'$ifNull': ['$share_count', 0]},
                'views_safe': {'$ifNull': ['$view_count', 0]}
            }},
            # Stage 4: Calculate raw engagement score
            {'$addFields': {
                'raw_engagement': {
                    '$add': [
                        {'$multiply': ['$comment_count', m.ENGAGEMENT_WEIGHTS['comment']]},
                        {'$multiply': ['$likes_safe', m.ENGAGEMENT_WEIGHTS['reaction']]},
                        {'$multiply': ['$shares_safe', m.ENGAGEMENT_WEIGHTS['share']]},
                        {'$multiply': ['$views_safe', m.ENGAGEMENT_WEIGHTS['view']]}
                    ]
                }
            }},
            # Stage 5: Sort by raw engagement and limit for top candidates
            {'$sort': {'raw_engagement': -1}},
            {'$limit': 50},
            # Stage 6: Remove lookup helper field
            {'$project': {'comment_data': 0, 'likes_safe': 0, 'shares_safe': 0, 'views_safe': 0}}
        ]

        posts = list(m.posts_conf.aggregate(pipeline))

        # Apply log dampening + time decay (like home page hot posts)
        now = datetime.datetime.now(datetime.timezone.utc)
        results = []

        for post in posts:
            if not post.get('slug'):
                continue

            comment_count = post.get('comment_count', 0)
            likes = post.get('likes_count', 0) or 0
            shares = post.get('share_count', 0) or 0
            views = post.get('view_count', 0) or 0
            raw_engagement = post.get('raw_engagement', 0)

            post_time = post.get('timestamp')
            if post_time:
                if post_time.tzinfo is None:
                    post_time = post_time.replace(tzinfo=datetime.timezone.utc)
                age_hours = (now - post_time).total_seconds() / 3600
            else:
                age_hours = 0

            # Log dampening on engagement (prevents early high-engagement posts from dominating)
            engagement_score = math_module.log1p(raw_engagement) * 10
            # Time decay denominator: (age_hours + 8)^1.2 - score drops as post ages
            time_decay = math_module.pow(age_hours + 8, 1.2)
            # Recency boost for very new posts
            recency_boost = 1.5 if age_hours < 2 else (1.2 if age_hours < 6 else 1.0)

            final_score = recency_boost * (engagement_score + 1) / time_decay

            # Format for JSON response
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            post['timestamp'] = post_time.strftime('%b %d, %Y at %I:%M %p') if post_time else None
            post['url'] = url_for('blog.view_post', slug=post['slug'], _external=True)
            post['comment_count'] = comment_count
            post['likes_count'] = likes
            post['share_count'] = shares
            post['view_count'] = views
            post['engagement_score'] = round(final_score, 2)

            post.pop('raw_engagement', None)
            results.append(post)

        results.sort(key=lambda x: x['engagement_score'], reverse=True)
        results = results[:20]

        # Batch-enrich with premium status and achievements
        result_author_ids = list(set(ObjectId(r['author_id']) for r in results if r.get('author_id')))
        premium_set = set()
        if result_author_ids:
            for u in m.users_conf.find({'_id': {'$in': result_author_ids}}, {'account_tier': 1, 'premium_until': 1, 'join_date': 1}):
                if m.get_user_tier(u) == 'premium':
                    premium_set.add(str(u['_id']))
        for r in results:
            aid = r.get('author_id')
            r['author_is_premium'] = aid in premium_set if aid else False
            r['author_achievements'] = m.get_active_achievements(ObjectId(aid)) if aid else []

        if m.redis_cache:
            try:
                m.redis_cache.setex(cache_key, 120, json.dumps(results, default=str))
            except Exception:
                pass

        return jsonify(results)
    except Exception as e:
        current_app.logger.error(f"Error in get_top_posts_json: {e}")
        return jsonify({'error': 'Could not retrieve top posts'}), 500


@bp.route('/api/posts/hot')
def get_hot_posts_json():
    import main as m
    try:
        # Fetch recent posts to calculate scores on (e.g., last 7 days)
        seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
        recent_posts = list(m.posts_conf.find(
            {'created_at': {'$gte': seven_days_ago}},
            {'_id': 1, 'title':1, 'slug':1, 'content':1, 'author':1, 'author_id':1, 'timestamp':1, 'created_at': 1, 'view_count': 1, 'image_url':1, 'image_urls':1, 'likes_count': 1, 'share_count': 1, 'reactions': 1}
        ))

        # Get comment counts for these posts
        slugs = [p['slug'] for p in recent_posts if p.get('slug')]
        comment_counts = {doc['_id']: doc.get('count', 0) for doc in m.comments_conf.aggregate([
            {'$match': {'post_slug': {'$in': slugs}, 'is_deleted': False}},
            {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}}
        ])}

        # Calculate hot score for each post
        scored_posts = []
        for post in recent_posts:
            if not post.get('slug'):
                continue
            comment_count = comment_counts.get(post['slug'], 0)
            post['hot_score'] = m.calculate_hot_score(post, comment_count)
            post['comment_count'] = comment_count
            post['_id'] = str(post['_id'])
            post['author_id'] = str(post.get('author_id'))
            
            # Formatting timestamp
            post_time = post.get('created_at') or post.get('timestamp')
            if post_time:
                if post_time.tzinfo is None:
                    post_time = post_time.replace(tzinfo=datetime.timezone.utc)
                post['timestamp'] = post_time.strftime('%b %d, %Y at %I:%M %p')
            else:
                post['timestamp'] = None
                
            post['url'] = url_for('blog.view_post', slug=post['slug'], _external=True)
            post['likes_count'] = post.get('likes_count', 0)
            post['share_count'] = post.get('share_count', 0)

            scored_posts.append(post)

        # Sort by hot score and return top 20
        scored_posts.sort(key=lambda p: p['hot_score'], reverse=True)
        return jsonify(scored_posts[:20])
    except Exception as e:
        current_app.logger.error(f"Error in get_hot_posts_json: {e}")
        return jsonify({'error': 'Could not retrieve hot posts'}), 500


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
        
        # OPTIMIZATION: Batch-fetch all user docs and note docs for unlock notifications
        # instead of individual find_one() calls per notification
        _unlock_user_ids = list(set(ObjectId(n['unlocked_by']) for n in unlock_notifs if n.get('unlocked_by')))
        _unlock_users_map = {}
        if _unlock_user_ids:
            for u in m.users_conf.find({'_id': {'$in': _unlock_user_ids}}, {'username': 1}):
                _unlock_users_map[str(u['_id'])] = u.get('username', 'Someone')

        _unlock_note_ids = list(set(n['note_id'] for n in unlock_notifs if n.get('note_id')))
        _unlock_notes_map = {}
        if _unlock_note_ids:
            for n in m.personal_posts_conf.find(
                {'_id': {'$in': _unlock_note_ids}},
                {'reference': 1, 'content': 1, 'user_id': 1, 'content_owner_id': 1, 'owner_id': 1, 'source_owner_id': 1, 'saved_from_owner_id': 1, 'source_note_id': 1}
            ):
                _unlock_notes_map[n['_id']] = n

        unlock_activities = []
        for notif in unlock_notifs:
            u_id = notif.get('unlocked_by')
            u_name = _unlock_users_map.get(str(u_id), notif.get('unlocked_by_name', 'Someone')) if u_id else notif.get('unlocked_by_name', 'Someone')

            unlock_activities.append({
                '_id': notif['_id'],
                'note_id': notif.get('note_id'),
                'activity_type': 'surprise_unlocked',
                'latest_activity': notif['unlocked_at'],
                'share_id': notif.get('share_id'),
                'unlocked_by_name': u_name,
                'unlocked_by': u_id,
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
                u_id = post.get('unlocked_by')
                
                # Use batch-fetched note data instead of individual queries
                note_title = "Shared note"
                if post.get('note_id'):
                    note = _unlock_notes_map.get(post['note_id'])
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
        # Invalidate user loader cache so changes take effect immediately
        cache_key = f"user:{current_user.id}"
        m.user_loader_cache.pop(cache_key, None)
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
    import secrets
    import redis
    import urllib.request
    from werkzeug.utils import secure_filename
    
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content", '') or ''
        tags = request.form.getlist("tags")
        images_files = request.files.getlist('images') if request.files else []
        image_alts = request.form.getlist('image_alts') if request.form else []
        video_file = request.files.get('video')

        temp_image_paths = []
        temp_video_path = None

        has_media = any(f and f.filename for f in images_files) or (video_file and video_file.filename)
        if title and (content or has_media):
            base_slug = m.slugify(title)
            if not base_slug:
                base_slug = f"post-{secrets.token_hex(6)}"
            slug = base_slug
            counter = 1
            while m.posts_conf.find_one({'slug': slug}):
                slug = f"{base_slug}-{counter}"
                counter += 1

            # Save files temporarily for background processing
            for img_file in images_files:
                if img_file and img_file.filename and '.' in img_file.filename and img_file.filename.rsplit('.', 1)[1].lower() in m.ALLOWED_IMAGE_EXTENSIONS:
                    try:
                        img_file.stream.seek(0, os.SEEK_END)
                        img_size = img_file.stream.tell()
                        img_file.stream.seek(0)
                        if img_size > m.MAX_IMAGE_SIZE:
                            continue  # Skip images exceeding 5 MB
                    except Exception:
                        pass
                    filename = secure_filename(f"{secrets.token_hex(8)}-{img_file.filename}")
                    path = os.path.join(current_app.config['TEMP_UPLOAD_FOLDER'], filename)
                    img_file.save(path)
                    temp_image_paths.append(path)

            if video_file and video_file.filename and '.' in video_file.filename and video_file.filename.rsplit('.', 1)[1].lower() in m.ALLOWED_VIDEO_EXTENSIONS:
                try:
                    stream = video_file.stream
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    stream.seek(0)
                    if size <= m.MAX_VIDEO_SIZE:
                        filename = secure_filename(f"{secrets.token_hex(8)}-{video_file.filename}")
                        path = os.path.join(current_app.config['TEMP_UPLOAD_FOLDER'], filename)
                        video_file.save(path)
                        temp_video_path = path
                except Exception:
                    pass

            normalized_alts = []
            for i in range(len(images_files)):
                try:
                    alt = image_alts[i].strip()
                except Exception:
                    alt = ''
                if not alt:
                    alt = f"{title} image {i+1}"
                normalized_alts.append(alt)

            new_post_data = {
                'author_id': ObjectId(current_user.id),
                'slug': slug,
                'title': title,
                'content': content,
                'tags': [t.strip().lower() for t in tags if t.strip()],
                'author': current_user.username,
                'status': 'processing_media' if temp_image_paths or temp_video_path else 'published',
                'view_count': 0,
                'timestamp': datetime.datetime.now(datetime.timezone.utc),
                'image_alts': normalized_alts,
            }
            result = m.posts_conf.insert_one(new_post_data)
            post_id_str = str(result.inserted_id)

            # Enqueue media processing
            if temp_image_paths or temp_video_path:
                try:
                    m.process_post_media.queue(post_id_str, temp_image_paths, temp_video_path)
                    current_app.logger.info(f"Enqueued media processing job for post {post_id_str}")
                except redis.exceptions.ConnectionError as e:
                    current_app.logger.warning(f"Redis connection failed. Falling back to thread for media processing. Error: {e}")
                    with current_app.app_context():
                        m.executor.submit(m.process_post_media, post_id_str, temp_image_paths, temp_video_path)
                except Exception as e:
                    current_app.logger.error(f"Failed to process media for post {post_id_str}: {e}")
                    m.posts_conf.delete_one({'_id': ObjectId(post_id_str)})
                    flash("Could not create post due to a server issue. Please try again.", "danger")
                    return redirect(url_for("blog.blog"))
            else:
                try:
                    m.send_new_post_notifications.queue(post_id_str)
                    current_app.logger.info(f"Enqueued notification job for post {post_id_str}")
                except redis.exceptions.ConnectionError as e:
                    current_app.logger.warning(f"Redis connection failed. Falling back to thread for notifications. Error: {e}")
                    with current_app.app_context():
                        m.executor.submit(m.send_new_post_notifications, post_id_str)
                except Exception as e:
                    current_app.logger.error(f"Failed to enqueue notification job for post {post_id_str}: {e}")
                
                try:
                    if m._t.ts_posts:
                        m.index_post_to_typesense(post_id_str)
                except Exception as e:
                    current_app.logger.debug(f"Typesense index skipped for {post_id_str}: {e}")

            # Send ntfy notification
            try:
                ntfy_message = f"\"{title}\" by {current_user.username}"
                m.send_ntfy_notification.queue(ntfy_message, "New Post Created", "tada")
            except redis.exceptions.ConnectionError as e:
                current_app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {e}")
                with current_app.app_context():
                    m.executor.submit(m.send_ntfy_notification, ntfy_message, "New Post Created", "tada")
            except Exception as e:
                current_app.logger.error(f"Failed to enqueue ntfy notification for new post: {e}")

            # Send web push notifications
            try:
                m.send_push_notifications_for_new_post.queue(post_id_str)
                current_app.logger.info(f"Enqueued push notification job for post {post_id_str}")
            except redis.exceptions.ConnectionError as e:
                current_app.logger.warning(f"Redis connection failed. Falling back to thread for push notifications. Error: {e}")
                with current_app.app_context():
                    m.executor.submit(m.send_push_notifications_for_new_post, post_id_str)
            except Exception as e:
                current_app.logger.error(f"Failed to enqueue push notification for new post: {e}")

            # Clear sitemap cache
            try:
                if m.redis_cache:
                    m.redis_cache.delete('sitemap_index_xml')
                ping_url = 'https://www.google.com/ping?sitemap=https://echowithin.xyz/sitemap_index.xml'
                urllib.request.urlopen(ping_url, timeout=5)
            except Exception as e:
                current_app.logger.debug(f"Sitemap ping failed (non-critical): {e}")

            flash("Post created successfully!", "success")
        else:
            flash("Title is required. Content is also required unless you attach media.", "danger")
    return redirect(url_for("blog.blog"))


@bp.route('/uploads/<filename>')
def uploaded_file(filename):
    import main as m
    return send_from_directory(m.UPLOAD_FOLDER, filename)


@bp.route('/post/<slug>')
def view_post(slug):
    import main as m
    import markdown
    import bleach
    post = m.posts_conf.find_one({'slug': slug})
    if not post:
        flash("Post not found.", "danger")
        return redirect(url_for('blog.blog'))

    # If current user is the author, update author_last_viewed
    if current_user.is_authenticated:
        try:
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            # Update author-specific marker if they are the author
            if str(post.get('author_id')) == current_user.id:
                m.posts_conf.update_one(
                    {'_id': post['_id']},
                    {'$set': {'author_last_viewed': now_utc}}
                )
        except Exception as e:
            current_app.app_context().logger.error(f"Failed to update view tracking for post {slug}: {e}")

    # Convert post content from Markdown to HTML
    post_html = markdown.markdown(post.get('content', ''), extensions=['fenced_code', 'nl2br'])
    # Linkify bare URLs in post content
    post_html = bleach.linkify(post_html, callbacks=[m._linkify_target_blank], parse_email=True)
    post['content'] = post_html

    # --- Fetch Related Posts using Typesense (with caching) ---
    related_posts = []
    post_id_str = str(post['_id'])

    # Try cache first
    related_cache_key = f"related_posts:{post_id_str}"
    cached_related = m.related_posts_cache.get(related_cache_key)

    if cached_related is not None:
        related_posts = cached_related
    elif m._t.ts_posts:
        try:
            search_query = post.get('title', '')
            search_params = {
                'q': search_query or '*',
                'query_by': 'title,content,tags',
                'per_page': 4,
                'filter_by': f'id:!={post_id_str}',
            }

            if post.get('tags'):
                tags_str = " ".join(post.get('tags'))
                search_query = f"{tags_str} {search_query}"
                search_params['q'] = search_query

            search_result = m._t._ts_search('posts', search_params)
            hits = search_result.get('hits', [])
            related_posts_raw = [h.get('document', h) for h in hits[:3]]

            for p in related_posts_raw:
                if p.get('created_at'):
                    p['created_at'] = datetime.datetime.fromtimestamp(p['created_at'], tz=datetime.timezone.utc)
            related_posts = related_posts_raw

            m.related_posts_cache[related_cache_key] = related_posts
        except Exception as e:
            current_app.logger.error(f"Failed to get similar posts for {post_id_str}: {e}")

    # Add comment count and fetch recent comments
    try:
        comment_count = m.comments_conf.count_documents({'post_slug': slug, 'is_deleted': False})
        comment_page = 1
        per_page = 10
        comments = list(m.comments_conf.find({'post_slug': slug, 'is_deleted': False}).sort('created_at', 1).skip((comment_page-1)*per_page).limit(per_page))
        reply_counts = {}
        try:
            pipeline = [
                {'$match': {'post_slug': slug, 'is_deleted': False, 'parent_id': {'$ne': None}}},
                {'$group': {'_id': '$parent_id', 'count': {'$sum': 1}}}
            ]
            agg = list(m.comments_conf.aggregate(pipeline))
            for doc in agg:
                reply_counts[str(doc['_id'])] = doc.get('count', 0)
        except Exception as e:
            current_app.logger.debug(f"Failed to compute reply counts for post {slug}: {e}")

        # Ensure that all parent comments are present so replies can be correctly nested in the UI
        try:
            processed_comment_ids = set(str(c['_id']) for c in comments)
            while True:
                parents_to_fetch = []
                for c in comments:
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
                        comments.append(p)
                        processed_comment_ids.add(p_id_str)
                
                comments.sort(key=lambda x: x.get('created_at') or datetime.datetime.min)
        except Exception as e:
            current_app.logger.debug(f"Failed to fetch recursive parent comments for post {slug}: {e}")
        has_more = comment_count > comment_page * per_page
    except Exception as e:
        current_app.logger.error(f"Failed to load comments for post {slug}: {e}")
        comment_count = 0
        comments = []
        comment_page = 1
        per_page = 10
        has_more = False

    page_title = post.get('title', 'View Post')
    raw_content_doc = m.posts_conf.find_one({'slug': slug}, {'content': 1})
    raw_text = raw_content_doc.get('content', '') if raw_content_doc else ''
    
    clean_text = re.sub(r'[#*_`\[\]()>~]', '', raw_text)
    clean_text = clean_text.replace('\n', ' ').replace('\r', ' ')
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    clean_text = m.clean_xml_text(clean_text)
    
    page_description = (clean_text[:155] + '...') if len(clean_text) > 155 else clean_text

    is_saved = False
    if current_user.is_authenticated:
        u = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'saved_posts': 1})
        if u and post['_id'] in u.get('saved_posts', []):
            is_saved = True

        if str(post.get('author_id')) == current_user.id:
            try:
                now = datetime.datetime.now(datetime.timezone.utc)
                latest_p_comment = m.comments_conf.find_one(
                    {'post_slug': slug, 'author_id': {'$ne': ObjectId(current_user.id)}, 'is_deleted': {'$ne': True}},
                    projection={'created_at': 1},
                    sort=[('created_at', -1)]
                )

                view_marker = now
                if latest_p_comment and latest_p_comment.get('created_at'):
                    lp_time = latest_p_comment['created_at']
                    if lp_time.tzinfo is None: lp_time = lp_time.replace(tzinfo=datetime.timezone.utc)
                    if lp_time > view_marker:
                        view_marker = lp_time

                m.posts_conf.update_one(
                    {'_id': post['_id']},
                    {'$set': {'author_last_viewed': view_marker}}
                )
            except Exception as e:
                current_app.logger.debug(f"Failed to update author_last_viewed for post {slug}: {e}")

    # Prepare SEO meta fields
    meta_url = url_for('blog.view_post', slug=slug, _external=True)
    meta_image = None
    if post.get('image_urls'):
        meta_image = post.get('image_urls')[0]
    elif post.get('image_url'):
        meta_image = post.get('image_url')
    elif post.get('video_url'):
        video_url = post['video_url']
        if 'res.cloudinary.com' in video_url:
            thumb_url = video_url.rsplit('.', 1)[0] + '.jpg'
            thumb_url = thumb_url.replace('/video/upload/', '/video/upload/so_0,w_1200,h_630,c_fill/')
            meta_image = thumb_url
        else:
            meta_image = url_for('static', filename='logo-512.png', _external=True)
    else:
        meta_image = url_for('static', filename='logo-512.png', _external=True)

    # JSON-LD structured data for the post
    try:
        jsonld_article = {
            "@context": "https://schema.org",
            "@type": "BlogPosting",
            "mainEntityOfPage": {
                "@type": "WebPage",
                "@id": meta_url
            },
            "headline": post.get('title', '')[:110],
            "image": [meta_image] if meta_image else [],
            "author": {
                "@type": "Person",
                "name": post.get('author')
            },
            "publisher": {
                "@type": "Organization",
                "name": "EchoWithin",
                "logo": {
                    "@type": "ImageObject",
                    "url": url_for('static', filename='logo.png', _external=True)
                }
            },
            "datePublished": post.get('timestamp').isoformat() if post.get('timestamp') else None,
            "dateModified": (post.get('edited_at') or post.get('timestamp', '')).isoformat() if (post.get('edited_at') or post.get('timestamp')) else None,
            "url": meta_url,
            "description": page_description
        }
        jsonld_breadcrumb = {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {
                    "@type": "ListItem",
                    "position": 1,
                    "name": "Blog",
                    "item": url_for('blog.blog', _external=True)
                },
                {
                    "@type": "ListItem",
                    "position": 2,
                    "name": post.get('title', '')[:60]
                }
            ]
        }

        # Build combined JSON-LD string
        jsonld_str = json.dumps(jsonld_article) + '</script>\n<script type="application/ld+json">' + json.dumps(jsonld_breadcrumb)

        if post.get('video_url'):
            video_url = post['video_url']
            jsonld_video = {
                "@context": "https://schema.org",
                "@type": "VideoObject",
                "name": post.get('title', 'Video'),
                "description": page_description,
                "contentUrl": video_url,
                "uploadDate": post.get('timestamp').isoformat() if post.get('timestamp') else None,
                "thumbnailUrl": meta_image or url_for('static', filename='logo-512.png', _external=True)
            }
            jsonld_article["video"] = jsonld_video
            jsonld_str = json.dumps(jsonld_article) + '</script>\n<script type="application/ld+json">' + json.dumps(jsonld_breadcrumb) + '</script>\n<script type="application/ld+json">' + json.dumps(jsonld_video)
    except Exception:
        jsonld_str = ''

    return render_template('view_post.html', post=post, comments=comments, comment_count=comment_count, comment_page=comment_page, per_page=per_page, has_more=has_more, active_page='blog', title=page_title, description=page_description, reply_counts=reply_counts, meta_image=meta_image, meta_url=meta_url, meta_jsonld=jsonld_str, related_posts=related_posts, is_saved=is_saved)


@bp.route('/api/posts/<post_id>/view', methods=['POST'])
def api_record_post_view(post_id):
    import main as m
    try:
        if current_user.is_authenticated:
            user_identifier = str(current_user.id)
        else:
            visitor_id = request.headers.get('X-Visitor-ID') or request.cookies.get('echowithin_visitor_id')
            user_identifier = f"visitor:{visitor_id}" if visitor_id else f"ip:{request.remote_addr}"

        view_record = m.logs_conf.find_one({
            'type': 'post_view',
            'post_id': ObjectId(post_id),
            'user_identifier': user_identifier,
        })

        if not view_record:
            m.logs_conf.insert_one({
                'type': 'post_view',
                'post_id': ObjectId(post_id),
                'user_identifier': user_identifier,
                'timestamp': datetime.datetime.now(datetime.timezone.utc)
            })
            m.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$inc': {'view_count': 1}})

        if current_user.is_authenticated:
            try:
                m.user_post_views_conf.update_one(
                    {'user_id': ObjectId(current_user.id), 'post_id': ObjectId(post_id)},
                    {'$set': {'last_viewed': datetime.datetime.now(datetime.timezone.utc)}},
                    upsert=True
                )
            except Exception as ev:
                current_app.logger.error(f"Failed to update per-user view for post {post_id}: {ev}")

        post = m.posts_conf.find_one({'_id': ObjectId(post_id)}, {'view_count': 1})
        view_count = post.get('view_count', 0) if post else 0
        return jsonify({'success': True, 'view_count': view_count})
    except Exception as e:
        current_app.logger.error(f"Failed to record view for post {post_id}: {e}")
        return jsonify({'success': False, 'error': 'Failed to record view'}), 500


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
    return render_template('edit_post.html', post=post, active_page='blog', title=f"Editing: {post.get('title')} - EchoWithin", description="Edit your post.")


@bp.route('/update_post/<post_id>', methods=['POST'])
@login_required
def update_post(post_id):
    import main as m
    import secrets
    import redis
    post = m.posts_conf.find_one({'_id': ObjectId(post_id)})
    if not post:
        abort(404)
    if str(post.get('author_id')) != current_user.id:
        flash("You can only edit your own posts.", "danger")
        return redirect(url_for('blog.view_post', slug=post.get('slug')))

    title = request.form.get("title")
    content = request.form.get("content")
    tags = request.form.getlist("tags")
    images_files = request.files.getlist('images') if request.files else []
    video_file = request.files.get('video')
    
    image_url = post.get('image_url')
    image_public_id = post.get('image_public_id')
    image_urls = post.get('image_urls', [])
    image_public_ids = post.get('image_public_ids', [])
    video_url = post.get('video_url')
    video_public_id = post.get('video_public_id')
    slug = post.get('slug')
    image_status = post.get('image_status', 'none')
    video_status = post.get('video_status', 'none')

    content = content or ''
    has_existing_media = bool(image_urls) or bool(image_url) or bool(video_url)
    has_new_media = any(f and f.filename for f in images_files) or (video_file and video_file.filename)

    if title and (content or has_existing_media or has_new_media):
        if images_files and any(f and f.filename for f in images_files):
            try:
                old_publics = []
                if isinstance(image_public_id, list):
                    old_publics = image_public_id
                elif image_public_id:
                    old_publics = [image_public_id]
                elif image_public_ids:
                    old_publics = image_public_ids
                for pid in old_publics:
                    try:
                        m.cloudinary.uploader.destroy(pid)
                    except Exception:
                        current_app.logger.debug(f"Failed to delete old Cloudinary image {pid}")

                new_urls = []
                new_publics = []
                for img_file in images_files:
                    if not img_file or not img_file.filename:
                        continue
                    if '.' not in img_file.filename:
                        continue
                    ext = img_file.filename.rsplit('.', 1)[1].lower()
                    if ext not in m.ALLOWED_IMAGE_EXTENSIONS:
                        continue
                    try:
                        img_file.stream.seek(0, os.SEEK_END)
                        img_size = img_file.stream.tell()
                        img_file.stream.seek(0)
                        if img_size > m.MAX_IMAGE_SIZE:
                            continue
                    except Exception:
                        pass
                    upload_result = m.cloudinary.uploader.upload(img_file, folder="echowithin_posts")
                    url = m.optimize_cloudinary_url(upload_result.get('secure_url'))
                    pid = upload_result.get('public_id')
                    if url:
                        new_urls.append(url)
                    if pid:
                        new_publics.append(pid)

                if new_urls:
                    image_urls = new_urls
                    image_url = new_urls[0]
                if new_publics:
                    image_public_ids = new_publics
                    image_public_id = new_publics[0]
                image_status = 'safe'
                try:
                    for url, pid in zip(new_urls, new_publics):
                        m.process_image_for_nsfw.queue(post_id, url, pid)
                except Exception as e:
                    current_app.logger.debug(f"Failed to enqueue NSFW checks for updated images: {e}")
            except Exception as e:
                try:
                    message = f"NSFW content detected in post '{post.get('title')}' by {post.get('author')}. Image has been flagged."
                    m.send_ntfy_notification.queue(message, "NSFW Content Detected", "see_no_evil")
                except redis.exceptions.ConnectionError as ntfy_e:
                    current_app.logger.warning(f"Redis connection failed. Falling back to thread for ntfy notification. Error: {ntfy_e}")
                    with current_app.app_context():
                        m.executor.submit(m.send_ntfy_notification, message, "NSFW Content Detected", "see_no_evil")
                except Exception as ntfy_e:
                    current_app.logger.error(f"Failed to enqueue ntfy notification for NSFW content: {ntfy_e}")
                current_app.logger.error(f"Cloudinary upload/delete failed during update: {e}")

        if video_file and video_file.filename != '' and '.' in video_file.filename:
            video_ext = video_file.filename.rsplit('.', 1)[1].lower()
            if video_ext not in m.ALLOWED_VIDEO_EXTENSIONS:
                flash('Unsupported video format. Allowed: mp4, webm, ogg, mov', 'danger')
                return redirect(url_for('blog.view_post', slug=slug))
            try:
                stream = video_file.stream
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(0)
            except Exception:
                size = None

            if size is not None and size > m.MAX_VIDEO_SIZE:
                flash('Video exceeds maximum allowed size of 50 MB.', 'danger')
                return redirect(url_for('blog.view_post', slug=slug))

            try:
                if video_public_id:
                    m.cloudinary.uploader.destroy(video_public_id, resource_type='video')
                upload_result = m.cloudinary.uploader.upload(
                    video_file,
                    resource_type='video',
                    folder='echowithin_posts',
                    eager=[{"quality": "auto", "fetch_format": "mp4"}],
                    eager_async=True
                )
                video_url = m.optimize_cloudinary_url(upload_result.get('secure_url'))
                video_public_id = upload_result.get('public_id')
                video_status = 'uploaded'
            except Exception as e:
                current_app.logger.error(f"Cloudinary video upload/delete failed during update: {e}")

        if title != post.get('title'):
            base_slug = m.slugify(title)
            if not base_slug:
                base_slug = f"post-{secrets.token_hex(6)}"
            new_slug = base_slug
            counter = 1
            while m.posts_conf.find_one({'slug': new_slug, '_id': {'$ne': post['_id']}}):
                new_slug = f"{base_slug}-{counter}"
                counter += 1
            slug = new_slug

        m.posts_conf.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {
                'title': title,
                'content': content,
                'tags': [t.strip().lower() for t in tags if t.strip()],
                'image_url': image_url,
                'image_public_id': image_public_id,
                'image_urls': image_urls,
                'image_public_ids': image_public_ids,
                'image_status': image_status,
                'video_url': video_url,
                'video_public_id': video_public_id,
                'video_status': video_status,
                'slug': slug,
                'edited_at': datetime.datetime.now(datetime.timezone.utc),
            }}
        )
        try:
            if m._t.ts_posts:
                m.index_post_to_typesense(post_id)
        except Exception as e:
            current_app.logger.error(f"Failed to re-index post {post_id} after update: {e}")
        flash("Post updated successfully!", "success")
        return redirect(url_for('blog.view_post', slug=slug))
    else:
        flash("Title and content/media cannot be empty.", "danger")
    return redirect(url_for('blog.view_post', slug=slug))


@bp.route('/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    import main as m
    post_to_delete = m.posts_conf.find_one({'_id': ObjectId(post_id)})

    if not post_to_delete or str(post_to_delete.get('author_id')) != current_user.id:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('blog.blog'))

    # Delete the image from Cloudinary if it exists
    if post_to_delete.get('image_public_id'):
        try:
            m.cloudinary.uploader.destroy(post_to_delete['image_public_id'])
        except Exception as e:
            current_app.logger.error(f"Failed to delete Cloudinary image {post_to_delete.get('image_public_id')}: {e}")

    # Support multiple images list deletion
    if post_to_delete.get('image_public_ids'):
        for pid in post_to_delete['image_public_ids']:
            try:
                m.cloudinary.uploader.destroy(pid)
            except Exception as e:
                current_app.logger.error(f"Failed to delete Cloudinary image {pid}: {e}")

    # Delete the video from Cloudinary if it exists
    if post_to_delete.get('video_public_id'):
        try:
            m.cloudinary.uploader.destroy(post_to_delete['video_public_id'], resource_type='video')
        except Exception as e:
            current_app.logger.error(f"Failed to delete Cloudinary video {post_to_delete.get('video_public_id')}: {e}")

    m.posts_conf.delete_one({'_id': ObjectId(post_id)})
    m.comments_conf.delete_many({'post_slug': post_to_delete.get('slug')})

    flash('Post deleted successfully.', 'success')
    return redirect(url_for('blog.blog'))


@bp.route('/post/<post_id>/react', methods=['POST'])
@login_required
def toggle_reaction_post(post_id):
    import main as m
    try:
        # Support both 'reaction' and 'emoji' keys to be backward-compatible
        data = request.get_json() or {}
        reaction_type = data.get('reaction') or data.get('emoji') or 'heart'
        
        # Allowed reactions
        allowed = ['heart', 'wow', 'insightful', 'laugh', 'sad']
        if reaction_type not in allowed:
            reaction_type = 'heart'

        post_oid = ObjectId(post_id)
        post = m.posts_conf.find_one({'_id': post_oid})
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        user_id = str(current_user.id)

        # Reactions are stored as a dict: { "heart": [user_id, ...], "wow": [...] }
        reactions = post.get('reactions', {})
        if not isinstance(reactions, dict):
            reactions = {}

        # Find which reaction types this user currently has
        current_user_reactions = [r for r, users in reactions.items() if user_id in users]

        is_added = False
        if reaction_type in current_user_reactions:
            # Toggle OFF: user already has this exact reaction, remove it
            m.posts_conf.update_one(
                {'_id': post_oid},
                {'$pull': {f'reactions.{reaction_type}': user_id}}
            )
            is_added = False
        else:
            # Build a single atomic update: pull from all old reactions + addToSet new one
            update_ops = {'$addToSet': {f'reactions.{reaction_type}': user_id}}
            if current_user_reactions:
                pull_ops = {f'reactions.{old}': user_id for old in current_user_reactions}
                m.posts_conf.update_one({'_id': post_oid}, {'$pull': pull_ops})
            # Add new reaction
            m.posts_conf.update_one({'_id': post_oid}, update_ops)
            is_added = True

        # Reconcile likes_count from actual reaction data
        updated_post = m.posts_conf.find_one({'_id': post_oid})
        new_reactions = updated_post.get('reactions', {})
        actual_total = sum(len(users) for users in new_reactions.values() if isinstance(users, list))
        reaction_counts = {r: len(u) for r, u in new_reactions.items() if isinstance(u, list)}

        # Sync likes_count to match reality
        if updated_post.get('likes_count') != actual_total:
            m.posts_conf.update_one({'_id': post_oid}, {'$set': {'likes_count': actual_total}})

        # Emit WebSocket event for real-time reaction update
        m.socketio.emit('post_reacted', {
            'post_id': post_id,
            'reaction_counts': reaction_counts,
            'total_count': actual_total
        })

        return jsonify({
            'success': True,
            'reaction': reaction_type if is_added else None,
            'reaction_counts': reaction_counts,
            'total_count': actual_total
        })

    except Exception as e:
        current_app.logger.error(f"Error toggling reaction for post {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/post/<post_id>/toggle_save', methods=['POST'])
@login_required
def toggle_save_post(post_id):
    import main as m
    try:
        post_oid = ObjectId(post_id)
        post = m.posts_conf.find_one({'_id': post_oid})
        if not post:
            if request.is_json:
                return jsonify({'error': 'Post not found'}), 404
            flash('Post not found.', 'danger')
            return redirect(url_for('pages.home'))

        user_id = ObjectId(current_user.id)
        user = m.users_conf.find_one({'_id': user_id})
        saved_posts = user.get('saved_posts', [])

        is_saved = False
        if post_oid in saved_posts:
            m.users_conf.update_one({'_id': user_id}, {'$pull': {'saved_posts': post_oid}})
            is_saved = False
        else:
            m.users_conf.update_one({'_id': user_id}, {'$addToSet': {'saved_posts': post_oid}})
            is_saved = True

        if request.is_json:
            return jsonify({'saved': is_saved})

        flash('Post saved!' if is_saved else 'Post removed from saved.', 'success')
        return redirect(request.referrer or url_for('blog.view_post', slug=post['slug']))
    except Exception as e:
        current_app.logger.error(f"Error toggling save for post {post_id}: {e}")
        if request.is_json:
            return jsonify({'error': 'Internal error'}), 500
        flash('An error occurred.', 'danger')
        return redirect(url_for('pages.home'))


@bp.route('/post/<post_id>/share', methods=['POST'])
def share_post(post_id):
    import main as m
    try:
        post_oid = ObjectId(post_id)
        post = m.posts_conf.find_one({'_id': post_oid}, {'slug': 1, 'title': 1, 'share_count': 1})
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        # Increment share count
        m.posts_conf.update_one({'_id': post_oid}, {'$inc': {'share_count': 1}})

        # Get updated count
        updated_post = m.posts_conf.find_one({'_id': post_oid}, {'share_count': 1})
        share_count = updated_post.get('share_count', 1) if updated_post else 1

        # Generate shareable URL
        share_url = url_for('blog.view_post', slug=post['slug'], _external=True)

        return jsonify({
            'success': True,
            'share_count': share_count,
            'share_url': share_url,
            'title': post.get('title', 'Check out this post on EchoWithin')
        })
    except Exception as e:
        current_app.logger.error(f"Error tracking share for post {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/api/post/<post_id>/share-data')
def get_share_data(post_id):
    import main as m
    try:
        post_oid = ObjectId(post_id)
        post = m.posts_conf.find_one({'_id': post_oid}, {'slug': 1, 'title': 1, 'content': 1, 'share_count': 1})
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        share_url = url_for('blog.view_post', slug=post['slug'], _external=True)
        title = post.get('title', 'Check out this post')

        content = post.get('content', '')
        # Strip HTML and truncate
        clean_content = re.sub('<[^<]+?>', '', content)
        description = clean_content[:150] + '...' if len(clean_content) > 150 else clean_content

        # URL-encode for share links
        from urllib.parse import quote
        encoded_url = quote(share_url, safe='')
        encoded_title = quote(title, safe='')
        encoded_text = quote(f"{title} - {description}", safe='')

        return jsonify({
            'share_url': share_url,
            'title': title,
            'description': description,
            'share_count': post.get('share_count', 0),
            'platforms': {
                'twitter': f"https://twitter.com/intent/tweet?url={encoded_url}&text={encoded_title}",
                'facebook': f"https://www.facebook.com/sharer/sharer.php?u={encoded_url}",
                'linkedin': f"https://www.linkedin.com/sharing/share-offsite/?url={encoded_url}",
                'whatsapp': f"https://wa.me/?text={encoded_text}%20{encoded_url}",
                'telegram': f"https://t.me/share/url?url={encoded_url}&text={encoded_title}",
                'reddit': f"https://reddit.com/submit?url={encoded_url}&title={encoded_title}",
                'email': f"mailto:?subject={encoded_title}&body={encoded_text}%0A%0A{encoded_url}"
            }
        })
    except Exception as e:
        current_app.logger.error(f"Error getting share data for post {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500
