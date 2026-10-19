import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security


class TestPostSlugAndModel:
    """Tests for post slug generation and metadata formatting."""

    def test_post_document_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        post = {
            '_id': ObjectId(),
            'title': 'My First Post',
            'slug': 'my-first-post',
            'content': 'Hello world markdown content',
            'author': 'testuser',
            'author_id': ObjectId(),
            'timestamp': now,
            'likes_count': 5,
            'comment_count': 2,
            'view_count': 42,
            'reactions': {
                'heart': ['507f1f77bcf86cd799439011'],
                'wow': [],
                'insightful': []
            },
            'is_pinned': False,
            'is_suppressed': False,
            'moderation_status': 'cleared'
        }
        assert post['timestamp'].tzinfo == datetime.timezone.utc
        assert post['slug'] == 'my-first-post'
        assert isinstance(post['reactions'], dict)


class TestReactionsSystem:
    """Tests for multi-reaction toggles."""

    def test_reaction_types_allowed(self):
        valid_reactions = ['heart', 'wow', 'insightful', 'laugh', 'sad']
        assert len(valid_reactions) == 5
        assert 'heart' in valid_reactions
        assert 'insightful' in valid_reactions

    def test_reaction_toggle_logic(self):
        reactions = {
            'heart': ['user_1', 'user_2'],
            'wow': ['user_3']
        }
        user_id = 'user_1'

        # If user_1 unreacts heart
        reactions['heart'].remove(user_id)
        assert user_id not in reactions['heart']

        # If user_1 reacts wow
        reactions['wow'].append(user_id)
        assert user_id in reactions['wow']


class TestCommentTree:
    """Tests for nested comment reply structure."""

    def test_comment_document_structure(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        parent_comment = {
            '_id': ObjectId(),
            'post_slug': 'my-first-post',
            'author': 'alice',
            'author_id': ObjectId(),
            'content': 'Great post!',
            'created_at': now,
            'is_deleted': False,
            'parent_id': None
        }
        child_reply = {
            '_id': ObjectId(),
            'post_slug': 'my-first-post',
            'author': 'bob',
            'author_id': ObjectId(),
            'content': 'I agree with Alice',
            'created_at': now,
            'is_deleted': False,
            'parent_id': parent_comment['_id']
        }
        assert parent_comment['created_at'].tzinfo == datetime.timezone.utc
        assert child_reply['parent_id'] == parent_comment['_id']


class TestBlogEndpointsAccess:
    """Tests for public blog endpoints and auth requirements."""

    def test_blog_public_feed_accessible(self, client):
        res = client.get('/blog')
        assert res.status_code == 200

    def test_create_post_requires_auth(self, client):
        res = client.get('/post')
        assert res.status_code in [302, 401]

    def test_toggle_save_post_requires_auth(self, client):
        res = client.post('/api/posts/507f1f77bcf86cd799439011/save')
        assert res.status_code in [302, 401, 404]

    def test_blog_search_empty_query_redirect(self, client):
        res = client.get('/blog?query=   ')
        assert res.status_code == 302

    def test_blog_search_with_query(self, client):
        res = client.get('/blog?query=reflection')
        assert res.status_code == 200
        assert b'Search Results for "reflection"' in res.data or b'reflection' in res.data

    def test_blog_search_typesense_mock(self, client):
        import main as m
        mock_hit = {
            'document': {
                'id': '507f1f77bcf86cd799439011',
                'title': 'Mocked Search Post',
                'slug': 'mocked-search-post',
                'author_username': 'tester',
                'content': 'Searching content via Typesense'
            }
        }
        with patch.object(m._t, 'ts_posts', 'posts'), \
             patch.object(m._t, '_ts_search', return_value={'found': 1, 'hits': [mock_hit]}):
            res = client.get('/blog?query=Mocked')
            assert res.status_code == 200

    def test_advanced_search_endpoint(self, client):
        res = client.get('/search')
        assert res.status_code == 200
        assert b'Advanced Search' in res.data

    def test_advanced_search_query_execution(self, client):
        res = client.get('/search?q=hello&sort=newest')
        assert res.status_code == 200

    def test_blog_feed_tabs(self, client):
        """Verify the unified blog feed tabs render successfully."""
        res_trend = client.get('/blog?tab=trending')
        assert res_trend.status_code == 200
        assert b'Trending' in res_trend.data
        assert b'Latest</a>' not in res_trend.data
        assert b'Most Active' in res_trend.data

        res_latest = client.get('/blog?tab=latest')
        assert res_latest.status_code == 200
        assert b'Trending' in res_latest.data
        assert b'Latest</a>' not in res_latest.data

    def test_blog_feed_batch_endpoint(self, client):
        res = client.get('/api/blog/feed?tab=trending&limit=5')
        assert res.status_code == 200
        assert res.mimetype == 'text/html'

    def test_blog_feed_has_back_to_top_and_sticky_nav(self, client):
        res = client.get('/blog')
        assert res.status_code == 200
        assert b'feed-top-btn' in res.data
        assert b'navbar-sticky' in res.data

    def test_blog_feed_batch_endpoint_rejects_bad_params(self, client):
        res = client.get('/api/blog/feed?tab=nonsense&limit=abc&exclude=, ,')
        assert res.status_code == 200


class TestBlogAlgorithmAndDiversity:
    """Tests for Hacker News gravity decay scoring, author diversity, and partner boosts."""

    def test_calculate_post_gravity_score(self):
        from blueprints.blog import calculate_post_gravity_score
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # New post with moderate engagement
        new_post = {
            'timestamp': now - datetime.timedelta(hours=1),
            'likes_count': 5,
            'comment_count': 2,
            'share_count': 1,
            'view_count': 50
        }
        # Older post (7 days ago) with high engagement
        old_post = {
            'timestamp': now - datetime.timedelta(days=7),
            'likes_count': 20,
            'comment_count': 10,
            'share_count': 5,
            'view_count': 500
        }

        score_new = calculate_post_gravity_score(new_post, now)
        score_old = calculate_post_gravity_score(old_post, now)

        # Fresh active post should rank well relative to 7-day old post due to gravity decay
        assert score_new > 0
        assert score_old > 0
        assert score_new > score_old

    def test_partner_and_tag_boosts(self):
        from blueprints.blog import calculate_post_gravity_score
        now = datetime.datetime.now(datetime.timezone.utc)
        post = {
            'author_id': 'partner_123',
            'timestamp': now - datetime.timedelta(hours=2),
            'likes_count': 2,
            'tags': ['travel', 'love']
        }
        base_score = calculate_post_gravity_score(post, now)
        partner_score = calculate_post_gravity_score(post, now, partner_ids={'partner_123'})
        tag_score = calculate_post_gravity_score(post, now, user_tag_scores={'travel': 5})

        assert partner_score > base_score
        assert tag_score > base_score

    def test_author_interest_boost(self):
        from blueprints.blog import calculate_post_gravity_score
        now = datetime.datetime.now(datetime.timezone.utc)
        post = {
            'author_id': 'author_123',
            'timestamp': now - datetime.timedelta(hours=2),
            'likes_count': 2,
            'tags': ['general']
        }

        base_score = calculate_post_gravity_score(post, now)
        author_score = calculate_post_gravity_score(post, now, user_author_scores={'author_123': 5})

        assert author_score > base_score

    def test_bond_partner_lookup_supports_current_schema(self):
        import blueprints.blog as blog
        from blueprints.blog import _get_bond_partner_ids
        blog._bond_partners_memory_cache.clear()
        user_id = ObjectId('507f1f77bcf86cd799439011')
        partner_id = ObjectId('507f1f77bcf86cd799439022')
        user = MagicMock(is_authenticated=True, id=str(user_id))
        db = MagicMock()
        db.redis_cache = None
        db.bonds_conf.find.return_value = [{
            'user_a_id': user_id,
            'user_b_id': partner_id,
            'status': 'active'
        }]

        partner_ids = _get_bond_partner_ids(db, user)

        assert str(partner_id) in partner_ids

    def test_bond_partner_lookup_is_cached(self):
        import blueprints.blog as blog
        from blueprints.blog import _get_bond_partner_ids
        blog._bond_partners_memory_cache.clear()
        user_id = ObjectId('507f1f77bcf86cd7994390aa')
        partner_id = ObjectId('507f1f77bcf86cd7994390bb')
        user = MagicMock(is_authenticated=True, id=str(user_id))
        db = MagicMock()
        db.redis_cache = None
        db.bonds_conf.find.return_value = [{'user_a_id': user_id, 'user_b_id': partner_id, 'status': 'active'}]

        _get_bond_partner_ids(db, user)
        _get_bond_partner_ids(db, user)

        assert db.bonds_conf.find.call_count == 1

    def test_apply_author_diversity(self):
        from blueprints.blog import apply_author_diversity
        # Author A has 5 posts, Author B has 2 posts, Author C has 1 post
        posts = [
            {'_id': '1', 'author_id': 'A'},
            {'_id': '2', 'author_id': 'A'},
            {'_id': '3', 'author_id': 'A'},
            {'_id': '4', 'author_id': 'A'},
            {'_id': '5', 'author_id': 'B'},
            {'_id': '6', 'author_id': 'B'},
            {'_id': '7', 'author_id': 'C'}
        ]
        diverse = apply_author_diversity(posts, max_per_author=2, target_count=5)
        # Should pick A (2), B (2), C (1)
        a_count = sum(1 for p in diverse if p['author_id'] == 'A')
        b_count = sum(1 for p in diverse if p['author_id'] == 'B')
        assert a_count <= 2
        assert b_count <= 2
        assert len(diverse) == 5


    def test_weighted_rotation_sample_stable_with_same_seed(self):
        import random
        from blueprints.blog import _weighted_rotation_sample
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': float(i)} for i in range(12)]

        r1 = _weighted_rotation_sample(posts, 10, random.Random(42))
        r2 = _weighted_rotation_sample(posts, 10, random.Random(42))

        assert [p['_id'] for p in r1] == [p['_id'] for p in r2]
        assert len(r1) == 10
        assert len({p['_id'] for p in r1}) == 10

    def test_weighted_rotation_sample_has_no_fixed_head(self):
        import random
        from blueprints.blog import _weighted_rotation_sample
        # Highest-scored post is not permanently anchored at position 0.
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': 10.0 - i} for i in range(8)]

        first_positions = {
            _weighted_rotation_sample(posts, 6, random.Random(seed))[0]['_id']
            for seed in range(40)
        }

        assert len(first_positions) > 1

    def test_weighted_rotation_sample_varies_across_seeds(self):
        import random
        from blueprints.blog import _weighted_rotation_sample
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': 10.0 - i} for i in range(12)]

        orderings = {
            tuple(p['_id'] for p in _weighted_rotation_sample(posts, 10, random.Random(seed)))
            for seed in range(30)
        }

        # A single frozen ordering would defeat discovery; sampling must vary per request
        assert len(orderings) > 1

    def test_weighted_rotation_sample_small_pool_returns_all(self):
        import random
        from blueprints.blog import _weighted_rotation_sample
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': float(i)} for i in range(4)]

        result = _weighted_rotation_sample(posts, 10, random.Random(1))
        assert {p['_id'] for p in result} == {str(i) for i in range(4)}

    def test_recently_viewed_post_ids(self):
        from blueprints.blog import _get_recently_viewed_post_ids
        import datetime as dt
        user_id = ObjectId('507f1f77bcf86cd799439011')
        viewed_id = ObjectId('507f1f77bcf86cd799439022')
        user = MagicMock(is_authenticated=True, id=str(user_id))
        db = MagicMock()
        db.user_post_views_conf.find.return_value = [{'post_id': viewed_id}]

        now = dt.datetime.now(dt.timezone.utc)
        ids = _get_recently_viewed_post_ids(db, user, now)

        assert str(viewed_id) in ids
        query = db.user_post_views_conf.find.call_args[0][0]
        assert query['user_id'] == user_id
        assert 'last_viewed' in query

    def test_recently_viewed_post_ids_anon(self):
        from blueprints.blog import _get_recently_viewed_post_ids
        import datetime as dt
        assert _get_recently_viewed_post_ids(MagicMock(), None, dt.datetime.now(dt.timezone.utc)) == set()

    def test_visitor_viewed_post_ids_uses_visitor_cookie(self, app):
        from blueprints.blog import _get_visitor_viewed_post_ids
        import main as m

        now = datetime.datetime.now(datetime.timezone.utc)
        post_id = ObjectId('507f1f77bcf86cd799439055')
        db = MagicMock()
        db.logs_conf.find.return_value = [{'post_id': post_id}]

        with app.test_request_context('/', headers={'X-Visitor-ID': 'visitor-abc'}):
            ids = _get_visitor_viewed_post_ids(db, [post_id], now, 720)

        assert str(post_id) in ids
        query = db.logs_conf.find.call_args[0][0]
        assert query['user_identifier'] == 'visitor:visitor-abc'
        assert query['type'] == 'post_view'
        assert query['timestamp']['$gte'] <= now

    def test_visitor_viewed_post_ids_without_identity(self, app):
        from blueprints.blog import _get_visitor_viewed_post_ids
        import datetime as dt
        db = MagicMock()
        with app.test_request_context('/'):
            assert _get_visitor_viewed_post_ids(db, [ObjectId()], dt.datetime.now(dt.timezone.utc), 720) == set()

    def test_inject_comment_counts_sets_live_counts(self):
        from blueprints.blog import _inject_comment_counts
        db = MagicMock()
        db.comments_conf.aggregate.return_value = [
            {'_id': 'post-a', 'count': 4},
            {'_id': 'post-b', 'count': 2},
        ]
        posts = [
            {'slug': 'post-a', 'comment_count': 0},
            {'slug': 'post-b', 'comment_count': 0},
            {'slug': 'post-c', 'comment_count': 9},
        ]

        _inject_comment_counts(db, posts)

        assert posts[0]['comment_count'] == 4
        assert posts[1]['comment_count'] == 2
        assert posts[2]['comment_count'] == 0

    def test_inject_comment_counts_aggregate_failure_keeps_stored(self):
        from blueprints.blog import _inject_comment_counts
        db = MagicMock()
        db.comments_conf.aggregate.side_effect = RuntimeError('boom')
        posts = [{'slug': 'post-a', 'comment_count': 3}]

        _inject_comment_counts(db, posts)

        assert posts[0]['comment_count'] == 3

    def test_feed_pool_shared_across_users_and_feeds(self, app, monkeypatch):
        import blueprints.blog as blog
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        posts = [
            {
                '_id': ObjectId(f'507f1f77bcf86cd79943905{i}'),
                'slug': f'post-{i}', 'title': f'Post {i}', 'content': 'body',
                'author': f'author{i}', 'author_id': ObjectId(f'507f1f77bcf86cd7994390{i:02d}'[:24]),
                'timestamp': now - datetime.timedelta(hours=1),
                'likes_count': 2, 'comment_count': 0, 'share_count': 0, 'view_count': 0,
                'tags': [], 'is_pinned': False,
            }
            for i in range(4)
        ]

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True or 'likes_count' in query:
                return _Cursor([])
            return _Cursor(posts)

        find_mock = MagicMock(side_effect=fake_find)
        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=find_mock))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock(find=lambda *a, **k: []))
        monkeypatch.setattr(m, 'prepare_posts', lambda p: p)
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))

        user_a = MagicMock(is_authenticated=True, id=str(ObjectId('507f1f77bcf86cd799439091')))
        user_b = MagicMock(is_authenticated=True, id=str(ObjectId('507f1f77bcf86cd799439092')))
        with app.app_context():
            blog.get_latest_posts_feed(feed_type='trending', user=user_a, limit=3)
            pool_first = m.blog_feed_cache.get('feedpool_base')
            assert pool_first is not None
            blog.get_latest_posts_feed(feed_type='for_you', user=user_b, limit=3)

        # The second request (different user + feed) reused the same cached pool
        assert m.blog_feed_cache.get('feedpool_base') is pool_first

    def test_viewed_pinned_post_drops_for_anonymous_visitor(self, app, monkeypatch):
        import blueprints.blog as blog
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        pinned = {
            '_id': ObjectId('507f1f77bcf86cd799439077'),
            'slug': 'pinned-post', 'title': 'Pinned', 'content': 'body',
            'author': 'alice', 'author_id': ObjectId('507f1f77bcf86cd799439012'),
            'timestamp': now, 'likes_count': 1, 'comment_count': 0, 'share_count': 0,
            'view_count': 0, 'tags': [], 'is_pinned': True,
        }
        normal = {
            '_id': ObjectId('507f1f77bcf86cd799439078'),
            'slug': 'normal-post', 'title': 'Normal', 'content': 'body',
            'author': 'bob', 'author_id': ObjectId('507f1f77bcf86cd799439022'),
            'timestamp': now, 'likes_count': 1, 'comment_count': 0, 'share_count': 0,
            'view_count': 0, 'tags': [], 'is_pinned': False,
        }

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True:
                return _Cursor([pinned])
            if 'likes_count' in query:
                return _Cursor([])
            return _Cursor([normal])

        logs = MagicMock()
        logs.find.return_value = [{'post_id': pinned['_id']}]
        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=fake_find))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'logs_conf', logs)
        monkeypatch.setattr(m, 'prepare_posts', lambda p: p)
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))

        with app.test_request_context('/', headers={'X-Visitor-ID': 'visitor-xyz'}):
            result = blog.get_latest_posts_feed(feed_type='trending', user=None, limit=5)

        ids = [str(p['_id']) for p in result]
        assert str(pinned['_id']) not in ids
        assert str(normal['_id']) in ids


    def test_feed_limit_exclude_and_read_penalty(self, app, monkeypatch):
        import blueprints.blog as blog
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        user_oid = ObjectId('507f1f77bcf86cd799439011')
        posts = [
            {
                '_id': ObjectId(f'507f1f77bcf86cd79943901{i}'),
                'slug': f'post-{i}', 'title': f'Post {i}', 'content': 'body',
                'author': f'author{i}', 'author_id': ObjectId(f'507f1f77bcf86cd7994390{i:02d}'[:24]),
                'timestamp': now - datetime.timedelta(hours=1),
                'likes_count': 2, 'comment_count': 0, 'share_count': 0, 'view_count': 0,
                'tags': [], 'is_pinned': False,
            }
            for i in range(5)
        ]

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True or 'likes_count' in query:
                return _Cursor([])
            return _Cursor(posts)

        captured = {}

        def fake_sample(candidates, target, rng, max_per_author=2):
            captured['scores'] = {str(p['_id']): p.get('_feed_score') for p in candidates}
            return sorted(candidates, key=lambda x: x.get('_feed_score', 0), reverse=True)[:target]

        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=fake_find))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock(
            find=lambda *a, **k: [{'post_id': posts[0]['_id']}]
        ))
        monkeypatch.setattr(m, 'prepare_posts', lambda p: p)
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))
        monkeypatch.setattr(blog, '_weighted_rotation_sample', fake_sample)

        user = MagicMock(is_authenticated=True, id=str(user_oid))
        with app.app_context():
            result = blog.get_latest_posts_feed(feed_type='trending', user=user, limit=4, exclude_ids={str(posts[1]['_id'])})

        ids = [str(p['_id']) for p in result]
        assert len(result) == 4
        assert str(posts[1]['_id']) not in ids
        # Viewed post is down-weighted relative to an identical unviewed post
        assert captured['scores'][str(posts[0]['_id'])] < captured['scores'][str(posts[2]['_id'])]

    def test_viewed_pinned_post_drops_from_feed(self, app, monkeypatch):
        import blueprints.blog as blog
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        user_oid = ObjectId('507f1f77bcf86cd799439011')
        pinned = {
            '_id': ObjectId('507f1f77bcf86cd799439099'),
            'slug': 'pinned-post', 'title': 'Pinned', 'content': 'body',
            'author': 'alice', 'author_id': ObjectId('507f1f77bcf86cd799439012'),
            'timestamp': now, 'likes_count': 1, 'comment_count': 0, 'share_count': 0,
            'view_count': 0, 'tags': [], 'is_pinned': True,
        }
        normal = {
            '_id': ObjectId('507f1f77bcf86cd799439021'),
            'slug': 'normal-post', 'title': 'Normal', 'content': 'body',
            'author': 'bob', 'author_id': ObjectId('507f1f77bcf86cd799439022'),
            'timestamp': now, 'likes_count': 1, 'comment_count': 0, 'share_count': 0,
            'view_count': 0, 'tags': [], 'is_pinned': False,
        }

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True:
                return _Cursor([pinned])
            if 'likes_count' in query:
                return _Cursor([])
            return _Cursor([normal])

        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=fake_find))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock(
            find=lambda *a, **k: [{'post_id': pinned['_id']}]
        ))
        monkeypatch.setattr(m, 'prepare_posts', lambda p: p)
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))

        user = MagicMock(is_authenticated=True, id=str(user_oid))
        with app.app_context():
            result = blog.get_latest_posts_feed(feed_type='trending', user=user, limit=5)

        ids = [str(p['_id']) for p in result]
        assert str(pinned['_id']) not in ids
        assert str(normal['_id']) in ids

    def test_feed_guarantees_recent_posts(self, app, monkeypatch):
        import blueprints.blog as blog
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = {
            '_id': ObjectId('507f1f77bcf86cd799439031'),
            'slug': 'fresh-post', 'title': 'Fresh', 'content': 'body',
            'author': 'carol', 'author_id': ObjectId('507f1f77bcf86cd799439032'),
            'timestamp': now, 'likes_count': 0, 'comment_count': 0, 'share_count': 0,
            'view_count': 0, 'tags': [], 'is_pinned': False,
        }
        old_posts = [
            {
                '_id': ObjectId(f'507f1f77bcf86cd7994391{i:02d}'),
                'slug': f'old-{i}', 'title': f'Old {i}', 'content': 'body',
                'author': f'author{i}', 'author_id': ObjectId(f'507f1f77bcf86cd7994392{i:02d}'),
                'timestamp': now - datetime.timedelta(days=2),
                'likes_count': 20, 'comment_count': 3, 'share_count': 1, 'view_count': 100,
                'tags': [], 'is_pinned': False,
            }
            for i in range(10)
        ]
        all_posts = [fresh] + old_posts

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True or 'likes_count' in query:
                return _Cursor([])
            return _Cursor(all_posts)

        # Simulate a sampler that never selects the fresh, low-engagement post
        monkeypatch.setattr(blog, '_weighted_rotation_sample', lambda cands, target, rng, max_per_author=2:
                            [p for p in cands if str(p['_id']) != str(fresh['_id'])][:target])
        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=fake_find))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'prepare_posts', lambda p: p)
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))

        with app.app_context():
            result = blog.get_latest_posts_feed(feed_type='trending', user=None, limit=3)

        assert str(fresh['_id']) in [str(p['_id']) for p in result]
        assert len(result) == 3



    def test_blog_feed_batch_renders_posts(self, client, monkeypatch):
        import main as m
        from cachetools import TTLCache

        now = datetime.datetime.now(datetime.timezone.utc)
        post = {
            '_id': ObjectId('507f1f77bcf86cd799439011'),
            'slug': 'hello-world', 'title': 'Hello World Post', 'content': 'Some body text here',
            'author': 'alice', 'author_id': ObjectId('507f1f77bcf86cd799439012'),
            'timestamp': now, 'likes_count': 3, 'comment_count': 1, 'share_count': 0,
            'view_count': 5, 'tags': [], 'is_pinned': False, 'status': 'published',
            'reactions': {}, 'image_url': None, 'image_urls': [], 'video_url': None,
        }

        class _Cursor:
            def __init__(self, docs): self._docs = list(docs)
            def sort(self, *a, **k): return self
            def limit(self, n): self._docs = self._docs[:n]; return self
            def __iter__(self): return iter(self._docs)

        def fake_find(query=None, projection=None, *a, **k):
            query = query or {}
            if query.get('is_pinned') is True or 'likes_count' in query:
                return _Cursor([])
            return _Cursor([post])

        def fake_prepare(posts):
            for p in posts:
                p['url'] = '/blog/post/' + p.get('slug', '')
                p.setdefault('comment_count', 0)
            return posts

        monkeypatch.setattr(m, 'posts_conf', MagicMock(find=fake_find))
        monkeypatch.setattr(m, 'comments_conf', MagicMock())
        monkeypatch.setattr(m, 'prepare_posts', fake_prepare)
        monkeypatch.setattr(m, 'user_post_views_conf', MagicMock(find=lambda *a, **k: []))
        monkeypatch.setattr(m, 'blog_feed_cache', TTLCache(maxsize=32, ttl=60))

        res = client.get('/api/blog/feed?tab=trending&limit=5')
        assert res.status_code == 200
        assert b'Hello World Post' in res.data


class TestCoopGamesApi:
    """Tests for cooperative games dynamic prompt and word generation endpoints."""

    def test_coop_prompt_api(self, client):
        res = client.get('/api/games/coop/prompt?category=romance')
        assert res.status_code == 200
        data = res.get_json()
        assert data['status'] == 'success'
        assert 'word' in data
        assert 'hint' in data
        assert 'category_label' in data

    def test_coop_words_api(self, client):
        res = client.get('/api/games/coop/words?count=25')
        assert res.status_code == 200
        data = res.get_json()
        assert data['status'] == 'success'
        assert len(data['words']) == 25



