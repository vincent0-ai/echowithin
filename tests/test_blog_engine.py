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
        from blueprints.blog import _get_bond_partner_ids
        user_id = ObjectId('507f1f77bcf86cd799439011')
        partner_id = ObjectId('507f1f77bcf86cd799439022')
        user = MagicMock(is_authenticated=True, id=str(user_id))
        db = MagicMock()
        db.bonds_conf.find.return_value = [{
            'user_a_id': user_id,
            'user_b_id': partner_id,
            'status': 'active'
        }]

        partner_ids = _get_bond_partner_ids(db, user)

        assert str(partner_id) in partner_ids

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


    def test_weighted_rotation_sample_stable_within_bucket(self):
        from blueprints.blog import _weighted_rotation_sample, _feed_rotation_rng, FEED_HEAD_COUNT
        import datetime as dt
        now = lambda: dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': float(i)} for i in range(12)]

        rng1 = _feed_rotation_rng('trending', 'user1', now())
        r1 = _weighted_rotation_sample(posts, 10, rng1)
        rng2 = _feed_rotation_rng('trending', 'user1', now())
        r2 = _weighted_rotation_sample(posts, 10, rng2)

        assert r1 == r2
        assert len(r1) == 10
        # Quality anchors stay at the top
        assert r1[:FEED_HEAD_COUNT] == sorted(posts, key=lambda p: p['_feed_score'], reverse=True)[:FEED_HEAD_COUNT]

    def test_weighted_rotation_sample_rotates_across_buckets(self):
        from blueprints.blog import _weighted_rotation_sample, _feed_rotation_rng
        import datetime as dt
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': 10.0 - i} for i in range(12)]
        t0 = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)

        orderings = set()
        for bucket in range(20):
            t = t0 + dt.timedelta(seconds=900 * bucket)
            rng = _feed_rotation_rng('trending', 'user1', t)
            orderings.add(tuple(p['_id'] for p in _weighted_rotation_sample(posts, 10, rng)))

        # A single frozen ordering would defeat discovery; rotation must vary across buckets
        assert len(orderings) > 1

    def test_weighted_rotation_sample_small_pool_returns_all(self):
        from blueprints.blog import _weighted_rotation_sample, _feed_rotation_rng
        import datetime as dt
        now = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
        posts = [{'_id': str(i), 'author_id': f'A{i}', '_feed_score': float(i)} for i in range(4)]

        rng = _feed_rotation_rng('trending', 'user1', now)
        result = _weighted_rotation_sample(posts, 10, rng)
        assert {p['_id'] for p in result} == {str(i) for i in range(4)}


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



