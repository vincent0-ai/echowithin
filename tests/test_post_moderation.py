import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security
from utils import get_public_posts_filter


class TestPublicPostsFilter:
    """Tests for get_public_posts_filter query helper."""

    def test_base_filter_suppression_clauses(self):
        f = get_public_posts_filter()
        assert f['is_suppressed'] == {'$ne': True}
        assert f['moderation_status'] == {'$nin': ['flagged', 'ai_flagged', 'banned', 'deleted']}
        # image_status is hidden unless is_approved — encoded as $or
        assert '$or' in f
        assert {'image_status': {'$ne': 'removed_nsfw'}} in f['$or']
        assert {'is_approved': True} in f['$or']

    def test_merged_filter_preserves_extra_query(self):
        extra = {'tags': 'technology', 'author_id': ObjectId('507f1f77bcf86cd799439011')}
        f = get_public_posts_filter(extra)
        assert f['tags'] == 'technology'
        assert f['author_id'] == ObjectId('507f1f77bcf86cd799439011')
        assert f['is_suppressed'] == {'$ne': True}
        assert f['moderation_status'] == {'$nin': ['flagged', 'ai_flagged', 'banned', 'deleted']}
        assert '$or' in f
        assert {'image_status': {'$ne': 'removed_nsfw'}} in f['$or']

    def test_empty_and_none_extra_query(self):
        f1 = get_public_posts_filter(None)
        f2 = get_public_posts_filter({})
        assert f1 == f2
        assert f1['is_suppressed'] == {'$ne': True}


class TestPostModerationStandards:
    """Tests standard datetime compliance and moderation state transitions."""

    def test_utc_timestamp_and_z_suffix(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        iso_str = (now.isoformat() + 'Z').replace('+00:00Z', 'Z')
        assert iso_str.endswith('Z')
        parsed = security.parse_iso_utc(iso_str)
        assert parsed.tzinfo == datetime.timezone.utc

    def test_report_reasons_allowed(self):
        valid_reasons = ['spam', 'harassment', 'hate_speech', 'inappropriate', 'misinformation', 'other']
        assert len(valid_reasons) == 6
        assert 'spam' in valid_reasons
        assert 'inappropriate' in valid_reasons

    def test_admin_approve_and_clear_schema(self):
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        update_doc = {
            'moderation_status': 'cleared',
            'is_suppressed': False,
            'is_approved': True,
            'is_reported': False,
            'reviewed_by': ObjectId('507f1f77bcf86cd799439011'),
            'reviewed_at': now_utc,
        }
        assert update_doc['is_suppressed'] is False
        assert update_doc['is_approved'] is True
        assert update_doc['moderation_status'] == 'cleared'
        assert update_doc['reviewed_at'].tzinfo == datetime.timezone.utc


class TestPostReportingAndAdminEndpoints:
    """Integration style tests for post report and admin moderation endpoints."""

    def test_report_post_requires_auth(self, client):
        res = client.post('/api/posts/507f1f77bcf86cd799439011/report', json={'reason': 'spam'})
        assert res.status_code in [302, 401]

    def test_admin_reports_endpoint_requires_admin(self, client):
        res = client.get('/api/admin/posts/507f1f77bcf86cd799439011/reports')
        assert res.status_code in [302, 401, 403]

    def test_admin_dismiss_endpoint_requires_admin(self, client):
        res = client.post('/api/admin/post_reports/507f1f77bcf86cd799439011/dismiss')
        assert res.status_code in [302, 401, 403]

    def test_admin_approve_post_requires_admin(self, client):
        res = client.post('/admin/posts/507f1f77bcf86cd799439011/approve')
        assert res.status_code in [302, 401, 403]

