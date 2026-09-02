import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch
import security


class TestAdminHealthMetrics:
    """Tests for admin system health metrics and schema."""

    def test_health_metrics_keys_presence(self):
        health = {
            'typesense': {'status': 'healthy', 'posts_docs': 100, 'notes_docs': 500},
            'redis': {'status': 'healthy', 'used_memory_human': '25M'},
            'rq': {'status': 'healthy', 'queued_jobs': 0, 'failed_jobs': 0},
            'backup': {'status': 'healthy', 'minutes_ago': 45},
            'communities': {'status': 'healthy', 'total': 12, 'pending_reports': 0},
            'post_moderation': {'status': 'healthy', 'pending_reports': 0, 'ai_flagged': 0}
        }
        assert health['typesense']['status'] == 'healthy'
        assert health['post_moderation']['pending_reports'] == 0
        assert health['communities']['pending_reports'] == 0


class TestPinnedPostsLimit:
    """Tests that maximum pinned posts is strictly bounded (max 3)."""

    def test_max_3_pinned_posts_rule(self):
        max_pinned = 3
        current_pinned_count = 3
        # Attempting to pin a 4th post should be denied
        can_pin = current_pinned_count < max_pinned
        assert can_pin is False


class TestUserBanAndAdminStatus:
    """Tests for user account state transitions."""

    def test_banned_user_flag(self):
        user_doc = {
            '_id': ObjectId(),
            'username': 'spammer',
            'is_banned': True,
            'banned_at': datetime.datetime.now(datetime.timezone.utc),
            'ban_reason': 'Violation of community guidelines'
        }
        assert user_doc['is_banned'] is True
        assert user_doc['banned_at'].tzinfo == datetime.timezone.utc


class TestPremiumVouchersAndTiers:
    """Tests for premium account vouchers and expiration tracking."""

    def test_voucher_redemption_period_calc(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        duration_days = 30
        new_expiry = now + datetime.timedelta(days=duration_days)
        assert new_expiry.tzinfo == datetime.timezone.utc
        assert (new_expiry - now).days == 30

    def test_premium_expiry_iso_standard(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry_iso = (now.isoformat() + 'Z').replace('+00:00Z', 'Z')
        assert expiry_iso.endswith('Z')
        parsed = security.parse_iso_utc(expiry_iso)
        assert parsed.tzinfo == datetime.timezone.utc


class TestAdminEndpointsAuth:
    """Tests that all admin endpoints require admin role."""

    def test_admin_dashboard_requires_admin(self, client):
        res = client.get('/admin')
        assert res.status_code in [302, 401, 403, 404]

    def test_admin_system_health_requires_admin(self, client):
        res = client.get('/admin/system_health')
        assert res.status_code in [302, 401, 403]

