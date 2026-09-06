import datetime
from bson.objectid import ObjectId
from unittest.mock import MagicMock, patch


class TestMultiplePinnedAnnouncements:
    """Test support for multiple pinned announcements and cache invalidation."""

    def test_inject_pinned_announcements_multiple(self):
        import main as m

        # Clear cache first
        m.invalidate_pinned_announcements_cache()

        ann1_id = ObjectId()
        ann2_id = ObjectId()
        now = datetime.datetime.now(datetime.timezone.utc)

        mock_announcements = [
            {
                '_id': ann1_id,
                'content': 'Second Announcement https://echowithin.xyz/survey',
                'is_pinned': True,
                'created_at': now
            },
            {
                '_id': ann2_id,
                'content': 'First Announcement',
                'is_pinned': True,
                'created_at': now - datetime.timedelta(hours=1)
            }
        ]

        with patch.object(m.announcements_conf, 'find') as mock_find:
            mock_cursor = MagicMock()
            mock_cursor.sort.return_value = mock_announcements
            mock_find.return_value = mock_cursor

            context = m.inject_pinned_announcement()

            assert 'pinned_announcements' in context
            assert len(context['pinned_announcements']) == 2
            assert context['pinned_announcements'][0]['_id'] == str(ann1_id)
            assert context['pinned_announcements'][1]['_id'] == str(ann2_id)
            # Backward compatibility check
            assert context['pinned_announcement']['_id'] == str(ann1_id)

    def test_invalidate_pinned_announcements_cache(self):
        import main as m

        m._pinned_announcement_cache['pinned_announcements'] = [{'test': 1}]
        assert 'pinned_announcements' in m._pinned_announcement_cache

        m.invalidate_pinned_announcements_cache()
        assert 'pinned_announcements' not in m._pinned_announcement_cache

    def test_blog_template_renders_multiple_and_dismiss_button(self):
        import main as m

        ann1 = {
            '_id': str(ObjectId()),
            'content': 'Announcement One http://example.com'
        }
        ann2 = {
            '_id': str(ObjectId()),
            'content': 'Announcement Two'
        }

        with m.app.test_request_context('/'):
            rendered = m.render_template(
                'blog.html',
                posts=[],
                pinned_announcements=[ann1, ann2],
                now=datetime.datetime.now(datetime.timezone.utc),
                categories=[],
                tags=[],
                author_usernames=[],
                tag=None,
                category=None,
                author=None,
                sort='latest',
                query=None,
                page=1,
                total_pages=1
            )

            # Both announcements rendered
            assert f'announcement-banner-{ann1["_id"]}' in rendered
            assert f'announcement-banner-{ann2["_id"]}' in rendered
            # Dismiss buttons rendered
            assert f'data-id="{ann1["_id"]}"' in rendered
            assert f'data-id="{ann2["_id"]}"' in rendered
            assert 'announcement-dismiss-btn' in rendered
            assert 'Announcement One' in rendered
            assert 'Announcement Two' in rendered
