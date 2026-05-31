from concurrent.futures import ThreadPoolExecutor

# MongoDB client and database — set by main.py at startup
client = None
db = None
users_conf = None
posts_conf = None
logs_conf = None
auth_conf = None
announcements_conf = None
comments_conf = None
personal_posts_conf = None
note_shares_conf = None
note_versions_conf = None
note_discussions_conf = None
push_subscriptions_conf = None
fcm_tokens_conf = None
direct_messages_conf = None
newsletter_conf = None
user_post_views_conf = None
unlock_notifications_conf = None
weekly_winners_conf = None
app_tokens_conf = None
app_updates_conf = None
communities_conf = None
community_notes_conf = None
community_reactions_conf = None
community_reports_conf = None
dm_permissions_conf = None
scheduled_messages_conf = None
note_attachments_conf = None
activities_conf = None
comment_votes_conf = None

# Redis cache — set by main.py at startup
redis_cache = None

# Shared thread pool
executor = ThreadPoolExecutor(max_workers=10)

# Performance caches
from cachetools import TTLCache
_pinned_announcement_cache = TTLCache(maxsize=1, ttl=60)
profile_stats_cache = TTLCache(maxsize=256, ttl=30)
profile_posts_cache = TTLCache(maxsize=256, ttl=30)
related_posts_cache = TTLCache(maxsize=128, ttl=120)
post_comment_stats_cache = TTLCache(maxsize=256, ttl=30)
community_stats_cache = TTLCache(maxsize=1, ttl=60)
blog_feed_cache = TTLCache(maxsize=1, ttl=15)
user_loader_cache = TTLCache(maxsize=512, ttl=30)
weekly_winners_cache = TTLCache(maxsize=1, ttl=3600)
_user_fernet_cache = TTLCache(maxsize=512, ttl=3600)
_dm_fernet_cache = TTLCache(maxsize=512, ttl=3600)
_decrypted_notes_memory_cache = TTLCache(maxsize=1024, ttl=300)

# In-memory tracker for active chat views (user_id -> set of partner_ids they're viewing)
active_chat_views = {}

# In-memory tracker for shared note viewers (share_id -> {user_id: {name, avatar, id}})
active_note_viewers = {}

# In-memory edit locks for shared notes (share_id -> {user_id, user_name, timestamp})
note_locks = {}

# Periodic global state cleanup timestamp
_last_state_cleanup = {'at': 0}
