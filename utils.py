import datetime
import re
import json
import math
import html
import hashlib
import os
from io import BytesIO

from flask import url_for
from markupsafe import Markup
import bleach
import markdown
import cloudinary
import cloudinary.uploader
from PIL import Image
import requests
from cachetools import cached, TTLCache
from bson.objectid import ObjectId

from config import TIER_LIMITS, PREMIUM_TRIAL_DAYS, _TAG_KEYWORDS
import database
from security import decrypt_note, get_active_achievements, decrypt_dm

_APP = None
_T = None
_SOCKETIO = None


def _get_app():
    global _APP
    if _APP is None:
        import main
        _APP = main.app
    return _APP


def _get_t():
    global _T
    if _T is None:
        import typesense_client as _tc
        _T = _tc
    return _T


def _get_socketio():
    global _SOCKETIO
    if _SOCKETIO is None:
        import main
        _SOCKETIO = main.socketio
    return _SOCKETIO


def _get_send_push_notification():
    import main
    return main.send_push_notification_to_user


# ---------------------------------------------------------------------------
# Typesense indexing
# ---------------------------------------------------------------------------

def _note_to_typesense_doc(note_doc: dict, decrypted_content=None) -> dict:
    """Convert a MongoDB personal note document to Typesense document shape.
    Content is sanitised before indexing to prevent stored-XSS via search highlights."""
    user_id = str(note_doc.get('user_id', ''))
    content = decrypted_content if decrypted_content is not None else decrypt_note(note_doc.get('content', ''), user_id=user_id)
    content = bleach.clean(content or '', tags=[], strip=True)
    return {
        'id': str(note_doc.get('_id')),
        'user_id': user_id,
        'is_locked': bool(note_doc.get('is_locked', False)),
        'content': content,
        'reference': note_doc.get('reference', ''),
        'tags': note_doc.get('tags', []),
        'created_at': int((note_doc.get('created_at') or datetime.datetime.now(datetime.timezone.utc)).timestamp()),
    }


def _is_ios_web_push_subscription(subscription_doc: dict) -> bool:
    endpoint = (subscription_doc or {}).get('endpoint', '') or ''
    endpoint_lower = endpoint.lower()
    return 'web.push.apple' in endpoint_lower or 'apple' in endpoint_lower


def _remove_stale_push_subscription(subscription_doc: dict, platform: str, user_label: str, reason: str):
    try:
        database.push_subscriptions_conf.delete_one({'_id': subscription_doc['_id']})
        _get_app().logger.info(f"Removed stale {platform} push subscription for {user_label} ({reason})")
    except Exception as exc:
        _get_app().logger.error(f"Failed to remove stale {platform} push subscription for {user_label}: {exc}")


def index_note_to_typesense(note_id: str, decrypted_content=None):
    """Index a single personal note into Typesense. Safe no-op if not configured."""
    if not _get_t().ts_notes:
        return False
    try:
        note = database.personal_posts_conf.find_one({'_id': ObjectId(note_id)})
        if not note:
            return False
        doc = _note_to_typesense_doc(note, decrypted_content)
        _get_t()._ts_upsert_document('personal_notes', doc)
        return True
    except Exception as e:
        _get_app().logger.error(f'Error indexing note {note_id} to Typesense: {e}')
        return False


def remove_note_from_typesense(note_id: str):
    """Remove a personal note from Typesense index."""
    if not _get_t().ts_notes:
        return False
    try:
        _get_t()._ts_delete_document('personal_notes', str(note_id))
        return True
    except Exception as e:
        _get_app().logger.error(f'Error removing note {note_id} from Typesense: {e}')
        return False


def remove_notes_from_typesense(note_ids: list):
    """Remove multiple personal notes from Typesense index."""
    if not _get_t().ts_notes or not note_ids:
        return False
    try:
        for nid in note_ids:
            try:
                _get_t()._ts_delete_document('personal_notes', str(nid))
            except Exception:
                pass
        return True
    except Exception as e:
        _get_app().logger.error(f'Error removing notes from Typesense: {e}')
        return False


def reindex_user_notes_to_typesense(user_id: str):
    """Reindex all personal notes for a specific user into Typesense."""
    if not _get_t().ts_notes:
        return False
    try:
        notes = list(database.personal_posts_conf.find({'user_id': ObjectId(user_id)}))
        if not notes:
            return True
        docs = [_note_to_typesense_doc(n) for n in notes]
        _get_t()._ts_import_documents('personal_notes', docs)
        return True
    except Exception as e:
        _get_app().logger.error(f'Error reindexing notes for user {user_id}: {e}')
        return False


def _post_to_typesense_doc(post_doc: dict) -> dict:
    """Convert a MongoDB post document to Typesense document shape."""
    return {
        'id': str(post_doc.get('_id')),
        'title': post_doc.get('title', ''),
        'content': post_doc.get('content', ''),
        'slug': post_doc.get('slug'),
        'author_id': str(post_doc.get('author_id')) if post_doc.get('author_id') else None,
        'author_username': post_doc.get('author_username') or post_doc.get('author', ''),
        'tags': post_doc.get('tags', []),
        'created_at': int((post_doc.get('created_at') or post_doc.get('timestamp') or datetime.datetime.now(datetime.timezone.utc)).timestamp()),
    }


def index_post_to_typesense(post_id: str):
    """Index a single post into Typesense. Safe no-op if not configured."""
    if not _get_t().ts_posts:
        return False
    try:
        post = database.posts_conf.find_one({'_id': ObjectId(post_id)})
        if not post:
            return False
        doc = _post_to_typesense_doc(post)
        _get_t()._ts_upsert_document('posts', doc)
        return True
    except Exception as e:
        _get_app().logger.error(f'Error indexing post {post_id} to Typesense: {e}')
        return False


def reindex_all_posts_to_typesense(batch_size: int = 1000):
    """Reindex all posts into Typesense from MongoDB."""
    if not _get_t().ts_posts:
        raise RuntimeError('Typesense not configured')
    try:
        last_id = None
        total = 0
        while True:
            query = {} if last_id is None else {"_id": {"$gt": last_id}}
            docs = list(database.posts_conf.find(query).sort("_id", 1).limit(batch_size))
            if not docs:
                break
            _get_t()._ts_import_documents('posts', [_post_to_typesense_doc(p) for p in docs])
            total += len(docs)
            last_id = docs[-1]["_id"]
        _get_app().logger.info(f'Reindexed {total} posts into Typesense')
        return total
    except Exception as e:
        _get_app().logger.error(f'Error during reindex_all_posts_to_typesense: {e}')
        raise


def reindex_all_notes_to_typesense(batch_size: int = 500):
    """Reindex ALL users' personal notes into Typesense from MongoDB."""
    if not _get_t().ts_notes:
        raise RuntimeError('Typesense notes collection not configured')
    try:
        last_id = None
        total = 0
        while True:
            query = {} if last_id is None else {'_id': {'$gt': last_id}}
            notes = list(database.personal_posts_conf.find(query).sort('_id', 1).limit(batch_size))
            if not notes:
                break
            docs = [_note_to_typesense_doc(n) for n in notes]
            _get_t()._ts_import_documents('personal_notes', docs)
            total += len(docs)
            last_id = notes[-1]['_id']
        _get_app().logger.info(f'Reindexed {total} notes into Typesense')
        return total
    except Exception as e:
        _get_app().logger.error(f'Error during reindex_all_notes_to_typesense: {e}')
        raise


# ---------------------------------------------------------------------------
# Template filters
# ---------------------------------------------------------------------------

def linkify_filter(text):
    """A Jinja2 filter to turn URLs in text into clickable links."""
    return bleach.linkify(text)


def _linkify_target_blank(attrs, new=False):
    """Bleach linkify callback to add target=_blank and rel=noopener to links."""
    attrs[(None, 'target')] = '_blank'
    attrs[(None, 'rel')] = 'noopener noreferrer'
    return attrs


def markdown_filter(text):
    """A Jinja2 filter to convert markdown text to HTML, sanitized to prevent XSS."""
    if not text:
        return ''
    # Convert markdown to HTML
    html = markdown.markdown(text, extensions=['fenced_code', 'nl2br'])
    # Linkify bare URLs into clickable links before sanitizing
    html = bleach.linkify(html, callbacks=[_linkify_target_blank], parse_email=True)
    # Sanitize HTML to prevent XSS - allow safe tags only
    allowed_tags = [
        'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's', 'strike',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'code', 'pre',
        'a', 'img', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'span', 'div', 'sub', 'sup'
    ]
    allowed_attrs = {
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        'code': ['class'],
        'pre': ['class'],
        'span': ['class'],
        'div': ['class'],
        '*': ['class']
    }
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs, strip=True)


def from_timestamp_filter(timestamp):
    """A Jinja2 filter to convert a Unix timestamp to a datetime object."""
    try:
        return datetime.datetime.fromtimestamp(int(timestamp), tz=datetime.timezone.utc)
    except (ValueError, TypeError):
        return timestamp # Return original value if conversion fails


def to_iso_filter(dt):
    """Convert a datetime object to ISO 8601 format string for JavaScript parsing."""
    try:
        if isinstance(dt, datetime.datetime):
            # Ensure timezone awareness
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.isoformat()
        return str(dt)
    except (ValueError, TypeError, AttributeError):
        return str(dt)


def to_local_filter(dt):
    """Ensure datetime object is timezone-aware (assume UTC if naive).
    Previously this converted to a fixed server timezone; now we leave
    conversion to the client's browser."""
    try:
        if isinstance(dt, datetime.datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        return dt
    except (ValueError, TypeError, AttributeError):
        return dt


def optimize_cloudinary_url(url):
    """Insert f_auto,q_auto transformations into a Cloudinary URL for optimal delivery.
    This makes Cloudinary auto-serve WebP/AVIF and auto-compress based on the client.
    Safe no-op for non-Cloudinary URLs."""
    if not url or 'res.cloudinary.com' not in url:
        return url
    # Avoid double-applying
    if 'f_auto' in url:
        return url
    return url.replace('/upload/', '/upload/f_auto,q_auto/')


def extract_cloudinary_public_id(url):
    """
    Extracts the public_id from a Cloudinary URL.
    Example: https://res.cloudinary.com/demo/image/upload/v12345678/folder/sample.jpg
    Returns: 'folder/sample'
    """
    if not url or 'res.cloudinary.com' not in url:
        return None
    
    # Split by '/upload/' and remove version (v...) and extension
    try:
        parts = url.split('/upload/')
        if len(parts) < 2:
            return None
        
        path = parts[1]
        # Skip version if present (e.g., v12345678/)
        if path.startswith('v') and '/' in path:
            path = path.split('/', 1)[1]
        
        # Remove extension
        if '.' in path:
            path = path.rsplit('.', 1)[0]
        
        return path
    except Exception:
        return None


def cleanup_share_media(share):
    """
    Checks if media files in a share are used elsewhere. 
    If not, deletes them from Cloudinary to save storage.
    Uses media_hash for cross-collection dedup (avoids decrypting every record).
    """
    media_hash_fields = {
        'valentine_photo': 'valentine_photo_hash',
        'valentine_audio': 'valentine_audio_hash'
    }
    for field, hash_field in media_hash_fields.items():
        media_hash = share.get(hash_field)
        encrypted_url = share.get(field)
        if not encrypted_url:
            continue

        # Decrypt URL to get the actual Cloudinary URL for deletion
        owner_id = str(share.get('owner_id', ''))
        url = decrypt_note(encrypted_url, user_id=owner_id)
        if not url or url.startswith('gAAAAA'):
            continue  # Decryption failed, skip

        try:
            # Check if any OTHER active share uses this exact media (by hash)
            other_usage = None
            other_post = None
            if media_hash:
                other_usage = database.note_shares_conf.find_one({
                    hash_field: media_hash,
                    '_id': {'$ne': share['_id']}
                })
                other_post = database.personal_posts_conf.find_one({
                    hash_field: media_hash
                })
            else:
                # Legacy records without hash — fall back to URL comparison
                other_usage = database.note_shares_conf.find_one({
                    field: encrypted_url,
                    '_id': {'$ne': share['_id']}
                })
                other_post = database.personal_posts_conf.find_one({
                    field: encrypted_url
                })

            if not other_usage and not other_post:
                public_id = extract_cloudinary_public_id(url)
                if public_id:
                    res_type = "video" if field == 'valentine_audio' else "image"
                    cloudinary.uploader.destroy(public_id, resource_type=res_type)
                    _get_app().logger.info(f"Deleted orphaned Cloudinary media: {public_id} (Type: {res_type})")
        except Exception as e:
            _get_app().logger.error(f"Failed to cleanup media: {e}")


def cleanup_post_media(post):
    """
    Checks if media files in a personal post are used elsewhere. 
    If not, deletes them from Cloudinary to save storage.
    Uses media_hash for cross-collection dedup (avoids decrypting every record).
    """
    media_hash_fields = {
        'valentine_photo': 'valentine_photo_hash',
        'valentine_audio': 'valentine_audio_hash'
    }
    for field, hash_field in media_hash_fields.items():
        media_hash = post.get(hash_field)
        encrypted_url = post.get(field)
        if not encrypted_url:
            continue

        # Decrypt URL to get the actual Cloudinary URL for deletion
        owner_id = str(post.get('user_id', ''))
        url = decrypt_note(encrypted_url, user_id=owner_id)
        if not url or url.startswith('gAAAAA'):
            continue  # Decryption failed, skip

        try:
            # Check if any OTHER post or share uses this exact media (by hash)
            other_post = None
            other_share = None
            if media_hash:
                other_post = database.personal_posts_conf.find_one({
                    hash_field: media_hash,
                    '_id': {'$ne': post['_id']}
                })
                other_share = database.note_shares_conf.find_one({
                    hash_field: media_hash
                })
            else:
                # Legacy records without hash — fall back to URL comparison
                other_post = database.personal_posts_conf.find_one({
                    field: encrypted_url,
                    '_id': {'$ne': post['_id']}
                })
                other_share = database.note_shares_conf.find_one({
                    field: encrypted_url
                })

            if not other_post and not other_share:
                public_id = extract_cloudinary_public_id(url)
                if public_id:
                    res_type = "video" if field == 'valentine_audio' else "image"
                    cloudinary.uploader.destroy(public_id, resource_type=res_type)
                    _get_app().logger.info(f"Deleted orphaned Cloudinary media from post: {public_id} (Type: {res_type})")
        except Exception as e:
            _get_app().logger.error(f"Failed to cleanup post media: {e}")


def localtime_filter(dt, fmt='%b %d, %Y at %I:%M %p'):
    """Render a <time> element with an ISO datetime for client-side
    conversion. The fallback text (before JS runs / for no-JS clients /
    inside emails) is the UTC-formatted time with an explicit ' UTC' suffix
    so users never see an ambiguous timestamp that *looks* like local time
    but is actually server time. The browser's JS will replace this with
    the user's local timezone via the `time.local-time` converter."""
    try:
        if isinstance(dt, datetime.datetime):
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            # Use 'Z' instead of '+00:00' so JavaScript Date parsing is unambiguous
            iso = dt.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
            fallback = dt.astimezone(datetime.timezone.utc).strftime(fmt)
            # Only add ' UTC' suffix when the format includes a time component
            # (avoids "Jan 2026 UTC" on month-only formats like %B %Y).
            if any(tok in fmt for tok in ('%H', '%I', '%M', '%S', '%p', '%X')):
                fallback = f"{fallback} UTC"
            return Markup(f"<time class=\"local-time\" datetime=\"{iso}\">{fallback}</time>")
        return str(dt)
    except (ValueError, TypeError, AttributeError):
        return str(dt)


# ---------------------------------------------------------------------------
# Tier helpers
# ---------------------------------------------------------------------------

def get_user_tier(user_doc):
    """Determine the effective tier for a user document (dict from MongoDB).
    Checks: explicit tier → trial period → fallback to free."""
    if not user_doc:
        return 'free'
    if user_doc.get('is_admin'):
        return 'premium'
    tier = user_doc.get('account_tier', 'free')
    if tier == 'premium':
        # Check if subscription is still active
        premium_until = user_doc.get('premium_until')
        if premium_until:
            if isinstance(premium_until, datetime.datetime):
                if premium_until.tzinfo is None:
                    premium_until = premium_until.replace(tzinfo=datetime.timezone.utc)
                if datetime.datetime.now(datetime.timezone.utc) > premium_until:
                    return 'free'  # expired
        return 'premium'
    # Check 3-day free trial for new accounts
    join_date = user_doc.get('join_date')
    if join_date:
        if isinstance(join_date, datetime.datetime):
            if join_date.tzinfo is None:
                join_date = join_date.replace(tzinfo=datetime.timezone.utc)
            trial_end = join_date + datetime.timedelta(days=PREMIUM_TRIAL_DAYS)
            if datetime.datetime.now(datetime.timezone.utc) < trial_end:
                return 'premium'  # still on free trial
    return 'free'


def get_limit(user_doc, limit_name):
    """Get a specific limit value for a user based on their tier."""
    tier = get_user_tier(user_doc)
    return TIER_LIMITS.get(tier, TIER_LIMITS['free']).get(limit_name)


def is_premium(user_doc):
    """Check if a user currently has premium access (paid or trial)."""
    return get_user_tier(user_doc) == 'premium'


def is_on_trial(user_doc):
    """Check if a user is on their free trial (not a paid subscriber)."""
    if not user_doc:
        return False
    tier = user_doc.get('account_tier', 'free')
    if tier == 'premium':
        return False  # paid subscriber, not trial
    join_date = user_doc.get('join_date')
    if join_date:
        if isinstance(join_date, datetime.datetime):
            if join_date.tzinfo is None:
                join_date = join_date.replace(tzinfo=datetime.timezone.utc)
            trial_end = join_date + datetime.timedelta(days=PREMIUM_TRIAL_DAYS)
            if datetime.datetime.now(datetime.timezone.utc) < trial_end:
                return True
    return False


def get_trial_days_remaining(user_doc):
    """Returns number of trial days remaining, or 0."""
    if not user_doc:
        return 0
    join_date = user_doc.get('join_date')
    if not join_date or user_doc.get('account_tier') == 'premium':
        return 0
    if isinstance(join_date, datetime.datetime):
        if join_date.tzinfo is None:
            join_date = join_date.replace(tzinfo=datetime.timezone.utc)
        trial_end = join_date + datetime.timedelta(days=PREMIUM_TRIAL_DAYS)
        remaining = (trial_end - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        return max(0, int(remaining / 86400) + (1 if remaining % 86400 > 0 else 0))
    return 0


# ---------------------------------------------------------------------------
# Post / comment helpers
# ---------------------------------------------------------------------------

comment_count_cache = TTLCache(maxsize=512, ttl=300)


@cached(comment_count_cache)
def get_batch_comment_counts(post_urls: tuple) -> dict:
    """Return a mapping from post slug (extracted from URL) to internal comment counts.

    This queries the local `comments` collection once for all given slugs.
    """
    counts_map = {}
    try:
        # Extract slugs from the provided URLs by splitting on '/post/'
        slugs = []
        for u in post_urls:
            if '/post/' in u:
                slugs.append(u.split('/post/')[-1])

        if not slugs:
            return counts_map

        pipeline = [
            {'$match': {'post_slug': {'$in': slugs}, 'is_deleted': False}},
            {'$group': {'_id': '$post_slug', 'count': {'$sum': 1}}}
        ]
        agg = list(database.comments_conf.aggregate(pipeline))
        for doc in agg:
            counts_map[doc['_id']] = doc.get('count', 0)
    except Exception as e:
        _get_app().logger.warning(f"Could not fetch batch comment counts from internal collection: {e}")
    return counts_map


def prepare_posts(posts):
    """
    Add `url` and `comment_count` fields to each post.
    Also ensures timestamps are timezone-aware for template calculations.
    """
    if not posts:
        return []

    # ---- Step 1: Build canonical URLs and deduplicate them ----
    urls_to_fetch = set()
    for post in posts:
        post_url = url_for("blog.view_post", slug=post.get("slug"), _external=True)
        post["url"] = post_url

        # Ensure timestamp is timezone-aware
        if post.get('timestamp') and post['timestamp'].tzinfo is None:
            post['timestamp'] = post['timestamp'].replace(tzinfo=datetime.timezone.utc)
        if post.get('edited_at') and post['edited_at'].tzinfo is None:
            post['edited_at'] = post['edited_at'].replace(tzinfo=datetime.timezone.utc)

        # Only fetch count if not already present (e.g., from an aggregation pipeline)
        if 'comment_count' not in post:
            urls_to_fetch.add(post_url)

    # ---- Step 2: Batch-retrieve comment counts ONLY if needed ----
    if urls_to_fetch:
        counts_map = get_batch_comment_counts(tuple(sorted(urls_to_fetch)))

    # ---- Step 3b: Batch-fetch premium status for all post authors ----
    author_ids = list(set(p.get('author_id') for p in posts if p.get('author_id')))
    premium_authors = set()
    if author_ids:
        premium_users = database.users_conf.find(
            {'_id': {'$in': author_ids}},
            {'account_tier': 1, 'premium_until': 1, 'join_date': 1}
        )
        for u in premium_users:
            if get_user_tier(u) == 'premium':
                premium_authors.add(u['_id'])

    # ---- Step 3c: Assign comment counts, achievements, and premium badge ----
    for post in posts:
        if 'comment_count' not in post:
            slug = post.get('slug')
            post["comment_count"] = counts_map.get(slug, 0) if urls_to_fetch else 0
        elif post.get('comment_count') is None:
            post['comment_count'] = 0
        
        # Inject author achievements
        author_id = post.get('author_id')
        if author_id:
            post['author_achievements'] = get_active_achievements(author_id)
            post['author_is_premium'] = author_id in premium_authors
        else:
            post['author_achievements'] = []
            post['author_is_premium'] = False

    return posts


def calculate_hot_score(post, comment_count):
    """
    Calculates a 'hot' score for a post using an improved algorithm.
    Uses logarithmic scaling to prevent viral posts from dominating,
    and includes all engagement signals (comments, likes, shares, views).
    """
    import math as math_module

    post_time = post.get('created_at') or post.get('timestamp')
    if not post_time:
        return 0

    # Ensure post_time is timezone-aware for correct calculation
    if post_time.tzinfo is None:
        post_time = post_time.replace(tzinfo=datetime.timezone.utc)

    age_in_hours = (datetime.datetime.now(datetime.timezone.utc) - post_time).total_seconds() / 3600

    # Get all engagement signals
    views = post.get('view_count', 0) or 0
    likes = post.get('likes_count', 0) or 0
    shares = post.get('share_count', 0) or 0

    # Weighted engagement score: comments(5) + likes(3) + shares(4) + views(0.1)
    raw_score = (comment_count * 5) + (likes * 3) + (shares * 4) + (views * 0.1)

    # Use logarithmic scaling to prevent viral posts from completely dominating
    # log1p(x) = log(1 + x), handles zero values safely
    log_score = math_module.log1p(raw_score) * 10

    # Exponential time decay - softened half-life
    # Quality posts now stay "warm" much longer (72 hour half-life vs 24 hour)
    half_life_hours = 72
    decay_factor = 0.5 ** (age_in_hours / half_life_hours)

    # Boost for very recent posts (first 4 hours get extra visibility)
    if age_in_hours < 4:
        recency_boost = 1.3 - (age_in_hours * 0.075)  # 1.3x to 1.0x
    else:
        recency_boost = 1.0

    return log_score * decay_factor * recency_boost


def _serialize_comment(doc, reply_counts=None):
    if reply_counts is None: reply_counts = {}
    return {
        'id': str(doc.get('_id')),
        'post_slug': doc.get('post_slug'),
        'author_id': str(doc.get('author_id')) if doc.get('author_id') else None,
        'author_username': doc.get('author_username') or doc.get('author'),
        'content': doc.get('content'),
        'created_at': doc.get('created_at').isoformat() if doc.get('created_at') else None,
        'edited_at': doc.get('edited_at').isoformat() if doc.get('edited_at') else None,
        'is_deleted': doc.get('is_deleted', False),
        'parent_id': str(doc.get('parent_id')) if doc.get('parent_id') else None,
        'upvote_count': doc.get('upvote_count', 0),
        'upvoted_by': [str(uid) for uid in doc.get('upvoted_by', [])],
        'reply_count': reply_counts.get(str(doc.get('_id')), 0),
    }


def _get_user_badge_count(user_id_str):
    """Get the unread notification count for a user (lightweight version for FCM badge).
    
    Uses the global last_activity_check threshold for speed since this runs
    in notification-sending context. Returns at least 1 when called during
    notification delivery so the badge is never empty.
    """
    try:
        user_id = ObjectId(user_id_str)
        user_doc = database.users_conf.find_one({'_id': user_id}, {'last_activity_check': 1})
        threshold = user_doc.get('last_activity_check') if user_doc else None
        if not threshold:
            threshold = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
        if threshold.tzinfo is None:
            threshold = threshold.replace(tzinfo=datetime.timezone.utc)

        count = 0
        # Comments on user's own posts
        user_post_slugs = [p.get('slug') for p in database.posts_conf.find({'author_id': user_id}, {'slug': 1})]
        if user_post_slugs:
            count += database.comments_conf.count_documents({
                'post_slug': {'$in': user_post_slugs},
                'author_id': {'$ne': user_id},
                'created_at': {'$gt': threshold},
                'is_deleted': {'$ne': True}
            })

        # Replies to user's comments
        my_comment_ids = [c['_id'] for c in database.comments_conf.find({'author_id': user_id}, {'_id': 1})]
        if my_comment_ids:
            count += database.comments_conf.count_documents({
                'parent_id': {'$in': my_comment_ids},
                'author_id': {'$ne': user_id},
                'created_at': {'$gt': threshold},
                'is_deleted': {'$ne': True}
            })

        return max(count, 1)  # At least 1 since we're sending a notification right now
    except Exception:
        return 1


def _invalidate_badge_cache(user_id_str):
    """Clear cached badge counts so the next poll returns fresh data.
    
    Call this whenever a new DM, comment, or notification is created
    that should update the target user's badge count immediately.
    """
    if database.redis_cache:
        try:
            database.redis_cache.delete(f"unread_notif_count:{user_id_str}")
            database.redis_cache.delete(f"badge_counts:{user_id_str}")
        except Exception:
            pass


def _has_active_auto_approve(share_id, editor_id):
    """Check if a specific editor still has auto-approve enabled on the given share."""
    if not share_id or not editor_id:
        return False
    share = database.note_shares_conf.find_one({'share_id': share_id}, {'auto_approved_users': 1})
    if not share:
        return False
    auto_approved = share.get('auto_approved_users', [])
    try:
        return ObjectId(editor_id) in auto_approved
    except Exception:
        return str(editor_id) in [str(uid) for uid in auto_approved]


def can_dm(user_a_id, user_b_id):
    """Check if two users are allowed to exchange DMs.
    Returns True if:
      - An accepted dm_permission exists between them (either direction), OR
      - They have prior message history (grandfathered conversations)
    """
    a_oid = ObjectId(user_a_id)
    b_oid = ObjectId(user_b_id)
    
    # Check for accepted permission in either direction
    perm = database.dm_permissions_conf.find_one({
        '$or': [
            {'requester_id': a_oid, 'target_id': b_oid, 'status': 'accepted'},
            {'requester_id': b_oid, 'target_id': a_oid, 'status': 'accepted'}
        ]
    })
    if perm:
        return True
    
    # Grandfathering: check if any messages exist between them
    existing = database.direct_messages_conf.find_one({
        '$or': [
            {'sender_id': a_oid, 'recipient_id': b_oid},
            {'sender_id': b_oid, 'recipient_id': a_oid}
        ]
    })
    return existing is not None


def fetch_link_preview(url):
    """Fetches OpenGraph metadata from a URL for a link preview card."""
    try:
        response = requests.get(url, timeout=3, stream=True)
        # Read only a small chunk to prevent memory issues with large files
        chunk = next(response.iter_content(chunk_size=50000))
        html_content = chunk.decode('utf-8', errors='ignore')
        
        # Simple regex parsing (avoids pulling in bs4 just for this)
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        
        def get_meta(property_name):
            m = re.search(rf'<meta[^>]*property="{property_name}"[^>]*content="([^"]+)"[^>]*>', html_content, re.IGNORECASE)
            if not m:
                m = re.search(rf'<meta[^>]*content="([^"]+)"[^>]*property="{property_name}"[^>]*>', html_content, re.IGNORECASE)
            return m.group(1) if m else ""

        og_title = get_meta("og:title")
        og_desc = get_meta("og:description")
        og_image = get_meta("og:image")
        
        title = og_title or (title_match.group(1).strip() if title_match else url)
        title = html.unescape(title)
        
        return {
            'url': url,
            'title': title[:100],
            'description': html.unescape(og_desc)[:150],
            'image': og_image
        }
    except Exception as e:
        _get_app().logger.warning(f"Failed to fetch link preview for {url}: {e}")
        return None


def _deliver_scheduled_message(sched_msg):
    """Core delivery logic: converts a scheduled_messages doc into a real DM.
    
    Called by:
      1. process_scheduled_messages.py (background scheduler — every minute)
      2. api_schedule_send_now() (user clicks 'Send Now')
    """
    try:
        sender_id_str = str(sched_msg['sender_id'])
        recipient_id_str = str(sched_msg['recipient_id'])

        # Build the direct_messages document (content is already encrypted)
        message_doc = {
            'sender_id': sched_msg['sender_id'],
            'recipient_id': sched_msg['recipient_id'],
            'content': sched_msg['content'],
            'encrypted': True,
            'timestamp': datetime.datetime.now(datetime.timezone.utc),
            'is_read': False,
            'message_type': sched_msg.get('message_type', 'text')
        }

        if sched_msg.get('image_url'):
            message_doc['image_url'] = sched_msg['image_url']
        if sched_msg.get('reply_to_id'):
            message_doc['reply_to_id'] = sched_msg['reply_to_id']
            message_doc['reply_to_preview'] = sched_msg.get('reply_to_preview')
            message_doc['reply_to_sender'] = sched_msg.get('reply_to_sender')
        if sched_msg.get('link_preview'):
            message_doc['link_preview'] = sched_msg['link_preview']

        # Insert into direct_messages
        database.direct_messages_conf.insert_one(message_doc)

        # Decrypt content for the real-time payload (plain text for Socket.IO)
        plain_content = sched_msg.get('content', '')
        if plain_content and plain_content.startswith('gAAAAA'):
            try:
                plain_content = decrypt_dm(plain_content, sender_id_str, recipient_id_str)
            except Exception:
                plain_content = ''

        plain_image = ''
        if sched_msg.get('image_url'):
            raw_img = sched_msg['image_url']
            if raw_img and raw_img.startswith('gAAAAA'):
                try:
                    plain_image = decrypt_dm(raw_img, sender_id_str, recipient_id_str)
                except Exception:
                    plain_image = raw_img
            else:
                plain_image = raw_img

        # Decrypt reply preview for payload
        plain_reply_preview = sched_msg.get('reply_to_preview', '')
        if plain_reply_preview and isinstance(plain_reply_preview, str) and plain_reply_preview.startswith('gAAAAA'):
            try:
                plain_reply_preview = decrypt_dm(plain_reply_preview, sender_id_str, recipient_id_str)
            except Exception:
                pass

        # Decrypt link_preview for payload
        plain_link_preview = None
        if sched_msg.get('link_preview') and isinstance(sched_msg['link_preview'], dict):
            lp = sched_msg['link_preview']
            plain_link_preview = {}
            for field in ['url', 'title', 'description', 'image']:
                val = lp.get(field, '')
                if val and isinstance(val, str) and val.startswith('gAAAAA'):
                    try:
                        plain_link_preview[field] = decrypt_dm(val, sender_id_str, recipient_id_str)
                    except Exception:
                        plain_link_preview[field] = val
                else:
                    plain_link_preview[field] = val

        # Look up sender username
        sender = database.users_conf.find_one({'_id': sched_msg['sender_id']}, {'username': 1})
        sender_username = sender['username'] if sender else 'Unknown'

        # Socket.IO real-time broadcast
        payload = {
            'id': str(message_doc['_id']),
            'sender_id': sender_id_str,
            'recipient_id': recipient_id_str,
            'sender_username': sender_username,
            'content': plain_content,
            'timestamp': message_doc['timestamp'].isoformat().replace('+00:00', 'Z'),
            'is_read': False,
            'message_type': sched_msg.get('message_type', 'text')
        }
        if plain_image:
            payload['image_url'] = plain_image
        if sched_msg.get('reply_to_id'):
            payload['reply_to_id'] = str(sched_msg['reply_to_id'])
            payload['reply_to_preview'] = plain_reply_preview
            payload['reply_to_sender'] = sched_msg.get('reply_to_sender')
        if plain_link_preview:
            payload['link_preview'] = plain_link_preview

        _get_socketio().emit('new_dm', payload, room=f"user_{recipient_id_str}")
        _get_socketio().emit('new_dm', payload, room=f"user_{sender_id_str}")

        # Push notification
        push_body = "📸 Photo" if sched_msg.get('message_type') == 'image' else (plain_content[:100] + ('...' if len(plain_content) > 100 else ''))
        _get_send_push_notification()(
            recipient_id_str,
            f"New message from {sender_username}",
            push_body,
            url=url_for('messages_page', _external=True),
            tag=f'dm-{sender_id_str}'
        )

        # Invalidate badge cache
        _invalidate_badge_cache(recipient_id_str)

        # Mark scheduled message as sent
        database.scheduled_messages_conf.update_one(
            {'_id': sched_msg['_id']},
            {'$set': {'status': 'sent', 'delivered_at': datetime.datetime.now(datetime.timezone.utc)}}
        )

        _get_app().logger.info(f"Scheduled message {sched_msg['_id']} delivered from {sender_id_str} to {recipient_id_str}")
        return True
    except Exception as e:
        _get_app().logger.error(f"Failed to deliver scheduled message {sched_msg.get('_id')}: {e}")
        return False


# ---------------------------------------------------------------------------
# NLP
# ---------------------------------------------------------------------------

def _nlp_suggest_tags(text: str, max_tags: int = 4) -> list:
    """Free local NLP tag suggestion — no API tokens used.
    Scores each predefined tag by counting keyword hits in the text,
    then returns the top-scoring tags."""
    text_lower = text.lower()
    scores = {}
    for tag, keywords in _TAG_KEYWORDS.items():
        score = 0
        for kw in keywords:
            if kw in text_lower:
                # Longer keyword matches are worth more (more specific)
                score += 1 + len(kw) / 20
        if score > 0:
            scores[tag] = score

    if not scores:
        return []

    # Sort by score descending and return top tags
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [tag for tag, _ in ranked[:max_tags]]


# ---------------------------------------------------------------------------
# Zen quote
# ---------------------------------------------------------------------------

def get_zen_quote():
    """Fetches a random quote from ZenQuotes API with 2-minute caching."""
    cache_key = 'zen_quote'

    # Try to get from Redis cache
    if database.redis_cache:
        try:
            cached_quote = database.redis_cache.get(cache_key)
            if cached_quote:
                return json.loads(cached_quote)
        except Exception as e:
            _get_app().logger.warning(f"Error reading quote from Redis: {e}")

    # Fallback to in-memory cache if Redis is down or missing
    # (Though redis_cache is preferred based on its setup in main.py)

    try:
        # Fetch from ZenQuotes API
        # Free version restricted to 5 requests per 30 seconds
        response = requests.get("https://zenquotes.io/api/random", timeout=5)
        if response.status_code == 200:
            quote_data = response.json()
            if quote_data and isinstance(quote_data, list) and len(quote_data) > 0:
                quote = {
                    'text': quote_data[0].get('q'),
                    'author': quote_data[0].get('a'),
                    'html': quote_data[0].get('h')
                }

                # Cache the quote for 2 minutes (120 seconds)
                if database.redis_cache:
                    try:
                        database.redis_cache.setex(cache_key, 120, json.dumps(quote))
                    except Exception as e:
                        _get_app().logger.warning(f"Error caching quote to Redis: {e}")

                return quote
    except Exception as e:
        _get_app().logger.error(f"Error fetching ZenQuote: {e}")

    # Fallback quote if API fails
    return {
        'text': "The only way to do great work is to love what you do.",
        'author': "Steve Jobs",
        'html': "<blockquote>&ldquo;The only way to do great work is to love what you do.&rdquo; &mdash; <footer>Steve Jobs</footer></blockquote>"
    }
