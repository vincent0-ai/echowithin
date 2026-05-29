# DISCOVERY.md — EchoWithin Platform Full Audit

Generated: 2026-05-29 | main.py: 14,135 lines | 628,926 bytes

---

## Phase 1.1 — Stack Inventory

### a. Python Version
- **Python 3.13.13** (from `python --version`)
- No version-specific patterns beyond standard-library usage

### b. Web Layer
- **Flask 3.1.2** with `@app.route()` decorator pattern
- **No Blueprints** used for existing routes (all routes decorated directly on `app`)
- One exception: `api_bp` (Blueprint `api_v1`) registered at line 14132 under `/api/v1`, defined in `api.py` (1,200+ lines, for mobile/native app REST API)
- WSGI served via gunicorn (requirements.txt), entry via `wsgi.py` which does `from main import app`
- **Total routes: ~179** `@app.route` decorators
- **13 SocketIO event handlers** (`@socketio.on`)
- ProxyFix middleware for reverse proxy headers (Render)

### c. Database Layer
- **MongoDB via PyMongo 4.15.4** (`pymongo.MongoClient`)
- Database: `echowithin_db` (configured via env vars `DB_USERNAME`, `DB_PASSWORD`, `DB_CLUSTER`, `DB_NAME`)
- **27 collections** tracked (line ~497–547):
  - `users` (users_conf)
  - `posts` (posts_conf)
  - `logs` (logs_conf)
  - `auth` (auth_conf)
  - `announcements` (announcements_conf)
  - `comments` (comments_conf)
  - `personal_posts` (personal_posts_conf)
  - `note_shares` (note_shares_conf)
  - `note_versions` (note_versions_conf)
  - `note_discussions` (note_discussions_conf)
  - `push_subscriptions` (push_subscriptions_conf)
  - `fcm_tokens` (fcm_tokens_conf)
  - `direct_messages` (direct_messages_conf)
  - `newsletter_subs` (newsletter_conf)
  - `user_post_views` (user_post_views_conf)
  - `unlock_notifications` (unlock_notifications_conf)
  - `weekly_winners` (weekly_winners_conf)
  - `app_tokens` (app_tokens_conf)
  - `app_updates` (app_updates_conf)
  - `communities` (communities_conf)
  - `community_notes` (community_notes_conf)
  - `community_reactions` (community_reactions_conf)
  - `community_reports` (community_reports_conf)
  - `dm_permissions` (dm_permissions_conf)
  - `scheduled_messages` (scheduled_messages_conf)
  - `note_attachments` (note_attachments_conf)
- Query patterns: `find_one`, `find`, `insert_one`, `update_one`, `update_many`, `delete_one`, `delete_many`, `count_documents`, aggregation pipelines with `$lookup`, `$match`, `$group`, `$sort`, `$project`
- **Redis** (redis 7.1.0) for caching, session state, rate-limit debouncing. Used via `redis_cache` global.
- **RQ 2.6.0** (Flask-RQ2) for background job queue, with `@rq.job` decorator.

### d. Authentication
- **Flask-Login 0.6.3** with `UserMixin` class
- `@login_manager.user_loader` — `load_user` (line 1681) with in-memory TTLCache
- `@login_manager.request_loader` — `load_user_from_request` (line 1710) for API tokens (`X-App-Token` header, `Authorization: Bearer`, `x_app_token` cookie)
- Session-based web auth + token-based mobile/native auth
- **Google OAuth** via `requests-oauthlib` (`OAuth2Session`) — `/google_login` + `/google_callback`
- Mobile deep-link bridging via one-time login tokens (OTLT) stored in Redis
- Password hashing via `werkzeug.security.generate_password_hash` / `check_password_hash`
- Email confirmation codes (6-digit, SHA-256 hashed, 24h expiry)
- Password reset flow with tokens
- Ban system with force-logout middleware
- `@admin_required` decorator (checks `current_user.is_admin`)
- `@owner_required` decorator (checks post ownership)

### e. File Handling
- **Cloudinary** for image/video/audio uploads (profile pictures, post media, DM images, voice notes, community note media, valentine/surprise media)
- **Local file serving**: `/uploads/<filename>` via `send_from_directory`
- **APK serving**: `/download/note-app.apk` + admin APK upload to `static/downloads/`
- **Service worker**: `/service-worker.js` served from static
- **Temp uploads**: `temp_uploads/` folder for post creation workflow
- **NSFW image detection**: Uses JigsawStack (via `jigsawstack` SDK + raw HTTP API) with background RQ job `process_image_for_nsfw`

### f. Email / Notifications
- **Flask-Mail 0.10.0** (`Mail`, `Message`)
- Email functions:
  - `send_code` (verification code)
  - `send_reset_code` (password reset)
  - `send_new_post_notifications` (RQ job — to immediate subscribers)
  - `send_weekly_newsletter` (RQ job — top 15 posts by engagement score)
  - `send_log_email_job` (RQ job — daily log attachment)
- Templates: `verify.html`, `reset_email.html`, `weekly_newsletter.html`, `new_post_notification.html`
- **Unsubscribe tokens**: per-recipient SHA-256 tokens, RFC 8058 one-click (`List-Unsubscribe` header)

### g. External Integrations
- **Typesense** — full-text search backend (`typesense_client.py`)
- **JigsawStack** — AI: NSFW image detection, tag suggestions, note merge conflict resolution
- **Cloudinary** — image/video hosting
- **Paystack** — payment processing (KES 50/month premium subscriptions + donations)
- **Google OAuth 2.0** — social login (`requests-oauthlib`)
- **Firebase Cloud Messaging (FCM)** — Android native push notifications (`firebase-admin`)
- **Web Push API** — PWA push notifications via `pywebpush` (VAPID)
- **ZenQuotes API** — random quotes on dashboard (Redis cached 120s)
- **ntfy.sh** — admin alert notifications
- **MongoDB Atlas** — backup target (`backup_to_atlas.py`)

### h. Background / Async Work
- **RQ** (`Flask-RQ2`) background job queue (Redis-backed):
  - `process_image_for_nsfw` — NSFW image detection
  - `send_new_post_notifications` — email new post to immediate subscribers
  - `send_weekly_newsletter` — weekly digest email
  - `send_push_notification_to_user` — per-user Web Push + FCM
  - `send_admin_broadcast_push` — site-wide push broadcast
  - `send_push_notifications_for_new_post` — new post push to all subscribers
  - `send_push_notification_for_comment` — comment reply push
  - `send_log_email_job` — daily log email
  - `send_ntfy_notification` — ntfy.sh alert
  - `reindex_typesense_job` — batch reindex
  - `process_post_media` — post media upload/resize
- **ThreadPoolExecutor** (`executor` global, max_workers=10) for fire-and-forget tasks (fallback when Redis unavailable)
- **Scheduler** (`scheduler.py`) — standalone `schedule` library process for cron-like jobs:
  - Daily log email (01:00 AM)
  - Weekly newsletter (Sunday 09:00 AM)
  - Auth cleanup (every hour)
  - Weekly achievements (Monday 00:01 AM)
  - Atlas backup (every 6 hours)
  - Scheduled message processing (every 1 minute)
- **RQ Worker** (`worker.py`) — standalone process for processing RQ queues

### i. Template Rendering
- **Jinja2** (Flask default, via `render_template`)
- 42 templates in `templates/` directory
- **Custom template filters**: `linkify`, `markdown`, `from_timestamp`, `to_iso`, `to_local`, `localtime`
- **Context processors**: `inject_pinned_announcement`, `inject_template_globals` (injects tier info, csp_nonce, current_year, TIER_LIMITS)
- **Base template**: `base.html`
- **Macros**: `_macros.html`

### j. Configuration
- **python-dotenv** — `.env` file loading
- **Environment variables** (key ones):
  - `SECRET_KEY`, `DB_USERNAME`, `DB_PASSWORD`, `DB_CLUSTER`, `DB_NAME`
  - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
  - `VAPID_PRIVATE_KEY`, `VAPID_PUBLIC_KEY`
  - `REDIS_URL` / `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
  - `TYPESENSE_HOST`, `TYPESENSE_PORT`, `TYPESENSE_PROTOCOL`, `TYPESENSE_API_KEY`
  - `CLOUDINARY_URL`
  - `PAYSTACK_SECRET_KEY`, `PAYSTACK_PUBLIC_KEY`
  - `JIGSAWSTACK_API_KEY`
  - `FIREBASE_CREDENTIALS` (JSON path)
  - `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`
  - `SOCKETIO_ALLOWED_ORIGINS`, `SESSION_COOKIE_SECURE`, `CSP_STRICT_NONCES`

### k. Testing
- `tests/` directory exists but appears **empty** (no test files found)
- `pytest` not in requirements.txt (no test framework installed)
- No test infrastructure detected

### l. Other Patterns
- **Monkey patching**: `gevent.monkey.patch_all()` at top of main.py (line 2–3)
- **Rate limiting**: `ratelimit` library, wrapped in custom `limits` decorator (with dev bypass via `BYpass_RATE_LIMIT`)
- **CSRF protection**: Flask-WTF `CSRFProtect` with exempt routes
- **Security headers**: CSP (with nonce support), HSTS, X-Frame-Options, etc. via `@app.after_request`
- **Canonical domain redirect** via `@app.before_request`
- **Encryption**: Three-tier Fernet scheme (v1 global, v2 per-user, v3 per-conversation) using `cryptography` library
- **JSON logging**: `python-json-logger` with `RequestIDFilter` and `RotatingFileHandler`
- **Note version control**: Snapshots before edits (cap 50), collaborative proposals with approve/reject workflow
- **Note sync**: Bidirectional clone-original sync with conflict detection (push/pull)
- **App lock**: 4-digit PIN with 5-minute session unlock window
- **DM permission system**: Request → accept/reject flow
- **PWA support**: Service worker, manifest, offline page, share target, `update-manifest.json`
- **Asset Links**: `/.well-known/assetlinks.json` for Android App Links
- **SEO**: Sitemap (auto-generated, Redis-cached 1h), robots.txt, JSON-LD structured data, RSS feed (`/feed.xml`)

---

## Phase 1.2 — Symbol Inventory (Summary)

### Main.py Total Symbols: ~300+
- **~289 function definitions** (including route handlers, helpers, RQ jobs)
- **2 class definitions**: `RequestIDFilter`, `User(UserMixin)`
- **~179 route handlers** (`@app.route`)
- **18 app-level hooks** (5 before_request, 1 after_request, 2 context_processor, 1 user_loader, 1 request_loader, 3 errorhandler, 5 template_filter)
- **13 socketio event handlers**
- **11 RQ job functions** (`@rq.job`)
- **27 MongoDB collection variables**
- **15+ cache instances** (TTLCache, dict, Redis)
- **~40 global constants** (`TIER_LIMITS`, `ENGAGEMENT_WEIGHTS`, `ALLOWED_*_EXTENSIONS`, `VAPID_*`, etc.)

### External Files
- **api.py**: Blueprint `api_v1` with ~25 API endpoints (auth, notes CRUD, app lock, push, sharing, versions, sync, proposals), ~1,200+ lines
- **typesense_client.py**: Typesense client module, ~294 lines
- **scheduler.py**: Standalone scheduler process, 135 lines
- **worker.py**: RQ worker process, 32 lines
- **wsgi.py**: WSGI entry point, 3 lines
- **Standalone scripts** (run via scheduler subprocess or directly):
  - `process_scheduled_messages.py` (5,324 lines) — processes due scheduled DMs
  - `weekly_achievements.py` (8,046 lines) — calculates weekly achievement winners
  - `backup_to_atlas.py` (6,511 lines) — syncs MongoDB data to Atlas
  - `cleanup_expired_auth.py` (1,963 lines) — removes expired auth tokens
  - `schedule_log_email.py` (1,560 lines) — sends daily log email
  - `send_weekly_newsletter.py` (1,663 lines) — sends weekly newsletter
  - `fix_template_syntax.py` (1,354 lines) — utility script

---

## Phase 1.3 — Dependency Graph (High-Level Clusters)

### Cluster 1: **Core Infrastructure** (bottom layer)
Shared utilities imported by nearly everything:
- MongoDB client + collections
- Redis cache
- Typesense client (`_t`)
- App config, env variables
- Template filters, context processors
- Security middlewares, hooks
- Logging setup
- Rate limiter wrapper

### Cluster 2: **Authentication**
- User model (`User(UserMixin)`)
- `load_user`, `load_user_from_request`
- Login, register, confirm, logout routes
- Google OAuth flow
- Password reset, forgot password
- `admin_required`, `owner_required` decorators
- App tokens, re-auth

### Cluster 3: **Encryption**
- `_derive_fernet_key`, `get_notes_fernet`, `_get_user_fernet`, `_get_dm_fernet`
- `encrypt_note`, `decrypt_note`, `encrypt_dm`, `decrypt_dm`
- `_decrypt_note_record`, `_decrypt_with_candidate_ids`
- `encrypt_community_note`, `decrypt_community_note`
- Used by: notes, DMs, community notes

### Cluster 4: **Notifications**
- `send_code`, `send_reset_code` (email)
- `send_new_post_notifications`, `send_weekly_newsletter` (email/RQ)
- `send_push_notification_to_user`, `send_admin_broadcast_push`, `send_push_notifications_for_new_post`
- `send_push_notification_for_comment`
- `send_fcm_notification_to_user`, `send_fcm_notifications_batch`
- `send_ntfy_notification`
- Push subscription management (subscribe, unsubscribe, VAPID)
- FCM token registration

### Cluster 5: **Blog/Posts**
- Post CRUD: `create_post`, `post`, `edit_post`, `update_post`, `delete_post`
- Post viewing: `view_post`, `blog`, `all_posts`, `dashboard`, `home`
- Post APIs: `get_all_posts_json`, `get_top_posts_json`, `get_hot_posts_json`, `get_related_posts_json`
- Post interactions: `toggle_reaction_post`, `toggle_save_post`, `share_post`
- Post feed: `feed.xml` (RSS), `prepare_posts` (enrichment)

### Cluster 6: **Comments**
- `api_post_comments` (GET/POST)
- `api_delete_comment`, `api_edit_comment`, `api_vote_comment`
- `_serialize_comment`, `get_batch_comment_counts`

### Cluster 7: **Personal Notes**
- CRUD: `create_personal_post`, `create_personal_post_json`, `edit_personal_post`, `delete_personal_post`
- Sync: `sync_personal_post` (bidirectional push/pull)
- Search: `search_personal_notes` (Typesense + MongoDB fallback)
- Space: `personal_space` (view saved posts + personal notes)
- App lock: `app_lock_setup`, `app_lock_verify`, `app_lock_remove`, `app_lock_relock`, `app_lock_check_status`, `toggle_note_lock`
- Typesense: `reindex_my_notes`, `index_note_to_typesense`, `remove_note_from_typesense`

### Cluster 8: **Note Sharing & Collaboration**
- Share CRUD: `api_create_share`, `api_revoke_share`, `api_get_note_shares`, `api_toggle_share_auto_approve`
- View shared: `view_shared_note`, `view_saved_note`
- Attachments: `api_upload_note_attachment`, `api_list_note_attachments`, `api_delete_note_attachment`
- Versions: `api_get_note_versions`, `api_restore_note_version`
- Proposals: `api_decide_note_proposal`
- Edit shared: `api_edit_shared_note`
- Note discussions: `api_get_note_comments`, `api_post_note_comment`, `api_post_note_reply`, `api_delete_note_comment`
- SocketIO collaboration: `join_note`, `leave_note`, `acquire_lock`, `release_lock`, `note_update`
- AI merge: `merge_conflict_ai`

### Cluster 9: **Chat / Direct Messages**
- Inbox: `messages_page`, `api_message_history`
- SocketIO DM: `join_inbox`, `send_dm`, `viewing_chat`, `leave_chat`, `disconnect`, `typing`, `stop_typing`
- DM CRUD: `api_edit_message`, `api_delete_message`, `api_delete_chat`
- DM media: `api_upload_dm_image`, `api_upload_dm_voice`
- Reactions: `api_react_message`
- Search: `api_search_messages`
- Unread: `api_unread_dm_count`, `get_badge_counts`, `_invalidate_badge_cache`
- DM requests: `api_send_dm_request`, `api_accept_dm_request`, `api_reject_dm_request`, `api_list_dm_requests`, `api_dm_status`
- Scheduled messages: `api_schedule_message`, `api_list_scheduled_messages`, `api_schedule_cancel`, `api_schedule_send_now`, `api_process_scheduled_messages`, `_deliver_scheduled_message`
- Helpers: `can_dm`, `fetch_link_preview`

### Cluster 10: **Communities**
- Community CRUD: `api_create_community`, `api_update_community`, `api_regenerate_invite`, `api_leave_community`, `api_remove_member`
- Joining: `join_community_link`, `api_join_community_code`, `api_join_public_community`
- View: `communities_page`, `view_community`
- Notes: `api_create_community_note`, `api_delete_community_note`
- Reactions: `api_react_community_note`
- Share: `view_shared_community_note`, `api_save_community_note`
- Reporting: `api_report_community`
- Admin: `admin_communities`, `api_admin_ban_community`, `api_admin_unban_community`, `api_admin_delete_community`, `api_admin_community_reports`, `api_admin_dismiss_report`

### Cluster 11: **Admin**
- Dashboard: `admin_dashboard`, `admin_metrics`, `admin_traffic`, `admin_system_health`
- Posts: `admin_posts`, `admin_delete_post`, `admin_pin_post`, `admin_unpin_post`
- Users: `admin_users`, `ban_user`, `unban_user`, `delete_user`, `admin_active_users`
- Premium: `admin_premium_users`, `grant_premium`, `revoke_premium`
- Announcements: `admin_announcements`, `pin_announcement`, `unpin_announcement`, `delete_announcement`, `admin_send_push`
- APK: `admin_upload_apk`
- Export: `admin_export_csv`
- Reindex: `admin_reindex_typesense`, `admin_reindex_notes_typesense`, `reindex_typesense_job`, `api_clear_sitemap_cache`

### Cluster 12: **Profile & Settings**
- Profile view: `profile`, `user_posts_page`
- Settings: `profile_settings` (username, bio, avatar, notification pref, DM privacy)
- Export data: `export_data`
- Delete account: `delete_account`

### Cluster 13: **Payments (Paystack)**
- `paystack_initialize`, `paystack_callback`, `paystack_webhook`

### Cluster 14: **Tier/Premium**
- `get_user_tier`, `get_limit`, `is_premium`, `is_on_trial`, `get_trial_days_remaining`
- `TIER_LIMITS` constant

### Cluster 15: **Search**
- `search` route (Typesense + MongoDB fallback)
- Typesense indexing helpers (posts + notes)

### Cluster 16: **Misc Web Pages**
- Static pages: `offline`, `about`, `terms`, `faq`
- `contact_developer` (contact form → email)
- `unsubscribe` (newsletter)
- `sitemap_index`, `robots`, `sitemap_legacy_redirect`
- `android_assetlinks`, `service_worker`, `download_note_app_apk`, `serve_update_manifest`
- `get_quote_api`, `get_zen_quote`
- `api_newsletter_subscribe`
- `api_suggest_tags`, `api_user_suggest`, `_nlp_suggest_tags`
- `favicon`, `mobile_auth`

### Cluster 17: **Scheduled Scripts** (standalone `.py` files, not in main.py)
- `scheduler.py` — master scheduler process
- `worker.py` — RQ worker process
- `process_scheduled_messages.py` — delivers due scheduled DMs
- `weekly_achievements.py` — calculates weekly winners
- `backup_to_atlas.py` — MongoDB Atlas backup
- `cleanup_expired_auth.py` — removes expired auth tokens/codes
- `schedule_log_email.py` — sends daily log email
- `send_weekly_newsletter.py` — sends weekly newsletter digest

---

## Phase 1.4 — Dead Code Analysis

Processing in Phase 3 after full symbol reference scan. Preliminary candidates:
- `fix_template_syntax.py` (utility script, not imported by any production code)
- Any symbols in main.py found with zero cross-references after full scan

---

## Dynamic Symbols (KEEP)
- `get_main_globals()` in `api.py` — dynamic import of main module
- All `@socketio.on` handlers — registered via decorator on global `socketio` object
- All `@app.template_filter`, `@app.context_processor`, `@app.before_request`, `@app.after_request`, `@app.errorhandler` — Flask hook registration
- All `@login_manager.user_loader`, `@login_manager.request_loader` — Flask-Login registration
- All `@rq.job` — RQ task queue registration
- All `from main import app` (wsgi.py) — WSGI entry point
