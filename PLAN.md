# PLAN.md — EchoWithin Modularization Plan

## Module Structure Overview

```
echowithin/
├── app.py                       # Entry point: app creation, hooks, blueprint registration
├── config.py                    # Environment variables, constants, app config
├── database.py                  # MongoDB client, collections, Redis, executor
├── security.py                  # Encryption, rate limiting, decorators, safe utils
├── utils.py                     # Shared utilities (~60 symbols)
├── notifications.py             # Email + push notification functions
├── models.py                    # User class, user loaders
├── typesense_client.py          # Existing — unchanged
├── api.py                       # Existing mobile API blueprint — updated imports only
│
├── blueprints/
│   ├── __init__.py              # (empty)
│   ├── auth.py                  # Registration, login, logout, Google OAuth, password reset
│   ├── blog.py                  # Blog feed, post CRUD, comments, reactions, saves, shares
│   ├── notes.py                 # Personal notes CRUD, sync, search, personal space, app lock
│   ├── sharing.py               # Note sharing, collaboration, versions, proposals, note discussions
│   ├── chat.py                  # DM inbox, messaging, DM requests, scheduled messages
│   ├── communities.py           # Communities CRUD, community notes, reactions, reporting
│   ├── admin.py                 # Admin dashboard, metrics, user/post/announcement/community mgmt
│   ├── profile.py               # Profile view, settings, export, delete account
│   ├── payments.py              # Paystack integration
│   └── pages.py                 # Static pages, sitemap, robots.txt, RSS feed, contact, newsletter
│
├── scripts/                     # Scheduled/background scripts (moved from root)
│   ├── scheduler.py
│   ├── worker.py
│   ├── process_scheduled_messages.py
│   ├── weekly_achievements.py
│   ├── backup_to_atlas.py
│   ├── cleanup_expired_auth.py
│   ├── schedule_log_email.py
│   └── send_weekly_newsletter.py
│
├── templates/                   # Unchanged
├── static/                      # Unchanged
├── wsgi.py                      # Updated import
└── requirements.txt             # Unchanged
```

**Total: 21 modules (12 new, 1 new directory, 8 moved scripts)**

---

## Layer Dependency Order

```
Layer 0 — Standalone (imported by all, imports nothing internal)
  config.py

Layer 1 — Infrastructure (depends on config)
  database.py

Layer 2 — Shared Utilities (depends on database)
  security.py
  utils.py
  notifications.py
  models.py

Layer 3 — Shared Subsystems
  typesense_client.py  (unchanged, depends on its own env vars)

Layer 4 — Feature Blueprints (depend on layers 0–3 + typesense_client)
  blueprints/*
  api.py  (existing blueprint, updated imports)

Layer 5 — Entry Point (depends on everything)
  app.py

Layer 6 — External Entry
  wsgi.py
  scripts/*
```

---

## Detailed Module Assignments

### 1. config.py (~150 lines)

**Purpose:** Environment variables, global constants, app configuration init.

**Symbols assigned:**

- `load_dotenv(override=True)` call
- `get_env_variable(name)` — helper
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- `UPLOAD_FOLDER`, `ALLOWED_IMAGE_EXTENSIONS`, `ALLOWED_VIDEO_EXTENSIONS`, `ALLOWED_AUDIO_EXTENSIONS`
- `MAX_VIDEO_SIZE`, `MAX_IMAGE_SIZE`, `TEMP_UPLOAD_FOLDER`
- `VAPID_PRIVATE_KEY`, `VAPID_PUBLIC_KEY`, `VAPID_CLAIMS`
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`
- `BYpass_RATE_LIMIT`
- `_NOTES_KDF_ITERATIONS`, `_NOTES_V1_SALT`
- `TIER_LIMITS`, `PREMIUM_TRIAL_DAYS`, `PREMIUM_PRICE_KSH`
- `ENGAGEMENT_WEIGHTS`
- `FIREBASE_AVAILABLE`, Firebase SDK initialization (try/except block)
- `_ALLOWED_ORIGINS`
- `PREDEFINED_TAGS`, `_TAG_KEYWORDS`
- `clean_xml_text(text)` — utility function

**Imports from:** `os`, `secrets` (for `_NOTES_V1_SALT` if computed), `dotenv`, `firebase_admin` (optional)

**Imported by:** database.py, security.py, app.py, virtually everything

---

### 2. database.py (~100 lines)

**Purpose:** MongoDB client, all collection references, Redis cache, thread pool executor.

**Symbols assigned:**

- `client` (MongoClient)
- `db` (echowithin_db)
- All 27 collection variables:
  - `users_conf`, `posts_conf`, `logs_conf`, `auth_conf`, `announcements_conf`
  - `comments_conf`, `personal_posts_conf`, `note_shares_conf`, `note_versions_conf`
  - `note_discussions_conf`, `push_subscriptions_conf`, `fcm_tokens_conf`
  - `direct_messages_conf`, `newsletter_conf`, `user_post_views_conf`
  - `unlock_notifications_conf`, `weekly_winners_conf`, `app_tokens_conf`
  - `app_updates_conf`, `communities_conf`, `community_notes_conf`
  - `community_reactions_conf`, `community_reports_conf`, `dm_permissions_conf`
  - `scheduled_messages_conf`, `note_attachments_conf`
- `redis_cache` (Redis client or None)
- `executor` (ThreadPoolExecutor)

**Imports from:** `config` (env vars), `pymongo`, `redis`, `concurrent.futures`

**Imported by:** models.py, utils.py, security.py, notifications.py, app.py, all blueprints

---

### 3. security.py (~250 lines)

**Purpose:** Encryption system (v1/v2/v3 Fernet), rate limiting, security utilities.

**Symbols assigned:**

- Encryption core:
  - `_derive_fernet_key(secret_bytes, salt, iterations)`
  - `_get_notes_encryption_key()` — v1 legacy
  - `get_notes_fernet()` — v1 singleton
  - `_get_user_fernet(user_id)` — v2 per-user
  - `_get_dm_fernet(user1_id, user2_id)` — v3 per-conversation
  - `_notes_fernet`, `_user_fernet_cache`, `_dm_fernet_cache` (singletons)
- Encryption API:
  - `encrypt_dm(content, user1_id, user2_id)`
  - `decrypt_dm(encrypted_content, user1_id, user2_id)`
  - `encrypt_note(content, user_id=None)`
  - `decrypt_note(encrypted_content, user_id=None)`
  - `_candidate_user_ids(*values)`
  - `_decrypt_with_candidate_ids(encrypted_content, candidate_user_ids)`
  - `_note_decryption_candidates(note, share=None)`
  - `_decrypt_note_record(note, share=None)`
- Community encryption:
  - `_get_community_fernet(community_id)`
  - `encrypt_community_note(plaintext, community_id)`
  - `decrypt_community_note(ciphertext, community_id)`
- Security utilities:
  - `safe_object_id(id_string)`
  - `is_safe_url(target)`
  - `is_same_origin_request()`
  - `parse_iso_utc(value)`
  - `check_image_for_nsfw(image_path)`
- Rate limiter:
  - `limits(calls, period)` — decorator factory wrapping `ratelimit.limits`
- Decorators:
  - `admin_required(f)` — wraps `@login_required` + admin check
  - `owner_required(f)` — wraps post ownership check

**Imports from:** `config`, `database`, `cryptography`, `ratelimit`, `werkzeug.security`, `bson.objectid`, `flask`, `flask_login`, `jigsawstack`

**Imported by:** app.py, utils.py, notifications.py, models.py, all blueprints

---

### 4. utils.py (~800 lines)

**Purpose:** Template filters, tier/premium helpers, Cloudinary/media helpers, Typesense indexing wrappers, text utilities, achievement helpers, comment helpers, badge helpers, post preparation, caches, socketio shared state, sitemap generation, NLP tag suggestions, DM helpers.

**Symbols assigned:**

Template filters (registered in app.py on the app object):

- `linkify_filter(text)` — `@app.template_filter('linkify')` logic
- `_linkify_target_blank(attrs, new=False)` — bleach callback
- `markdown_filter(text)` — `@app.template_filter('markdown')` logic
- `from_timestamp_filter(timestamp)` — `@app.template_filter('from_timestamp')` logic
- `to_iso_filter(dt)` — `@app.template_filter('to_iso')` logic
- `to_local_filter(dt)` — `@app.template_filter('to_local')` logic
- `localtime_filter(dt, fmt)` — `@app.template_filter('localtime')` logic
- `optimize_cloudinary_url(url)`
- `extract_cloudinary_public_id(url)`
- `cleanup_share_media(share)`
- `cleanup_post_media(post)`
- Cloudinary media utilities for DM/voice/image upload helpers
- `build_unified_diff_text(original_text, updated_text, context, max_lines)`
- `build_merge_preview_text(current_text, incoming_text)`
- `prepare_posts(posts)`
- `calculate_hot_score(post, comment_count)`
- `get_active_achievements(user_id)`
- `get_batch_comment_counts(post_urls)` + `comment_count_cache`
- `_serialize_comment(c)`
- `_get_user_badge_count(user_id_str)`
- `_invalidate_badge_cache(user_id)`
- `fetch_link_preview(url)`
- `can_dm(user_a, user_b)`
- `_nlp_suggest_tags(content)`
- `_has_active_auto_approve(share_id)`
- `get_zen_quote()`
- `_deliver_scheduled_message(msg_doc)`
- Sitemap generation helpers (if separable from route logic)

Tier/premium helpers:

- `get_user_tier(user_doc)`
- `get_limit(user_doc, limit_name)`
- `is_premium(user_doc)`
- `is_on_trial(user_doc)`
- `get_trial_days_remaining(user_doc)`

Typesense indexing wrappers:

- `_note_to_typesense_doc(note_doc, decrypted_content)`
- `_post_to_typesense_doc(post_doc)`
- `index_note_to_typesense(note_id, decrypted_content)`
- `remove_note_from_typesense(note_id)`
- `remove_notes_from_typesense(note_ids)`
- `reindex_user_notes_to_typesense(user_id)`
- `index_post_to_typesense(post_id)`
- `reindex_all_posts_to_typesense(batch_size)`
- `reindex_all_notes_to_typesense(batch_size)`
- `_is_ios_web_push_subscription(subscription_doc)`
- `_remove_stale_push_subscription(subscription_doc, platform, user_label, reason)`

Caches:

- `_pinned_announcement_cache`, `profile_stats_cache`, `profile_posts_cache`
- `related_posts_cache`, `post_comment_stats_cache`, `community_stats_cache`
- `blog_feed_cache`, `user_loader_cache`, `weekly_winners_cache`

SocketIO shared state:

- `active_chat_views` (dict)
- `active_note_viewers` (dict)
- `note_locks` (dict)
- `_last_state_cleanup` (dict)

**Imports from:** `config`, `database`, `security`, `typesense_client`, `datetime`, `markdown`, `bleach`, `cloudinary`, `cachetools`, `difflib`, `PIL`, `math`, `json`, `requests`, `re`

**Imported by:** app.py, all blueprints

---

### 5. notifications.py (~500 lines)

**Purpose:** Email sending, push notification (Web Push + FCM), push subscription management.

**Symbols assigned:**

Email:

- `send_code(email, gen_code, retries, delay)` — verification code
- `send_reset_code(email, reset_token, retries, delay)` — password reset
- `send_new_post_notifications(post_id_str)` — RQ job
- `send_weekly_newsletter()` — RQ job
- `send_log_email_job()` — RQ job

Push notifications:

- `send_push_notification_to_user(user_id_str, title, body, url, tag, extra_data)` — RQ job
- `send_admin_broadcast_push(title, body, url)` — RQ job
- `send_push_notifications_for_new_post(post_id_str)` — RQ job
- `send_push_notification_for_comment(comment_id_str, post_slug)` — RQ job
- `send_fcm_notification_to_user(user_id_str, title, body, url, data)`
- `send_fcm_notifications_batch(tokens_list, title, body, url, data)`

Other:

- `send_ntfy_notification(event_type, message, tags)` — RQ job
- Push subscription routes: `get_vapid_public_key`, `subscribe_push`, `unsubscribe_push`, `push_subscription_status`
- FCM registration routes: `register_fcm_token`, `unregister_fcm_token`
- `process_image_for_nsfw(post_id, image_url, public_id)` — RQ job (moved from security if tightly coupled with notifications)

**Imports from:** `config`, `database`, `security`, `utils`, `typesense_client`, `flask`, `flask_mail`, `pywebpush`, `firebase_admin`, `hashlib`, `requests`, `datetime`

**Note:** Some of these are route handlers and RQ jobs. The route handlers can optionally be extracted as a sub-blueprint (`push_bp`) if there are enough routes. For now they stay in this module and are registered in app.py.

**Imported by:** app.py, blueprints that trigger notifications (blog, notes, chat, etc.)

Actually, `notifications.py` has a design tension. It has both:

- Pure notification-sending utility functions (used by many blueprints)
- Route handlers (push subscribe/unsubscribe, FCM register/unregister)

The route handlers are only called via HTTP. They need to be registered as routes. Options:

1. Keep route handlers in notifications.py and register them in app.py
2. Split route handlers into a separate push blueprint
3. Move route handlers back into the blueprint that makes most sense (e.g., blog.py or a push.py blueprint)

I'll go with option 2: create `blueprints/push.py` for push subscription management routes, and keep `notifications.py` as pure utility functions.

Wait, there's no `push.py` in my blueprint list. Let me add it. Actually, push subscription routes are small (5 routes) and could go in any existing blueprint. Let me put them in `blueprints/pages.py` since they're not really tied to any specific domain feature. Or better, put them in `blueprints/blog.py` since they relate to post notifications. Actually, they're standalone — let me create `blueprints/push.py`.

Updated blueprints list:

- `blueprints/push.py` — Push subscriptions, FCM registration, VAPID key
- Remove push-related routes from `notifications.py`

But wait, do I really want 12 blueprint files? The push part is only ~5 routes and ~100 lines. It's fine to keep them in notifications.py (as utility functions decorated with routes) and register them separately in app.py using `app.add_url_rule` or flatten them. Let me just keep them in notifications.py for now and register them in app.py.

Actually, the cleanest Flasks approach: put all push-related routes in a small Blueprint inside `notifications.py` itself, then register that blueprint in app.py. But the instructions say "If it does not use Blueprints, do not introduce them" — however, the codebase DOES use Blueprints (api.py). So introducing Blueprints for new modules is fine since it's an existing pattern.

Let me finalize: `notifications.py` will contain:

1. Pure utility functions (send_email, send_push, etc.)
2. A small Blueprint `push_bp` for the push subscription routes

This keeps push routes colocated with push utilities, which makes sense.

---

### 6. models.py (~100 lines)

**Purpose:** User model, user loaders for Flask-Login.

**Symbols assigned:**

- `class User(UserMixin)` with all methods:
  - `__init__`, `is_active` (property), `is_premium` (property)
  - `is_trial` (property), `trial_days_remaining` (property)
  - `get_limit`, `get_admin`
- `load_user(user_id)` — `@login_manager.user_loader`
- `load_user_from_request(req)` — `@login_manager.request_loader`

**Imports from:** `config`, `database`, `utils` (tier helpers), `flask_login`, `datetime`, `bson.objectid`

**Imported by:** app.py, api.py, all blueprints

---

### 7. app.py (~300 lines)

**Purpose:** Create Flask app + SocketIO + Mail + LoginManager + CSRF + RQ, register all hooks/middleware/context_processors/error_handlers, register all blueprints, run block.

**Symbols assigned:**

- `app` (Flask instance)
- `socketio` (SocketIO instance)
- `mail` (Mail instance)
- `login_manager` (LoginManager instance)
- `csrf` (CSRFProtect instance)
- `rq` (RQ instance)
- **Hooks:**
  - `set_request_id()` — `@app.before_request`
  - `set_csp_nonce()` — `@app.before_request`
  - `cleanup_stale_global_state()` — `@app.before_request`
  - `make_session_permanent()` — `@app.before_request`
  - `enforce_canonical_domain_and_https()` — `@app.before_request`
  - `update_last_active()` — `@app.before_request`
  - `add_security_headers(response)` — `@app.after_request`
- **Context processors:**
  - `inject_pinned_announcement()` — `@app.context_processor`
  - `inject_template_globals()` — `@app.context_processor`
- **Error handlers:**
  - `page_not_found(e)` — 404
  - `handle_ratelimit_exception(e)` — RateLimitException
  - `internal_server_error(e)` — 500
- **Login manager hooks:**
  - Register `unauthorized_api` handler
  - Register `load_user` user_loader (from models.py)
  - Register `load_user_from_request` request_loader (from models.py)
- **Template filter registration** (via `app.add_template_filter` using utils.py functions)
- **Blueprint registration** — all blueprints
- `if __name__ == '__main__': socketio.run(app)` block (if present)
- Logging setup (RotatingFileHandler, RequestIDFilter)

**Imports from:** EVERYTHING — all shared modules and blueprints

**Imported by:** wsgi.py

---

### 8. blueprints/auth.py (~250 lines)

**Purpose:** All authentication-related routes.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/register` | GET, POST | `register` |
| `/confirm/<email>` | GET, POST | `confirm` |
| `/login` | GET, POST | `login` |
| `/google_login` | GET | `google_login` |
| `/google_callback` | GET | `google_callback` |
| `/forgot_password` | GET, POST | `forgot_password` |
| `/reset_password/<token>` | GET, POST | `reset_password` |
| `/logout` | GET | `logout` |
| `/mobile_auth` | GET | `mobile_auth` |
| `/api/app_reauth` | POST | `app_reauth` |

**Template rendering:** `auth.html`, `confirm.html`, `forgot_password.html`, `reset_password.html`, `mobile_redirect.html`

**Estimated lines:** ~450

---

### 9. blueprints/blog.py (~1,500 lines)

**Purpose:** Blog feed, post CRUD, comments, reactions, saves, shares, RSS feed.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/` | GET | `dashboard` |
| `/dashboard` | GET | `dashboard` |
| `/home` | GET | `home` |
| `/blog` | GET | `blog` |
| `/blog/all` | GET | `all_posts` |
| `/api/posts` | GET | `get_all_posts_json` |
| `/api/posts/top-by-comments` | GET | `get_top_posts_json` |
| `/api/posts/hot` | GET | `get_hot_posts_json` |
| `/api/posts/my-commented` | GET | `get_my_commented_posts_json` |
| `/api/posts/mark-all-read` | POST | `mark_all_comments_read` |
| `/api/posts/related` | GET | `get_related_posts_json` |
| `/create_post` | GET | `create_post` |
| `/post` | GET, POST | `post` |
| `/post/<slug>` | GET | `view_post` |
| `/api/posts/<post_id>/view` | POST | `api_record_post_view` |
| `/api/posts/<post_id>/status` | GET | `get_post_status` |
| `/edit_post/<post_id>` | GET | `edit_post` |
| `/update_post/<post_id>` | POST | `update_post` |
| `/delete_post/<post_id>` | POST | `delete_post` |
| `/post/<post_id>/react` | POST | `toggle_reaction_post` |
| `/post/<post_id>/toggle_save` | POST | `toggle_save_post` |
| `/post/<post_id>/share` | POST | `share_post` |
| `/api/post/<post_id>/share-data` | GET | `get_share_data` |
| `/api/posts/<slug>/comments` | GET, POST | `api_post_comments` |
| `/api/comments/<comment_id>` | DELETE, PUT/PATCH | `api_delete_comment`, `api_edit_comment` |
| `/api/comments/<comment_id>/vote` | POST | `api_vote_comment` |
| `/feed.xml` | GET | `feed` |
| `/share-target` | GET | `share_target` |
| `/api/notifications/unread-count` | GET | `get_unread_notification_count` |

**RQ jobs in this module:**

- `process_post_media(post_id_str, temp_image_paths, temp_video_path)` — `@rq.job`

**Template rendering:** `dashboard.html`, `home.html`, `blog.html`, `all_posts.html`, `view_post.html`, `edit_post.html`, `create_post.html`, `feed.xml`

**SocketIO events emitted:** `comment_posted`, `post_reacted`, `metrics_updated`

**Estimated lines:** ~2,000

---

### 10. blueprints/notes.py (~1,200 lines)

**Purpose:** Personal notes CRUD, sync, search, personal space, app lock.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/personal_space` | GET | `personal_space` |
| `/api/activity/mark_read` | POST | `api_mark_activity_read` |
| `/personal_post/create` | POST | `create_personal_post` |
| `/personal_post/create_json` | POST | `create_personal_post_json` |
| `/personal_post/search` | GET | `search_personal_notes` |
| `/personal_post/reindex_notes` | POST | `reindex_my_notes` |
| `/api/merge/ai` | POST | `merge_conflict_ai` |
| `/personal_post/edit/<post_id>` | POST | `edit_personal_post` |
| `/personal_post/sync/<post_id>` | POST | `sync_personal_post` |
| `/personal_post/delete/<post_id>` | POST | `delete_personal_post` |
| `/api/app_lock/setup` | POST | `app_lock_setup` |
| `/api/app_lock/verify` | POST | `app_lock_verify` |
| `/api/app_lock/remove` | POST | `app_lock_remove` |
| `/api/app_lock/relock` | POST | `app_lock_relock` |
| `/api/app_lock/check_status` | GET | `app_lock_check_status` |
| `/personal_post/toggle_lock/<post_id>` | POST | `toggle_note_lock` |

**Template rendering:** `personal_space.html`

**SocketIO events emitted:** `note_changed`, `note_proposal_created`, `note_auto_approved`

**Estimated lines:** ~1,200

---

### 11. blueprints/sharing.py (~900 lines)

**Purpose:** Note sharing links, shared note viewing, version history, collaborative proposals, note discussions, attachments. Plus socketio events for note collaboration.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/api/share/<share_id>/ping` | POST | `ping_collaborators` |
| `/personal_post/share/<post_id>` | POST | `api_create_share` |
| `/share/note/<share_id>` | GET, POST | `view_shared_note` |
| `/share/note/<share_id>/upload` | POST | `api_upload_note_attachment` |
| `/share/note/<share_id>/attachments` | GET | `api_list_note_attachments` |
| `/share/note/<share_id>/attachment/<aid>` | DELETE | `api_delete_note_attachment` |
| `/shared_note/save/<share_id>` | POST | `api_save_shared_note` |
| `/saved_note/view/<note_id>` | GET | `view_saved_note` |
| `/share/note/<share_id>/edit` | POST | `api_edit_shared_note` |
| `/personal_post/revoke_share/<share_id>` | POST | `api_revoke_share` |
| `/personal_post/toggle_share_auto_approve/<share_id>` | POST | `api_toggle_share_auto_approve` |
| `/personal_post/shares/<post_id>` | GET | `api_get_note_shares` |
| `/api/share/<share_id>/history` | GET | `api_get_share_history` |
| `/personal_post/versions/<post_id>` | GET | `api_get_note_versions` |
| `/personal_post/version/restore/<post_id>/<version_id>` | POST | `api_restore_note_version` |
| `/personal_post/proposal/<version_id>/decision` | POST | `api_decide_note_proposal` |
| `/share/note/<share_id>/comments` | GET, POST | `api_get_note_comments`, `api_post_note_comment` |
| `/share/note/<share_id>/comments/<cid>/replies` | POST | `api_post_note_reply` |
| `/share/note/<share_id>/comments/<cid>` | DELETE | `api_delete_note_comment` |

**SocketIO event handlers:**

- `join_note`, `leave_note`, `acquire_lock`, `release_lock`, `note_update`, `discussion_new_comment`

**Template rendering:** `shared_note.html`

**SocketIO events emitted:** `note_changed`, `note_proposal_created`, `note_auto_approved`, `presence_update`, `lock_status`, `lock_released`, `lock_acquired`, `lock_denied`, `discussion_updated`

**Estimated lines:** ~1,200

---

### 12. blueprints/chat.py (~1,200 lines)

**Purpose:** DM inbox, real-time messaging, DM requests, scheduled messages, message search/edit/delete, image/voice upload.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/messages` | GET | `messages_page` |
| `/api/messages/history/<other_user_id>` | GET | `api_message_history` |
| `/api/messages/upload_image` | POST | `api_upload_dm_image` |
| `/api/messages/upload_voice` | POST | `api_upload_dm_voice` |
| `/api/messages/react/<message_id>` | POST | `api_react_message` |
| `/api/messages/search/<other_user_id>` | GET | `api_search_messages` |
| `/api/messages/edit/<message_id>` | POST | `api_edit_message` |
| `/api/messages/delete/<message_id>` | POST | `api_delete_message` |
| `/api/messages/chat/delete/<other_user_id>` | POST | `api_delete_chat` |
| `/api/messages/unread_count` | GET | `api_unread_dm_count` |
| `/api/notifications/badge-counts` | GET | `get_badge_counts` |
| `/api/messages/request/<target_user_id>` | POST | `api_send_dm_request` |
| `/api/messages/request/<request_id>/accept` | POST | `api_accept_dm_request` |
| `/api/messages/request/<request_id>/reject` | POST | `api_reject_dm_request` |
| `/api/messages/requests` | GET | `api_list_dm_requests` |
| `/api/messages/dm_status/<target_user_id>` | GET | `api_dm_status` |
| `/api/messages/schedule` | POST | `api_schedule_message` |
| `/api/messages/scheduled/<other_user_id>` | GET | `api_list_scheduled_messages` |
| `/api/messages/schedule/<msg_id>/cancel` | POST | `api_schedule_cancel` |
| `/api/messages/schedule/<msg_id>/send-now` | POST | `api_schedule_send_now` |
| `/api/messages/schedule/process` | POST | `api_process_scheduled_messages` |

**SocketIO event handlers:**

- `join_inbox`, `send_dm`, `viewing_chat`, `leave_chat`, `disconnect`, `typing`, `stop_typing`

**Template rendering:** `messages.html`

**SocketIO events emitted:** `new_dm`, `message_confirmed`, `messages_read`, `user_typing`, `user_stop_typing`, `message_reacted`, `message_edited`, `message_deleted`, `chat_deleted`, `dm_request`, `dm_request_accepted`, `dm_error`, `presence_update`, `lock_released`

**Estimated lines:** ~1,500

---

### 13. blueprints/communities.py (~700 lines)

**Purpose:** Community CRUD, joining, community notes, reactions, reporting.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/communities` | GET | `communities_page` |
| `/community/<community_id>` | GET | `view_community` |
| `/api/community/create` | POST | `api_create_community` |
| `/community/join/<invite_code>` | GET | `join_community_link` |
| `/api/community/join` | POST | `api_join_community_code` |
| `/api/community/<community_id>/join-public` | POST | `api_join_public_community` |
| `/api/community/<community_id>/settings` | POST | `api_update_community` |
| `/api/community/<community_id>/regenerate-invite` | POST | `api_regenerate_invite` |
| `/api/community/<community_id>/leave` | POST | `api_leave_community` |
| `/api/community/<community_id>/remove-member` | POST | `api_remove_member` |
| `/api/community/<community_id>/note/create` | POST | `api_create_community_note` |
| `/api/community/note/<note_id>/react` | POST | `api_react_community_note` |
| `/api/community/note/<note_id>/delete` | POST | `api_delete_community_note` |
| `/share/community-note/<share_id>` | GET | `view_shared_community_note` |
| `/api/community/note/<note_id>/save` | POST | `api_save_community_note` |
| `/api/community/<community_id>/report` | POST | `api_report_community` |

**Template rendering:** `communities.html`, `community_space.html`, `shared_note.html`

**Estimated lines:** ~800

---

### 14. blueprints/admin.py (~1,000 lines)

**Purpose:** Admin dashboard, metrics, user management, posts management, announcements, communities admin, system health, reindexing, CSV export, APK upload.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/admin/dashboard` | GET | `admin_dashboard` |
| `/admin/upload_apk` | POST | `admin_upload_apk` |
| `/admin/metrics` | GET | `admin_metrics` |
| `/admin/active_users` | GET | `admin_active_users` |
| `/admin/export_csv` | GET | `admin_export_csv` |
| `/admin/traffic` | GET | `admin_traffic` |
| `/admin/system_health` | GET | `admin_system_health` |
| `/admin/reindex_typesense` | POST | `admin_reindex_typesense` |
| `/admin/reindex_notes_typesense` | POST | `admin_reindex_notes_typesense` |
| `/admin/posts` | GET | `admin_posts` |
| `/admin/delete_post/<post_id>` | POST | `admin_delete_post` |
| `/admin/posts/pin/<post_id>` | POST | `admin_pin_post` |
| `/admin/posts/unpin/<post_id>` | POST | `admin_unpin_post` |
| `/admin/announcements` | GET, POST | `admin_announcements` |
| `/admin/push/send` | POST | `admin_send_push` |
| `/admin/announcements/pin/<aid>` | POST | `pin_announcement` |
| `/admin/announcements/unpin/<aid>` | POST | `unpin_announcement` |
| `/admin/announcements/delete/<aid>` | POST | `delete_announcement` |
| `/admin/premium_users` | GET | `admin_premium_users` |
| `/admin/premium/grant/<user_id>` | POST | `grant_premium` |
| `/admin/premium/revoke/<user_id>` | POST | `revoke_premium` |
| `/admin/users` | GET | `admin_users` |
| `/admin/users/ban/<user_id>` | POST | `ban_user` |
| `/admin/users/unban/<user_id>` | POST | `unban_user` |
| `/admin/users/delete/<user_id>` | POST | `delete_user` |
| `/admin/communities` | GET | `admin_communities` |
| `/api/admin/community/<cid>/ban` | POST | `api_admin_ban_community` |
| `/api/admin/community/<cid>/unban` | POST | `api_admin_unban_community` |
| `/api/admin/community/<cid>/delete` | POST | `api_admin_delete_community` |
| `/api/admin/community/<cid>/reports` | GET | `api_admin_community_reports` |
| `/api/admin/reports/<rid>/dismiss` | POST | `api_admin_dismiss_report` |

**RQ jobs in this module:**

- `reindex_typesense_job()` — `@rq.job`

**Template rendering:** `admin_dashboard.html`, `admin_posts.html`, `admin_users.html`, `admin_premium_users.html`, `admin_announcements.html`, `admin_communities.html`

**Estimated lines:** ~1,200

---

### 15. blueprints/profile.py (~300 lines)

**Purpose:** Profile view, settings, data export, account deletion.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/profile/<username>` | GET | `profile` |
| `/profile/<username>/posts` | GET | `user_posts_page` |
| `/profile/<username>/settings` | GET, POST | `profile_settings` |
| `/profile/<username>/export_data` | POST | `export_data` |
| `/profile/<username>/delete_account` | POST | `delete_account` |

**Template rendering:** `profile.html`, `user_posts.html`, `profile_settings.html`

**Estimated lines:** ~400

---

### 16. blueprints/payments.py (~200 lines)

**Purpose:** Paystack payment processing.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/api/paystack/initialize` | POST | `paystack_initialize` |
| `/paystack/callback` | GET | `paystack_callback` |
| `/api/paystack/webhook` | POST | `paystack_webhook` |

**Estimated lines:** ~200

---

### 17. blueprints/pages.py (~500 lines)

**Purpose:** Static pages, sitemap, robots.txt, contact, newsletter, RSS, favicon, APK download, update manifest, assetlinks, service worker, quote API, user/tag suggestions.

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/offline` | GET | `offline` |
| `/about` | GET | `about` |
| `/terms` | GET | `terms` |
| `/faq` | GET | `faq` |
| `/contact` | POST | `contact_developer` |
| `/api/quote` | GET | `get_quote_api` |
| `/search` | GET | `search` |
| `/download/note-app.apk` | GET | `download_note_app_apk` |
| `/static/update-manifest.json` | GET | `serve_update_manifest` |
| `/.well-known/assetlinks.json` | GET | `android_assetlinks` |
| `/service-worker.js` | GET | `service_worker` |
| `/favicon.ico` | GET | `favicon` |
| `/unsubscribe/<email>/<token>` | GET, POST | `unsubscribe` |
| `/api/newsletter/subscribe` | POST | `api_newsletter_subscribe` |
| `/sitemap_index.xml` | GET | `sitemap_index` |
| `/sitemap.xml` | GET | `sitemap_legacy_redirect` |
| `/robots.txt` | GET | `robots` |
| `/api/admin/clear-sitemap-cache` | POST | `api_clear_sitemap_cache` |
| `/api/ai/suggest-tags` | POST | `api_suggest_tags` |
| `/api/users/suggest` | GET | `api_user_suggest` |
| `/uploads/<filename>` | GET | `uploaded_file` |

**Template rendering:** `offline.html`, `about.html`, `terms.html`, `faq.html`, `search_results.html`, `unsubscribe_result.html`

**Estimated lines:** ~600

---

### 18. blueprints/push.py (~120 lines)

**Purpose:** Push notification subscription management (Web Push + FCM).

**Routes:**
| Route | Methods | Handler |
|-------|---------|---------|
| `/api/push/vapid-public-key` | GET | `get_vapid_public_key` |
| `/api/push/subscribe` | POST | `subscribe_push` |
| `/api/push/unsubscribe` | POST | `unsubscribe_push` |
| `/api/push/status` | GET | `push_subscription_status` |
| `/api/fcm/register` | POST | `register_fcm_token` |
| `/api/fcm/unregister` | POST | `unregister_fcm_token` |

**Estimated lines:** ~120

---

## Circular Import Risk Analysis

**Risk 1: utils.py → typesense_client.py → utils.py**

- utils.py uses `_t` (typesense client singleton) for indexing functions
- typesense_client.py is a standalone module with no imports from the project
- **Resolution:** No risk. typesense_client imports nothing from the project.

**Risk 2: Blueprints → notifications.py → Blueprints**

- Blueprints trigger notifications when posts/comments are created
- notifications.py is pure utility functions, does not import from blueprints
- **Resolution:** No risk.

**Risk 3: app.py imports all blueprints; blueprints need app.py imports**

- Blueprints import from shared modules (database, utils, security, etc.), not from app.py
- app.py only creates the app and registers blueprints
- **Resolution:** No risk. Blueprints never import from app.py.

**Risk 4: socketio in database.py vs blueprints that use socketio.emit**

- `socketio` object is created in app.py (needs app instance)
- Blueprints use `socketio.emit()` for real-time events
- Need to ensure socketio is importable by blueprints
- **Resolution:** Import socketio from app.py in blueprints. Since app.py registers blueprints AFTER creating socketio, and Python module imports are cached, this works. Alternatively, store socketio on a shared module (e.g., make database.py hold it). Let's put socketio on app.py and import `from app import socketio` in blueprints — this is a common Flask-SocketIO pattern.

Actually, this IS a circular risk: app.py imports blueprints, blueprints import socketio from app.py. Python resolves module-level imports correctly if app.py registers blueprints after socketio is created (not at import time, but at function-call time). In practice:

- `from app import socketio` in a blueprint
- app.py does `socketio = SocketIO(app)` before `app.register_blueprint(auth_bp)`
- When the blueprint module is first imported, `app` module is loaded and `socketio` is available
- **Works fine.**

**Risk 5: api.py (existing blueprint) imports from main via get_main_globals()**

- api.py currently does `def get_main_globals(): import main; return main`
- After refactoring, api.py needs to import from new shared modules instead
- **Resolution:** Update api.py imports to use new modules (database, utils, security, models, notifications). Remove the lazy import pattern. This is a breaking change only for api.py, which we control.

---

## Dead Code Removal List

Symbols classified as DEAD after full project scan:

| Line | Symbol                   | Reason                                                                    |
| ---- | ------------------------ | ------------------------------------------------------------------------- |
| TBD  | `fix_template_syntax.py` | Utility script, never imported/called by any production code or scheduler |

Additional dead symbols will be identified in Phase 3 after exhaustive cross-reference scan.

---

## Special Care Symbols

| Symbol                                       | Location | Care Needed                                                                                                                                                                                          |
| -------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| All `@rq.job` functions                      | main.py  | RQ discovers jobs by function reference. Keep original qualified names or ensure RQ is configured to discover from new modules. Functions must remain importable from where RQ worker resolves them. |
| `get_main_globals()` in api.py               | api.py   | Must be updated to import from new shared modules directly. This is a DYNAMIC pattern being replaced.                                                                                                |
| `@socketio.on` handlers                      | main.py  | Must be registered on the same `socketio` instance. After moving to blueprints, use `@socketio.on` importing socketio from app.py.                                                                   |
| `@login_manager.user_loader`                 | main.py  | Must be registered on the same `login_manager` instance. Will be registered in app.py using import from models.py.                                                                                   |
| `@login_manager.request_loader`              | main.py  | Same as above.                                                                                                                                                                                       |
| `@app.template_filter`                       | main.py  | Must be registered on the app. Will be done in app.py using imported filter functions from utils.py.                                                                                                 |
| `@app.before_request` / `@app.after_request` | main.py  | Must be registered on the app. Will stay in app.py.                                                                                                                                                  |
| `@app.context_processor`                     | main.py  | Must be registered on the app. Will stay in app.py.                                                                                                                                                  |
| `@app.errorhandler`                          | main.py  | Must be registered on the app. Will stay in app.py.                                                                                                                                                  |
| `wsgi.py`                                    | root     | `from main import app` → must update to `from app import app`                                                                                                                                        |
| `scheduler.py` subprocess calls              | scripts/ | Paths change from `os.path.dirname(__file__)` — update references when moving to scripts/ folder                                                                                                     |

---

## Scripts Directory Migration

The following standalone scripts will be moved from `echowithin/` root to `echowithin/scripts/`:

1. `scheduler.py` → `scripts/scheduler.py`
2. `worker.py` → `scripts/worker.py`
3. `process_scheduled_messages.py` → `scripts/process_scheduled_messages.py`
4. `weekly_achievements.py` → `scripts/weekly_achievements.py`
5. `backup_to_atlas.py` → `scripts/backup_to_atlas.py`
6. `cleanup_expired_auth.py` → `scripts/cleanup_expired_auth.py`
7. `schedule_log_email.py` → `scripts/schedule_log_email.py`
8. `send_weekly_newsletter.py` → `scripts/send_weekly_newsletter.py`

**Update needed in scheduler.py:** The script uses `os.path.dirname(__file__)` to resolve paths to child scripts. After moving to `scripts/`, the child scripts will be in the same directory, so path resolution remains correct (`os.path.join(os.path.dirname(__file__), 'send_weekly_newsletter.py')` still works since the files are siblings in `scripts/`).

**Update needed in Procfile / docker-compose:** If the Procfile or docker-compose references paths like `python scheduler.py`, they must be updated to `python scripts/scheduler.py`.

---

## Line Count Estimates

| Module                    | Est. Lines         |
| ------------------------- | ------------------ |
| config.py                 | 150                |
| database.py               | 100                |
| security.py               | 250                |
| utils.py                  | 800                |
| notifications.py          | 500                |
| models.py                 | 100                |
| app.py                    | 300                |
| blueprints/auth.py        | 450                |
| blueprints/blog.py        | 2,000              |
| blueprints/notes.py       | 1,200              |
| blueprints/sharing.py     | 1,200              |
| blueprints/chat.py        | 1,500              |
| blueprints/communities.py | 800                |
| blueprints/admin.py       | 1,200              |
| blueprints/profile.py     | 400                |
| blueprints/payments.py    | 200                |
| blueprints/pages.py       | 600                |
| blueprints/push.py        | 120                |
| typesense_client.py       | 294 (unchanged)    |
| api.py                    | 1,200+ (unchanged) |
| **Total new/extracted**   | **~12,364**        |
| **main.py before**        | **14,135**         |
| **app.py after**          | **~300**           |

---

## Extraction Order (lowest layer first)

1. `scripts/` directory creation + script moves
2. `config.py`
3. `database.py`
4. `security.py`
5. `utils.py` 
6. `notifications.py`
7. `models.py`
8. `typesense_client.py` (no change, just verify)
9. `api.py` (update imports, no structural change)
10. `blueprints/pages.py` (fewest dependencies)
11. `blueprints/push.py`
12. `blueprints/auth.py`
13. `blueprints/payments.py`
14. `blueprints/profile.py`
15. `blueprints/blog.py`
16. `blueprints/notes.py`
17. `blueprints/sharing.py`
18. `blueprints/chat.py`
19. `blueprints/communities.py`
20. `blueprints/admin.py`
21. `app.py` (final wiring)
22. Update `wsgi.py` import
