# DISCOVERY.md — EchoWithin Platform Full Audit (Regenerated)

Generated: 2026-08-02 | Architecture: Blueprint-split monolith (post-refactor) | Deployed: https://echowithin.xyz

This document replaces the 2026-05-29 discovery (which described the pre-refactor single-file monolith at main.py 14,135 lines). The codebase has since been split into 13 Flask blueprints plus a mobile API blueprint. All line references below were verified by full file reads during this audit pass.

---

## 1. Stack Inventory

### 1.1 Runtime / Web Layer

- **Python 3.12+** (`Dockerfile` uses `python:3.12-slim`; host runs 3.13)
- **Flask 3.1.2**, app factory in `main.py:182`, extensions: Flask-SocketIO 5.3.6, Flask-Login, Flask-WTF (CSRFProtect `main.py:183`), Flask-RQ2 (`main.py:484`)
- **WSGI:** gunicorn, single worker, geventwebsocket worker class (`Procfile:1`) + `honcho start`
- **Reverse proxy:** ProxyFix `x_for/x_proto/x_host/x_prefix=1` (`main.py:314`)
- **Processes (`Procfile`):** `web` (gunicorn gevent + socketio), `worker` (RQ `scripts/worker.py`), `scheduler` (APScheduler `scripts/scheduler.py`)

### 1.2 Blueprint layout (all registered `main.py:186-199`)

| Blueprint   | File                        | Approx. lines | Function                                                                                                  |
| ----------- | --------------------------- | ------------- | --------------------------------------------------------------------------------------------------------- |
| pages       | `blueprints/pages.py`       | 447           | Landing, search, sitemaps, RSS, APK/SW serving, newsletter                                                |
| auth        | `blueprints/auth.py`        | 945           | Register/login/logout/confirm, Google OAuth, sessions, mobile OTLT                                        |
| push        | `blueprints/push.py`        | 243           | FCM + Web Push subscribe/unsubscribe, unread counts                                                       |
| payments    | `blueprints/payments.py`    | 156           | Paystack premium/donation                                                                                 |
| profile     | `blueprints/profile.py`     | 355           | Public profile, settings, export, delete account                                                          |
| blog        | `blueprints/blog.py`        | 2069          | Public posts/feed/comments/reactions/shares, uploads route                                                |
| notes       | `blueprints/notes.py`       | 1532          | Encrypted personal notes, co-editing, proposals, versions                                                 |
| sharing     | `blueprints/sharing.py`     | 1528          | Share links, collaborators, permissions, ping                                                             |
| chat        | `blueprints/chat.py`        | 850           | DM page, scheduled messages, aggregation queries                                                          |
| communities | `blueprints/communities.py` | 1532          | Communities, notes, challenges, polls, resources, check-ins                                               |
| admin       | `blueprints/admin.py`       | 804           | Admin console: APK publish, moderation, premium, bans                                                     |
| whisper     | `blueprints/whisper.py`     | 649           | Ephemeral timed conversations (TTL-deleted)                                                               |
| bonds       | `blueprints/bonds.py`       | 4131          | Partner "Bond" system (goals/journal/mood/qotd/habits/countdowns/album/bucketlist/recommendations/pulses) |
| **api_v1**  | `api.py`                    | 1807          | Mobile REST API (`/api/v1`, CSRF-exempt)                                                                  |

### 1.3 Database Layer

- **MongoDB** (`echowithin_db`) via PyMongo 4.15.4; `main.py:543-551` (maxPoolSize=20, minPoolSize=4)
- **38 collections** (`database.py`): users, posts, logs, auth, announcements, comments, personal_posts, note_shares, note_versions, note_discussions, push_subscriptions, fcm_tokens, direct_messages, newsletter_subs, user_post_views, unlock_notifications, weekly_winners, app_tokens, user_sessions, app_updates, communities, community_notes, community_reactions, community_reports, community_challenges, community_poll_votes, community_checkins, dm_permissions, scheduled_messages, note_attachments, activities, comment_votes, whisper_sessions, whisper_messages, bonds, bond_goals/journal/moods/qotd/habits/countdowns/album_photos/bucketlist/recommendations/pulses, community_questions
- TTL indexes: whisper messages/sessions (`main.py:690-694`), app tokens 90d (`main.py:801`), auth codes, user_sessions 30d
- **Redis:** caching, session/decryption cache, rate-limit debounce; URL built `main.py:478`; falls back to in-memory if unavailable (`main.py:505`)
- **Typesense:** post + note full-text search (note plaintext indexed — see Privacy section)
- **Cloudinary:** post images, album photos, resources, media encryption-at-rest (encrypted bytes uploaded as opaque assets)
- **Firebase Admin (FCM)** + **Web Push (VAPID)** for notifications

### 1.4 Authentication Model

- Flask-Login dual loaders: `user_loader` (`models.py:76-101`, 30s cache) + `request_loader` (`models.py:104-166`) accepting `X-App-Token` header, `Authorization: Bearer`, or `x_app_token` httpOnly cookie (secure, SameSite=Lax, 90d)
- Password hashing: Werkzeug `generate_password_hash` (scrypt) at `auth.py:154`, `api.py:51`; PINs hashed in `notes.py`
- Email verification: 6-digit codes, SHA-256 at rest, 24h expiry, constant-time compare on web (`auth.py:209`) but plain `==` on mobile (`api.py:107`)
- Sessions: `user_sessions` collection + login-activity feature (`auth.py`), session-token validation via `before_app_request`
- SocketIO auth = Flask session cookie during WS handshake (no connect handler, no token in query string); `authenticated_only` decorator `main.py:1393`

---

## 2. Encryption Architecture (server-side, at-rest)

**Model:** server-side encryption with server-held keys — NOT end-to-end. Anyone with `SECRET_KEY` (or a DB dump + key) can decrypt all user content. v3 envelope adds defense-in-depth against DB-only breach.

| Data                  | Key scheme                                                                | Version | Ref                   |
| --------------------- | ------------------------------------------------------------------------- | ------- | --------------------- |
| Notes (global legacy) | PBKDF2(SECRET_KEY, fixed salt `echowithin_notes_salt_v1`, 100k)           | v1      | `security.py:164-175` |
| Notes                 | PBKDF2(SECRET_KEY, salt `echowithin_notes_v2_{user_id}`, 480k)            | v2      | `security.py:180-191` |
| Notes                 | PBKDF2(DEK, per-user random salt, 480k); DEK wrapped by KEK               | v3      | `security.py:422-481` |
| DMs                   | PBKDF2(SECRET_KEY, salt `echowithin_dm_v1_{conv_id}`, 480k)               | v2      | `security.py:566-582` |
| DMs                   | DEK per conversation (random), wrapped by KEK, stored in `dm_permissions` | v3      | `security.py:497-552` |
| Bonds                 | PBKDF2(SECRET_KEY, salt `echowithin_bonds_v1_{bond_id}`, 480k)            | —       | `security.py:209-246` |
| Community notes       | PBKDF2(SECRET_KEY, salt community_id, 480k)                               | —       | `security.py:886-947` |
| Media bytes           | Single global key PBKDF2(SECRET_KEY, salt `echowithin_media_at_rest_v1`)  | —       | `security.py:306-337` |
| KEK                   | PBKDF2(SECRET_KEY, salt `echowithin_kek_v1`) wraps all v3 DEKs            | —       | `security.py:408-449` |

- KDF: PBKDF2-HMAC-SHA256, `_NOTES_KDF_ITERATIONS = 480000` (`config.py:77`)
- Decryption chains fall back v3 → v2 → v1 → **legacy plaintext passthrough** (`security.py:243, 617, 668, 713`)
- Keys derived on demand (never stored); derived Fernets cached in memory TTL (1h); **decrypted note plaintext cached in Redis 5-min TTL** (`security.py:829-841`)
- Media served via HMAC-signed capability URLs (`build_media_serve_url`, 15-min expiry, 128-bit truncated signature `security.py:340-376`)
- Migration/rotation: `scripts/rotate_secret_key.py`, `migrate_to_v3.py`, `scripts/encrypt_plaintext_fields.py`

---

## 3. Subsystem Summaries

### 3.1 Notes (`blueprints/notes.py`) + Sharing (`blueprints/sharing.py`)

Encrypted personal notes with markdown, tags, references; surprise notes; lock/PIN notes (hashed PINs); versions; merge-proposal flow (collaborator saves push a proposal to the original owner via SocketIO room + push notification; owner direct-push path version-snapshots). Share links with permission levels (read-only/collaborate) and optional expiration. `ping_collaborators` has Redis/session cooldown. Server decrypts on read.

### 3.2 Blog (`blueprints/blog.py`)

Public posting platform: feeds (personalized via interest scoring), posts with Cloudinary media + NSFW queue, threaded comments with votes/edit/delete, reactions, saves, shares, view tracking, RSS/JSON-LD SEO. XSS sanitized via `bleach` allowlists (`blog.py:993, 1166-1172`, `utils.py:248-270`). **Anonymous post views fingerprinted and stored by raw IP** (`blog.py:1368`). Full public read access by design.

### 3.3 Messages (`blueprints/chat.py`) + Whisper (`blueprints/whisper.py`)

DMs encrypted at rest (v2/v3 pair keys), SocketIO real-time delivery, scheduled messages (`X-Scheduler-Secret` internal endpoint), DM privacy settings (`nobody` gate). Whisper = ephemeral timed conversations; messages actually deleted via app-level `delete_many` + TTL index (`main.py:694`); session docs TTL-purged 24h after expiry. **System metadata messages persist in the DM thread as plaintext** (`whisper.py:37`).

### 3.4 Communities (`blueprints/communities.py`)

User-created communities (invite codes, public/private, member management); encrypted community notes with surprise themes/media, reactions, save-to-personal; admin-only challenges/polls; encrypted resource uploads (Cloudinary signed downloads); daily mood check-ins; welcome messages; reporting flow. Voucher codes grant premium on join. **Several endpoints lack membership checks** (see Investigation findings).

### 3.5 Bonds (`blueprints/bonds.py` — largest feature)

Two-person partnership system: request/accept/break lifecycle (3-day break cooldown), goals, shared journal, mutual-reveal mood tracker, daily QotD (deterministic + AI-generated via Gemini/JigsawStack + community bank), habits, countdowns, shared photo album (encrypted-at-rest Cloudinary + local plaintext fallback), bucket list, media recommendations, pulses. Consistent `_is_bond_participant` authorization on all 52 endpoints (no IDOR found). AI QotD sends decrypted recent QotD content to Gemini/JigsawStack.

### 3.6 Admin (`blueprints/admin.py`)

All routes `@login_required + @admin_required` (`security.py:960-972`, audit-logged). OTA APK publishing (no signature/hash validation), post moderation, announcements + broadcast push, premium grant/revoke, voucher minting, user ban/delete, community ban/delete, report review, metrics/traffic/health dashboards. `is_admin` is a plain boolean flag on the user doc.

### 3.7 Payments (`blueprints/payments.py`)

Paystack premium subscriptions + donations. Webhook HMAC-verified (but timing-unsafe string compare). Callback + webhook both grant premium. **No ownership check on callback; no idempotency; amount not re-verified** (see Investigation findings).

### 3.8 Mobile API (`api.py`)

37 REST endpoints for the native Android app (Capacitor-based, repo external). Dual session/token auth; entire blueprint CSRF-exempt (`main.py:234`). Note CRUD (server-side decryption), shares, versions, proposals, app lock (4-digit PIN), FCM registration, premium activation, sync. **`POST /premium/activate` grants premium with no payment check.**

### 3.9 Push (`blueprints/push.py`) / Notifications (`notifications.py`)

FCM (Android) + VAPID Web Push subscriptions; unread badge counts; notification collapse. **Push bodies carry decrypted user content to third-party push infrastructure** (Google FCM / Web Push service) — e.g., bond titles, pulse messages, DM previews.

---

## 4. Security Baseline (verified positives)

- CSRFProtect global (`main.py:183`); tight exemption list (`main.py:234-243`) — entire `api_v1` blueprint, confirm, app_reauth, push subscribe/unsubscribe, paystack webhook, internal scheduler endpoint, two notes/chat helpers
- Session cookies: HttpOnly, Secure, SameSite=Lax, 14d (`main.py:361-377`)
- Security headers: X-Frame-Options, nosniff, XSS-protection, Referrer-Policy, Permissions-Policy, HSTS (secure requests only), CSP (`main.py:1102-1168`) — **CSP script-src defaults to `'unsafe-inline'`** unless `CSP_STRICT_NONCES` set; strict nonce infra exists (`main.py:266-268, 1125-1134`)
- Constant-time compares used in most token checks; `is_same_origin_request()` (`security.py:44-63`) for service-worker JSON endpoints — **returns True when Origin/Referer absent**
- No MongoDB operator injection found across blueprints (user input never reaches query dicts as operator keys); object IDs via `safe_obj_id`; admin regex search is the one exception (`admin.py:434-438`, unescaped `$regex`)
- Media uploads: extension-only validation, size caps mostly present, Cloudinary path encrypted; **local-fallback path writes plaintext to public `static/uploads/` and never cleans up**
- Whisper messages genuinely TTL-deleted; guest data purged on expiry
- SSRF protection for link previews (`utils.py:863-887`); no user-controlled server-side fetches

---

## 5. Preliminary Concern Register (expanded in Investigation Phase)

| #   | Area                | Concern                                                                                                                             | Ref                                                                            |
| --- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 1   | Payments            | Free premium via `/api/v1/premium/activate` (no payment check)                                                                      | `api.py:460-474`                                                               |
| 2   | Payments            | Callback upgrades logged-in user w/o verifying transaction ownership; no idempotency (repeat re-grant); amount unverified           | `payments.py:78-117, 146-152`                                                  |
| 3   | Rate limiting       | `ratelimit` lib uses a single global counter per function — not per-IP; cross-user 429 DoS (login/register); only 1 gunicorn worker | `security.py:139-145`, `api.py:23,115`                                         |
| 4   | Communities         | Missing membership checks on save-note / vote-poll / react-note → outsiders read private notes                                      | `communities.py:684, 910, 1161`                                                |
| 5   | Supply chain        | `update-manifest.json` + `app-debug.apk` public, unsigned, no hash/integrity; debug-signed APK                                      | `pages.py:244-260`, `admin.py:42-69`                                           |
| 6   | Encryption          | Single `SECRET_KEY` derives v1/v2/DM-v2/bond/media/community/KEK; leak + DB dump = full plaintext                                   | `security.py`                                                                  |
| 7   | Privacy             | Decrypted note plaintext cached in Redis + indexed into Typesense + cached in SW Cache Storage                                      | `security.py:837-841`, `utils.py:66-79`, `service-worker.js:128-151`           |
| 8   | Privacy             | Push notifications transmit decrypted content to Google/FCM/WebPush; AI QotD sends decrypted content to Gemini/JigsawStack          | `bonds.py:443, 2291, 4069`                                                     |
| 9   | Privacy             | Anonymous post-view IP fingerprinting in `logs_conf`; admin traffic returns top IPs; newsletter stores IP                           | `blog.py:1368`, `admin.py:174`, `pages.py:441`                                 |
| 10  | Auth                | 6-digit email code: no attempt limit on mobile confirm, plain `==` compare, unsalted SHA-256 at rest                                | `api.py:80-112, 48`                                                            |
| 11  | Auth                | App-lock 4-digit PIN verify: no throttle, CSRF-exempt                                                                               | `api.py:495-515`                                                               |
| 12  | Admin               | Regex injection in premium-users search (unescaped `$regex`)                                                                        | `admin.py:434-438`                                                             |
| 13  | Deletion            | `delete_account` leaves blog posts, comments, whisper data, IP logs, activities; admin `delete_user` even less thorough             | `profile.py:326-350`, `admin.py:585-601`                                       |
| 14  | Whisper             | Extension can be self-approved by requester (no consent); only tier cap limits                                                      | `whisper.py:417-447`                                                           |
| 15  | Perf                | N+1 queries + uncached per-record decryption loops; unbounded full-collection scans                                                 | `bonds.py`, `api.py:200-264, 1213-1560`, `blog.py:599, 896`, `push.py:179-234` |
| 16  | Media               | Local-storage fallback writes plaintext media to public route, never deleted; album upload memory DoS (unbounded files/request)     | `bonds.py:3287-3294, 3242-3274`                                                |
| 17  | Socket              | `join_note`/`note_update` don't verify share authorization — possession of `share_id` + any auth = plaintext note stream            | `main.py:1403, 1497`                                                           |
| 18  | Media proxy         | `mime` query param served verbatim, no Content-Disposition → stored-XSS vector via HTML served from canonical origin                | `main.py:202-231`                                                              |
| 19  | CSP                 | `'unsafe-inline'` scripts by default; strict nonce off unless env set                                                               | `main.py:1136-1138`                                                            |
| 20  | Account enumeration | Register/confirm/login distinguish username-taken / email-exists / Google-account / wrong-details                                   | `api.py:38-52, 89, 112, 131, 178`                                              |

---

## 6. Recommended Next Steps (Phase 2)

1. **2A Security:** validate findings 1-6, 10-12, 14, 17-19 with reproduction analysis; check share/permission checks in `notes.py`/`sharing.py` (not yet line-audited for IDOR); verify `app_tokens` storage/revocation; confirm `is_admin` escalation paths.
2. **2B Speed:** quantify N+1 + decryption-loop hotspots; index coverage for album sort modes; unbounded scans; Typesense/Redis cache effectiveness.
3. **2C Privacy:** document the server-trust encryption model; third-party data flows (Typesense, Gemini, JigsawStack, FCM/WebPush, Cloudinary, Paystack, ip-api.com geolocation); data retention gaps (logs, backups, orphaned uploads); GDPR-style deletion completeness.
4. **Phase 3:** severity-ordered findings table + remediation roadmap.
