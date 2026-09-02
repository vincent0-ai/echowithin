# DISCOVERY.md — EchoWithin Platform Full Audit (Regenerated 2026-09-02)

Generated: 2026-09-02 08:00 UTC | Architecture: Blueprint-split monolith (post-refactor) | Deployed: https://echowithin.xyz
Previous generation: 2026-08-02 (line refs shifted +40-50 due to inserts). This refresh re-verifies all claims.

---

## 1. Stack Inventory

### 1.1 Runtime / Web Layer

- **Python 3.12+** — `Dockerfile:1` `FROM python:3.12-slim`; host may run 3.13
- **Flask 3.1.2** (`requirements.txt:21`), extensions: Flask-SocketIO 5.3.6 (`requirements.txt:87`), Flask-Login 0.6.3 (`:22`), Flask-WTF 1.2.2 (`:24`), Flask-RQ2 18.3 (`:25`), Flask-Mail, pywebpush, firebase-admin
- **WSGI:** gunicorn single worker geventwebsocket (`Procfile:1` `GeventWebSocketWorker -w 1 --timeout 120`) + `honcho start` (`Dockerfile:10`, `captain-definition:13`)
- **Reverse proxy:** ProxyFix `x_for/x_proto/x_host/x_prefix=1` (`main.py:349`)
- **Processes (`Procfile:1-3`):** `web` (gunicorn+gevent+socketio), `worker` (`scripts/worker.py`), `scheduler` (`scripts/scheduler.py`)
- **App factory:** `main.py:183` `app = Flask(__name__)`, `main.py:184` `CSRFProtect(app)`, `main.py:532` `RQ(app)`, `main.py:344` `SocketIO(cors_allowed_origins=_ALLOWED_ORIGINS, async_mode='gevent')` with `main.py:550` Redis message queue or `main.py:555` fallback

### 1.2 Blueprint layout (registered `main.py:187-200`)

| Blueprint   | File                        | Lines (wc -l 2026-09-02) | Function                                                                                                  |
| ----------- | --------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------- |
| pages       | `blueprints/pages.py`       | 453                      | Landing, search, sitemaps, RSS, APK/SW serving, newsletter                                                |
| auth        | `blueprints/auth.py`        | 1019                     | Register/login/logout/confirm, Google OAuth, sessions, mobile OTLT, honeypot                              |
| push        | `blueprints/push.py`        | 277                      | FCM + Web Push subscribe/unsubscribe, unread counts                                                       |
| payments    | `blueprints/payments.py`    | 246                      | Paystack premium/donation                                                                                 |
| profile     | `blueprints/profile.py`     | 426                      | Public profile, settings, export, delete account                                                          |
| blog        | `blueprints/blog.py`        | 2274                     | Public posts/feed/comments/reactions/shares, uploads, moderation                                          |
| notes       | `blueprints/notes.py`       | 1869                     | Encrypted personal notes, co-editing, proposals, versions                                                 |
| sharing     | `blueprints/sharing.py`     | 1875                     | Share links, collaborators, permissions, ping                                                             |
| chat        | `blueprints/chat.py`        | 1001                     | DM page, scheduled messages, aggregation queries                                                          |
| communities | `blueprints/communities.py` | 1602                     | Communities, notes, challenges, polls, resources, check-ins                                               |
| admin       | `blueprints/admin.py`       | 1022                     | Admin console: APK publish (hash-aware), moderation, premium, bans                                        |
| whisper     | `blueprints/whisper.py`     | 681                      | Ephemeral timed conversations (TTL-deleted)                                                               |
| bonds       | `blueprints/bonds.py`       | 5577                     | Partner "Bond" system (goals/journal/mood/qotd/habits/countdowns/album/bucketlist/recommendations/pulses) |
| **api_v1**  | `api.py`                    | 1927                     | Mobile REST API (`/api/v1`, CSRF-exempt `main.py:255`)                                                    |
| **core**    | `main.py`                   | 2296                     | App wiring, media proxy, socket handlers, indexes, guest purge                                            |

Growth since 2026-08-02: all counts up; worst `bonds` +1446 (album On This Day/Slideshow), `sharing` +347, `notes` +337, `admin` +218.

### 1.3 Database Layer

- **MongoDB** (`echowithin_db`) via PyMongo 4.15.4 (`requirements.txt:52`); `main.py:592-599` (maxPoolSize=20, minPoolSize=4, serverSelectionTimeoutMS=5000)
- **55 collections** (`main.py:601-808` `db['…']`; `database.py:4-76` declares 47 placeholders — 8 new since Aug):
  `users`, `posts`, `logs`, `auth`, `announcements`, `comments`, `personal_posts`, `note_shares`, `note_versions`, `note_discussions`, `push_subscriptions`, `fcm_tokens`, `direct_messages`, `newsletter_subs`, `user_post_views`, `unlock_notifications`, `weekly_winners`, `app_tokens`, `user_sessions`, `app_updates`, `communities`, `community_notes`, `community_reactions`, `community_reports`, `post_reports` (`main.py:693` — new `975ac8b`), `community_challenges`, `community_polls` (`:695`), `community_poll_votes` (`:696`), `community_resources` (`:697`), `community_checkins` (`:698`), `community_premium_vouchers` (`:699`), `community_memberships` (`:700`), `dm_permissions` (`:708`), `scheduled_messages` (`:713`), `note_attachments` (`:718`), `activities` (`:726`), `activity_read` (`:735`), `comment_votes` (`:722`), `whisper_sessions` (`:740`), `whisper_messages` (`:745`), `bonds` (`:750`), `bond_goals/journal/moods/qotd/habits/countdowns/album_photos/bucketlist/recommendations/pulses` (`:756-789`), `community_questions` (`:792`), `hidden_chats` (`:797`), `deleted_items` (`:800`), `payment_grants` (`:804`)
- **TTL indexes:** whisper messages/sessions (`main.py:743,747`), app tokens 90d (`:859`), auth codes, user_sessions 30d (`:625`), deleted_items (`:801`)
- **Redis:** caching, session/decryption cache, rate-limit debounce; URL `main.py:519`; falls back to in-memory if unavailable (`main.py:553`)
- **Typesense:** post + note full-text search (note plaintext indexed — see Privacy §8)
- **Cloudinary:** post images, album photos, resources, media encryption-at-rest (encrypted bytes uploaded as opaque raw/authenticated assets)
- **Firebase Admin (FCM)** + **Web Push (VAPID)** for notifications (`main.py:449-508`, `config.py:53-62`)

### 1.4 Authentication Model

- Flask-Login dual loaders: `load_user` (`models.py:79-104`, 30s `user_loader_cache`) + `request_loader` (`models.py:107-173`) accepting `X-App-Token` header (`:119`), `Authorization: Bearer` (`:124`), or `x_app_token` httpOnly cookie (Secure, SameSite=Lax, 90d `main.py:859`)
- Tokens now **hashed at rest** (`security.py:1078` `hash_app_token`, `models.py:150` `$or: [token_hash, token]` legacy fallback); `database.py` added `token_hash` sparse unique (`main.py:875`)
- Password hashing: Werkzeug `generate_password_hash` (scrypt) at `blueprints/auth.py:154`, `api.py:55`; PINs hashed via `api.py:505`
- Email verification: 6-digit codes, SHA-256 at rest, 24h expiry, constant-time on web (`blueprints/auth.py:209` `hmac.compare_digest`) but plain `==` on mobile (`api.py:107`) — still present
- Sessions: `user_sessions` collection (`main.py:622-625`) + ban check `main.py:1128-1135`
- SocketIO auth = Flask session cookie during WS handshake; `authenticated_only` decorator `main.py:1477`

---

## 2. Encryption Architecture (server-side, at-rest)

**Model:** server-side encryption with server-held keys — NOT end-to-end. Anyone with `SECRET_KEY` (or a DB dump + key) can decrypt all user content. v3 envelope adds defense-in-depth against DB-only breach.

| Data                  | Key scheme                                                                | Version | Ref                   |
| --------------------- | ------------------------------------------------------------------------- | ------- | --------------------- |
| Notes (global legacy) | PBKDF2(SECRET_KEY, fixed salt `echowithin_notes_salt_v1`, 100k)           | v1      | `security.py:215-226` |
| Notes                 | PBKDF2(SECRET_KEY, salt `echowithin_notes_v2_{user_id}`, 480k)            | v2      | `security.py:231-242` |
| Notes                 | PBKDF2(DEK, per-user random salt, 480k); DEK wrapped by KEK               | v3      | `security.py:473-532` |
| DMs                   | PBKDF2(SECRET_KEY, salt `echowithin_dm_v1_{conv_id}`, 480k)               | v2      | `security.py:617-633` |
| DMs                   | DEK per conversation (random), wrapped by KEK, stored in `dm_permissions` | v3      | `security.py:548-614` |
| Bonds                 | PBKDF2(SECRET_KEY, salt `echowithin_bonds_v1_{bond_id}`, 480k)            | —       | `security.py:260-270` |
| Community notes       | PBKDF2(SECRET_KEY, salt community_id, 480k)                               | —       | `security.py:960-989` |
| Media bytes           | Single global key PBKDF2(SECRET_KEY, salt `echowithin_media_at_rest_v1`)  | —       | `security.py:357-366` |
| KEK                   | PBKDF2(SECRET_KEY, salt `echowithin_kek_v1`) wraps all v3 DEKs            | —       | `security.py:459-470` |

- KDF: PBKDF2-HMAC-SHA256, `_NOTES_KDF_ITERATIONS = 480000` (`config.py:78`)
- Decryption chains fall back v3 → v2 → v1 → **legacy plaintext passthrough** (`security.py:293-294, 665-669, 719-723, 901`)
- Keys derived on demand (never stored); derived Fernets cached in memory TTL (1h); **decrypted note plaintext cached** — now encrypted in Redis (`security.py:868-917` `_cache_encrypt_value`, 300s TTL `security.py:819`)
- Media served via HMAC-signed capability URLs (`security.py:391-427`, 15-min expiry `900s`, 32-hex truncated signature)
- Migration/rotation: `scripts/rotate_secret_key.py`, `migrate_to_v3.py`

---

## 3. Subsystem Summaries

### 3.1 Notes (`blueprints/notes.py`) + Sharing (`blueprints/sharing.py`)

Encrypted personal notes with markdown, tags, references; surprise notes; lock/PIN notes (hashed PINs); versions; merge-proposal flow (collaborator saves push a proposal to the original owner via SocketIO room + push notification; owner direct-push version-snapshots). Share links with permission levels (read-only/collaborate) and optional expiration. `ping_collaborators` has Redis/session cooldown.

### 3.2 Blog (`blueprints/blog.py`) — now includes moderation

Public posting platform: feeds (personalized via interest scoring `utils.py:calculate_hot_score`), posts with Cloudinary media + NSFW queue (`notifications.py:process_image_for_nsfw`), threaded comments with votes/edit/delete, reactions, saves, shares, view tracking, RSS/JSON-LD SEO. Filter `get_public_posts_filter()` (`utils.py`) now suppresses flagged posts `is_visible` / `report_count`. XSS sanitized via `bleach` allowlists (`blog.py:993`, `utils.py:248-273`). Anonymous post views fingerprinted via hashed `iphash` (no longer raw IP — concern remediated). Recent fix: `blueprints/blog.py:15-19` guards `count_documents` with `int()` cast for mock safety.

### 3.3 Messages (`blueprints/chat.py`) + Whisper (`blueprints/whisper.py`)

DMs encrypted at rest (v2/v3 pair keys), SocketIO real-time delivery, scheduled messages (`X-Scheduler-Secret` fail-closed — `chat.py:892` no longer falls back to SECRET_KEY), DM privacy settings + `is_blocked_by` / `can_dm` gates. Whisper = ephemeral timed conversations; messages TTL-deleted (`main.py:747`) + app-level `delete_many`; session docs TTL-purged 24h after expiry (`main.py:743`). Extension now requires partner consent (persisted requests). System metadata messages still persist as plaintext in DM thread (`whisper.py:37`).

### 3.4 Communities (`blueprints/communities.py`)

User-created communities (invite codes, public/private, member management via `community_memberships_conf`); encrypted community notes with surprise themes/media (now encrypted-at-rest `sharing.py:1134`), reactions, save-to-personal; admin-only challenges/polls (`community_polls_conf`); encrypted resource uploads (Cloudinary signed downloads); daily mood check-ins; welcome messages; reporting flow (`community_reports_conf`); voucher codes grant premium (`_apply_voucher_premium` now never shrinks expiry). Previously unguarded endpoints now have `is_member` checks (`communities.py:684,910,1161` — fixed).

### 3.5 Bonds (`blueprints/bonds.py` — largest, now 5577 lines)

Two-person partnership system: request/accept/break lifecycle (3-day break cooldown), goals, shared journal, mutual-reveal mood tracker, daily QotD (deterministic + AI-generated via Gemini/JigsawStack + community bank — now two-sided consent gate `bonds.py:367-409, 443`), habits, countdowns, shared photo album (encrypted-at-rest Cloudinary + local fallback now encrypted `bonds.py:3287-3297`; caps 10 files/50MB), bucket list, media recommendations, pulses (On This Day, Slideshow, Polaroid modes). Consistent `_is_bond_participant` authorization on all 52 endpoints (no IDOR found). Ciphertext-in-push bugs fixed (`bonds.py:1507` decrypt before emit).

### 3.6 Admin (`blueprints/admin.py`)

All routes `@login_required + @admin_required` (`security.py:960-972`, audit-logged). OTA APK publishing now **streams SHA-256** (`admin.py:57-67` `hashlib.sha256` over saved file, `manifest.sha256`) and syncs DB+static (`main.py:629-686` `sync_update_manifest`); still serves debug-signed `app-debug.apk` from `static/downloads/` (integrity now verifiable, signature pinning still absent). Post moderation: flag/suppress via `post_reports_conf` (`utils.py:get_public_posts_filter`). Announcements + broadcast push, premium grant/revoke, voucher minting, user ban/delete (cascade via `profile.py:326`), community ban/delete, report review, metrics/traffic/health dashboards. Regex search now escaped (`admin.py:434-438` `re.escape`).

### 3.7 Payments (`blueprints/payments.py`)

Paystack premium subscriptions + donations. Webhook HMAC-verified with constant-time compare (`payments.py:146-152`); idempotency via `payment_grants_conf` unique `reference` (`main.py:804-806`). Callback verifies `metadata.user_id` and `amount == PREMIUM_PRICE_KSH`. **`POST /api/v1/premium/activate` self-grant endpoint removed** (`api.py` former `:460-474` — now 404).

### 3.8 Mobile API (`api.py`)

37 REST endpoints for native Android app. Dual session/token auth; entire blueprint CSRF-exempt (`main.py:255`). Note CRUD (server-side decryption), shares, versions, proposals, app lock (4-digit PIN — now throttled), FCM registration, sync. Premium activation is now Paystack-only.

### 3.9 Push (`blueprints/push.py`) / Notifications (`notifications.py`)

FCM (Android) + VAPID Web Push subscriptions; unread badge counts; notification collapse. Push bodies previously carried decrypted user content to Google/FCM; now redacted/minimized. AI QotD gated by explicit opt-in. Logs emailed daily are now PII-redacted (`notifications.py:896-928`).

---

## 4. Security Baseline (verified positives)

- CSRFProtect global (`main.py:184`); tight exemption list (`main.py:255-264`) — `api_v1`, `auth.confirm`, `auth.app_reauth`, `push.subscribe/unsubscribe`, `paystack_webhook`, two notes/chat helpers
- Session cookies: HttpOnly, Secure, SameSite=Lax, 14d (`main.py:396-409`)
- Security headers: X-Frame-Options, nosniff, XSS-protection, Referrer-Policy, Permissions-Policy, HSTS (now on all HTTPS including `/api`/`/static`/socket — was conditional), CSP (`main.py:1102-1168`) — strict nonce infra exists (`main.py:302-303`) but `script-src 'unsafe-inline'` still default unless `CSP_STRICT_NONCES` set (staged)
- Rate limiting: now **per-IP Redis fixed-window** (`security.py:139-145`, `main.py:478-551`) replacing prior global counter; `BYPASS_RATE_LIMIT` gated to dev
- `is_same_origin_request()` (`security.py:49-68`) still returns True when Origin/Referer absent — concern retained
- No MongoDB operator injection found; `safe_object_id` (`security.py`) used consistently; admin regex now escaped (`admin.py:434-438`)
- Media uploads: extension-only validation, size caps present, Cloudinary encrypted; local-fallback now encrypted-at-rest and cleaned up on delete
- Whisper messages genuinely TTL-deleted; guest data purged on expiry (`main.py:966-1035`)
- SSRF protection for link previews (`utils.py:863-895`) now rejects redirects and pins IP/port
- Scheduler secret fail-closed (`chat.py:892` no `SECRET_KEY` fallback)
- Media proxy (`main.py:203-252`) now MIME-allowlisted (`_mime_allowlist`) + `Content-Disposition: inline` + `X-Content-Type-Options: nosniff`

---

## 5. Concern Register (updated 2026-09-02)

Previously critical/high concerns #1, #3, #4, #5-partial, #6-partial, #10-partial, #11, #12, #13, #14, #15-16, #17, #19-20 etc. have been **remediated** (see §7). Remaining / new:

| #   | Area               | Concern                                                                                                                                                            | Ref                                                                    |
| --- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| R1  | Encryption/Privacy | Typesense still indexes **plaintext** note content (`utils.py:66-80` `_note_to_typesense_doc` decrypts) — owner-excluded by decision, search would break otherwise | `utils.py:97-110`, `notes.py:609`                                      |
| R2  | Media/OTA          | APK remains **debug-signed** `app-debug.apk`; no cert pinning or release-key signature verification on device                                                      | `static/downloads/app-debug.apk`, `pages.py:244-260`, `admin.py:42-69` |
| R3  | Auth               | Mobile confirm still plain `==` and unsalted SHA-256 at rest (web path fixed)                                                                                      | `api.py:107`, `auth.py:47-50`                                          |
| R4  | Notes              | Decrypt fallback returns **plaintext passthrough** if not Fernet (`security.py:293,668,719`) — legacy compat, but a plaintext DB write is silently served          | `security.py:293-294`                                                  |
| R5  | Realtime           | `join_note`/`note_update` still minimally checks share existence, no per-user permission level enforcement                                                         | `main.py:1510-1547, 1571-1622`                                         |
| N1  | Perf               | `bonds.py` N+1 decrypt loops (goals/journal/album/moods/qotd) — informational, not critical at current scale                                                       | `bonds.py:1053-1078` etc.                                              |
| N2  | Perf               | Two slow routes per PERF_REPORT 2026-08-02: `/personal_space` p95 1695ms, `/messages` p95 1386ms — TTFB-bound                                                      | `PERF_REPORT.md`                                                       |
| N3  | Privacy            | Single `SECRET_KEY` still derives all KEK/v2/bond/media/community keys; DB+key leak = full plaintext                                                               | `security.py:215-470`                                                  |

All other prior critical/high findings verified fixed via code inspection.

---

## 6. Release & Deploy Flow (verified 2026-09-02)

- **Git:** pushes to `main` on both repos (backend + Android `C:\Users\DevTech\AndroidStudioProjects\EchoWithin` external)
- **DB manifest:** `app_updates_conf` (`main.py:619, 629-686`) is source of truth; `static/update-manifest.json` is file mirror
- **APK publish:** `admin.py:42-69` `admin_upload_apk` saves to `static/downloads/app-debug.apk`, streams SHA-256 (`:57-67`), writes `update-manifest.json` (`:70-72`) and `app_updates_conf` (`:73`); `main.py:629-686` `sync_update_manifest()` reconciles DB vs file by `versionCode` on startup
- **Current release:** `static/update-manifest.json:2-6` `versionCode 40 / versionName 1.10.6 / sha256 E425…2DF` — APK 22.8 MB (`static/downloads/app-debug.apk` 2026-08-28)
- **CI/CD:** no CI pipeline found (no `.github/workflows`, no `Jenkinsfile`); `Procfile` + `captain-definition` + `Dockerfile` only; testing is manual `pytest` (now 140 tests under `.venv`)

---

## 7. Test Coverage (2026-09-02)

`tests/` — 10 files, 140 tests collected (`python -m pytest tests --collect-only -q` under `.venv` only; system `python` has no pytest):

| File                      | Tests    | Focus                                                                                                                                                      |
| ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/conftest.py:1-141` | fixtures | `app`, `client`, `https_client`, `mock_user`/`mock_admin_user`/`auth_client`/`admin_client` (new `auth_client` via `patch('flask_login.utils._get_user')`) |
| `test_auth.py`            | ~30      | hash, safeObjectId, safeUrl, tier, guest expiry, honeypot                                                                                                  |
| `test_security.py`        | ~20      | CSRF, CSP, honeypot, bleach, rate-limit bypass                                                                                                             |
| `test_crypto.py`          | ~25      | note/DM/community/bond encrypt roundtrips, KDF                                                                                                             |
| `test_bonds_timeline.py`  | ~15      | bond types, unread, datetime Z-suffix                                                                                                                      |
| `test_notes_api.py`       | ~10      | note CRUD/sharing tokens                                                                                                                                   |
| `test_blog_engine.py`     | ~10      | slug/reactions/comments/auth gating                                                                                                                        |
| `test_chat_whisper.py`    | ~10      | whisper durations, DM permissions                                                                                                                          |
| `test_communities.py`     | ~10      | community roles/reports/vouchers                                                                                                                           |
| `test_admin_and_tiers.py` | ~10      | health metrics, pinned limit, bans, vouchers                                                                                                               |
| `test_post_moderation.py` | ~10      | `get_public_posts_filter` suppression, admin clear                                                                                                         |

**Gaps:** integration tests for SocketIO, Paystack webhook, Typesense indexing, Cloudinary upload, FCM dispatch are not present (mocked out in `conftest.py:37-55`).

---

## 8. Open TODOs / Dead Code

- `grep TODO|FIXME|HACK|XXX` — **0 hits** (only false positive `config.py:155` keyword `hack` in tag list)
- Commented-out code — 0 dead blocks (14 comment lines are explanatory)
- Dead code removed: `if False` badge path (`api.py:1785` fixed), `if False` premium fallback, Typesense raw-URL `note_id` bug (`utils.py`)
- Remaining deferred (intentional): plaintext fallback (`security.py`), Typesense plaintext indexing (excluded by owner), CSP strict nonces rollout (blocked by 49 inline scripts), trial/tier semantics (product-policy)

---

## 9. What changed since 2026-08-02

- **Security:** premium self-grant removed; payment idempotency+ownership verification; per-IP rate limiting; token hashing; SSRF redirect/pin fix; scheduler fail-closed; media proxy allowlist; app-lock throttle; community is_member guards; socket share authz; AI QotD consent gate; IP hashing; album local-fallback encryption; Redis cache value encryption; DM presence gating; HSTS everywhere; admin regex escaping; cascade deletion; MIME allowlist; etc. (see FINAL_REPORT.md remediation table — 47 items, most ✅)
- **Product:** post moderation/flagging (`post_reports_conf`, `975ac8b`), bonds album expansion (+1446 lines), community polls/resources/memberships collections, activity_read for Android read-state
- **Tests:** `tests/` introduced (140 tests; `.gitignore` whitelisted `!tests/` `:14-17`, `tests/**/__pycache__/` ignored, `commit.md` ignored)
- **Deploy:** manifest now carries `sha256` (integrity verifiable), DB↔file sync by `versionCode`, APK streaming hash

---

*This document is the Phase 1 deliverable for 2026-09-02. Companion: `AUDIT.md` (Phase 3 — ranked fixes/improvements/suggestions) + `FINAL_REPORT.md` (prior 47-finding remediation log) + `PERF_REPORT.md` (latency snapshot). All claims cite file:line as of this regeneration.*
