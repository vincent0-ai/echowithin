# EchoWithin — Secure Notes, Community, Bonds & Collaboration Platform

EchoWithin is a comprehensive platform that combines blogging, encrypted personal notes, collaborative note sharing, pair relationship spaces ("Bonds & Echo Together"), direct messaging with ephemeral Whisper Mode, interactive forms and multiplayer games, and premium-tier power features. It is built with a Python/Flask backend, MongoDB, real-time WebSocket communication, and ships as both a Progressive Web App (PWA) and a native Android application.

---

## Features

### Encrypted Personal Notes

- End-to-end encrypted personal notes using **Fernet symmetric encryption** with per-user **PBKDF2-HMAC-SHA256** key derivation (480,000 iterations, OWASP 2024).
- Full-text search over personal notes via Typesense (tenant-isolated scoped keys).
- Version history with restore, diff previews, and merge conflict handling.
- Note locking, pinning, tags, and reference fields.
- Tiered limits: 500 notes / 20K chars (free) → unlimited / 100K chars (premium).

### Note Sharing & Real-Time Collaboration

- Share notes with view or edit permissions, optional access codes, and expiry (1h, 1d, 7d).
- Per-share **auto-approve** toggle (premium) — collaborators are auto-approved on subsequent edits.
- **Surprise themes** (Valentine, Birthday, Anniversary, Celebration) with custom photo and audio uploads, configurable via a dedicated share settings page.
- Typewriter-effect reveal for recipients.
- Real-time collaboration via **Socket.IO**: live co-editing, edit locks, presence tracking ("Studying Now").
- Merge proposal system: collaborators propose changes, owners review, accept, or reject.
- Bidirectional sync between saved copies and the original source.
- Discussion threads and file attachments on shared notes.

### Bonds & Echo Together (Pair Relationships)

- **Dedicated Pair Spaces**: Connect with partners, best friends, study mates, family, or accountability partners with custom labels, icons, and automated milestone tracking (1 week to multi-year anniversaries with push notifications).
- **Daily Streaks & Streak Shields**: Track consecutive days of shared activity. Streaks decay automatically via a daily scheduler job if neither partner participates. Streak shields (limited use) protect streaks from breaking on inactive days.
- **Daily Habits System**: Build shared daily habits (up to 10 active habits per bond) with E2E encrypted habit titles at rest, real-time WebSocket toggles, and habit check-offs contributing to shared daily streaks.
- **Shared Countdowns**: Track upcoming shared events (birthdays, anniversaries, trips) with live day counters ("X days left", "Today!", "Tomorrow!") and E2E encrypted titles at rest.
- **Shared Calendar**: A full calendar system with custom events, recurrence support, RSVP tracking, nearest upcoming event banners, and **ICS export** for syncing with external calendar apps (Google Calendar, Apple Calendar, Outlook).
- **Shared Photo Album**: Upload, organize, and browse shared photos with category filters (memories, dates, milestones, travel, pets), multiple view modes (grid, polaroid, timeline), emoji reactions, photo pinning, photo editing/deletion, auto-downsampled uploads for performance, and a full lightbox viewer. Includes **"On This Day" memories** — surfacing photos from the same date in previous years.
- **Encrypted Shared Journaling**: Write and reflect in a private, end-to-end encrypted shared journal using per-bond Fernet keys.
- **Daily Question of the Day (QotD)**: Deepen connections with curated daily prompts, AI-generated questions (via JigsawStack), or custom partner-written questions. Features a dual blind reveal mechanic (answers are hidden until both partners respond). Encrypted at rest. Full QotD history browsing.
- **Mutual Goals & Milestones**: Propose shared goals requiring partner approval, track milestone step completions, log progress check-ins, edit goals, and manage goal lifecycles (complete/abandon) with encrypted titles and descriptions.
- **Daily Mood Tracker & 30-Day Insights**: Log daily moods with dual reveal, compare 30-day side-by-side mood histories, and view monthly recap summaries ("Echo Together") tracking streaks, completed goals, QotDs answered, and top moods.
- **Partner Nudges**: Send gentle nudge notifications to remind your partner to participate (daily limit enforced per tier).
- **Offline-First Architecture**: Full IndexedDB-backed offline caching for bonds data. Offline action queue with automatic sync when connectivity returns, pending action badges, and offline question of the day generation via deterministic hashing.
- **Real-Time Sync & Activity Push Notifications**: Instant Socket.IO state synchronization accompanied by push notifications for 14+ bond activity triggers. Per-section unread badges with mark-as-read tracking.

### Direct Messaging

- Encrypted 1-on-1 conversations with text, images, and voice notes.
- Emoji reactions, message pinning, message editing, deletion, and full conversation deletion.
- Message **request system** — users approve or reject first contact.
- Typing indicators, read receipts (single ✓ → blue ✓✓), and active chat presence via Socket.IO.
- **In-chat search** across message history with keyword highlighting.
- **Swipe-to-reply** — touch-based gesture to quote and reply to specific messages.
- **Chat themes** — customizable conversation color themes (premium).
- **Scheduled messages** — compose messages for delayed delivery at a chosen time (premium).
- **Voice messages** — record and send voice notes with waveform playback.
- **Send queue with retry** — optimistic local rendering with automatic retry on network failure.

### Whisper Mode (Ephemeral Chat)

- **Timed self-destructing sessions**: Invite a partner to a private, ephemeral chat with configurable durations (5–120 minutes). All messages are permanently deleted when the session expires, with MongoDB TTL indexes enforcing automatic purging.
- **Session extensions**: Either partner can request a time extension during an active session; the other must approve.
- **End-to-end encryption**: All whisper messages are encrypted at rest using per-pair Fernet keys.
- **Dynamic session watermarks**: Unique per-session watermark overlays to deter external capture.
- **Swipe-to-reply**: Touch-based reply gesture with quoted reply rendering in chat bubbles and `reply_to` threading stored in the backend.
- **Message editing**: Edit sent text messages in-place (no history kept, TTL unaffected).
- **Emoji reactions**: Double-tap or long-press received messages to react with emoji; reactions persist across history reloads.
- **Read receipts**: DM-parity single ✓ → blue ✓✓ tick system for sent messages.
- **Image sharing with anti-save protection**:
  - CSS `pointer-events: none` on `<img>` elements with transparent overlay shields.
  - Context menu and drag prevention on all whisper images.
  - Protected lightbox using `background-image` instead of `<img>` — eliminates browser "Save Image As" option.
  - `user-select: none` on the entire message container to prevent text copying.
  - Right-click disabled on the entire whisper overlay.
- **Tiered screenshot detection** (minimized false positives):
  - **High-confidence triggers** (alert both parties): PrintScreen key, Ctrl+Shift+S / Win+Shift+S / Cmd+Shift+3/4/5 keyboard shortcuts, DevTools opening (F12, Ctrl+Shift+I/J/C).
  - **Low-confidence triggers** (blur content only, no alert): Visibility change (tab switch, phone calls), window blur (Alt+Tab, notification taps). Content is blurred with `filter: blur(20px)` to protect against passive screen captures without spamming false positive alerts.
  - 10-second debounce and server-side rate limiting per session.
- **Push notifications**: Redacted push notifications for new whisper messages (content is never exposed in push payloads).

### Interactive Forms

- **Form builder**: Create shareable forms with multiple question types — short text, paragraph, single choice, multiple choice, and rating scales (up to 15 questions per form).
- **Encrypted responses**: All form submissions are encrypted at rest using Fernet symmetric encryption.
- **Shareable via link**: Each form gets a unique share ID for distribution; forms can be deactivated or deleted by the owner.
- **Response dashboard**: View aggregated responses with per-question breakdowns, submission timestamps, and respondent tracking.
- **CSV export**: Export all form responses as a CSV file for external analysis.
- **Analytics**: Real-time response count and submission statistics.

### Multiplayer Games

- **Game lobbies**: Create and join real-time multiplayer game sessions with up to 30 players via shareable lobby codes.
- **Six game modes**:
  - **Poll** — multi-question polls with live results and percentage breakdowns.
  - **Trivia** — timed quiz questions with correct answer reveals and scoring.
  - **Would You Rather** — binary choice dilemmas with community vote percentages.
  - **Two Truths and a Lie** — players submit statements; others guess the lie.
  - **Story Chain** — collaborative storytelling where players take turns adding sentences.
  - **Caption This** — image-based caption contest with voting.
- **Real-time gameplay** via Socket.IO with live player join/leave, answer submissions, and result reveals.
- **Game results page** with leaderboards, per-question breakdowns, and statistics.
- **Lobby expiry**: Games auto-expire after a configurable duration.

### Community Blogging

- Rich posts with **Markdown** support, image/video uploads, and tag categorization.
- **Threaded comments** with replies, voting, and reactions (Heart, Wow, Insightful, etc.).
- Post saving/bookmarking, view tracking, and engagement-based sorting (hot / top / trending).
- Full-text search with typo tolerance (Typesense) plus tag, author, and date filters.
- Auto-generated RSS feed, sitemap_index.xml, and OpenGraph/Twitter meta tags.
- **Weekly achievements & leaderboard**: Automated weekly calculation of top contributors based on engagement weights (comments, reactions, shares, views).

### Communities

- Create and join topic-based communities with public or invite-code access.
- Community notes with surprise themes, reactions, and moderation tools.
- **Community challenges** — admins create time-bound writing prompts; members submit notes linked to the challenge; winner picked by reaction count.
- **Anonymous posting** — post community notes without revealing your identity.
- Reporting system for rule violations.
- **Community vouchers** — invite codes for private communities.
- Tiered limits: 1 community (free) → 5 communities (premium).

### Push Notifications

- **Web Push** (PWA) via VAPID for browser notifications on desktop, Android, and iOS.
- **Firebase Cloud Messaging (FCM)** for native Android app notifications.
- Notifications for: new posts, comments, replies, message requests, collaboration proposals, admin announcements, bond activity triggers (habit check-offs, countdowns, goal proposals/check-ins, QotD & mood reveals, bond invites, nudges, anniversary milestones), whisper invites, and game lobbies.
- Smart suppression: no push when the recipient is actively viewing the conversation.
- **Proactive push self-healing**: Idle-deferred endpoint health verification, automatic re-subscription when endpoints are revoked by FCM, revocation blacklist with 14-day TTL tombstones to prevent re-registration of dead tokens, and background resume verification on PWA wake.
- Stale subscription cleanup, iOS Safari-specific handling.

### Premium Tier — KSH 50/month

| Feature                     | Free       | Premium     |
| --------------------------- | ---------- | ----------- |
| Personal notes              | 500        | Unlimited   |
| Characters per note         | 20,000     | 100,000     |
| Share links per note        | 3          | Unlimited   |
| Surprise notes              | 20         | Unlimited   |
| Note locking                | No         | Yes         |
| Blog space                  | No         | Yes         |
| Scheduled messages          | No         | Yes         |
| Note media attachments      | No         | Up to 20    |
| Version history retention   | 7 days     | 365 days    |
| Auto-approve collaborations | No         | Yes         |
| Communities                 | 1          | 5           |
| Voice messages              | Yes        | Yes         |
| Bonds                       | 3          | 3           |
| Goals per bond              | 5          | 20          |
| Nudges per day              | 3          | 10          |
| Calendar events per bond    | 20         | 100         |
| Whisper sessions per day    | 3          | 10          |
| Max whisper duration        | 30 min     | 120 min     |

All new accounts receive a **1-day free trial** of premium features. Payments processed via **Paystack**.

### Admin Dashboard

- Real-time analytics: posts/day, comments/day, active users, traffic, system health.
- User management: ban, unban, delete accounts, grant/revoke premium.
- Post management: pin, unpin, force-delete.
- Community management: review reports, manage members, community vouchers.
- Announcements and site-wide push broadcast.
- CSV data export and Typesense reindex.
- APK upload with OTA update manifest for the Android app (auto-synced on startup).
- Premium user management dashboard.

### Security & Safety

- **CSRF protection** via Flask-WTF on all mutating routes.
- **Rate limiting** on authentication endpoints (15 calls/minute) and all API routes.
- Honeypot bot detection on registration.
- Secure cookies (HttpOnly, Secure, SameSite=Lax), **HSTS** (1 year with preload), and **CSP** headers with per-request nonces.
- End-to-end encryption at rest for personal notes, DMs, shared journals, bond habits, countdowns, QotDs, shared goals, and form responses using per-user / per-bond **Fernet symmetric encryption** with PBKDF2 key derivation.
- HTML sanitization via **Bleach** — Markdown rendered safely, links set to `target="_blank" rel="noopener"`.
- NSFW image detection via **JigsawStack** — flagged images are tagged and hidden.
- Canonical domain enforcement and automatic HTTP→HTTPS redirects.
- Open redirect protection via `is_safe_url()`.
- ProxyFix middleware for correct IP/URL generation behind reverse proxies.
- **Capability-based media URLs**: Encrypted media is served via HMAC-signed, time-windowed capability URLs (4-hour stable windows for browser caching) with ETag validation and 304 Not Modified support.
- **Session management**: Multi-device session tracking with force-logout capability and session listing in profile settings.
- **Secret key rotation**: Standalone utility for rotating the Flask secret key with backward-compatible re-encryption of all stored Fernet ciphertext.

### PWA & Native App

- Installable on Android and iOS via the browser.
- Service Worker with offline caching and a dedicated `/offline` fallback page.
- Web Share Target API support.
- **Capacitor**-wrapped native Android app with:
  - Persistent auth tokens (90-day httpOnly cookies).
  - App Lock: optional 4-digit PIN with 5-minute unlock session, PIN-gated removal, email-based recovery.
  - Bidirectional offline sync for personal notes.
  - Offline-first architecture: local SQLite database, smart sync dispatcher, periodic auto-sync (30-min interval).
  - Deep linking via Android App Links.
  - OTA update manifest for in-app updates.

---

## Tech Stack

| Category               | Technology                                                                     |
| ---------------------- | ------------------------------------------------------------------------------ |
| **Backend Framework**  | Python 3.12, Flask 3.1 (blueprints), Gunicorn 23 (gevent WebSocket worker)     |
| **Database**           | MongoDB 7 (primary), Redis 7 (caching + task queue)                            |
| **Real-time**          | Flask-SocketIO 5.3, gevent-websocket                                           |
| **Search**             | Typesense (full-text with typo tolerance, tenant-isolated scoped keys)         |
| **Media**              | Cloudinary (images, video, audio)                                              |
| **Background Jobs**    | Flask-RQ2 (RQ 2.6)                                                             |
| **Push Notifications** | pywebpush (VAPID), firebase-admin (FCM)                                        |
| **Email**              | Flask-Mail (SMTP) with List-Unsubscribe headers                                |
| **Authentication**     | Flask-Login, Google OAuth2 (requests-oauthlib)                                 |
| **Encryption**         | Fernet (cryptography 46), PBKDF2-HMAC-SHA256                                   |
| **AI / Moderation**    | JigsawStack (NSFW detection, AI QotD generation, tag suggestions)              |
| **Markdown**           | Python-Markdown 3.10 + Bleach 6.3 sanitization                                 |
| **Payments**           | Paystack                                                                       |
| **Frontend**           | Jinja2 templates, vanilla JS, CSS                                              |
| **PWA**                | Service Worker, Web App Manifest, Web Share Target                             |
| **Native App**         | Capacitor (Android + iOS) with Jetpack Compose UI                              |
| **Scheduling**         | schedule library + custom scheduler.py                                         |
| **Deployment**         | Docker, CapRover, Render/Heroku Procfile                                       |
| **Monitoring**         | JSON-formatted rotating logs, ntfy push notifications, system health dashboard |
| **Testing**            | pytest                                                                         |

---

## Architecture

```
echowithin/
├── main.py              # Flask app init, config, MongoDB setup, Socket.IO handlers
├── api.py               # REST API blueprint (/api/v1/*) for mobile/native clients
├── config.py            # Environment variables, tier limits, feature flags, tags
├── database.py          # MongoDB collection references
├── models.py            # User model, helpers
├── security.py          # Encryption, rate limiting, HMAC signing, media capability URLs
├── utils.py             # Shared utilities (encryption, media cleanup, timezone, tier checks)
├── notifications.py     # Push notification dispatch (Web Push + FCM)
├── typesense_client.py  # Typesense search client wrapper
├── wsgi.py              # WSGI entry point
├── blueprints/
│   ├── auth.py              # Registration, login, logout, Google OAuth, password reset, sessions
│   ├── pages.py             # Home, search, feed, offline, about, terms, FAQ, RSS
│   ├── blog.py              # Blog posts, comments, reactions, views, saves, encrypted media
│   ├── notes.py             # Personal space, note CRUD, search, merge, app lock
│   ├── sharing.py           # Shared notes, attachments, proposals, version history, surprise themes
│   ├── chat.py              # Direct messages, scheduled messages, reactions, pinning, voice, search
│   ├── whisper.py           # Ephemeral self-destructing chat sessions, extensions, screenshot alerts
│   ├── bonds.py             # Bonds & Echo Together: habits, countdowns, QotD, goals, journal,
│   │                        #   mood, nudges, streaks, calendar, photo album, insights
│   ├── communities.py       # Communities, notes, challenges, vouchers, reports
│   ├── forms.py             # Form builder, submissions, encrypted responses, CSV export
│   ├── game.py              # Multiplayer game lobbies (poll, trivia, WYR, TTAL, story, caption)
│   ├── admin.py             # Admin dashboard, user/post management, APK upload, announcements
│   ├── payments.py          # Paystack webhook, premium activation
│   ├── profile.py           # User profile, settings, data export
│   └── push.py              # Web Push subscribe/unsubscribe, endpoint health verification
├── scripts/
│   ├── worker.py                    # RQ background job worker
│   ├── scheduler.py                 # Cron-style scheduler for all periodic tasks
│   ├── backup_to_atlas.py           # Incremental MongoDB → Atlas backup sync (every 30 min)
│   ├── restore_from_atlas.py        # Atlas → local MongoDB restore utility
│   ├── streak_decay.py              # Daily bond streak decay for inactive pairs (02:00 AM)
│   ├── anniversary_check.py         # Daily bond milestone detection & push alerts (08:00 AM)
│   ├── weekly_achievements.py       # Weekly leaderboard calculation (Monday 00:01)
│   ├── process_scheduled_messages.py  # Delivers due scheduled DMs (every minute)
│   ├── schedule_log_email.py        # Enqueues daily admin log email (01:00 AM)
│   ├── send_weekly_newsletter.py    # Enqueues weekly newsletter (Sunday 09:00 AM)
│   ├── cleanup_expired_auth.py      # Removes expired verification codes/tokens (every hour)
│   ├── encrypt_plaintext_fields.py  # Migration: encrypts legacy plaintext fields
│   └── rotate_secret_key.py         # Secret key rotation with re-encryption
├── templates/           # Jinja2 templates (54 files)
├── static/              # CSS, JS, service worker, PWA assets, APK downloads
├── tests/               # pytest test suites
├── mobile-app/          # Capacitor native app wrapper + Android/iOS configs
├── requirements.txt     # Python dependencies
├── Procfile             # Process types for Render/Heroku
├── Dockerfile           # Docker image definition
├── captain-definition   # CapRover deployment config
└── README.md
```

**Process model** (via Procfile / honcho):

- `web`: Gunicorn with 3 gevent WebSocket workers
- `worker`: RQ worker for background jobs
- `scheduler`: Custom scheduler for periodic tasks (streak decay, anniversary checks, backups, scheduled messages, cleanup, newsletters, achievements)

---

## Installation & Setup

### Prerequisites

- Python 3.12+
- MongoDB instance (Atlas or local)
- Redis server
- Typesense instance (optional; search works in degraded mode without it)

### Quickstart

```bash
git clone <repo-url>
cd echowithin

pip install -r requirements.txt

# Configure environment variables (see below)
cp .env.example .env

# Run locally (development)
python main.py

# Run with all processes (production simulation)
honcho start
```

### Production

```bash
gunicorn -k geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
  -w 3 --timeout 120 --keep-alive 5 \
  -b 0.0.0.0:$PORT main:app
```

### Environment Variables

| Variable                                                                        | Required | Description                                                          |
| ------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------- |
| `SECRET`                                                                        | Yes      | Flask secret key for sessions, CSRF, and encryption derivation       |
| `MONGODB_CONNECTION`                                                            | Yes      | MongoDB connection URI                                               |
| `REDIS_HOST`                                                                    | Yes      | Redis hostname                                                       |
| `REDIS_PORT`                                                                    | Yes      | Redis port                                                           |
| `REDIS_PASSWORD`                                                                | Yes      | Redis password                                                       |
| `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`                    | Yes      | SMTP credentials                                                     |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`                                      | Yes      | Google OAuth2 credentials                                            |
| `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`          | Yes      | Cloudinary media storage                                             |
| `JIGSAW_API_KEY`                                                                | Yes      | AI content moderation & tag suggestions                              |
| `TYPESENSE_HOST`, `TYPESENSE_PORT`, `TYPESENSE_API_KEY`, `TYPESENSE_SEARCH_KEY` | No       | Typesense search engine (search degrades without it)                 |
| `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`                        | No       | Web Push notifications                                               |
| `FIREBASE_CREDENTIALS` or `FIREBASE_SERVICE_ACCOUNT`                            | No       | FCM native app push                                                  |
| `PAYSTACK_SECRET_KEY`                                                           | No       | Payment processing                                                   |
| `NTFY_TOPIC`, `NTFY_USERNAME`, `NTFY_PASSWORD`                                  | No       | Admin push notifications via ntfy                                    |
| `FLASK_URL`                                                                     | No       | Canonical base URL for email links (default: https://echowithin.xyz) |
| `SESSION_COOKIE_SECURE`                                                         | No       | Force secure cookies (default: True)                                 |
| `BYPASS_RATE_LIMIT`                                                             | No       | Development only — disables rate limiting when FLASK_ENV=development |
| `TIME`                                                                          | Yes      | Timezone offset configuration                                        |

---

## API

A REST API is available at `/api/v1/*` for mobile/native app clients. Key endpoint groups:

| Group                  | Endpoints                                                                                                                                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Auth**               | `POST /register`, `POST /confirm/<email>`, `POST /login`, `POST /logout`, `POST /app_reauth`                                                                                                             |
| **Notes**              | `GET /notes`, `GET /notes/<id>`, `GET /notes/content/<id>`, `POST /notes/create`, `POST /notes/edit/<id>`, `POST /notes/delete/<id>`                                                                     |
| **Note Shares**        | `GET /notes/shares`, `GET /notes/shares/<id>`, `POST /notes/share/<id>`, `POST /notes/share/<id>/auto_approve`, `POST /notes/revoke_share/<id>`                                                          |
| **Note Previews**      | `POST /notes/previews`                                                                                                                                                                                   |
| **Note Dedup**         | `POST /notes/dedup`                                                                                                                                                                                      |
| **Versions**           | `GET /notes/versions/<id>`, `POST /notes/version/restore/<id>/<ver>`                                                                                                                                     |
| **Proposals**          | `GET /notes/proposals`, `POST /notes/proposal/<id>/decision`                                                                                                                                             |
| **Sync**               | `POST /notes/<id>/sync`                                                                                                                                                                                  |
| **Lock**               | `POST /notes/toggle_lock/<id>`                                                                                                                                                                           |
| **App Lock**           | `POST /app_lock/setup`, `POST /app_lock/verify`, `GET /app_lock/check_status`, `POST /app_lock/remove`                                                                                                   |
| **Bonds & Habits**     | `POST /api/bonds/request/<user_id>`, `POST /api/bonds/accept/<id>`, `POST /api/bonds/break/<id>`, `GET /api/bonds/<id>/habits`, `POST /api/bonds/<id>/habits`, `POST /api/bonds/habits/<id>/toggle`      |
| **Countdowns & Recap** | `GET /api/bonds/<id>/countdowns`, `POST /api/bonds/<id>/countdowns`, `DELETE /api/bonds/countdowns/<id>`, `GET /api/bonds/<id>/insights`                                                                 |
| **Bond Goals & QotD**  | `GET /api/bonds/<id>/goals`, `POST /api/bonds/<id>/goals`, `POST /api/bonds/goals/<id>/approve`, `GET /api/bonds/<id>/qotd`, `POST /api/bonds/<id>/qotd/answer`, `POST /api/bonds/<id>/qotd/generate_ai` |
| **Calendar**           | `GET /api/bonds/<id>/calendar`, `POST /api/bonds/<id>/calendar`, `PUT /api/bonds/calendar/<id>`, `DELETE /api/bonds/calendar/<id>`, `POST /api/bonds/calendar/<id>/rsvp`, `GET /api/bonds/<id>/calendar/export.ics` |
| **Photo Album**        | `GET /api/bonds/<id>/album/photos`, `POST /api/bonds/<id>/album/upload`, `PUT /api/bonds/album/<id>`, `DELETE /api/bonds/album/<id>`, `POST /api/bonds/album/<id>/pin`, `POST /api/bonds/album/<id>/react` |
| **Nudges & Streaks**   | `POST /api/bonds/<id>/nudge`, `POST /api/bonds/<id>/streak-shield`                                                                                                                                       |
| **Whisper**            | `POST /api/whisper/invite`, `POST /api/whisper/<id>/respond`, `POST /api/whisper/<id>/extend`, `POST /api/whisper/<id>/end`, `GET /api/whisper/active`, `GET /api/whisper/history/<id>`, `GET /api/whisper/durations` |
| **Forms**              | `POST /api/forms/create`, `GET /forms/<share_id>`, `POST /forms/<share_id>/submit`, `GET /forms/<share_id>/responses`, `GET /forms/<share_id>/responses/export` |
| **Games**              | `GET /games`, `POST /games/create`, `GET /games/<lobby_id>`, `GET /games/<lobby_id>/results`, `GET /api/games/<lobby_id>/stats` |
| **Activity**           | `GET /posts/my-commented`, `POST /posts/mark-all-read`, `POST /activity/mark_read`, `GET /notifications/badge-counts`                                                                                    |
| **Push**               | `POST /api/push/subscribe`, `POST /api/push/unsubscribe`, `GET /api/push/status`                                                                                                                         |
| **FCM**                | `POST /fcm/register`, `POST /fcm/unregister`                                                                                                                                                             |
| **Premium**            | `POST /premium/activate`                                                                                                                                                                                 |
| **Profile**            | `GET /profile`                                                                                                                                                                                           |
| **Collaboration**      | `GET /notes/share/<id>/attachments`                                                                                                                                                                      |

---

## Testing

```bash
pytest tests/ -v
```

---

## Contributing

Contributions are welcome. Fork the repository and submit a pull request with a clear description of your changes. Please ensure code passes existing linting (`flake8`, `pylint`).

---

## License

See [LICENSE](LICENSE) for details.

---

Built with care by the EchoWithin Team.
