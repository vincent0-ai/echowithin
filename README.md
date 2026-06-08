# EchoWithin — Secure Notes, Community & Collaboration Platform

EchoWithin is a community platform that combines blogging, encrypted personal notes, collaborative note sharing, direct messaging, and premium-tier power features. It is built with a Python/Flask backend, MongoDB, real-time WebSocket communication, and ships as both a Progressive Web App (PWA) and a native Android application.

---

## Features

### Encrypted Personal Notes

- End-to-end encrypted personal notes using **Fernet symmetric encryption** with per-user **PBKDF2-HMAC-SHA256** key derivation (480,000 iterations, OWASP 2024).
- Full-text search over personal notes via Typesense (tenant-isolated scoped keys).
- Version history with restore, diff previews, and merge conflict handling.
- Note locking, pinning, tags, and reference fields.
- Tiered limits: 50 notes / 20K chars (free) → unlimited / 100K chars (premium).

### Note Sharing & Real-Time Collaboration

- Share notes with view or edit permissions, optional access codes, and expiry (1h, 1d, 7d).
- Per-share **auto-approve** toggle (premium) — collaborators are auto-approved on subsequent edits.
- **Surprise themes** (Valentine, Birthday, Anniversary, Celebration) with custom photo and audio uploads, configurable via a dedicated share settings page.
- Typewriter-effect reveal for recipients.
- Real-time collaboration via **Socket.IO**: live co-editing, edit locks, presence tracking ("Studying Now").
- Merge proposal system: collaborators propose changes, owners review, accept, or reject.
- Bidirectional sync between saved copies and the original source.
- Discussion threads and file attachments on shared notes.

### Community Blogging

- Rich posts with **Markdown** support, image/video uploads, and tag categorization.
- **Threaded comments** with replies, voting, and reactions (Heart, Wow, Insightful, etc.).
- Post saving/bookmarking, view tracking, and engagement-based sorting (hot / top / trending).
- Full-text search with typo tolerance (Typesense) plus tag, author, and date filters.
- Auto-generated RSS feed, sitemap_index.xml, and OpenGraph/Twitter meta tags.

### Communities

- Create and join topic-based communities with public or invite-code access.
- Community notes with surprise themes, reactions, and moderation tools.
- **Community challenges** — admins create time-bound writing prompts; members submit notes linked to the challenge; winner picked by reaction count.
- **Anonymous posting** — post community notes without revealing your identity.
- Reporting system for rule violations.
- Tiered limits: 1 community (free) → 5 communities (premium).

### Direct Messaging

- Encrypted 1-on-1 conversations with text, images, and voice notes.
- Emoji reactions, message editing, deletion, and full conversation deletion.
- Message **request system** — users approve or reject first contact.
- Typing indicators, read receipts, and active chat presence via Socket.IO.
- **Scheduled messages** for delayed delivery (premium feature).

### Push Notifications

- **Web Push** (PWA) via VAPID for browser notifications on desktop, Android, and iOS.
- **Firebase Cloud Messaging (FCM)** for native Android app notifications.
- Notifications for: new posts, comments, replies, message requests, collaboration proposals, and admin announcements.
- Smart suppression: no push when the recipient is actively viewing the conversation.
- Stale subscription cleanup, iOS Safari-specific handling.

### Premium Tier — KSH 50/month

| Feature                     | Free   | Premium   |
| --------------------------- | ------ | --------- |
| Personal notes              | 50     | Unlimited |
| Characters per note         | 20,000 | 100,000   |
| Share links per note        | 3      | Unlimited |
| Surprise notes              | 20     | Unlimited |
| Note locking                | No     | Yes       |
| Blog space                  | No     | Yes       |
| Scheduled messages          | No     | Yes       |
| Note media attachments      | No     | Up to 20  |
| Version history retention   | 7 days | 365 days  |
| Auto-approve collaborations | No     | Yes       |
| Communities                 | 1      | 5         |
| Voice messages              | Yes    | Yes       |

All new accounts receive a **1-day free trial** of premium features. Payments processed via **Paystack**.

### Admin Dashboard

- Real-time analytics: posts/day, comments/day, active users, traffic, system health.
- User management: ban, unban, delete accounts, grant/revoke premium.
- Post management: pin, unpin, force-delete.
- Community management: review reports, manage members.
- Announcements and site-wide push broadcast.
- CSV data export and Typesense reindex.
- APK upload with OTA update manifest for the Android app (auto-synced on startup).

### Security & Safety

- **CSRF protection** via Flask-WTF on all mutating routes.
- **Rate limiting** on authentication endpoints (15 calls/minute).
- Honeypot bot detection on registration.
- Secure cookies (HttpOnly, Secure, SameSite=Lax), **HSTS** (1 year with preload), and **CSP** headers.
- HTML sanitization via **Bleach** — Markdown rendered safely, links set to `target="_blank" rel="noopener"`.
- NSFW image detection via **JigsawStack** — flagged images are tagged and hidden.
- Canonical domain enforcement and automatic HTTP→HTTPS redirects.
- Open redirect protection via `is_safe_url()`.
- ProxyFix middleware for correct IP/URL generation behind reverse proxies.

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
| **Backend Framework**  | Python 3.12, Flask 3.1 (blueprints), Gunicorn 23 (gevent WebSocket worker)                  |
| **Database**           | MongoDB 7 (primary), Redis 7 (caching + task queue)                            |
| **Real-time**          | Flask-SocketIO 5.3, gevent-websocket                                           |
| **Search**             | Typesense (full-text with typo tolerance, tenant-isolated scoped keys)         |
| **Media**              | Cloudinary (images, video, audio)                                              |
| **Background Jobs**    | Flask-RQ2 (RQ 2.6)                                                             |
| **Push Notifications** | pywebpush (VAPID), firebase-admin (FCM)                                        |
| **Email**              | Flask-Mail (SMTP) with List-Unsubscribe headers                                |
| **Authentication**     | Flask-Login, Google OAuth2 (requests-oauthlib)                                 |
| **Encryption**         | Fernet (cryptography 46), PBKDF2-HMAC-SHA256                                   |
| **AI / Moderation**    | JigsawStack (NSFW detection, tag suggestions)                                  |
| **Markdown**           | Python-Markdown 3.10 + Bleach 6.3 sanitization                                 |
| **Payments**           | Paystack                                                                       |
| **Frontend**           | Jinja2 templates, vanilla JS, CSS                                              |
| **PWA**                | Service Worker, Web App Manifest, Web Share Target                             |
| **Native App**         | Capacitor (Android + iOS) with Jetpack Compose UI                              |
| **Scheduling**         | schedule library + custom scheduler.py                                         |
| **Deployment**         | Docker, CapRover, Render/Heroku Procfile                                       |
| **Monitoring**         | JSON-formatted rotating logs, ntfy push notifications, system health dashboard |
| **Linting**            | Flake8, Pylint, Prospector                                                     |

---

## Architecture

```
echowithin/
├── main.py              # Flask app init, config, MongoDB setup, helpers
├── api.py               # REST API blueprint (/api/v1/*) for mobile/native clients
├── blueprints/
│   ├── auth.py              # Registration, login, logout, Google OAuth, password reset
│   ├── pages.py             # Home, search, feed, offline, about, terms, FAQ, RSS
│   ├── blog.py              # Blog posts, comments, reactions, views, saves
│   ├── notes.py             # Personal space, note CRUD, search, merge, app lock
│   ├── sharing.py           # Shared notes, attachments, proposals, version history
│   ├── chat.py              # Direct messages, scheduled messages, reactions
│   ├── communities.py       # Communities, notes, challenges, reports
│   ├── admin.py             # Admin dashboard, user/post management, APK upload
│   ├── payments.py          # Paystack webhook, premium activation
│   ├── profile.py           # User profile, settings, data export
│   └── push.py              # Web Push subscribe/unsubscribe
├── wsgi.py              # WSGI entry point
├── config.py            # Environment variables, tier limits, feature flags
├── database.py          # MongoDB collection references
├── models.py            # User model, helpers
├── utils.py             # Shared utilities (encryption, media cleanup, timezone)
├── scripts/
│   ├── worker.py            # RQ background job worker
│   ├── scheduler.py         # Cron-style scheduler (log emails, newsletter, backups, etc.)
│   ├── backup_to_atlas.py   # Incremental MongoDB → Atlas backup sync
│   ├── weekly_achievements.py  # Weekly leaderboard calculation
│   ├── process_scheduled_messages.py  # Delivers due scheduled messages
│   ├── schedule_log_email.py    # Enqueues weekly log email job
│   ├── send_weekly_newsletter.py # Enqueues weekly newsletter job
│   └── cleanup_expired_auth.py   # Removes expired verification codes/tokens
├── templates/           # Jinja2 templates (44 files)
├── static/              # CSS, JS, service worker, PWA assets
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
- `scheduler`: Custom scheduler for periodic tasks

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

---

## API

A REST API is available at `/api/v1/*` for mobile/native app clients. Key endpoint groups:

| Group             | Endpoints                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Auth**          | `POST /register`, `POST /confirm/<email>`, `POST /login`, `POST /logout`, `POST /app_reauth`                           |
| **Notes**         | `GET /notes`, `GET /notes/<id>`, `GET /notes/content/<id>`, `POST /notes/create`, `POST /notes/edit/<id>`, `POST /notes/delete/<id>` |
| **Note Shares**   | `GET /notes/shares`, `GET /notes/shares/<id>`, `POST /notes/share/<id>`, `POST /notes/share/<id>/auto_approve`, `POST /notes/revoke_share/<id>` |
| **Note Previews** | `POST /notes/previews`                                                                                                 |
| **Note Dedup**    | `POST /notes/dedup`                                                                                                    |
| **Versions**      | `GET /notes/versions/<id>`, `POST /notes/version/restore/<id>/<ver>`                                                   |
| **Proposals**     | `GET /notes/proposals`, `POST /notes/proposal/<id>/decision`                                                           |
| **Sync**          | `POST /notes/<id>/sync`                                                                                                |
| **Lock**          | `POST /notes/toggle_lock/<id>`                                                                                         |
| **App Lock**      | `POST /app_lock/setup`, `POST /app_lock/verify`, `GET /app_lock/check_status`, `POST /app_lock/remove`                |
| **Activity**      | `GET /posts/my-commented`, `POST /posts/mark-all-read`, `POST /activity/mark_read`, `GET /notifications/badge-counts`  |
| **FCM**           | `POST /fcm/register`, `POST /fcm/unregister`                                                                           |
| **Premium**       | `POST /premium/activate`                                                                                               |
| **Profile**       | `GET /profile`                                                                                                         |
| **Collaboration** | `GET /notes/share/<id>/attachments`                                                                                    |

---

## Contributing

Contributions are welcome. Fork the repository and submit a pull request with a clear description of your changes. Please ensure code passes existing linting (`flake8`, `pylint`).

---

Built with care by the EchoWithin Team.
