# EchoWithin - A Community Discussion Platform

EchoWithin is a podcast group and community platform where the unspoken but real are uncovered. Built for authentic and real human perspective, we encourage meaningful debates and respectful engagement across all topics. At EchoWithin, we value original human thought and want your real ideas, experiences, and perspectives to echo within our community.

This web application, built with Flask and MongoDB, provides the digital space for this community to thrive.

## Features

- User Registration with password hashing
- User Login and Logout
- Community blog for posts and discussions
- Persistent user sessions using Flask-Login
- Protected routes accessible only to authenticated users
- Integration with MongoDB for data storage

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- [Python 3.7+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/) (Python package installer)
- [MongoDB](https://www.mongodb.com/try/download/community)

## Setup and Installation

Follow these steps to get your development environment set up and running.

**Overview**

EchoWithin is a Flask-based community blogging and discussion platform that focuses on creating a private, moderated space for people to share ideas, stories and media. The app uses MongoDB for persistence, Redis + RQ for background jobs, Cloudinary for media storage, and several integrations for email, OAuth, and automated moderation.

**Key Features**
- **Authentication:** Email confirmation, password hashing, Google OAuth.
- **Posts:** Create, edit, delete posts with images and short videos.
- **Comments:** Threaded comments stored in a local `comments` collection.
- **Background Processing:** Media upload, NSFW checks, and email notifications via RQ.
- **Admin Tools:** Manage users, posts and announcements.
- **Notifications:** Email and optional `ntfy` push notifications.

**Prerequisites**
- **Python 3.8+**
- **pip** (or Poetry/Poetry-managed environment)
- **MongoDB** (connection string required)
- **Redis** (for RQ background jobs)

**Quickstart — Development**

1. Clone the repository and enter the project directory:

```bash
git clone <your-repo-url>
cd echowithin
```

2. Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure environment variables. See the **Environment Variables** section below for the full list and a sample `.env`.

5. Start the app for local development:

```bash
# simple development run (uses main.py entrypoint)
python main.py

# OR run with Flask CLI if you prefer
export FLASK_APP=main.py
export FLASK_ENV=development
flask run
```

Note: The app sets `SESSION_COOKIE_SECURE=True` by default to protect cookies in production (HTTPS). For local HTTP development you may set `SESSION_COOKIE_SECURE=false` in your environment or run behind an HTTPS proxy.

**Environment Variables**
The application requires several environment variables. At minimum, for a basic local setup you should set:

- `SECRET` : Flask secret key (string)
- `MONGODB_CONNECTION` : MongoDB connection URI (e.g. `mongodb://localhost:27017`)
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` : Redis connection info (RQ)
- `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD` : SMTP settings for sending mail
- `TIME` : Rate limiter period (integer seconds used by `ratelimit` decorator)

Optional / integrations (recommended for full feature set):
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` : Google OAuth credentials
- `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` : Cloudinary media uploads
- `JIGSAW_API_KEY` : JigsawStack API key used for NSFW detection
- `MY_EMAIL` : Developer/system email used for admin log deliveries
- `NTFY_TOPIC`, `NTFY_USERNAME`, `NTFY_PASSWORD` : `ntfy` push notifications
- `REMARK42_HOST`, `REMARK42_SITE_ID`, `REMARK42_INTERNAL` : (legacy) remark42 settings if used

Sample `.env` contents (fill values appropriately):

```env
SECRET=replace-with-a-long-random-secret
MONGODB_CONNECTION=mongodb://localhost:27017/echowithin_db
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
MAIL_SERVER=smtp.example.com
MAIL_PORT=465
MAIL_USERNAME=you@example.com
MAIL_PASSWORD=supersecret
TIME=3600

# Optional integrations
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SECRET=
JIGSAW_API_KEY=
MY_EMAIL=dev@example.com
NTFY_TOPIC=

```

You can load these variables with a `.env` file and `python-dotenv` (already used by the app).

**Running background workers**
Many tasks (media processing, NSFW checks, email sends) run via RQ. To start a worker locally:

```bash
# Start a worker (ensure Redis is running and the env vars are set)
rq worker
```

Or use the included RQ integration with your process manager or systemd in production.

**Deployment**
- Production servers should use `gunicorn` and the `wsgi` module. Example (Procfile already included):

```bash
gunicorn wsgi:app --workers 3 --log-file -
```

- Make sure your production environment provides HTTPS so cookies, OAuth callbacks, and third-party integrations work correctly.

**Tests**
There are test files included (e.g. `test_e2e_comments.py`, `test_notification.py`). Run tests with `pytest`:

```bash
pip install -r requirements.txt
pytest -q
```

**Common Tips & Troubleshooting**
- If email sending fails, confirm SMTP credentials and that `MAIL_PORT`/`MAIL_USE_SSL` are correct.
- If background jobs don't run, confirm Redis is reachable and `REDIS_*` variables are correct.
- For local dev where you don't want to configure Cloudinary/SMTP, you can stub those integrations or set minimal environment values and use the UI with limited functionality.

**Contributing**
- Fork the repo, create a feature branch, and open a PR with a clear description. Run tests and keep changes small and focused.

**Files of interest**
- `main.py` : Primary Flask app and routes
- `wsgi.py` : WSGI entry for production
- `requirements.txt` : Python dependencies
- `templates/` and `static/` : UI templates and assets

If you want, I can also:
- Add a minimal `docker-compose.yml` to run MongoDB + Redis + the app for local development
- Generate a `.env.example` with the variables listed above

---
Updated README created to reflect current project layout and runtime requirements.