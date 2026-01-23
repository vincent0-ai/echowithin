# EchoWithin — A Community Discussion Platform

EchoWithin is a high-performance community blogging and discussion platform designed for authentic, deep engagement. It provides a private, moderated space for users to share long-form content, multimedia, and encrypted personal notes.

Built with a modern Python stack and a mobile-first Progressive Web App (PWA) approach, EchoWithin ensures your community's voice echoes with clarity and security.

---

## 🚀 Key Features

### 📝 Content & Community
- **Rich Blogging**: Create and edit posts with Markdown support, multiple images, and videos.
- **Threaded Discussions**: Engaging, hierarchical comment system with voting and real-time activity tracking.
- **Personal Space**: A private repository for saved posts and **end-to-end encrypted** personal notes.
- **Engagement Tools**: Multiple reaction types (Heart, Wow, Insightful, etc.) and native sharing integration.

### 📱 Modern Experience (PWA)
- **Installable**: Full Progressive Web App support for Android and iOS.
- **Offline Mode**: Access cached content and a dedicated offline fallback page.
- **Push Notifications**: Real-time web push notifications for comments and replies, with specialized "Marker Leap" logic to ensure read-state synchronization.

### 🛡️ Safety & Security
- **AI Moderation**: Automatic NSFW detection for all uploaded images via JigsawStack.
- **Secure Authentication**: Email verification, session persistence, and Google OAuth2 integration.
- **Rate Limiting**: Intelligent protection against brute-force and spam across all critical endpoints.

### 🔍 Discovery & SEO
- **Blazing Fast Search**: Full-text search powered by Meilisearch with real-time indexing.
- **Automated SEO**: Dynamic `sitemap.xml`, `robots.txt`, and rich OpenGraph/Twitter meta tags.
- **Newsletter**: Weekly automated digests of the most popular community content.

---

## 🛠️ Technical Stack

- **Backend**: Python 3.8+, Flask, Gunicorn
- **Database**: MongoDB (Persistence), Redis (Caching & Task Queue)
- **Background Jobs**: Flask-RQ2 for asynchronous media processing and notifications.
- **Search Engine**: Meilisearch
- **Integrations**:
  - **Cloudinary**: Cloud-based image and video management.
  - **JigsawStack**: AI-powered content safety.
  - **Mailgun/SMTP**: Transactional and newsletter email delivery.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.8+
- MongoDB instance (Atlas or local)
- Redis server
- Meilisearch instance

### 2. Quickstart
```bash
# Clone the repository
git clone <repo-url>
cd echowithin

# Install dependencies
pip install -r requirements.txt

# Configure environment (see below)
cp .env.example .env

# Run the application
python main.py
```

### 3. Environment Variables
The application requires the following core variables:

| Variable | Description |
|----------|-------------|
| `SECRET` | Flask secret key for sessions and CSRF. |
| `MONGODB_CONNECTION` | Your MongoDB URI. |
| `REDIS_HOST`, `REDIS_PORT` | Redis connection details. |
| `GOOGLE_CLIENT_ID/SECRET` | For Google OAuth login. |
| `CLOUDINARY_*` | API keys for media storage. |
| `JIGSAW_API_KEY` | For AI content moderation. |
| `VAPID_PUBLIC/PRIVATE_KEY`| For Web Push notifications. |

---

## 🏗️ Deployment
Professional deployment is handled via Gunicorn. A `Procfile` is included for compatibility with platforms like Heroku or Render.

```bash
gunicorn wsgi:app --workers 3 --bind 0.0.0.0:$PORT
```

---

## 🤝 Contributing
We value original human thought. If you'd like to contribute, please fork the repository and submit a pull request with a clear description of your changes.

---
*Built with ❤️ by the EchoWithin Team.*