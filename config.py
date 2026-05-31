import datetime
import re
import os
from dotenv import load_dotenv

load_dotenv(override=True)

ENGAGEMENT_WEIGHTS = {
    'comment': 5.0,
    'reaction': 3.0,
    'share': 4.0,
    'view': 0.1
}

def clean_xml_text(text):
    """
    Removes characters that are illegal in XML 1.0 (control characters).
    XML 1.0 allows: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    """
    if not text:
        return ""
    illegal_xml_chars_re = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')
    return illegal_xml_chars_re.sub('', str(text))

def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        message = f"Expected environment variable '{name}' not set."
        raise Exception(message)

# Google OAuth configuration
GOOGLE_CLIENT_ID = get_env_variable('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = get_env_variable('GOOGLE_CLIENT_SECRET')

# Configuration for file uploads (now handled by Cloudinary)
# UPLOAD_FOLDER is kept for backward compatibility with old posts.
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg', 'mov', 'm4v', 'avi', 'mkv'}
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'm4a', 'aac'}
MAX_VIDEO_SIZE = 50 * 1024 * 1024  # 50 MB limit for uploaded videos
MAX_IMAGE_SIZE = 5 * 1024 * 1024   # 5 MB limit per uploaded image

# --- Temporary Uploads for Background Processing ---
TEMP_UPLOAD_FOLDER = 'temp_uploads'

# --- VAPID Configuration for Web Push Notifications ---
# Generate these keys using: vapid --gen or use an online generator
# Store the private key securely and share the public key with clients
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '').strip()
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '').strip()

# Firebase Admin SDK for FCM (native app push notifications)
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False

# Configure Redis connection for RQ background jobs
REDIS_HOST = get_env_variable('REDIS_HOST')
REDIS_PORT = get_env_variable('REDIS_PORT')
REDIS_PASSWORD = get_env_variable('REDIS_PASSWORD') # Password can be optional

TIME = int(get_env_variable('TIME'))

# Rate limit bypass for LOCAL testing only (never enable in production)
_bypass_env = os.environ.get('BYPASS_RATE_LIMIT', '').lower()
BYPASS_RATE_LIMIT = _bypass_env in ('1', 'true', 'yes') and os.environ.get('FLASK_ENV') == 'development'

# --- Encryption utilities for personal notes ---
# v2: Per-user key derivation with increased iterations (OWASP 2024 recommendation).
# Backward-compatible: falls back to v1 global key for notes encrypted before the upgrade.
_NOTES_KDF_ITERATIONS = 480000  # OWASP minimum for PBKDF2-HMAC-SHA256
_NOTES_V1_SALT = b'echowithin_notes_salt_v1'  # legacy global salt

TIER_LIMITS = {
    'free': {
        'max_notes': 50,
        'max_chars_per_note': 20000,
        'max_share_links_per_note': 3,
        'max_surprise_notes': 20,         # total surprise notes (shared with theme)
        'note_locking': False,
        'blog_space': False,
        'scheduled_messages': False,
        'note_media_attachments': False,
        'max_note_attachments': 0,
        'voice_messages': True,             # voice messages are free for all users
        'version_history_days': 7,
        'auto_approve_collab': False,
        'max_communities': 1,               # free users can create 1 community
    },
    'premium': {
        'max_notes': 99999,               # effectively unlimited
        'max_chars_per_note': 100000,
        'max_share_links_per_note': 99999, # effectively unlimited
        'max_surprise_notes': 99999,
        'note_locking': True,
        'blog_space': True,
        'scheduled_messages': True,
        'note_media_attachments': True,
        'max_note_attachments': 20,
        'voice_messages': True,
        'version_history_days': 365,
        'auto_approve_collab': True,
        'max_communities': 5,               # premium users can create up to 5 communities
    }
}

PREMIUM_TRIAL_DAYS = 1
PREMIUM_PRICE_KSH = 50  # per month

PREDEFINED_TAGS = [
    # General Topics
    'Education', 'Law', 'Politics', 'Business', 'Science',
    'Philosophy', 'History', 'Environment', 'Announcement',
    # Tech & Innovation
    'Technology', 'Programming', 'Cybersecurity',
    # Vibe & Tone
    'Motivation', 'Meme', 'Rant', 'Opinion', 'Storytime',
    'Deep Dive', 'Quick Read', 'Advice', 'How To',
    # Lifestyle & Student Life
    'University Life', 'Productivity', 'Mental Health', 'Career',
    'Health', 'Finance', 'Relationships', 'Gaming', 'Music',
    'Art', 'Sports', 'Travel', 'Food', 'Entertainment',
]

# Expanded keyword map for NLP fallback — maps keywords/phrases to predefined tags
_TAG_KEYWORDS = {
    'Education': ['education', 'school', 'learn', 'study', 'student', 'academic', 'course', 'class', 'lecture', 'exam', 'degree', 'teacher', 'professor', 'curriculum', 'scholarship'],
    'Law': ['law', 'legal', 'court', 'judge', 'attorney', 'lawyer', 'justice', 'constitution', 'legislation', 'rights', 'criminal', 'civil', 'statute'],
    'Politics': ['politics', 'political', 'government', 'election', 'democracy', 'policy', 'vote', 'congress', 'parliament', 'president', 'campaign', 'senator'],
    'Business': ['business', 'company', 'startup', 'entrepreneur', 'market', 'revenue', 'profit', 'invest', 'economy', 'commerce', 'corporate', 'trade', 'management'],
    'Science': ['science', 'scientific', 'research', 'experiment', 'biology', 'chemistry', 'physics', 'theory', 'hypothesis', 'lab', 'discovery', 'atom', 'molecule'],
    'Philosophy': ['philosophy', 'philosophical', 'ethics', 'morality', 'existential', 'meaning', 'truth', 'logic', 'consciousness', 'metaphysics', 'epistemology'],
    'History': ['history', 'historical', 'ancient', 'century', 'civilization', 'war', 'empire', 'dynasty', 'revolution', 'colonial', 'medieval'],
    'Environment': ['environment', 'climate', 'pollution', 'sustainability', 'ecology', 'green', 'carbon', 'renewable', 'conservation', 'recycle', 'deforestation'],
    'Announcement': ['announcement', 'announce', 'update', 'notice', 'official', 'launching', 'introducing', 'new feature', 'release'],
    'Technology': ['technology', 'tech', 'software', 'hardware', 'computer', 'digital', 'internet', 'app', 'device', 'innovation', 'ai', 'artificial intelligence', 'machine learning', 'data'],
    'Programming': ['programming', 'code', 'coding', 'developer', 'python', 'javascript', 'java', 'api', 'framework', 'debug', 'algorithm', 'frontend', 'backend', 'database', 'git', 'html', 'css', 'react', 'flask', 'django', 'node'],
    'Cybersecurity': ['cybersecurity', 'security', 'hack', 'hacker', 'vulnerability', 'encryption', 'malware', 'firewall', 'phishing', 'breach', 'password', 'cyber'],
    'Motivation': ['motivation', 'motivate', 'inspire', 'inspiration', 'dream', 'goal', 'success', 'achieve', 'believe', 'never give up', 'keep going', 'hustle', 'grind', 'determination'],
    'Meme': ['meme', 'funny', 'lol', 'lmao', 'humor', 'joke', 'hilarious', 'comedy', 'sarcasm'],
    'Rant': ['rant', 'frustrated', 'annoyed', 'angry', 'fed up', 'sick of', 'tired of', 'ridiculous', 'unacceptable', 'complaint'],
    'Opinion': ['opinion', 'think', 'believe', 'perspective', 'view', 'stance', 'take', 'unpopular opinion', 'hot take', 'controversial'],
    'Storytime': ['storytime', 'story time', 'story', 'happened to me', 'experience', 'let me tell you', 'true story', 'once upon', 'anecdote'],
    'Deep Dive': ['deep dive', 'in-depth', 'analysis', 'breakdown', 'comprehensive', 'detailed', 'explore', 'thorough', 'investigation'],
    'Quick Read': ['quick read', 'short', 'brief', 'quick', 'summary', 'tldr', 'tl;dr', 'in a nutshell', 'overview'],
    'Advice': ['advice', 'tip', 'tips', 'recommend', 'suggestion', 'guide', 'help', 'how to deal', 'what to do', 'should you'],
    'How To': ['how to', 'tutorial', 'step by step', 'guide', 'walkthrough', 'instructions', 'setup', 'install', 'configure', 'build'],
    'University Life': ['university', 'college', 'campus', 'dorm', 'freshman', 'semester', 'gpa', 'major', 'minor', 'lecture hall', 'roommate', 'sorority', 'fraternity'],
    'Productivity': ['productivity', 'productive', 'efficiency', 'time management', 'organize', 'focus', 'habit', 'routine', 'workflow', 'planner', 'prioritize'],
    'Mental Health': ['mental health', 'anxiety', 'depression', 'stress', 'therapy', 'therapist', 'self care', 'self-care', 'wellbeing', 'burnout', 'overwhelm', 'mindfulness', 'meditation'],
    'Career': ['career', 'job', 'interview', 'resume', 'cv', 'hire', 'salary', 'promotion', 'internship', 'profession', 'workplace', 'linkedin', 'networking'],
    'Health': ['health', 'healthy', 'fitness', 'exercise', 'workout', 'diet', 'nutrition', 'medical', 'doctor', 'hospital', 'disease', 'wellness', 'vitamin'],
    'Finance': ['finance', 'financial', 'money', 'budget', 'saving', 'invest', 'stock', 'crypto', 'debt', 'loan', 'income', 'expense', 'bank', 'wealth'],
    'Relationships': ['relationship', 'dating', 'love', 'partner', 'breakup', 'marriage', 'couple', 'romance', 'friendship', 'toxic', 'trust', 'communication'],
    'Gaming': ['gaming', 'game', 'gamer', 'playstation', 'xbox', 'nintendo', 'pc gaming', 'esports', 'fps', 'rpg', 'multiplayer', 'steam', 'twitch', 'fortnite', 'valorant'],
    'Music': ['music', 'song', 'album', 'artist', 'concert', 'playlist', 'genre', 'rap', 'hip hop', 'rock', 'pop', 'beat', 'melody', 'spotify'],
    'Art': ['art', 'artist', 'painting', 'drawing', 'sculpture', 'design', 'creative', 'illustration', 'gallery', 'aesthetic', 'canvas', 'sketch'],
    'Sports': ['sports', 'football', 'soccer', 'basketball', 'tennis', 'cricket', 'athlete', 'team', 'match', 'tournament', 'championship', 'league', 'trophy', 'coach'],
    'Travel': ['travel', 'trip', 'vacation', 'holiday', 'destination', 'flight', 'hotel', 'backpack', 'explore', 'adventure', 'tourist', 'passport', 'abroad'],
    'Food': ['food', 'recipe', 'cook', 'cooking', 'meal', 'restaurant', 'eat', 'delicious', 'cuisine', 'ingredient', 'bake', 'chef', 'snack', 'breakfast', 'dinner', 'lunch'],
    'Entertainment': ['entertainment', 'movie', 'film', 'tv', 'show', 'series', 'netflix', 'anime', 'drama', 'celebrity', 'streaming', 'trailer', 'review', 'podcast'],
}
