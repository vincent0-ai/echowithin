import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('SECRET', 'test-secret-key-for-pytest')
os.environ.setdefault('MONGODB_CONNECTION', 'mongodb://localhost:27017')
os.environ.setdefault('REDIS_HOST', 'localhost')
os.environ.setdefault('REDIS_PORT', '6379')
os.environ.setdefault('REDIS_PASSWORD', '')
os.environ.setdefault('MAIL_SERVER', 'smtp.example.com')
os.environ.setdefault('MAIL_PORT', '587')
os.environ.setdefault('MAIL_USERNAME', 'test@example.com')
os.environ.setdefault('MAIL_PASSWORD', 'test-password')
os.environ.setdefault('CLOUDINARY_CLOUD_NAME', 'test-cloud')
os.environ.setdefault('CLOUDINARY_API_KEY', 'test-key')
os.environ.setdefault('CLOUDINARY_API_SECRET', 'test-secret')
os.environ.setdefault('JIGSAW_API_KEY', 'test-jigsaw-key')
os.environ.setdefault('GOOGLE_CLIENT_ID', 'test-google-id.apps.googleusercontent.com')
os.environ.setdefault('GOOGLE_CLIENT_SECRET', 'test-google-secret')
os.environ.setdefault('TIME', '3600')
os.environ.setdefault('MEILI_URL', '')
os.environ.setdefault('MEILI_MASTER_KEY', '')
os.environ.setdefault('FLASK_ENV', 'development')
os.environ.setdefault('BYPASS_RATE_LIMIT', 'true')

import gevent.monkey


@pytest.fixture(scope='session', autouse=True)
def _session_mocks():
    _patches = []
    _patches.append(patch.object(gevent.monkey, 'patch_all', new=lambda **kw: None))
    _patches.append(patch('pymongo.MongoClient', autospec=True))
    _patches.append(patch('redis.Redis', autospec=True))
    _patches.append(patch('redis.from_url', autospec=True))
    _patches.append(patch('flask_mail.Mail.send', autospec=True))
    _patches.append(patch('flask_mail.Mail.connect', autospec=True))
    _patches.append(patch('flask_socketio.SocketIO', autospec=True))
    _patches.append(patch('cloudinary.uploader.upload', autospec=True))
    _patches.append(patch('cloudinary.uploader.destroy', autospec=True))
    _patches.append(patch('cloudinary.uploader.add_tag', autospec=True))
    _patches.append(patch('cloudinary.config', autospec=True))
    _patches.append(patch('meilisearch.Client', autospec=True))
    _patches.append(patch('pywebpush.webpush', autospec=True))
    _patches.append(patch('requests.get', autospec=True))
    _patches.append(patch('requests.post', autospec=True))
    _patches.append(patch.dict('sys.modules', {
        'firebase_admin': MagicMock(),
        'firebase_admin.credentials': MagicMock(),
        'firebase_admin.messaging': MagicMock(),
    }))
    for p in _patches:
        p.start()
    yield
    for p in _patches:
        p.stop()


@pytest.fixture(scope='session')
def app():
    from main import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SERVER_NAME'] = 'echowithin.xyz'
    flask_app.config['PREFERRED_URL_SCHEME'] = 'https'
    from flask_login import LoginManager
    if isinstance(flask_app.login_manager, LoginManager):
        flask_app.login_manager.login_view = None
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def https_client(app):
    tc = app.test_client()
    original_open = tc.open
    def https_open(*args, **kwargs):
        if 'environ_base' not in kwargs:
            kwargs['environ_base'] = {}
        kwargs['environ_base'].setdefault('wsgi.url_scheme', 'https')
        kwargs['environ_base'].setdefault('HTTP_X_FORWARDED_PROTO', 'https')
        return original_open(*args, **kwargs)
    tc.open = https_open
    return tc
