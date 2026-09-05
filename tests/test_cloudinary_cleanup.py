import datetime
import pytest
from unittest.mock import patch, MagicMock, call
from bson.objectid import ObjectId

import security
import utils


class TestCloudinaryDestroyHelper:
    def test_destroy_empty_or_invalid_public_id(self, app):
        with app.app_context():
            assert security.destroy_cloudinary_media(None) is False
            assert security.destroy_cloudinary_media('') is False
            assert security.destroy_cloudinary_media('   ') is False
            assert security.destroy_cloudinary_media(123) is False

    def test_destroy_success(self, app):
        with app.app_context():
            with patch('cloudinary.uploader.destroy', return_value={'result': 'ok'}) as mock_destroy:
                res = security.destroy_cloudinary_media('sample_id', resource_type='raw', delivery_type='authenticated')
                assert res is True
                mock_destroy.assert_called_once_with('sample_id', resource_type='raw', type='authenticated', invalidate=True)

    def test_destroy_fallback_on_not_found(self, app):
        with app.app_context():
            # First call returns 'not found', subsequent fallback returns 'ok'
            destroy_results = [
                {'result': 'not found'},
                {'result': 'ok'}
            ]
            with patch('cloudinary.uploader.destroy', side_effect=destroy_results) as mock_destroy:
                res = security.destroy_cloudinary_media('legacy_sample', resource_type='raw', delivery_type='authenticated')
                assert res is True
                assert mock_destroy.call_count == 2
                # Verify fallback was attempted
                calls = mock_destroy.call_args_list
                assert calls[0] == call('legacy_sample', resource_type='raw', type='authenticated', invalidate=True)
                assert calls[1] == call('legacy_sample', resource_type='raw', type='upload', invalidate=True)

    def test_destroy_exception_never_raises(self, app):
        with app.app_context():
            with patch('cloudinary.uploader.destroy', side_effect=Exception('Cloudinary network timeout')):
                res = security.destroy_cloudinary_media('failing_id')
                assert res is False


class TestExtractCloudinaryPublicId:
    def test_extract_from_standard_url(self):
        url = "https://res.cloudinary.com/ds6ncvcr7/image/upload/v1747714395/dm_images/fan7frsmy47zqihaeqyi.jpg"
        assert utils.extract_cloudinary_public_id(url) == "dm_images/fan7frsmy47zqihaeqyi"

    def test_extract_from_authenticated_url(self):
        url = "https://res.cloudinary.com/ds6ncvcr7/raw/authenticated/s--abc123--/v1747714395/dm_images/wijteiguodcenp3bevbn"
        assert utils.extract_cloudinary_public_id(url) == "dm_images/wijteiguodcenp3bevbn"

    def test_extract_from_transformed_video_url(self):
        url = "https://res.cloudinary.com/ds6ncvcr7/video/upload/c_fill,w_300/v1747714395/dm_voice/rcugckeccvpsv9zahfhc.mp4"
        assert utils.extract_cloudinary_public_id(url) == "dm_voice/rcugckeccvpsv9zahfhc"

    def test_extract_from_media_proxy_url(self):
        url = "https://echowithin.xyz/serve_encrypted_media/dm_images%2Fwijteiguodcenp3bevbn?mime=image%2Fjpeg&sig=123"
        assert utils.extract_cloudinary_public_id(url) == "dm_images/wijteiguodcenp3bevbn"

    def test_extract_invalid_or_none(self):
        assert utils.extract_cloudinary_public_id(None) is None
        assert utils.extract_cloudinary_public_id('') is None
        assert utils.extract_cloudinary_public_id('https://google.com/image.png') is None


class TestChatMediaDeletion:
    def test_api_delete_message_destroys_media(self, app):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.chat import api_delete_message

        user_oid = ObjectId()
        recipient_oid = ObjectId()
        msg_oid = ObjectId()

        raw_pub = 'dm_images/test_encrypted_pub'
        encrypted_pub = security.encrypt_dm(raw_pub, str(user_oid), str(recipient_oid))

        msg_doc = {
            '_id': msg_oid,
            'sender_id': user_oid,
            'recipient_id': recipient_oid,
            'content': 'hello',
            'image_public_id': encrypted_pub,
            'media_encrypted': True,
            'timestamp': datetime.datetime.now(datetime.timezone.utc)
        }

        user_doc = {
            '_id': user_oid,
            'username': 'testuser',
            'email': 'testuser@example.com',
            'is_confirmed': True,
            'is_admin': False
        }

        with app.test_request_context():
            login_user(User(user_doc))
            with patch.object(m, 'direct_messages_conf') as mock_dms, \
                 patch.object(m, 'destroy_cloudinary_media') as mock_destroy, \
                 patch('utils.backup_before_delete'):

                mock_dms.find_one.return_value = msg_doc

                res = api_delete_message(str(msg_oid))
                assert res.status_code == 200
                mock_destroy.assert_called_once_with(raw_pub, resource_type='raw', delivery_type='authenticated')
                mock_dms.delete_one.assert_called_once_with({'_id': msg_oid})

    def test_api_delete_message_fallback_to_image_url(self, app):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.chat import api_delete_message

        user_oid = ObjectId()
        recipient_oid = ObjectId()
        msg_oid = ObjectId()

        raw_url = 'https://res.cloudinary.com/test-cloud/image/upload/v12345/dm_images/fallback_img.jpg'
        encrypted_url = security.encrypt_dm(raw_url, str(user_oid), str(recipient_oid))

        msg_doc = {
            '_id': msg_oid,
            'sender_id': user_oid,
            'recipient_id': recipient_oid,
            'content': '',
            'image_url': encrypted_url,
            'media_encrypted': False,
            'message_type': 'image',
            'timestamp': datetime.datetime.now(datetime.timezone.utc)
        }

        user_doc = {
            '_id': user_oid,
            'username': 'testuser',
            'email': 'testuser@example.com',
            'is_confirmed': True,
            'is_admin': False
        }

        with app.test_request_context():
            login_user(User(user_doc))
            with patch.object(m, 'direct_messages_conf') as mock_dms, \
                 patch.object(m, 'destroy_cloudinary_media') as mock_destroy, \
                 patch('utils.backup_before_delete'):

                mock_dms.find_one.return_value = msg_doc

                res = api_delete_message(str(msg_oid))
                assert res.status_code == 200
                mock_destroy.assert_called_once_with('dm_images/fallback_img', resource_type='image', delivery_type='upload')


class TestWhisperMediaCleanup:
    def test_cleanup_whisper_session_media(self, app):
        import main as m
        from blueprints.whisper import _cleanup_whisper_session_media

        sess_oid = ObjectId()
        u1_oid = ObjectId()
        u2_oid = ObjectId()

        session_doc = {
            '_id': sess_oid,
            'initiator_id': u1_oid,
            'recipient_id': u2_oid,
            'status': 'expired'
        }

        raw_pub = 'whisper_images/secret_pic'
        enc_pub = security.encrypt_dm(raw_pub, str(u1_oid), str(u2_oid))

        whisper_msgs = [
            {
                '_id': ObjectId(),
                'session_id': sess_oid,
                'image_public_id': enc_pub,
                'media_encrypted': True
            }
        ]

        with app.app_context(), \
             patch.object(m, 'whisper_sessions_conf') as mock_sess, \
             patch.object(m, 'whisper_messages_conf') as mock_msgs, \
             patch.object(m, 'destroy_cloudinary_media') as mock_destroy:

            mock_sess.find_one.return_value = session_doc
            mock_msgs.find.return_value = whisper_msgs

            _cleanup_whisper_session_media(str(sess_oid), session_doc)
            mock_destroy.assert_called_once_with(raw_pub, resource_type='raw', delivery_type='authenticated')

    def test_whisper_view_once_burn_destroys_media(self, app):
        import main as m
        from main import User
        from flask_login import login_user
        from blueprints.whisper import api_whisper_view_once_burn

        sess_oid = ObjectId()
        msg_oid = ObjectId()
        u1_oid = ObjectId()
        u2_oid = ObjectId()

        session_doc = {
            '_id': sess_oid,
            'initiator_id': u1_oid,
            'recipient_id': u2_oid,
            'status': 'active'
        }

        raw_pub = 'whisper_images/view_once_pic'
        enc_pub = security.encrypt_dm(raw_pub, str(u1_oid), str(u2_oid))

        msg_doc = {
            '_id': msg_oid,
            'session_id': sess_oid,
            'view_once': True,
            'image_public_id': enc_pub,
            'media_encrypted': True
        }

        user_doc = {
            '_id': u1_oid,
            'username': 'u1',
            'email': 'u1@example.com',
            'is_confirmed': True,
            'is_admin': False
        }

        with app.test_request_context():
            login_user(User(user_doc))
            with patch.object(m, 'whisper_sessions_conf') as mock_sess, \
                 patch.object(m, 'whisper_messages_conf') as mock_msgs, \
                 patch.object(m, 'destroy_cloudinary_media') as mock_destroy, \
                 patch.object(m.socketio, 'emit'):

                mock_msgs.find_one.return_value = msg_doc
                mock_sess.find_one.return_value = session_doc

                res = api_whisper_view_once_burn(str(msg_oid))
                assert res.status_code == 200
                mock_destroy.assert_called_once_with(raw_pub, resource_type='raw', delivery_type='authenticated')
                mock_msgs.update_one.assert_called_once()
                update_call = mock_msgs.update_one.call_args[0]
                assert '$unset' in update_call[1]
                assert update_call[1]['$set']['view_once_destroyed'] is True
