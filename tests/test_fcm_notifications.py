import pytest
from bson.objectid import ObjectId
import datetime
from unittest.mock import MagicMock, patch
import main as m
import notifications
import database


def test_fcm_register_legacy_route(auth_client, mock_user):
    """Verify /api/fcm/register succeeds for authenticated client."""
    token_val = "fcm_test_device_token_legacy_123"
    with patch.object(m.fcm_tokens_conf, 'update_one') as mock_update:
        resp = auth_client.post(
            '/api/fcm/register',
            json={'token': token_val, 'platform': 'android'}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('success') is True
        mock_update.assert_called_once()
        filter_arg = mock_update.call_args[0][0]
        assert filter_arg['user_id'] == mock_user['_id']
        assert filter_arg['token'] == token_val


def test_fcm_register_api_v1_route(auth_client, mock_user):
    """Verify /api/v1/fcm/register succeeds under api_bp."""
    token_val = "fcm_test_device_token_v1_456"
    with patch.object(m.fcm_tokens_conf, 'update_one') as mock_update:
        resp = auth_client.post(
            '/api/v1/fcm/register',
            json={'token': token_val, 'platform': 'android'}
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('success') is True
        mock_update.assert_called_once()
        filter_arg = mock_update.call_args[0][0]
        assert filter_arg['user_id'] == mock_user['_id']
        assert filter_arg['token'] == token_val


def test_fcm_unregister_routes(auth_client, mock_user):
    """Verify /api/fcm/unregister and /api/v1/fcm/unregister delete tokens."""
    token_val = "token_to_unregister_1"
    with patch.object(m.fcm_tokens_conf, 'delete_one') as mock_delete:
        resp = auth_client.post(
            '/api/fcm/unregister',
            json={'token': token_val}
        )
        assert resp.status_code == 200
        mock_delete.assert_called_once_with({'user_id': mock_user['_id'], 'token': token_val})

    with patch.object(m.fcm_tokens_conf, 'delete_many') as mock_delete_many:
        resp2 = auth_client.post(
            '/api/v1/fcm/unregister',
            json={}
        )
        assert resp2.status_code == 200
        assert any(call[0][0] == {'user_id': mock_user['_id']} for call in mock_delete_many.call_args_list)


def test_send_fcm_notification_channel_and_string_data(mock_user):
    """Verify send_fcm_notification_to_user sets channel_id='echowithin_notifications' and stringifies data."""
    token_val = "fcm_test_device_token_mock_789"
    user_id_str = str(mock_user['_id'])

    tokens = [{'user_id': mock_user['_id'], 'token': token_val, 'platform': 'android'}]

    captured_messages = []
    fake_messaging = MagicMock()
    def mock_send(msg):
        captured_messages.append(msg)
        return "msg_id_123"
    fake_messaging.send = mock_send
    fake_messaging.Message = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.Notification = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.AndroidConfig = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.AndroidNotification = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.APNSConfig = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.APNSPayload = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.Aps = MagicMock(side_effect=lambda **kwargs: kwargs)
    fake_messaging.ApsAlert = MagicMock(side_effect=lambda **kwargs: kwargs)

    with patch.object(m, 'FIREBASE_INITIALIZED', True), \
         patch.object(notifications, 'messaging', fake_messaging), \
         patch.object(database.fcm_tokens_conf, 'find', return_value=tokens):

        # Note: data has non-string values: integer post_id and boolean
        sent = notifications.send_fcm_notification_to_user(
            user_id_str,
            title="Note Updated",
            body="Your note was updated",
            url="/personal_space",
            data={'note_id': 12345, 'is_updated': True}
        )

        assert sent == 1
        assert len(captured_messages) == 1
        msg = captured_messages[0]

        # Verify android notification channel
        android_config = msg['android']
        assert android_config['notification']['channel_id'] == 'echowithin_notifications'
        assert android_config['notification']['icon'] == 'ic_stat_notification'

        # Verify all values in data payload are strings
        for k, v in msg['data'].items():
            assert isinstance(k, str)
            assert isinstance(v, str)
        assert msg['data']['note_id'] == '12345'
        assert msg['data']['is_updated'] == 'True'
