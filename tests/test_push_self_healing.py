import datetime
from bson.objectid import ObjectId
from unittest.mock import patch, MagicMock
import pytest
import database
import main as m
from utils import _remove_stale_push_subscription


def test_remove_stale_push_subscription_records_revocation():
    sub_doc = {
        '_id': ObjectId(),
        'user_id': ObjectId(),
        'endpoint': 'https://fcm.googleapis.com/fcm/send/dead-token-123',
        'keys': {'p256dh': 'key', 'auth': 'auth'}
    }
    mock_push_conf = MagicMock()
    mock_revoked_conf = MagicMock()

    with patch.object(database, 'push_subscriptions_conf', mock_push_conf), \
         patch.object(database, 'revoked_push_endpoints_conf', mock_revoked_conf):
        _remove_stale_push_subscription(sub_doc, 'non-iOS', 'test_user', 'status=410')

        mock_push_conf.delete_one.assert_called_once_with({'_id': sub_doc['_id']})
        mock_revoked_conf.update_one.assert_called_once()
        args, kwargs = mock_revoked_conf.update_one.call_args
        assert args[0] == {'endpoint': sub_doc['endpoint']}
        assert args[1]['$set']['reason'] == 'status=410'
        assert args[1]['$set']['platform'] == 'non-iOS'
        assert kwargs.get('upsert') is True


def test_push_status_with_valid_endpoint(auth_client, mock_user):
    test_endpoint = 'https://fcm.googleapis.com/fcm/send/valid-endpoint'
    mock_push_conf = MagicMock()
    mock_push_conf.count_documents.return_value = 1
    mock_push_conf.find_one.return_value = {'endpoint': test_endpoint, 'user_id': mock_user['_id']}

    with patch.object(m, 'push_subscriptions_conf', mock_push_conf):
        resp = auth_client.get(f'/api/push/status?endpoint={test_endpoint}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['subscribed'] is True
        assert data['endpoint_valid'] is True
        assert data['force_new'] is False


def test_push_status_with_revoked_endpoint(auth_client, mock_user):
    test_endpoint = 'https://fcm.googleapis.com/fcm/send/revoked-endpoint'
    mock_push_conf = MagicMock()
    mock_push_conf.count_documents.return_value = 0
    mock_push_conf.find_one.return_value = None

    mock_revoked_conf = MagicMock()
    mock_revoked_conf.find_one.return_value = {'endpoint': test_endpoint, 'reason': 'status=410'}

    with patch.object(m, 'push_subscriptions_conf', mock_push_conf), \
         patch.object(m, 'revoked_push_endpoints_conf', mock_revoked_conf):
        resp = auth_client.get(f'/api/push/status?endpoint={test_endpoint}')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['endpoint_valid'] is False
        assert data['force_new'] is True


def test_push_subscribe_blocks_revoked_endpoint(auth_client, mock_user):
    test_endpoint = 'https://fcm.googleapis.com/fcm/send/revoked-endpoint'
    mock_revoked_conf = MagicMock()
    mock_revoked_conf.find_one.return_value = {'endpoint': test_endpoint, 'reason': 'status=403 after 3 consecutive failures'}

    with patch.object(m, 'VAPID_PUBLIC_KEY', 'dummy-pub'), \
         patch.object(m, 'VAPID_PRIVATE_KEY', 'dummy-priv'), \
         patch.object(m, 'is_same_origin_request', return_value=True), \
         patch.object(m, 'revoked_push_endpoints_conf', mock_revoked_conf):
        resp = auth_client.post('/api/push/subscribe', json={
            'endpoint': test_endpoint,
            'keys': {'p256dh': 'test', 'auth': 'test'}
        })
        assert resp.status_code == 410
        data = resp.get_json()
        assert data.get('force_new') is True
