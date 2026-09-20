import pytest
import io
import datetime
from unittest.mock import patch, MagicMock
from bson.objectid import ObjectId
import database
from blueprints.vault import _hash_pin, _verify_pin


def test_hash_and_verify_pin():
    pin = "1234"
    h, salt = _hash_pin(pin)
    assert isinstance(h, str) and len(h) == 64
    assert isinstance(salt, bytes) and len(salt) == 16
    assert _verify_pin("1234", h, salt) is True
    assert _verify_pin("9999", h, salt) is False
    assert _verify_pin("12345", h, salt) is False


def test_vault_status_no_pin(auth_client, mock_user):
    user_doc = dict(mock_user)
    with patch.object(database.users_conf, 'find_one', return_value=user_doc):
        r = auth_client.get('/api/vault/status')
        assert r.status_code == 200
        data = r.get_json()
        assert data['has_pin'] is False
        assert data['unlocked'] is False


def test_vault_status_with_pin_locked(auth_client, mock_user):
    h, salt = _hash_pin("1234")
    user_doc = dict(mock_user)
    user_doc['vault_pin_hash'] = h
    user_doc['vault_pin_salt'] = salt
    with patch.object(database.users_conf, 'find_one', return_value=user_doc):
        r = auth_client.get('/api/vault/status')
        assert r.status_code == 200
        data = r.get_json()
        assert data['has_pin'] is True
        assert data['unlocked'] is False


def test_vault_setup_pin_validation(auth_client, mock_user):
    user_doc = dict(mock_user)
    with patch.object(database.users_conf, 'find_one', return_value=user_doc):
        # Short PIN
        r = auth_client.post('/api/vault/setup-pin', json={'pin': '12', 'confirm': '12'})
        assert r.status_code == 400
        assert 'digits' in r.get_json()['error']

        # Non-numeric PIN
        r = auth_client.post('/api/vault/setup-pin', json={'pin': 'abcd', 'confirm': 'abcd'})
        assert r.status_code == 400

        # Mismatched PIN
        r = auth_client.post('/api/vault/setup-pin', json={'pin': '1234', 'confirm': '5678'})
        assert r.status_code == 400
        assert 'match' in r.get_json()['error']


def test_vault_setup_pin_success(auth_client, mock_user):
    user_doc = dict(mock_user)
    with patch.object(database.users_conf, 'find_one', return_value=user_doc), \
         patch.object(database.users_conf, 'update_one') as mock_update:
        r = auth_client.post('/api/vault/setup-pin', json={'pin': '1234', 'confirm': '1234'})
        assert r.status_code == 200
        assert r.get_json()['success'] is True
        mock_update.assert_called_once()
        update_args = mock_update.call_args[0][1]['$set']
        assert 'vault_pin_hash' in update_args
        assert 'vault_pin_salt' in update_args
        assert 'vault_pin_set_at' in update_args


def test_vault_unlock_success_and_lock(auth_client, mock_user):
    h, salt = _hash_pin("4321")
    user_doc = dict(mock_user)
    user_doc['vault_pin_hash'] = h
    user_doc['vault_pin_salt'] = salt

    with patch.object(database.users_conf, 'find_one', return_value=user_doc):
        # Incorrect PIN
        r = auth_client.post('/api/vault/unlock', json={'pin': '0000'})
        assert r.status_code == 403

        # Correct PIN
        r = auth_client.post('/api/vault/unlock', json={'pin': '4321'})
        assert r.status_code == 200
        assert r.get_json()['success'] is True

        # Check status now reports unlocked
        r_status = auth_client.get('/api/vault/status')
        assert r_status.get_json()['unlocked'] is True

        # Lock vault
        r_lock = auth_client.post('/api/vault/lock')
        assert r_lock.status_code == 200
        assert r_lock.get_json()['success'] is True

        # Check status is locked again
        r_status2 = auth_client.get('/api/vault/status')
        assert r_status2.get_json()['unlocked'] is False


def test_vault_change_pin(auth_client, mock_user):
    h, salt = _hash_pin("1111")
    user_doc = dict(mock_user)
    user_doc['vault_pin_hash'] = h
    user_doc['vault_pin_salt'] = salt

    with patch.object(database.users_conf, 'find_one', return_value=user_doc):
        # Attempt change while locked -> 403
        r = auth_client.post('/api/vault/change-pin', json={'current_pin': '1111', 'new_pin': '2222', 'confirm': '2222'})
        assert r.status_code == 403

        # Unlock
        r_unlock = auth_client.post('/api/vault/unlock', json={'pin': '1111'})
        assert r_unlock.status_code == 200

        # Wrong current pin
        r = auth_client.post('/api/vault/change-pin', json={'current_pin': '0000', 'new_pin': '2222', 'confirm': '2222'})
        assert r.status_code == 403

        # Success
        with patch.object(database.users_conf, 'update_one') as mock_up:
            r = auth_client.post('/api/vault/change-pin', json={'current_pin': '1111', 'new_pin': '2222', 'confirm': '2222'})
            assert r.status_code == 200
            assert r.get_json()['success'] is True
            mock_up.assert_called_once()


def test_vault_upload_locked_fails(auth_client):
    data = {'file': (io.BytesIO(b'dummy content'), 'secret.png')}
    r = auth_client.post('/api/vault/upload', data=data, content_type='multipart/form-data')
    assert r.status_code == 403


def test_vault_upload_success_and_list(auth_client, mock_user):
    h, salt = _hash_pin("1234")
    user_doc = dict(mock_user)
    user_doc['vault_pin_hash'] = h
    user_doc['vault_pin_salt'] = salt

    item_id = ObjectId()
    created_at = datetime.datetime.now(datetime.timezone.utc)

    mock_doc = {
        '_id': item_id,
        'user_id': mock_user['_id'],
        'cloudinary_public_id': 'vault_items/sample123',
        'filename_enc': '',
        'notes_enc': '',
        'mime_type': 'image/png',
        'media_type': 'image',
        'file_size': 1234,
        'thumbnail_data': '',
        'created_at': created_at,
        'updated_at': created_at,
    }

    mock_vault = MagicMock()
    mock_vault.count_documents.return_value = 0
    mock_vault.insert_one.return_value = MagicMock(inserted_id=item_id)

    with patch.object(database.users_conf, 'find_one', return_value=user_doc), \
         patch.object(database, 'vault_items_conf', mock_vault), \
         patch('cloudinary.uploader.upload', return_value={'public_id': 'vault_items/sample123'}):

        # Unlock
        r_unlock = auth_client.post('/api/vault/unlock', json={'pin': '1234'})
        assert r_unlock.status_code == 200

        # Upload
        file_data = {'file': (io.BytesIO(b'PNG_FAKE_IMAGE_DATA'), 'private_photo.png')}
        r = auth_client.post('/api/vault/upload', data=file_data, content_type='multipart/form-data')
        assert r.status_code == 200
        assert r.get_json()['success'] is True
        mock_vault.insert_one.assert_called_once()

    # List items
    mock_cursor = MagicMock()
    mock_cursor.sort.return_value.skip.return_value.limit.return_value = [mock_doc]
    mock_vault.find.return_value = mock_cursor
    mock_vault.count_documents.return_value = 1

    with patch.object(database.users_conf, 'find_one', return_value=user_doc), \
         patch.object(database, 'vault_items_conf', mock_vault):
        r_list = auth_client.get('/api/vault/items')
        assert r_list.status_code == 200
        items_data = r_list.get_json()
        assert len(items_data['items']) == 1
        assert items_data['items'][0]['id'] == str(item_id)
        assert items_data['items'][0]['created_at'].endswith('Z')


def test_vault_delete_item(auth_client, mock_user):
    h, salt = _hash_pin("1234")
    user_doc = dict(mock_user)
    user_doc['vault_pin_hash'] = h
    user_doc['vault_pin_salt'] = salt
    item_id = ObjectId()

    doc = {
        '_id': item_id,
        'user_id': mock_user['_id'],
        'cloudinary_public_id': 'vault_items/abc',
    }

    mock_vault = MagicMock()
    mock_vault.find_one.return_value = doc

    with patch.object(database.users_conf, 'find_one', return_value=user_doc), \
         patch.object(database, 'vault_items_conf', mock_vault), \
         patch('cloudinary.uploader.destroy') as mock_destroy:

        # Unlock
        r_unlock = auth_client.post('/api/vault/unlock', json={'pin': '1234'})
        assert r_unlock.status_code == 200

        # Delete
        r = auth_client.delete(f'/api/vault/items/{item_id}')
        assert r.status_code == 200
        assert r.get_json()['success'] is True
        mock_destroy.assert_called_once_with('vault_items/abc', resource_type='raw', type='authenticated')
        mock_vault.delete_one.assert_called_once_with({'_id': item_id})
