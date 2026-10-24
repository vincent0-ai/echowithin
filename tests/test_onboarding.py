from unittest.mock import patch

from bson.objectid import ObjectId


def test_save_onboarding_preference(auth_client, mock_user):
    import main as m

    with patch.object(m.users_conf, 'update_one') as update_one:
        response = auth_client.post(
            '/api/onboarding/preferences',
            json={'use_case': 'relationship'}
        )

    assert response.status_code == 200
    assert response.get_json() == {'success': True, 'use_case': 'relationship'}
    update_one.assert_called_once_with(
        {'_id': ObjectId(mock_user['_id'])},
        {'$set': {'onboarding_use_case': 'relationship'}}
    )


def test_save_onboarding_preference_rejects_unknown_value(auth_client):
    import main as m

    with patch.object(m.users_conf, 'update_one') as update_one:
        response = auth_client.post(
            '/api/onboarding/preferences',
            json={'use_case': 'unknown'}
        )

    assert response.status_code == 400
    update_one.assert_not_called()
