"""
Tests for encryption/decryption utilities in the EchoWithin application.
Covers: note encryption (v1 + v2), DM encryption (v3), community encryption.
"""

import pytest


class TestNoteEncryption:
    """Tests for personal note encryption (Fernet v1 + v2 per-user keys)."""

    def test_encrypt_note_produces_ciphertext(self, app):
        """encrypt_note should produce non-empty ciphertext"""
        from main import encrypt_note
        plaintext = 'Hello, EchoWithin!'
        with app.app_context():
            ciphertext = encrypt_note(plaintext)
            assert ciphertext != plaintext
            assert len(ciphertext) > 0
            assert ciphertext.startswith('gAAAAA')

    def test_encrypt_note_with_user_id(self, app):
        """encrypt_note with user_id should produce valid v2 ciphertext"""
        from main import encrypt_note
        plaintext = 'Hello with user key'
        with app.app_context():
            ciphertext = encrypt_note(plaintext, user_id='507f1f77bcf86cd799439011')
            assert ciphertext != plaintext
            assert ciphertext.startswith('gAAAAA')

    def test_decrypt_note_roundtrip(self, app):
        """Encrypting then decrypting should return original text"""
        from main import encrypt_note, decrypt_note
        plaintext = 'Hello, World!'
        with app.app_context():
            ciphertext = encrypt_note(plaintext)
            decrypted = decrypt_note(ciphertext)
            assert decrypted == plaintext

    def test_decrypt_note_roundtrip_v2(self, app):
        """Per-user encryption/decryption should round-trip correctly"""
        from main import encrypt_note, decrypt_note
        user_id = '507f1f77bcf86cd799439011'
        plaintext = 'Hello with per-user key'
        with app.app_context():
            ciphertext = encrypt_note(plaintext, user_id=user_id)
            decrypted = decrypt_note(ciphertext, user_id=user_id)
            assert decrypted == plaintext

    def test_decrypt_note_cross_user_fails(self, app):
        """Content encrypted for user A should not be decryptable by user B"""
        from main import encrypt_note, decrypt_note
        plaintext = 'Sensitive data for Alice'
        with app.app_context():
            ciphertext = encrypt_note(plaintext, user_id='507f1f77bcf86cd799439001')
            decrypted = decrypt_note(ciphertext, user_id='507f1f77bcf86cd799439002')
            # Should fall through to v1 attempt or raw text fallback
            # With v2 keys, cross-user decryption should fail
            assert decrypted != plaintext or decrypted == '[Content unavailable — decryption error]'

    def test_encrypt_none_returns_none(self, app):
        """Encrypting None or empty string should return it unchanged"""
        from main import encrypt_note
        with app.app_context():
            assert encrypt_note(None) is None
            assert encrypt_note('') == ''

    def test_decrypt_none_returns_none(self, app):
        """Decrypting None or empty should return it unchanged"""
        from main import decrypt_note
        with app.app_context():
            assert decrypt_note(None) is None
            assert decrypt_note('') == ''

    def test_decrypt_unavailable_marker_returns_as_is(self, app):
        """Content marked as decryption error should pass through unchanged"""
        from main import decrypt_note
        marker = '[Content unavailable — decryption error]'
        with app.app_context():
            assert decrypt_note(marker) == marker

    def test_decrypt_legacy_unencrypted(self, app):
        """Plaintext that doesn't look like Fernet should be returned as-is"""
        from main import decrypt_note
        plaintext = 'This is just plain text from before encryption was added'
        with app.app_context():
            result = decrypt_note(plaintext)
            assert result == plaintext

    def test_encrypt_decrypt_unicode(self, app):
        """Unicode content should survive encryption round-trip"""
        from main import encrypt_note, decrypt_note
        unicode_text = 'Hello 世界 🌍 — emojis and accents éàü'
        with app.app_context():
            ciphertext = encrypt_note(unicode_text)
            decrypted = decrypt_note(ciphertext)
            assert decrypted == unicode_text

    def test_encrypt_decrypt_long_text(self, app):
        """Long text should survive encryption round-trip"""
        from main import encrypt_note, decrypt_note
        long_text = 'X' * 10000 + '\n' + 'Y' * 5000
        with app.app_context():
            ciphertext = encrypt_note(long_text)
            decrypted = decrypt_note(ciphertext)
    def test_decrypt_note_record_cache_and_preview(self, app):
        """_decrypt_note_record should utilize Redis cache for previews when available"""
        from main import encrypt_note
        from security import _decrypt_note_record, _decrypted_cache_key
        import database
        from unittest.mock import MagicMock, patch
        from bson.objectid import ObjectId

        user_id = '507f1f77bcf86cd799439011'
        plaintext = 'A very long note content that exceeds thirty characters for testing.'
        note_id = ObjectId()
        note = {
            '_id': note_id,
            'user_id': ObjectId(user_id),
            'content_owner_id': ObjectId(user_id),
            'content': None,
        }

        with app.app_context():
            note['content'] = encrypt_note(plaintext, user_id=user_id)
            
            # Setup a mock redis_cache
            mock_redis = MagicMock()
            # Set the cache value directly
            mock_redis.get.return_value = plaintext.encode('utf-8')
            
            original_redis = database.redis_cache
            database.redis_cache = mock_redis
            try:
                # With patch, ensure that decrypt function is not called when cache hit occurs
                with patch('security._decrypt_with_candidate_ids') as mock_decrypt:
                    preview = _decrypt_note_record(note, max_preview_chars=10)
                    # Verify cache lookup occurred
                    mock_redis.get.assert_called_once_with(_decrypted_cache_key(str(note_id)))
                    # Decryption was bypassed because of cache hit
                    mock_decrypt.assert_not_called()
                    assert preview == plaintext[:10] + '...'
            finally:
                database.redis_cache = original_redis


class TestDMEncryption:
    """Tests for direct message encryption (v3 conversation keys)."""

    def test_dm_encrypt_roundtrip(self, app):
        """DM encryption should round-trip for the correct conversation"""
        from main import encrypt_dm, decrypt_dm
        user_a = '507f1f77bcf86cd799439003'
        user_b = '507f1f77bcf86cd799439004'
        plaintext = 'Secret DM message'
        with app.app_context():
            encrypted = encrypt_dm(plaintext, user_a, user_b)
            assert encrypted != plaintext
            decrypted = decrypt_dm(encrypted, user_a, user_b)
            assert decrypted == plaintext

    def test_dm_order_independent(self, app):
        """Encryption should work regardless of user ID order"""
        from main import encrypt_dm, decrypt_dm
        user_a = '507f1f77bcf86cd799439003'
        user_b = '507f1f77bcf86cd799439004'
        plaintext = 'Order independent test'
        with app.app_context():
            encrypted = encrypt_dm(plaintext, user_a, user_b)
            decrypted_reversed = decrypt_dm(encrypted, user_b, user_a)
            assert decrypted_reversed == plaintext

    def test_dm_encrypt_none_returns_none(self, app):
        """Encrypting None DM content should return None"""
        from main import encrypt_dm
        with app.app_context():
            assert encrypt_dm(None, 'a', 'b') is None
            assert encrypt_dm('', 'a', 'b') == ''


class TestCommunityEncryption:
    """Tests for community note encryption."""

    def test_community_encrypt_roundtrip(self, app):
        """Community note encryption should round-trip"""
        from main import encrypt_community_note, decrypt_community_note
        community_id = '507f1f77bcf86cd799439011'
        plaintext = 'Community secret note'
        with app.app_context():
            encrypted = encrypt_community_note(plaintext, community_id)
            assert encrypted != plaintext
            decrypted = decrypt_community_note(encrypted, community_id)
            assert decrypted == plaintext

    def test_community_encrypt_none(self, app):
        """Encrypting None should return None"""
        from main import encrypt_community_note
        with app.app_context():
            assert encrypt_community_note(None, 'abc') is None
            assert encrypt_community_note('', 'abc') == ''

    def test_community_decrypt_non_fernet(self, app):
        """Non-encrypted content should pass through decrypt unchanged"""
        from main import decrypt_community_note
        plaintext = 'Not encrypted at all'
        with app.app_context():
            result = decrypt_community_note(plaintext, 'abc')
            assert result == plaintext


class TestKeyDerivation:
    """Tests for key derivation utilities."""

    def test_derive_key_produces_urlsafe_base64(self, app):
        """Derived keys should be URL-safe base64"""
        from main import _derive_fernet_key
        import base64
        secret = b'my-test-secret-key'
        salt = b'test-salt'
        with app.app_context():
            key = _derive_fernet_key(secret, salt, iterations=10000)
            # Should be valid base64
            decoded = base64.urlsafe_b64decode(key)
            assert len(decoded) == 32  # Fernet key is 32 bytes

    def test_derive_key_deterministic(self, app):
        """Same inputs should produce the same key"""
        from main import _derive_fernet_key
        secret = b'secret'
        salt = b'salt'
        with app.app_context():
            key1 = _derive_fernet_key(secret, salt, iterations=10000)
            key2 = _derive_fernet_key(secret, salt, iterations=10000)
            assert key1 == key2

    def test_derive_key_different_salts_yield_different_keys(self, app):
        """Different salts should yield different keys"""
        from main import _derive_fernet_key
        secret = b'secret'
        with app.app_context():
            key1 = _derive_fernet_key(secret, b'salt1', iterations=10000)
            key2 = _derive_fernet_key(secret, b'salt2', iterations=10000)
            assert key1 != key2


class TestCandidateResolution:
    """Tests for _candidate_user_ids helper."""

    def test_candidate_user_ids_deduplicates(self):
        from main import _candidate_user_ids
        result = _candidate_user_ids('abc', 'abc', 'def', None)
        assert result == ['abc', 'def']

    def test_candidate_user_ids_skips_none_and_empty(self):
        from main import _candidate_user_ids
        result = _candidate_user_ids(None, '', '   ', 'valid')
        assert result == ['valid']


class TestXMLCleaning:
    """Tests for clean_xml_text utility."""

    def test_clean_xml_removes_control_chars(self):
        from main import clean_xml_text
        dirty = 'hello\x00\x01\x08world'
        clean = clean_xml_text(dirty)
        assert clean == 'helloworld'

    def test_clean_xml_preserves_valid_chars(self):
        from main import clean_xml_text
        text = 'Hello\tWorld\nLine2\rReturn'
        result = clean_xml_text(text)
        # Tab, newline, carriage return are valid XML 1.0
        assert '\t' in result
        assert '\n' in result

    def test_clean_xml_none_returns_empty(self):
        from main import clean_xml_text
        assert clean_xml_text(None) == ''


class TestBondDataEncryption:
    """Tests for per-bond encrypted data (timeline, journals, memories)."""

    def test_bond_encryption_roundtrip(self, app):
        from security import encrypt_bond_data, decrypt_bond_data
        bond_id = '507f1f77bcf86cd799439077'
        plaintext = 'Private bond memory between partners'
        with app.app_context():
            encrypted = encrypt_bond_data(plaintext, bond_id)
            assert encrypted != plaintext
            assert encrypted.startswith('gAAAAA')
            decrypted = decrypt_bond_data(encrypted, bond_id)
            assert decrypted == plaintext

    def test_bond_cross_bond_decryption_fails(self, app):
        from security import encrypt_bond_data, decrypt_bond_data
        bond_a = '507f1f77bcf86cd799439077'
        bond_b = '507f1f77bcf86cd799439088'
        plaintext = 'Private bond memory'
        with app.app_context():
            encrypted = encrypt_bond_data(plaintext, bond_a)
            decrypted = decrypt_bond_data(encrypted, bond_b)
            assert decrypted == '[Content unavailable — decryption error]'

    def test_bond_empty_none_content(self, app):
        from security import encrypt_bond_data, decrypt_bond_data
        with app.app_context():
            assert encrypt_bond_data('', '507f1f77bcf86cd799439077') == ''
            assert decrypt_bond_data(None, '507f1f77bcf86cd799439077') is None


class TestGameDataEncryption:
    """Tests for per-lobby encrypted game data (votes, submissions, answers)."""

    def test_game_encryption_roundtrip(self, app):
        from security import encrypt_game_data, decrypt_game_data
        lobby_id = 'test_lobby_abc123'
        plaintext = 'Paris'
        with app.app_context():
            encrypted = encrypt_game_data(plaintext, lobby_id)
            assert encrypted != plaintext
            assert encrypted.startswith('gAAAAA')
            decrypted = decrypt_game_data(encrypted, lobby_id)
            assert decrypted == plaintext

    def test_game_cross_lobby_decryption_fails(self, app):
        from security import encrypt_game_data, decrypt_game_data
        lobby_a = 'test_lobby_aaa'
        lobby_b = 'test_lobby_bbb'
        plaintext = 'Secret vote option'
        with app.app_context():
            encrypted = encrypt_game_data(plaintext, lobby_a)
            decrypted = decrypt_game_data(encrypted, lobby_b)
            assert decrypted == '[Unavailable]'

    def test_game_empty_none_content(self, app):
        from security import encrypt_game_data, decrypt_game_data
        with app.app_context():
            assert encrypt_game_data('', 'test_lobby_abc123') == ''
            assert decrypt_game_data(None, 'test_lobby_abc123') is None

    def test_game_decrypt_legacy_plaintext_passthrough(self, app):
        """Pre-encryption rows stored raw must still read back unchanged."""
        from security import decrypt_game_data
        with app.app_context():
            assert decrypt_game_data('Paris', 'test_lobby_abc123') == 'Paris'
            assert decrypt_game_data('2', 'test_lobby_abc123') == '2'

    def test_game_randomized_ciphertext(self, app):
        """Same option encrypts differently each time (why tallies stay plaintext)."""
        from security import encrypt_game_data
        with app.app_context():
            enc1 = encrypt_game_data('Paris', 'test_lobby_abc123')
            enc2 = encrypt_game_data('Paris', 'test_lobby_abc123')
            assert enc1 != enc2


class TestFormDefinitionEncryption:
    """Tests for encrypted form definitions (title/description/questions)."""

    def _sample_questions(self):
        return [
            {'id': 'q1', 'label': 'Your name?', 'type': 'short_text', 'required': True, 'options': []},
            {'id': 'q2', 'label': 'Pick one', 'type': 'single_choice', 'required': False, 'options': ['Alpha', 'Beta']},
        ]

    def test_form_definition_roundtrip(self, app):
        from blueprints.forms import _encrypt_form_definition, _decrypt_form_definition
        from bson.objectid import ObjectId
        form_oid = ObjectId()
        with app.app_context():
            enc_title, enc_desc, enc_qs = _encrypt_form_definition(str(form_oid), 'Secret Survey', 'Be honest', self._sample_questions())
            assert enc_title.startswith('gAAAAA')
            assert enc_qs[0]['label'].startswith('gAAAAA')
            assert enc_qs[1]['options'][0].startswith('gAAAAA')
            # structure keys stay plaintext
            assert enc_qs[1]['id'] == 'q2' and enc_qs[1]['type'] == 'single_choice' and enc_qs[1]['required'] is False
            stored = {'_id': form_oid, 'title': enc_title, 'description': enc_desc, 'questions': enc_qs}
            plain = _decrypt_form_definition(stored)
            assert plain['title'] == 'Secret Survey'
            assert plain['description'] == 'Be honest'
            assert plain['questions'][0]['label'] == 'Your name?'
            assert plain['questions'][1]['options'] == ['Alpha', 'Beta']
            # stored doc untouched by decrypt
            assert stored['title'] == enc_title

    def test_form_definition_legacy_passthrough(self, app):
        """Pre-encryption forms stored raw must still render unchanged."""
        from blueprints.forms import _decrypt_form_definition
        from bson.objectid import ObjectId
        legacy = {'_id': ObjectId(), 'title': 'Old Form', 'description': 'desc',
                  'questions': [{'id': 'q1', 'label': 'Q?', 'type': 'short_text', 'required': True, 'options': []}]}
        with app.app_context():
            plain = _decrypt_form_definition(legacy)
            assert plain['title'] == 'Old Form'
            assert plain['questions'][0]['label'] == 'Q?'

    def test_form_definition_empty_fields(self, app):
        from blueprints.forms import _encrypt_form_definition, _decrypt_form_definition
        from bson.objectid import ObjectId
        form_oid = ObjectId()
        with app.app_context():
            enc_title, enc_desc, enc_qs = _encrypt_form_definition(str(form_oid), '', '', [])
            assert enc_title == '' and enc_desc == '' and enc_qs == []
            plain = _decrypt_form_definition({'_id': form_oid, 'title': '', 'description': '', 'questions': []})
            assert plain['title'] == '' and plain['questions'] == []


class TestSecretKeyRotation:
    """Tests for _RotationKeyRing and media envelope key rotation."""

    def test_keyring_rotates_all_domains_without_data_loss(self, app):
        import base64
        import secrets
        from scripts.rotate_secret_key import _RotationKeyRing

        old_sec = 'unit_test_old_secret_' + secrets.token_hex(8)
        new_sec = 'unit_test_new_secret_' + secrets.token_hex(8)

        with app.app_context():
            kr = _RotationKeyRing(old_sec, new_sec)

            # 1. User v2 -> v3 rotation
            uid = '507f1f77bcf86cd799439011'
            dek_raw = secrets.token_bytes(32)
            salt_b64 = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
            kr.register_user_v3_dek(uid, dek_raw, salt_b64)

            old_v2_cipher = kr.get_old_user_v2(uid).encrypt(b'My secret note').decode('utf-8')
            rotated_cipher, st = kr.rotate_user_field(old_v2_cipher, [uid], primary_uid=uid)
            assert st == 'rotated'
            assert kr.get_user_v3(uid).decrypt(rotated_cipher.encode('utf-8')).decode('utf-8') == 'My secret note'

            # Idempotency check
            _, st2 = kr.rotate_user_field(rotated_cipher, [uid], primary_uid=uid)
            assert st2 == 'skipped'

            # 2. DM v2 -> v3 rotation
            u1, u2 = '507f1f77bcf86cd799439001', '507f1f77bcf86cd799439002'
            dm_dek = secrets.token_bytes(32)
            kr.register_dm_v3_dek(u1, u2, dm_dek)

            old_dm_cipher = kr.get_old_dm_v2(u1, u2).encrypt(b'Private DM image url').decode('utf-8')
            rot_dm, st_dm = kr.rotate_dm_field(old_dm_cipher, u1, u2)
            assert st_dm == 'rotated'
            assert kr.get_dm_v3(u1, u2).decrypt(rot_dm.encode('utf-8')).decode('utf-8') == 'Private DM image url'
            assert kr.rotate_dm_field(rot_dm, u1, u2)[1] == 'skipped'

            # 3. Bond, Community, Form, Game, Vault simple field rotation
            bid = '507f1f77bcf86cd799439077'
            bond_c = kr.get_old_bond(bid).encrypt(b'Bond journal').decode('utf-8')
            rot_bond, st_bond = kr.rotate_simple_field(bond_c, kr.get_old_bond(bid), kr.get_new_bond(bid))
            assert st_bond == 'rotated'
            assert kr.get_new_bond(bid).decrypt(rot_bond.encode('utf-8')).decode('utf-8') == 'Bond journal'
            assert kr.rotate_simple_field(rot_bond, kr.get_old_bond(bid), kr.get_new_bond(bid))[1] == 'skipped'

    def test_media_envelope_key_preserves_media_across_secret_rotation(self, app):
        import secrets
        from unittest.mock import MagicMock
        import database
        import security

        old_sec = 'media_old_secret_' + secrets.token_hex(8)
        new_sec = 'media_new_secret_' + secrets.token_hex(8)
        orig_secret = app.config['SECRET_KEY']
        orig_auth = database.auth_conf

        try:
            with app.app_context():
                # Step 1: Encrypt media bytes under old_sec (before rotation)
                app.config['SECRET_KEY'] = old_sec
                security._KEK_CACHE.clear()
                security._MEDIA_FERNET_CACHE.clear()
                database.auth_conf = None

                raw_media = b'\x89PNG\r\n\x1a\nsecret_image_bytes'
                cipher_bytes = security.encrypt_media_bytes(raw_media)
                assert security.decrypt_media_bytes(cipher_bytes) == raw_media

                # Step 2: Simulate Phase 3 rotation wrapping old media key with new KEK
                old_media_key = security._derive_fernet_key(
                    old_sec.encode('utf-8'), b'echowithin_media_at_rest_v1', security._NOTES_KDF_ITERATIONS
                )
                app.config['SECRET_KEY'] = new_sec
                security._KEK_CACHE.clear()
                security._MEDIA_FERNET_CACHE.clear()

                wrapped_media_key = security._get_kek().encrypt(old_media_key).decode('utf-8')
                mock_auth = MagicMock()
                mock_auth.find_one.return_value = {
                    'type': 'media_encryption_key',
                    'encryption_key_enc': wrapped_media_key,
                }
                database.auth_conf = mock_auth

                # Step 3: Decrypt pre-rotation media bytes under new_sec!
                decrypted = security.decrypt_media_bytes(cipher_bytes)
                assert decrypted == raw_media
        finally:
            app.config['SECRET_KEY'] = orig_secret
            database.auth_conf = orig_auth
            security._KEK_CACHE.clear()
            security._MEDIA_FERNET_CACHE.clear()


