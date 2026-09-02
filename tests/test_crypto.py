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

