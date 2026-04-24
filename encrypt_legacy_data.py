"""
EchoWithin — Legacy Data Encryption Migration Script
=====================================================
Encrypts all plaintext sensitive data left in the database from before
encryption was enforced.  Run with --dry-run first to preview changes.

Usage:
    python encrypt_legacy_data.py                   # live migration
    python encrypt_legacy_data.py --dry-run         # preview only
    python encrypt_legacy_data.py --batch-size 200  # smaller batches

Targets:
    1. note_versions  — remove content_plain / base_content_plain / proposed_content_plain
    2. direct_messages — encrypt unencrypted content, reply_to_preview, link_preview, image_url
    3. note_shares     — encrypt valentine_photo / valentine_audio + add media_hash
    4. personal_posts  — encrypt valentine_photo / valentine_audio + add media_hash
    5. personal_posts  — encrypt unencrypted note content
    6. note_discussions — encrypt unencrypted comment content

IMPORTANT: Back up your database before running in live mode.
"""

import argparse
import datetime
import hashlib
import os
import sys
import base64

from dotenv import load_dotenv
from pymongo import MongoClient
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

load_dotenv()

# ── Configuration ────────────────────────────────────────────────────────────

MONGODB_URI = os.environ.get('MONGODB_CONNECTION')
SECRET_KEY = os.environ.get('SECRET')

if not MONGODB_URI or not SECRET_KEY:
    print("ERROR: MONGODB_CONNECTION and SECRET environment variables are required.")
    sys.exit(1)

client = MongoClient(MONGODB_URI)
db = client['echowithin_db']

direct_messages_conf = db['direct_messages']
note_versions_conf = db['note_versions']
note_shares_conf = db['note_shares']
personal_posts_conf = db['personal_posts']
note_discussions_conf = db['note_discussions']

# ── Encryption Helpers (mirrored from main.py) ──────────────────────────────

_NOTES_KDF_ITERATIONS = 480000
_NOTES_V1_SALT = b'echowithin_notes_salt_v1'


def _derive_fernet_key(secret_bytes: bytes, salt: bytes, iterations: int = _NOTES_KDF_ITERATIONS):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(secret_bytes))


# v1 global key
_secret = SECRET_KEY.encode() if isinstance(SECRET_KEY, str) else SECRET_KEY
_v1_key = _derive_fernet_key(_secret, _NOTES_V1_SALT, iterations=100000)
_v1_fernet = Fernet(_v1_key)

# Per-user key cache
_user_fernet_cache = {}


def _get_user_fernet(user_id: str) -> Fernet:
    if user_id in _user_fernet_cache:
        return _user_fernet_cache[user_id]
    salt = f'echowithin_notes_v2_{user_id}'.encode()
    key = _derive_fernet_key(_secret, salt, _NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    _user_fernet_cache[user_id] = f
    return f


# Per-conversation DM key cache
_dm_fernet_cache = {}


def _get_dm_fernet(user1_id: str, user2_id: str) -> Fernet:
    uids = sorted([str(user1_id), str(user2_id)])
    conv_id = f"{uids[0]}_{uids[1]}"
    if conv_id in _dm_fernet_cache:
        return _dm_fernet_cache[conv_id]
    salt = f'echowithin_dm_v1_{conv_id}'.encode()
    key = _derive_fernet_key(_secret, salt, iterations=_NOTES_KDF_ITERATIONS)
    f = Fernet(key)
    _dm_fernet_cache[conv_id] = f
    return f


def encrypt_dm(content, user1_id, user2_id):
    if not content:
        return content
    try:
        f = _get_dm_fernet(user1_id, user2_id)
        return f.encrypt(content.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"  [ERR] DM encrypt failed: {e}")
        return content


def decrypt_dm(encrypted_content, user1_id, user2_id):
    if not encrypted_content:
        return encrypted_content
    try:
        f = _get_dm_fernet(user1_id, user2_id)
        return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception:
        return encrypted_content


def encrypt_note(content, user_id=None):
    if not content:
        return content
    try:
        if user_id:
            f = _get_user_fernet(str(user_id))
        else:
            f = _v1_fernet
        return f.encrypt(content.encode('utf-8')).decode('utf-8')
    except Exception as e:
        print(f"  [ERR] Note encrypt failed: {e}")
        raise


def decrypt_note(encrypted_content, user_id=None):
    if not encrypted_content:
        return encrypted_content
    if user_id:
        try:
            f = _get_user_fernet(str(user_id))
            return f.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
        except Exception:
            pass
    try:
        return _v1_fernet.decrypt(encrypted_content.encode('utf-8')).decode('utf-8')
    except Exception:
        if encrypted_content and not encrypted_content.startswith('gAAAAA'):
            return encrypted_content
        return None


def is_encrypted(value):
    """Check if a string value looks like Fernet ciphertext."""
    return bool(value) and isinstance(value, str) and value.startswith('gAAAAA')


# ── Migration Tasks ─────────────────────────────────────────────────────────

def migrate_note_versions_remove_plaintext(dry_run=False, batch_size=500):
    """Task 1: Remove content_plain, base_content_plain, proposed_content_plain from note_versions."""
    print("\n═══ Task 1: Remove plaintext fields from note_versions ═══")

    query = {
        '$or': [
            {'content_plain': {'$exists': True}},
            {'base_content_plain': {'$exists': True}},
            {'proposed_content_plain': {'$exists': True}}
        ]
    }
    count = note_versions_conf.count_documents(query)
    print(f"  Found {count} note_versions records with plaintext fields")

    if count == 0:
        print("  ✓ Nothing to do")
        return 0

    if dry_run:
        print(f"  [DRY RUN] Would unset plaintext fields from {count} records")
        return count

    result = note_versions_conf.update_many(
        query,
        {'$unset': {
            'content_plain': '',
            'base_content_plain': '',
            'proposed_content_plain': ''
        }}
    )
    print(f"  ✓ Cleaned {result.modified_count} records")
    return result.modified_count


def migrate_dm_messages(dry_run=False, batch_size=500):
    """Task 2: Encrypt unencrypted DM messages + encrypt reply_to_preview, link_preview, image_url on all messages."""
    print("\n═══ Task 2: Encrypt DM message metadata ═══")

    total_encrypted_content = 0
    total_encrypted_preview = 0
    total_encrypted_link = 0
    total_encrypted_image = 0
    total_errors = 0

    # Sub-task 2a: Encrypt message content that isn't encrypted yet
    unencrypted_query = {
        '$and': [
            {'encrypted': {'$ne': True}},
            {'content': {'$exists': True, '$ne': ''}},
        ]
    }
    unencrypted_count = direct_messages_conf.count_documents(unencrypted_query)
    print(f"  Found {unencrypted_count} unencrypted DM messages")

    last_id = None
    while True:
        q = dict(unencrypted_query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(direct_messages_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for msg in batch:
            try:
                content = msg.get('content', '')
                sender_id = str(msg['sender_id'])
                recipient_id = str(msg['recipient_id'])

                if not content or is_encrypted(content):
                    continue

                if dry_run:
                    total_encrypted_content += 1
                    continue

                update_fields = {
                    'content': encrypt_dm(content, sender_id, recipient_id),
                    'encrypted': True
                }
                direct_messages_conf.update_one({'_id': msg['_id']}, {'$set': update_fields})
                total_encrypted_content += 1
            except Exception as e:
                total_errors += 1
                print(f"  [ERR] Failed to encrypt DM {msg['_id']}: {e}")

    print(f"  {'[DRY RUN] Would encrypt' if dry_run else '✓ Encrypted'} {total_encrypted_content} message contents")

    # Sub-task 2b: Encrypt reply_to_preview, link_preview, image_url on ALL messages
    metadata_query = {
        '$or': [
            {'reply_to_preview': {'$exists': True, '$ne': None}},
            {'link_preview': {'$exists': True, '$ne': None}},
            {'image_url': {'$exists': True, '$ne': None}}
        ]
    }
    metadata_count = direct_messages_conf.count_documents(metadata_query)
    print(f"  Found {metadata_count} DM messages with metadata fields to check")

    last_id = None
    while True:
        q = dict(metadata_query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(direct_messages_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for msg in batch:
            try:
                sender_id = str(msg['sender_id'])
                recipient_id = str(msg['recipient_id'])
                update_fields = {}

                # reply_to_preview
                rtp = msg.get('reply_to_preview')
                if rtp and isinstance(rtp, str) and not is_encrypted(rtp):
                    update_fields['reply_to_preview'] = encrypt_dm(rtp, sender_id, recipient_id)
                    total_encrypted_preview += 1

                # image_url
                img_url = msg.get('image_url')
                if img_url and isinstance(img_url, str) and not is_encrypted(img_url):
                    update_fields['image_url'] = encrypt_dm(img_url, sender_id, recipient_id)
                    total_encrypted_image += 1

                # link_preview (dict with url, title, description, image)
                lp = msg.get('link_preview')
                if lp and isinstance(lp, dict):
                    encrypted_lp = {}
                    needs_encryption = False
                    for key in ('url', 'title', 'description', 'image'):
                        val = lp.get(key, '')
                        if val and isinstance(val, str) and not is_encrypted(val):
                            encrypted_lp[key] = encrypt_dm(val, sender_id, recipient_id)
                            needs_encryption = True
                        else:
                            encrypted_lp[key] = val
                    if needs_encryption:
                        update_fields['link_preview'] = encrypted_lp
                        total_encrypted_link += 1

                if update_fields:
                    if dry_run:
                        continue
                    direct_messages_conf.update_one({'_id': msg['_id']}, {'$set': update_fields})
            except Exception as e:
                total_errors += 1
                print(f"  [ERR] Failed to encrypt DM metadata {msg['_id']}: {e}")

    prefix = "[DRY RUN] Would encrypt" if dry_run else "✓ Encrypted"
    print(f"  {prefix} {total_encrypted_preview} reply previews")
    print(f"  {prefix} {total_encrypted_link} link previews")
    print(f"  {prefix} {total_encrypted_image} image URLs")
    if total_errors:
        print(f"  ⚠ {total_errors} errors encountered")

    return total_encrypted_content + total_encrypted_preview + total_encrypted_link + total_encrypted_image


def migrate_note_share_media(dry_run=False, batch_size=500):
    """Task 3: Encrypt valentine_photo/valentine_audio in note_shares + add media_hash."""
    print("\n═══ Task 3: Encrypt note_shares media URLs ═══")

    total = 0
    errors = 0
    query = {
        '$or': [
            {'valentine_photo': {'$exists': True, '$ne': None}},
            {'valentine_audio': {'$exists': True, '$ne': None}}
        ]
    }
    count = note_shares_conf.count_documents(query)
    print(f"  Found {count} note_shares with media fields to check")

    last_id = None
    while True:
        q = dict(query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(note_shares_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for share in batch:
            try:
                owner_id = str(share.get('owner_id', ''))
                update_fields = {}

                for field, hash_field in [('valentine_photo', 'valentine_photo_hash'), ('valentine_audio', 'valentine_audio_hash')]:
                    val = share.get(field)
                    if not val:
                        continue
                    if is_encrypted(val):
                        # Already encrypted — just add hash if missing
                        if not share.get(hash_field):
                            # Try to decrypt to compute hash
                            plain = decrypt_note(val, user_id=owner_id)
                            if plain and not is_encrypted(plain):
                                update_fields[hash_field] = hashlib.sha256(plain.encode()).hexdigest()
                        continue
                    # Not encrypted yet — encrypt and add hash
                    update_fields[field] = encrypt_note(val, user_id=owner_id) if owner_id else encrypt_note(val)
                    update_fields[hash_field] = hashlib.sha256(val.encode()).hexdigest()
                    total += 1

                if update_fields:
                    if dry_run:
                        continue
                    note_shares_conf.update_one({'_id': share['_id']}, {'$set': update_fields})
            except Exception as e:
                errors += 1
                print(f"  [ERR] Failed to encrypt share media {share['_id']}: {e}")

    prefix = "[DRY RUN] Would encrypt" if dry_run else "✓ Encrypted"
    print(f"  {prefix} {total} media URLs in note_shares")
    if errors:
        print(f"  ⚠ {errors} errors encountered")
    return total


def migrate_personal_post_media(dry_run=False, batch_size=500):
    """Task 4: Encrypt valentine_photo/valentine_audio in personal_posts + add media_hash."""
    print("\n═══ Task 4: Encrypt personal_posts media URLs ═══")

    total = 0
    errors = 0
    query = {
        '$or': [
            {'valentine_photo': {'$exists': True, '$ne': None}},
            {'valentine_audio': {'$exists': True, '$ne': None}}
        ]
    }
    count = personal_posts_conf.count_documents(query)
    print(f"  Found {count} personal_posts with media fields to check")

    last_id = None
    while True:
        q = dict(query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(personal_posts_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for post in batch:
            try:
                user_id = str(post.get('user_id', ''))
                update_fields = {}

                for field, hash_field in [('valentine_photo', 'valentine_photo_hash'), ('valentine_audio', 'valentine_audio_hash')]:
                    val = post.get(field)
                    if not val:
                        continue
                    if is_encrypted(val):
                        # Already encrypted — just add hash if missing
                        if not post.get(hash_field):
                            plain = decrypt_note(val, user_id=user_id)
                            if plain and not is_encrypted(plain):
                                update_fields[hash_field] = hashlib.sha256(plain.encode()).hexdigest()
                        continue
                    # Not encrypted yet — encrypt and add hash
                    update_fields[field] = encrypt_note(val, user_id=user_id) if user_id else encrypt_note(val)
                    update_fields[hash_field] = hashlib.sha256(val.encode()).hexdigest()
                    total += 1

                if update_fields:
                    if dry_run:
                        continue
                    personal_posts_conf.update_one({'_id': post['_id']}, {'$set': update_fields})
            except Exception as e:
                errors += 1
                print(f"  [ERR] Failed to encrypt post media {post['_id']}: {e}")

    prefix = "[DRY RUN] Would encrypt" if dry_run else "✓ Encrypted"
    print(f"  {prefix} {total} media URLs in personal_posts")
    if errors:
        print(f"  ⚠ {errors} errors encountered")
    return total


def migrate_unencrypted_notes(dry_run=False, batch_size=500):
    """Task 5: Encrypt personal_posts where content is not yet encrypted."""
    print("\n═══ Task 5: Encrypt unencrypted personal notes ═══")

    query = {
        'encrypted': {'$ne': True},
        'content': {'$exists': True, '$ne': ''}
    }
    count = personal_posts_conf.count_documents(query)
    print(f"  Found {count} unencrypted personal notes")

    if count == 0:
        print("  ✓ Nothing to do")
        return 0

    total = 0
    errors = 0
    last_id = None
    while True:
        q = dict(query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(personal_posts_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for note in batch:
            try:
                content = note.get('content', '')
                if is_encrypted(content):
                    continue

                user_id = str(note.get('user_id', ''))
                encrypted = encrypt_note(content, user_id=user_id) if user_id else encrypt_note(content)

                if dry_run:
                    total += 1
                    continue

                personal_posts_conf.update_one(
                    {'_id': note['_id']},
                    {'$set': {
                        'content': encrypted,
                        'encrypted': True,
                        'content_owner_id': note.get('user_id')
                    }}
                )
                total += 1
            except Exception as e:
                errors += 1
                print(f"  [ERR] Failed to encrypt note {note['_id']}: {e}")

    prefix = "[DRY RUN] Would encrypt" if dry_run else "✓ Encrypted"
    print(f"  {prefix} {total} personal notes")
    if errors:
        print(f"  ⚠ {errors} errors encountered")
    return total


def migrate_unencrypted_discussions(dry_run=False, batch_size=500):
    """Task 6: Encrypt note_discussions where content is not yet encrypted."""
    print("\n═══ Task 6: Encrypt unencrypted note discussion comments ═══")

    query = {
        'encrypted': {'$ne': True},
        'content': {'$exists': True, '$ne': ''}
    }
    count = note_discussions_conf.count_documents(query)
    print(f"  Found {count} unencrypted discussion comments")

    if count == 0:
        print("  ✓ Nothing to do")
        return 0

    total = 0
    errors = 0
    last_id = None
    while True:
        q = dict(query)
        if last_id:
            q['_id'] = {'$gt': last_id}
        batch = list(note_discussions_conf.find(q).sort('_id', 1).limit(batch_size))
        if not batch:
            break
        last_id = batch[-1]['_id']

        for comment in batch:
            try:
                content = comment.get('content', '')
                if is_encrypted(content):
                    continue

                # Note discussions use v1 global key (per user's decision)
                encrypted = encrypt_note(content)

                if dry_run:
                    total += 1
                    continue

                note_discussions_conf.update_one(
                    {'_id': comment['_id']},
                    {'$set': {'content': encrypted, 'encrypted': True}}
                )
                total += 1
            except Exception as e:
                errors += 1
                print(f"  [ERR] Failed to encrypt discussion {comment['_id']}: {e}")

    prefix = "[DRY RUN] Would encrypt" if dry_run else "✓ Encrypted"
    print(f"  {prefix} {total} discussion comments")
    if errors:
        print(f"  ⚠ {errors} errors encountered")
    return total


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Encrypt legacy plaintext data in EchoWithin DB')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without modifying data')
    parser.add_argument('--batch-size', type=int, default=500, help='Batch size for processing (default: 500)')
    args = parser.parse_args()

    print("=" * 60)
    print("EchoWithin Legacy Data Encryption Migration")
    print("=" * 60)
    if args.dry_run:
        print(">>> DRY RUN MODE — no data will be modified <<<")
    print(f"Batch size: {args.batch_size}")
    print(f"Started at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")

    totals = {}
    totals['note_versions_cleaned'] = migrate_note_versions_remove_plaintext(args.dry_run, args.batch_size)
    totals['dm_encrypted'] = migrate_dm_messages(args.dry_run, args.batch_size)
    totals['share_media'] = migrate_note_share_media(args.dry_run, args.batch_size)
    totals['post_media'] = migrate_personal_post_media(args.dry_run, args.batch_size)
    totals['notes_encrypted'] = migrate_unencrypted_notes(args.dry_run, args.batch_size)
    totals['discussions_encrypted'] = migrate_unencrypted_discussions(args.dry_run, args.batch_size)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for key, val in totals.items():
        print(f"  {key}: {val}")
    print(f"\nCompleted at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")

    if args.dry_run:
        print("\n>>> This was a DRY RUN. Run without --dry-run to apply changes. <<<")


if __name__ == '__main__':
    main()
