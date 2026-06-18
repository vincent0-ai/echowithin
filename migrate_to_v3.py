"""
One-time migration script: Upgrade all existing users to v3 envelope encryption.

Usage (from the app container):
    python migrate_to_v3.py                 # Dry-run (no changes)
    python migrate_to_v3.py --confirm       # Execute migration
    python migrate_to_v3.py --confirm --batch-size 5   # Smaller batches

What this does:
1. For each user WITHOUT envelope keys:
   - Generates a random DEK + salt
   - Stores the encrypted DEK + salt in the user document
   - Re-encrypts all their personal notes from v2 to v3
2. For each DM conversation WITHOUT envelope keys:
   - Generates a random conversation DEK
   - Stores it in the dm_permissions document
   - Re-encrypts all messages in that conversation from v2 to v3

Safety:
- Dry-run mode by default (no writes)
- Processes users in small batches with logging
- Skips notes/messages that fail to decrypt (leaves them on v2)
- Idempotent: re-running is safe (skips already-migrated users)

Model: Antigravity (Advanced Coding Agent)
Date: 2026-06-18
"""

import sys
import os
import argparse
import time

# Ensure we can import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gevent import monkey
monkey.patch_all()


def run_migration(confirm=False, batch_size=10, verbose=False):
    """Run the v2 → v3 envelope encryption migration."""
    import main as m
    from security import (
        generate_user_envelope_keys, generate_conversation_envelope_keys,
        _get_user_fernet, _get_user_fernet_v3, _decrypt_dek,
        _get_dm_fernet, _get_dm_fernet_v3,
        _derive_fernet_key, _NOTES_KDF_ITERATIONS,
        _get_kek
    )
    from cryptography.fernet import Fernet
    from bson.objectid import ObjectId
    import base64
    import database

    with m.app.app_context():
        print("=" * 60)
        print("EchoWithin v3 Envelope Encryption Migration")
        print("=" * 60)
        if not confirm:
            print("[DRY RUN] No changes will be made. Pass --confirm to execute.")
        print()

        # ---- Phase 1: Migrate Users ----
        print("--- Phase 1: User envelope key generation + note re-encryption ---")
        users_without_keys = list(database.users_conf.find(
            {'encryption_key_enc': {'$exists': False}},
            {'_id': 1, 'username': 1}
        ))
        print(f"Found {len(users_without_keys)} users without v3 envelope keys.")

        migrated_users = 0
        migrated_notes = 0
        failed_notes = 0

        for i in range(0, len(users_without_keys), batch_size):
            batch = users_without_keys[i:i + batch_size]
            for user_doc in batch:
                user_id = user_doc['_id']
                user_id_str = str(user_id)
                username = user_doc.get('username', '?')

                if verbose:
                    print(f"  Processing user: {username} ({user_id_str})")

                # Generate envelope keys
                envelope_keys = generate_user_envelope_keys()

                if confirm:
                    database.users_conf.update_one(
                        {'_id': user_id},
                        {'$set': envelope_keys}
                    )

                # Get the OLD v2 Fernet and the NEW v3 Fernet for this user
                try:
                    old_fernet = _get_user_fernet(user_id_str)
                except Exception as e:
                    print(f"  [ERROR] Cannot derive v2 key for {username}: {e}")
                    continue

                # Derive the v3 Fernet from the keys we just generated
                try:
                    dek_raw = _get_kek().decrypt(envelope_keys['encryption_key_enc'].encode('utf-8'))
                    salt = base64.urlsafe_b64decode(envelope_keys['encryption_salt'])
                    new_key = _derive_fernet_key(dek_raw, salt, _NOTES_KDF_ITERATIONS)
                    new_fernet = Fernet(new_key)
                except Exception as e:
                    print(f"  [ERROR] Cannot derive v3 key for {username}: {e}")
                    continue

                # Re-encrypt all notes for this user
                notes = list(database.personal_posts_conf.find(
                    {'user_id': user_id},
                    {'_id': 1, 'content': 1}
                ))

                user_note_count = 0
                user_fail_count = 0
                for note in notes:
                    content = note.get('content', '')
                    if not content or not content.startswith('gAAAAA'):
                        continue  # Skip empty or unencrypted notes

                    try:
                        # Decrypt with v2 (try user key, then v1 global)
                        plaintext = old_fernet.decrypt(content.encode('utf-8')).decode('utf-8')
                    except Exception:
                        # Try v1 global key
                        try:
                            from security import get_notes_fernet
                            plaintext = get_notes_fernet().decrypt(content.encode('utf-8')).decode('utf-8')
                        except Exception:
                            if verbose:
                                print(f"    [SKIP] Note {note['_id']}: decrypt failed (leaving on v2)")
                            user_fail_count += 1
                            continue

                    # Re-encrypt with v3
                    try:
                        new_ciphertext = new_fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')
                    except Exception as e:
                        print(f"    [ERROR] Note {note['_id']}: v3 encrypt failed: {e}")
                        user_fail_count += 1
                        continue

                    if confirm:
                        database.personal_posts_conf.update_one(
                            {'_id': note['_id']},
                            {'$set': {'content': new_ciphertext, 'encryption_version': 3}}
                        )
                        # Invalidate decryption cache
                        try:
                            from security import _invalidate_decrypted_cache
                            _invalidate_decrypted_cache(note['_id'])
                        except Exception:
                            pass

                    user_note_count += 1

                migrated_users += 1
                migrated_notes += user_note_count
                failed_notes += user_fail_count

                if verbose or user_fail_count > 0:
                    print(f"  User {username}: {user_note_count} notes re-encrypted, {user_fail_count} skipped")

            # Pause between batches to avoid overwhelming the DB
            if confirm and i + batch_size < len(users_without_keys):
                print(f"  ... batch {i // batch_size + 1} complete, pausing 1s ...")
                time.sleep(1)

        print(f"\nPhase 1 complete: {migrated_users} users, {migrated_notes} notes re-encrypted, {failed_notes} failed/skipped.")

        # ---- Phase 2: Migrate DM Conversations ----
        print("\n--- Phase 2: DM conversation envelope key generation + message re-encryption ---")
        conversations_without_keys = list(database.dm_permissions_conf.find(
            {
                'conversation_key_enc': {'$exists': False},
                'status': 'accepted'
            },
            {'_id': 1, 'requester_id': 1, 'target_id': 1}
        ))
        print(f"Found {len(conversations_without_keys)} conversations without v3 envelope keys.")

        migrated_convos = 0
        migrated_messages = 0
        failed_messages = 0

        for i in range(0, len(conversations_without_keys), batch_size):
            batch = conversations_without_keys[i:i + batch_size]
            for perm_doc in batch:
                requester_id = str(perm_doc['requester_id'])
                target_id = str(perm_doc['target_id'])

                if verbose:
                    print(f"  Processing conversation: {requester_id} <-> {target_id}")

                # Generate conversation envelope keys
                conv_envelope = generate_conversation_envelope_keys()

                if confirm:
                    database.dm_permissions_conf.update_one(
                        {'_id': perm_doc['_id']},
                        {'$set': conv_envelope}
                    )

                # Get OLD v2 DM Fernet
                try:
                    old_dm_fernet = _get_dm_fernet(requester_id, target_id)
                except Exception as e:
                    print(f"  [ERROR] Cannot derive v2 DM key: {e}")
                    continue

                # Derive NEW v3 DM Fernet from the keys we just generated
                try:
                    uids = sorted([requester_id, target_id])
                    conv_id = f"{uids[0]}_{uids[1]}"
                    dek_raw = _get_kek().decrypt(conv_envelope['conversation_key_enc'].encode('utf-8'))
                    salt = f'echowithin_dm_v3_{conv_id}'.encode()
                    new_key = _derive_fernet_key(dek_raw, salt, _NOTES_KDF_ITERATIONS)
                    new_dm_fernet = Fernet(new_key)
                except Exception as e:
                    print(f"  [ERROR] Cannot derive v3 DM key: {e}")
                    continue

                # Re-encrypt all messages in this conversation
                messages = list(database.direct_messages_conf.find(
                    {
                        '$or': [
                            {'sender_id': ObjectId(requester_id), 'receiver_id': ObjectId(target_id)},
                            {'sender_id': ObjectId(target_id), 'receiver_id': ObjectId(requester_id)}
                        ]
                    },
                    {'_id': 1, 'content': 1}
                ))

                conv_msg_count = 0
                conv_fail_count = 0
                for msg in messages:
                    content = msg.get('content', '')
                    if not content or not content.startswith('gAAAAA'):
                        continue  # Skip empty or unencrypted messages

                    try:
                        plaintext = old_dm_fernet.decrypt(content.encode('utf-8')).decode('utf-8')
                    except Exception:
                        if verbose:
                            print(f"    [SKIP] Message {msg['_id']}: decrypt failed (leaving on v2)")
                        conv_fail_count += 1
                        continue

                    try:
                        new_ciphertext = new_dm_fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')
                    except Exception as e:
                        print(f"    [ERROR] Message {msg['_id']}: v3 encrypt failed: {e}")
                        conv_fail_count += 1
                        continue

                    if confirm:
                        database.direct_messages_conf.update_one(
                            {'_id': msg['_id']},
                            {'$set': {'content': new_ciphertext, 'encryption_version': 3}}
                        )

                    conv_msg_count += 1

                migrated_convos += 1
                migrated_messages += conv_msg_count
                failed_messages += conv_fail_count

                if verbose or conv_fail_count > 0:
                    print(f"  Conversation {requester_id}<->{target_id}: {conv_msg_count} messages re-encrypted, {conv_fail_count} skipped")

            if confirm and i + batch_size < len(conversations_without_keys):
                print(f"  ... batch {i // batch_size + 1} complete, pausing 1s ...")
                time.sleep(1)

        print(f"\nPhase 2 complete: {migrated_convos} conversations, {migrated_messages} messages re-encrypted, {failed_messages} failed/skipped.")

        # ---- Summary ----
        print("\n" + "=" * 60)
        print("MIGRATION SUMMARY")
        print("=" * 60)
        print(f"Users migrated:        {migrated_users}")
        print(f"Notes re-encrypted:    {migrated_notes} (failed: {failed_notes})")
        print(f"Convos migrated:       {migrated_convos}")
        print(f"Messages re-encrypted: {migrated_messages} (failed: {failed_messages})")
        if not confirm:
            print("\n[DRY RUN] No changes were made. Run with --confirm to execute.")
        else:
            print("\n[DONE] Migration complete. All new data will use v3 envelope encryption.")
            print("Old v2 keys still work for any notes/messages that failed to re-encrypt.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Migrate to v3 envelope encryption')
    parser.add_argument('--confirm', action='store_true', help='Actually execute the migration (default: dry run)')
    parser.add_argument('--batch-size', type=int, default=10, help='Users per batch (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print per-user/per-note details')
    args = parser.parse_args()

    run_migration(confirm=args.confirm, batch_size=args.batch_size, verbose=args.verbose)
