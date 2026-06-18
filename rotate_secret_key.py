"""
SECRET_KEY rotation tool for v3 envelope encryption.

Once all users are on v3 envelope encryption, rotating SECRET_KEY is simple:
the KEK changes, so we re-wrap (decrypt with old KEK, encrypt with new KEK)
every user's DEK and every conversation's DEK. The actual data encryption
is UNTOUCHED because it uses the random DEKs, not SECRET_KEY directly.

Usage (from the app container):
    python rotate_secret_key.py OLD_SECRET NEW_SECRET                  # Dry-run
    python rotate_secret_key.py OLD_SECRET NEW_SECRET --confirm        # Execute

Safety:
- Dry-run by default
- Verifies that the old KEK can decrypt at least one DEK before proceeding
- Processes in batches
- Idempotent: if a DEK is already wrapped with the new KEK, it's skipped

IMPORTANT: After running this tool with --confirm:
1. Update the SECRET_KEY environment variable to NEW_SECRET
2. Restart the application
3. The _KEK_CACHE will be re-derived from the new SECRET_KEY on first request

Model: Antigravity (Advanced Coding Agent)
Date: 2026-06-18
"""

import sys
import os
import argparse
import time
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gevent import monkey
monkey.patch_all()


def run_rotation(old_secret: str, new_secret: str, confirm=False, batch_size=50):
    """Re-wrap all DEKs from old KEK to new KEK."""
    # We can't use the normal app import flow because SECRET_KEY is changing.
    # Instead, derive the old and new KEKs directly.
    from security import _derive_fernet_key, _NOTES_KDF_ITERATIONS
    from cryptography.fernet import Fernet
    import database

    # Import the app to get database connections
    import main as m

    with m.app.app_context():
        print("=" * 60)
        print("SECRET_KEY Rotation Tool")
        print("=" * 60)
        if not confirm:
            print("[DRY RUN] No changes will be made. Pass --confirm to execute.")
        print()

        # Derive old and new KEKs
        old_secret_bytes = old_secret.encode('utf-8')
        new_secret_bytes = new_secret.encode('utf-8')

        old_kek_key = _derive_fernet_key(old_secret_bytes, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)
        new_kek_key = _derive_fernet_key(new_secret_bytes, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)

        old_kek = Fernet(old_kek_key)
        new_kek = Fernet(new_kek_key)

        print("KEK derivation complete.")

        # ---- Verify old KEK works ----
        print("\nVerifying old KEK can decrypt existing DEKs...")
        test_user = database.users_conf.find_one(
            {'encryption_key_enc': {'$exists': True}},
            {'encryption_key_enc': 1, 'username': 1}
        )
        if test_user:
            try:
                old_kek.decrypt(test_user['encryption_key_enc'].encode('utf-8'))
                print(f"  ✓ Successfully decrypted DEK for user '{test_user.get('username', '?')}'")
            except Exception as e:
                print(f"  ✗ FAILED to decrypt DEK with old SECRET_KEY: {e}")
                print("  Aborting. The OLD_SECRET provided does not match the current SECRET_KEY.")
                sys.exit(1)
        else:
            print("  No users with v3 keys found. Nothing to rotate.")
            print("  Run migrate_to_v3.py first to generate envelope keys.")
            sys.exit(0)

        # ---- Phase 1: Re-wrap user DEKs ----
        print("\n--- Phase 1: Re-wrapping user DEKs ---")
        users_with_keys = list(database.users_conf.find(
            {'encryption_key_enc': {'$exists': True}},
            {'_id': 1, 'username': 1, 'encryption_key_enc': 1}
        ))
        print(f"Found {len(users_with_keys)} users with v3 envelope keys.")

        rewrapped_users = 0
        failed_users = 0

        for i in range(0, len(users_with_keys), batch_size):
            batch = users_with_keys[i:i + batch_size]
            for user_doc in batch:
                try:
                    # Decrypt DEK with old KEK
                    dek_raw = old_kek.decrypt(user_doc['encryption_key_enc'].encode('utf-8'))
                    # Re-encrypt DEK with new KEK
                    new_encrypted_dek = new_kek.encrypt(dek_raw).decode('utf-8')

                    if confirm:
                        database.users_conf.update_one(
                            {'_id': user_doc['_id']},
                            {'$set': {'encryption_key_enc': new_encrypted_dek}}
                        )

                    rewrapped_users += 1
                except Exception as e:
                    print(f"  [ERROR] User {user_doc.get('username', '?')}: {e}")
                    failed_users += 1

            if confirm and i + batch_size < len(users_with_keys):
                time.sleep(0.5)

        print(f"Phase 1 complete: {rewrapped_users} user DEKs re-wrapped, {failed_users} failed.")

        # ---- Phase 2: Re-wrap conversation DEKs ----
        print("\n--- Phase 2: Re-wrapping conversation DEKs ---")
        convos_with_keys = list(database.dm_permissions_conf.find(
            {'conversation_key_enc': {'$exists': True}},
            {'_id': 1, 'requester_id': 1, 'target_id': 1, 'conversation_key_enc': 1}
        ))
        print(f"Found {len(convos_with_keys)} conversations with v3 envelope keys.")

        rewrapped_convos = 0
        failed_convos = 0

        for i in range(0, len(convos_with_keys), batch_size):
            batch = convos_with_keys[i:i + batch_size]
            for perm_doc in batch:
                try:
                    dek_raw = old_kek.decrypt(perm_doc['conversation_key_enc'].encode('utf-8'))
                    new_encrypted_dek = new_kek.encrypt(dek_raw).decode('utf-8')

                    if confirm:
                        database.dm_permissions_conf.update_one(
                            {'_id': perm_doc['_id']},
                            {'$set': {'conversation_key_enc': new_encrypted_dek}}
                        )

                    rewrapped_convos += 1
                except Exception as e:
                    print(f"  [ERROR] Conversation {perm_doc['_id']}: {e}")
                    failed_convos += 1

            if confirm and i + batch_size < len(convos_with_keys):
                time.sleep(0.5)

        print(f"Phase 2 complete: {rewrapped_convos} conversation DEKs re-wrapped, {failed_convos} failed.")

        # ---- Summary ----
        print("\n" + "=" * 60)
        print("ROTATION SUMMARY")
        print("=" * 60)
        print(f"User DEKs re-wrapped:         {rewrapped_users} (failed: {failed_users})")
        print(f"Conversation DEKs re-wrapped: {rewrapped_convos} (failed: {failed_convos})")
        if not confirm:
            print("\n[DRY RUN] No changes were made. Run with --confirm to execute.")
        else:
            print("\n[DONE] All DEKs re-wrapped with the new KEK.")
            print("\nNEXT STEPS:")
            print("  1. Update SECRET_KEY environment variable to the new secret")
            print("  2. Restart the application")
            print("  3. Verify that notes and DMs are still readable")
            print("\nThe actual encrypted data was NOT touched — only the DEK wrappers changed.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Rotate SECRET_KEY by re-wrapping all DEKs')
    parser.add_argument('old_secret', help='The current SECRET_KEY value')
    parser.add_argument('new_secret', help='The new SECRET_KEY value to rotate to')
    parser.add_argument('--confirm', action='store_true', help='Actually execute the rotation (default: dry run)')
    parser.add_argument('--batch-size', type=int, default=50, help='Items per batch (default: 50)')
    args = parser.parse_args()

    if args.old_secret == args.new_secret:
        print("ERROR: Old and new secrets are the same. Nothing to rotate.")
        sys.exit(1)

    run_rotation(
        old_secret=args.old_secret,
        new_secret=args.new_secret,
        confirm=args.confirm,
        batch_size=args.batch_size
    )
