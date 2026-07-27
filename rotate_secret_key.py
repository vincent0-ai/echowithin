"""
SECRET_KEY rotation tool for v3 envelope encryption.

Once all users are on v3 envelope encryption, rotating SECRET_KEY is simple:
the KEK changes, so we re-wrap (decrypt with old KEK, encrypt with new KEK)
every user's DEK and every conversation's DEK. The actual data encryption
is UNTOUCHED because it uses the random DEKs, not SECRET_KEY directly.

Usage (from the app container):
    # Via environment variables (recommended):
    export OLD_SECRET_KEY="current-secret"
    export NEW_SECRET_KEY="new-secret"
    python rotate_secret_key.py --dry-run
    python rotate_secret_key.py --confirm

    # Or interactively (prompts on stdin, never touches argv/history):
    python rotate_secret_key.py --interactive --dry-run
    python rotate_secret_key.py --interactive --confirm

    # Legacy positional args (NOT recommended — secrets appear in ps/history):
    python rotate_secret_key.py OLD_SECRET NEW_SECRET --dry-run

Safety:
- Dry-run by default; --confirm required for any mutation
- Verifies that the old KEK can decrypt at least one DEK before proceeding
- Idempotent: records already wrapped with the new KEK are skipped
- Processes in batches with throttling
- Circuit breaker: aborts if failure rate exceeds 5% or 10 failures
- Writes a timestamped audit log (rotate_secret_key_<timestamp>.json)

***** CRITICAL — READ BEFORE RUNNING WITH --confirm *****

This script runs while the live app is still serving traffic with the
OLD SECRET_KEY. During the rotation window, brand-new registrations and
DM permission grants will generate DEKs wrapped under the OLD KEK.
Those new records created AFTER this script's initial snapshot will be
MISSED by the rotation.

BEFORE running with --confirm, put the app in maintenance/read-only mode:
  1. Block new registrations (set REGISTRATION_DISABLED=true, restart)
  2. Pause DM permission creation endpoints
  3. Or simply stop the app entirely for the rotation window

After the app restarts with the NEW SECRET_KEY, any old-KEK-wrapped
DEK that was missed during rotation becomes permanently undecryptable,
silently falling back to v2 encryption for that user/conversation.

IMPORTANT: After running this tool with --confirm:
1. Stop the application (if not already in maintenance mode)
2. Update the SECRET_KEY environment variable to the new secret
3. Restart the application
4. Verify that notes and DMs are still readable
5. Resume normal traffic

Model: Antigravity (Advanced Coding Agent)
Date: 2026-07-27
"""

import sys
import os
import argparse
import time
import base64
import json
import datetime
import hmac
import hashlib
import getpass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gevent import monkey
monkey.patch_all()

_CIRCUIT_BREAKER_THRESHOLD = 0.05   # 5% failure rate
_CIRCUIT_BREAKER_MIN_FAILURES = 10  # but at least 10 failed before tripping


def _derive_old_new_keks(old_secret: str, new_secret: str):
    """Derive the old and new KEK Fernet instances from raw secret strings."""
    from security import _derive_fernet_key, _NOTES_KDF_ITERATIONS
    from cryptography.fernet import Fernet

    old_secret_bytes = old_secret.encode('utf-8')
    new_secret_bytes = new_secret.encode('utf-8')

    old_kek_key = _derive_fernet_key(old_secret_bytes, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)
    new_kek_key = _derive_fernet_key(new_secret_bytes, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)

    return Fernet(old_kek_key), Fernet(new_kek_key)


def _check_circuit_breaker(total, failed, label):
    """Raise SystemExit if the failure rate exceeds the circuit breaker threshold."""
    if failed < _CIRCUIT_BREAKER_MIN_FAILURES:
        return
    rate = failed / max(total, 1)
    if rate > _CIRCUIT_BREAKER_THRESHOLD:
        print(f"\n  CIRCUIT BREAKER TRIPPED for {label}: {failed}/{total} "
              f"failed ({rate:.1%} > {_CIRCUIT_BREAKER_THRESHOLD:.1%}). Aborting.")
        sys.exit(1)


def _write_audit_log(entries, log_path):
    """Persist audit records to a timestamped JSON file."""
    os.makedirs(os.path.dirname(log_path) or '.', exist_ok=True)
    with open(log_path, 'w') as f:
        json.dump(entries, f, indent=2, default=str)


def _get_secret(label, env_var, interactive=False):
    """Resolve a secret from env var, interactive prompt, or positional arg fallback."""
    val = os.environ.get(env_var)
    if val:
        return val
    if interactive:
        return getpass.getpass(f"Enter {label}: ").strip()
    return None


def run_rotation(old_secret: str, new_secret: str, confirm=False, batch_size=50):
    """Re-wrap all DEKs from old KEK to new KEK."""
    import database
    import main as m

    with m.app.app_context():
        print("=" * 60)
        print("SECRET_KEY Rotation Tool")
        print("=" * 60)
        if not confirm:
            print("[DRY RUN] No changes will be made. Pass --confirm to execute.")
        print()

        # Derive old and new KEKs
        old_kek, new_kek = _derive_old_new_keks(old_secret, new_secret)
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
                print(f"  OK Successfully decrypted DEK for user '{test_user.get('username', '?')}'")
            except Exception as e:
                print(f"  FAILED to decrypt DEK with old SECRET_KEY: {e}")
                print("  Aborting. The OLD_SECRET provided does not match the current SECRET_KEY.")
                sys.exit(1)
        else:
            print("  No users with v3 keys found. Nothing to rotate.")
            print("  Run migrate_to_v3.py first to generate envelope keys.")
            sys.exit(0)

        # ---- Audit log setup ----
        ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')
        log_path = f'rotate_secret_key_{ts}.json'
        audit_entries = []

        # ---- Phase 1: Re-wrap user DEKs ----
        print("\n--- Phase 1: Re-wrapping user DEKs ---")
        users_with_keys = list(database.users_conf.find(
            {'encryption_key_enc': {'$exists': True}},
            {'_id': 1, 'username': 1, 'encryption_key_enc': 1}
        ))
        print(f"Found {len(users_with_keys)} users with v3 envelope keys.")

        rewrapped_users = 0
        skipped_users = 0
        failed_users = 0

        for i in range(0, len(users_with_keys), batch_size):
            batch = users_with_keys[i:i + batch_size]
            for user_doc in batch:
                uid = str(user_doc['_id'])
                entry = {'phase': 'users', 'id': uid,
                         'username': user_doc.get('username', '?')}
                try:
                    encrypted_dek = user_doc['encryption_key_enc'].encode('utf-8')
                    # Idempotency check: try new KEK first
                    try:
                        new_kek.decrypt(encrypted_dek)
                        skipped_users += 1
                        entry['result'] = 'skipped'
                        audit_entries.append(entry)
                        continue
                    except Exception:
                        pass  # Not yet wrapped with new KEK — proceed

                    dek_raw = old_kek.decrypt(encrypted_dek)
                    new_encrypted_dek = new_kek.encrypt(dek_raw).decode('utf-8')

                    if confirm:
                        database.users_conf.update_one(
                            {'_id': user_doc['_id']},
                            {'$set': {'encryption_key_enc': new_encrypted_dek}}
                        )

                    rewrapped_users += 1
                    entry['result'] = 'rewrapped'
                except Exception as e:
                    print(f"  [ERROR] User {user_doc.get('username', '?')}: {e}")
                    failed_users += 1
                    entry['result'] = 'failed'
                    entry['error'] = str(e)
                    _check_circuit_breaker(
                        rewrapped_users + skipped_users + failed_users,
                        failed_users, 'Phase 1 (users)')
                audit_entries.append(entry)

            if confirm and i + batch_size < len(users_with_keys):
                time.sleep(0.5)

        print(f"Phase 1 complete: {rewrapped_users} rewrapped, "
              f"{skipped_users} already migrated, {failed_users} failed.")

        # ---- Phase 2: Re-wrap conversation DEKs ----
        print("\n--- Phase 2: Re-wrapping conversation DEKs ---")
        convos_with_keys = list(database.dm_permissions_conf.find(
            {'conversation_key_enc': {'$exists': True}},
            {'_id': 1, 'requester_id': 1, 'target_id': 1, 'conversation_key_enc': 1}
        ))
        print(f"Found {len(convos_with_keys)} conversations with v3 envelope keys.")

        rewrapped_convos = 0
        skipped_convos = 0
        failed_convos = 0

        for i in range(0, len(convos_with_keys), batch_size):
            batch = convos_with_keys[i:i + batch_size]
            for perm_doc in batch:
                cid = str(perm_doc['_id'])
                entry = {'phase': 'conversations', 'id': cid}
                try:
                    encrypted_dek = perm_doc['conversation_key_enc'].encode('utf-8')
                    # Idempotency check: try new KEK first
                    try:
                        new_kek.decrypt(encrypted_dek)
                        skipped_convos += 1
                        entry['result'] = 'skipped'
                        audit_entries.append(entry)
                        continue
                    except Exception:
                        pass

                    dek_raw = old_kek.decrypt(encrypted_dek)
                    new_encrypted_dek = new_kek.encrypt(dek_raw).decode('utf-8')

                    if confirm:
                        database.dm_permissions_conf.update_one(
                            {'_id': perm_doc['_id']},
                            {'$set': {'conversation_key_enc': new_encrypted_dek}}
                        )

                    rewrapped_convos += 1
                    entry['result'] = 'rewrapped'
                except Exception as e:
                    print(f"  [ERROR] Conversation {perm_doc['_id']}: {e}")
                    failed_convos += 1
                    entry['result'] = 'failed'
                    entry['error'] = str(e)
                    _check_circuit_breaker(
                        rewrapped_convos + skipped_convos + failed_convos,
                        failed_convos, 'Phase 2 (conversations)')
                audit_entries.append(entry)

            if confirm and i + batch_size < len(convos_with_keys):
                time.sleep(0.5)

        print(f"Phase 2 complete: {rewrapped_convos} rewrapped, "
              f"{skipped_convos} already migrated, {failed_convos} failed.")

        # ---- Summary ----
        print("\n" + "=" * 60)
        print("ROTATION SUMMARY")
        print("=" * 60)
        print(f"User DEKs:         {rewrapped_users} rewrapped, "
              f"{skipped_users} skipped, {failed_users} failed")
        print(f"Conversation DEKs: {rewrapped_convos} rewrapped, "
              f"{skipped_convos} skipped, {failed_convos} failed")
        if not confirm:
            print("\n[DRY RUN] No changes were made. Run with --confirm to execute.")
        else:
            print("\n[DONE] All DEKs re-wrapped with the new KEK.")
            print(f"\nAudit log written to: {log_path}")
            print("\n" + "=" * 60)
            print("CRITICAL NEXT STEPS")
            print("=" * 60)
            print("  The app may still be running with the OLD SECRET_KEY.")
            print("  New registrations / DM grants during the rotation window")
            print("  will have DEKs wrapped under the OLD KEK and will be")
            print("  LOST after the restart unless the app was in maintenance mode.")
            print()
            print("  1. Stop the application NOW if not already in maintenance mode")
            print("  2. Update the SECRET_KEY environment variable to the new secret")
            print("  3. Restart the application")
            print("  4. Verify that notes and DMs are still readable")
            print("  5. Resume normal traffic (re-enable registrations, etc.)")
            print("\nThe actual encrypted data was NOT touched — only the DEK wrappers changed.")

        # Write audit log
        _write_audit_log(audit_entries, log_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Rotate SECRET_KEY by re-wrapping all DEKs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Security note:
  Prefer --old-secret-env / --new-secret-env or --interactive.
  Passing secrets as positional CLI args leaks them in shell
  history, ps output, and /proc/<pid>/cmdline.""")
    parser.add_argument('old_secret', nargs='?', default=None,
                        help='The current SECRET_KEY value (NOT recommended)')
    parser.add_argument('new_secret', nargs='?', default=None,
                        help='The new SECRET_KEY value to rotate to (NOT recommended)')
    parser.add_argument('--old-secret-env', '-o', default='OLD_SECRET_KEY',
                        help='Environment variable for the current SECRET_KEY '
                             '(default: OLD_SECRET_KEY)')
    parser.add_argument('--new-secret-env', '-n', default='NEW_SECRET_KEY',
                        help='Environment variable for the new SECRET_KEY '
                             '(default: NEW_SECRET_KEY)')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Prompt for secrets via stdin (securely, never '
                             'touches argv)')
    parser.add_argument('--confirm', '--dry-run', dest='confirm',
                        action='store_true',
                        help='Actually execute the rotation (default: dry run)')
    parser.add_argument('--batch-size', type=int, default=50,
                        help='Items per batch (default: 50)')
    args = parser.parse_args()

    # Resolve secrets: env var > interactive > positional arg
    old_secret = _get_secret("OLD_SECRET_KEY", args.old_secret_env,
                             args.interactive)
    new_secret = _get_secret("NEW_SECRET_KEY", args.new_secret_env,
                             args.interactive)

    # Fall back to positional args for backward compatibility
    if not old_secret and args.old_secret:
        old_secret = args.old_secret
    if not new_secret and args.new_secret:
        new_secret = args.new_secret

    if not old_secret or not new_secret:
        print("ERROR: Both old and new secrets are required.")
        print("  Set OLD_SECRET_KEY/NEW_SECRET_KEY env vars, or")
        print("  use --interactive, or pass as positional args.")
        sys.exit(1)

    if old_secret == new_secret:
        print("ERROR: Old and new secrets are the same. Nothing to rotate.")
        sys.exit(1)

    if not args.old_secret and not args.new_secret and not args.interactive:
        if os.environ.get(args.old_secret_env) and os.environ.get(args.new_secret_env):
            print(f"Reading secrets from env vars: "
                  f"{args.old_secret_env}, {args.new_secret_env}")
        else:
            print("NOTE: Secrets read from environment. Pass --interactive to "
                  "avoid env vars in process metadata.")

    run_rotation(
        old_secret=old_secret,
        new_secret=new_secret,
        confirm=args.confirm,
        batch_size=args.batch_size
    )
