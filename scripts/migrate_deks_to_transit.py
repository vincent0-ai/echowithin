"""
Migrate at-rest data-key wrappings from the legacy SECRET_KEY-derived KEK to
Vault Transit.

Only the *wrapping* of data keys changes; the data keys themselves are never
re-generated, so all previously encrypted content remains decryptable.

Targets:
  - users.encryption_key_enc              (per-user envelope DEK)
  - dm_permissions.conversation_key_enc   (per-conversation envelope DEK)
  - auth (type='media_encryption_key')    (media-at-rest envelope key)

Idempotent: tokens already wrapped by Vault Transit ('vault:vN:...') are skipped.
Lazy migration already happens on first use in the app; this script exists to
migrate everything up-front and to decouple stored data from SECRET_KEY.

Usage (from the project root):
    # Requires VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY, MONGODB_CONNECTION, SECRET
    python scripts/migrate_deks_to_transit.py --dry-run
    python scripts/migrate_deks_to_transit.py --confirm

Safety:
  - Dry-run by default; --confirm is required for any database mutation
  - Circuit breaker aborts if the failure rate exceeds 5% (min 10 failures)
  - Writes a timestamped audit log (migrate_deks_to_transit_<timestamp>.json)
"""

import os
import sys
import json
import time
import argparse
import datetime

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(override=True)

from bson.objectid import ObjectId  # noqa: F401  (parity with other scripts)
from cryptography.fernet import Fernet
from pymongo import MongoClient

from config import _NOTES_KDF_ITERATIONS
from security import _derive_fernet_key
import key_management

_CIRCUIT_BREAKER_THRESHOLD = 0.05
_CIRCUIT_BREAKER_MIN_FAILURES = 10

# (collection, filter, fields)
_TARGETS = [
    ('users', {'encryption_key_enc': {'$exists': True}}, ['encryption_key_enc']),
    ('dm_permissions', {'conversation_key_enc': {'$exists': True}}, ['conversation_key_enc']),
    ('auth', {'type': 'media_encryption_key'}, ['encryption_key_enc', 'encryption_key_enc_prev']),
]


def _get_env(name):
    val = os.environ.get(name, '').strip()
    if not val:
        print(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val


def _build_legacy_keks():
    """Candidate KEKs that may have wrapped the stored data keys (pre-Transit)."""
    keks = [Fernet(_derive_fernet_key(_get_env('SECRET').encode('utf-8'),
                                       b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS))]
    master = os.environ.get('MASTER_KEY', '').strip()
    if master:
        keks.append(Fernet(_derive_fernet_key(master.encode('utf-8'),
                                              b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)))
    return keks


def _unwrap_with_any(keks, token_str):
    for kek in keks:
        try:
            return kek.decrypt(token_str.encode('utf-8'))
        except Exception:
            continue
    return None


def _migrate(confirm=False):
    client = MongoClient(_get_env('MONGODB_CONNECTION'))
    db = client['echowithin_db']

    keks = _build_legacy_keks()
    stats = {'migrated': 0, 'skipped': 0, 'failed': 0, 'by_collection': {}}
    audit = []

    for coll_name, flt, fields in _TARGETS:
        coll = db[coll_name]
        per = stats['by_collection'].setdefault(coll_name, {'migrated': 0, 'skipped': 0, 'failed': 0})
        projection = {f: 1 for f in fields}
        for doc in coll.find(flt, projection):
            updates = {}
            for field in fields:
                token = doc.get(field)
                if not token:
                    continue
                if isinstance(token, str) and token.startswith('vault:'):
                    stats['skipped'] += 1
                    per['skipped'] += 1
                    continue
                raw = _unwrap_with_any(keks, token)
                if raw is None:
                    stats['failed'] += 1
                    per['failed'] += 1
                    audit.append({'collection': coll_name, '_id': str(doc['_id']),
                                  'field': field, 'status': 'unwrap_failed'})
                    continue
                updates[field] = key_management.transit_encrypt(raw)
            if updates and confirm:
                coll.update_one({'_id': doc['_id']}, {'$set': updates})
            for field in updates:
                stats['migrated'] += 1
                per['migrated'] += 1
                audit.append({'collection': coll_name, '_id': str(doc['_id']),
                              'field': field, 'status': 'migrated'})

            total = stats['migrated'] + stats['failed']
            if stats['failed'] >= _CIRCUIT_BREAKER_MIN_FAILURES and \
                    stats['failed'] / max(total, 1) > _CIRCUIT_BREAKER_THRESHOLD:
                print(f"\n  CIRCUIT BREAKER TRIPPED: {stats['failed']}/{total} failed. Aborting.")
                _write_audit(audit)
                sys.exit(1)

    return stats, audit


def _write_audit(entries):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = os.path.join(_PROJECT_ROOT, f'migrate_deks_to_transit_{ts}.json')
    with open(path, 'w') as f:
        json.dump(entries, f, indent=2, default=str)
    print(f"\nAudit log written: {path}")


def main():
    if not key_management.transit_enabled():
        print("VAULT_TRANSIT_KEY is not set — nothing to migrate to.")
        sys.exit(1)

    print(f"Key custody mode: {key_management.current_mode()}")
    if not args.dry_run:
        print("Confirming Vault Transit health...")
        if not key_management.verify_transit():
            print("Transit self-check failed; aborting.")
            sys.exit(1)

    start = time.time()
    stats, audit = _migrate(confirm=args.confirm)
    elapsed = time.time() - start

    mode = "DRY-RUN" if args.dry_run else "APPLIED"
    print(f"\n[{mode}] migrated={stats['migrated']} skipped={stats['skipped']} "
          f"failed={stats['failed']} in {elapsed:.1f}s")
    print("  Per collection (legacy=needs migration, transit=already done):")
    for coll_name, per in stats['by_collection'].items():
        print(f"    {coll_name}: legacy={per['migrated']} transit={per['skipped']} "
              f"failed={per['failed']}")
    _write_audit(audit)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Migrate data-key wrappings to Vault Transit.")
    parser.add_argument('--dry-run', action='store_true', default=False)
    parser.add_argument('--confirm', action='store_true', default=False,
                        help="Apply changes (required for any database mutation).")
    args = parser.parse_args()
    if args.confirm and args.dry_run:
        print("Choose either --dry-run or --confirm, not both.")
        sys.exit(1)
    if not args.confirm:
        args.dry_run = True
    main()
