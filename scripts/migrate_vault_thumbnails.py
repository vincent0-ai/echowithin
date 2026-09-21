"""Migrate existing plaintext vault thumbnails to encrypted format.

One-time script to encrypt plaintext thumbnail_data in vault_items documents.
Detects whether a thumbnail is already encrypted by attempting Fernet decryption.

Usage:
    python scripts/migrate_vault_thumbnails.py
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from security import _get_user_fernet
import database


def migrate():
    """Encrypt all plaintext thumbnail_data in vault_items."""
    with app.app_context():
        total = 0
        encrypted = 0
        skipped = 0
        errors = 0

        cursor = database.vault_items_conf.find(
            {'thumbnail_data': {'$exists': True, '$ne': ''}},
            {'_id': 1, 'user_id': 1, 'thumbnail_data': 1}
        )

        for doc in cursor:
            total += 1
            raw_thumb = doc.get('thumbnail_data', '')
            if not raw_thumb:
                skipped += 1
                continue

            user_id = str(doc['user_id'])

            # Try decrypting — if it works, it's already encrypted
            try:
                fernet = _get_user_fernet(user_id)
                fernet.decrypt(raw_thumb.encode('utf-8'))
                skipped += 1  # Already encrypted
                continue
            except Exception:
                pass  # Not encrypted yet — proceed

            # Encrypt the plaintext thumbnail
            try:
                fernet = _get_user_fernet(user_id)
                encrypted_thumb = fernet.encrypt(raw_thumb.encode('utf-8')).decode('utf-8')
                database.vault_items_conf.update_one(
                    {'_id': doc['_id']},
                    {'$set': {'thumbnail_data': encrypted_thumb}}
                )
                encrypted += 1
                if encrypted % 10 == 0:
                    print(f"  Encrypted {encrypted} thumbnails so far...")
            except Exception as e:
                errors += 1
                print(f"  ERROR encrypting {doc['_id']}: {e}")

        print(f"\n=== Migration Complete ===")
        print(f"  Total documents scanned: {total}")
        print(f"  Already encrypted (skipped): {skipped}")
        print(f"  Newly encrypted: {encrypted}")
        print(f"  Errors: {errors}")


if __name__ == '__main__':
    print("Starting vault thumbnail encryption migration...")
    migrate()
