"""
Prune script: Safely remove orphaned bond album photo records from MongoDB
whose corresponding files no longer exist on Cloudinary (HTTP 404).

Safety:
- Defaults to --dry-run (no deletions unless --confirm is provided)
- Exports a backup JSON of all to-be-deleted records before removing them
- Only targets documents missing both public_id and thumb_public_id that return 404

Usage:
    cd /app
    python scripts/prune_missing_album_photos.py --dry-run
    python scripts/prune_missing_album_photos.py --confirm
"""
import argparse
import datetime
import json
import os
import re
import sys

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_url_exists(raw_url, generate_signed_url_func):
    """Returns True if the URL or its signed Cloudinary variant exists (HTTP 200)."""
    import requests
    if not raw_url or not raw_url.startswith('http'):
        return False

    if ' ' in raw_url:
        raw_url = raw_url.replace(' ', '%20')

    try:
        r = requests.head(raw_url, timeout=10, allow_redirects=True)
        if r.status_code == 200:
            return True
        # Try GET in case HEAD is blocked
        r_get = requests.get(raw_url, timeout=15, stream=True)
        if r_get.status_code == 200:
            return True
    except Exception:
        pass

    # Try extracting public_id and generating signed URL
    m_id = re.search(r'/(?:image|raw|video)/(?:upload|authenticated)/(?:s--[^/]+--/)?(?:v\d+/)?(.+?)(?:\.[a-zA-Z0-9]+)?$', raw_url)
    if m_id and generate_signed_url_func:
        extracted_id = m_id.group(1).replace('%20', ' ')
        for r_type in ['image', 'raw']:
            for d_type in ['authenticated', 'upload']:
                for id_cand in [extracted_id, extracted_id.replace(' ', '%20')]:
                    s_url = generate_signed_url_func(id_cand, resource_type=r_type, delivery_type=d_type)
                    if s_url:
                        try:
                            t = requests.head(s_url, timeout=10)
                            if t.status_code == 200:
                                return True
                        except Exception:
                            pass
    return False


def run_prune(confirm=False):
    from main import app, bond_album_photos_conf
    from security import decrypt_bond_data, generate_signed_cloudinary_url
    from bson.objectid import ObjectId

    with app.app_context():
        # Target documents that do not have thumbnails
        query = {
            '$or': [
                {'thumb_public_id': {'$exists': False}},
                {'thumb_public_id': ''},
                {'thumb_public_id': None},
            ]
        }

        docs = list(bond_album_photos_conf.find(query))
        print(f"[prune] Found {len(docs)} documents without thumbnails to inspect.")

        orphans = []

        for doc in docs:
            photo_id = doc['_id']
            public_id = doc.get('public_id')
            raw_url = doc.get('url', '')

            # Decrypt URL if encrypted
            if doc.get('encrypted') and raw_url:
                try:
                    raw_url = decrypt_bond_data(raw_url, str(doc['bond_id']))
                except Exception:
                    pass

            exists = False
            if raw_url and raw_url.startswith('http'):
                exists = check_url_exists(raw_url, generate_signed_cloudinary_url)
            elif public_id:
                s_url = generate_signed_cloudinary_url(public_id, resource_type='raw', delivery_type='authenticated')
                if s_url:
                    exists = check_url_exists(s_url, None)

            if not exists:
                print(f"  [ORPHAN] ID={photo_id} (date={doc.get('date_taken')}) -> remote file missing (404)")
                orphans.append(doc)
            else:
                print(f"  [OK] ID={photo_id} -> file exists remotely, keeping.")

        print(f"\n[prune] Total orphaned documents identified: {len(orphans)}")

        if not orphans:
            print("[prune] No orphaned documents to delete.")
            return

        if not confirm:
            print("\n[DRY RUN] No records deleted. Run with --confirm to prune these orphaned records.")
            return

        # Backup before deletion
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_deleted_photos_{timestamp}.json"
        
        # Serialize docs safely
        serializable_orphans = []
        for d in orphans:
            d_copy = {}
            for k, v in d.items():
                if isinstance(v, ObjectId):
                    d_copy[k] = str(v)
                elif isinstance(v, (datetime.datetime, datetime.date)):
                    d_copy[k] = v.isoformat()
                else:
                    d_copy[k] = v
            serializable_orphans.append(d_copy)

        with open(backup_filename, 'w', encoding='utf-8') as f:
            json.dump(serializable_orphans, f, indent=2)
        print(f"[prune] Backup of {len(orphans)} documents saved to {backup_filename}")

        # Collect affected bond IDs
        affected_bonds = list(set(str(d.get('bond_id')) for d in orphans if d.get('bond_id')))

        # Execute deletion
        orphan_ids = [d['_id'] for d in orphans]
        res = bond_album_photos_conf.delete_many({'_id': {'$in': orphan_ids}})
        print(f"[prune] SUCCESS: Deleted {res.deleted_count} orphaned records from MongoDB.")

        # Emit socket updates so UI refreshes live
        try:
            from main import socketio
            for bid in affected_bonds:
                socketio.emit('bond_album_updated', {'bond_id': bid})
            print(f"[prune] Emitted live refresh event for bonds: {affected_bonds}")
        except Exception:
            pass
        print(f"[prune] Your album database now contains only valid, existing photos.")


def main():
    parser = argparse.ArgumentParser(description="Prune orphaned album photos from MongoDB.")
    parser.add_argument('--confirm', action='store_true', help="Confirm deletion of orphaned records")
    parser.add_argument('--dry-run', action='store_true', help="Preview deletions without modifying database")
    args = parser.parse_args()

    run_prune(confirm=args.confirm and not args.dry_run)


if __name__ == '__main__':
    main()
