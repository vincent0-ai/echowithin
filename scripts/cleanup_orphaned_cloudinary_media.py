#!/usr/bin/env python3
"""
Orphaned Cloudinary Media Audit & Cleanup Script for EchoWithin.

Safely cross-references all Cloudinary assets against active MongoDB references
and identifies orphaned files that are no longer referenced by any database record.

Safety rules:
  1. Defaults to --dry-run. No destructive actions are performed unless --confirm is passed.
  2. Preserves Cloudinary default samples and system assets.
  3. Supports batch deletion (up to 100 assets per call) when --confirm is provided.
  4. Non-blocking error handling: individual batch failures are logged without terminating the audit.
"""

import os
import sys
import re
import json
import argparse
from typing import Set, Dict, List, Any
from dotenv import load_dotenv

# Ensure project root is in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

load_dotenv(os.path.join(PROJECT_ROOT, '.env'), override=True)

import main as m
import cloudinary
import cloudinary.api
from pymongo import MongoClient
from bson.objectid import ObjectId

import security
import utils


def get_cloudinary_credentials():
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME')
    api_key = os.environ.get('CLOUDINARY_API_KEY')
    api_secret = os.environ.get('CLOUDINARY_API_SECRET')

    if not all([cloud_name, api_key, api_secret]):
        raise ValueError(
            "Missing Cloudinary credentials. Ensure CLOUDINARY_CLOUD_NAME, "
            "CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET are set."
        )
    return cloud_name, api_key, api_secret


def collect_mongo_references(db) -> Dict[str, List[str]]:
    """Scan all MongoDB collections and collect all referenced public IDs."""
    references: Dict[str, List[str]] = {}

    def add_ref(pid: str, source: str):
        if not pid or not isinstance(pid, str):
            return
        pid = pid.strip()
        if not pid or pid.startswith('[Content unavailable'):
            return
        # Normalize: strip any leading slash or file extension
        clean_pid = pid.lstrip('/')
        if clean_pid not in references:
            references[clean_pid] = []
        references[clean_pid].append(source)
        # Also store version without extension if extension was included
        if '.' in clean_pid:
            base_pid = clean_pid.rsplit('.', 1)[0]
            if base_pid not in references:
                references[base_pid] = []
            references[base_pid].append(source)

    # 1. Posts (Blog)
    for p in db['posts'].find({}, {'_id': 1, 'image_public_id': 1, 'image_public_ids': 1, 'video_public_id': 1}):
        if p.get('image_public_id'):
            add_ref(p['image_public_id'], f"posts._id={p['_id']}:image_public_id")
        for pid in p.get('image_public_ids') or []:
            add_ref(pid, f"posts._id={p['_id']}:image_public_ids")
        if p.get('video_public_id'):
            add_ref(p['video_public_id'], f"posts._id={p['_id']}:video_public_id")

    # 2. Users (Avatars)
    for u in db['users'].find({}, {'_id': 1, 'profile_image_public_id': 1}):
        if u.get('profile_image_public_id'):
            add_ref(u['profile_image_public_id'], f"users._id={u['_id']}:profile_image_public_id")

    # 3. Direct Messages
    for dm in db['direct_messages'].find({}):
        u1, u2 = str(dm.get('sender_id', '')), str(dm.get('recipient_id', ''))
        raw_pub = dm.get('image_public_id')
        if raw_pub:
            plain_pub = raw_pub
            if isinstance(raw_pub, str) and raw_pub.startswith('gAAAAA'):
                try:
                    plain_pub = security.decrypt_dm(raw_pub, u1, u2)
                except Exception:
                    try:
                        plain_pub = security.decrypt_dm(raw_pub, u2, u1)
                    except Exception:
                        plain_pub = None
            if plain_pub:
                add_ref(plain_pub, f"direct_messages._id={dm['_id']}:image_public_id")

        raw_url = dm.get('image_url')
        if raw_url:
            plain_url = raw_url
            if isinstance(raw_url, str) and raw_url.startswith('gAAAAA'):
                try:
                    plain_url = security.decrypt_dm(raw_url, u1, u2)
                except Exception:
                    try:
                        plain_url = security.decrypt_dm(raw_url, u2, u1)
                    except Exception:
                        plain_url = None
            if plain_url:
                ext_pid = utils.extract_cloudinary_public_id(plain_url)
                if ext_pid:
                    add_ref(ext_pid, f"direct_messages._id={dm['_id']}:image_url")

    # 4. Scheduled Messages
    for sm in db['scheduled_messages'].find({}):
        u1, u2 = str(sm.get('sender_id', '')), str(sm.get('recipient_id', ''))
        raw_pub = sm.get('image_public_id')
        if raw_pub:
            plain_pub = raw_pub
            if isinstance(raw_pub, str) and raw_pub.startswith('gAAAAA'):
                try:
                    plain_pub = security.decrypt_dm(raw_pub, u1, u2)
                except Exception:
                    try:
                        plain_pub = security.decrypt_dm(raw_pub, u2, u1)
                    except Exception:
                        plain_pub = None
            if plain_pub:
                add_ref(plain_pub, f"scheduled_messages._id={sm['_id']}:image_public_id")

        raw_url = sm.get('image_url')
        if raw_url:
            plain_url = raw_url
            if isinstance(raw_url, str) and raw_url.startswith('gAAAAA'):
                try:
                    plain_url = security.decrypt_dm(raw_url, u1, u2)
                except Exception:
                    try:
                        plain_url = security.decrypt_dm(raw_url, u2, u1)
                    except Exception:
                        plain_url = None
            if plain_url:
                ext_pid = utils.extract_cloudinary_public_id(plain_url)
                if ext_pid:
                    add_ref(ext_pid, f"scheduled_messages._id={sm['_id']}:image_url")

    # 5. Whisper Messages
    for wm in db['whisper_messages'].find({}):
        raw_pub = wm.get('image_public_id')
        if raw_pub:
            add_ref(raw_pub, f"whisper_messages._id={wm['_id']}:image_public_id")
        raw_url = wm.get('image_url')
        if raw_url:
            ext_pid = utils.extract_cloudinary_public_id(raw_url)
            if ext_pid:
                add_ref(ext_pid, f"whisper_messages._id={wm['_id']}:image_url")

    # 6. Personal Posts (Notes)
    for pp in db['personal_posts'].find({}):
        uid = str(pp.get('user_id', ''))
        for field in ('valentine_photo', 'valentine_audio', 'valentine_document'):
            pub_field = f"{field}_public_id"
            if pp.get(pub_field):
                add_ref(pp[pub_field], f"personal_posts._id={pp['_id']}:{pub_field}")
            enc_url = pp.get(field)
            if enc_url:
                dec_url = None
                if enc_url.startswith('gAAAAA'):
                    try:
                        dec_url = security.decrypt_note(enc_url, user_id=uid)
                    except Exception:
                        dec_url = None
                else:
                    dec_url = enc_url
                if dec_url and not dec_url.startswith('gAAAAA') and not dec_url.startswith('[Content unavailable'):
                    ext_pid = utils.extract_cloudinary_public_id(dec_url)
                    if ext_pid:
                        add_ref(ext_pid, f"personal_posts._id={pp['_id']}:{field}")

    # 7. Note Shares
    for ns in db['note_shares'].find({}):
        oid = str(ns.get('owner_id', ''))
        for field in ('valentine_photo', 'valentine_audio', 'valentine_document'):
            pub_field = f"{field}_public_id"
            if ns.get(pub_field):
                add_ref(ns[pub_field], f"note_shares._id={ns['_id']}:{pub_field}")
            enc_url = ns.get(field)
            if enc_url:
                dec_url = None
                if enc_url.startswith('gAAAAA'):
                    try:
                        dec_url = security.decrypt_note(enc_url, user_id=oid)
                    except Exception:
                        dec_url = None
                else:
                    dec_url = enc_url
                if dec_url and not dec_url.startswith('gAAAAA') and not dec_url.startswith('[Content unavailable'):
                    ext_pid = utils.extract_cloudinary_public_id(dec_url)
                    if ext_pid:
                        add_ref(ext_pid, f"note_shares._id={ns['_id']}:{field}")

    # 8. Note Attachments
    for na in db['note_attachments'].find({}):
        if na.get('public_id'):
            add_ref(na['public_id'], f"note_attachments._id={na['_id']}:public_id")

    # 9. Bond Album Photos
    for bp in db['bond_album_photos'].find({}):
        pid = bp.get('public_id') or bp.get('image_public_id')
        if pid:
            add_ref(pid, f"bond_album_photos._id={bp['_id']}:public_id")

    # 10. Bond Recommendations
    for br in db['bond_recommendations'].find({}):
        pid = br.get('image_public_id') or br.get('public_id')
        if pid:
            add_ref(pid, f"bond_recommendations._id={br['_id']}:image_public_id")

    # 11. Community Resources
    for cr in db['community_resources'].find({}):
        pid = cr.get('public_id') or cr.get('file_public_id')
        if pid:
            add_ref(pid, f"community_resources._id={cr['_id']}:public_id")

    # 12. Community Notes
    for cn in db['community_notes'].find({}):
        if cn.get('valentine_photo_public_id'):
            add_ref(cn['valentine_photo_public_id'], f"community_notes._id={cn['_id']}:valentine_photo_public_id")
        if cn.get('valentine_audio_public_id'):
            add_ref(cn['valentine_audio_public_id'], f"community_notes._id={cn['_id']}:valentine_audio_public_id")

    # 13. Deleted Items (recovery backups within 3 days)
    for di in db['deleted_items'].find({}):
        doc_data = di.get('data') or {}
        for k, v in doc_data.items():
            if isinstance(v, str) and any(sub in k for sub in ['public_id', 'photo', 'video', 'audio']):
                if not v.startswith('gAAAAA'):
                    add_ref(v, f"deleted_items._id={di['_id']}:{k}")

    return references


def fetch_all_cloudinary_resources():
    """Fetches all assets across all resource_types and delivery_types from Cloudinary."""
    resource_types = ['image', 'raw', 'video']
    delivery_types = ['upload', 'authenticated']
    all_assets = []

    for r_type in resource_types:
        for d_type in delivery_types:
            next_cursor = None
            while True:
                params = {
                    'resource_type': r_type,
                    'type': d_type,
                    'max_results': 500
                }
                if next_cursor:
                    params['next_cursor'] = next_cursor
                try:
                    res = cloudinary.api.resources(**params)
                    items = res.get('resources', [])
                    for item in items:
                        all_assets.append({
                            'public_id': item.get('public_id'),
                            'resource_type': r_type,
                            'delivery_type': d_type,
                            'format': item.get('format'),
                            'bytes': item.get('bytes', 0),
                            'created_at': item.get('created_at'),
                            'secure_url': item.get('secure_url')
                        })
                    next_cursor = res.get('next_cursor')
                    if not next_cursor:
                        break
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print(f"Warning fetching {r_type}:{d_type}: {e}", file=sys.stderr)
                    break
    return all_assets


def is_system_or_sample(public_id: str) -> bool:
    """Never delete default Cloudinary samples or system demo assets."""
    if not public_id:
        return True
    pid_lower = public_id.lower()
    if pid_lower.startswith('sample') or pid_lower.startswith('samples/') or '/samples/' in pid_lower:
        return True
    return False


def run_cleanup(mongo_uri: str, dry_run: bool = True, verbose: bool = False, output_path: str = None):
    print("=" * 70)
    print(f"EchoWithin Cloudinary Orphan Cleanup {'(DRY RUN)' if dry_run else '(LIVE DELETION)'}")
    print("=" * 70)

    cloud_name, api_key, api_secret = get_cloudinary_credentials()
    cloudinary.config(
        cloud_name=cloud_name,
        api_key=api_key,
        api_secret=api_secret,
        secure=True
    )
    print(f"Connected to Cloudinary account: {cloud_name}")

    print(f"Connecting to MongoDB...")
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db = client['echowithin_db']
    print(f"Connected to MongoDB database: {db.name}")

    import database
    database.client = client
    database.db = db
    for attr in dir(database):
        if attr.endswith('_conf'):
            coll_name = attr[:-5]
            setattr(database, attr, db[coll_name])

    print("\n[Phase 1] Scanning MongoDB collections for referenced media...")
    references = collect_mongo_references(db)
    print(f"  Total unique referenced public IDs in MongoDB: {len(references)}")

    print("\n[Phase 2] Fetching all assets from Cloudinary...")
    cloudinary_assets = fetch_all_cloudinary_resources()
    print(f"  Total Cloudinary assets found: {len(cloudinary_assets)}")

    # Categorize
    referenced_assets = []
    orphaned_assets = []
    sample_assets = []

    for asset in cloudinary_assets:
        pid = asset['public_id']
        if is_system_or_sample(pid):
            sample_assets.append(asset)
            continue

        clean_pid = pid.lstrip('/')
        base_pid = clean_pid.rsplit('.', 1)[0] if '.' in clean_pid else clean_pid

        if clean_pid in references or base_pid in references:
            referenced_assets.append(asset)
        else:
            orphaned_assets.append(asset)

    total_orphan_bytes = sum(a.get('bytes', 0) for a in orphaned_assets)
    total_orphan_mb = total_orphan_bytes / (1024 * 1024)

    print("\n" + "-" * 50)
    print("AUDIT SUMMARY:")
    print(f"  Active referenced assets (KEEP):     {len(referenced_assets)}")
    print(f"  Default sample assets (PROTECTED):   {len(sample_assets)}")
    print(f"  Orphaned assets (CANDIDATES):        {len(orphaned_assets)}")
    print(f"  Reclaimable storage:                 {total_orphan_mb:.2f} MB ({total_orphan_bytes:,} bytes)")
    print("-" * 50)

    # Group orphans by resource_type & delivery_type
    grouped_orphans: Dict[tuple, List[dict]] = {}
    for a in orphaned_assets:
        key = (a['resource_type'], a['delivery_type'])
        if key not in grouped_orphans:
            grouped_orphans[key] = []
        grouped_orphans[key].append(a)

    print("\nOrphan Breakdown by Type:")
    for (r_type, d_type), items in grouped_orphans.items():
        mb = sum(it.get('bytes', 0) for it in items) / (1024 * 1024)
        print(f"  {r_type}:{d_type:15} -> {len(items):4d} assets ({mb:.2f} MB)")

    if verbose and orphaned_assets:
        print("\nOrphaned Assets List:")
        for a in orphaned_assets:
            print(f"  [{a['resource_type']}:{a['delivery_type']}] {a['public_id']} ({a.get('bytes', 0):,} bytes)")

    if output_path:
        report = {
            'timestamp': str(security.datetime.datetime.now(security.datetime.timezone.utc)),
            'summary': {
                'total_cloudinary_assets': len(cloudinary_assets),
                'referenced_count': len(referenced_assets),
                'sample_count': len(sample_assets),
                'orphan_count': len(orphaned_assets),
                'orphan_bytes': total_orphan_bytes,
                'orphan_mb': round(total_orphan_mb, 2)
            },
            'orphaned_assets': orphaned_assets
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport written to {output_path}")

    # Execution Phase
    if dry_run:
        print("\n[DRY RUN COMPLETE] No assets were deleted.")
        print("To permanently delete these orphaned assets, run this script with --confirm.")
        return

    print("\n[Phase 3] DELETING ORPHANED ASSETS FROM CLOUDINARY...")
    deleted_count = 0
    failed_count = 0

    for (r_type, d_type), items in grouped_orphans.items():
        pids = [it['public_id'] for it in items]
        print(f"\nDeleting {len(pids)} assets of type {r_type}:{d_type} in batches of 100...")

        # Batch in 100s
        for i in range(0, len(pids), 100):
            batch = pids[i:i + 100]
            try:
                res = cloudinary.api.delete_resources(
                    batch,
                    resource_type=r_type,
                    type=d_type,
                    invalidate=True
                )
                deleted_map = res.get('deleted', {})
                for pid, status in deleted_map.items():
                    if status in ('deleted', 'not_found'):
                        deleted_count += 1
                    else:
                        failed_count += 1
                        print(f"  Failed to delete {pid}: {status}", file=sys.stderr)
            except Exception as batch_err:
                print(f"  Batch delete failed for {r_type}:{d_type} (batch {i//100 + 1}): {batch_err}", file=sys.stderr)
                # Fallback to individual destroy
                for pid in batch:
                    ok = security.destroy_cloudinary_media(pid, resource_type=r_type, delivery_type=d_type)
                    if ok:
                        deleted_count += 1
                    else:
                        failed_count += 1

    print("\n" + "=" * 50)
    print(f"DELETION COMPLETE:")
    print(f"  Successfully deleted: {deleted_count}")
    print(f"  Failed:               {failed_count}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description="Audit and clean up orphaned Cloudinary media for EchoWithin.")
    parser.add_argument('--confirm', action='store_true', help="Perform actual deletion. Without this flag, script runs in dry-run mode.")
    parser.add_argument('--mongo-uri', default=None, help="MongoDB connection URI (defaults to LIVE_MONGODB_CONNECTION or MONGODB_CONNECTION).")
    parser.add_argument('--verbose', action='store_true', help="Print details of every orphaned asset.")
    parser.add_argument('--output', default=None, help="Write detailed JSON report to this file.")

    args = parser.parse_args()

    mongo_uri = args.mongo_uri or os.environ.get('LIVE_MONGODB_CONNECTION') or os.environ.get('MONGODB_CONNECTION')
    if not mongo_uri:
        print("Error: No MongoDB connection string found. Set LIVE_MONGODB_CONNECTION in .env or pass --mongo-uri.", file=sys.stderr)
        sys.exit(1)

    dry_run = not args.confirm
    run_cleanup(mongo_uri=mongo_uri, dry_run=dry_run, verbose=args.verbose, output_path=args.output)


if __name__ == '__main__':
    main()
