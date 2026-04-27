"""
repair_version_owner_ids.py — One-time data repair script
Fixes historical note_versions records that are missing content_owner_id.

For each version record, if content_owner_id is missing:
1. Looks at the parent note's content_owner_id or user_id
2. If the version has a share_id, looks at the share's owner_id
3. Sets the content_owner_id on the version record

Run with --dry-run first to see what would be changed.
Run without --dry-run to apply changes.

This script is idempotent — safe to re-run.

Usage:
    python repair_version_owner_ids.py --dry-run
    python repair_version_owner_ids.py

Date: 2026-04-27
Author: Antigravity (automated repair)
"""

import sys
import os
import argparse
from bson import ObjectId
from dotenv import load_dotenv

# Add parent directory to path so we can import from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
load_dotenv()


def get_db_connection():
    """Get MongoDB connection from environment (matches encrypt_legacy_data.py)."""
    from pymongo import MongoClient
    mongo_uri = os.environ.get('MONGODB_CONNECTION')
    if not mongo_uri:
        print("ERROR: MONGODB_CONNECTION environment variable not found.")
        print("Make sure your .env file is present or set the variable, e.g.:")
        print("  export MONGODB_CONNECTION='mongodb+srv://...'")
        sys.exit(1)
    
    client = MongoClient(mongo_uri)
    db = client['echowithin_db']
    return db


def repair_versions(dry_run=True):
    """Repair note_versions records missing content_owner_id."""
    db = get_db_connection()
    
    note_versions = db['note_versions']
    personal_posts = db['personal_posts']
    note_shares = db['note_shares']
    
    # Find all version records that are missing content_owner_id
    missing_filter = {
        '$or': [
            {'content_owner_id': None},
            {'content_owner_id': {'$exists': False}}
        ]
    }
    
    total = note_versions.count_documents(missing_filter)
    print(f"\n{'[DRY RUN] ' if dry_run else ''}Found {total} version records missing content_owner_id\n")
    
    if total == 0:
        print("Nothing to repair!")
        return
    
    fixed = 0
    skipped = 0
    errors = 0
    
    cursor = note_versions.find(missing_filter).batch_size(100)
    
    for v in cursor:
        ver_id = v['_id']
        note_id = v.get('note_id')
        share_id = v.get('share_id')
        editor_id = v.get('editor_id')
        
        resolved_owner_id = None
        resolution_source = None
        
        # Strategy 1: Look at the parent note
        if note_id:
            note = personal_posts.find_one(
                {'_id': note_id},
                {'content_owner_id': 1, 'user_id': 1}
            )
            if note:
                resolved_owner_id = note.get('content_owner_id') or note.get('user_id')
                resolution_source = 'parent note'
        
        # Strategy 2: Look at the share record
        if not resolved_owner_id and share_id:
            share = note_shares.find_one(
                {'share_id': share_id},
                {'owner_id': 1}
            )
            if share and share.get('owner_id'):
                resolved_owner_id = share['owner_id']
                resolution_source = 'share record'
        
        # Strategy 3: Use the editor_id as fallback (they created the snapshot)
        if not resolved_owner_id and editor_id:
            resolved_owner_id = editor_id
            resolution_source = 'editor_id fallback'
        
        if not resolved_owner_id:
            print(f"  SKIP {ver_id} — cannot determine owner (note_id={note_id}, share_id={share_id})")
            skipped += 1
            continue
        
        # Ensure it's an ObjectId
        if not isinstance(resolved_owner_id, ObjectId):
            try:
                resolved_owner_id = ObjectId(str(resolved_owner_id))
            except Exception:
                print(f"  ERROR {ver_id} — invalid owner ID: {resolved_owner_id}")
                errors += 1
                continue
        
        event_type = v.get('event_type', 'snapshot')
        editor_name = v.get('editor_name', 'Unknown')
        created_at = v.get('created_at', '?')
        
        if dry_run:
            print(f"  WOULD FIX {ver_id} [{event_type}] by {editor_name} @ {created_at}")
            print(f"           → content_owner_id = {resolved_owner_id} (from {resolution_source})")
        else:
            try:
                note_versions.update_one(
                    {'_id': ver_id},
                    {'$set': {'content_owner_id': resolved_owner_id}}
                )
                print(f"  FIXED {ver_id} [{event_type}] → {resolved_owner_id} (from {resolution_source})")
            except Exception as e:
                print(f"  ERROR {ver_id} — update failed: {e}")
                errors += 1
                continue
        
        fixed += 1
    
    print(f"\n{'[DRY RUN] ' if dry_run else ''}Summary:")
    print(f"  Total missing:  {total}")
    print(f"  {'Would fix' if dry_run else 'Fixed'}:      {fixed}")
    print(f"  Skipped:        {skipped}")
    print(f"  Errors:         {errors}")
    
    if dry_run and fixed > 0:
        print(f"\nRun without --dry-run to apply these {fixed} fixes.")


def verify_decryption(sample_size=5):
    """After repair, verify a sample of records can be decrypted."""
    print(f"\n--- Decryption Verification (sample of {sample_size}) ---")
    
    try:
        # Import app decryption functions
        from main import _get_user_fernet, get_notes_fernet
        
        db = get_db_connection()
        note_versions = db['note_versions']
        
        # Get a sample of encrypted versions with content_owner_id
        sample = list(note_versions.find(
            {'encrypted': True, 'content_owner_id': {'$exists': True, '$ne': None}}
        ).limit(sample_size))
        
        success = 0
        fail = 0
        
        for v in sample:
            content = v.get('content', '')
            owner_id = str(v.get('content_owner_id', ''))
            
            if not content or not content.startswith('gAAAAA'):
                print(f"  SKIP {v['_id']} — not encrypted content")
                continue
            
            try:
                f = _get_user_fernet(owner_id)
                f.decrypt(content.encode('utf-8'))
                print(f"  OK   {v['_id']} — decrypts with owner {owner_id}")
                success += 1
            except Exception:
                try:
                    get_notes_fernet().decrypt(content.encode('utf-8'))
                    print(f"  OK   {v['_id']} — decrypts with v1 global key")
                    success += 1
                except Exception:
                    print(f"  FAIL {v['_id']} — cannot decrypt with owner {owner_id} or v1 key")
                    fail += 1
        
        print(f"\nVerification: {success} OK, {fail} FAIL out of {len(sample)} sampled")
        
    except ImportError as e:
        print(f"  Cannot import app modules for verification: {e}")
        print("  Skipping verification — run from the app directory.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Repair note_versions records missing content_owner_id')
    parser.add_argument('--dry-run', action='store_true', default=False,
                        help='Show what would be changed without modifying anything')
    parser.add_argument('--verify', action='store_true', default=False,
                        help='After repair, verify a sample of records can be decrypted')
    args = parser.parse_args()
    
    print("=" * 60)
    print("  EchoWithin — Note Version Owner ID Repair Script")
    print("=" * 60)
    
    repair_versions(dry_run=args.dry_run)
    
    if args.verify and not args.dry_run:
        verify_decryption()
    
    print("\nDone.")
