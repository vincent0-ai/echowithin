#!/usr/bin/env python3
"""
Backs up all collections from the local MongoDB to a MongoDB Atlas cluster.
Runs as a scheduled task via scheduler.py.

Uses incremental sync: only documents created/modified since the last
successful backup are transferred.  A full sync of deletions is still
performed, but only the _id field is fetched for comparison.

Only requires ATLAS_MONGODB_CONNECTION env var to be set.
"""

import os
import sys
import datetime
import requests
from dotenv import load_dotenv

load_dotenv()


def send_ntfy_alert(message, title="🚨 CRITICAL: Database Backup Circuit Breaker", tags="rotating_light,sos,warning", priority="max"):
    """Sends a high-priority alert to the configured ntfy topic."""
    ntfy_topic = os.environ.get('NTFY_TOPIC')
    if not ntfy_topic:
        print("NTFY_TOPIC not configured; skipping ntfy alert.")
        return
    try:
        headers = {
            'Title': title,
            'Tags': tags,
            'Priority': priority
        }
        ntfy_user = os.environ.get('NTFY_USERNAME')
        ntfy_pass = os.environ.get('NTFY_PASSWORD')
        auth = (ntfy_user, ntfy_pass) if ntfy_user and ntfy_pass else None

        resp = requests.post(
            f"https://ntfy.sh/{ntfy_topic}",
            data=message.encode('utf-8'),
            headers=headers,
            timeout=10,
            auth=auth
        )
        if resp.ok:
            print(f"Successfully sent ntfy alert to topic: {ntfy_topic}")
        else:
            print(f"Failed to send ntfy alert: status={resp.status_code}, body={resp.text}")
    except Exception as e:
        print(f"Error sending ntfy alert: {e}")

# Collections that have a reliable timestamp field for incremental sync
# Maps collection name -> list of timestamp field names to check (in priority order)
TIMESTAMP_FIELDS = {
    'users':                    ['last_active', 'created_at'],
    'posts':                    ['edited_at', 'timestamp'],
    'comments':                 ['timestamp'],
    'personal_posts':           ['updated_at', 'created_at'],
    'note_shares':              ['created_at'],
    'note_versions':            ['created_at'],
    'note_discussions':         ['created_at'],
    'announcements':            ['created_at'],
    'logs':                     ['timestamp'],
    'newsletter_subs':          ['subscribed_at'],
    'push_subscriptions':       ['created_at'],
    'fcm_tokens':               ['updated_at', 'created_at'],
    'user_post_views':          ['last_viewed'],
    'unlock_notifications':     ['created_at'],
    'weekly_winners':           ['week_start'],
    'direct_messages':          ['timestamp'],
    'bond_journal':             ['created_at', 'timestamp'],
    'bond_moods':               ['timestamp', 'created_at'],
    'bond_goals':               ['updated_at', 'created_at'],
    'bond_habits':              ['updated_at', 'created_at'],
    'bond_qotd':                ['date', 'created_at'],
    'bond_pulses':              ['timestamp', 'created_at'],
    'bond_album_photos':        ['created_at'],
    'bond_countdowns':          ['target_date', 'created_at'],
    'bond_events':              ['created_at', 'updated_at', 'start_date'],
    'bond_bucketlist':          ['updated_at', 'created_at'],
    'bond_recommendations':     ['created_at'],
    'bonds':                    ['updated_at', 'created_at', 'accepted_at'],
    'communities':              ['updated_at', 'created_at'],
    'community_notes':          ['updated_at', 'created_at'],
    'community_questions':      ['created_at'],
    'community_checkins':       ['timestamp', 'created_at'],
    'community_polls':          ['created_at'],
    'community_poll_votes':     ['created_at'],
    'community_reactions':      ['created_at'],
    'community_reports':        ['created_at'],
    'community_premium_vouchers': ['created_at'],
    'forms':                    ['updated_at', 'created_at'],
    'form_responses':           ['created_at', 'submitted_at'],
    'game_votes':               ['created_at'],
    'game_sessions':            ['updated_at', 'created_at'],
    'arcade_leaderboards':      ['updated_at', 'timestamp'],
    'dm_permissions':           ['updated_at', 'created_at'],
    'scheduled_messages':       ['created_at', 'scheduled_at'],
    'note_attachments':         ['created_at'],
    'app_tokens':               ['created_at', 'last_used'],
    'user_sessions':            ['last_active', 'created_at'],
    'app_updates':              ['release_date', 'created_at'],
    'auth':                     ['created_at'],
    'revoked_push_endpoints':   ['revoked_at', 'created_at'],
}


def run_backup():
    from pymongo import MongoClient, ReplaceOne
    from bson.objectid import ObjectId

    local_uri = os.environ.get('MONGODB_CONNECTION')
    atlas_uri = os.environ.get('ATLAS_MONGODB_CONNECTION')

    if not local_uri:
        print("ERROR: MONGODB_CONNECTION env var not set")
        return False

    if not atlas_uri:
        print("SKIP: ATLAS_MONGODB_CONNECTION env var not set, skipping Atlas backup")
        return True  # Not an error, just not configured

    db_name = 'echowithin_db'

    try:
        # Connect to both databases
        local_client = MongoClient(local_uri, serverSelectionTimeoutMS=10000)
        
        # Add retry logic for Atlas connection to handle transient DNS errors
        import time
        max_retries = 3
        atlas_client = None
        for attempt in range(max_retries):
            try:
                atlas_client = MongoClient(atlas_uri, serverSelectionTimeoutMS=15000)
                atlas_client.admin.command('ping')
                break
            except Exception as e:
                print(f"[{datetime.datetime.now(datetime.timezone.utc)}] Atlas connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    raise

        local_db = local_client[db_name]
        atlas_db = atlas_client[db_name]

        # Test connections
        local_client.admin.command('ping')
        atlas_client.admin.command('ping')
        now = datetime.datetime.now(datetime.timezone.utc)
        print(f"[{now}] Connected to both local and Atlas MongoDB")

        # Retrieve last successful backup time from Atlas metadata
        meta_coll = atlas_db['_backup_meta']
        meta = meta_coll.find_one({'_id': 'last_backup'})
        last_backup = meta['timestamp'] if meta else None
        if last_backup:
            print(f"  Last backup: {last_backup.isoformat()}")
        else:
            print("  No previous backup found — running full sync")

        # Get all collection names from local
        collections = local_db.list_collection_names()
        total_synced = 0
        total_deleted = 0
        total_errors = 0

        # --- Circuit Breaker / Mass Deletion Guard ---
        # Calculate total active documents in local DB vs Atlas DB
        total_local_docs = sum(local_db[c].count_documents({}) for c in collections if not c.startswith('system.') and not c.startswith('_backup') and c != 'deleted_items' and not c.startswith('whisper_'))
        atlas_colls = atlas_db.list_collection_names()
        total_atlas_docs = sum(atlas_db[c].count_documents({'_deleted_at': {'$exists': False}}) for c in collections if c in atlas_colls and not c.startswith('system.') and not c.startswith('_backup') and c != 'deleted_items' and not c.startswith('whisper_'))

        if total_atlas_docs >= 20 and total_local_docs < (total_atlas_docs * 0.5):
            alert_msg = (
                f"🚨 BACKUP ABORTED! Circuit Breaker Triggered.\n"
                f"Local DB document count ({total_local_docs}) is less than 50% of Atlas DB count ({total_atlas_docs}).\n"
                f"Atlas backup is locked to prevent data destruction. Inspect local MongoDB immediately!"
            )
            print(f"[{now}] {alert_msg}")
            send_ntfy_alert(alert_msg)
            return False

        for coll_name in collections:
            if coll_name.startswith('system.') or coll_name.startswith('_backup') or coll_name == 'deleted_items' or coll_name.startswith('whisper_'):
                continue

            local_coll = local_db[coll_name]
            atlas_coll = atlas_db[coll_name]

            # --- Incremental fetch: only docs modified since last backup ---
            ts_fields = TIMESTAMP_FIELDS.get(coll_name)
            query = {}
            if last_backup:
                or_clauses = []
                if ts_fields:
                    or_clauses.extend([{f: {'$gte': last_backup}} for f in ts_fields])
                try:
                    min_oid = ObjectId.from_datetime(last_backup)
                    or_clauses.append({'_id': {'$gte': min_oid}})
                except Exception:
                    pass
                if or_clauses:
                    query = {'$or': or_clauses}

            docs = list(local_coll.find(query))
            if not docs and last_backup:
                # No changes since last backup for this collection — skip upsert
                pass

            # Upsert changed documents to Atlas in batches
            synced = 0
            errors = 0
            batch_size = 100
            for i in range(0, len(docs), batch_size):
                batch = docs[i:i + batch_size]
                operations = [ReplaceOne({'_id': doc['_id']}, doc, upsert=True) for doc in batch]
                try:
                    atlas_coll.bulk_write(operations, ordered=False)
                    synced += len(batch)
                except Exception as e:
                    # Fallback to individual replace_one if bulk_write encounters an error
                    for doc in batch:
                        try:
                            atlas_coll.replace_one({'_id': doc['_id']}, doc, upsert=True)
                            synced += 1
                        except Exception as doc_err:
                            errors += 1
                            if errors <= 3:
                                print(f"  Error syncing doc in {coll_name}: {doc_err}")

            # --- Remove stale documents (deleted locally) ---
            # Only fetch _id fields for comparison to minimize data transfer
            local_ids = {d['_id'] for d in local_coll.find({}, {'_id': 1})}
            atlas_ids = {d['_id'] for d in atlas_coll.find({}, {'_id': 1})}
            stale_ids = list(atlas_ids - local_ids)
            deleted = 0
            marked = 0
            if stale_ids:
                # Mark newly deleted documents in Atlas with '_deleted_at' if not already marked
                mark_result = atlas_coll.update_many(
                    {'_id': {'$in': stale_ids}, '_deleted_at': {'$exists': False}},
                    {'$set': {'_deleted_at': now}}
                )
                marked = mark_result.modified_count

                # Purge stale documents in Atlas whose '_deleted_at' is older than 3 days
                three_days_ago = now - datetime.timedelta(days=3)
                delete_result = atlas_coll.delete_many(
                    {'_id': {'$in': stale_ids}, '_deleted_at': {'$lt': three_days_ago}}
                )
                deleted = delete_result.deleted_count
                if marked or deleted:
                    print(f"  {coll_name}: marked {marked} deleted, removed {deleted} stale documents")

            total_synced += synced
            total_deleted += deleted
            total_errors += errors
            if synced or marked or deleted or errors:
                print(f"  {coll_name}: {synced} synced, {marked} marked deleted, {deleted} purged, {errors} errors")

        # Save backup timestamp
        meta_coll.replace_one(
            {'_id': 'last_backup'},
            {'_id': 'last_backup', 'timestamp': now},
            upsert=True
        )

        print(f"[{now}] Atlas backup complete: {total_synced} docs synced, "
              f"{total_deleted} deleted, {total_errors} errors")

        local_client.close()
        atlas_client.close()
        return total_errors == 0

    except Exception as e:
        print(f"[{datetime.datetime.now()}] Atlas backup failed: {e}")
        return False


if __name__ == '__main__':
    success = run_backup()
    sys.exit(0 if success else 1)
