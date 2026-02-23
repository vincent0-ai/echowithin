#!/usr/bin/env python3
"""
Backs up all collections from the local MongoDB to a MongoDB Atlas cluster.
Runs as a scheduled task via scheduler.py.

Uses upsert operations to sync data without duplicates.
Only requires ATLAS_MONGODB_CONNECTION env var to be set.
"""

import os
import sys
import datetime
from dotenv import load_dotenv

load_dotenv()


def run_backup():
    from pymongo import MongoClient

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
        atlas_client = MongoClient(atlas_uri, serverSelectionTimeoutMS=15000)

        local_db = local_client[db_name]
        atlas_db = atlas_client[db_name]

        # Test connections
        local_client.admin.command('ping')
        atlas_client.admin.command('ping')
        print(f"[{datetime.datetime.now()}] Connected to both local and Atlas MongoDB")

        # Get all collection names from local
        collections = local_db.list_collection_names()
        total_docs = 0
        total_errors = 0

        for coll_name in collections:
            if coll_name.startswith('system.'):
                continue  # Skip system collections

            local_coll = local_db[coll_name]
            atlas_coll = atlas_db[coll_name]

            # Get all documents from local
            docs = list(local_coll.find())
            if not docs:
                continue

            # Upsert each document to Atlas
            synced = 0
            errors = 0
            for doc in docs:
                try:
                    atlas_coll.replace_one(
                        {'_id': doc['_id']},
                        doc,
                        upsert=True
                    )
                    synced += 1
                except Exception as e:
                    errors += 1
                    if errors <= 3:  # Only log first 3 errors per collection
                        print(f"  Error syncing doc in {coll_name}: {e}")

            # Remove documents from Atlas that no longer exist locally
            local_ids = {doc['_id'] for doc in docs}
            atlas_docs = atlas_coll.find({}, {'_id': 1})
            stale_ids = [d['_id'] for d in atlas_docs if d['_id'] not in local_ids]
            if stale_ids:
                atlas_coll.delete_many({'_id': {'$in': stale_ids}})
                print(f"  {coll_name}: removed {len(stale_ids)} stale documents")

            total_docs += synced
            total_errors += errors
            print(f"  {coll_name}: {synced} docs synced, {errors} errors")

        print(f"[{datetime.datetime.now()}] Atlas backup complete: {total_docs} docs synced across {len(collections)} collections, {total_errors} errors")

        local_client.close()
        atlas_client.close()
        return total_errors == 0

    except Exception as e:
        print(f"[{datetime.datetime.now()}] Atlas backup failed: {e}")
        return False


if __name__ == '__main__':
    success = run_backup()
    sys.exit(0 if success else 1)
