#!/usr/bin/env python3
"""
Restores soft-deleted documents (marked with _deleted_at) from MongoDB Atlas back to the local MongoDB database.
Supports selective restoration by collection and user ID.
"""

import os
import sys
import datetime
import argparse
from dotenv import load_dotenv

load_dotenv()

# Maps collection name to the field name that stores the user reference
USER_FIELD_MAPPING = {
    'users': '_id',
    'posts': 'author_id',
    'comments': 'author_id',
    'personal_posts': 'user_id',
    'note_shares': 'owner_id',
    'note_versions': 'content_owner_id',
    'note_discussions': 'user_id',
    'announcements': 'author_id',
    'push_subscriptions': 'user_id',
    'fcm_tokens': 'user_id',
    'user_post_views': 'user_id',
    'unlock_notifications': 'owner_id',
}


def run_restore(collections_to_restore=None, user_id=None):
    from pymongo import MongoClient
    from bson.objectid import ObjectId

    local_uri = os.environ.get('MONGODB_CONNECTION')
    atlas_uri = os.environ.get('ATLAS_MONGODB_CONNECTION')

    if not local_uri:
        print("ERROR: MONGODB_CONNECTION env var not set")
        return False

    if not atlas_uri:
        print("ERROR: ATLAS_MONGODB_CONNECTION env var not set")
        return False

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
        now = datetime.datetime.now(datetime.timezone.utc)
        print(f"[{now}] Connected to both local and Atlas MongoDB")

        # Get all collection names from Atlas
        all_collections = atlas_db.list_collection_names()
        total_restored = 0
        total_errors = 0

        for coll_name in all_collections:
            if coll_name.startswith('system.') or coll_name.startswith('_backup'):
                continue

            # Filter by collection if specified
            if collections_to_restore and coll_name not in collections_to_restore:
                continue

            local_coll = local_db[coll_name]
            atlas_coll = atlas_db[coll_name]

            # Build query to select soft-deleted documents
            query = {'_deleted_at': {'$exists': True}}

            if user_id:
                user_field = USER_FIELD_MAPPING.get(coll_name)
                if not user_field:
                    # Skip collections that do not contain user-specific data to prevent leaking/overwriting
                    continue

                # Query matching either ObjectId or string format of the user_id
                try:
                    user_obj_id = ObjectId(user_id)
                    query[user_field] = {'$in': [user_obj_id, user_id]}
                except Exception:
                    query[user_field] = user_id

            docs = list(atlas_coll.find(query))
            if not docs:
                continue

            restored = 0
            errors = 0
            for doc in docs:
                try:
                    # Remove the metadata field before inserting/updating locally
                    doc.pop('_deleted_at', None)
                    
                    # Restore/upsert to local DB
                    local_coll.replace_one(
                        {'_id': doc['_id']},
                        doc,
                        upsert=True
                    )
                    
                    # Remove '_deleted_at' field from the document in Atlas so it is no longer marked as deleted
                    atlas_coll.update_one(
                        {'_id': doc['_id']},
                        {'$unset': {'_deleted_at': ''}}
                    )
                    restored += 1
                except Exception as e:
                    errors += 1
                    if errors <= 3:
                        print(f"  Error restoring doc in {coll_name}: {e}")

            total_restored += restored
            total_errors += errors
            if restored or errors:
                print(f"  {coll_name}: restored {restored} documents, {errors} errors")

        print(f"[{datetime.datetime.now(datetime.timezone.utc)}] Restore complete: {total_restored} documents restored, {total_errors} errors")

        local_client.close()
        atlas_client.close()
        return total_errors == 0

    except Exception as e:
        print(f"[{datetime.datetime.now()}] Restore failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Restore soft-deleted data from Atlas to local MongoDB.")
    parser.add_argument(
        '--collections',
        type=str,
        help="Comma-separated list of collections to restore (e.g. personal_posts,note_shares)"
    )
    parser.add_argument(
        '--user-id',
        type=str,
        help="Restore only documents matching this User ID"
    )

    args = parser.parse_args()

    collections_to_restore = None
    if args.collections:
        collections_to_restore = [c.strip() for c in args.collections.split(',') if c.strip()]

    success = run_restore(
        collections_to_restore=collections_to_restore,
        user_id=args.user_id
    )
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
