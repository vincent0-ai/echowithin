#!/usr/bin/env python3
"""
Final migration script for EchoWithin.
- Migrates 'liked_by' list to 'reactions.heart'.
- Removes 'liked_by' and 'notify_new_posts' fields.
- Ensures all users have a 'notification_preference'.
"""

import os
import sys
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

def get_env_variable(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError:
        raise Exception(f"Expected environment variable '{name}' not set.")

def cleanup():
    connection_string = get_env_variable('MONGODB_CONNECTION')
    client = MongoClient(connection_string)
    db = client.get_default_database()
    
    posts_conf = db['posts']
    users_conf = db['users']

    print("--- Starting Post Migration (liked_by -> reactions.heart) ---")
    posts_with_likes = list(posts_conf.find({'liked_by': {'$exists': True, '$ne': []}}))
    print(f"Found {len(posts_with_likes)} posts with legacy likes.")

    for post in posts_with_likes:
        liked_by = post.get('liked_by', [])
        # Ensure all IDs are strings (standard for reactions)
        liked_by_strs = [str(uid) for uid in liked_by]
        
        posts_conf.update_one(
            {'_id': post['_id']},
            {
                '$addToSet': {'reactions.heart': {'$each': liked_by_strs}},
                '$unset': {'liked_by': ""}
            }
        )
    
    # Also clean up any empty liked_by fields
    res_clean_posts = posts_conf.update_many(
        {'liked_by': {'$exists': True}},
        {'$unset': {'liked_by': ""}}
    )
    print(f"Post cleanup complete. {res_clean_posts.modified_count} additional posts cleaned.")

    print("\n--- Starting User Migration (notify_new_posts cleanup) ---")
    
    # 1. Ensure notification_preference exists
    res_pref = users_conf.update_many(
        {'notification_preference': {'$exists': False}},
        {'$set': {'notification_preference': 'weekly'}}
    )
    print(f"Set default notification_preference for {res_pref.modified_count} users.")

    # 2. Remove legacy field
    res_clean_users = users_conf.update_many(
        {'notify_new_posts': {'$exists': True}},
        {'$unset': {'notify_new_posts': ""}}
    )
    print(f"User cleanup complete. {res_clean_users.modified_count} users cleaned.")

    print("\nMigration successfully completed!")

if __name__ == '__main__':
    cleanup()
