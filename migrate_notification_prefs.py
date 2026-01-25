#!/ reentry/env python3
"""
Migration script to initialize notification_preference for existing users.
- notify_new_posts: True or missing -> notification_preference: 'weekly'
- notify_new_posts: False -> notification_preference: 'none'
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

def migrate():
    connection_string = get_env_variable('MONGODB_CONNECTION')
    client = MongoClient(connection_string)
    db = client['echowithin_db']
    users_conf = db['users']

    print("Starting migration of notification preferences...")

    # 1. Users who opted out previously -> 'none'
    res_none = users_conf.update_many(
        {'notify_new_posts': False},
        {'$set': {'notification_preference': 'none'}}
    )
    print(f"Updated {res_none.modified_count} users to 'none' (based on notify_new_posts=False).")

    # 2. Users who opted in or have no field set -> 'weekly'
    # We check for notification_preference: {$exists: false} to avoid overwriting step 1 or future reruns
    res_weekly = users_conf.update_many(
        {'notification_preference': {'$exists': False}},
        {'$set': {'notification_preference': 'weekly'}}
    )
    print(f"Updated {res_weekly.modified_count} users to 'weekly' (default).")

    print("Migration completed.")

if __name__ == '__main__':
    migrate()
