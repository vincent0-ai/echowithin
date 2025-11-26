#!/usr/bin/env python3
"""
Migration script to set notify_new_posts=True for all existing users.
This ensures all users are opted-in to email notifications by default.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import users_conf


def migrate_users_to_opt_in():
    """
    Set notify_new_posts=True for all users who don't have the field set.
    This makes them opted-in to notifications by default.
    """
    print("=" * 60)
    print("Migrating users to opt-in by default")
    print("=" * 60)
    
    # Find users without notify_new_posts field
    users_without_field = list(users_conf.find({'notify_new_posts': {'$exists': False}}))
    
    if not users_without_field:
        print("✓ All users already have notify_new_posts field set.")
        return True
    
    print(f"Found {len(users_without_field)} users without notify_new_posts field")
    print("Setting notify_new_posts=True for these users...")
    
    try:
        result = users_conf.update_many(
            {'notify_new_posts': {'$exists': False}},
            {'$set': {'notify_new_posts': True}}
        )
        print(f"✓ Updated {result.modified_count} users")
        print("\nMigration complete! All users are now opted-in to email notifications.")
        print("Users can opt-out by unchecking the preference in Account Settings.")
        return True
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = migrate_users_to_opt_in()
    sys.exit(0 if success else 1)
