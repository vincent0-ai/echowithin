#!/usr/bin/env python3
"""
Cleanup script for expired authentication tokens and confirmation codes.
This script deletes expired reset tokens and confirmation codes from the auth collection.
"""

import os
import sys
import datetime

# Add the parent directory to the path so we can import from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Environment variable {name} is not set")
    return value

def cleanup_expired_auth_records():
    """
    Delete expired authentication records from the database.
    - Confirmation codes older than 24 hours
    - Password reset tokens older than their expiry time
    """
    try:
        client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
        db = client['echowithin_db']
        auth_conf = db['auth']
        
        now = datetime.datetime.now()
        
        # Delete expired confirmation codes (code_expiry < now)
        expired_codes_result = auth_conf.delete_many({
            'hashed_code': {'$exists': True},
            'code_expiry': {'$lt': now}
        })
        
        # Delete expired reset tokens (reset_expiry < now)
        expired_tokens_result = auth_conf.delete_many({
            'reset_token': {'$exists': True},
            'reset_expiry': {'$lt': now}
        })
        
        # Also delete old confirmation codes that don't have an expiry field (legacy records)
        # These are codes older than 24 hours based on no expiry field existing
        # We'll delete codes that have hashed_code but no code_expiry (legacy) and no reset_token
        legacy_cleanup = auth_conf.delete_many({
            'hashed_code': {'$exists': True},
            'code_expiry': {'$exists': False},
            'reset_token': {'$exists': False}
        })
        
        total_deleted = (expired_codes_result.deleted_count + 
                        expired_tokens_result.deleted_count + 
                        legacy_cleanup.deleted_count)
        
        print(f"Cleanup completed at {now.isoformat()}")
        print(f"  - Expired confirmation codes deleted: {expired_codes_result.deleted_count}")
        print(f"  - Expired reset tokens deleted: {expired_tokens_result.deleted_count}")
        print(f"  - Legacy records cleaned: {legacy_cleanup.deleted_count}")
        print(f"  - Total records deleted: {total_deleted}")
        
        client.close()
        return total_deleted
        
    except Exception as e:
        print(f"Error during cleanup: {e}")
        return 0

if __name__ == '__main__':
    cleanup_expired_auth_records()
