#!/usr/bin/env python3
"""
This script cleans up expired authentication records from the auth collection.
It removes:
  - Expired email verification codes (code_expiry < now)
  - Expired password reset tokens (reset_expiry < now)

It is intended to be run hourly by the scheduler.py script.
"""

import os
import sys
import datetime

from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()


def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        message = f"Expected environment variable '{name}' not set."
        raise Exception(message)


client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
db = client['echowithin_db']
auth_conf = db['auth']


def _purge_guest_data_standalone(db, guest_id_str):
    """Standalone database purge for an expired guest tour session."""
    from bson.objectid import ObjectId
    try:
        g_oid = ObjectId(guest_id_str)
    except Exception:
        return
    
    user_doc = db['users'].find_one({'_id': g_oid, 'is_guest': True})
    if not user_doc:
        return

    # 1. Notes & shares
    db['personal_posts'].delete_many({'user_id': g_oid})
    db['note_shares'].delete_many({'$or': [{'owner_id': g_oid}, {'user_id': g_oid}]})

    # 2. Bonds & partner demo bot
    bonds = list(db['bonds'].find({'$or': [{'user_a_id': g_oid}, {'user_b_id': g_oid}]}))
    for b in bonds:
        p_id = b['user_b_id'] if b['user_a_id'] == g_oid else b['user_a_id']
        db['users'].delete_one({'_id': p_id, 'is_demo_bot': True})

    db['bonds'].delete_many({'$or': [{'user_a_id': g_oid}, {'user_b_id': g_oid}]})
    db['bond_goals'].delete_many({'proposed_by': g_oid})
    db['bond_journal'].delete_many({'user_id': g_oid})
    db['bond_moods'].delete_many({'user_id': g_oid})
    db['bond_habits'].delete_many({'created_by': g_oid})
    db['bond_countdowns'].delete_many({'created_by': g_oid})

    # 3. Messages & Communities
    db['direct_messages'].delete_many({'$or': [{'sender_id': g_oid}, {'recipient_id': g_oid}]})
    db['dm_permissions'].delete_many({'$or': [{'requester_id': g_oid}, {'target_id': g_oid}]})
    db['community_memberships'].delete_many({'user_id': g_oid})

    # 4. User record
    db['users'].delete_one({'_id': g_oid})


def cleanup_expired_auth():
    """Removes expired verification codes, password reset tokens, and expired guest tour sessions."""
    try:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Delete expired email verification codes
        result_codes = auth_conf.delete_many({
            'code_expiry': {'$exists': True, '$ne': None, '$lt': now}
        })

        # Delete expired password reset tokens
        result_tokens = auth_conf.delete_many({
            'reset_expiry': {'$exists': True, '$ne': None, '$lt': now}
        })

        # Purge expired guest tour sessions
        users_conf = db['users']
        expired_guests = list(users_conf.find(
            {'is_guest': True, 'guest_expires_at': {'$exists': True, '$ne': None, '$lt': now}},
            {'_id': 1}
        ))
        
        twenty_mins_ago = now - datetime.timedelta(minutes=20)
        orphaned_guests = list(users_conf.find(
            {'is_guest': True, 'guest_expires_at': None, 'join_date': {'$lt': twenty_mins_ago}},
            {'_id': 1}
        ))
        
        all_expired_ids = set(str(g['_id']) for g in (expired_guests + orphaned_guests))
        for guest_id_str in all_expired_ids:
            _purge_guest_data_standalone(db, guest_id_str)

        total_deleted = result_codes.deleted_count + result_tokens.deleted_count + len(all_expired_ids)
        if total_deleted > 0:
            print(
                f"Auth & Guest cleanup: removed {result_codes.deleted_count} expired verification codes, "
                f"{result_tokens.deleted_count} expired reset tokens, and {len(all_expired_ids)} expired guest session(s)."
            )
        else:
            print("Auth cleanup: no expired records found.")
    finally:
        client.close()


if __name__ == '__main__':
    cleanup_expired_auth()
