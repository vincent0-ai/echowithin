#!/usr/bin/env python3
"""
This script finds and purges orphaned communities in EchoWithin:
  - Communities with 0 members.
  - Communities where all members are deleted accounts.
  - Communities whose creator/admin was deleted with no remaining members.
  - If a creator/admin was deleted but active members remain, reassigns admin to the first active member.

Can be run standalone or invoked by the scheduler.
"""

import os
import sys
import datetime
from bson.objectid import ObjectId
from dotenv import load_dotenv
from pymongo import MongoClient

# Ensure repository root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

load_dotenv()


def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        raise Exception(f"Expected environment variable '{name}' not set.")


def run_prune():
    client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
    db = client['echowithin_db']

    communities_conf = db['communities']
    users_conf = db['users']
    community_resources_conf = db['community_resources']
    community_notes_conf = db['community_notes']
    community_reactions_conf = db['community_reactions']
    community_reports_conf = db['community_reports']
    community_challenges_conf = db['community_challenges']
    community_polls_conf = db['community_polls']
    community_poll_votes_conf = db['community_poll_votes']
    community_checkins_conf = db['community_checkins']
    community_premium_vouchers_conf = db['community_premium_vouchers']
    community_memberships_conf = db['community_memberships']
    community_tournaments_conf = db['community_tournaments']

    print(f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Scanning for orphaned or 0-member communities...")

    all_comms = list(communities_conf.find({}))
    pruned_count = 0
    reassigned_count = 0

    for comm in all_comms:
        comm_id = comm['_id']
        comm_name = comm.get('name', 'Unknown')
        raw_members = comm.get('members') or []

        # Find which members actually exist
        valid_members = [
            mid for mid in raw_members
            if users_conf.find_one({'_id': mid}, {'_id': 1})
        ] if raw_members else []

        if not valid_members:
            print(f"Purging orphaned community '{comm_name}' ({comm_id}): 0 valid members")
            # 1. Resources
            community_resources_conf.delete_many({'community_id': comm_id})
            # 2. Notes & Reactions
            notes = list(community_notes_conf.find({'community_id': comm_id}, {'_id': 1}))
            note_ids = [n['_id'] for n in notes]
            if note_ids:
                community_reactions_conf.delete_many({'note_id': {'$in': note_ids}})
            community_notes_conf.delete_many({'community_id': comm_id})
            # 3. Sub-collections
            community_challenges_conf.delete_many({'community_id': comm_id})
            polls = list(community_polls_conf.find({'community_id': comm_id}, {'_id': 1}))
            poll_ids = [p['_id'] for p in polls]
            if poll_ids:
                community_poll_votes_conf.delete_many({'poll_id': {'$in': poll_ids}})
            community_polls_conf.delete_many({'community_id': comm_id})
            community_checkins_conf.delete_many({'community_id': comm_id})
            community_reports_conf.delete_many({'community_id': comm_id})
            community_tournaments_conf.delete_many({'community_id': comm_id})
            community_premium_vouchers_conf.delete_many({'community_id': comm_id})
            community_memberships_conf.delete_many({'community_id': comm_id})
            # 4. Community record
            communities_conf.delete_one({'_id': comm_id})
            pruned_count += 1
            continue

        updates = {}
        if len(valid_members) != len(raw_members):
            updates['members'] = valid_members

        admin_id = comm.get('admin_id')
        admin_valid = admin_id and users_conf.find_one({'_id': admin_id}, {'_id': 1})
        if not admin_valid:
            raw_mods = comm.get('moderators') or []
            valid_mods = [mod for mod in raw_mods if mod in valid_members]
            new_admin = valid_mods[0] if valid_mods else valid_members[0]
            updates['admin_id'] = new_admin
            updates['moderators'] = valid_mods
            print(f"Reassigned admin of '{comm_name}' ({comm_id}) to member {new_admin}")
            reassigned_count += 1

        if updates:
            communities_conf.update_one({'_id': comm_id}, {'$set': updates})

    print(f"Completed: {pruned_count} communities purged, {reassigned_count} admins reassigned.")


if __name__ == '__main__':
    run_prune()
