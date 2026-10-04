#!/usr/bin/env python3
"""
Migrate legacy form responses and form documents to discrete versioning.

For forms edited prior to explicit versioning:
  - Updates form document to version: 2
  - Assigns submissions prior to updated_at to form_version: 1
  - Assigns submissions on/after updated_at to form_version: 2
"""

import os
import sys
import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId

load_dotenv()

MONGO_URI = os.environ.get('MONGODB_CONNECTION') or os.environ.get('MONGO_URI')
if not MONGO_URI:
    print("Error: MONGODB_CONNECTION or MONGO_URI environment variable not set.")
    sys.exit(1)

client = MongoClient(MONGO_URI)
db = client['echowithin_db']
forms_col = db['forms']
responses_col = db['form_responses']


def migrate_legacy_form_versions():
    # Find forms that have updated_at but no versions array or missing/outdated version field
    query = {
        'updated_at': {'$exists': True, '$ne': None},
        '$or': [
            {'versions': {'$exists': False}},
            {'versions': {'$size': 0}},
            {'version': {'$exists': False}},
            {'version': {'$lt': 2}}
        ]
    }
    
    forms = list(forms_col.find(query))
    print(f"Found {len(forms)} edited form(s) requiring version normalization.")

    total_responses_updated = 0
    total_forms_updated = 0

    for f in forms:
        f_id = f['_id']
        share_id = f.get('share_id', str(f_id))
        title = f.get('title', 'Untitled Form')
        updated_at = f.get('updated_at')
        if updated_at and updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)

        responses = list(responses_col.find({'form_id': f_id}))
        print(f"\nProcessing form '{title}' ({share_id}) with {len(responses)} response(s)...")

        form_v1_count = 0
        form_v2_count = 0

        for r in responses:
            r_id = r['_id']
            sub_at = r.get('submitted_at')
            if sub_at and sub_at.tzinfo is None:
                sub_at = sub_at.replace(tzinfo=datetime.timezone.utc)

            # Determine version
            target_v = 1
            if updated_at and sub_at and sub_at >= updated_at:
                target_v = 2
            elif r.get('form_version') and r['form_version'] >= 2:
                target_v = r['form_version']

            if target_v == 2:
                form_v2_count += 1
            else:
                form_v1_count += 1

            if r.get('form_version') != target_v:
                responses_col.update_one({'_id': r_id}, {'$set': {'form_version': target_v}})
                total_responses_updated += 1

        # Update form document to version: 2
        forms_col.update_one({'_id': f_id}, {'$set': {'version': 2}})
        total_forms_updated += 1
        print(f"  Form updated to version 2. Submissions classified: {form_v1_count} in v1, {form_v2_count} in v2.")

    print(f"\nMigration complete: {total_forms_updated} form(s) updated, {total_responses_updated} response document(s) normalized.")


if __name__ == '__main__':
    migrate_legacy_form_versions()
