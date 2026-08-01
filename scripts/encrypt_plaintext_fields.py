"""
Migration script: Encrypt all legacy plaintext private user data in-place.
Idempotent and safe to run multiple times.
"""

import sys
import os
import logging
from bson.objectid import ObjectId

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def run_migration():
    from main import (
        app, users_conf, personal_posts_conf, bond_album_photos_conf,
        bond_recommendations_conf, bond_bucketlist_conf, bond_moods_conf,
        bond_pulses_conf, encrypt_note, encrypt_bond_data
    )

    with app.app_context():
        logger.info("Starting data encryption migration...")

        # 1. Note tags & references
        logger.info("--- 1. Migrating note references & tags ---")
        note_count = 0
        notes = personal_posts_conf.find({
            'title_encrypted': {'$ne': True},
            '$or': [
                {'reference': {'$exists': True, '$ne': ''}},
                {'tags': {'$exists': True, '$ne': []}}
            ]
        })
        for note in notes:
            uid_str = str(note.get('content_owner_id') or note.get('user_id'))
            ref = note.get('reference', '')
            tags = note.get('tags', [])

            enc_ref = ref
            if ref and isinstance(ref, str) and not ref.startswith('gAAAAA'):
                enc_ref = encrypt_note(ref, user_id=uid_str)

            enc_tags = []
            if tags and isinstance(tags, list):
                for t in tags:
                    if t and isinstance(t, str) and not t.startswith('gAAAAA'):
                        enc_tags.append(encrypt_note(t, user_id=uid_str))
                    else:
                        enc_tags.append(t)

            personal_posts_conf.update_one(
                {'_id': note['_id']},
                {'$set': {
                    'reference': enc_ref,
                    'tags': enc_tags,
                    'title_encrypted': True
                }}
            )
            note_count += 1
        logger.info(f"Migrated {note_count} note metadata records.")

        # 2. Album photo titles & descriptions
        logger.info("--- 2. Migrating bond album photo titles & descriptions ---")
        photo_count = 0
        photos = bond_album_photos_conf.find({
            'encrypted': {'$ne': True},
            '$or': [
                {'title': {'$exists': True, '$ne': ''}},
                {'description': {'$exists': True, '$ne': ''}}
            ]
        })
        for photo in photos:
            bond_id = str(photo['bond_id'])
            title = photo.get('title', '')
            desc = photo.get('description', '')

            enc_title = title
            if title and isinstance(title, str) and not title.startswith('gAAAAA'):
                enc_title = encrypt_bond_data(title, bond_id)

            enc_desc = desc
            if desc and isinstance(desc, str) and not desc.startswith('gAAAAA'):
                enc_desc = encrypt_bond_data(desc, bond_id)

            bond_album_photos_conf.update_one(
                {'_id': photo['_id']},
                {'$set': {
                    'title': enc_title,
                    'description': enc_desc,
                    'encrypted': True
                }}
            )
            photo_count += 1
        logger.info(f"Migrated {photo_count} album photo records.")

        # 3. Recommendation titles, notes & links
        logger.info("--- 3. Migrating bond recommendations ---")
        rec_count = 0
        recs = bond_recommendations_conf.find({
            'encrypted': {'$ne': True},
            '$or': [
                {'title': {'$exists': True, '$ne': ''}},
                {'note': {'$exists': True, '$ne': ''}},
                {'link': {'$exists': True, '$ne': ''}}
            ]
        })
        for rec in recs:
            bond_id = str(rec['bond_id'])
            title = rec.get('title', '')
            note_text = rec.get('note', '')
            link = rec.get('link', '')

            enc_title = title
            if title and isinstance(title, str) and not title.startswith('gAAAAA'):
                enc_title = encrypt_bond_data(title, bond_id)

            enc_note = note_text
            if note_text and isinstance(note_text, str) and not note_text.startswith('gAAAAA'):
                enc_note = encrypt_bond_data(note_text, bond_id)

            enc_link = link
            if link and isinstance(link, str) and not link.startswith('gAAAAA'):
                enc_link = encrypt_bond_data(link, bond_id)

            bond_recommendations_conf.update_one(
                {'_id': rec['_id']},
                {'$set': {
                    'title': enc_title,
                    'note': enc_note,
                    'link': enc_link,
                    'encrypted': True
                }}
            )
            rec_count += 1
        logger.info(f"Migrated {rec_count} recommendation records.")

        # 4. Bucketlist titles & descriptions
        logger.info("--- 4. Migrating bond bucketlist items ---")
        bl_count = 0
        items = bond_bucketlist_conf.find({
            'encrypted': {'$ne': True},
            '$or': [
                {'title': {'$exists': True, '$ne': ''}},
                {'description': {'$exists': True, '$ne': ''}}
            ]
        })
        for item in items:
            bond_id = str(item['bond_id'])
            title = item.get('title', '')
            desc = item.get('description', '')

            enc_title = title
            if title and isinstance(title, str) and not title.startswith('gAAAAA'):
                enc_title = encrypt_bond_data(title, bond_id)

            enc_desc = desc
            if desc and isinstance(desc, str) and not desc.startswith('gAAAAA'):
                enc_desc = encrypt_bond_data(desc, bond_id)

            bond_bucketlist_conf.update_one(
                {'_id': item['_id']},
                {'$set': {
                    'title': enc_title,
                    'description': enc_desc,
                    'encrypted': True
                }}
            )
            bl_count += 1
        logger.info(f"Migrated {bl_count} bucketlist records.")

        # 5. Moods
        logger.info("--- 5. Migrating bond mood logs ---")
        mood_count = 0
        moods = bond_moods_conf.find({
            'encrypted': {'$ne': True},
            'mood': {'$exists': True, '$ne': ''}
        })
        for mood_doc in moods:
            bond_id = str(mood_doc['bond_id'])
            mood = mood_doc.get('mood', '')

            enc_mood = mood
            if mood and isinstance(mood, str) and not mood.startswith('gAAAAA'):
                enc_mood = encrypt_bond_data(mood, bond_id)

            bond_moods_conf.update_one(
                {'_id': mood_doc['_id']},
                {'$set': {
                    'mood': enc_mood,
                    'encrypted': True
                }}
            )
            mood_count += 1
        logger.info(f"Migrated {mood_count} mood records.")

        # 6. Pulse messages
        logger.info("--- 6. Migrating bond pulse messages ---")
        pulse_count = 0
        pulses = bond_pulses_conf.find({
            'encrypted': {'$ne': True},
            'message': {'$exists': True, '$ne': ''}
        })
        for pulse in pulses:
            bond_id = str(pulse['bond_id'])
            msg = pulse.get('message', '')

            enc_msg = msg
            if msg and isinstance(msg, str) and not msg.startswith('gAAAAA'):
                enc_msg = encrypt_bond_data(msg, bond_id)

            bond_pulses_conf.update_one(
                {'_id': pulse['_id']},
                {'$set': {
                    'message': enc_msg,
                    'encrypted': True
                }}
            )
            pulse_count += 1
        logger.info(f"Migrated {pulse_count} pulse records.")

        # 7. User bios
        logger.info("--- 7. Migrating user bios ---")
        bio_count = 0
        user_list = users_conf.find({
            'bio_encrypted': {'$ne': True},
            'bio': {'$exists': True, '$ne': ''}
        })
        for user_doc in user_list:
            uid_str = str(user_doc['_id'])
            bio = user_doc.get('bio', '')

            enc_bio = bio
            if bio and isinstance(bio, str) and not bio.startswith('gAAAAA'):
                enc_bio = encrypt_note(bio, user_id=uid_str)

            users_conf.update_one(
                {'_id': user_doc['_id']},
                {'$set': {
                    'bio': enc_bio,
                    'bio_encrypted': True
                }}
            )
            bio_count += 1
        logger.info(f"Migrated {bio_count} user bios.")

        logger.info("Migration complete! All legacy plaintext fields are now encrypted at rest.")


if __name__ == '__main__':
    run_migration()
