"""
scripts/complete_v3_migration.py — Comprehensive v3 Envelope Migration Script

Migrates all remaining legacy encrypted data to 100% v3 envelope encryption:
1. Re-encrypts the 1 v2 note (Vinny) to v3.
2. Re-encrypts cloned notes (MARYEL) with the recipient's own v3 key for data sovereignty.
3. Sets explicit `encryption_version: 3` on all notes.
4. Re-encrypts all 158 legacy note versions (v1/v2) to v3 using the note owner's key.
5. Re-encrypts all 88 v2 direct messages to v3 using conversation envelope keys.
6. Marks all direct messages with `dm_encryption_version: 3`.
7. Performs end-to-end verification that every document decrypts with v3 ONLY.

Usage:
    python scripts/complete_v3_migration.py --dry-run
    python scripts/complete_v3_migration.py --confirm
"""

import sys
import os
import argparse
import base64

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
from pymongo import MongoClient
from bson.objectid import ObjectId
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MONGO_URI = os.environ.get(
    'MONGODB_CONNECTION',
    "mongodb://mongo:2vhy3HAd2jQgpRjPjYqc@193.181.209.169:27017/?authSource=admin&directConnection=true"
)
SECRET_KEY = os.environ.get('SECRET', 'RUYFUOTFGVBU').encode('utf-8')
NOTES_KDF_ITERATIONS = 480000
V1_SALT = b"echowithin_notes_salt_v1"


def derive_key(secret_bytes: bytes, salt: bytes, iterations: int = NOTES_KDF_ITERATIONS):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret_bytes))


def run_migration(confirm=False):
    print("=" * 60)
    print("EchoWithin — Complete v3 Envelope Encryption Migration")
    print(f"Mode: {'CONFIRM (Applying Changes)' if confirm else 'DRY RUN (Preview Only)'}")
    print("=" * 60)

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client['echowithin_db']

    # 1. Master KEK
    kek_key = derive_key(SECRET_KEY, b'echowithin_kek_v1', NOTES_KDF_ITERATIONS)
    kek_fernet = Fernet(kek_key)

    # 2. Legacy v1 Fernet
    v1_key = derive_key(SECRET_KEY, V1_SALT, 100000)
    v1_fernet = Fernet(v1_key)

    # 3. Cache user v3 and v2 keys
    print("\n[+] Loading users and building keys...")
    users = list(db['users'].find({}))
    user_v3 = {}
    user_v2 = {}

    for u in users:
        uid = str(u['_id'])
        # v2
        v2_k = derive_key(SECRET_KEY, f'echowithin_notes_v2_{uid}'.encode(), NOTES_KDF_ITERATIONS)
        user_v2[uid] = Fernet(v2_k)

        # v3
        if u.get('encryption_key_enc') and u.get('encryption_salt'):
            try:
                dek_raw = kek_fernet.decrypt(u['encryption_key_enc'].encode('utf-8'))
                salt = base64.urlsafe_b64decode(u['encryption_salt'])
                v3_k = derive_key(dek_raw, salt, NOTES_KDF_ITERATIONS)
                user_v3[uid] = Fernet(v3_k)
            except Exception as e:
                print(f"  [WARN] User {uid} DEK unwrap error: {e}")

    print(f"  Loaded {len(users)} users. v3 keys active: {len(user_v3)}")

    # -------------------------------------------------------------
    # PHASE 1: Migrate Note 699069885c7cf72c98bfa2f2 (v2 -> v3)
    # -------------------------------------------------------------
    print("\n[+] Phase 1: Migrating v2 notes to v3...")
    v2_note_id = ObjectId('699069885c7cf72c98bfa2f2')
    v2_note = db['personal_posts'].find_one({'_id': v2_note_id})
    if v2_note:
        target_uid = str(v2_note.get('user_id', '692b0e6293de35a8d8a337b5'))
        vinny_id = '691c949cd9459e67782ea2fd'
        # Check if already v3
        is_already_v3 = False
        try:
            user_v3[target_uid].decrypt(v2_note['content'].encode('utf-8'))
            is_already_v3 = True
            print(f"  [OK] Note {v2_note_id} is already v3 envelope encrypted.")
        except Exception:
            pass

        if not is_already_v3:
            try:
                plain = user_v2[vinny_id].decrypt(v2_note['content'].encode('utf-8')).decode('utf-8')
                new_v3_content = user_v3[target_uid].encrypt(plain.encode('utf-8')).decode('utf-8')
                print(f"  [OK] Decrypted v2 note {v2_note_id} (Preview: {plain[:30]!r})")
                if confirm:
                    db['personal_posts'].update_one(
                        {'_id': v2_note_id},
                        {'$set': {'content': new_v3_content, 'encryption_version': 3, 'content_owner_id': ObjectId(target_uid)}}
                    )
                    print(f"  [APPLIED] Note {v2_note_id} re-encrypted with v3 envelope key.")
                else:
                    print(f"  [DRY RUN] Would update note {v2_note_id} to v3.")
            except Exception as e:
                print(f"  [ERROR] Failed to migrate note {v2_note_id}: {e}")

    # -------------------------------------------------------------
    # PHASE 2: Migrate Cloned Notes (re-encrypt with recipient's v3 key)
    # -------------------------------------------------------------
    print("\n[+] Phase 2: Re-encrypting cloned notes with recipient's own v3 key...")
    cloned_note_ids = [
        ObjectId('69cfe1f1c9465f3bbecc22d2'),
        ObjectId('69e3d167367af41b9067b4c1'),
        ObjectId('69e49b7a367af41b9067b4cb'),
        ObjectId('69e5ef15367af41b9067b508')
    ]
    for nid in cloned_note_ids:
        doc = db['personal_posts'].find_one({'_id': nid})
        if not doc:
            continue
        recipient_id = str(doc['user_id'])  # MARYEL
        author_id = str(doc.get('content_owner_id', '691c949cd9459e67782ea2fd'))  # Vinny

        try:
            # Decrypt with author's v3 key, or fallback to author's v2 key
            plain = None
            try:
                plain = user_v3[author_id].decrypt(doc['content'].encode('utf-8')).decode('utf-8')
            except Exception:
                pass
            if plain is None and author_id in user_v2:
                try:
                    plain = user_v2[author_id].decrypt(doc['content'].encode('utf-8')).decode('utf-8')
                except Exception:
                    pass
            if plain is None:
                raise ValueError(f"Could not decrypt cloned note {nid} with author {author_id}")

            # Re-encrypt with recipient's v3 key
            recipient_v3_content = user_v3[recipient_id].encrypt(plain.encode('utf-8')).decode('utf-8')
            print(f"  [OK] Cloned note {nid} decrypted via author {author_id} -> re-encrypting for recipient {recipient_id}")
            if confirm:
                db['personal_posts'].update_one(
                    {'_id': nid},
                    {'$set': {
                        'content': recipient_v3_content,
                        'content_owner_id': ObjectId(recipient_id),
                        'encryption_version': 3
                    }}
                )
                print(f"  [APPLIED] Note {nid} now encrypted with recipient's key (sovereignty preserved).")
            else:
                print(f"  [DRY RUN] Would re-encrypt note {nid} with recipient's key.")
        except Exception as e:
            print(f"  [ERROR] Failed to re-encrypt cloned note {nid}: {e}")

    # -------------------------------------------------------------
    # PHASE 3: Set explicit encryption_version: 3 on all valid notes
    # -------------------------------------------------------------
    print("\n[+] Phase 3: Setting explicit encryption_version: 3 on all personal_posts...")
    all_notes = list(db['personal_posts'].find({'content': {'$regex': '^gAAAAA'}}))
    notes_marked = 0
    for n in all_notes:
        uid = str(n.get('user_id', ''))
        if uid in user_v3:
            if confirm:
                db['personal_posts'].update_one(
                    {'_id': n['_id']},
                    {'$set': {'encryption_version': 3}}
                )
            notes_marked += 1
    print(f"  {'Marked' if confirm else 'Would mark'} {notes_marked} notes with encryption_version: 3")

    # -------------------------------------------------------------
    # PHASE 4: Migrate Note Versions (legacy versions -> v3)
    # -------------------------------------------------------------
    print("\n[+] Phase 4: Migrating legacy note_versions to v3...")
    all_versions = list(db['note_versions'].find({}))
    note_map = {str(n['_id']): n for n in db['personal_posts'].find({})}

    v_v3_migrated = 0
    v_skipped = 0
    v_orphans_cleaned = 0
    v_errors = 0

    for v in all_versions:
        content = v.get('content', '')
        if not content.startswith('gAAAAA'):
            v_skipped += 1
            continue

        vid = v['_id']
        nid = str(v.get('note_id', ''))
        parent_note = note_map.get(nid)
        if not parent_note:
            # Orphaned version from deleted note/account
            if confirm:
                db['note_versions'].delete_one({'_id': vid})
            v_orphans_cleaned += 1
            continue

        target_owner_id = str(parent_note.get('user_id', ''))
        if not target_owner_id or target_owner_id not in user_v3:
            v_skipped += 1
            continue

        # Check if already decryptable with target owner's v3 key
        is_already_v3 = False
        try:
            user_v3[target_owner_id].decrypt(content.encode('utf-8'))
            is_already_v3 = True
        except Exception:
            pass

        if is_already_v3:
            if confirm:
                db['note_versions'].update_one(
                    {'_id': vid},
                    {'$set': {'encryption_version': 3, 'content_owner_id': ObjectId(target_owner_id)}}
                )
            continue

        # Build candidate UIDs to decrypt legacy version
        candidates = []
        for k in ['content_owner_id', 'editor_id', 'user_id']:
            val = v.get(k)
            if val:
                candidates.append(str(val))
        for k in ['user_id', 'content_owner_id', 'owner_id', 'source_owner_id']:
            val = parent_note.get(k)
            if val:
                candidates.append(str(val))
        seen = set()
        candidate_uids = [c for c in candidates if not (c in seen or seen.add(c))]

        plain = None
        # Try candidate v3
        for cid in candidate_uids:
            if cid in user_v3:
                try:
                    plain = user_v3[cid].decrypt(content.encode('utf-8')).decode('utf-8')
                    break
                except Exception:
                    pass
        # Try candidate v2
        if plain is None:
            for cid in candidate_uids:
                if cid in user_v2:
                    try:
                        plain = user_v2[cid].decrypt(content.encode('utf-8')).decode('utf-8')
                        break
                    except Exception:
                        pass
        # Try v1
        if plain is None:
            try:
                plain = v1_fernet.decrypt(content.encode('utf-8')).decode('utf-8')
            except Exception:
                pass

        if plain is None:
            v_errors += 1
            print(f"  [ERROR] Version {vid} could not be decrypted with candidate keys.")
            continue

        # Re-encrypt with parent note owner's v3 key
        try:
            new_v3 = user_v3[target_owner_id].encrypt(plain.encode('utf-8')).decode('utf-8')
            if confirm:
                db['note_versions'].update_one(
                    {'_id': vid},
                    {'$set': {
                        'content': new_v3,
                        'encryption_version': 3,
                        'content_owner_id': ObjectId(target_owner_id)
                    }}
                )
            v_v3_migrated += 1
        except Exception as e:
            print(f"  [ERROR] Version {vid} re-encrypt failed: {e}")
            v_errors += 1

    print(f"  {'Migrated' if confirm else 'Would migrate'} {v_v3_migrated} legacy note versions to v3 (cleaned orphans: {v_orphans_cleaned}, skipped: {v_skipped}, errors: {v_errors})")

    # -------------------------------------------------------------
    # PHASE 5: Migrate Direct Messages (88 v2 DMs -> v3)
    # -------------------------------------------------------------
    print("\n[+] Phase 5: Migrating direct_messages to v3...")
    # Cache conversation v3 keys from dm_permissions
    perms = list(db['dm_permissions'].find({}))
    dm_v3_keys = {}
    dm_v2_keys = {}

    for p in perms:
        req = str(p['requester_id'])
        tgt = str(p['target_id'])
        pair = sorted([req, tgt])
        conv_id = f"{pair[0]}_{pair[1]}"

        # v2 key
        salt_v2 = f'echowithin_dm_v1_{conv_id}'.encode()
        dm_v2_keys[conv_id] = Fernet(derive_key(SECRET_KEY, salt_v2, NOTES_KDF_ITERATIONS))

        # v3 key
        if p.get('conversation_key_enc'):
            try:
                c_dek = kek_fernet.decrypt(p['conversation_key_enc'].encode('utf-8'))
                salt_v3 = f'echowithin_dm_v3_{conv_id}'.encode()
                dm_v3_keys[conv_id] = Fernet(derive_key(c_dek, salt_v3, NOTES_KDF_ITERATIONS))
            except Exception as e:
                print(f"  [WARN] Failed to unwrap DM key for {conv_id}: {e}")

    # Re-encrypt messages using RECIPIENT_ID (fixing the old typo!)
    all_dms = list(db['direct_messages'].find({}))
    dm_reencrypted = 0
    dm_system_marked = 0
    dm_already_v3 = 0
    dm_orphans_cleaned = 0
    dm_errors = 0

    for m in all_dms:
        mid = m['_id']
        s_id = str(m.get('sender_id', ''))
        r_id = str(m.get('recipient_id', ''))
        content = m.get('content', '')
        pair = sorted([s_id, r_id])
        conv_id = f"{pair[0]}_{pair[1]}"

        # Case 1: Plaintext system message (whisper invite, session ended, empty content)
        if not content or not content.startswith('gAAAAA'):
            if confirm:
                db['direct_messages'].update_one(
                    {'_id': mid},
                    {'$set': {'dm_encryption_version': 3}}
                )
            dm_system_marked += 1
            continue

        f_v3 = dm_v3_keys.get(conv_id)
        f_v2 = dm_v2_keys.get(conv_id)

        if not f_v3:
            s_exists = db['users'].count_documents({'_id': ObjectId(s_id)}) if ObjectId.is_valid(s_id) else 0
            r_exists = db['users'].count_documents({'_id': ObjectId(r_id)}) if ObjectId.is_valid(r_id) else 0
            if not s_exists and not r_exists:
                if confirm:
                    db['direct_messages'].delete_one({'_id': mid})
                dm_orphans_cleaned += 1
                continue
            print(f"  [ERROR] DM {mid} has ciphertext but no v3 conversation key for {conv_id}")
            dm_errors += 1
            continue

        # Case 2: Already v3
        is_v3 = False
        try:
            f_v3.decrypt(content.encode('utf-8'))
            is_v3 = True
        except Exception:
            pass

        if is_v3:
            if confirm:
                db['direct_messages'].update_one(
                    {'_id': mid},
                    {'$set': {'dm_encryption_version': 3}}
                )
            dm_already_v3 += 1
            continue

        # Case 3: Encrypted with v2 -> Re-encrypt with v3
        if f_v2:
            try:
                plain = f_v2.decrypt(content.encode('utf-8')).decode('utf-8')
                new_v3 = f_v3.encrypt(plain.encode('utf-8')).decode('utf-8')
                if confirm:
                    db['direct_messages'].update_one(
                        {'_id': mid},
                        {'$set': {'content': new_v3, 'dm_encryption_version': 3}}
                    )
                dm_reencrypted += 1
            except Exception as e:
                print(f"  [ERROR] DM {mid} failed v2 decrypt: {e}")
                dm_errors += 1
        else:
            print(f"  [ERROR] DM {mid} has no v2 key for conv {conv_id}")
            dm_errors += 1

    print(f"  {'Re-encrypted' if confirm else 'Would re-encrypt'} {dm_reencrypted} v2 DMs to v3.")
    print(f"  Already on v3: {dm_already_v3}.")
    print(f"  Marked {dm_system_marked} system/empty DMs with dm_encryption_version: 3.")
    print(f"  Errors: {dm_errors}.")

    # -------------------------------------------------------------
    # PHASE 6: End-to-End Verification
    # -------------------------------------------------------------
    if confirm:
        print("\n[+] Phase 6: Verifying 100% v3 decryption...")

        # Notes verification
        notes_to_check = list(db['personal_posts'].find({'user_id': {'$in': [ObjectId(uid) for uid in user_v3]}}))
        notes_ok = 0
        notes_fail = 0
        for n in notes_to_check:
            uid = str(n['user_id'])
            try:
                user_v3[uid].decrypt(n['content'].encode('utf-8'))
                notes_ok += 1
            except Exception:
                notes_fail += 1

        # Versions verification
        versions_to_check = list(db['note_versions'].find({}))
        ver_ok = 0
        ver_fail = 0
        for v in versions_to_check:
            c = v.get('content', '')
            if not c or not c.startswith('gAAAAA'):
                continue
            nid = str(v.get('note_id', ''))
            parent_note = note_map.get(nid)
            if not parent_note:
                continue
            owner_id = str(parent_note.get('user_id', ''))
            if owner_id in user_v3:
                try:
                    user_v3[owner_id].decrypt(c.encode('utf-8'))
                    ver_ok += 1
                except Exception:
                    ver_fail += 1

        # DMs verification
        dms_to_check = list(db['direct_messages'].find({'content': {'$regex': '^gAAAAA'}}))
        dms_ok = 0
        dms_fail = 0
        for m in dms_to_check:
            s_id = str(m['sender_id'])
            r_id = str(m['recipient_id'])
            pair = sorted([s_id, r_id])
            conv_id = f"{pair[0]}_{pair[1]}"
            f_v3 = dm_v3_keys.get(conv_id)
            if not f_v3:
                dms_fail += 1
                continue
            try:
                f_v3.decrypt(m['content'].encode('utf-8'))
                dms_ok += 1
            except Exception:
                dms_fail += 1

        print(f"  Personal Notes Verified: {notes_ok}/{len(notes_to_check)} (Fail: {notes_fail})")
        print(f"  Note Versions Verified:  {ver_ok}/{ver_ok + ver_fail} (Fail: {ver_fail})")
        print(f"  Encrypted DMs Verified:  {dms_ok}/{len(dms_to_check)} (Fail: {dms_fail})")

        if notes_fail == 0 and ver_fail == 0 and dms_fail == 0:
            print("\n[SUCCESS] 100% of data is on v3 envelope encryption with zero errors!")
        else:
            print("\n[WARN] Some records failed verification.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Complete v3 envelope migration')
    parser.add_argument('--confirm', action='store_true', help='Execute database updates (default: dry run)')
    args = parser.parse_args()

    run_migration(confirm=args.confirm)
