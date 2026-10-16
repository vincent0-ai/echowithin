"""
Read-only audit of legacy encryption formats across collections.

Counts how many stored records are still in a legacy format so the matching
compatibility fallbacks can be retired safely. Performs NO writes and prints no
key material.

Usage (from the project root, with the app environment loaded):
    python scripts/audit_legacy_encryption.py
    python scripts/audit_legacy_encryption.py --limit 20000 --json audit_out.json
"""

import os
import sys
import json
import argparse

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(override=True)

import base64
from cryptography.fernet import Fernet, InvalidToken
from pymongo import MongoClient

from config import _NOTES_KDF_ITERATIONS, _NOTES_V1_SALT
from security import _derive_fernet_key
import key_management

_FERNET_HEADER = 'gAAAAA'


def _get_env(name):
    val = os.environ.get(name, '').strip()
    if not val:
        print(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val


class _Keys:
    """Standalone replication of the runtime key derivations (no Flask app)."""

    def __init__(self):
        self.secret = _get_env('SECRET').encode('utf-8')
        self._v1 = None
        self._user_v2 = {}
        self._dm_v2 = {}
        self._comm = {}

    def v1_notes(self):
        if self._v1 is None:
            self._v1 = Fernet(_derive_fernet_key(self.secret, _NOTES_V1_SALT, iterations=100000))
        return self._v1

    def user_v2(self, uid):
        f = self._user_v2.get(uid)
        if f is None:
            key = _derive_fernet_key(self.secret, f'echowithin_notes_v2_{uid}'.encode(), _NOTES_KDF_ITERATIONS)
            f = Fernet(key)
            self._user_v2[uid] = f
        return f

    def dm_v2(self, conv_id):
        f = self._dm_v2.get(conv_id)
        if f is None:
            key = _derive_fernet_key(self.secret, f'echowithin_dm_v1_{conv_id}'.encode(), _NOTES_KDF_ITERATIONS)
            f = Fernet(key)
            self._dm_v2[conv_id] = f
        return f

    def community(self, cid, iters):
        ck = (str(cid), iters)
        f = self._comm.get(ck)
        if f is None:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                             salt=str(cid).encode('utf-8'), iterations=iters)
            f = Fernet(base64.urlsafe_b64encode(kdf.derive(self.secret)))
            self._comm[ck] = f
        return f


class _Envelope:
    """Unwraps data keys via Vault Transit or the primary/legacy KEK."""

    def __init__(self):
        secret = _get_env('SECRET').encode('utf-8')
        material = key_management.get_master_key_material(secret)
        self.kek = Fernet(_derive_fernet_key(material, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS))
        self.legacy_kek = None
        if material != secret:
            self.legacy_kek = Fernet(_derive_fernet_key(secret, b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS))

    def unwrap(self, token):
        if isinstance(token, str) and token.startswith('vault:'):
            return key_management.transit_decrypt(token)
        if isinstance(token, str):
            token = token.encode('utf-8')
        try:
            return self.kek.decrypt(token)
        except InvalidToken:
            if self.legacy_kek is None:
                raise
            return self.legacy_kek.decrypt(token)


def _is_cipher(value):
    return isinstance(value, str) and value.startswith(_FERNET_HEADER)


def _classify_notes(db, keys, env, limit):
    """Classify note ciphertext as v3 / v2 / v1 / undecryptable."""
    result = {'plaintext': 0, 'v3': 0, 'v2': 0, 'v1': 0, 'undecryptable': 0, 'scanned': 0}
    user_salt = {}
    for note in db['personal_posts'].find({}, {'content': 1, 'user_id': 1, 'content_owner_id': 1}).limit(limit):
        result['scanned'] += 1
        content = note.get('content')
        if not _is_cipher(content):
            result['plaintext'] += 1
            continue
        uid = note.get('content_owner_id') or note.get('user_id')
        uid = str(uid) if uid is not None else None
        done = False
        if uid:
            try:
                f_v3 = _user_v3(db, env, uid, user_salt)
                if f_v3:
                    f_v3.decrypt(content.encode('utf-8'))
                    result['v3'] += 1
                    done = True
            except Exception:
                pass
            if not done:
                try:
                    keys.user_v2(uid).decrypt(content.encode('utf-8'))
                    result['v2'] += 1
                    done = True
                except Exception:
                    pass
        if not done:
            try:
                keys.v1_notes().decrypt(content.encode('utf-8'))
                result['v1'] += 1
            except Exception:
                result['undecryptable'] += 1
    return result


def _user_v3(db, env, uid, cache):
    if uid in cache:
        return cache[uid]
    f = None
    try:
        from bson.objectid import ObjectId
        doc = db['users'].find_one({'_id': ObjectId(uid)}, {'encryption_key_enc': 1, 'encryption_salt': 1})
        if doc and doc.get('encryption_key_enc') and doc.get('encryption_salt'):
            dek = env.unwrap(doc['encryption_key_enc'])
            salt = base64.urlsafe_b64decode(doc['encryption_salt'])
            f = Fernet(_derive_fernet_key(dek, salt, _NOTES_KDF_ITERATIONS))
    except Exception:
        f = None
    cache[uid] = f
    return f


def _classify_dms(db, keys, env, limit):
    result = {'plaintext': 0, 'v3': 0, 'v2': 0, 'undecryptable': 0, 'scanned': 0}
    conv_dek = {}
    for msg in db['direct_messages'].find({}, {'content': 1, 'sender_id': 1, 'recipient_id': 1}).limit(limit):
        result['scanned'] += 1
        content = msg.get('content')
        if not _is_cipher(content):
            result['plaintext'] += 1
            continue
        s, r = msg.get('sender_id'), msg.get('recipient_id')
        if s is None or r is None:
            result['undecryptable'] += 1
            continue
        conv_id = f"{min(str(s), str(r))}_{max(str(s), str(r))}"
        done = False
        try:
            dek = _conv_dek(db, env, conv_id, conv_dek)
            if dek is not None:
                f = Fernet(_derive_fernet_key(dek, f'echowithin_dm_v3_{conv_id}'.encode(), _NOTES_KDF_ITERATIONS))
                f.decrypt(content.encode('utf-8'))
                result['v3'] += 1
                done = True
        except Exception:
            pass
        if not done:
            try:
                keys.dm_v2(conv_id).decrypt(content.encode('utf-8'))
                result['v2'] += 1
            except Exception:
                result['undecryptable'] += 1
    return result


def _conv_dek(db, env, conv_id, cache):
    if conv_id in cache:
        return cache[conv_id]
    a, b = conv_id.split('_', 1)
    from bson.objectid import ObjectId
    dek = None
    try:
        doc = db['dm_permissions'].find_one(
            {'$or': [
                {'requester_id': ObjectId(a), 'target_id': ObjectId(b)},
                {'requester_id': ObjectId(b), 'target_id': ObjectId(a)},
            ]},
            {'conversation_key_enc': 1},
        )
        if doc and doc.get('conversation_key_enc'):
            dek = env.unwrap(doc['conversation_key_enc'])
    except Exception:
        dek = None
    cache[conv_id] = dek
    return dek


def _classify_community(db, keys, limit):
    result = {'plaintext': 0, 'v2': 0, 'v1': 0, 'undecryptable': 0, 'scanned': 0}
    for note in db['community_notes'].find({}, {'content': 1, 'community_id': 1}).limit(limit):
        result['scanned'] += 1
        content = note.get('content')
        cid = note.get('community_id')
        if not _is_cipher(content) or cid is None:
            result['plaintext'] += 1
            continue
        try:
            keys.community(cid, _NOTES_KDF_ITERATIONS).decrypt(content.encode('utf-8'))
            result['v2'] += 1
            continue
        except Exception:
            pass
        try:
            keys.community(cid, 100000).decrypt(content.encode('utf-8'))
            result['v1'] += 1
        except Exception:
            result['undecryptable'] += 1
    return result


def _has_ciphertext(value, _depth=0):
    """True if a document (recursively) holds any Fernet-looking string.

    Bonds/forms/game lobbies do not use a single ``content`` field; each sensitive
    field (title, description, journal, goals, mood, answers, ...) is encrypted
    individually, so a shallow ``content`` probe misreports them as plaintext.
    """
    if _depth > 6:
        return False
    if isinstance(value, str):
        return value.startswith(_FERNET_HEADER)
    if isinstance(value, dict):
        return any(_has_ciphertext(v, _depth + 1) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_ciphertext(v, _depth + 1) for v in value)
    return False


def _shape_counts(db, limit):
    """Encrypted-vs-plaintext counts + plaintext-token counts (no decryption).

    For bonds/forms/game_sessions a record is counted as ``with_ciphertext`` when
    any (possibly nested) field holds a Fernet token; ``without_ciphertext`` covers
    records that hold no encrypted field at all (e.g. empty/newly created rows).
    """
    out = {}
    for coll in ('bonds', 'forms', 'game_sessions'):
        enc = plain = 0
        for doc in db[coll].find({}).limit(limit):
            if _has_ciphertext(doc):
                enc += 1
            else:
                plain += 1
        out[coll] = {'with_ciphertext': enc, 'without_ciphertext': plain}
    tokens = db['app_tokens']
    out['app_tokens'] = {
        'with_plaintext_token': tokens.count_documents({'token': {'$exists': True, '$ne': None}}),
        'with_token_hash': tokens.count_documents({'token_hash': {'$exists': True, '$ne': None}}),
    }
    users = db['users']
    out['users'] = {
        'total': users.count_documents({}),
        'with_envelope_key': users.count_documents({'encryption_key_enc': {'$exists': True}}),
        'vault_wrapped': users.count_documents({'encryption_key_enc': {'$regex': '^vault:'}}),
        'version_lt_3': users.count_documents({'encryption_version': {'$lt': 3}}),
    }
    return out


def main():
    ap = argparse.ArgumentParser(description="Read-only legacy encryption audit.")
    ap.add_argument('--limit', type=int, default=10000, help="Max records scanned per collection (default 10000).")
    ap.add_argument('--all', action='store_true', help="Scan everything (ignore --limit).")
    ap.add_argument('--json', default='', help="Optional path to write the report as JSON.")
    args = ap.parse_args()
    limit = 0 if args.all else args.limit

    db = MongoClient(_get_env('MONGODB_CONNECTION'))['echowithin_db']
    keys = _Keys()
    env = _Envelope()

    report = {
        'transit_enabled': key_management.transit_enabled(),
        'key_custody': key_management.current_mode(),
        'scanned_limit': limit or 'all',
        'collections': {},
    }
    report['collections']['personal_posts'] = _classify_notes(db, keys, env, limit)
    report['collections']['direct_messages'] = _classify_dms(db, keys, env, limit)
    report['collections']['community_notes'] = _classify_community(db, keys, limit)
    report['shapes'] = _shape_counts(db, limit)

    print(f"\nKey custody: {report['key_custody']} (transit_enabled={report['transit_enabled']})")
    print(f"Scanned per collection: {report['scanned_limit']}\n")
    for name in ('personal_posts', 'direct_messages', 'community_notes'):
        c = report['collections'][name]
        parts = ' '.join(f"{k}={v}" for k, v in c.items())
        print(f"  {name}: {parts}")
    print("\n  shapes:")
    for k, v in report['shapes'].items():
        print(f"    {k}: {v}")

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\nJSON report written: {args.json}")


if __name__ == '__main__':
    main()
