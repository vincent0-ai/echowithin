"""
Move per-object at-rest keys for bonds, forms and game lobbies onto Vault-wrapped
per-object DEKs (the same envelope pattern already used for users and DM conversations).

For each bond / form / game lobby this script:
  1. Generates a random 32-byte DEK and stores it Vault-Transit-wrapped on the
     object's own document (`bond_key_enc` / `form_key_enc` / `game_key_enc`).
  2. Re-encrypts every encrypted field of that object from the legacy
     SECRET_KEY-derived key (``echowithin_<scope>_v1_<id>``) to the new DEK-derived
     key (``echowithin_<scope>_v2_<id>``).

Fields already decryptable by the new per-object key are left untouched, so the
script is idempotent and safe to re-run. Objects created after deploy already carry
a DEK (see blueprints), so only their legacy stragglers get re-encrypted.

Usage (from the project root or the app container):
    # Requires VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY, MONGODB_CONNECTION, SECRET
    python scripts/migrate_object_deks_to_transit.py --dry-run
    python scripts/migrate_object_deks_to_transit.py --confirm

Safety:
  - Dry-run by default; --confirm is required for any database mutation
  - Circuit breaker aborts if the failure rate exceeds 5% (min 10 failures)
  - Writes a timestamped audit log (migrate_object_deks_to_transit_<timestamp>.json)
"""

import os
import sys
import json
import time
import argparse
import datetime

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(override=True)

from cryptography.fernet import Fernet
from pymongo import MongoClient

from config import _NOTES_KDF_ITERATIONS
from security import _derive_fernet_key
import key_management

_CIRCUIT_BREAKER_THRESHOLD = 0.05
_CIRCUIT_BREAKER_MIN_FAILURES = 10


def _get_env(name):
    val = os.environ.get(name, '').strip()
    if not val:
        print(f"Missing required environment variable: {name}")
        sys.exit(1)
    return val


def _is_fernet_token(val) -> bool:
    return isinstance(val, str) and val.startswith('gAAAAA') and len(val) >= 50


def _try_decrypt(fernet, ciphertext):
    if not _is_fernet_token(ciphertext):
        return None
    try:
        return fernet.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception:
        return None


def _rotate_field(ciphertext, old_f, new_f):
    """Returns (new_ciphertext, status in {'skipped','rotated','failed'})."""
    if not _is_fernet_token(ciphertext):
        return ciphertext, 'skipped'
    if _try_decrypt(new_f, ciphertext) is not None:
        return ciphertext, 'skipped'
    plaintext = _try_decrypt(old_f, ciphertext)
    if plaintext is None:
        return ciphertext, 'failed'
    return new_f.encrypt(plaintext.encode('utf-8')).decode('utf-8'), 'rotated'


class _Stats:
    def __init__(self):
        self.rotated = 0
        self.skipped = 0
        self.failed = 0
        self.objects_keyed = 0
        self.audit = []

    def note(self, collection, doc_id, field, status):
        self.audit.append({'collection': collection, '_id': str(doc_id), 'field': field, 'status': status})

    def should_break(self):
        total = self.rotated + self.failed
        return self.failed >= _CIRCUIT_BREAKER_MIN_FAILURES and \
            self.failed / max(total, 1) > _CIRCUIT_BREAKER_THRESHOLD


def _legacy_fernet(secret, scope, oid):
    return Fernet(_derive_fernet_key(secret, f'echowithin_{scope}_v1_{oid}'.encode(), _NOTES_KDF_ITERATIONS))


def _v3_fernet(dek_raw, scope, oid):
    return Fernet(_derive_fernet_key(dek_raw, f'echowithin_{scope}_v2_{oid}'.encode(), _NOTES_KDF_ITERATIONS))


def _ensure_object_dek(coll, query, key_field, version_field, confirm, stats):
    """Return (dek_raw_or_None, created_bool). Creates+wraps a DEK if absent."""
    doc = coll.find_one(query, {key_field: 1})
    if not doc:
        return None, False
    token = doc.get(key_field)
    if token:
        if isinstance(token, str) and token.startswith('vault:'):
            try:
                return key_management.transit_decrypt(token), False
            except Exception as e:
                print(f"  Could not unwrap {key_field} for {query}: {e}")
                return None, False
        # Legacy KEK-wrapped: re-wrap under Transit.
        try:
            raw = Fernet(_derive_fernet_key(_get_env('SECRET').encode('utf-8'),
                                            b'echowithin_kek_v1', _NOTES_KDF_ITERATIONS)).decrypt(token.encode('utf-8'))
        except Exception:
            return None, False
        if confirm:
            coll.update_one(query, {'$set': {key_field: key_management.transit_encrypt(raw)}})
        return raw, False
    dek_raw = os.urandom(32)
    if confirm:
        coll.update_one(query, {'$set': {key_field: key_management.transit_encrypt(dek_raw),
                                         version_field: 3}})
    stats.objects_keyed += 1
    return dek_raw, True


# ---------------------------------------------------------------------------
# Bonds
# ---------------------------------------------------------------------------

_BOND_SIMPLE = [
    ('bond_journal', ('content',)),
    ('bond_moods', ('mood',)),
    ('bond_habits', ('title',)),
    ('bond_countdowns', ('title', 'note')),
    ('bond_events', ('title', 'note', 'location')),
    ('bond_album_photos', ('url', 'title', 'description')),
    ('bond_bucketlist', ('title', 'description')),
    ('bond_recommendations', ('title', 'link', 'note', 'image_url')),
    ('bond_pulses', ('message',)),
]


def _migrate_bonds(db, secret, confirm, stats):
    # 1. Ensure every bond has a DEK; build {bid: (old_f, new_f)}
    keys = {}
    for bdoc in db['bonds'].find({}, {'_id': 1}):
        bid = str(bdoc['_id'])
        dek, _ = _ensure_object_dek(db['bonds'], {'_id': bdoc['_id']}, 'bond_key_enc', 'bond_encryption_version', confirm, stats)
        if dek is None:
            continue
        keys[bid] = (_legacy_fernet(secret, 'bonds', bid), _v3_fernet(dek, 'bonds', bid))

    def _simple(coll_name, fields):
        coll = db[coll_name]
        for doc in coll.find({}):
            bid = str(doc.get('bond_id', ''))
            if bid not in keys:
                stats.skipped += 1
                continue
            old_f, new_f = keys[bid]
            updates = {}
            failed = False
            for fn in fields:
                nv, st = _rotate_field(doc.get(fn), old_f, new_f)
                if st == 'rotated':
                    updates[fn] = nv
                elif st == 'failed':
                    failed = True
            _commit(coll, doc, updates, failed, stats, coll_name)

    # bond_goals: title, description, milestones[].title, check_ins[].note
    for gdoc in db['bond_goals'].find({}):
        bid = str(gdoc.get('bond_id', ''))
        if bid not in keys:
            stats.skipped += 1
            continue
        old_f, new_f = keys[bid]
        updates, failed = {}, False
        for fn in ('title', 'description'):
            nv, st = _rotate_field(gdoc.get(fn), old_f, new_f)
            if st == 'rotated':
                updates[fn] = nv
            elif st == 'failed':
                failed = True
        for src, dst in (('milestones', 'title'), ('check_ins', 'note')):
            lst = gdoc.get(src)
            if isinstance(lst, list):
                new_list, changed = [], False
                for item in lst:
                    if isinstance(item, dict) and _is_fernet_token(item.get(dst)):
                        nv, st = _rotate_field(item[dst], old_f, new_f)
                        copy = dict(item)
                        if st == 'rotated':
                            copy[dst] = nv
                            changed = True
                        elif st == 'failed':
                            failed = True
                        new_list.append(copy)
                    else:
                        new_list.append(item)
                if changed:
                    updates[src] = new_list
        _commit(db['bond_goals'], gdoc, updates, failed, stats, 'bond_goals')

    # bond_qotd: question_text, answers.<uid>.answer or answers.<uid>
    for qdoc in db['bond_qotd'].find({}):
        bid = str(qdoc.get('bond_id', ''))
        if bid not in keys:
            stats.skipped += 1
            continue
        old_f, new_f = keys[bid]
        updates, failed = {}, False
        nv, st = _rotate_field(qdoc.get('question_text'), old_f, new_f)
        if st == 'rotated':
            updates['question_text'] = nv
        elif st == 'failed':
            failed = True
        answers = qdoc.get('answers')
        if isinstance(answers, dict):
            new_answers, changed = dict(answers), False
            for uid_key, a_val in answers.items():
                if isinstance(a_val, dict) and _is_fernet_token(a_val.get('answer')):
                    nv, st = _rotate_field(a_val['answer'], old_f, new_f)
                    if st == 'rotated':
                        a_copy = dict(a_val)
                        a_copy['answer'] = nv
                        new_answers[uid_key] = a_copy
                        changed = True
                    elif st == 'failed':
                        failed = True
                elif _is_fernet_token(a_val):
                    nv, st = _rotate_field(a_val, old_f, new_f)
                    if st == 'rotated':
                        new_answers[uid_key] = nv
                        changed = True
                    elif st == 'failed':
                        failed = True
            if changed:
                updates['answers'] = new_answers
        _commit(db['bond_qotd'], qdoc, updates, failed, stats, 'bond_qotd')

    for coll_name, fields in _BOND_SIMPLE:
        _simple(coll_name, fields)


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------

def _migrate_forms(db, secret, confirm, stats):
    keys = {}
    for fdoc in db['forms'].find({}, {'_id': 1}):
        fid = str(fdoc['_id'])
        dek, _ = _ensure_object_dek(db['forms'], {'_id': fdoc['_id']}, 'form_key_enc', 'form_encryption_version', confirm, stats)
        if dek is None:
            continue
        keys[fid] = (_legacy_fernet(secret, 'forms', fid), _v3_fernet(dek, 'forms', fid))

    for fdoc in db['forms'].find({}):
        fid = str(fdoc['_id'])
        if fid not in keys:
            stats.skipped += 1
            continue
        old_f, new_f = keys[fid]
        updates, failed = {}, False
        for fn in ('title', 'description'):
            nv, st = _rotate_field(fdoc.get(fn), old_f, new_f)
            if st == 'rotated':
                updates[fn] = nv
            elif st == 'failed':
                failed = True
        qs = fdoc.get('questions')
        if isinstance(qs, list):
            new_qs, changed = [], False
            for q in qs:
                if not isinstance(q, dict):
                    new_qs.append(q)
                    continue
                q_copy = dict(q)
                nv, st = _rotate_field(q.get('label'), old_f, new_f)
                if st == 'rotated':
                    q_copy['label'] = nv
                    changed = True
                elif st == 'failed':
                    failed = True
                if isinstance(q.get('options'), list):
                    new_opts = []
                    for o in q['options']:
                        nv, st = _rotate_field(o, old_f, new_f)
                        if st == 'rotated':
                            new_opts.append(nv)
                            changed = True
                        elif st == 'failed':
                            new_opts.append(o)
                            failed = True
                        else:
                            new_opts.append(o)
                    q_copy['options'] = new_opts
                new_qs.append(q_copy)
            if changed:
                updates['questions'] = new_qs
        _commit(db['forms'], fdoc, updates, failed, stats, 'forms')

    for rdoc in db['form_responses'].find({}):
        fid = str(rdoc.get('form_id', ''))
        if fid not in keys:
            stats.skipped += 1
            continue
        old_f, new_f = keys[fid]
        ans_list = rdoc.get('answers')
        if not isinstance(ans_list, list):
            stats.skipped += 1
            continue
        new_ans, changed, failed = [], False, False
        for a in ans_list:
            if isinstance(a, dict) and _is_fernet_token(a.get('value')):
                nv, st = _rotate_field(a['value'], old_f, new_f)
                a_copy = dict(a)
                if st == 'rotated':
                    a_copy['value'] = nv
                    changed = True
                elif st == 'failed':
                    failed = True
                new_ans.append(a_copy)
            else:
                new_ans.append(a)
        _commit(db['form_responses'], rdoc, {'answers': new_ans} if changed else {}, failed, stats, 'form_responses')


# ---------------------------------------------------------------------------
# Games
# ---------------------------------------------------------------------------

def _migrate_games(db, secret, confirm, stats):
    keys = {}
    for gdoc in db['game_sessions'].find({}, {'lobby_id': 1}):
        lid = str(gdoc.get('lobby_id', ''))
        if not lid:
            continue
        dek, _ = _ensure_object_dek(db['game_sessions'], {'lobby_id': lid}, 'game_key_enc', 'game_encryption_version', confirm, stats)
        if dek is None:
            continue
        keys[lid] = (_legacy_fernet(secret, 'games', lid), _v3_fernet(dek, 'games', lid))

    for gdoc in db['game_sessions'].find({}):
        lid = str(gdoc.get('lobby_id', ''))
        if lid not in keys:
            stats.skipped += 1
            continue
        old_f, new_f = keys[lid]
        updates, failed = {}, False
        for fn in ('title', 'prompt'):
            nv, st = _rotate_field(gdoc.get(fn), old_f, new_f)
            if st == 'rotated':
                updates[fn] = nv
            elif st == 'failed':
                failed = True
        q0 = gdoc.get('question')
        if isinstance(q0, dict):
            q0_copy, changed = dict(q0), False
            for qf in ('label', 'correct_option'):
                nv, st = _rotate_field(q0.get(qf), old_f, new_f)
                if st == 'rotated':
                    q0_copy[qf] = nv
                    changed = True
                elif st == 'failed':
                    failed = True
            if changed:
                updates['question'] = q0_copy
        qs = gdoc.get('questions')
        if isinstance(qs, list):
            new_qs, changed = [], False
            for q in qs:
                if isinstance(q, dict):
                    q_copy = dict(q)
                    for qf in ('label', 'correct_option'):
                        nv, st = _rotate_field(q.get(qf), old_f, new_f)
                        if st == 'rotated':
                            q_copy[qf] = nv
                            changed = True
                        elif st == 'failed':
                            failed = True
                    new_qs.append(q_copy)
                else:
                    new_qs.append(q)
            if changed:
                updates['questions'] = new_qs
        sents = gdoc.get('sentences')
        if isinstance(sents, list):
            new_sents, changed = [], False
            for s in sents:
                if isinstance(s, dict) and _is_fernet_token(s.get('text')):
                    nv, st = _rotate_field(s['text'], old_f, new_f)
                    s_copy = dict(s)
                    if st == 'rotated':
                        s_copy['text'] = nv
                        changed = True
                    elif st == 'failed':
                        failed = True
                    new_sents.append(s_copy)
                else:
                    new_sents.append(s)
            if changed:
                updates['sentences'] = new_sents
        live_ans = gdoc.get('live_answers')
        if isinstance(live_ans, dict):
            new_live, changed = {}, False
            for q_idx, players_map in live_ans.items():
                if isinstance(players_map, dict):
                    new_pmap = {}
                    for pid, pinfo in players_map.items():
                        if isinstance(pinfo, dict) and _is_fernet_token(pinfo.get('option')):
                            nv, st = _rotate_field(pinfo['option'], old_f, new_f)
                            p_copy = dict(pinfo)
                            if st == 'rotated':
                                p_copy['option'] = nv
                                changed = True
                            elif st == 'failed':
                                failed = True
                            new_pmap[pid] = p_copy
                        else:
                            new_pmap[pid] = pinfo
                    new_live[q_idx] = new_pmap
                else:
                    new_live[q_idx] = players_map
            if changed:
                updates['live_answers'] = new_live
        _commit(db['game_sessions'], gdoc, updates, failed, stats, 'game_sessions')

    for sub in db['game_submissions'].find({}):
        lid = str(sub.get('lobby_id', ''))
        content = sub.get('content')
        if lid not in keys or not isinstance(content, dict):
            stats.skipped += 1
            continue
        old_f, new_f = keys[lid]
        c_copy, changed, failed = dict(content), False, False
        if isinstance(content.get('statements'), list):
            new_stmts = []
            for s in content['statements']:
                nv, st = _rotate_field(s, old_f, new_f)
                if st == 'rotated':
                    new_stmts.append(nv)
                    changed = True
                elif st == 'failed':
                    new_stmts.append(s)
                    failed = True
                else:
                    new_stmts.append(s)
            c_copy['statements'] = new_stmts
        for fn in ('lie_index', 'caption'):
            nv, st = _rotate_field(content.get(fn), old_f, new_f)
            if st == 'rotated':
                c_copy[fn] = nv
                changed = True
            elif st == 'failed':
                failed = True
        _commit(db['game_submissions'], sub, {'content': c_copy} if changed else {}, failed, stats, 'game_submissions')

    for vdoc in db['game_votes'].find({}):
        lid = str(vdoc.get('lobby_id', ''))
        opt = vdoc.get('option')
        if lid not in keys or not _is_fernet_token(opt):
            stats.skipped += 1
            continue
        old_f, new_f = keys[lid]
        nv, st = _rotate_field(opt, old_f, new_f)
        failed = (st == 'failed')
        _commit(db['game_votes'], vdoc, {'option': nv} if st == 'rotated' else {}, failed, stats, 'game_votes')


def _commit(coll, doc, updates, failed, stats, coll_name):
    if failed:
        stats.failed += 1
        stats.note(coll_name, doc['_id'], ','.join(updates) or '-', 'failed')
    elif updates:
        if _CONFIRM:
            coll.update_one({'_id': doc['_id']}, {'$set': updates})
        stats.rotated += 1
        stats.note(coll_name, doc['_id'], ','.join(updates), 'rotated')
    else:
        stats.skipped += 1


_CONFIRM = False


def _write_audit(entries):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = os.path.join(_PROJECT_ROOT, f'migrate_object_deks_to_transit_{ts}.json')
    with open(path, 'w') as f:
        json.dump(entries, f, indent=2, default=str)
    print(f"\nAudit log written: {path}")


def _run(confirm):
    global _CONFIRM
    _CONFIRM = confirm
    secret = _get_env('SECRET')
    client = MongoClient(_get_env('MONGODB_CONNECTION'))
    db = client['echowithin_db']
    stats = _Stats()

    print("\n--- Bonds ---")
    _migrate_bonds(db, secret, confirm, stats)
    print("\n--- Forms ---")
    _migrate_forms(db, secret, confirm, stats)
    print("\n--- Games ---")
    _migrate_games(db, secret, confirm, stats)

    if stats.should_break():
        print(f"\n  CIRCUIT BREAKER TRIPPED: {stats.failed} failed. Aborting.")
        _write_audit(stats.audit)
        sys.exit(1)
    return stats


def main(args):
    if not key_management.transit_enabled():
        print("VAULT_TRANSIT_KEY is not set — nothing to migrate to.")
        sys.exit(1)
    print(f"Key custody mode: {key_management.current_mode()}")
    if args.confirm:
        print("Confirming Vault Transit health...")
        if not key_management.verify_transit():
            print("Transit self-check failed; aborting.")
            sys.exit(1)

    start = time.time()
    stats = _run(confirm=args.confirm)
    elapsed = time.time() - start
    mode = "APPLIED" if args.confirm else "DRY-RUN"
    print(f"\n[{mode}] objects_keyed={stats.objects_keyed} rotated={stats.rotated} "
          f"skipped={stats.skipped} failed={stats.failed} in {elapsed:.1f}s")
    _write_audit(stats.audit)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Move bond/form/game keys onto Vault-wrapped per-object DEKs.")
    parser.add_argument('--dry-run', action='store_true', default=False)
    parser.add_argument('--confirm', action='store_true', default=False,
                        help="Apply changes (required for any database mutation).")
    args = parser.parse_args()
    if args.confirm and args.dry_run:
        print("Choose either --dry-run or --confirm, not both.")
        sys.exit(1)
    if not args.confirm:
        args.dry_run = True
    main(args)
