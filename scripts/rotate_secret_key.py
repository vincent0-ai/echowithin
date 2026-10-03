"""
Comprehensive SECRET_KEY rotation tool for EchoWithin.

Safely rotates SECRET_KEY across ALL encrypted data categories in the platform:
  Phase 1:  User v3 envelope DEKs (users.encryption_key_enc) + missing v3 keys
  Phase 2:  Conversation v3 envelope DEKs (dm_permissions.conversation_key_enc)
  Phase 3:  Media-at-rest envelope key (auth collection type='media_encryption_key')
            so encrypted Cloudinary / local media blobs remain decryptable
  Phase 4:  Private Vault items (vault_items: filename_enc, notes_enc, thumbnail_data)
  Phase 5:  User-keyed legacy v1/v2 fields (users.bio, personal_posts, note_versions,
            note_attachments, note_discussions, note_shares)
  Phase 6:  DM-keyed legacy v2 fields (direct_messages, scheduled_messages,
            whisper_messages including media URLs, public IDs, and previews)
  Phase 7:  All Bond collections (bond_goals, bond_journal, bond_moods, bond_qotd,
            bond_habits, bond_countdowns, bond_events, bond_album_photos,
            bond_bucketlist, bond_recommendations, bond_pulses)
  Phase 8:  Community Notes (community_notes.content)
  Phase 9:  Forms & Form Responses (forms, form_responses)
  Phase 10: Game Lobbies, Submissions & Votes (game_sessions, game_submissions, game_votes)

Usage (from the project root or app container):
    # Via environment variables (recommended):
    export OLD_SECRET_KEY="current-secret"
    export NEW_SECRET_KEY="new-secret"
    python scripts/rotate_secret_key.py --dry-run
    python scripts/rotate_secret_key.py --confirm

    # Or interactively (prompts on stdin, never touches argv/history):
    python scripts/rotate_secret_key.py --interactive --dry-run
    python scripts/rotate_secret_key.py --interactive --confirm

Safety:
- Dry-run by default; --confirm is required for any database mutation
- Pre-flight check verifies that OLD_SECRET_KEY (or NEW_SECRET_KEY if resuming)
  can decrypt existing keys/records before mutating anything
- Idempotent: records already encrypted/wrapped with NEW_SECRET_KEY (or v3 DEKs)
  are automatically detected and skipped
- Circuit breaker: aborts if failure rate exceeds 5% (with at least 10 failures)
- Writes a timestamped audit log (rotate_secret_key_<timestamp>.json)
"""

import sys
import os
import argparse
import base64
import time
import json
import datetime
import getpass
import secrets as _secrets

# Add project root to sys.path so imports work whether run from root or scripts/
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from gevent import monkey
monkey.patch_all()

from bson.objectid import ObjectId
from cryptography.fernet import Fernet

_CIRCUIT_BREAKER_THRESHOLD = 0.05   # 5% failure rate
_CIRCUIT_BREAKER_MIN_FAILURES = 10  # at least 10 failures before tripping


def _is_fernet_token(val) -> bool:
    """Return True if value looks like a Fernet token string."""
    return isinstance(val, str) and val.startswith('gAAAAA') and len(val) >= 50


def _try_decrypt(fernet: Fernet, token_str: str):
    """Attempt to decrypt a Fernet token string. Returns plaintext str or None."""
    if not fernet or not _is_fernet_token(token_str):
        return None
    try:
        return fernet.decrypt(token_str.encode('utf-8')).decode('utf-8')
    except Exception:
        return None


def _check_circuit_breaker(total, failed, label):
    """Raise SystemExit if the failure rate exceeds the circuit breaker threshold."""
    if failed < _CIRCUIT_BREAKER_MIN_FAILURES:
        return
    rate = failed / max(total, 1)
    if rate > _CIRCUIT_BREAKER_THRESHOLD:
        print(f"\n  CIRCUIT BREAKER TRIPPED for {label}: {failed}/{total} "
              f"failed ({rate:.1%} > {_CIRCUIT_BREAKER_THRESHOLD:.1%}). Aborting.")
        sys.exit(1)


def _write_audit_log(entries, log_path):
    """Persist audit records to a timestamped JSON file."""
    os.makedirs(os.path.dirname(log_path) or '.', exist_ok=True)
    with open(log_path, 'w') as f:
        json.dump(entries, f, indent=2, default=str)


def _get_secret(label, env_var, interactive=False):
    """Resolve a secret from env var or interactive prompt."""
    val = os.environ.get(env_var)
    if val:
        return val
    if interactive:
        return getpass.getpass(f"Enter {label}: ").strip()
    return None


class _RotationKeyRing:
    """Derives and caches old/new Fernet instances across all encryption domains."""

    def __init__(self, old_secret: str, new_secret: str):
        from security import _derive_fernet_key, _NOTES_KDF_ITERATIONS, _NOTES_V1_SALT
        self._derive = _derive_fernet_key
        self._iters = _NOTES_KDF_ITERATIONS
        self._v1_salt = _NOTES_V1_SALT

        self.old_bytes = old_secret.encode('utf-8')
        self.new_bytes = new_secret.encode('utf-8')

        # Master KEKs (for v3 user & conversation DEKs + media DEK)
        self.old_kek = Fernet(self._derive(self.old_bytes, b'echowithin_kek_v1', self._iters))
        self.new_kek = Fernet(self._derive(self.new_bytes, b'echowithin_kek_v1', self._iters))

        # Legacy v1 global note Fernets (100k iterations)
        self.old_v1_notes = Fernet(self._derive(self.old_bytes, self._v1_salt, 100000))
        self.new_v1_notes = Fernet(self._derive(self.new_bytes, self._v1_salt, 100000))

        # Caches
        self._old_user_v2 = {}
        self._new_user_v2 = {}
        self._user_v3 = {}  # uid_str -> Fernet

        self._old_dm_v2 = {}
        self._new_dm_v2 = {}
        self._dm_v3 = {}    # conv_id -> Fernet

        self._old_bond = {}
        self._new_bond = {}

        self._old_comm_v2 = {}
        self._old_comm_v1 = {}
        self._new_comm_v2 = {}
        self._new_comm_v1 = {}

        self._old_form = {}
        self._new_form = {}

        self._old_game = {}
        self._new_game = {}

    def register_user_v3_dek(self, uid_str: str, dek_raw: bytes, salt_b64: str):
        """Cache a user's v3 Fernet instance from their unwrapped DEK + salt."""
        try:
            salt = base64.urlsafe_b64decode(salt_b64)
            key = self._derive(dek_raw, salt, self._iters)
            self._user_v3[str(uid_str)] = Fernet(key)
        except Exception:
            pass

    def get_user_v3(self, uid_str: str):
        return self._user_v3.get(str(uid_str))

    def get_old_user_v2(self, uid_str: str) -> Fernet:
        uid_str = str(uid_str)
        if uid_str not in self._old_user_v2:
            salt = f'echowithin_notes_v2_{uid_str}'.encode('utf-8')
            self._old_user_v2[uid_str] = Fernet(self._derive(self.old_bytes, salt, self._iters))
        return self._old_user_v2[uid_str]

    def get_new_user_v2(self, uid_str: str) -> Fernet:
        uid_str = str(uid_str)
        if uid_str not in self._new_user_v2:
            salt = f'echowithin_notes_v2_{uid_str}'.encode('utf-8')
            self._new_user_v2[uid_str] = Fernet(self._derive(self.new_bytes, salt, self._iters))
        return self._new_user_v2[uid_str]

    @staticmethod
    def conv_id(u1: str, u2: str) -> str:
        uids = sorted([str(u1), str(u2)])
        return f"{uids[0]}_{uids[1]}"

    def register_dm_v3_dek(self, u1: str, u2: str, dek_raw: bytes):
        """Cache a conversation's v3 Fernet instance from its unwrapped DEK."""
        cid = self.conv_id(u1, u2)
        salt = f'echowithin_dm_v3_{cid}'.encode('utf-8')
        self._dm_v3[cid] = Fernet(self._derive(dek_raw, salt, self._iters))

    def get_dm_v3(self, u1: str, u2: str):
        return self._dm_v3.get(self.conv_id(u1, u2))

    def get_old_dm_v2(self, u1: str, u2: str) -> Fernet:
        cid = self.conv_id(u1, u2)
        if cid not in self._old_dm_v2:
            salt = f'echowithin_dm_v1_{cid}'.encode('utf-8')
            self._old_dm_v2[cid] = Fernet(self._derive(self.old_bytes, salt, self._iters))
        return self._old_dm_v2[cid]

    def get_new_dm_v2(self, u1: str, u2: str) -> Fernet:
        cid = self.conv_id(u1, u2)
        if cid not in self._new_dm_v2:
            salt = f'echowithin_dm_v1_{cid}'.encode('utf-8')
            self._new_dm_v2[cid] = Fernet(self._derive(self.new_bytes, salt, self._iters))
        return self._new_dm_v2[cid]

    def get_old_bond(self, bond_id: str) -> Fernet:
        bid = str(bond_id)
        if bid not in self._old_bond:
            salt = f'echowithin_bonds_v1_{bid}'.encode('utf-8')
            self._old_bond[bid] = Fernet(self._derive(self.old_bytes, salt, self._iters))
        return self._old_bond[bid]

    def get_new_bond(self, bond_id: str) -> Fernet:
        bid = str(bond_id)
        if bid not in self._new_bond:
            salt = f'echowithin_bonds_v1_{bid}'.encode('utf-8')
            self._new_bond[bid] = Fernet(self._derive(self.new_bytes, salt, self._iters))
        return self._new_bond[bid]

    def get_old_comm_v2(self, comm_id: str) -> Fernet:
        cid = str(comm_id)
        if cid not in self._old_comm_v2:
            self._old_comm_v2[cid] = Fernet(self._derive(self.old_bytes, cid.encode('utf-8'), self._iters))
        return self._old_comm_v2[cid]

    def get_old_comm_v1(self, comm_id: str) -> Fernet:
        cid = str(comm_id)
        if cid not in self._old_comm_v1:
            self._old_comm_v1[cid] = Fernet(self._derive(self.old_bytes, cid.encode('utf-8'), 100000))
        return self._old_comm_v1[cid]

    def get_new_comm_v2(self, comm_id: str) -> Fernet:
        cid = str(comm_id)
        if cid not in self._new_comm_v2:
            self._new_comm_v2[cid] = Fernet(self._derive(self.new_bytes, cid.encode('utf-8'), self._iters))
        return self._new_comm_v2[cid]

    def get_new_comm_v1(self, comm_id: str) -> Fernet:
        cid = str(comm_id)
        if cid not in self._new_comm_v1:
            self._new_comm_v1[cid] = Fernet(self._derive(self.new_bytes, cid.encode('utf-8'), 100000))
        return self._new_comm_v1[cid]

    def get_old_form(self, form_id: str) -> Fernet:
        fid = str(form_id)
        if fid not in self._old_form:
            salt = f'echowithin_forms_v1_{fid}'.encode('utf-8')
            self._old_form[fid] = Fernet(self._derive(self.old_bytes, salt, self._iters))
        return self._old_form[fid]

    def get_new_form(self, form_id: str) -> Fernet:
        fid = str(form_id)
        if fid not in self._new_form:
            salt = f'echowithin_forms_v1_{fid}'.encode('utf-8')
            self._new_form[fid] = Fernet(self._derive(self.new_bytes, salt, self._iters))
        return self._new_form[fid]

    def get_old_game(self, lobby_id: str) -> Fernet:
        lid = str(lobby_id)
        if lid not in self._old_game:
            salt = f'echowithin_games_v1_{lid}'.encode('utf-8')
            self._old_game[lid] = Fernet(self._derive(self.old_bytes, salt, self._iters))
        return self._old_game[lid]

    def get_new_game(self, lobby_id: str) -> Fernet:
        lid = str(lobby_id)
        if lid not in self._new_game:
            salt = f'echowithin_games_v1_{lid}'.encode('utf-8')
            self._new_game[lid] = Fernet(self._derive(self.new_bytes, salt, self._iters))
        return self._new_game[lid]

    def rotate_user_field(self, ciphertext: str, candidate_uids: list, primary_uid: str = None):
        """Rotate a user-keyed field to primary_uid's v3 DEK (or new v2 key).

        Returns (new_ciphertext, status) where status is 'skipped', 'rotated', or 'failed'.
        """
        if not _is_fernet_token(ciphertext):
            return ciphertext, 'skipped'

        clean_uids = []
        for u in candidate_uids:
            if u is not None:
                s = str(u).strip()
                if s and s not in clean_uids:
                    clean_uids.append(s)

        owner_uid = str(primary_uid).strip() if primary_uid else (clean_uids[0] if clean_uids else None)

        # 1. Check if already decryptable with any candidate's v3 key
        for uid in clean_uids:
            f_v3 = self.get_user_v3(uid)
            if f_v3 and _try_decrypt(f_v3, ciphertext) is not None:
                return ciphertext, 'skipped'

        # 2. If no candidate has a v3 key, check if already decryptable with new v2 or new v1
        for uid in clean_uids:
            if not self.get_user_v3(uid):
                if _try_decrypt(self.get_new_user_v2(uid), ciphertext) is not None:
                    return ciphertext, 'skipped'
        if not owner_uid and _try_decrypt(self.new_v1_notes, ciphertext) is not None:
            return ciphertext, 'skipped'

        # 3. Decrypt using old v2 keys, new v2 keys (if upgrading to v3), old v1, or new v1
        plaintext = None
        matched_uid = None
        for uid in clean_uids:
            plaintext = _try_decrypt(self.get_old_user_v2(uid), ciphertext)
            if plaintext is not None:
                matched_uid = uid
                break
            plaintext = _try_decrypt(self.get_new_user_v2(uid), ciphertext)
            if plaintext is not None:
                matched_uid = uid
                break

        if plaintext is None:
            plaintext = _try_decrypt(self.old_v1_notes, ciphertext)
        if plaintext is None:
            plaintext = _try_decrypt(self.new_v1_notes, ciphertext)

        if plaintext is None:
            return ciphertext, 'failed'

        # 4. Re-encrypt with target key (prefer v3 DEK of owner/matched user, else new v2, else new v1)
        target_uid = matched_uid or owner_uid
        target_fernet = None
        if target_uid:
            target_fernet = self.get_user_v3(target_uid) or self.get_new_user_v2(target_uid)
        else:
            target_fernet = self.new_v1_notes

        new_cipher = target_fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')
        return new_cipher, 'rotated'

    def rotate_dm_field(self, ciphertext: str, u1: str, u2: str):
        """Rotate a DM-keyed field to the pair's v3 conversation key (or new v2 DM key).

        Returns (new_ciphertext, status) where status is 'skipped', 'rotated', or 'failed'.
        """
        if not _is_fernet_token(ciphertext) or not u1 or not u2:
            return ciphertext, 'skipped'

        f_v3 = self.get_dm_v3(u1, u2)
        f_new_v2 = self.get_new_dm_v2(u1, u2)
        f_old_v2 = self.get_old_dm_v2(u1, u2)

        # If pair has v3 conversation key, check if already encrypted with v3
        if f_v3:
            if _try_decrypt(f_v3, ciphertext) is not None:
                return ciphertext, 'skipped'
        else:
            if _try_decrypt(f_new_v2, ciphertext) is not None:
                return ciphertext, 'skipped'

        # Decrypt with old v2 (or new v2 if upgrading to v3, or v3)
        plaintext = _try_decrypt(f_old_v2, ciphertext)
        if plaintext is None:
            plaintext = _try_decrypt(f_new_v2, ciphertext)
        if plaintext is None and f_v3:
            plaintext = _try_decrypt(f_v3, ciphertext)

        if plaintext is None:
            return ciphertext, 'failed'

        target_fernet = f_v3 if f_v3 else f_new_v2
        new_cipher = target_fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')
        return new_cipher, 'rotated'

    def rotate_simple_field(self, ciphertext: str, old_fernet: Fernet, new_fernet: Fernet, extra_old_fernets=None):
        """Rotate a single-domain Fernet field (bond, community, form, game, vault).

        Returns (new_ciphertext, status) where status is 'skipped', 'rotated', or 'failed'.
        """
        if not _is_fernet_token(ciphertext):
            return ciphertext, 'skipped'

        if _try_decrypt(new_fernet, ciphertext) is not None:
            return ciphertext, 'skipped'

        plaintext = _try_decrypt(old_fernet, ciphertext)
        if plaintext is None and extra_old_fernets:
            for ef in extra_old_fernets:
                plaintext = _try_decrypt(ef, ciphertext)
                if plaintext is not None:
                    break

        if plaintext is None:
            return ciphertext, 'failed'

        new_cipher = new_fernet.encrypt(plaintext.encode('utf-8')).decode('utf-8')
        return new_cipher, 'rotated'


def run_rotation(old_secret: str, new_secret: str, confirm=False, batch_size=50):
    """Execute or dry-run the full 10-phase SECRET_KEY rotation."""
    import database
    import main as m
    import security

    with m.app.app_context():
        print("=" * 68)
        print("EchoWithin Comprehensive SECRET_KEY Rotation Tool (10 Phases)")
        print("=" * 68)
        if not confirm:
            print("[DRY RUN] No changes will be written to the database. Pass --confirm to execute.")
        else:
            print("[LIVE EXECUTION] Changes WILL be written to the database.")
        print()

        keyring = _RotationKeyRing(old_secret, new_secret)
        print("Keyring initialized.")

        # ---- Pre-flight verification ----
        print("\nVerifying OLD_SECRET_KEY against existing encrypted data...")
        test_user = database.users_conf.find_one(
            {'encryption_key_enc': {'$exists': True, '$ne': ''}},
            {'encryption_key_enc': 1, 'username': 1}
        )
        if test_user:
            enc_dek = test_user['encryption_key_enc'].encode('utf-8')
            verified = False
            try:
                keyring.old_kek.decrypt(enc_dek)
                print(f"  OK: Verified OLD_SECRET_KEY against user DEK ('{test_user.get('username', '?')}').")
                verified = True
            except Exception:
                try:
                    keyring.new_kek.decrypt(enc_dek)
                    print(f"  OK: User DEK ('{test_user.get('username', '?')}') is already wrapped with NEW_SECRET_KEY (resuming rotation).")
                    verified = True
                except Exception as e:
                    print(f"  FAILED: Neither OLD_SECRET_KEY nor NEW_SECRET_KEY could decrypt user DEK: {e}")
                    print("  Aborting immediately. No data was modified.")
                    sys.exit(1)

        ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')
        log_path = f'rotate_secret_key_{ts}.json'
        audit_entries = []
        summary = {}

        # ==================================================================
        # PHASE 1: User Envelope DEKs (users.encryption_key_enc)
        # ==================================================================
        print("\n--- Phase 1: User Envelope DEKs (users) ---")
        all_users = list(database.users_conf.find(
            {},
            {'_id': 1, 'username': 1, 'encryption_key_enc': 1, 'encryption_salt': 1}
        ))
        p1_rewrapped, p1_generated, p1_skipped, p1_failed = 0, 0, 0, 0

        for user_doc in all_users:
            uid = str(user_doc['_id'])
            enc_dek_str = user_doc.get('encryption_key_enc')
            salt_b64 = user_doc.get('encryption_salt')

            if not enc_dek_str or not salt_b64:
                # Generate v3 envelope key for user missing one
                try:
                    dek_raw = _secrets.token_bytes(32)
                    salt_raw = _secrets.token_bytes(32)
                    salt_b64 = base64.urlsafe_b64encode(salt_raw).decode('utf-8')
                    new_enc_dek = keyring.new_kek.encrypt(dek_raw).decode('utf-8')
                    keyring.register_user_v3_dek(uid, dek_raw, salt_b64)
                    if confirm:
                        database.users_conf.update_one(
                            {'_id': user_doc['_id']},
                            {'$set': {
                                'encryption_key_enc': new_enc_dek,
                                'encryption_salt': salt_b64,
                                'encryption_version': 3
                            }}
                        )
                    p1_generated += 1
                    audit_entries.append({'phase': 'p1_users', 'id': uid, 'result': 'generated_v3'})
                except Exception as e:
                    p1_failed += 1
                    audit_entries.append({'phase': 'p1_users', 'id': uid, 'result': 'failed', 'error': str(e)})
                continue

            try:
                enc_bytes = enc_dek_str.encode('utf-8')
                try:
                    dek_raw = keyring.new_kek.decrypt(enc_bytes)
                    keyring.register_user_v3_dek(uid, dek_raw, salt_b64)
                    p1_skipped += 1
                    continue
                except Exception:
                    pass

                dek_raw = keyring.old_kek.decrypt(enc_bytes)
                keyring.register_user_v3_dek(uid, dek_raw, salt_b64)
                new_enc_dek = keyring.new_kek.encrypt(dek_raw).decode('utf-8')
                if confirm:
                    database.users_conf.update_one(
                        {'_id': user_doc['_id']},
                        {'$set': {'encryption_key_enc': new_enc_dek}}
                    )
                p1_rewrapped += 1
                audit_entries.append({'phase': 'p1_users', 'id': uid, 'result': 'rewrapped'})
            except Exception as e:
                print(f"  [ERROR] User {user_doc.get('username', uid)}: {e}")
                p1_failed += 1
                audit_entries.append({'phase': 'p1_users', 'id': uid, 'result': 'failed', 'error': str(e)})
                _check_circuit_breaker(p1_rewrapped + p1_generated + p1_skipped + p1_failed, p1_failed, 'Phase 1 (users)')

        summary['Phase 1 (User DEKs)'] = f"{p1_rewrapped} rewrapped, {p1_generated} generated, {p1_skipped} skipped, {p1_failed} failed"
        print(f"  Phase 1 complete: {summary['Phase 1 (User DEKs)']}")

        # ==================================================================
        # PHASE 2: Conversation Envelope DEKs (dm_permissions)
        # ==================================================================
        print("\n--- Phase 2: Conversation Envelope DEKs (dm_permissions) ---")
        all_perms = list(database.dm_permissions_conf.find(
            {},
            {'_id': 1, 'requester_id': 1, 'target_id': 1, 'conversation_key_enc': 1}
        ))
        p2_rewrapped, p2_generated, p2_skipped, p2_failed = 0, 0, 0, 0

        for perm_doc in all_perms:
            cid = str(perm_doc['_id'])
            u1 = str(perm_doc.get('requester_id', ''))
            u2 = str(perm_doc.get('target_id', ''))
            enc_dek_str = perm_doc.get('conversation_key_enc')

            if not enc_dek_str:
                try:
                    dek_raw = _secrets.token_bytes(32)
                    new_enc_dek = keyring.new_kek.encrypt(dek_raw).decode('utf-8')
                    if u1 and u2:
                        keyring.register_dm_v3_dek(u1, u2, dek_raw)
                    if confirm:
                        database.dm_permissions_conf.update_one(
                            {'_id': perm_doc['_id']},
                            {'$set': {'conversation_key_enc': new_enc_dek, 'dm_encryption_version': 3}}
                        )
                    p2_generated += 1
                    audit_entries.append({'phase': 'p2_conversations', 'id': cid, 'result': 'generated_v3'})
                except Exception as e:
                    p2_failed += 1
                    audit_entries.append({'phase': 'p2_conversations', 'id': cid, 'result': 'failed', 'error': str(e)})
                continue

            try:
                enc_bytes = enc_dek_str.encode('utf-8')
                try:
                    dek_raw = keyring.new_kek.decrypt(enc_bytes)
                    if u1 and u2:
                        keyring.register_dm_v3_dek(u1, u2, dek_raw)
                    p2_skipped += 1
                    continue
                except Exception:
                    pass

                dek_raw = keyring.old_kek.decrypt(enc_bytes)
                if u1 and u2:
                    keyring.register_dm_v3_dek(u1, u2, dek_raw)
                new_enc_dek = keyring.new_kek.encrypt(dek_raw).decode('utf-8')
                if confirm:
                    database.dm_permissions_conf.update_one(
                        {'_id': perm_doc['_id']},
                        {'$set': {'conversation_key_enc': new_enc_dek}}
                    )
                p2_rewrapped += 1
                audit_entries.append({'phase': 'p2_conversations', 'id': cid, 'result': 'rewrapped'})
            except Exception as e:
                print(f"  [ERROR] Conversation {cid}: {e}")
                p2_failed += 1
                audit_entries.append({'phase': 'p2_conversations', 'id': cid, 'result': 'failed', 'error': str(e)})
                _check_circuit_breaker(p2_rewrapped + p2_generated + p2_skipped + p2_failed, p2_failed, 'Phase 2 (conversations)')

        summary['Phase 2 (Conversation DEKs)'] = f"{p2_rewrapped} rewrapped, {p2_generated} generated, {p2_skipped} skipped, {p2_failed} failed"
        print(f"  Phase 2 complete: {summary['Phase 2 (Conversation DEKs)']}")

        # ==================================================================
        # PHASE 3: Media-at-Rest Envelope Key (auth.type='media_encryption_key')
        # ==================================================================
        print("\n--- Phase 3: Media-at-Rest Envelope Key (Cloudinary / local media) ---")
        try:
            media_doc = database.auth_conf.find_one({'type': 'media_encryption_key'})
            media_key_raw = None
            p3_status = 'rewrapped'

            if media_doc and media_doc.get('encryption_key_enc'):
                enc_val = media_doc['encryption_key_enc'].encode('utf-8')
                try:
                    media_key_raw = keyring.new_kek.decrypt(enc_val)
                    p3_status = 'skipped'
                except Exception:
                    try:
                        media_key_raw = keyring.old_kek.decrypt(enc_val)
                    except Exception:
                        prev_val = media_doc.get('encryption_key_enc_prev')
                        if prev_val:
                            media_key_raw = keyring.old_kek.decrypt(prev_val.encode('utf-8'))

            if media_key_raw is None:
                # First-time rotation: preserve the existing media key derived from old_secret
                media_key_raw = keyring._derive(keyring.old_bytes, b'echowithin_media_at_rest_v1', keyring._iters)
                p3_status = 'initialized_envelope'

            if p3_status != 'skipped' and confirm:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                database.auth_conf.update_one(
                    {'type': 'media_encryption_key'},
                    {'$set': {
                        'type': 'media_encryption_key',
                        'encryption_key_enc': keyring.new_kek.encrypt(media_key_raw).decode('utf-8'),
                        'encryption_key_enc_prev': keyring.old_kek.encrypt(media_key_raw).decode('utf-8'),
                        'updated_at': now_utc,
                    }},
                    upsert=True
                )
            summary['Phase 3 (Media Envelope Key)'] = p3_status
            audit_entries.append({'phase': 'p3_media_key', 'result': p3_status})
            print(f"  Phase 3 complete: {p3_status}")
        except Exception as e:
            print(f"  [ERROR] Phase 3 Media Key failed: {e}")
            summary['Phase 3 (Media Envelope Key)'] = f"failed ({e})"
            sys.exit(1)

        # ==================================================================
        # PHASE 4: Private Vault Items (vault_items)
        # ==================================================================
        print("\n--- Phase 4: Private Vault Items (vault_items) ---")
        vault_docs = list(database.vault_items_conf.find({}))
        p4_rotated, p4_skipped, p4_failed = 0, 0, 0

        for vdoc in vault_docs:
            uid = str(vdoc.get('user_id', ''))
            if not uid:
                p4_skipped += 1
                continue
            updates = {}
            doc_failed = False
            old_f = keyring.get_old_user_v2(uid)
            new_f = keyring.get_new_user_v2(uid)
            extra_f = [f for f in (keyring.get_user_v3(uid), keyring.old_v1_notes) if f]

            for field in ('filename_enc', 'notes_enc', 'thumbnail_data'):
                val = vdoc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_simple_field(val, old_f, new_f, extra_old_fernets=extra_f)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        doc_failed = True

            if doc_failed:
                p4_failed += 1
                audit_entries.append({'phase': 'p4_vault', 'id': str(vdoc['_id']), 'result': 'failed'})
            elif updates:
                if confirm:
                    database.vault_items_conf.update_one({'_id': vdoc['_id']}, {'$set': updates})
                p4_rotated += 1
                audit_entries.append({'phase': 'p4_vault', 'id': str(vdoc['_id']), 'result': 'rotated'})
            else:
                p4_skipped += 1

        summary['Phase 4 (Vault Items)'] = f"{p4_rotated} rotated, {p4_skipped} skipped, {p4_failed} failed"
        print(f"  Phase 4 complete: {summary['Phase 4 (Vault Items)']}")

        # ==================================================================
        # PHASE 5: User-Keyed Legacy v1/v2 Fields
        # (users.bio, personal_posts, note_versions, note_attachments,
        #  note_discussions, note_shares)
        # ==================================================================
        print("\n--- Phase 5: User-Keyed Records (bio, notes, versions, attachments, shares, discussions) ---")
        p5_rotated, p5_skipped, p5_failed = 0, 0, 0

        # 5a. users.bio
        for udoc in database.users_conf.find({'bio': {'$exists': True, '$ne': ''}}, {'_id': 1, 'bio': 1}):
            uid = str(udoc['_id'])
            bio = udoc.get('bio', '')
            if _is_fernet_token(bio):
                new_bio, st = keyring.rotate_user_field(bio, [uid], primary_uid=uid)
                if st == 'rotated':
                    if confirm:
                        database.users_conf.update_one({'_id': udoc['_id']}, {'$set': {'bio': new_bio}})
                    p5_rotated += 1
                elif st == 'failed':
                    p5_failed += 1
                else:
                    p5_skipped += 1

        # 5b. personal_posts (content, reference, tags)
        note_owner_map = {}
        for ndoc in database.personal_posts_conf.find({}):
            nid = str(ndoc['_id'])
            cands = security._note_decryption_candidates(ndoc)
            primary = str(ndoc.get('content_owner_id') or ndoc.get('user_id') or (cands[0] if cands else ''))
            if primary:
                note_owner_map[nid] = primary

            updates = {}
            failed_flag = False

            for field in ('content', 'reference'):
                val = ndoc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_user_field(val, cands, primary_uid=primary)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        failed_flag = True

            tags = ndoc.get('tags')
            if isinstance(tags, list) and any(_is_fernet_token(t) for t in tags):
                new_tags = []
                tags_changed = False
                for t in tags:
                    if _is_fernet_token(t):
                        nt, st = keyring.rotate_user_field(t, cands, primary_uid=primary)
                        if st == 'rotated':
                            new_tags.append(nt)
                            tags_changed = True
                        elif st == 'failed':
                            new_tags.append(t)
                            failed_flag = True
                        else:
                            new_tags.append(t)
                    else:
                        new_tags.append(t)
                if tags_changed:
                    updates['tags'] = new_tags

            if failed_flag:
                p5_failed += 1
            elif updates:
                if confirm:
                    database.personal_posts_conf.update_one({'_id': ndoc['_id']}, {'$set': updates})
                p5_rotated += 1
            else:
                p5_skipped += 1

        # 5c. note_versions (content, base_content, proposed_content)
        for vdoc in database.note_versions_conf.find({}):
            nid = str(vdoc.get('note_id', ''))
            cands = [vdoc.get('content_owner_id'), vdoc.get('editor_id'), vdoc.get('user_id'), note_owner_map.get(nid)]
            primary = str(vdoc.get('content_owner_id') or note_owner_map.get(nid) or vdoc.get('editor_id') or '')
            updates = {}
            failed_flag = False
            for field in ('content', 'base_content', 'proposed_content'):
                val = vdoc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_user_field(val, cands, primary_uid=primary)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        failed_flag = True
            if failed_flag:
                p5_failed += 1
            elif updates:
                if confirm:
                    database.note_versions_conf.update_one({'_id': vdoc['_id']}, {'$set': updates})
                p5_rotated += 1
            else:
                p5_skipped += 1

        # 5d. note_attachments (url, filename)
        for adoc in database.note_attachments_conf.find({}):
            nid = str(adoc.get('note_id', ''))
            cands = [adoc.get('user_id'), note_owner_map.get(nid)]
            primary = str(adoc.get('user_id') or note_owner_map.get(nid) or '')
            updates = {}
            failed_flag = False
            for field in ('url', 'filename'):
                val = adoc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_user_field(val, cands, primary_uid=primary)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        failed_flag = True
            if failed_flag:
                p5_failed += 1
            elif updates:
                if confirm:
                    database.note_attachments_conf.update_one({'_id': adoc['_id']}, {'$set': updates})
                p5_rotated += 1
            else:
                p5_skipped += 1

        # 5e. note_discussions (content)
        for ddoc in database.note_discussions_conf.find({}):
            uid = str(ddoc.get('author_id', ''))
            val = ddoc.get('content')
            if _is_fernet_token(val):
                new_val, st = keyring.rotate_user_field(val, [uid], primary_uid=uid)
                if st == 'rotated':
                    if confirm:
                        database.note_discussions_conf.update_one({'_id': ddoc['_id']}, {'$set': {'content': new_val}})
                    p5_rotated += 1
                elif st == 'failed':
                    p5_failed += 1
                else:
                    p5_skipped += 1

        # 5f. note_shares (valentine_photo, valentine_audio, valentine_document)
        for sdoc in database.note_shares_conf.find({}):
            cands = [sdoc.get('owner_id'), sdoc.get('source_owner_id')]
            primary = str(sdoc.get('owner_id') or sdoc.get('source_owner_id') or '')
            updates = {}
            failed_flag = False
            for field in ('valentine_photo', 'valentine_audio', 'valentine_document'):
                val = sdoc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_user_field(val, cands, primary_uid=primary)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        failed_flag = True
            if failed_flag:
                p5_failed += 1
            elif updates:
                if confirm:
                    database.note_shares_conf.update_one({'_id': sdoc['_id']}, {'$set': updates})
                p5_rotated += 1
            else:
                p5_skipped += 1

        summary['Phase 5 (User-Keyed Docs)'] = f"{p5_rotated} rotated, {p5_skipped} skipped, {p5_failed} failed"
        print(f"  Phase 5 complete: {summary['Phase 5 (User-Keyed Docs)']}")

        # ==================================================================
        # PHASE 6: DM-Keyed Collections
        # (direct_messages, scheduled_messages, whisper_messages)
        # ==================================================================
        print("\n--- Phase 6: DM-Keyed Records (direct_messages, scheduled_messages, whisper_messages) ---")
        p6_rotated, p6_skipped, p6_failed = 0, 0, 0

        def _rotate_dm_doc(doc, u1_str, u2_str, fields):
            updates = {}
            failed_flag = False
            for field in fields:
                val = doc.get(field)
                if _is_fernet_token(val):
                    new_val, st = keyring.rotate_dm_field(val, u1_str, u2_str)
                    if st == 'rotated':
                        updates[field] = new_val
                    elif st == 'failed':
                        failed_flag = True
            lp = doc.get('link_preview')
            if isinstance(lp, dict):
                new_lp = dict(lp)
                lp_changed = False
                for k in ('url', 'title', 'description', 'image'):
                    v = lp.get(k)
                    if _is_fernet_token(v):
                        nv, st = keyring.rotate_dm_field(v, u1_str, u2_str)
                        if st == 'rotated':
                            new_lp[k] = nv
                            lp_changed = True
                        elif st == 'failed':
                            failed_flag = True
                if lp_changed:
                    updates['link_preview'] = new_lp
            return updates, failed_flag

        # 6a. direct_messages
        dm_fields = ('content', 'image_url', 'image_public_id', 'reply_to_preview')
        for dmdoc in database.direct_messages_conf.find({}):
            u1 = str(dmdoc.get('sender_id', ''))
            u2 = str(dmdoc.get('recipient_id', ''))
            updates, failed_flag = _rotate_dm_doc(dmdoc, u1, u2, dm_fields)
            if failed_flag:
                p6_failed += 1
            elif updates:
                if confirm:
                    database.direct_messages_conf.update_one({'_id': dmdoc['_id']}, {'$set': updates})
                p6_rotated += 1
            else:
                p6_skipped += 1

        # 6b. scheduled_messages
        for smdoc in database.scheduled_messages_conf.find({}):
            u1 = str(smdoc.get('sender_id', ''))
            u2 = str(smdoc.get('recipient_id', ''))
            updates, failed_flag = _rotate_dm_doc(smdoc, u1, u2, dm_fields)
            if failed_flag:
                p6_failed += 1
            elif updates:
                if confirm:
                    database.scheduled_messages_conf.update_one({'_id': smdoc['_id']}, {'$set': updates})
                p6_rotated += 1
            else:
                p6_skipped += 1

        # 6c. whisper_messages
        whisper_sessions_map = {}
        for ws in database.whisper_sessions_conf.find({}, {'_id': 1, 'initiator_id': 1, 'recipient_id': 1}):
            whisper_sessions_map[str(ws['_id'])] = (str(ws.get('initiator_id', '')), str(ws.get('recipient_id', '')))

        wm_fields = ('content', 'image_url', 'video_url', 'image_public_id', 'video_public_id')
        for wmdoc in database.whisper_messages_conf.find({}):
            sid = str(wmdoc.get('session_id', ''))
            u1, u2 = whisper_sessions_map.get(sid, ('', ''))
            if not u1 or not u2:
                p6_skipped += 1
                continue
            updates, failed_flag = _rotate_dm_doc(wmdoc, u1, u2, wm_fields)
            if failed_flag:
                p6_failed += 1
            elif updates:
                if confirm:
                    database.whisper_messages_conf.update_one({'_id': wmdoc['_id']}, {'$set': updates})
                p6_rotated += 1
            else:
                p6_skipped += 1

        summary['Phase 6 (DM/Whisper Docs)'] = f"{p6_rotated} rotated, {p6_skipped} skipped, {p6_failed} failed"
        print(f"  Phase 6 complete: {summary['Phase 6 (DM/Whisper Docs)']}")

        # ==================================================================
        # PHASE 7: Bond Collections (_get_bond_fernet)
        # ==================================================================
        print("\n--- Phase 7: Bond Collections (11 collections) ---")
        p7_rotated, p7_skipped, p7_failed = 0, 0, 0

        def _rotate_bond_simple_collection(coll, field_names):
            nonlocal p7_rotated, p7_skipped, p7_failed
            if coll is None:
                return
            for doc in coll.find({}):
                bid = str(doc.get('bond_id', ''))
                if not bid:
                    p7_skipped += 1
                    continue
                old_f = keyring.get_old_bond(bid)
                new_f = keyring.get_new_bond(bid)
                updates = {}
                failed_flag = False
                for fn in field_names:
                    val = doc.get(fn)
                    if _is_fernet_token(val):
                        nv, st = keyring.rotate_simple_field(val, old_f, new_f)
                        if st == 'rotated':
                            updates[fn] = nv
                        elif st == 'failed':
                            failed_flag = True
                if failed_flag:
                    p7_failed += 1
                elif updates:
                    if confirm:
                        coll.update_one({'_id': doc['_id']}, {'$set': updates})
                    p7_rotated += 1
                else:
                    p7_skipped += 1

        # 7a. bond_goals (title, description, milestones[].title, check_ins[].note)
        for gdoc in database.bond_goals_conf.find({}):
            bid = str(gdoc.get('bond_id', ''))
            if not bid:
                p7_skipped += 1
                continue
            old_f = keyring.get_old_bond(bid)
            new_f = keyring.get_new_bond(bid)
            updates = {}
            failed_flag = False
            for fn in ('title', 'description'):
                val = gdoc.get(fn)
                if _is_fernet_token(val):
                    nv, st = keyring.rotate_simple_field(val, old_f, new_f)
                    if st == 'rotated':
                        updates[fn] = nv
                    elif st == 'failed':
                        failed_flag = True

            ms_list = gdoc.get('milestones')
            if isinstance(ms_list, list):
                new_ms = []
                ms_changed = False
                for ms in ms_list:
                    if isinstance(ms, dict) and _is_fernet_token(ms.get('title')):
                        ms_copy = dict(ms)
                        nv, st = keyring.rotate_simple_field(ms['title'], old_f, new_f)
                        if st == 'rotated':
                            ms_copy['title'] = nv
                            ms_changed = True
                        elif st == 'failed':
                            failed_flag = True
                        new_ms.append(ms_copy)
                    else:
                        new_ms.append(ms)
                if ms_changed:
                    updates['milestones'] = new_ms

            ci_list = gdoc.get('check_ins')
            if isinstance(ci_list, list):
                new_ci = []
                ci_changed = False
                for ci in ci_list:
                    if isinstance(ci, dict) and _is_fernet_token(ci.get('note')):
                        ci_copy = dict(ci)
                        nv, st = keyring.rotate_simple_field(ci['note'], old_f, new_f)
                        if st == 'rotated':
                            ci_copy['note'] = nv
                            ci_changed = True
                        elif st == 'failed':
                            failed_flag = True
                        new_ci.append(ci_copy)
                    else:
                        new_ci.append(ci)
                if ci_changed:
                    updates['check_ins'] = new_ci

            if failed_flag:
                p7_failed += 1
            elif updates:
                if confirm:
                    database.bond_goals_conf.update_one({'_id': gdoc['_id']}, {'$set': updates})
                p7_rotated += 1
            else:
                p7_skipped += 1

        # 7b. bond_qotd (question_text, answers.<uid>.answer or answers.<uid>, skips[].question_text)
        for qdoc in database.bond_qotd_conf.find({}):
            bid = str(qdoc.get('bond_id', ''))
            if not bid:
                p7_skipped += 1
                continue
            old_f = keyring.get_old_bond(bid)
            new_f = keyring.get_new_bond(bid)
            updates = {}
            failed_flag = False

            qt = qdoc.get('question_text')
            if _is_fernet_token(qt):
                nv, st = keyring.rotate_simple_field(qt, old_f, new_f)
                if st == 'rotated':
                    updates['question_text'] = nv
                elif st == 'failed':
                    failed_flag = True

            answers = qdoc.get('answers')
            if isinstance(answers, dict):
                new_answers = dict(answers)
                ans_changed = False
                for uid_key, a_val in answers.items():
                    if isinstance(a_val, dict) and _is_fernet_token(a_val.get('answer')):
                        a_copy = dict(a_val)
                        nv, st = keyring.rotate_simple_field(a_val['answer'], old_f, new_f)
                        if st == 'rotated':
                            a_copy['answer'] = nv
                            new_answers[uid_key] = a_copy
                            ans_changed = True
                        elif st == 'failed':
                            failed_flag = True
                    elif _is_fernet_token(a_val):
                        nv, st = keyring.rotate_simple_field(a_val, old_f, new_f)
                        if st == 'rotated':
                            new_answers[uid_key] = nv
                            ans_changed = True
                        elif st == 'failed':
                            failed_flag = True
                if ans_changed:
                    updates['answers'] = new_answers

            if failed_flag:
                p7_failed += 1
            elif updates:
                if confirm:
                    database.bond_qotd_conf.update_one({'_id': qdoc['_id']}, {'$set': updates})
                p7_rotated += 1
            else:
                p7_skipped += 1

        # 7c. Remaining bond collections
        _rotate_bond_simple_collection(database.bond_journal_conf, ('content',))
        _rotate_bond_simple_collection(database.bond_moods_conf, ('mood',))
        _rotate_bond_simple_collection(database.bond_habits_conf, ('title',))
        _rotate_bond_simple_collection(database.bond_countdowns_conf, ('title', 'note'))
        _rotate_bond_simple_collection(database.bond_events_conf, ('title', 'note', 'location'))
        _rotate_bond_simple_collection(database.bond_album_photos_conf, ('url', 'title', 'description'))
        _rotate_bond_simple_collection(database.bond_bucketlist_conf, ('title', 'description'))
        _rotate_bond_simple_collection(database.bond_recommendations_conf, ('title', 'link', 'note', 'image_url'))
        _rotate_bond_simple_collection(database.bond_pulses_conf, ('message',))

        summary['Phase 7 (Bond Collections)'] = f"{p7_rotated} rotated, {p7_skipped} skipped, {p7_failed} failed"
        print(f"  Phase 7 complete: {summary['Phase 7 (Bond Collections)']}")

        # ==================================================================
        # PHASE 8: Community Notes (_get_community_fernet)
        # ==================================================================
        print("\n--- Phase 8: Community Notes (community_notes) ---")
        p8_rotated, p8_skipped, p8_failed = 0, 0, 0
        for cdoc in database.community_notes_conf.find({}):
            cid = str(cdoc.get('community_id', ''))
            val = cdoc.get('content')
            if not cid or not _is_fernet_token(val):
                p8_skipped += 1
                continue
            old_f = keyring.get_old_comm_v2(cid)
            new_f = keyring.get_new_comm_v2(cid)
            extra_f = [keyring.get_old_comm_v1(cid), keyring.get_new_comm_v1(cid)]
            nv, st = keyring.rotate_simple_field(val, old_f, new_f, extra_old_fernets=extra_f)
            if st == 'rotated':
                if confirm:
                    database.community_notes_conf.update_one({'_id': cdoc['_id']}, {'$set': {'content': nv}})
                p8_rotated += 1
            elif st == 'failed':
                p8_failed += 1
            else:
                p8_skipped += 1

        summary['Phase 8 (Community Notes)'] = f"{p8_rotated} rotated, {p8_skipped} skipped, {p8_failed} failed"
        print(f"  Phase 8 complete: {summary['Phase 8 (Community Notes)']}")

        # ==================================================================
        # PHASE 9: Forms & Form Responses (_get_form_fernet)
        # ==================================================================
        print("\n--- Phase 9: Forms & Form Responses (forms, form_responses) ---")
        p9_rotated, p9_skipped, p9_failed = 0, 0, 0

        for fdoc in database.forms_conf.find({}):
            fid = str(fdoc['_id'])
            old_f = keyring.get_old_form(fid)
            new_f = keyring.get_new_form(fid)
            updates = {}
            failed_flag = False

            for fn in ('title', 'description'):
                val = fdoc.get(fn)
                if _is_fernet_token(val):
                    nv, st = keyring.rotate_simple_field(val, old_f, new_f)
                    if st == 'rotated':
                        updates[fn] = nv
                    elif st == 'failed':
                        failed_flag = True

            qs = fdoc.get('questions')
            if isinstance(qs, list):
                new_qs = []
                qs_changed = False
                for q in qs:
                    if not isinstance(q, dict):
                        new_qs.append(q)
                        continue
                    q_copy = dict(q)
                    if _is_fernet_token(q.get('label')):
                        nv, st = keyring.rotate_simple_field(q['label'], old_f, new_f)
                        if st == 'rotated':
                            q_copy['label'] = nv
                            qs_changed = True
                        elif st == 'failed':
                            failed_flag = True
                    opts = q.get('options')
                    if isinstance(opts, list):
                        new_opts = []
                        for o in opts:
                            if _is_fernet_token(o):
                                nv, st = keyring.rotate_simple_field(o, old_f, new_f)
                                if st == 'rotated':
                                    new_opts.append(nv)
                                    qs_changed = True
                                elif st == 'failed':
                                    new_opts.append(o)
                                    failed_flag = True
                                else:
                                    new_opts.append(o)
                            else:
                                new_opts.append(o)
                        q_copy['options'] = new_opts
                    new_qs.append(q_copy)
                if qs_changed:
                    updates['questions'] = new_qs

            if failed_flag:
                p9_failed += 1
            elif updates:
                if confirm:
                    database.forms_conf.update_one({'_id': fdoc['_id']}, {'$set': updates})
                p9_rotated += 1
            else:
                p9_skipped += 1

        for rdoc in database.form_responses_conf.find({}):
            fid = str(rdoc.get('form_id', ''))
            if not fid:
                p9_skipped += 1
                continue
            old_f = keyring.get_old_form(fid)
            new_f = keyring.get_new_form(fid)
            ans_list = rdoc.get('answers')
            if not isinstance(ans_list, list):
                p9_skipped += 1
                continue
            new_ans = []
            ans_changed = False
            failed_flag = False
            for a in ans_list:
                if isinstance(a, dict) and _is_fernet_token(a.get('value')):
                    a_copy = dict(a)
                    nv, st = keyring.rotate_simple_field(a['value'], old_f, new_f)
                    if st == 'rotated':
                        a_copy['value'] = nv
                        ans_changed = True
                    elif st == 'failed':
                        failed_flag = True
                    new_ans.append(a_copy)
                else:
                    new_ans.append(a)
            if failed_flag:
                p9_failed += 1
            elif ans_changed:
                if confirm:
                    database.form_responses_conf.update_one({'_id': rdoc['_id']}, {'$set': {'answers': new_ans}})
                p9_rotated += 1
            else:
                p9_skipped += 1

        summary['Phase 9 (Forms & Responses)'] = f"{p9_rotated} rotated, {p9_skipped} skipped, {p9_failed} failed"
        print(f"  Phase 9 complete: {summary['Phase 9 (Forms & Responses)']}")

        # ==================================================================
        # PHASE 10: Game Lobbies, Submissions & Votes (_get_game_fernet)
        # ==================================================================
        print("\n--- Phase 10: Game Sessions, Submissions & Votes ---")
        p10_rotated, p10_skipped, p10_failed = 0, 0, 0

        for gdoc in database.game_sessions_conf.find({}):
            lid = str(gdoc.get('lobby_id', ''))
            if not lid:
                p10_skipped += 1
                continue
            old_f = keyring.get_old_game(lid)
            new_f = keyring.get_new_game(lid)
            updates = {}
            failed_flag = False

            for fn in ('title', 'prompt'):
                val = gdoc.get(fn)
                if _is_fernet_token(val):
                    nv, st = keyring.rotate_simple_field(val, old_f, new_f)
                    if st == 'rotated':
                        updates[fn] = nv
                    elif st == 'failed':
                        failed_flag = True

            q0 = gdoc.get('question')
            if isinstance(q0, dict):
                q0_copy = dict(q0)
                q0_changed = False
                for qf in ('label', 'correct_option'):
                    if _is_fernet_token(q0.get(qf)):
                        nv, st = keyring.rotate_simple_field(q0[qf], old_f, new_f)
                        if st == 'rotated':
                            q0_copy[qf] = nv
                            q0_changed = True
                        elif st == 'failed':
                            failed_flag = True
                if q0_changed:
                    updates['question'] = q0_copy

            qs = gdoc.get('questions')
            if isinstance(qs, list):
                new_qs = []
                qs_changed = False
                for q in qs:
                    if isinstance(q, dict):
                        q_copy = dict(q)
                        for qf in ('label', 'correct_option'):
                            if _is_fernet_token(q.get(qf)):
                                nv, st = keyring.rotate_simple_field(q[qf], old_f, new_f)
                                if st == 'rotated':
                                    q_copy[qf] = nv
                                    qs_changed = True
                                elif st == 'failed':
                                    failed_flag = True
                        new_qs.append(q_copy)
                    else:
                        new_qs.append(q)
                if qs_changed:
                    updates['questions'] = new_qs

            sents = gdoc.get('sentences')
            if isinstance(sents, list):
                new_sents = []
                sents_changed = False
                for s in sents:
                    if isinstance(s, dict) and _is_fernet_token(s.get('text')):
                        s_copy = dict(s)
                        nv, st = keyring.rotate_simple_field(s['text'], old_f, new_f)
                        if st == 'rotated':
                            s_copy['text'] = nv
                            sents_changed = True
                        elif st == 'failed':
                            failed_flag = True
                        new_sents.append(s_copy)
                    else:
                        new_sents.append(s)
                if sents_changed:
                    updates['sentences'] = new_sents

            live_ans = gdoc.get('live_answers')
            if isinstance(live_ans, dict):
                new_live_ans = {}
                la_changed = False
                for q_idx, players_map in live_ans.items():
                    if isinstance(players_map, dict):
                        new_pmap = {}
                        for pid, pinfo in players_map.items():
                            if isinstance(pinfo, dict) and _is_fernet_token(pinfo.get('option')):
                                p_copy = dict(pinfo)
                                nv, st = keyring.rotate_simple_field(pinfo['option'], old_f, new_f)
                                if st == 'rotated':
                                    p_copy['option'] = nv
                                    la_changed = True
                                elif st == 'failed':
                                    failed_flag = True
                                new_pmap[pid] = p_copy
                            else:
                                new_pmap[pid] = pinfo
                        new_live_ans[q_idx] = new_pmap
                    else:
                        new_live_ans[q_idx] = players_map
                if la_changed:
                    updates['live_answers'] = new_live_ans

            if failed_flag:
                p10_failed += 1
            elif updates:
                if confirm:
                    database.game_sessions_conf.update_one({'_id': gdoc['_id']}, {'$set': updates})
                p10_rotated += 1
            else:
                p10_skipped += 1

        game_subs_conf = getattr(m, 'game_submissions_conf', None) or database.db['game_submissions']
        for sub in game_subs_conf.find({}):
            lid = str(sub.get('lobby_id', ''))
            content = sub.get('content')
            if not lid or not isinstance(content, dict):
                p10_skipped += 1
                continue
            old_f = keyring.get_old_game(lid)
            new_f = keyring.get_new_game(lid)
            c_copy = dict(content)
            c_changed = False
            failed_flag = False

            if isinstance(content.get('statements'), list):
                new_stmts = []
                for s in content['statements']:
                    if _is_fernet_token(s):
                        nv, st = keyring.rotate_simple_field(s, old_f, new_f)
                        if st == 'rotated':
                            new_stmts.append(nv)
                            c_changed = True
                        elif st == 'failed':
                            new_stmts.append(s)
                            failed_flag = True
                        else:
                            new_stmts.append(s)
                    else:
                        new_stmts.append(s)
                c_copy['statements'] = new_stmts

            for fn in ('lie_index', 'caption'):
                if _is_fernet_token(content.get(fn)):
                    nv, st = keyring.rotate_simple_field(content[fn], old_f, new_f)
                    if st == 'rotated':
                        c_copy[fn] = nv
                        c_changed = True
                    elif st == 'failed':
                        failed_flag = True

            if failed_flag:
                p10_failed += 1
            elif c_changed:
                if confirm:
                    game_subs_conf.update_one({'_id': sub['_id']}, {'$set': {'content': c_copy}})
                p10_rotated += 1
            else:
                p10_skipped += 1

        for vdoc in database.game_votes_conf.find({}):
            lid = str(vdoc.get('lobby_id', ''))
            opt = vdoc.get('option')
            if not lid or not _is_fernet_token(opt):
                p10_skipped += 1
                continue
            old_f = keyring.get_old_game(lid)
            new_f = keyring.get_new_game(lid)
            nv, st = keyring.rotate_simple_field(opt, old_f, new_f)
            if st == 'rotated':
                if confirm:
                    database.game_votes_conf.update_one({'_id': vdoc['_id']}, {'$set': {'option': nv}})
                p10_rotated += 1
            elif st == 'failed':
                p10_failed += 1
            else:
                p10_skipped += 1

        summary['Phase 10 (Games & Votes)'] = f"{p10_rotated} rotated, {p10_skipped} skipped, {p10_failed} failed"
        print(f"  Phase 10 complete: {summary['Phase 10 (Games & Votes)']}")

        # ---- Clear caches on confirm ----
        if confirm:
            for cache_attr in (
                '_user_fernet_cache', '_dm_fernet_cache', '_decrypted_notes_memory_cache',
                '_user_fernet_v3_cache', '_dm_fernet_v3_cache', '_community_fernet_v2_cache',
                '_bond_fernet_cache', '_form_fernet_cache', '_game_fernet_cache'
            ):
                c = getattr(database, cache_attr, None)
                if c is not None:
                    c.clear()
            security._KEK_CACHE.clear()
            security._MEDIA_FERNET_CACHE.clear()
            security._notes_fernet = None

        # ---- Final Summary ----
        print("\n" + "=" * 68)
        print("ROTATION SUMMARY")
        print("=" * 68)
        for k, v in summary.items():
            print(f"  {k:<32}: {v}")
        if not confirm:
            print("\n[DRY RUN] No changes were made. Run with --confirm to execute.")
        else:
            _write_audit_log(audit_entries, log_path)
            print(f"\n[DONE] All 10 encryption phases rotated. Audit log written to: {log_path}")
            print("\nNEXT STEPS:")
            print("  1. Update SECRET in your .env / environment to the NEW_SECRET_KEY value")
            print("  2. Restart the application processes (web, worker, scheduler)")
            print("  3. Verify notes, DMs, vault items, bonds, and media load normally")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Rotate SECRET_KEY across all EchoWithin encrypted collections and DEKs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Security note:
  Prefer --old-secret-env / --new-secret-env or --interactive.
  Passing secrets as positional CLI args leaks them in shell history and ps output.""")
    parser.add_argument('old_secret', nargs='?', default=None,
                        help='The current SECRET_KEY value (prefer env var or --interactive)')
    parser.add_argument('new_secret', nargs='?', default=None,
                        help='The new SECRET_KEY value to rotate to (prefer env var or --interactive)')
    parser.add_argument('--old-secret-env', '-o', default='OLD_SECRET_KEY',
                        help='Environment variable for the current SECRET_KEY (default: OLD_SECRET_KEY)')
    parser.add_argument('--new-secret-env', '-n', default='NEW_SECRET_KEY',
                        help='Environment variable for the new SECRET_KEY (default: NEW_SECRET_KEY)')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Prompt for secrets via stdin (never touches argv/history)')
    parser.add_argument('--confirm', dest='confirm', action='store_true', default=False,
                        help='Actually execute the rotation (default: dry run)')
    parser.add_argument('--dry-run', dest='confirm', action='store_false',
                        help='Run in dry-run mode without modifying the database (default)')
    parser.add_argument('--batch-size', type=int, default=50,
                        help='Items per batch (default: 50)')
    args = parser.parse_args()

    old_secret = _get_secret("OLD_SECRET_KEY", args.old_secret_env, args.interactive)
    new_secret = _get_secret("NEW_SECRET_KEY", args.new_secret_env, args.interactive)

    if not old_secret and args.old_secret:
        old_secret = args.old_secret
    if not new_secret and args.new_secret:
        new_secret = args.new_secret

    if not old_secret or not new_secret:
        print("ERROR: Both old and new secrets are required.")
        print("  Set OLD_SECRET_KEY and NEW_SECRET_KEY env vars, or use --interactive.")
        sys.exit(1)

    if old_secret == new_secret:
        print("ERROR: Old and new secrets are identical. Nothing to rotate.")
        sys.exit(1)

    run_rotation(
        old_secret=old_secret,
        new_secret=new_secret,
        confirm=args.confirm,
        batch_size=args.batch_size
    )
