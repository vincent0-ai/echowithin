# -*- coding: utf-8 -*-
"""One-time backfill: count untallied matches into the bonds leaderboard.

Finds finished 1v1 matches in ``game_match_history`` that have no ``bond_id``
and, when both players are members of an *active* bond, replays the result
into ``bond_h2h_records`` (win/loss/draw counts + last_played_at) and stamps
the match doc with the detected ``bond_id``.

Idempotent: a match doc once stamped with a bond_id is never touched again,
and re-running only processes docs where ``bond_id`` is falsy.

Dry-run by default — nothing is written unless ``--apply`` is passed.

Usage (from the project root):
    python scripts/backfill_bond_h2h.py            # preview only
    python scripts/backfill_bond_h2h.py --apply    # actually write

Requires the same environment variables the app uses (MONGODB_CONNECTION);
secrets are read strictly from the environment, never hardcoded.
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bson.objectid import ObjectId  # noqa: E402
from pymongo import MongoClient  # noqa: E402

try:
    from dotenv import load_dotenv  # noqa: E402
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))
except ImportError:
    pass


def get_conn_str():
    conn = os.environ.get('MONGODB_CONNECTION')
    if not conn:
        print("ERROR: MONGODB_CONNECTION is not set in the environment.")
        sys.exit(1)
    return conn


def main():
    parser = argparse.ArgumentParser(description='Backfill bond H2H leaderboard from match history.')
    parser.add_argument('--apply', action='store_true',
                        help='Write changes to the database (default: dry run).')
    args = parser.parse_args()

    client = MongoClient(get_conn_str(), serverSelectionTimeoutMS=5000)
    db = client['echowithin_db']
    matches = db['game_match_history']
    bonds = db['bonds']
    h2h = db['bond_h2h_records']

    # Restrict to games the app tracks (mirrors GAMES_WITH_MATCH_TRACKING)
    tracked_games = {'tic_tac_toe', 'connect_four', 'dots_and_boxes', 'ping_pong',
                     'slime_volleyball', 'gomoku', 'whack_a_mole', 'air_hockey'}

    # Matches where auto-detection never ran (legacy) or found no bond.
    cursor = matches.find(
        {'$or': [{'bond_id': None}, {'bond_id': {'$exists': False}}],
         'game': {'$in': list(tracked_games)},
         'players': {'$exists': True}}
    )

    scanned = matched = updated_h2h = 0
    for m in cursor:
        scanned += 1
        players = m.get('players') or []
        if len(players) < 2 or not all(p.get('user_id') for p in players):
            continue
        p1, p2 = players[0]['user_id'], players[1]['user_id']
        if p1 == p2:
            continue
        try:
            p1_oid, p2_oid = ObjectId(p1), ObjectId(p2)
        except Exception:
            continue

        # Skip self-play (same user listed twice under different names)
        # and matches that already went through auto-detect without a bond.
        if m.get('metadata', {}).get('bond_auto_detect_attempted'):
            continue

        bond = bonds.find_one({
            'status': 'active',
            '$or': [
                {'user_a_id': p1_oid, 'user_b_id': p2_oid},
                {'user_a_id': p2_oid, 'user_b_id': p1_oid}
            ]
        }, {'_id': 1})
        if not bond:
            # Mark so we never re-scan this doc on future runs.
            if args.apply:
                matches.update_one({'_id': m['_id']},
                                   {'$set': {'metadata.bond_auto_detect_attempted': True}})
            continue

        matched += 1
        bond_oid = bond['_id']
        game = m['game']
        winner_id = m.get('winner_id')
        now_utc = datetime.datetime.now(datetime.timezone.utc)

        print(f"  [{'+'.join(p.get('username', '?') for p in players)}] "
              f"{game} winner={winner_id or 'draw'} -> bond {bond_oid}")

        if args.apply:
            existing = h2h.find_one({'bond_id': bond_oid, 'game': game})
            if not existing:
                h2h.insert_one({
                    'bond_id': bond_oid,
                    'game': game,
                    'user_a_id': p1,
                    'user_b_id': p2,
                    'user_a_wins': 1 if winner_id == p1 else 0,
                    'user_b_wins': 1 if winner_id == p2 else 0,
                    'draws': 1 if not winner_id else 0,
                    'total_matches': 1,
                    'last_played_at': now_utc,
                    'backfilled': True,
                })
            else:
                inc = {'total_matches': 1}
                if not winner_id:
                    inc['draws'] = 1
                elif winner_id == str(existing.get('user_a_id', '')):
                    inc['user_a_wins'] = 1
                else:
                    inc['user_b_wins'] = 1
                h2h.update_one({'_id': existing['_id']},
                               {'$inc': inc, '$set': {'last_played_at': now_utc}})
            updated_h2h += 1
            # Stamp the match so a rerun is a no-op (idempotency guarantee).
            matches.update_one(
                {'_id': m['_id'], 'bond_id': None},
                {'$set': {'bond_id': str(bond_oid),
                          'bond_id_backfilled': True,
                          'metadata.bond_auto_detect_attempted': True}}
            )

    print()
    mode = 'APPLIED' if args.apply else 'DRY RUN (nothing written)'
    print(f"{mode}: scanned={scanned} bond_matches_found={matched} "
          f"h2h_updates={updated_h2h if args.apply else 0}")


if __name__ == '__main__':
    main()
