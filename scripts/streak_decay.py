#!/usr/bin/env python3
"""
Daily streak decay job.

Resets streak_count to 0 for bonds where the last_streak_date is more than
1 day behind today (UTC). For bonds with exactly a 1-day gap, saves the
previous streak info so the streak shield can recover it during the same day.

Runs daily at 02:00 UTC via scheduler.py.
"""

import sys
import os
import datetime

# Add parent directory to path so we can import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run():
    import main as m

    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()
    # Any bond whose last_streak_date is before yesterday 00:00 UTC has a broken streak
    yesterday_start = datetime.datetime.combine(
        today - datetime.timedelta(days=1),
        datetime.time.min,
        tzinfo=datetime.timezone.utc
    )
    # Bonds with exactly 1 day missed (last_streak_date was 2 days ago) can
    # still be recovered by a shield, so we save prev_streak for those.
    two_days_ago_start = datetime.datetime.combine(
        today - datetime.timedelta(days=2),
        datetime.time.min,
        tzinfo=datetime.timezone.utc
    )

    # Phase 1: Bonds with exactly 1 day missed — save prev_streak before reset
    recoverable = list(m.bonds_conf.find({
        'status': 'active',
        'streak_count': {'$gt': 0},
        'last_streak_date': {
            '$gte': two_days_ago_start,
            '$lt': yesterday_start
        }
    }))

    for bond in recoverable:
        m.bonds_conf.update_one(
            {'_id': bond['_id']},
            {'$set': {
                'streak_count': 0,
                'prev_streak': {
                    'count': bond['streak_count'],
                    'last_date': bond.get('last_streak_date'),
                    'reset_at': now,
                }
            }}
        )

    # Phase 2: Bonds with >1 day missed — no recovery possible, just reset
    result = m.bonds_conf.update_many(
        {
            'status': 'active',
            'streak_count': {'$gt': 0},
            'last_streak_date': {'$lt': two_days_ago_start}
        },
        {
            '$set': {'streak_count': 0}
        }
    )

    total_reset = len(recoverable) + result.modified_count
    print(f"[streak_decay] {now.isoformat()} — Reset {total_reset} stale streaks "
          f"({len(recoverable)} recoverable, {result.modified_count} expired, "
          f"cutoff: {yesterday_start.isoformat()})")


if __name__ == '__main__':
    run()

