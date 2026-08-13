#!/usr/bin/env python3
"""
Daily streak decay job.

Resets streak_count to 0 for bonds where the last_streak_date is more than
1 day behind today (UTC). This keeps the database clean so queries like
"bonds with active streaks" work without needing _get_effective_streak()
at query time.

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
    # Any bond whose last_streak_date is before yesterday 00:00 UTC has a broken streak
    yesterday_start = datetime.datetime.combine(
        now.date() - datetime.timedelta(days=1),
        datetime.time.min,
        tzinfo=datetime.timezone.utc
    )

    result = m.bonds_conf.update_many(
        {
            'status': 'active',
            'streak_count': {'$gt': 0},
            'last_streak_date': {'$lt': yesterday_start}
        },
        {
            '$set': {'streak_count': 0}
        }
    )

    print(f"[streak_decay] {now.isoformat()} — Reset {result.modified_count} stale streaks "
          f"(matched {result.matched_count}, cutoff: {yesterday_start.isoformat()})")


if __name__ == '__main__':
    run()
