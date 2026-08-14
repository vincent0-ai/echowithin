#!/usr/bin/env python3
"""
Bond Anniversary Check — sends push notifications for milestone bond ages.

Runs daily via scheduler.py. Checks all active bonds and sends a push
notification to both participants when they hit milestone days.

Milestones: 7, 14, 30, 50, 100, 150, 200, 365, 500, 730 (2yr), 1000, 1095 (3yr)
"""

import sys
import os
import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


MILESTONE_DAYS = {7, 14, 30, 50, 100, 150, 200, 365, 500, 730, 1000, 1095}

MILESTONE_LABELS = {
    7: '1 week',
    14: '2 weeks',
    30: '1 month',
    50: '50 days',
    100: '100 days',
    150: '150 days',
    200: '200 days',
    365: '1 year',
    500: '500 days',
    730: '2 years',
    1000: '1000 days',
    1095: '3 years',
}


def run_anniversary_check():
    """Check active bonds for milestone anniversaries and send push notifications."""
    # Lazy imports to avoid loading the full app at module level
    import main as m

    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()

    # Find all active bonds
    active_bonds = m.bonds_conf.find({'status': 'active'})

    notified = 0
    for bond in active_bonds:
        created_at = bond.get('created_at')
        if not created_at:
            continue

        if isinstance(created_at, datetime.datetime):
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=datetime.timezone.utc)
            bond_start = created_at.date()
        else:
            bond_start = created_at

        days_active = (today - bond_start).days
        if days_active not in MILESTONE_DAYS:
            continue

        label = MILESTONE_LABELS.get(days_active, f'{days_active} days')
        bond_id = str(bond['_id'])

        # Check we haven't already notified for this milestone
        already_notified = m.bonds_conf.find_one({
            '_id': bond['_id'],
            'anniversary_notified': {'$elemMatch': {'days': days_active}}
        })
        if already_notified:
            continue

        # Get both participants
        user1_id = str(bond.get('user1_id', ''))
        user2_id = str(bond.get('user2_id', ''))
        if not user1_id or not user2_id:
            continue

        user1 = m.users_conf.find_one({'_id': bond['user1_id']}, {'username': 1})
        user2 = m.users_conf.find_one({'_id': bond['user2_id']}, {'username': 1})
        if not user1 or not user2:
            continue

        user1_name = user1.get('username', 'Partner')
        user2_name = user2.get('username', 'Partner')

        # Send push to both
        try:
            m.send_push_notification_to_user(
                user1_id,
                f'Bond milestone: {label} with {user2_name}',
                'Your bond keeps growing stronger.',
                url=m.url_for('bonds.bonds_page', _external=True),
                tag=f'bond-anniversary-{bond_id}'
            )
            m.send_push_notification_to_user(
                user2_id,
                f'Bond milestone: {label} with {user1_name}',
                'Your bond keeps growing stronger.',
                url=m.url_for('bonds.bonds_page', _external=True),
                tag=f'bond-anniversary-{bond_id}'
            )
            notified += 1
        except Exception as e:
            print(f"Push error for bond {bond_id}: {e}")
            continue

        # Record that we notified for this milestone
        m.bonds_conf.update_one(
            {'_id': bond['_id']},
            {'$push': {'anniversary_notified': {
                'days': days_active,
                'label': label,
                'at': now
            }}}
        )

    print(f"Anniversary check complete: {notified} bonds notified")


if __name__ == '__main__':
    run_anniversary_check()
