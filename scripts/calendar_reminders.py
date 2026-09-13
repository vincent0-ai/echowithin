#!/usr/bin/env python3
"""
Calendar Event Reminders Check — sends push notifications before upcoming bond calendar events.

Runs periodically via scheduler.py. Checks active calendar events with a configured
reminder_offset and sends push notifications to bond participants when the reminder window opens.
"""

import sys
import os
import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_app_url():
    """Returns the app's base URL."""
    if os.environ.get('APP_URL'):
        return os.environ['APP_URL']
    mongo_conn = os.environ.get('MONGODB_CONNECTION', '')
    redis_host = os.environ.get('REDIS_HOST', '')
    if 'localhost' in mongo_conn or '127.0.0.1' in mongo_conn or 'localhost' in redis_host:
        return 'http://localhost:8000'
    return 'https://echowithin.xyz'



def _get_candidate_occurrence_dates(start_date, recurrence, today, max_end=None):
    """
    Get candidate occurrence dates around today (within -1 to +7 days) for recurrence checks.
    """
    candidates = []
    if recurrence == 'none':
        candidates.append(start_date)
        return candidates

    check_window_start = today - datetime.timedelta(days=1)
    check_window_end = today + datetime.timedelta(days=7)

    if recurrence == 'weekly':
        # Check weekly steps
        cur = start_date
        while cur <= check_window_end:
            if max_end and cur > max_end:
                break
            if cur >= check_window_start:
                candidates.append(cur)
            cur += datetime.timedelta(days=7)
    elif recurrence == 'monthly':
        cur = start_date
        while cur <= check_window_end:
            if max_end and cur > max_end:
                break
            if cur >= check_window_start:
                candidates.append(cur)
            # Advance one month
            y = cur.year + (cur.month // 12)
            m = (cur.month % 12) + 1
            import calendar as py_cal
            max_day = py_cal.monthrange(y, m)[1]
            cur = datetime.date(y, m, min(start_date.day, max_day))
    elif recurrence == 'yearly':
        for yr in (check_window_start.year, check_window_end.year):
            try:
                import calendar as py_cal
                max_day = py_cal.monthrange(yr, start_date.month)[1]
                cand = datetime.date(yr, start_date.month, min(start_date.day, max_day))
                if check_window_start <= cand <= check_window_end:
                    if not (max_end and cand > max_end):
                        candidates.append(cand)
            except Exception:
                pass
    else:
        candidates.append(start_date)

    return candidates


def check_and_dispatch_calendar_reminders(bonds_conf, bond_events_conf, decrypt_fn, push_fn, url_fn=None):
    """Core logic to inspect calendar events and dispatch due reminders."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    today = now_utc.date()

    # Pre-cache active bonds
    active_bonds = list(bonds_conf.find({'status': 'active'}))
    bonds_map = {b['_id']: b for b in active_bonds}

    events = list(bond_events_conf.find({
        'archived': {'$ne': True},
        'reminder_offset': {'$ne': None, '$exists': True}
    }))

    reminders_dispatched = 0

    for ev in events:
        bond = bonds_map.get(ev.get('bond_id'))
        if not bond:
            continue

        reminder_offset = ev.get('reminder_offset')
        if reminder_offset is None:
            continue

        try:
            reminder_offset = int(reminder_offset)
        except (ValueError, TypeError):
            continue

        s_date_raw = ev.get('start_date', '')
        try:
            if isinstance(s_date_raw, str):
                start_date = datetime.date.fromisoformat(s_date_raw[:10])
            elif isinstance(s_date_raw, datetime.datetime):
                start_date = s_date_raw.date()
            elif isinstance(s_date_raw, datetime.date):
                start_date = s_date_raw
            else:
                continue
        except Exception:
            continue

        e_date_raw = ev.get('end_date')
        max_end = None
        if e_date_raw:
            try:
                max_end = datetime.date.fromisoformat(str(e_date_raw)[:10])
            except Exception:
                pass

        recurrence = ev.get('recurrence', 'none')
        time_str = ev.get('time') or '09:00'
        try:
            time_parts = [int(p) for p in time_str.split(':')[:2]]
            ev_hour = time_parts[0]
            ev_minute = time_parts[1] if len(time_parts) > 1 else 0
        except Exception:
            ev_hour, ev_minute = 9, 0

        reminders_sent = set(ev.get('reminders_sent') or [])
        candidate_dates = _get_candidate_occurrence_dates(start_date, recurrence, today, max_end=max_end)

        for occ_date in candidate_dates:
            occ_key = f"{occ_date.isoformat()}_{reminder_offset}"
            if occ_key in reminders_sent:
                continue

            event_dt = datetime.datetime(
                occ_date.year, occ_date.month, occ_date.day,
                ev_hour, ev_minute, tzinfo=datetime.timezone.utc
            )
            target_reminder_dt = event_dt - datetime.timedelta(minutes=reminder_offset)

            # Fire if now_utc has reached target_reminder_dt and not older than 2 hours
            if target_reminder_dt <= now_utc <= (target_reminder_dt + datetime.timedelta(hours=2)):
                # Decrypt title
                bond_id_str = str(bond['_id'])
                if ev.get('encrypted') and decrypt_fn:
                    try:
                        title = decrypt_fn(ev.get('title', ''), bond_id_str)
                    except Exception:
                        title = ev.get('title', 'Calendar Event')
                else:
                    title = ev.get('title', 'Calendar Event')

                # Build readable reminder text
                if reminder_offset == 0:
                    offset_text = "is starting now"
                elif reminder_offset < 60:
                    offset_text = f"is in {reminder_offset} minutes"
                elif reminder_offset == 60:
                    offset_text = "is in 1 hour"
                elif reminder_offset < 1440:
                    offset_text = f"is in {reminder_offset // 60} hours"
                elif reminder_offset == 1440:
                    offset_text = "is tomorrow"
                else:
                    offset_text = f"is in {reminder_offset // 1440} days"

                body = f"'{title}' {offset_text} ({occ_date.isoformat()}{' at ' + time_str if ev.get('time') else ''})."

                rsvps = ev.get('rsvps') or {}
                user1_id = str(bond.get('user_a_id', ''))
                user2_id = str(bond.get('user_b_id', ''))

                sent_any = False
                bonds_url = '/bonds'
                if url_fn:
                    try:
                        bonds_url = url_fn('bonds.bonds_page', _external=True)
                    except Exception:
                        bonds_url = '/bonds'

                for uid in (user1_id, user2_id):
                    if not uid:
                        continue
                    if rsvps.get(uid) == 'declined':
                        continue
                    try:
                        push_fn(
                            uid,
                            f"Event Reminder: {title}",
                            body,
                            url=bonds_url,
                            tag=f"bond-cal-reminder-{ev['_id']}-{occ_date.isoformat()}",
                            category='calendar'
                        )
                        sent_any = True
                    except Exception as e:
                        print(f"Error sending calendar reminder to user {uid}: {e}")

                # Mark occurrence as notified in DB
                bond_events_conf.update_one(
                    {'_id': ev['_id']},
                    {'$push': {'reminders_sent': occ_key}}
                )
                reminders_sent.add(occ_key)
                if sent_any:
                    reminders_dispatched += 1

    return reminders_dispatched


def process_via_api():
    """Call the internal API endpoint on the web process.
    Ensures zero re-import overhead and no gevent monkey-patch shutdown conflicts.
    """
    secret_key = os.environ.get('SCHEDULER_SECRET')
    if not secret_key:
        return None

    app_url = get_app_url()
    try:
        response = requests.post(
            f"{app_url}/api/bonds/calendar/reminders/process",
            headers={
                'X-Scheduler-Secret': secret_key,
                'Content-Type': 'application/json'
            },
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return data.get('reminders_dispatched', 0)
        else:
            return None
    except Exception:
        return None


def run_calendar_reminders():
    """Check active calendar events and dispatch due push reminders."""
    # 1. First attempt to delegate to running web worker via internal API
    api_result = process_via_api()
    if api_result is not None:
        print(f"Calendar reminders check complete: {api_result} event reminders sent")
        return api_result

    # 2. Fallback: check if main is already imported (e.g. during tests or app runtime)
    if 'main' in sys.modules:
        m = sys.modules['main']
        count = check_and_dispatch_calendar_reminders(
            bonds_conf=m.bonds_conf,
            bond_events_conf=m.bond_events_conf,
            decrypt_fn=m.decrypt_bond_data,
            push_fn=m.send_push_notification_to_user,
            url_fn=getattr(m, 'url_for', None)
        )
        print(f"Calendar reminders check complete: {count} event reminders sent")
        return count

    # 3. Direct pymongo fallback (offline / standalone execution without importing main)
    try:
        from pymongo import MongoClient
        import security
        import notifications

        mongo_conn = os.environ.get('MONGODB_CONNECTION')
        if not mongo_conn:
            print("ERROR: MONGODB_CONNECTION not set for calendar reminders fallback")
            return 0

        client = MongoClient(mongo_conn, serverSelectionTimeoutMS=5000)
        db = client['echowithin_db']

        count = check_and_dispatch_calendar_reminders(
            bonds_conf=db['bonds'],
            bond_events_conf=db['bond_events'],
            decrypt_fn=security.decrypt_bond_data,
            push_fn=notifications.send_push_notification_to_user,
            url_fn=None
        )
        client.close()
        print(f"Calendar reminders check complete: {count} event reminders sent")
        return count
    except Exception as e:
        print(f"Error in direct calendar reminders check: {e}")
        return 0


if __name__ == '__main__':
    run_calendar_reminders()
