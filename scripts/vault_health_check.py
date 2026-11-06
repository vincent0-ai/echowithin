#!/usr/bin/env python3
"""Vault Transit health check and pending-DEK migration.

Called periodically by the scheduler (every 2 minutes).

Lightweight probe:
- Routine checks only use key_management directly (no Flask/Firebase/Typesense import).
- Fast execution (~50ms) with zero greenlet/gevent cleanup side-effects.
- Persists outage state via a temp flag file so admin alerts fire once per outage,
  and recovery migration is triggered automatically when Vault comes back up.
"""

import os
import sys
import tempfile
import requests

# Ensure the app root is on the path so imports resolve.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import key_management

FLAG_FILE = os.path.join(tempfile.gettempdir(), 'echowithin_vault_outage.flag')


def _send_ntfy(message: str, title: str, tags: str = ""):
    """Send an ntfy notification directly via requests without Flask/RQ overhead."""
    topic = os.environ.get('NTFY_TOPIC', '').strip()
    if not topic:
        return
    headers = {}
    if title:
        headers['Title'] = title
    if tags:
        headers['Tags'] = tags
    user = os.environ.get('NTFY_USERNAME', '').strip()
    password = os.environ.get('NTFY_PASSWORD', '').strip()
    auth = (user, password) if user and password else None
    try:
        requests.post(
            f"https://ntfy.sh/{topic}",
            data=message.encode('utf-8'),
            headers=headers,
            auth=auth,
            timeout=5,
        )
    except Exception as e:
        print(f"Failed to send ntfy notification: {e}")


def _run_recovery_migration():
    """Boot Flask context only on recovery to migrate pending-vault DEKs."""
    try:
        from main import app
        with app.app_context():
            from security import migrate_pending_vault_deks
            counts = migrate_pending_vault_deks()
            if counts:
                summary = ', '.join(f'{k}: {v}' for k, v in counts.items())
                msg = f'Vault recovered. Migrated DEKs: {summary}'
                print(msg)
                _send_ntfy(msg, 'Vault Transit Recovered', 'white_check_mark')
            else:
                print('No pending-vault DEKs to migrate.')
                _send_ntfy(
                    'Vault Transit is back online. No pending DEKs needed migration.',
                    'Vault Transit Recovered',
                    'white_check_mark',
                )
    except Exception as e:
        print(f'Error during recovery migration: {e}')


def main():
    if not key_management.transit_enabled():
        return 0

    healthy = key_management.verify_transit()

    if healthy:
        print('Vault Transit health: OK')
        if os.path.exists(FLAG_FILE):
            print('Vault recovered from previous outage. Running migration...')
            try:
                os.remove(FLAG_FILE)
            except OSError:
                pass
            _run_recovery_migration()
        return 0

    # Vault is down
    print('Vault Transit health: DOWN')
    if not os.path.exists(FLAG_FILE):
        try:
            with open(FLAG_FILE, 'w') as f:
                f.write('down')
        except OSError:
            pass
        _send_ntfy(
            'Vault Transit is unreachable. New DEKs are being wrapped '
            'with the local KEK fallback. They will be migrated '
            'automatically once Vault recovers. Check VAULT_ADDR / '
            'VAULT_TOKEN configuration.',
            'Vault Transit DOWN',
            'rotating_light,warning',
        )
        print('Admin notification sent.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
