#!/usr/bin/env python3
"""Vault Transit health check and pending-DEK migration.

Called periodically by the scheduler. Probes Vault Transit, sends an admin
ntfy notification on outage detection, and triggers DEK migration when Vault
recovers from a previous outage.
"""

import os
import sys

# Ensure the app root is on the path so imports resolve.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app  # noqa: E402 — bootstraps Flask + extensions

with app.app_context():
    from key_management import (
        transit_enabled, check_vault_health, is_vault_healthy,
        should_notify_admin, mark_vault_up,
    )
    from security import migrate_pending_vault_deks

    if not transit_enabled():
        print('Vault Transit not configured — nothing to check.')
        sys.exit(0)

    was_down_before = not is_vault_healthy()
    healthy = check_vault_health()

    if healthy:
        print('Vault Transit health: OK')

        # If this is a recovery from a previous outage, run DEK migration.
        if was_down_before:
            print('Vault recovered — migrating pending-vault DEKs...')
            try:
                counts = migrate_pending_vault_deks()
                if counts:
                    summary = ', '.join(f'{k}: {v}' for k, v in counts.items())
                    msg = f'Vault recovered. Migrated DEKs: {summary}'
                    print(msg)
                    # Send recovery notification
                    try:
                        from notifications import send_ntfy_notification
                        send_ntfy_notification.queue(
                            msg,
                            'Vault Transit Recovered',
                            'white_check_mark',
                        )
                    except Exception as e:
                        app.logger.warning(f'Could not send recovery ntfy: {e}')
                else:
                    print('No pending-vault DEKs to migrate.')
                    try:
                        from notifications import send_ntfy_notification
                        send_ntfy_notification.queue(
                            'Vault Transit is back online. No pending DEKs needed migration.',
                            'Vault Transit Recovered',
                            'white_check_mark',
                        )
                    except Exception as e:
                        app.logger.warning(f'Could not send recovery ntfy: {e}')
            except Exception as e:
                app.logger.error(f'DEK migration after Vault recovery failed: {e}')
    else:
        print('Vault Transit health: DOWN')

        # Fire the admin notification exactly once per outage window.
        if should_notify_admin():
            try:
                from notifications import send_ntfy_notification
                send_ntfy_notification.queue(
                    'Vault Transit is unreachable. New DEKs are being wrapped '
                    'with the local KEK fallback. They will be migrated '
                    'automatically once Vault recovers. Check VAULT_ADDR / '
                    'VAULT_TOKEN configuration.',
                    'Vault Transit DOWN',
                    'rotating_light,warning',
                )
                print('Admin notification sent.')
            except Exception as e:
                app.logger.error(f'Could not send Vault-down ntfy: {e}')
