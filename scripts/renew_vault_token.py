#!/usr/bin/env python3
"""Renew the Vault token used for at-rest key custody.

Run periodically (the scheduler does) so a long-running token never silently
expires and turns into a write outage. Best-effort: it never touches secrets and
reports clearly when Vault is unset, unreachable, or the token is non-renewable.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

import key_management


def main():
    if not key_management.vault_configured():
        print('Vault not configured; nothing to renew.')
        return 0

    try:
        status = key_management.token_status()
        if status:
            print(f"Vault token status: ttl={status.get('ttl')}s "
                  f"renewable={status.get('renewable')} policies={status.get('policies')}")
    except Exception as e:
        print(f'Could not read Vault token status: {e}')

    if not key_management.transit_enabled() and not os.environ.get('VAULT_MASTER_KEY_PATH', '').strip():
        print('Vault is configured but no Transit key / KV path is set; skipping renewal.')
        return 0

    ttl = key_management.renew_self_token()
    if ttl is None:
        print('Vault token renewal did not succeed (see logs). Re-issue VAULT_TOKEN if this repeats.')
        return 1

    print(f'Vault token renewed; new TTL ~{ttl}s.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
