#!/usr/bin/env python3
"""
This script cleans up expired authentication records from the auth collection.
It removes:
  - Expired email verification codes (code_expiry < now)
  - Expired password reset tokens (reset_expiry < now)

It is intended to be run hourly by the scheduler.py script.
"""

import os
import sys
import datetime

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project root to the Python path to allow imports from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, auth_conf


def cleanup_expired_auth():
    """Removes expired verification codes and password reset tokens."""
    with app.app_context():
        now = datetime.datetime.now(datetime.timezone.utc)
        now_naive = datetime.datetime.now()  # For records stored without timezone

        # Delete expired email verification codes
        result_codes = auth_conf.delete_many({
            'code_expiry': {'$exists': True, '$lt': now_naive}
        })

        # Delete expired password reset tokens
        result_tokens = auth_conf.delete_many({
            'reset_expiry': {'$exists': True, '$lt': now}
        })

        total_deleted = result_codes.deleted_count + result_tokens.deleted_count
        if total_deleted > 0:
            app.logger.info(
                f"Auth cleanup: removed {result_codes.deleted_count} expired verification codes "
                f"and {result_tokens.deleted_count} expired reset tokens."
            )
        else:
            app.logger.debug("Auth cleanup: no expired records found.")


if __name__ == '__main__':
    cleanup_expired_auth()
