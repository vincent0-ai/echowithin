#!/usr/bin/env python3
"""
This script enqueues the weekly newsletter job to the RQ worker queue.
It is intended to be run by a scheduler like cron or the scheduler.py script.
"""

import os
import sys
import redis
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project root to the Python path to allow imports from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, send_weekly_newsletter


def enqueue_newsletter_job():
    """Enqueues the send_weekly_newsletter job to RQ."""
    with app.app_context():
        app.logger.info("Attempting to enqueue weekly newsletter job...")
        try:
            job = send_weekly_newsletter.queue()
            app.logger.info(f"Successfully enqueued weekly newsletter job {job.id}")
        except redis.exceptions.ConnectionError as e:
            app.logger.warning(f"Redis connection failed. Falling back to thread for weekly newsletter job. Error: {e}")
            # The job function needs an app context to run, especially for mail.
            # The ThreadPoolExecutor doesn't automatically provide it.
            def run_in_context():
                with app.app_context():
                    send_weekly_newsletter()
            ThreadPoolExecutor().submit(run_in_context)
        except Exception as e:
            app.logger.error(f"An unexpected error occurred while enqueuing the weekly newsletter job: {e}", exc_info=True)


if __name__ == '__main__':
    enqueue_newsletter_job()
