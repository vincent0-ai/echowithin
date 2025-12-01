#!/usr/bin/env python3
"""
This script enqueues the log email job to the RQ worker queue.
It is intended to be run by a scheduler like cron.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project root to the Python path to allow imports from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, send_log_email_job


def enqueue_log_job():
    """Enqueues the send_log_email_job to RQ."""
    print("Enqueuing log email job...")
    try:
        job = send_log_email_job.queue()
        print(f"Successfully enqueued job {job.id}")
    except Exception as e:
        print(f"Error enqueuing job: {e}")


if __name__ == '__main__':
    enqueue_log_job()