#!/usr/bin/env python3
"""
This script acts as a background scheduler.
It runs continuously and triggers the email log job at a scheduled time.
"""

import schedule
import time
import subprocess
import os


def run_schedule_log_email():
    """
    Runs the schedule_log_email.py script using a subprocess.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'schedule_log_email.py')
    print(f"Scheduler triggered. Running script: {script_path}")
    try:
        subprocess.run(['python', script_path], check=True)
        print("Successfully executed schedule_log_email.py")
    except subprocess.CalledProcessError as e:
        print(f"Error executing schedule_log_email.py: {e}")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


if __name__ == '__main__':
    # Schedule the job to run every day at 01:00 AM server time.
    schedule.every().day.at("01:00").do(run_schedule_log_email)
    print("Scheduler started. Waiting for scheduled jobs...")
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every 60 seconds