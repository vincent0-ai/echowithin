#!/usr/bin/env python3
"""
This script acts as a background scheduler.
It runs continuously and triggers scheduled jobs at their configured times.
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


def run_weekly_newsletter():
    """
    Runs the send_weekly_newsletter.py script using a subprocess.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'send_weekly_newsletter.py')
    print(f"Scheduler triggered. Running weekly newsletter script: {script_path}")
    try:
        subprocess.run(['python', script_path], check=True)
        print("Successfully executed send_weekly_newsletter.py")
    except subprocess.CalledProcessError as e:
        print(f"Error executing send_weekly_newsletter.py: {e}")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


def run_cleanup_expired_auth():
    """
    Runs the cleanup_expired_auth.py script to remove expired tokens and codes.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'cleanup_expired_auth.py')
    print(f"Scheduler triggered. Running auth cleanup script: {script_path}")
    try:
        subprocess.run(['python', script_path], check=True)
        print("Successfully executed cleanup_expired_auth.py")
    except subprocess.CalledProcessError as e:
        print(f"Error executing cleanup_expired_auth.py: {e}")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


if __name__ == '__main__':
    # Schedule the log email job to run every day at 01:00 AM server time.
    schedule.every().day.at("01:00").do(run_schedule_log_email)
    
    # Schedule the weekly newsletter to run every Sunday at 09:00 AM server time.
    schedule.every().sunday.at("09:00").do(run_weekly_newsletter)
    
    # Schedule auth cleanup to run every hour to remove expired tokens/codes
    schedule.every().hour.do(run_cleanup_expired_auth)
    
    print("Scheduler started. Waiting for scheduled jobs...")
    print("  - Daily log email: 01:00 AM")
    print("  - Weekly newsletter: Sunday 09:00 AM")
    print("  - Auth cleanup: Every hour")
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every 60 seconds
