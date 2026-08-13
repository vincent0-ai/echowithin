#!/usr/bin/env python3
"""
This script acts as a background scheduler.
It runs continuously and triggers scheduled jobs at their configured times.

On startup, interval-based jobs are offset so they don't all fire immediately
(preventing a thundering-herd of missed-job replays after a restart).
"""

import schedule
import time
import subprocess
import os
import datetime


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


def run_weekly_achievements():
    """
    Runs the weekly_achievements.py script to calculate winners.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'weekly_achievements.py')
    print(f"Scheduler triggered. Running weekly achievements script: {script_path}")
    try:
        subprocess.run(['python', script_path], check=True)
        print("Successfully executed weekly_achievements.py")
    except subprocess.CalledProcessError as e:
        print(f"Error executing weekly_achievements.py: {e}")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


def run_backup_to_atlas():
    """
    Runs the backup_to_atlas.py script to sync data to MongoDB Atlas.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'backup_to_atlas.py')
    print(f"Scheduler triggered. Running Atlas backup script: {script_path}")
    try:
        subprocess.run(['python', script_path], check=True)
        print("Successfully executed backup_to_atlas.py")
    except subprocess.CalledProcessError as e:
        print(f"Error executing backup_to_atlas.py: {e}")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


def run_scheduled_messages():
    """
    Runs the process_scheduled_messages.py script to deliver due messages.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'process_scheduled_messages.py')
    try:
        subprocess.run(['python', script_path], check=True, timeout=60)
    except subprocess.CalledProcessError as e:
        print(f"Error executing process_scheduled_messages.py: {e}")
    except subprocess.TimeoutExpired:
        print("Warning: process_scheduled_messages.py timed out after 60 seconds")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


def run_streak_decay():
    """
    Runs the streak_decay.py script to reset stale bond streaks.
    """
    script_path = os.path.join(os.path.dirname(__file__), 'streak_decay.py')
    try:
        subprocess.run(['python', script_path], check=True, timeout=60)
    except subprocess.CalledProcessError as e:
        print(f"Error executing streak_decay.py: {e}")
    except subprocess.TimeoutExpired:
        print("Warning: streak_decay.py timed out after 60 seconds")
    except FileNotFoundError:
        print(f"Error: The script at {script_path} was not found.")


if __name__ == '__main__':
    # ── Fixed-time jobs (no catchup risk) ──────────────────────────
    # These fire at a specific wall-clock time, so the schedule library
    # naturally won't replay missed windows.
    schedule.every().day.at("01:00").do(run_schedule_log_email)
    schedule.every().day.at("02:00").do(run_streak_decay)
    schedule.every().sunday.at("09:00").do(run_weekly_newsletter)
    schedule.every().monday.at("00:01").do(run_weekly_achievements)

    # ── Interval jobs (catchup risk on restart) ────────────────────
    # The schedule library fires interval jobs immediately on the first
    # run_pending() call after registration because their next_run is
    # set to now. We register them and then push their next_run into
    # the future so a restart doesn't replay all missed windows at once.

    backup_job = schedule.every(30).minutes.do(run_backup_to_atlas)
    cleanup_job = schedule.every().hour.do(run_cleanup_expired_auth)
    messages_job = schedule.every(1).minutes.do(run_scheduled_messages)

    # Stagger first runs: backup in 2 min, cleanup in 5 min,
    # scheduled messages in 1 min (these are short-interval so a brief
    # initial delay is fine).
    now = datetime.datetime.now()
    messages_job.next_run = now + datetime.timedelta(minutes=1)
    backup_job.next_run = now + datetime.timedelta(minutes=2)
    cleanup_job.next_run = now + datetime.timedelta(minutes=5)

    print("Scheduler started. Waiting for scheduled jobs...")
    print("  - Daily log email: 01:00 AM")
    print("  - Daily streak decay: 02:00 AM")
    print("  - Weekly newsletter: Sunday 09:00 AM")
    print("  - Weekly achievements: Monday 00:01 AM")
    print(f"  - Auth cleanup: Every hour (first run in ~5 min)")
    print(f"  - Atlas backup: Every 30 minutes (first run in ~2 min)")
    print(f"  - Scheduled messages: Every minute (first run in ~1 min)")
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every 60 seconds
