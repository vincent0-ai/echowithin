#!/usr/bin/env python3
"""
Test script to manually trigger new-post notification emails.
This can be run standalone or from a Flask app context to verify email delivery.
"""

import os
import sys
from dotenv import load_dotenv
from bson.objectid import ObjectId

# Load environment variables
load_dotenv()

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import app, send_new_post_notifications, posts_conf, users_conf


def test_notification_job(post_id_str=None):
    """
    Test the notification job.
    
    If post_id_str is provided, it will trigger the job for that post.
    Otherwise, it will use the most recent post.
    """
    print("=" * 60)
    print("Testing new-post notification job")
    print("=" * 60)
    
    # Find a post to test with
    if not post_id_str:
        # Get the most recent post
        post = posts_conf.find_one(sort=[('timestamp', -1)])
        if not post:
            print("❌ No posts found in database. Create a post first.")
            return False
        post_id_str = str(post['_id'])
        print(f"✓ Using most recent post: {post['title']} (ID: {post_id_str})")
    else:
        post = posts_conf.find_one({'_id': ObjectId(post_id_str)})
        if not post:
            print(f"❌ Post {post_id_str} not found.")
            return False
        print(f"✓ Found post: {post['title']}")
    
    # Check opted-in users
    opted_in_users = list(users_conf.find(
        {'is_confirmed': True, 'notify_new_posts': True},
        {'email': 1, 'username': 1}
    ))
    
    if not opted_in_users:
        print("⚠ No users opted in to notifications.")
        print("  Hint: All new users default to notify_new_posts=True.")
        print("  Check database or update a user's notify_new_posts field.")
        return False
    
    print(f"✓ Found {len(opted_in_users)} opted-in users:")
    for u in opted_in_users:
        print(f"  - {u.get('username')} ({u.get('email')})")
    
    print("\nRunning notification job (synchronous)...")
    print("-" * 60)
    
    try:
        with app.app_context():
            send_new_post_notifications(post_id_str)
        print("-" * 60)
        print("✓ Notification job completed successfully!")
        print("\nCheck your email inbox for the notification.")
        return True
    except Exception as e:
        print("-" * 60)
        print(f"❌ Error running notification job: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_enqueue_job(post_id_str=None):
    """
    Test enqueuing the job to RQ (requires RQ worker to process it).
    """
    print("\n" + "=" * 60)
    print("Testing job enqueueing (RQ)")
    print("=" * 60)
    
    if not post_id_str:
        post = posts_conf.find_one(sort=[('timestamp', -1)])
        if not post:
            print("❌ No posts found in database.")
            return False
        post_id_str = str(post['_id'])
    
    print(f"Enqueuing job for post {post_id_str}...")
    
    try:
        job = send_new_post_notifications.queue(post_id_str)
        print(f"✓ Job enqueued successfully!")
        print(f"  Job ID: {job.id}")
        print(f"  Status: {job.get_status()}")
        print(f"\nNote: The job will be processed by an RQ worker.")
        print(f"Start a worker with: rq worker")
        return True
    except Exception as e:
        print(f"❌ Error enqueuing job: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Test new-post notification email sending'
    )
    parser.add_argument(
        '--post-id',
        help='Specific post ID to test (default: most recent post)'
    )
    parser.add_argument(
        '--enqueue',
        action='store_true',
        help='Enqueue job to RQ instead of running synchronously'
    )
    
    args = parser.parse_args()
    
    if args.enqueue:
        success = test_enqueue_job(args.post_id)
    else:
        success = test_notification_job(args.post_id)
    
    sys.exit(0 if success else 1)
