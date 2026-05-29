#!/usr/bin/env python3
"""
Processes scheduled messages whose delivery time has arrived.

Called by scheduler.py every minute. Hits the internal API endpoint on the
web process so that Socket.IO delivery works (real-time broadcast to recipient).

If the internal API is unreachable, falls back to direct MongoDB insertion
so the message is never lost — the 6-second client polling will pick it up.
"""

import os
import sys
import datetime
import requests
from dotenv import load_dotenv

load_dotenv()


def get_app_url():
    """Returns the app's base URL."""
    return 'https://echowithin.xyz'


def get_env_variable(name: str) -> str:
    """Get an environment variable or raise an exception."""
    try:
        return os.environ[name]
    except KeyError:
        message = f"Expected environment variable '{name}' not set."
        raise Exception(message)


def process_via_api():
    """Call the internal API endpoint to process scheduled messages.
    
    This approach ensures Socket.IO delivery works because the web process
    handles the actual message insertion and broadcast.
    """
    app_url = get_app_url()
    secret_key = get_env_variable('SECRET')
    
    try:
        response = requests.post(
            f"{app_url}/api/messages/schedule/process",
            headers={
                'X-Scheduler-Secret': secret_key,
                'Content-Type': 'application/json'
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            delivered = data.get('delivered', 0)
            failed = data.get('failed', 0)
            total = data.get('total', 0)
            if total > 0:
                print(f"Processed {total} scheduled messages: {delivered} delivered, {failed} failed")
            return True
        else:
            print(f"API returned status {response.status_code}: {response.text[:200]}")
            return False
    except requests.exceptions.ConnectionError:
        print("WARNING: Could not connect to web process. Falling back to direct DB processing.")
        return False
    except Exception as e:
        print(f"ERROR calling scheduled messages API: {e}")
        return False


def process_direct():
    """Fallback: process scheduled messages directly via MongoDB.
    
    Socket.IO broadcast won't work, but the message will be in the DB.
    The recipient's 6-second polling sync will pick it up.
    """
    try:
        from pymongo import MongoClient
        
        client = MongoClient(get_env_variable('MONGODB_CONNECTION'))
        db = client['echowithin_db']
        scheduled_messages = db['scheduled_messages']
        direct_messages = db['direct_messages']
        
        now = datetime.datetime.now(datetime.timezone.utc)
        due_messages = list(scheduled_messages.find({
            'scheduled_at': {'$lte': now},
            'status': 'pending'
        }).limit(50))
        
        if not due_messages:
            return
        
        delivered = 0
        for msg in due_messages:
            try:
                # Build the direct_messages document
                message_doc = {
                    'sender_id': msg['sender_id'],
                    'recipient_id': msg['recipient_id'],
                    'content': msg['content'],
                    'encrypted': True,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc),
                    'is_read': False,
                    'message_type': msg.get('message_type', 'text')
                }
                
                if msg.get('image_url'):
                    message_doc['image_url'] = msg['image_url']
                if msg.get('reply_to_id'):
                    message_doc['reply_to_id'] = msg['reply_to_id']
                    message_doc['reply_to_preview'] = msg.get('reply_to_preview')
                    message_doc['reply_to_sender'] = msg.get('reply_to_sender')
                if msg.get('link_preview'):
                    message_doc['link_preview'] = msg['link_preview']
                
                # Insert into direct_messages
                direct_messages.insert_one(message_doc)
                
                # Mark as sent
                scheduled_messages.update_one(
                    {'_id': msg['_id']},
                    {'$set': {
                        'status': 'sent',
                        'delivered_at': datetime.datetime.now(datetime.timezone.utc),
                        'delivery_method': 'direct_fallback'
                    }}
                )
                delivered += 1
            except Exception as e:
                print(f"ERROR delivering scheduled message {msg['_id']}: {e}")
        
        print(f"Direct fallback: delivered {delivered}/{len(due_messages)} scheduled messages")
        client.close()
    except Exception as e:
        print(f"ERROR in direct processing fallback: {e}")


if __name__ == '__main__':
    # Try API-based delivery first (supports Socket.IO + push notifications)
    # Fall back to direct DB insertion if the web process is unreachable
    if not process_via_api():
        process_direct()
