import datetime
import os
import json
import time
import hashlib
import secrets

from flask import render_template, url_for
from flask_mail import Mail, Message
from flask_rq2 import RQ
from bson.objectid import ObjectId
from jigsawstack import JigsawStack
from pywebpush import webpush, WebPushException
import cloudinary
import cloudinary.uploader
import requests

from config import (get_env_variable, ENGAGEMENT_WEIGHTS,
    VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY, FIREBASE_AVAILABLE)
from utils import (_is_ios_web_push_subscription,
    _remove_stale_push_subscription, _get_user_badge_count)
import database

messaging = None
if FIREBASE_AVAILABLE:
    try:
        from firebase_admin import messaging
    except ImportError:
        pass

_APP = None
_T = None

def _get_app():
    global _APP
    if _APP is None:
        import main
        _APP = main.app
    return _APP

def _get_t():
    global _T
    if _T is None:
        from typesense_client import _t as ts_t
        _T = ts_t
    return _T

_MAIL = None
def _get_mail():
    global _MAIL
    if _MAIL is None:
        import main
        _MAIL = main.mail
    return _MAIL

_MAIN = None
def _get_main():
    global _MAIN
    if _MAIN is None:
        import main
        _MAIN = main
    return _MAIN

class _RqProxy:
    @property
    def job(self):
        import main
        return main.rq.job

rq = _RqProxy()


def check_image_for_nsfw(image_path):
    """
    Checks an image for NSFW content using JigsawStack validate/nsfw.
    Returns True if NSFW, False otherwise.
    """
    try:
        client = JigsawStack(api_key=get_env_variable('JIGSAW_API_KEY'))
        response = client.validate.nsfw({
            'url': image_path
        })
        if isinstance(response, dict):
            return response.get('nsfw', False)
        return getattr(response, 'nsfw', False)

    except Exception as e:
        _get_app().logger.error(f"Error calling JigsawStack NSFW API via SDK: {e}")
        return False


@rq.job
def process_image_for_nsfw(post_id, image_url, public_id):
    """
    This function runs as a background job to check an image for NSFW content.
    It uses JigsawStack for NSFW detection and updates the post status.
    """
    _get_app().logger.info(f"Starting NSFW check job for post {post_id} on image URL: {image_url}")

    try:
        api_response = requests.post(
            'https://api.jigsawstack.com/v1/validate/nsfw',
            json={"url": image_url},
            headers={"x-api-key": get_env_variable('JIGSAW_API_KEY')},
            timeout=20
        )
        if api_response.status_code == 200:
            data = api_response.json()
            is_nsfw = data.get('nsfw', False)
        else:
            _get_app().logger.warning(f"NSFW API returned status {api_response.status_code} for post {post_id}")
            is_nsfw = False

        if is_nsfw:
            _get_app().logger.warning(f"NSFW content detected in {public_id} for post {post_id}. Tagging image and updating post.")
            try:
                cloudinary.uploader.add_tag('nsfw', [public_id])
            except Exception as cl_e:
                _get_app().logger.error(f"Cloudinary tagging failed: {cl_e}")
            database.posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'image_status': 'removed_nsfw'}})
        else:
            _get_app().logger.info(f"Image {public_id} for post {post_id} is safe. Updating post status.")
            database.posts_conf.update_one(
                {'_id': ObjectId(post_id), 'image_status': {'$ne': 'removed_nsfw'}},
                {'$set': {'image_status': 'safe'}}
            )
    except Exception as e:
        _get_app().logger.error(f"Error during NSFW check job for post {post_id}: {e}")
        database.posts_conf.update_one(
            {'_id': ObjectId(post_id), 'image_status': {'$ne': 'removed_nsfw'}},
            {'$set': {'image_status': 'safe'}}
        )



def send_code(email, gen_code=None, retries=3, delay=2):
    _get_app().logger.info(f"[DEV DEBUG] Generated verification code for {email}: {gen_code}")
    for attempt in range(retries):
        try:
            sender = f"EchoWithin <{get_env_variable('MAIL_USERNAME')}>"
            msg = Message(
                subject="Your EchoWithin Verification Code",
                sender=sender,
                recipients=[email]
            )
            msg.html = render_template("verify.html", code=gen_code)
            msg.body = f"Your EchoWithin verification code is: {gen_code}\n\nIf you didn't request this, please ignore this email."
            _get_mail().send(msg)
            _get_app().logger.info(f"Verification email sent to {email}. DEV CODE: {gen_code}")
            return True
        except Exception as e:
            _get_app().logger.error(f"Attempt {attempt+1} failed to send email to {email}: {e}")
            time.sleep(delay)
    else:
        _get_app().logger.error(f"Failed to send verification email to {email} after {retries} attempts.")

def send_reset_code(email, reset_token=None, retries=3, delay=2):
    reset_url = ""
    try:
        reset_url = url_for('reset_password', token=reset_token, _external=True)
        _get_app().logger.info(f"[DEV DEBUG] Generated password reset link for {email}: {reset_url}")
    except Exception:
        pass
    for attempt in range(retries):
        try:
            sender_email = _get_app().config.get('MAIL_DEFAULT_SENDER') or get_env_variable('MAIL_USERNAME')
            msg = Message(
                subject="EchoWithin Password Reset",
                sender=f"EchoWithin <{sender_email}>",
                recipients=[email]
            )
            if not reset_url:
                reset_url = url_for('reset_password', token=reset_token, _external=True)
            msg.html = render_template("reset_email.html", reset_url=reset_url)
            msg.body = f"""Password Reset Request

You requested a password reset for your EchoWithin account.

Click the link below to reset your password:
{reset_url}

If you didn't request this, please ignore this email.
This link will expire in 1 hour.
"""
            _get_mail().send(msg)
            _get_app().logger.info(f"Password reset email sent to {email}")
            return True
        except Exception as e:
            _get_app().logger.error(f"Attempt {attempt+1} failed to send reset email to {email}: {e}", exc_info=True)
            time.sleep(delay)
    else:
        _get_app().logger.error(f"Failed to send password reset email to {email} after {retries} attempts.")


@rq.job
def send_new_post_notifications(post_id_str):
    """Sends new post notification emails to opted-in users as a background job."""
    try:
        post = database.posts_conf.find_one({'_id': ObjectId(post_id_str)})
        if not post:
            _get_app().logger.error(f"Post {post_id_str} not found for notification job")
            return

        base_url = os.environ.get('FLASK_URL', 'https://echowithin.xyz')
        with _get_app().app_context():
            try:
                post_url = url_for('view_post', slug=post.get('slug'), _external=True)
            except RuntimeError:
                post_url = f"{base_url}/post/{post.get('slug')}"

            subject = f"New post on EchoWithin: {post.get('title')}"

            recipients_cursor = database.users_conf.find(
                {
                    'is_confirmed': True,
                    'notification_preference': 'immediate'
                },
                {'email': 1, 'username': 1}
            )

            with _get_mail().connect() as conn:
                for u in recipients_cursor:
                    try:
                        recipient_email = u.get('email')
                        recipient_name = u.get('username') or ''
                        
                        secret = _get_app().config["SECRET_KEY"]
                        unsub_token = hashlib.sha256(f"{secret}{recipient_email}unsubscribe".encode()).hexdigest()
                        try:
                            unsub_url = url_for('unsubscribe', email=recipient_email, token=unsub_token, _external=True)
                        except RuntimeError:
                            unsub_url = f"{base_url}/unsubscribe?email={recipient_email}&token={unsub_token}"
                        
                        msg = Message(
                            subject=subject,
                            sender=f"EchoWithin <{get_env_variable('MAIL_USERNAME')}>",
                            recipients=[recipient_email]
                        )
                        msg.html = render_template('new_post_notification.html', post=post, post_url=post_url, recipient_name=recipient_name, unsub_url=unsub_url)
                        msg.body = f"Hello {recipient_name},\n\nA new post has been published on EchoWithin: \"{post.get('title')}\" by {post.get('author')}.\n\nView post: {post_url}\n\nTo unsubscribe from these notifications, visit: {unsub_url}"
                        
                        msg.extra_headers = {
                            'List-Unsubscribe': f"<{unsub_url}>",
                            'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
                        }
                        
                        conn.send(msg)
                        _get_app().logger.info(f"Sent new-post notification for post {post_id_str}")
                    except Exception as e:
                        _get_app().logger.error(f"Failed to send new-post email for user {u.get('_id')}: {e}")
    except Exception as e:
        _get_app().logger.error(f"Error in send_new_post_notifications job for {post_id_str}: {e}", exc_info=True)


@rq.job
def send_weekly_newsletter():
    """Sends a weekly digest of all posts from the past week to newsletter subscribers."""
    try:
        with _get_app().app_context():
            now = datetime.datetime.now(datetime.timezone.utc)
            week_ago = now - datetime.timedelta(days=7)

            MAX_DIGEST_POSTS = 15
            total_post_count = database.posts_conf.count_documents({
                'timestamp': {'$gte': week_ago}
            })

            pipeline = [
                {'$match': {'timestamp': {'$gte': week_ago}}},
                {'$lookup': {
                    'from': 'comments',
                    'localField': 'slug',
                    'foreignField': 'post_slug',
                    'as': 'comment_data'
                }},
                {'$addFields': {
                    'comment_count': {'$size': '$comment_data'},
                    'likes_safe': {'$ifNull': ['$likes_count', 0]},
                    'shares_safe': {'$ifNull': ['$share_count', 0]},
                    'views_safe': {'$ifNull': ['$view_count', 0]}
                }},
                {'$addFields': {
                    'engagement_score': {'$add': [
                        {'$multiply': ['$comment_count', ENGAGEMENT_WEIGHTS['comment']]},
                        {'$multiply': ['$likes_safe', ENGAGEMENT_WEIGHTS['reaction']]},
                        {'$multiply': ['$shares_safe', ENGAGEMENT_WEIGHTS['share']]},
                        {'$multiply': ['$views_safe', ENGAGEMENT_WEIGHTS['view']]}
                    ]}
                }},
                {'$sort': {'engagement_score': -1, 'timestamp': -1}},
                {'$limit': MAX_DIGEST_POSTS},
                {'$project': {'comment_data': 0, 'likes_safe': 0, 'shares_safe': 0, 'views_safe': 0}}
            ]

            posts_list = list(database.posts_conf.aggregate(pipeline))

            base_url = os.environ.get('FLASK_URL', 'https://echowithin.xyz')
            for post in posts_list:
                try:
                    post['url'] = url_for('view_post', slug=post.get('slug'), _external=True)
                except RuntimeError:
                    post['url'] = f"{base_url}/post/{post.get('slug')}"

            week_start = week_ago.strftime('%B %d')
            week_end = now.strftime('%B %d, %Y')

            recipient_emails = set()
            
            for sub in database.newsletter_conf.find({}, {'email': 1}):
                if sub.get('email'):
                    recipient_emails.add(sub['email'])
            
            for user in database.users_conf.find({'is_confirmed': True, 'notification_preference': 'weekly'}, {'email': 1}):
                if user.get('email'):
                    recipient_emails.add(user['email'])

            if not recipient_emails:
                _get_app().logger.info("No recipients found for weekly newsletter, skipping")
                return

            subject = f"EchoWithin Weekly Digest - {week_end}"
            sender_email = get_env_variable('MAIL_USERNAME')

            sent_count = 0
            for recipient_email in recipient_emails:
                try:
                    secret = _get_app().config["SECRET_KEY"]
                    unsub_token = hashlib.sha256(f"{secret}{recipient_email}unsubscribe".encode()).hexdigest()
                    try:
                        unsub_url = url_for('unsubscribe', email=recipient_email, token=unsub_token, _external=True)
                    except RuntimeError:
                        unsub_url = f"{base_url}/unsubscribe/{recipient_email}/{unsub_token}"
                    
                    msg = Message(
                        subject=subject,
                        sender=f"EchoWithin <{sender_email}>",
                        recipients=[recipient_email]
                    )
                    msg.html = render_template(
                        'weekly_newsletter.html',
                        posts=posts_list,
                        total_post_count=total_post_count,
                        week_start=week_start,
                        week_end=week_end,
                        unsub_url=unsub_url
                    )
                    text_body = f"EchoWithin Weekly Digest ({week_start} - {week_end})\n\n"
                    if total_post_count > len(posts_list):
                        text_body += f"Top {len(posts_list)} of {total_post_count} posts this week:\n\n"
                    for p in posts_list[:5]:
                        text_body += f"- {p.get('title')} ({p.get('url')})\n"
                    text_body += f"\nUnsubscribe: {unsub_url}"
                    msg.body = text_body

                    msg.extra_headers = {
                        'List-Unsubscribe': f"<{unsub_url}>",
                        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
                    }

                    _get_mail().send(msg)
                    sent_count += 1
                    _get_app().logger.debug(f"Sent weekly newsletter (count: {sent_count})")
                except Exception as e:
                    _get_app().logger.error(f"Failed to send weekly newsletter: {e}")

            _get_app().logger.info(f"Weekly newsletter sent to {sent_count} recipients with top {len(posts_list)} of {total_post_count} posts")
    except Exception as e:
        _get_app().logger.error(f"Error in send_weekly_newsletter job: {e}", exc_info=True)


@rq.job
def send_push_notification_to_user(user_id_str, title, body, url=None, tag=None, extra_data=None):
    """Send a push notification (Web Push and FCM) to all devices of a user."""
    try:
        if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
            subscriptions = list(database.push_subscriptions_conf.find({'user_id': ObjectId(user_id_str)}))
            if subscriptions:
                web_sent = 0
                web_failed = 0
                payload = json.dumps({
                    'title': title,
                    'body': body,
                    'url': url or '/',
                    'tag': tag or 'echowithin',
                    'renotify': True,
                    'icon': '/static/logo-192.png',
                    'badge': '/static/logo-96.png'
                })

                for sub in subscriptions:
                    try:
                        subscription_info = {
                            'endpoint': sub['endpoint'],
                            'keys': sub['keys']
                        }
                        response = webpush(
                            subscription_info=subscription_info,
                            data=payload,
                            vapid_private_key=VAPID_PRIVATE_KEY,
                            vapid_claims=_get_main().VAPID_CLAIMS,
                            ttl=86400,
                            headers={"Urgency": "high"}
                        )
                        status = response.status_code if response else 'unknown'
                        is_ios = _is_ios_web_push_subscription(sub)
                        platform = 'iOS' if is_ios else 'non-iOS'
                        web_sent += 1
                        _get_app().logger.info(f"Web push delivered ({platform}): status={status}, user={user_id_str}")
                    except WebPushException as e:
                        status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                        resp_body = getattr(e.response, 'text', '')[:200] if hasattr(e, 'response') and e.response else ''
                        is_ios = _is_ios_web_push_subscription(sub)
                        platform = 'iOS' if is_ios else 'non-iOS'
                        web_failed += 1
                        _get_app().logger.warning(f"Web push failed ({platform}): status={status_code}, user={user_id_str}, body={resp_body}")
                        if status_code in [404, 410]:
                            _remove_stale_push_subscription(sub, platform, user_id_str, f"status={status_code}")
                        elif status_code == 403:
                            _get_app().logger.warning(
                                f"Web push unauthorized ({platform}) for user {user_id_str}; kept subscription for retry"
                            )
                    except Exception as e:
                        web_failed += 1
                        _get_app().logger.error(f"Unexpected error sending push to user {user_id_str}: {e}")
                _get_app().logger.info(f"Web push summary for user {user_id_str}: sent={web_sent}, failed={web_failed}")
        else:
            _get_app().logger.debug("VAPID keys not configured, skipping web push")

        if _get_main().FIREBASE_INITIALIZED:
            try:
                fcm_data = {'tag': tag or 'echowithin'}
                if extra_data:
                    fcm_data.update(extra_data)
                
                send_fcm_notification_to_user(
                    user_id_str, 
                    title, 
                    body, 
                    url=url,
                    data=fcm_data
                )
            except Exception as e:
                _get_app().logger.error(f"FCM notification failed for user {user_id_str}: {e}")

    except Exception as e:
        _get_app().logger.error(f"Error in send_push_notification_to_user: {e}", exc_info=True)


@rq.job
def send_admin_broadcast_push(title, body, url=None):
    """
    Send a site-wide push notification to ALL subscribed devices (Web Push and Native FCM).
    Processed in the background via RQ.
    """
    try:
        _get_app().logger.info(f"Starting admin broadcast push: '{title}'")
        
        web_success = 0
        web_failed = 0
        if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
            subscriptions = list(database.push_subscriptions_conf.find({}))
            _get_app().logger.info(f"Broadcasting to {len(subscriptions)} Web Push subscriptions")
            
            payload = json.dumps({
                'title': title,
                'body': body,
                'url': url or '/',
                'tag': 'admin-announcement',
                'icon': '/static/logo-192.png',
                'badge': '/static/logo-96.png'
            })
            
            for sub in subscriptions:
                try:
                    subscription_info = {'endpoint': sub['endpoint'], 'keys': sub['keys']}
                    webpush(
                        subscription_info=subscription_info,
                        data=payload,
                        vapid_private_key=VAPID_PRIVATE_KEY,
                        vapid_claims=_get_main().VAPID_CLAIMS,
                        ttl=86400
                    )
                    web_success += 1
                except WebPushException as e:
                    status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                    is_ios = _is_ios_web_push_subscription(sub)
                    if status_code in [404, 410]:
                        _remove_stale_push_subscription(sub, 'iOS' if is_ios else 'non-iOS', str(sub.get('user_id', 'unknown')), f"status={status_code}")
                        web_failed += 1
                    elif status_code == 403:
                        web_failed += 1
                        _get_app().logger.warning(
                            "Broadcast web push unauthorized (status=403); kept subscription for future retry"
                        )
                    else:
                        web_failed += 1
                except Exception:
                    web_failed += 1
        
        fcm_success = 0
        fcm_failed = 0
        if _get_main().FIREBASE_INITIALIZED:
            from firebase_admin import messaging
            tokens_cursor = database.fcm_tokens_conf.find({})
            all_tokens = [doc['token'] for doc in tokens_cursor]
            
            if all_tokens:
                _get_app().logger.info(f"Broadcasting to {len(all_tokens)} FCM tokens")
                for token in all_tokens:
                    try:
                        message = messaging.Message(
                            notification=messaging.Notification(title=title, body=body),
                            data={'url': url or '/', 'tag': 'admin-announcement'},
                            token=token
                        )
                        messaging.send(message)
                        fcm_success += 1
                    except messaging.UnregisteredError:
                        database.fcm_tokens_conf.delete_one({'token': token})
                        fcm_failed += 1
                    except Exception as e:
                        _get_app().logger.debug(f"FCM send failed for token {token[:10]}...: {e}")
                        fcm_failed += 1
        
        _get_app().logger.info(f"Broadcast complete. Web: {web_success} ok, {web_failed} failed. FCM: {fcm_success} ok, {fcm_failed} failed.")
        
    except Exception as e:
        _get_app().logger.error(f"Error in send_admin_broadcast_push: {e}", exc_info=True)


@rq.job
def send_push_notifications_for_new_post(post_id_str):
    """Send push notifications to all subscribed users about a new post."""
    try:
        post = database.posts_conf.find_one({'_id': ObjectId(post_id_str)})
        if not post:
            _get_app().logger.error(f"Post {post_id_str} not found for push notification")
            return

        title = "New Post on EchoWithin"
        body = f'"{post.get("title")}" by {post.get("author")}'

        with _get_app().app_context():
            try:
                post_url = url_for('view_post', slug=post.get('slug'), _external=True)
            except RuntimeError:
                base_url = os.environ.get('FLASK_URL', 'https://echowithin.xyz')
                post_url = f"{base_url}/post/{post.get('slug')}"

        author_id = post.get('author_id')

        if VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY:
            query = {'user_id': {'$ne': author_id}} if author_id else {}
            subscriptions = list(database.push_subscriptions_conf.find(query))
            sent_count = 0
            failed_count = 0

            payload = json.dumps({
                'title': title,
                'body': body,
                'url': post_url,
                'tag': f'new-post-{post_id_str}',
                'icon': '/static/logo-192.png',
                'badge': '/static/logo-96.png'
            })

            for sub in subscriptions:
                try:
                    subscription_info = {
                        'endpoint': sub['endpoint'],
                        'keys': sub['keys']
                    }
                    response = webpush(
                        subscription_info=subscription_info,
                        data=payload,
                        vapid_private_key=VAPID_PRIVATE_KEY,
                        vapid_claims=_get_main().VAPID_CLAIMS,
                        ttl=86400
                    )
                    status = response.status_code if response else 'unknown'
                    is_ios = _is_ios_web_push_subscription(sub)
                    platform = 'iOS' if is_ios else 'non-iOS'
                    user_id = sub.get('user_id', 'unknown')
                    sent_count += 1
                    _get_app().logger.info(f"Web push delivered ({platform}): status={status}, user={user_id}, post={post_id_str}")
                except WebPushException as e:
                    status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                    resp_body = getattr(e.response, 'text', '')[:200] if hasattr(e, 'response') and e.response else ''
                    is_ios = _is_ios_web_push_subscription(sub)
                    platform = 'iOS' if is_ios else 'non-iOS'
                    user_id = sub.get('user_id', 'unknown')
                    failed_count += 1
                    _get_app().logger.warning(f"Web push failed ({platform}): status={status_code}, user={user_id}, post={post_id_str}, body={resp_body}")
                    if status_code in [404, 410]:
                        _remove_stale_push_subscription(sub, platform, str(user_id), f"status={status_code}")
                    elif status_code == 403:
                        _get_app().logger.warning(
                            f"Web push unauthorized ({platform}) for user {user_id}; kept subscription for retry"
                        )
                except Exception as e:
                    failed_count += 1
                    _get_app().logger.error(f"Unexpected push error: {e}")

            _get_app().logger.info(
                f"Web push summary for new post {post_id_str}: "
                f"targets={len(subscriptions)}, sent={sent_count}, failed={failed_count}"
            )
        else:
            _get_app().logger.debug("VAPID keys not configured, skipping web push for new post")

        if _get_main().FIREBASE_INITIALIZED:
            try:
                tokens_query = {'user_id': {'$ne': author_id}} if author_id else {}
                tokens = list(database.fcm_tokens_conf.find(tokens_query))
                if tokens:
                    num_fcm_sent = send_fcm_notifications_batch(
                        tokens, 
                        title, 
                        body, 
                        url=post_url,
                        data={'type': 'new_post', 'post_id': post_id_str}
                    )
                    _get_app().logger.info(f"Sent FCM notifications for new post {post_id_str} to {num_fcm_sent} devices")
            except Exception as e:
                _get_app().logger.error(f"FCM batch sending failed for new post {post_id_str}: {e}")
    except Exception as e:
        _get_app().logger.error(f"Error in send_push_notifications_for_new_post: {e}", exc_info=True)


def send_fcm_notification_to_user(user_id_str, title, body, url=None, data=None):
    """Send FCM notification to all registered devices for a user (native app).

    This is called alongside web push to ensure both browser and native app users
    receive notifications.
    """
    if not _get_main().FIREBASE_INITIALIZED:
        return 0
    
    try:
        tokens = list(database.fcm_tokens_conf.find({'user_id': ObjectId(user_id_str)}))
        if not tokens:
            return 0
        
        badge_count = _get_user_badge_count(user_id_str)

        sent_count = 0
        for token_doc in tokens:
            try:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=body,
                    ),
                    data={
                        'url': url or '/',
                        'click_action': url or '/',
                        **(data or {})
                    },
                    token=token_doc['token'],
                    android=messaging.AndroidConfig(
                        priority='high',
                        notification=messaging.AndroidNotification(
                            icon='ic_stat_notification',
                            color='#3e2217',
                            channel_id='default',
                            notification_count=badge_count,
                        ),
                    ),
                    apns=messaging.APNSConfig(
                        headers={'apns-priority': '10'},
                        payload=messaging.APNSPayload(
                            aps=messaging.Aps(
                                alert=messaging.ApsAlert(
                                    title=title,
                                    body=body
                                ),
                                badge=badge_count,
                                sound='default',
                                mutable_content=True,
                            ),
                        ),
                    ),
                )
                messaging.send(message)
                sent_count += 1
            except messaging.UnregisteredError:
                database.fcm_tokens_conf.delete_one({'_id': token_doc['_id']})
                _get_app().logger.debug(f"Removed invalid FCM token for user {user_id_str}")
            except Exception as e:
                _get_app().logger.error(f"FCM send error for user {user_id_str}: {e}")
        
        return sent_count
    except Exception as e:
        _get_app().logger.error(f"Error in send_fcm_notification_to_user: {e}")
        return 0


def send_fcm_notifications_batch(tokens_list, title, body, url=None, data=None):
    """Send FCM notifications to multiple tokens at once (for broadcast notifications)."""
    if not _get_main().FIREBASE_INITIALIZED or not tokens_list:
        return 0
    
    try:
        messages = []
        for token_doc in tokens_list:
            token_user_id = token_doc.get('user_id')
            badge_count = _get_user_badge_count(str(token_user_id)) if token_user_id else 1

            messages.append(messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data={
                    'url': url or '/',
                    'click_action': url or '/',
                    **(data or {})
                },
                token=token_doc['token'],
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        icon='ic_stat_notification',
                        color='#3e2217',
                        channel_id='default',
                        notification_count=badge_count,
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={'apns-priority': '10'},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(
                                title=title,
                                body=body
                            ),
                            badge=badge_count,
                            sound='default',
                            mutable_content=True,
                        ),
                    ),
                ),
            ))
        
        sent_count = 0
        for i in range(0, len(messages), 500):
            batch = messages[i:i+500]
            response = messaging.send_each(batch)
            sent_count += response.success_count
            
            for idx, send_response in enumerate(response.responses):
                if not send_response.success:
                    if hasattr(send_response, 'exception') and isinstance(send_response.exception, messaging.UnregisteredError):
                        database.fcm_tokens_conf.delete_one({'_id': tokens_list[i + idx]['_id']})
        
        return sent_count
    except Exception as e:
        _get_app().logger.error(f"Error in send_fcm_notifications_batch: {e}")
        return 0


@rq.job
def send_push_notification_for_comment(comment_id_str, post_slug):
    """Send push notification to post author and parent comment author."""
    try:
        comment = database.comments_conf.find_one({'_id': ObjectId(comment_id_str)})
        if not comment:
            _get_app().logger.error(f"Comment {comment_id_str} not found for push notification")
            return

        post = database.posts_conf.find_one({'slug': post_slug})
        if not post:
            _get_app().logger.error(f"Post with slug {post_slug} not found for comment notification")
            return

        commenter_id = comment.get('author_id')
        commenter_username = comment.get('author_username', 'Someone')
        post_author_id = post.get('author_id')
        
        post_url = None
        with _get_app().app_context():
            try:
                post_url = url_for('view_post', slug=post_slug, _external=True)
            except RuntimeError:
                base_url = os.environ.get('FLASK_URL', 'https://echowithin.xyz')
                post_url = f"{base_url}/post/{post_slug}"

        notified_user_ids = set()

        parent_id = comment.get('parent_id')
        if parent_id:
            parent_comment = database.comments_conf.find_one({'_id': parent_id})
            if parent_comment:
                parent_author_id = parent_comment.get('author_id')
                if parent_author_id and str(parent_author_id) != str(commenter_id):
                    title = "New Reply to Your Comment"
                    body = f'{commenter_username} replied to your comment on "{post.get("title")}"'
                    send_push_notification_to_user(
                        str(parent_author_id), 
                        title, 
                        body, 
                        url=post_url, 
                        tag=f'reply-{comment_id_str}',
                        extra_data={'type': 'comment_reply', 'comment_id': comment_id_str}
                    )
                    notified_user_ids.add(str(parent_author_id))

        if post_author_id and str(post_author_id) != str(commenter_id) and str(post_author_id) not in notified_user_ids:
            title = "New Comment on Your Post"
            body = f'{commenter_username} commented on "{post.get("title")}"'
            send_push_notification_to_user(
                str(post_author_id), 
                title, 
                body, 
                url=post_url, 
                tag=f'comment-{comment_id_str}',
                extra_data={'type': 'comment', 'comment_id': comment_id_str}
            )

        _get_app().logger.info(f"Sent comment push notifications for comment {comment_id_str}")
    except Exception as e:
        _get_app().logger.error(f"Error in send_push_notification_for_comment: {e}", exc_info=True)


@rq.job
def send_log_email_job():
    """
    A background job that sends the contents of the log file via email
    and then rotates the log file.
    """
    log_file_path = 'echowithin.log'
    if not os.path.exists(log_file_path) or os.path.getsize(log_file_path) == 0:
        _get_app().logger.info("Log file is empty or does not exist. Skipping email.")
        return

    try:
        with _get_app().app_context():
            developer_email = get_env_variable('MY_EMAIL')
            msg = Message(
                subject=f"EchoWithin Weekly Log Report - {datetime.date.today().isoformat()}",
                sender=get_env_variable('MAIL_USERNAME'),
                recipients=[developer_email]
            )
            msg.body = "Attached is the latest log file from the EchoWithin application."

            with open(log_file_path, 'rb') as f:
                msg.attach(
                    "echowithin.log",
                    "text/plain",
                    f.read()
                )

            _get_mail().send(msg)
            _get_app().logger.info(f"Log file email sent to {developer_email}.")
    except Exception as e:
        _get_app().logger.error(f"Failed to send log file email: {e}", exc_info=True)


@rq.job
def send_ntfy_notification(message, title, tags=""):
    """Sends a push notification to an ntfy topic as a background job."""
    ntfy_topic = os.environ.get('NTFY_TOPIC')
    if not ntfy_topic:
        _get_app().logger.info("NTFY_TOPIC not set, skipping notification.")
        return

    try:
        headers = {}
        if title:
            headers['Title'] = title
        if tags:
            headers['Tags'] = tags

        ntfy_user = os.environ.get('NTFY_USERNAME')
        ntfy_pass = os.environ.get('NTFY_PASSWORD')
        auth = (ntfy_user, ntfy_pass) if ntfy_user and ntfy_pass else None

        resp = requests.post(
            f"https://ntfy.sh/{ntfy_topic}",
            data=message.encode('utf-8'),
            headers=headers,
            timeout=5,
            auth=auth
        )

        if resp.ok:
            _get_app().logger.info(f"Successfully sent ntfy notification to topic: {ntfy_topic} (status {resp.status_code})")
        else:
            _get_app().logger.error(f"ntfy send failed for topic {ntfy_topic}: status={resp.status_code}, body={resp.text}")
    except Exception as e:
        _get_app().logger.error(f"Failed to send ntfy notification: {e}", exc_info=True)
