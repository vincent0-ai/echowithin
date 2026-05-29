from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
import main as m

bp = Blueprint('push_bp', __name__, template_folder='templates')


@bp.route('/api/fcm/register', methods=['POST'])
@login_required
def register_fcm_token():
    import main as m
    try:
        data = request.get_json()
        data = request.get_json()
        token = data.get('token')
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        m.fcm_tokens_conf.update_one(
            {'user_id': ObjectId(current_user.id), 'token': token},
            {'$set': {
                'user_id': ObjectId(current_user.id),
                'token': token,
                'updated_at': datetime.datetime.now(datetime.timezone.utc),
                'platform': data.get('platform', 'android'),
            }},
            upsert=True
        )
        current_app.logger.info(f"FCM token registered for user {current_user.id}")
        return jsonify({'success': True, 'message': 'Token registered'})
    except Exception as e:
        current_app.logger.error(f"Error registering FCM token: {e}")
        return jsonify({'error': 'Failed to register token'}), 500


@bp.route('/api/fcm/unregister', methods=['POST'])
@login_required
def unregister_fcm_token():
    import main as m
    try:
        data = request.get_json()
        token = data.get('token')
        if token:
            m.fcm_tokens_conf.delete_one({'user_id': ObjectId(current_user.id), 'token': token})
        else:
            m.fcm_tokens_conf.delete_many({'user_id': ObjectId(current_user.id)})
        return jsonify({'success': True, 'message': 'Token unregistered'})
    except Exception as e:
        current_app.logger.error(f"Error unregistering FCM token: {e}")
        return jsonify({'error': 'Failed to unregister token'}), 500


@bp.route('/api/push/vapid-public-key')
def get_vapid_public_key():
    import main as m
    if not m.VAPID_PUBLIC_KEY:
        return jsonify({'error': 'Push notifications not configured'}), 503
    return jsonify({'publicKey': m.VAPID_PUBLIC_KEY})


@bp.route('/api/push/subscribe', methods=['POST'])
@m.csrf.exempt
@login_required
def subscribe_push():
    if not m.VAPID_PUBLIC_KEY or not m.VAPID_PRIVATE_KEY:
        return jsonify({'error': 'Push notifications not configured'}), 503
    if not m.is_same_origin_request():
        current_app.logger.warning(f"Blocked cross-origin push subscribe attempt for user {current_user.username}")
        return jsonify({'error': 'Forbidden'}), 403
    try:
        data = request.get_json(silent=True)
    except (OSError, Exception) as e:
        current_app.logger.warning(f"Failed to read push subscribe request body for user {current_user.username}: {e}")
        return jsonify({'error': 'Invalid request body'}), 400
    if not data or not data.get('endpoint') or not data.get('keys'):
        return jsonify({'error': 'Invalid subscription data'}), 400
    try:
        user_id = ObjectId(current_user.id)
        new_endpoint = data['endpoint']
        delete_result = m.push_subscriptions_conf.delete_many({
            'user_id': user_id,
            'endpoint': {'$ne': new_endpoint}
        })
        if delete_result.deleted_count > 0:
            current_app.logger.info(f"Cleaned up {delete_result.deleted_count} old push subscription(s) for user {current_user.username}")
        now = datetime.datetime.now(datetime.timezone.utc)
        m.push_subscriptions_conf.update_one(
            {'user_id': user_id, 'endpoint': new_endpoint},
            {
                '$set': {
                    'user_id': user_id,
                    'endpoint': new_endpoint,
                    'keys': data['keys'],
                    'updated_at': now,
                    'user_agent': request.headers.get('User-Agent', '')[:200]
                },
                '$setOnInsert': {
                    'created_at': now
                }
            },
            upsert=True
        )
        current_app.logger.info(f"Push subscription saved for user {current_user.username}")
        return jsonify({'success': True, 'message': 'Subscribed to push notifications'})
    except Exception as e:
        current_app.logger.error(f"Failed to save push subscription: {e}")
        return jsonify({'error': 'Failed to save subscription'}), 500


@bp.route('/api/push/unsubscribe', methods=['POST'])
@m.csrf.exempt
@login_required
def unsubscribe_push():
    if not m.is_same_origin_request():
        current_app.logger.warning(f"Blocked cross-origin push unsubscribe attempt for user {current_user.username}")
        return jsonify({'error': 'Forbidden'}), 403
    try:
        data = request.get_json(silent=True)
    except (OSError, Exception) as e:
        current_app.logger.warning(f"Failed to read push unsubscribe request body for user {current_user.username}: {e}")
        return jsonify({'error': 'Invalid request body'}), 400
    if not data or not data.get('endpoint'):
        return jsonify({'error': 'Invalid request'}), 400
    try:
        result = m.push_subscriptions_conf.delete_one({
            'user_id': ObjectId(current_user.id),
            'endpoint': data['endpoint']
        })
        if result.deleted_count > 0:
            current_app.logger.info(f"Push subscription removed for user {current_user.username}")
            return jsonify({'success': True, 'message': 'Unsubscribed from push notifications'})
        else:
            return jsonify({'success': True, 'message': 'Subscription not found'})
    except Exception as e:
        current_app.logger.error(f"Failed to remove push subscription: {e}")
        return jsonify({'error': 'Failed to unsubscribe'}), 500


@bp.route('/api/push/status')
@login_required
def push_subscription_status():
    import main as m
    try:
        count = m.push_subscriptions_conf.count_documents({'user_id': ObjectId(current_user.id)})
        return jsonify({'subscribed': count > 0, 'subscription_count': count})
    except Exception as e:
        current_app.logger.error(f"Failed to check push subscription status: {e}")
        return jsonify({'error': 'Failed to check status'}), 500


@bp.route('/api/notifications/unread-count')
@login_required
def get_unread_notification_count():
    import main as m
    user_id_str = str(current_user.id)
    cache_key = f'unread_count:{user_id_str}'
    if m.redis_cache:
        try:
            cached = m.redis_cache.get(cache_key)
            if cached is not None:
                return jsonify({'unread_count': int(cached)})
        except Exception:
            pass
    now = datetime.datetime.now(datetime.timezone.utc)
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'last_activity_check': 1, 'activity_check_per_post': 1})
    if not user_doc:
        return jsonify({'unread_count': 0})
    last_check = user_doc.get('last_activity_check')
    if last_check and last_check.tzinfo is None:
        last_check = last_check.replace(tzinfo=datetime.timezone.utc)
    per_post_times = user_doc.get('activity_check_per_post', {})
    try:
        pipeline = [
            {'$match': {
                'created_at': {'$gt': last_check} if last_check else {'$exists': True},
                'is_deleted': {'$ne': True}
            }},
            {'$facet': {
                'total_count': [{'$count': 'count'}],
                'unread_by_type': [
                    {'$group': {
                        '_id': {'$cond': [{'$eq': ['$type', 'comment']}, '$target_id', None]},
                        'count': {'$sum': 1}
                    }}
                ]
            }}
        ]
        result = list(m.activities_conf.aggregate(pipeline))
        total_count = result[0]['total_count'][0]['count'] if result[0]['total_count'] else 0
        if total_count == 0:
            if m.redis_cache:
                try:
                    m.redis_cache.setex(cache_key, 30, 0)
                except Exception:
                    pass
            return jsonify({'unread_count': 0})
        cutoff = last_check or datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        unread_pipeline = [
            {'$match': {
                'target_type': 'post',
                'created_at': {'$gt': cutoff},
                'is_deleted': {'$ne': True}
            }},
            {'$group': {
                '_id': '$target_id',
                'last_comment_at': {'$max': '$created_at'},
            }}
        ]
        unread_activities = list(m.activities_conf.aggregate(unread_pipeline))
        unread_count = 0
        for activity in unread_activities:
            target_id = activity.get('_id')
            if target_id:
                last_viewed_str = per_post_times.get(str(target_id))
                if last_viewed_str:
                    try:
                        last_viewed = datetime.datetime.fromisoformat(last_viewed_str)
                        if last_viewed.tzinfo is None:
                            last_viewed = last_viewed.replace(tzinfo=datetime.timezone.utc)
                        if activity['last_comment_at'] > last_viewed:
                            unread_count += 1
                    except Exception:
                        unread_count += 1
                else:
                    unread_count += 1
            else:
                unread_count += 1
        unread_count += total_count
        if m.redis_cache:
            try:
                m.redis_cache.setex(cache_key, 30, unread_count)
            except Exception:
                pass
        return jsonify({'unread_count': unread_count})
    except Exception as e:
        current_app.logger.error(f"Failed to compute unread count: {e}")
        return jsonify({'unread_count': 0})
