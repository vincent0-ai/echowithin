from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, os, hashlib, hmac, requests
from urllib.parse import urljoin

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('payments', __name__, template_folder='templates')


@bp.route('/api/paystack/initialize', methods=['POST'])
@login_required
def paystack_initialize():
    import main as m
    data_in = request.get_json() or {}
    is_donation = data_in.get('is_donation', False)
    if not is_donation and current_user.is_premium and not current_user.is_trial:
        return jsonify({'error': 'You are already a Premium member'}), 400
    secret_key = os.environ.get('PAYSTACK_SECRET_KEY')
    plan_code = os.environ.get('PAYSTACK_PLAN_CODE')
    if not secret_key:
        return jsonify({'error': 'Payment integration is not configured yet. Please contact support.'}), 500
    url = "https://api.paystack.co/transaction/initialize"
    headers = {"Authorization": f"Bearer {secret_key}", "Content-Type": "application/json"}
    callback_url = urljoin(request.host_url, url_for('payments.paystack_callback'))
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    user_email = user_doc.get('email') if user_doc else None
    if not user_email:
        user_email = f"{current_user.username}@echowithin.xyz"
    if is_donation:
        amount_ksh = data_in.get('amount', m.PREMIUM_PRICE_KSH)
        try:
            amount_ksh = int(amount_ksh)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount'}), 400
        if amount_ksh < 10 or amount_ksh > 100000:
            return jsonify({'error': 'Donation amount must be between KSH 10 and KSH 100,000'}), 400
    else:
        amount_ksh = m.PREMIUM_PRICE_KSH
    data = {
        "email": user_email,
        "amount": amount_ksh * 100,
        "currency": "KES",
        "callback_url": callback_url,
        "metadata": {"user_id": str(current_user.id), "is_donation": is_donation}
    }
    if plan_code and not is_donation:
        data["plan"] = plan_code
    try:
        response = requests.post(url, headers=headers, json=data)
        result = response.json()
        if result.get('status'):
            return jsonify({'authorization_url': result['data']['authorization_url']})
        else:
            return jsonify({'error': result.get('message', 'Failed to initialize payment')}), 400
    except Exception as e:
        current_app.logger.error(f"Paystack init error: {str(e)}")
        return jsonify({'error': 'An error occurred connecting to the payment provider.'}), 500


@bp.route('/paystack/callback')
@login_required
def paystack_callback():
    import main as m
    reference = request.args.get('reference')
    if not reference:
        flash("Invalid payment callback.", "danger")
        return redirect(url_for('profile.profile_settings', username=current_user.username))
    secret_key = os.environ.get('PAYSTACK_SECRET_KEY')
    if not secret_key:
        flash("Payment configuration error.", "danger")
        return redirect(url_for('profile.profile_settings', username=current_user.username))
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {secret_key}"}
    try:
        response = requests.get(url, headers=headers)
        result = response.json()
        if result.get('status') and result['data']['status'] == 'success':
            metadata = result['data'].get('metadata', {})
            if metadata.get('is_donation'):
                amount_kobo = result['data'].get('amount', 0)
                amount_ksh = amount_kobo // 100
                flash(f"Thank you for your generous donation of KSH {amount_ksh:,}! Your support keeps EchoWithin running.", "success")
            else:
                m.users_conf.update_one(
                    {'_id': current_user.id},
                    {'$set': {
                        'account_tier': 'premium',
                        'premium_until': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=31)
                    }}
                )
                flash("Payment successful! You are now a Premium member.", "success")
        else:
            flash(f"Payment verification failed: {result.get('message', 'Unknown error')}", "danger")
    except Exception as e:
        current_app.logger.error(f"Paystack verify error: {str(e)}")
        flash("An error occurred verifying your payment. Please contact support.", "danger")
    return redirect(url_for('profile.profile_settings', username=current_user.username))


@bp.route('/api/paystack/webhook', methods=['POST'])
@csrf_exempt
def paystack_webhook():
    import main as m
    secret_key = os.environ.get('PAYSTACK_SECRET_KEY')
    if not secret_key:
        return 'Not configured', 500
    signature = request.headers.get('x-paystack-signature')
    payload = request.get_data()
    hash_sign = hmac.new(secret_key.encode('utf-8'), payload, hashlib.sha512).hexdigest()
    if hash_sign != signature:
        return 'Invalid signature', 400
    try:
        event = request.json
        event_type = event.get('event')
        data = event.get('data', {})
        if event_type == 'charge.success':
            email = data.get('customer', {}).get('email')
            metadata = data.get('metadata', {})
            user_id_str = metadata.get('user_id')
            user = None
            if user_id_str:
                user = m.users_conf.find_one({'_id': ObjectId(user_id_str)})
            elif email:
                user = m.users_conf.find_one({'email': email})
            if user and not metadata.get('is_donation'):
                m.users_conf.update_one(
                    {'_id': user['_id']},
                    {'$set': {
                        'account_tier': 'premium',
                        'premium_until': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=31)
                    }}
                )
        return '', 200
    except Exception as e:
        current_app.logger.error(f"Paystack webhook error: {str(e)}")
        return 'Error processing webhook', 500
