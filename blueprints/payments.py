from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, os, hashlib, hmac, requests
from urllib.parse import urljoin
from security import limits

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('payments', __name__, template_folder='templates')

# Premium grant period in days
PREMIUM_GRANT_DAYS = 31


def _is_donation(metadata):
    """Check if metadata indicates a donation payment.
    
    Paystack may serialize boolean metadata values as strings (e.g., "false"
    instead of false), which are truthy in Python. This helper normalizes
    the check to handle both boolean and string representations.
    """
    val = metadata.get('is_donation')
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ('true', '1', 'yes')


def _grant_premium(user_id, reference, amount_ksh):
    """Idempotently grant premium for a verified Paystack transaction.

    Returns True if the grant was applied (or already applied for this
    reference), False if the reference was already consumed for a
    different purpose.

    Security notes:
      - Every grant is recorded in payment_grants keyed by the Paystack
        `reference` (unique index) so a single payment can never be
        replayed to extend premium indefinitely.
      - Only non-donation transactions that match the premium price are
        granted here; the caller is responsible for amount verification.
    """
    import main as m

    reference = str(reference or '').strip()
    if not reference:
        return False

    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        m.payment_grants_conf.insert_one({
            'reference': reference,
            'user_id': user_id,
            'grant_type': 'premium',
            'amount_ksh': amount_ksh,
            'created_at': now,
        })
    except Exception:
        # Reference already recorded -> this is a replay. Idempotent:
        # check whether the same user already holds this grant, and if so
        # treat it as a success (no-op) rather than extending premium again.
        existing = m.payment_grants_conf.find_one({'reference': reference})
        if existing and existing.get('grant_type') == 'premium' and str(existing.get('user_id')) == str(user_id):
            return True
        # Reference consumed by a different transaction/user -> refuse.
        return False

    result = m.users_conf.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {
            'account_tier': 'premium',
            'premium_until': now + datetime.timedelta(days=PREMIUM_GRANT_DAYS),
            'last_payment_reference': reference
        }}
    )
    return result.modified_count >= 0 or result.acknowledged


def _verify_amount_ksh(amount_kobo, is_donation):
    """Verify the paid amount matches expectations.

    Donations accept any amount (already bounded client-side). Premium
    purchases must exactly equal the premium price in KSH.
    """
    import main as m
    amount_ksh = int(amount_kobo or 0) // 100
    if is_donation:
        return True, amount_ksh
    if amount_ksh == m.PREMIUM_PRICE_KSH:
        return True, amount_ksh
    return False, amount_ksh


@bp.route('/api/paystack/initialize', methods=['POST'])
@login_required
@limits(calls=10, period=60)
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
            is_donation = _is_donation(metadata)
            amount_ksh_ok, amount_ksh = _verify_amount_ksh(result['data'].get('amount', 0), is_donation)

            # SECURITY: verify the transaction actually belongs to this user.
            tx_user_id = metadata.get('user_id')
            if str(tx_user_id) != str(current_user.id):
                current_app.logger.warning(
                    f"Paystack callback ownership mismatch: reference={reference} "
                    f"session_user={current_user.id} tx_user={tx_user_id}"
                )
                flash("This payment is not associated with your account.", "danger")
                return redirect(url_for('profile.profile_settings', username=current_user.username))

            if is_donation:
                flash(f"Thank you for your generous donation of KSH {amount_ksh:,}! Your support keeps EchoWithin running.", "success")
            else:
                if not amount_ksh_ok:
                    current_app.logger.warning(
                        f"Paystack callback amount mismatch: reference={reference} paid_ksh={amount_ksh} expected_ksh={m.PREMIUM_PRICE_KSH}"
                    )
                    flash("Payment verification failed: amount does not match the premium plan.", "danger")
                    return redirect(url_for('profile.profile_settings', username=current_user.username))

                granted = _grant_premium(current_user.id, reference, amount_ksh)
                if granted:
                    flash("Payment successful! You are now a Premium member.", "success")
                else:
                    flash("This payment reference has already been used.", "warning")
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
    # SECURITY: constant-time signature comparison
    if not signature or not hmac.compare_digest(hash_sign, signature):
        return 'Invalid signature', 400
    try:
        event = request.json
        event_type = event.get('event')
        data = event.get('data', {})
        if event_type == 'charge.success':
            email = data.get('customer', {}).get('email')
            metadata = data.get('metadata', {})
            reference = data.get('reference')
            user_id_str = metadata.get('user_id')
            user = None
            if user_id_str:
                try:
                    user = m.users_conf.find_one({'_id': ObjectId(user_id_str)})
                except Exception:
                    user = None
            elif email:
                user = m.users_conf.find_one({'email': email})
            if user and not _is_donation(metadata):
                is_donation = False
                amount_ksh_ok, amount_ksh = _verify_amount_ksh(data.get('amount', 0), is_donation)
                if amount_ksh_ok:
                    _grant_premium(user['_id'], reference, amount_ksh)
                else:
                    current_app.logger.warning(
                        f"Paystack webhook amount mismatch: reference={reference} paid_ksh={amount_ksh} expected_ksh={m.PREMIUM_PRICE_KSH}"
                    )
        return '', 200
    except Exception as e:
        current_app.logger.error(f"Paystack webhook error: {str(e)}")
        return 'Error processing webhook', 500
