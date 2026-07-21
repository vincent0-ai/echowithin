from flask import Blueprint, request, jsonify, render_template, current_app, url_for
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
import hashlib
from security import limits

bp = Blueprint('bonds', __name__, template_folder='templates')

# Goal categories
GOAL_CATEGORIES = [
    'Health', 'Finance', 'Education', 'Relationship',
    'Personal Growth', 'Creative', 'Custom'
]

BOND_COOLDOWN_DAYS = 7

# Bond types for personalisation
BOND_TYPES = {
    'partner':        {'label': 'Love Partner',           'icon': '❤️'},
    'friend':         {'label': 'Friend',                 'icon': '🤝'},
    'study_mate':     {'label': 'Study Mate',             'icon': '📚'},
    'family':         {'label': 'Family',                 'icon': '🏠'},
    'accountability': {'label': 'Accountability Partner',  'icon': '🎯'},
    'custom':         {'label': 'Custom',                 'icon': '🔗'},
}

# Mood options for the bond mood tracker
BOND_MOODS = {
    'great': {'emoji': '🌟', 'label': 'Great'},
    'good':  {'emoji': '😊', 'label': 'Good'},
    'okay':  {'emoji': '😐', 'label': 'Okay'},
    'down':  {'emoji': '😔', 'label': 'Down'},
    'tough': {'emoji': '💪', 'label': 'Tough but trying'},
}

# Question bank — curated conversation starters personalised by bond type
QUESTION_BANK = {
    'universal': [
        "What's something you've been thinking about a lot lately?",
        "If you could have dinner with anyone, living or dead, who would it be and why?",
        "What's a small thing that made you smile recently?",
        "What's a skill you wish you had?",
        "What does your ideal Sunday look like?",
        "What's something you believed as a child that you now find amusing?",
        "If you could live anywhere in the world for a year, where would you go?",
        "What's a book, movie, or song that changed your perspective?",
        "What's the best piece of advice you've ever received?",
        "What are you most grateful for right now?",
        "What's something you'd like to learn in the next year?",
        "If you could solve one problem in the world, what would it be?",
        "What's a memory that always makes you laugh?",
        "What does success mean to you?",
        "What's something about you that most people don't know?",
    ],
    'partner': [
        "What's your favourite memory of us together?",
        "What's something I do that makes you feel loved?",
        "Where do you see us in five years?",
        "What's a dream you'd like us to pursue together?",
        "What song reminds you of our relationship?",
        "What's one thing you'd like us to do more of together?",
        "What was your first impression of me?",
        "What's something new you'd like us to try together?",
        "How can I better support you right now?",
        "What's your love language, and do you feel it's being met?",
        "What's a challenge we've overcome that made us stronger?",
        "If we could take a trip anywhere tomorrow, where would we go?",
        "What's something about our future that excites you?",
        "What's a little thing I do that means a lot to you?",
        "What does a perfect evening together look like for you?",
    ],
    'friend': [
        "What's the funniest thing that's happened to you recently?",
        "If we could go on any adventure together, what would it be?",
        "What's a hobby you've been wanting to pick up?",
        "What's the best meal you've had this month?",
        "If you won the lottery tomorrow, what's the first thing you'd do?",
        "What's a hot take you have that might be unpopular?",
        "What show or movie are you obsessed with right now?",
        "What's the most spontaneous thing you've ever done?",
        "If you could relive one day of your life, which would it be?",
        "What's your go-to comfort food when you're having a rough day?",
        "What's a talent you have that would surprise people?",
        "If we started a business together, what would it be?",
        "What's the best concert or event you've ever been to?",
        "What's a life lesson you learned the hard way?",
        "What three words would your other friends use to describe you?",
    ],
    'study_mate': [
        "What's the most interesting thing you've learned recently?",
        "What study technique works best for you?",
        "What's a subject you wish you could master?",
        "How do you stay motivated when studying gets tough?",
        "What's your biggest academic goal this semester?",
        "If you could take any course in the world, what would it be?",
        "What's the most useful skill your education has given you?",
        "How do you balance study time with personal time?",
        "What's a resource or tool that's been a game-changer for you?",
        "What career path are you most excited about?",
        "What's a topic you could talk about for hours?",
        "How do you handle academic pressure or deadlines?",
    ],
    'family': [
        "What's a family tradition you love most?",
        "What's a story about our family that always gets told at gatherings?",
        "What value from our family do you carry with you every day?",
        "What's your favourite childhood memory with family?",
        "Is there a family recipe you'd love to learn or preserve?",
        "What's something you'd like our family to do more of?",
        "Who in our family inspires you the most, and why?",
        "What's a lesson a family member taught you that stuck?",
        "If we could plan a family trip, where would you want to go?",
        "What's something you appreciate about our family that you didn't when you were younger?",
    ],
    'accountability': [
        "What's the one goal you're most focused on right now?",
        "What habit are you trying to build or break?",
        "What's your biggest challenge in staying consistent?",
        "How do you measure your progress?",
        "What's one thing you accomplished this week that you're proud of?",
        "What does discipline look like for you on a daily basis?",
        "What's a setback you've faced recently, and how did you handle it?",
        "What's your morning routine, and is it serving you well?",
        "Where do you want to be in 3 months?",
        "What's one area of your life that needs the most attention right now?",
        "What motivates you to keep going when things get hard?",
        "What's a boundary you need to set to protect your goals?",
    ],
}

# Bond anniversary milestones (days -> label)
_ANNIVERSARY_MILESTONES = [
    (7,    '1 week'),
    (30,   '1 month'),
    (90,   '3 months'),
    (180,  '6 months'),
    (365,  '1 year'),
    (730,  '2 years'),
    (1095, '3 years'),
]


def _get_bond_anniversary(accepted_at):
    """Return the highest anniversary milestone reached, or None."""
    if not accepted_at:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    delta_days = (now - accepted_at).days
    milestone = None
    for days, label in _ANNIVERSARY_MILESTONES:
        if delta_days >= days:
            milestone = label
    return milestone


def _get_daily_question(bond_doc):
    """Deterministic daily question selection based on bond type + date."""
    bond_type = bond_doc.get('bond_type', 'custom')
    today_str = datetime.date.today().isoformat()
    bond_id_str = str(bond_doc['_id'])

    # Combine type-specific + universal questions
    type_questions = QUESTION_BANK.get(bond_type, [])
    universal = QUESTION_BANK.get('universal', [])
    # Weight type-specific 2:1 over universal
    pool = type_questions + type_questions + universal
    if not pool:
        pool = universal or ["What's on your mind today?"]

    # Deterministic selection
    hash_input = f"{bond_id_str}:{today_str}"
    hash_val = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)
    idx = hash_val % len(pool)

    question = pool[idx]
    # Determine category
    if question in type_questions:
        category = BOND_TYPES.get(bond_type, {}).get('label', 'Custom')
    else:
        category = 'Universal'

    return question, category


def _update_bond_streak(bond_doc):
    """Update streak count for a bond based on today's activity.
    Called from any activity endpoint (checkin, journal, mood, qotd, nudge).
    """
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()
    last_streak = bond_doc.get('last_streak_date')

    if last_streak:
        last_date = last_streak.date() if isinstance(last_streak, datetime.datetime) else last_streak
        if last_date == today:
            return  # Already counted today
        elif last_date == today - datetime.timedelta(days=1):
            m.bonds_conf.update_one(
                {'_id': bond_doc['_id']},
                {'$inc': {'streak_count': 1}, '$set': {'last_streak_date': now}}
            )
        else:
            m.bonds_conf.update_one(
                {'_id': bond_doc['_id']},
                {'$set': {'streak_count': 1, 'last_streak_date': now}}
            )
    else:
        m.bonds_conf.update_one(
            {'_id': bond_doc['_id']},
            {'$set': {'streak_count': 1, 'last_streak_date': now}}
        )


def _get_user_bonds(user_oid, status='active'):
    """Get all bonds for a user with a given status."""
    import main as m
    return list(m.bonds_conf.find({
        'status': status,
        '$or': [{'user_a_id': user_oid}, {'user_b_id': user_oid}]
    }).sort('accepted_at', -1))


def _get_partner_id_from_bond(bond_doc, user_id_str):
    """Get the partner's ObjectId string from a bond document."""
    if str(bond_doc['user_a_id']) == user_id_str:
        return str(bond_doc['user_b_id'])
    return str(bond_doc['user_a_id'])


def _is_bond_participant(bond_doc, user_id_str):
    """Check if user is a participant in the bond."""
    return user_id_str in (str(bond_doc['user_a_id']), str(bond_doc['user_b_id']))


def _get_bond_status_between(user_a_oid, user_b_oid):
    """Get bond status between two users. Returns dict with status info."""
    import main as m
    bond = m.bonds_conf.find_one({
        '$or': [
            {'user_a_id': user_a_oid, 'user_b_id': user_b_oid},
            {'user_a_id': user_b_oid, 'user_b_id': user_a_oid}
        ],
        'status': {'$in': ['pending', 'active']}
    })
    if not bond:
        return {'status': 'none'}
    if bond['status'] == 'pending':
        is_requester = str(bond['requested_by']) == str(user_a_oid)
        return {
            'status': 'pending',
            'bond_id': str(bond['_id']),
            'is_requester': is_requester
        }
    return {
        'status': 'active',
        'bond_id': str(bond['_id']),
        'label': bond.get('label', '')
    }


# --- Page Route ---

@bp.route('/bonds')
@login_required
def bonds_page():
    """Render the bonds page."""
    import main as m
    user_oid = ObjectId(current_user.id)

    # Get active bonds with partner info
    active_bonds = _get_user_bonds(user_oid, 'active')
    bonds_data = []
    for bond in active_bonds:
        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        partner = m.users_conf.find_one(
            {'_id': ObjectId(partner_id)},
            {'username': 1, 'profile_image_url': 1}
        )
        if not partner:
            continue

        # Count active goals
        goal_count = m.bond_goals_conf.count_documents({
            'bond_id': bond['_id'],
            'status': {'$in': ['active', 'proposed']}
        })

        bond_type = bond.get('bond_type', 'custom')
        type_info = BOND_TYPES.get(bond_type, BOND_TYPES['custom'])
        anniversary = _get_bond_anniversary(bond.get('accepted_at'))

        bonds_data.append({
            'id': str(bond['_id']),
            'partner_id': partner_id,
            'partner_username': partner['username'],
            'partner_avatar': partner.get('profile_image_url'),
            'label': bond.get('label', ''),
            'bond_type': bond_type,
            'bond_type_label': type_info['label'],
            'bond_type_icon': type_info['icon'],
            'accepted_at': bond.get('accepted_at'),
            'streak_count': bond.get('streak_count', 0),
            'goal_count': goal_count,
            'anniversary': anniversary
        })

    # Get pending received requests
    pending_received = list(m.bonds_conf.find({
        'status': 'pending',
        '$or': [{'user_a_id': user_oid}, {'user_b_id': user_oid}],
        'requested_by': {'$ne': user_oid}
    }).sort('created_at', -1))

    pending_data = []
    for bond in pending_received:
        requester_id = str(bond['requested_by'])
        requester = m.users_conf.find_one(
            {'_id': bond['requested_by']},
            {'username': 1, 'profile_image_url': 1}
        )
        if requester:
            bond_type = bond.get('bond_type', 'custom')
            type_info = BOND_TYPES.get(bond_type, BOND_TYPES['custom'])
            pending_data.append({
                'id': str(bond['_id']),
                'from_user_id': requester_id,
                'from_username': requester['username'],
                'from_avatar': requester.get('profile_image_url'),
                'label': bond.get('label', ''),
                'bond_type_label': type_info['label'],
                'bond_type_icon': type_info['icon'],
                'created_at': bond.get('created_at')
            })

    # Get pending sent requests
    pending_sent = list(m.bonds_conf.find({
        'status': 'pending',
        'requested_by': user_oid
    }).sort('created_at', -1))

    sent_data = []
    for bond in pending_sent:
        target_id = _get_partner_id_from_bond(bond, str(current_user.id))
        target = m.users_conf.find_one(
            {'_id': ObjectId(target_id)},
            {'username': 1, 'profile_image_url': 1}
        )
        if target:
            bond_type = bond.get('bond_type', 'custom')
            type_info = BOND_TYPES.get(bond_type, BOND_TYPES['custom'])
            sent_data.append({
                'id': str(bond['_id']),
                'to_user_id': target_id,
                'to_username': target['username'],
                'to_avatar': target.get('profile_image_url'),
                'label': bond.get('label', ''),
                'bond_type_label': type_info['label'],
                'bond_type_icon': type_info['icon'],
                'created_at': bond.get('created_at')
            })

    # Get user tier for template (streak shield availability)
    user_doc = m.users_conf.find_one({'_id': user_oid})
    user_tier = m.get_user_tier(user_doc) if user_doc else 'free'

    return render_template('bonds.html',
                           active_page='bonds',
                           bonds=bonds_data,
                           pending_received=pending_data,
                           pending_sent=sent_data,
                           goal_categories=GOAL_CATEGORIES,
                           bond_types=BOND_TYPES,
                           bond_moods=BOND_MOODS,
                           user_tier=user_tier)


# --- Bond Management ---

@bp.route('/api/bonds/request/<target_user_id>', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_request(target_user_id):
    """Send a bond request to another user."""
    import main as m
    try:
        data = request.get_json() or {}
        label = data.get('label', '').strip()[:50]
        bond_type = data.get('bond_type', 'custom').strip()
        if bond_type not in BOND_TYPES:
            bond_type = 'custom'

        user_oid = ObjectId(current_user.id)
        target_oid = ObjectId(target_user_id)

        if str(user_oid) == target_user_id:
            return jsonify({'error': 'Cannot bond with yourself'}), 400

        # Check target exists
        target = m.users_conf.find_one({'_id': target_oid}, {'username': 1})
        if not target:
            return jsonify({'error': 'User not found'}), 404

        # Check DM permission
        if not m.can_dm(str(user_oid), target_user_id):
            return jsonify({'error': 'You need accepted DM permission first.'}), 403

        # Check bond limits
        user_doc = m.users_conf.find_one({'_id': user_oid})
        tier = m.get_user_tier(user_doc)
        max_bonds = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_bonds', 3)
        active_count = m.bonds_conf.count_documents({
            'status': 'active',
            '$or': [{'user_a_id': user_oid}, {'user_b_id': user_oid}]
        })
        if active_count >= max_bonds:
            return jsonify({'error': f'You already have {max_bonds} active bonds.'}), 400

        # Check cooldown from broken bonds
        cooldown_cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=BOND_COOLDOWN_DAYS)
        recent_break = m.bonds_conf.find_one({
            'status': 'broken',
            'broken_by': user_oid,
            'broken_at': {'$gte': cooldown_cutoff}
        })
        if recent_break:
            return jsonify({'error': f'You must wait {BOND_COOLDOWN_DAYS} days after breaking a bond.'}), 400

        # Check existing bond or pending request
        existing = m.bonds_conf.find_one({
            '$or': [
                {'user_a_id': user_oid, 'user_b_id': target_oid},
                {'user_a_id': target_oid, 'user_b_id': user_oid}
            ],
            'status': {'$in': ['pending', 'active']}
        })
        if existing:
            if existing['status'] == 'active':
                return jsonify({'error': 'You are already bonded with this user.'}), 409
            if existing['status'] == 'pending':
                # If the target sent us a request, auto-accept
                if str(existing['requested_by']) == target_user_id:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    m.bonds_conf.update_one(
                        {'_id': existing['_id']},
                        {'$set': {'status': 'active', 'accepted_at': now}}
                    )
                    m.socketio.emit('bond_accepted', {
                        'bond_id': str(existing['_id']),
                        'by_username': current_user.username,
                        'by_user_id': str(current_user.id)
                    }, room=f"user_{target_user_id}")
                    return jsonify({'success': True, 'status': 'accepted'})
                return jsonify({'error': 'A bond request is already pending.'}), 409

        now = datetime.datetime.now(datetime.timezone.utc)
        bond_doc = {
            'user_a_id': user_oid,
            'user_b_id': target_oid,
            'requested_by': user_oid,
            'label': label,
            'bond_type': bond_type,
            'status': 'pending',
            'created_at': now,
            'accepted_at': None,
            'broken_at': None,
            'broken_by': None,
            'streak_count': 0,
            'last_streak_date': None,
            'nudge_data': None,
            'streak_shield': None
        }
        result = m.bonds_conf.insert_one(bond_doc)

        # Notify via SocketIO
        m.socketio.emit('bond_request_received', {
            'bond_id': str(result.inserted_id),
            'from_user_id': str(current_user.id),
            'from_username': current_user.username,
            'label': label
        }, room=f"user_{target_user_id}")

        # Push notification
        m.send_push_notification_to_user(
            target_user_id,
            f"{current_user.username} wants to form a Bond",
            f"{'\"' + label + '\" — ' if label else ''}Tap to respond",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-request-{current_user.id}'
        )

        return jsonify({'success': True, 'bond_id': str(result.inserted_id)})

    except Exception as e:
        current_app.logger.error(f"Bond request error: {e}")
        return jsonify({'error': 'Failed to send bond request'}), 500


@bp.route('/api/bonds/respond/<bond_id>', methods=['POST'])
@login_required
def api_bond_respond(bond_id):
    """Accept or decline a bond request."""
    import main as m
    try:
        data = request.get_json() or {}
        action = data.get('action')  # 'accept' or 'decline'

        if action not in ('accept', 'decline'):
            return jsonify({'error': 'Invalid action'}), 400

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'pending'})
        if not bond_doc:
            return jsonify({'error': 'Bond request not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        # Ensure the responder is NOT the requester
        if str(bond_doc['requested_by']) == user_id_str:
            return jsonify({'error': 'Cannot respond to your own request'}), 400

        requester_id = str(bond_doc['requested_by'])
        now = datetime.datetime.now(datetime.timezone.utc)

        if action == 'decline':
            m.bonds_conf.update_one(
                {'_id': ObjectId(bond_id)},
                {'$set': {'status': 'broken', 'broken_at': now}}
            )
            m.socketio.emit('bond_declined', {
                'bond_id': bond_id,
                'by_username': current_user.username
            }, room=f"user_{requester_id}")
            return jsonify({'success': True, 'status': 'declined'})

        # Accept — check bond limits for acceptor too
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        max_bonds = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_bonds', 3)
        active_count = m.bonds_conf.count_documents({
            'status': 'active',
            '$or': [{'user_a_id': ObjectId(user_id_str)}, {'user_b_id': ObjectId(user_id_str)}]
        })
        if active_count >= max_bonds:
            return jsonify({'error': f'You already have {max_bonds} active bonds.'}), 400

        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {'status': 'active', 'accepted_at': now}}
        )

        m.socketio.emit('bond_accepted', {
            'bond_id': bond_id,
            'by_username': current_user.username,
            'by_user_id': user_id_str
        }, room=f"user_{requester_id}")

        # Push notification
        m.send_push_notification_to_user(
            requester_id,
            f"{current_user.username} accepted your Bond request!",
            "You're now bonded. Start setting goals together.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-accepted-{current_user.id}'
        )

        return jsonify({'success': True, 'status': 'accepted'})

    except Exception as e:
        current_app.logger.error(f"Bond respond error: {e}")
        return jsonify({'error': 'Failed to respond'}), 500


@bp.route('/api/bonds/break/<bond_id>', methods=['POST'])
@login_required
def api_bond_break(bond_id):
    """Break a bond. Deletes all shared goals and journal entries."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({
            '_id': ObjectId(bond_id),
            'status': 'active'
        })
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        now = datetime.datetime.now(datetime.timezone.utc)

        # Delete all goals, journal entries, moods, and QotD for this bond
        m.bond_goals_conf.delete_many({'bond_id': ObjectId(bond_id)})
        m.bond_journal_conf.delete_many({'bond_id': ObjectId(bond_id)})
        m.bond_moods_conf.delete_many({'bond_id': ObjectId(bond_id)})
        m.bond_qotd_conf.delete_many({'bond_id': ObjectId(bond_id)})

        # Mark bond as broken
        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {
                'status': 'broken',
                'broken_at': now,
                'broken_by': ObjectId(user_id_str)
            }}
        )

        m.socketio.emit('bond_broken', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond break error: {e}")
        return jsonify({'error': 'Failed to break bond'}), 500


@bp.route('/api/bonds/active')
@login_required
def api_bonds_active():
    """List all active bonds for the current user."""
    import main as m
    try:
        bonds = _get_user_bonds(ObjectId(current_user.id), 'active')
        result = []
        for bond in bonds:
            partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
            partner = m.users_conf.find_one(
                {'_id': ObjectId(partner_id)},
                {'username': 1, 'profile_image_url': 1}
            )
            if partner:
                result.append({
                    'bond_id': str(bond['_id']),
                    'partner_id': partner_id,
                    'partner_username': partner['username'],
                    'partner_avatar': partner.get('profile_image_url'),
                    'label': bond.get('label', ''),
                    'accepted_at': bond['accepted_at'].isoformat().replace('+00:00', 'Z') if bond.get('accepted_at') else None,
                    'streak_count': bond.get('streak_count', 0)
                })
        return jsonify({'bonds': result})
    except Exception as e:
        current_app.logger.error(f"Bonds active error: {e}")
        return jsonify({'bonds': []})


# --- Goals ---

@bp.route('/api/bonds/<bond_id>/goals', methods=['GET'])
@login_required
def api_bond_goals_list(bond_id):
    """List all goals for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        goals = list(m.bond_goals_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1))

        result = []
        for g in goals:
            proposer = m.users_conf.find_one({'_id': g['proposed_by']}, {'username': 1})
            result.append({
                'id': str(g['_id']),
                'title': g['title'],
                'description': g.get('description', ''),
                'category': g.get('category', 'Custom'),
                'target_value': g.get('target_value', 0),
                'current_value': g.get('current_value', 0),
                'unit': g.get('unit', ''),
                'deadline': g['deadline'].isoformat().replace('+00:00', 'Z') if g.get('deadline') else None,
                'status': g['status'],
                'proposed_by': str(g['proposed_by']),
                'proposed_by_username': proposer['username'] if proposer else 'User',
                'milestones': [{
                    'title': ms['title'],
                    'completed': ms.get('completed', False),
                    'completed_by': str(ms['completed_by']) if ms.get('completed_by') else None,
                    'completed_at': ms['completed_at'].isoformat().replace('+00:00', 'Z') if ms.get('completed_at') else None
                } for ms in g.get('milestones', [])],
                'check_ins': [{
                    'user_id': str(ci['user_id']),
                    'value': ci.get('value', 0),
                    'note': ci.get('note', ''),
                    'at': ci['at'].isoformat().replace('+00:00', 'Z')
                } for ci in g.get('check_ins', [])[-10:]],  # last 10 check-ins
                'created_at': g['created_at'].isoformat().replace('+00:00', 'Z'),
                'completed_at': g['completed_at'].isoformat().replace('+00:00', 'Z') if g.get('completed_at') else None
            })

        return jsonify({'goals': result})

    except Exception as e:
        current_app.logger.error(f"Bond goals list error: {e}")
        return jsonify({'error': 'Failed to fetch goals'}), 500


@bp.route('/api/bonds/<bond_id>/goals', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_goal_create(bond_id):
    """Propose a new goal for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        # Check goal limit
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        max_goals = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_goals_per_bond', 5)
        active_goals = m.bond_goals_conf.count_documents({
            'bond_id': ObjectId(bond_id),
            'status': {'$in': ['proposed', 'active']}
        })
        if active_goals >= max_goals:
            return jsonify({'error': f'Goal limit reached ({max_goals} per bond).'}), 400

        data = request.get_json() or {}
        title = data.get('title', '').strip()
        if not title or len(title) > 200:
            return jsonify({'error': 'Title required (max 200 chars)'}), 400

        description = data.get('description', '').strip()[:1000]
        category = data.get('category', 'Custom')
        if category not in GOAL_CATEGORIES:
            category = 'Custom'

        target_value = data.get('target_value', 0)
        try:
            target_value = float(target_value)
        except (TypeError, ValueError):
            target_value = 0

        unit = data.get('unit', '').strip()[:30]

        deadline = None
        deadline_str = data.get('deadline')
        if deadline_str:
            try:
                deadline = datetime.datetime.fromisoformat(deadline_str.replace('Z', '+00:00'))
                if deadline.tzinfo is None:
                    deadline = deadline.replace(tzinfo=datetime.timezone.utc)
            except (ValueError, AttributeError):
                pass

        milestones = []
        raw_milestones = data.get('milestones', [])
        for ms in raw_milestones[:20]:
            ms_title = ms.get('title', '').strip() if isinstance(ms, dict) else str(ms).strip()
            if ms_title:
                milestones.append({
                    'title': ms_title[:200],
                    'completed': False,
                    'completed_by': None,
                    'completed_at': None
                })

        now = datetime.datetime.now(datetime.timezone.utc)
        goal_doc = {
            'bond_id': ObjectId(bond_id),
            'title': title,
            'description': description,
            'category': category,
            'target_value': target_value,
            'current_value': 0,
            'unit': unit,
            'deadline': deadline,
            'status': 'proposed',
            'proposed_by': ObjectId(current_user.id),
            'milestones': milestones,
            'check_ins': [],
            'created_at': now,
            'completed_at': None
        }
        result = m.bond_goals_conf.insert_one(goal_doc)

        # Notify partner
        partner_id = _get_partner_id_from_bond(bond_doc, str(current_user.id))
        m.socketio.emit('bond_goal_proposed', {
            'bond_id': bond_id,
            'goal_id': str(result.inserted_id),
            'title': title,
            'proposed_by': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} proposed a goal",
            f'"{title}" — Approve it on Bonds',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-goal-{result.inserted_id}'
        )

        return jsonify({'success': True, 'goal_id': str(result.inserted_id)})

    except Exception as e:
        current_app.logger.error(f"Bond goal create error: {e}")
        return jsonify({'error': 'Failed to create goal'}), 500


@bp.route('/api/bonds/goals/<goal_id>/approve', methods=['POST'])
@login_required
def api_bond_goal_approve(goal_id):
    """Approve a proposed goal (partner only)."""
    import main as m
    try:
        goal = m.bond_goals_conf.find_one({'_id': ObjectId(goal_id), 'status': 'proposed'})
        if not goal:
            return jsonify({'error': 'Goal not found or not pending'}), 404

        bond = m.bonds_conf.find_one({'_id': goal['bond_id'], 'status': 'active'})
        if not bond:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        # Must not be the proposer
        if str(goal['proposed_by']) == str(current_user.id):
            return jsonify({'error': 'Cannot approve your own goal'}), 400

        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {'$set': {'status': 'active'}}
        )

        proposer_id = str(goal['proposed_by'])
        m.socketio.emit('bond_goal_approved', {
            'goal_id': goal_id,
            'approved_by': current_user.username
        }, room=f"user_{proposer_id}")

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond goal approve error: {e}")
        return jsonify({'error': 'Failed to approve goal'}), 500


@bp.route('/api/bonds/goals/<goal_id>/checkin', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def api_bond_goal_checkin(goal_id):
    """Log a check-in on a goal."""
    import main as m
    try:
        goal = m.bond_goals_conf.find_one({'_id': ObjectId(goal_id), 'status': 'active'})
        if not goal:
            return jsonify({'error': 'Goal not found or not active'}), 404

        bond = m.bonds_conf.find_one({'_id': goal['bond_id'], 'status': 'active'})
        if not bond or not _is_bond_participant(bond, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        value = data.get('value', 0)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0

        note = data.get('note', '').strip()[:500]
        now = datetime.datetime.now(datetime.timezone.utc)

        check_in = {
            'user_id': ObjectId(current_user.id),
            'value': value,
            'note': note,
            'at': now
        }

        new_current = goal.get('current_value', 0) + value

        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {
                '$push': {'check_ins': check_in},
                '$set': {'current_value': new_current}
            }
        )

        # Update streak
        _update_bond_streak(bond)

        # Notify partner
        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        m.socketio.emit('bond_checkin', {
            'goal_id': goal_id,
            'by_username': current_user.username,
            'value': value,
            'new_total': new_current
        }, room=f"user_{partner_id}")

        return jsonify({
            'success': True,
            'current_value': new_current,
            'target_value': goal.get('target_value', 0)
        })

    except Exception as e:
        current_app.logger.error(f"Bond goal checkin error: {e}")
        return jsonify({'error': 'Failed to log check-in'}), 500


@bp.route('/api/bonds/goals/<goal_id>/milestone/<int:idx>/toggle', methods=['POST'])
@login_required
def api_bond_goal_milestone_toggle(goal_id, idx):
    """Toggle a milestone's completion status."""
    import main as m
    try:
        goal = m.bond_goals_conf.find_one({'_id': ObjectId(goal_id), 'status': 'active'})
        if not goal:
            return jsonify({'error': 'Goal not found'}), 404

        bond = m.bonds_conf.find_one({'_id': goal['bond_id'], 'status': 'active'})
        if not bond or not _is_bond_participant(bond, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        milestones = goal.get('milestones', [])
        if idx < 0 or idx >= len(milestones):
            return jsonify({'error': 'Invalid milestone index'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        ms = milestones[idx]
        if ms.get('completed'):
            ms['completed'] = False
            ms['completed_by'] = None
            ms['completed_at'] = None
        else:
            ms['completed'] = True
            ms['completed_by'] = ObjectId(current_user.id)
            ms['completed_at'] = now

        milestones[idx] = ms
        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {'$set': {'milestones': milestones}}
        )

        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        m.socketio.emit('bond_milestone_toggled', {
            'goal_id': goal_id,
            'milestone_idx': idx,
            'completed': ms['completed'],
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True, 'completed': ms['completed']})

    except Exception as e:
        current_app.logger.error(f"Milestone toggle error: {e}")
        return jsonify({'error': 'Failed to toggle milestone'}), 500


@bp.route('/api/bonds/goals/<goal_id>/complete', methods=['POST'])
@login_required
def api_bond_goal_complete(goal_id):
    """Mark a goal as completed."""
    import main as m
    try:
        goal = m.bond_goals_conf.find_one({'_id': ObjectId(goal_id), 'status': 'active'})
        if not goal:
            return jsonify({'error': 'Goal not found or not active'}), 404

        bond = m.bonds_conf.find_one({'_id': goal['bond_id'], 'status': 'active'})
        if not bond or not _is_bond_participant(bond, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc)
        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {'$set': {'status': 'completed', 'completed_at': now}}
        )

        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        m.socketio.emit('bond_goal_completed', {
            'goal_id': goal_id,
            'title': goal['title'],
            'completed_by': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            "Goal completed!",
            f'"{goal["title"]}" has been marked as completed.',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-goal-complete-{goal_id}'
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond goal complete error: {e}")
        return jsonify({'error': 'Failed to complete goal'}), 500


@bp.route('/api/bonds/goals/<goal_id>/abandon', methods=['POST'])
@login_required
def api_bond_goal_abandon(goal_id):
    """Abandon a goal."""
    import main as m
    try:
        goal = m.bond_goals_conf.find_one({
            '_id': ObjectId(goal_id),
            'status': {'$in': ['active', 'proposed']}
        })
        if not goal:
            return jsonify({'error': 'Goal not found'}), 404

        bond = m.bonds_conf.find_one({'_id': goal['bond_id'], 'status': 'active'})
        if not bond or not _is_bond_participant(bond, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {'$set': {'status': 'abandoned'}}
        )

        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        m.socketio.emit('bond_goal_abandoned', {
            'goal_id': goal_id,
            'title': goal['title'],
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond goal abandon error: {e}")
        return jsonify({'error': 'Failed to abandon goal'}), 500


# --- Journal ---

@bp.route('/api/bonds/<bond_id>/journal', methods=['GET'])
@login_required
def api_bond_journal_list(bond_id):
    """List journal entries for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        entries = list(m.bond_journal_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1).limit(100))

        result = []
        for entry in entries:
            author = m.users_conf.find_one({'_id': entry['author_id']}, {'username': 1})
            decrypted_content = m.decrypt_bond_data(entry.get('content', ''), bond_id)
            result.append({
                'id': str(entry['_id']),
                'author_id': str(entry['author_id']),
                'author_username': author['username'] if author else 'User',
                'content': decrypted_content,
                'created_at': entry['created_at'].isoformat().replace('+00:00', 'Z')
            })

        return jsonify({'entries': result})

    except Exception as e:
        current_app.logger.error(f"Bond journal list error: {e}")
        return jsonify({'error': 'Failed to fetch journal'}), 500


@bp.route('/api/bonds/<bond_id>/journal', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_journal_create(bond_id):
    """Create a new journal entry."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        content = data.get('content', '').strip()
        if not content or len(content) > 5000:
            return jsonify({'error': 'Content required (max 5000 chars)'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        encrypted_content = m.encrypt_bond_data(content, bond_id)
        entry = {
            'bond_id': ObjectId(bond_id),
            'author_id': ObjectId(current_user.id),
            'content': encrypted_content,
            'encrypted': True,
            'created_at': now,
            'updated_at': now
        }
        result = m.bond_journal_conf.insert_one(entry)

        # Journal entries contribute to streak
        _update_bond_streak(bond_doc)

        partner_id = _get_partner_id_from_bond(bond_doc, str(current_user.id))
        m.socketio.emit('bond_journal_new', {
            'bond_id': bond_id,
            'entry_id': str(result.inserted_id),
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({
            'success': True,
            'entry_id': str(result.inserted_id)
        })

    except Exception as e:
        current_app.logger.error(f"Bond journal create error: {e}")
        return jsonify({'error': 'Failed to create entry'}), 500


@bp.route('/api/bonds/journal/<entry_id>', methods=['DELETE'])
@login_required
def api_bond_journal_delete(entry_id):
    """Delete own journal entry."""
    import main as m
    try:
        entry = m.bond_journal_conf.find_one({'_id': ObjectId(entry_id)})
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        if str(entry['author_id']) != str(current_user.id):
            return jsonify({'error': 'Can only delete your own entries'}), 403

        m.bond_journal_conf.delete_one({'_id': ObjectId(entry_id)})
        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond journal delete error: {e}")
        return jsonify({'error': 'Failed to delete entry'}), 500


# --- Nudge ---

@bp.route('/api/bonds/<bond_id>/nudge', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_nudge(bond_id):
    """Send a 'thinking of you' nudge to bond partner."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_str = datetime.date.today().isoformat()

        # Check daily nudge limit
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        max_nudges = m.TIER_LIMITS.get(tier, m.TIER_LIMITS['free']).get('max_nudges_per_day', 3)

        nudge_data = bond_doc.get('nudge_data') or {}
        # Reset if date changed
        if nudge_data.get('date') != today_str:
            nudge_data = {'date': today_str, 'a_to_b': 0, 'b_to_a': 0}

        # Determine direction
        is_user_a = str(bond_doc['user_a_id']) == user_id_str
        nudge_key = 'a_to_b' if is_user_a else 'b_to_a'

        if nudge_data.get(nudge_key, 0) >= max_nudges:
            return jsonify({'error': f'You can only send {max_nudges} nudges per day.'}), 429

        now = datetime.datetime.now(datetime.timezone.utc)
        nudge_data[nudge_key] = nudge_data.get(nudge_key, 0) + 1
        last_key = 'last_a_to_b' if is_user_a else 'last_b_to_a'
        nudge_data[last_key] = now

        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {'nudge_data': nudge_data}}
        )

        # Nudge contributes to streak
        _update_bond_streak(bond_doc)

        # Notify partner
        m.socketio.emit('bond_nudge', {
            'bond_id': bond_id,
            'from_username': current_user.username,
            'from_user_id': user_id_str
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} is thinking of you 💭",
            "Tap to visit your bond.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-nudge-{bond_id}'
        )

        remaining = max_nudges - nudge_data[nudge_key]
        return jsonify({'success': True, 'remaining': remaining})

    except Exception as e:
        current_app.logger.error(f"Bond nudge error: {e}")
        return jsonify({'error': 'Failed to send nudge'}), 500


# --- Mood Tracker ---

@bp.route('/api/bonds/<bond_id>/mood', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_mood_log(bond_id):
    """Log today's mood for this bond. One per user per day."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        mood = data.get('mood', '').strip()
        if mood not in BOND_MOODS:
            return jsonify({'error': 'Invalid mood. Choose from: ' + ', '.join(BOND_MOODS.keys())}), 400

        today_str = datetime.date.today().isoformat()
        now = datetime.datetime.now(datetime.timezone.utc)
        user_oid = ObjectId(current_user.id)

        # Upsert — allows changing mood within the same day
        m.bond_moods_conf.update_one(
            {'bond_id': ObjectId(bond_id), 'date': today_str, 'user_id': user_oid},
            {'$set': {'mood': mood, 'created_at': now}},
            upsert=True
        )

        # Mood contributes to streak
        _update_bond_streak(bond_doc)

        # Check if partner also logged today (for mutual reveal)
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_mood_doc = m.bond_moods_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str,
            'user_id': ObjectId(partner_id)
        })

        revealed = partner_mood_doc is not None
        result = {
            'success': True,
            'my_mood': mood,
            'revealed': revealed
        }

        if revealed:
            result['partner_mood'] = partner_mood_doc['mood']
            # Notify partner that moods are now revealed
            m.socketio.emit('bond_mood_revealed', {
                'bond_id': bond_id,
                'your_mood': partner_mood_doc['mood'],
                'partner_mood': mood,
                'partner_username': current_user.username
            }, room=f"user_{partner_id}")

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Bond mood log error: {e}")
        return jsonify({'error': 'Failed to log mood'}), 500


@bp.route('/api/bonds/<bond_id>/mood', methods=['GET'])
@login_required
def api_bond_mood_status(bond_id):
    """Get today's mood status and 14-day history for this bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_str = datetime.date.today().isoformat()

        # Today's moods
        my_mood_doc = m.bond_moods_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str,
            'user_id': ObjectId(current_user.id)
        })
        partner_mood_doc = m.bond_moods_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str,
            'user_id': ObjectId(partner_id)
        })

        my_mood = my_mood_doc['mood'] if my_mood_doc else None
        partner_mood = partner_mood_doc['mood'] if partner_mood_doc else None
        revealed = my_mood is not None and partner_mood is not None

        # 14-day history (only show days where both logged — mutual reveal)
        fourteen_days_ago = (datetime.date.today() - datetime.timedelta(days=14)).isoformat()
        all_moods = list(m.bond_moods_conf.find({
            'bond_id': ObjectId(bond_id),
            'date': {'$gte': fourteen_days_ago}
        }).sort('date', 1))

        # Group by date
        by_date = {}
        for md in all_moods:
            d = md['date']
            if d not in by_date:
                by_date[d] = {}
            uid = str(md['user_id'])
            by_date[d][uid] = md['mood']

        history = []
        for d in sorted(by_date.keys()):
            entry = by_date[d]
            # Only include if both partners logged (past days are always revealed)
            if user_id_str in entry and partner_id in entry:
                history.append({
                    'date': d,
                    'my_mood': entry[user_id_str],
                    'partner_mood': entry[partner_id]
                })

        return jsonify({
            'my_mood': my_mood,
            'partner_mood': partner_mood if revealed else None,
            'revealed': revealed,
            'partner_logged': partner_mood is not None,
            'history': history,
            'moods': BOND_MOODS
        })

    except Exception as e:
        current_app.logger.error(f"Bond mood status error: {e}")
        return jsonify({'error': 'Failed to get mood status'}), 500


# --- Question of the Day ---

@bp.route('/api/bonds/<bond_id>/qotd', methods=['GET'])
@login_required
def api_bond_qotd_get(bond_id):
    """Get today's question of the day for this bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_str = datetime.date.today().isoformat()

        # Get or create today's question doc
        qotd_doc = m.bond_qotd_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str
        })

        if not qotd_doc:
            question_text, question_category = _get_daily_question(bond_doc)
            now = datetime.datetime.now(datetime.timezone.utc)
            qotd_doc = {
                'bond_id': ObjectId(bond_id),
                'date': today_str,
                'question_text': question_text,
                'question_category': question_category,
                'answers': {},
                'created_at': now
            }
            try:
                m.bond_qotd_conf.insert_one(qotd_doc)
            except Exception:
                # Race condition — another request created it
                qotd_doc = m.bond_qotd_conf.find_one({
                    'bond_id': ObjectId(bond_id),
                    'date': today_str
                })

        answers = qotd_doc.get('answers', {})
        my_answer = answers.get(user_id_str)
        partner_answer = answers.get(partner_id)

        my_answered = my_answer is not None
        partner_answered = partner_answer is not None
        revealed = my_answered and partner_answered

        my_ans_text = m.decrypt_bond_data(my_answer.get('answer'), bond_id) if my_answer else None

        result = {
            'question': qotd_doc['question_text'],
            'category': qotd_doc.get('question_category', 'Universal'),
            'my_answer': my_ans_text,
            'my_answered': my_answered,
            'partner_answered': partner_answered,
            'revealed': revealed
        }

        if revealed:
            partner_user = m.users_conf.find_one(
                {'_id': ObjectId(partner_id)},
                {'username': 1}
            )
            partner_ans_text = m.decrypt_bond_data(partner_answer.get('answer', ''), bond_id) if partner_answer else ''
            result['partner_answer'] = partner_ans_text
            result['partner_username'] = partner_user['username'] if partner_user else 'Partner'

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Bond QotD get error: {e}")
        return jsonify({'error': 'Failed to get question'}), 500


@bp.route('/api/bonds/<bond_id>/qotd', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_qotd_answer(bond_id):
    """Answer today's question of the day."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        answer = data.get('answer', '').strip()
        if not answer or len(answer) > 1000:
            return jsonify({'error': 'Answer required (max 1000 chars)'}), 400

        today_str = datetime.date.today().isoformat()
        now = datetime.datetime.now(datetime.timezone.utc)

        # Ensure question exists
        qotd_doc = m.bond_qotd_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str
        })

        if not qotd_doc:
            question_text, question_category = _get_daily_question(bond_doc)
            qotd_doc = {
                'bond_id': ObjectId(bond_id),
                'date': today_str,
                'question_text': question_text,
                'question_category': question_category,
                'answers': {},
                'created_at': now
            }
            try:
                m.bond_qotd_conf.insert_one(qotd_doc)
            except Exception:
                qotd_doc = m.bond_qotd_conf.find_one({
                    'bond_id': ObjectId(bond_id),
                    'date': today_str
                })

        # Save answer encrypted
        encrypted_ans = m.encrypt_bond_data(answer, bond_id)
        answer_key = f'answers.{user_id_str}'
        m.bond_qotd_conf.update_one(
            {'_id': qotd_doc['_id']},
            {'$set': {answer_key: {'answer': encrypted_ans, 'encrypted': True, 'answered_at': now}}}
        )

        # Answering QotD contributes to streak
        _update_bond_streak(bond_doc)

        # Check if partner also answered (mutual reveal)
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        # Re-fetch to get updated answers
        updated_doc = m.bond_qotd_conf.find_one({'_id': qotd_doc['_id']})
        answers = updated_doc.get('answers', {})
        partner_answer = answers.get(partner_id)
        revealed = partner_answer is not None

        result = {
            'success': True,
            'my_answer': answer,
            'revealed': revealed
        }

        if revealed:
            partner_ans_text = m.decrypt_bond_data(partner_answer.get('answer', ''), bond_id) if partner_answer else ''
            result['partner_answer'] = partner_ans_text
            partner_user = m.users_conf.find_one(
                {'_id': ObjectId(partner_id)},
                {'username': 1}
            )
            result['partner_username'] = partner_user['username'] if partner_user else 'Partner'

            # Notify partner that answers are now revealed
            m.socketio.emit('bond_qotd_revealed', {
                'bond_id': bond_id,
                'partner_username': current_user.username
            }, room=f"user_{partner_id}")

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Bond QotD answer error: {e}")
        return jsonify({'error': 'Failed to submit answer'}), 500


# --- Streak Shield ---

@bp.route('/api/bonds/<bond_id>/streak/shield', methods=['POST'])
@login_required
def api_bond_streak_shield(bond_id):
    """Use a streak shield to protect partner's streak (premium only, 1/week/bond)."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        # Premium only
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        tier = m.get_user_tier(user_doc)
        if tier != 'premium':
            return jsonify({'error': 'Streak shields are a premium feature.'}), 403

        # Check if shield already used this week
        now = datetime.datetime.now(datetime.timezone.utc)
        current_week = now.strftime('%G-W%V')  # ISO week
        shield_data = bond_doc.get('streak_shield')
        if shield_data and shield_data.get('week_iso') == current_week:
            return jsonify({'error': 'Streak shield already used this week.'}), 429

        # Shield restores a broken streak: set last_streak_date to yesterday
        # so the next activity continues the streak instead of resetting
        yesterday = now - datetime.timedelta(days=1)
        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {
                'last_streak_date': yesterday,
                'streak_shield': {
                    'used_by': ObjectId(user_id_str),
                    'used_at': now,
                    'week_iso': current_week
                }
            }}
        )

        # Notify partner
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_streak_shielded', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} shielded your streak! 🛡️",
            "Your streak is protected.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-shield-{bond_id}'
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Streak shield error: {e}")
        return jsonify({'error': 'Failed to use streak shield'}), 500
