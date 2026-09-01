from flask import Blueprint, request, jsonify, render_template, current_app, url_for, session
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
import hashlib
import os
import random
from security import limits

bp = Blueprint('bonds', __name__, template_folder='templates')

def _format_datetime(val):
    if not val:
        return None
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        if not s.endswith('Z') and '+00:00' not in s and not ('-' in s[10:] or '+' in s[10:]):
            return s + 'Z'
        return s.replace('+00:00', 'Z')
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=datetime.timezone.utc)
        else:
            val = val.astimezone(datetime.timezone.utc)
        res = val.isoformat()
        if res.endswith('+00:00'):
            res = res[:-6] + 'Z'
        elif not res.endswith('Z'):
            res = res + 'Z'
        return res
    if hasattr(val, 'isoformat'):
        res = val.isoformat()
        if res.endswith('+00:00'):
            return res[:-6] + 'Z'
        if not res.endswith('Z'):
            return res + 'Z'
        return res
    return str(val)

# Section names for unread badge tracking
BOND_SECTIONS = ['mood', 'qotd', 'journal', 'goals', 'habits', 'insights', 'album', 'bucketlist', 'recommendations', 'pulses', 'countdowns']


def _new_tracking_dict():
    """Returns initial section_activity / last_viewed dict with all sections set to now."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return {s: now for s in BOND_SECTIONS}


def _update_section_activity(bond_id, section, performed_by_user_id=None):
    """Set section_activity.{section} to now. Call after any partner action."""
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc)
    update_fields = {f'section_activity.{section}': now}
    if performed_by_user_id:
        update_fields[f'last_viewed.{performed_by_user_id}.{section}'] = now
        
    m.bonds_conf.update_one(
        {'_id': ObjectId(bond_id)},
        {'$set': update_fields}
    )
    return now


def _get_unread_sections(bond_doc, user_id):
    """Return dict of section -> bool: True if activity > user's last_viewed."""
    user_id_str = str(user_id)
    last_viewed = bond_doc.get('last_viewed', {}).get(user_id_str, {})
    activity = bond_doc.get('section_activity', {})
    result = {}
    for s in BOND_SECTIONS:
        act = activity.get(s)
        viewed = last_viewed.get(s)
        if isinstance(act, datetime.datetime) and act.tzinfo is None:
            act = act.replace(tzinfo=datetime.timezone.utc)
        if isinstance(viewed, datetime.datetime) and viewed.tzinfo is None:
            viewed = viewed.replace(tzinfo=datetime.timezone.utc)
        result[s] = bool(act and (not viewed or act > viewed))
    return result


def _emit_section_unread(bond_doc, section, performed_by_user_id):
    """Emit SocketIO bond_unread_update to the other bond participant."""
    import main as m
    user_a = str(bond_doc.get('user_a_id', ''))
    user_b = str(bond_doc.get('user_b_id', ''))
    other_id = user_b if user_a == str(performed_by_user_id) else user_a
    if other_id:
        m.socketio.emit('bond_unread_update', {
            'bond_id': str(bond_doc['_id']),
            'section': section
        }, room=f"user_{other_id}")


def _on_bond_action(bond_doc, section, performed_by_user_id):
    """Combined: update section_activity + emit SocketIO to other user."""
    _update_section_activity(str(bond_doc['_id']), section, performed_by_user_id)
    _emit_section_unread(bond_doc, section, performed_by_user_id)


# Goal categories
GOAL_CATEGORIES = [
    'Health', 'Finance', 'Education', 'Relationship',
    'Personal Growth', 'Creative', 'Custom'
]

BOND_COOLDOWN_DAYS = 3

def _clean_username(username):
    if not username:
        return 'Partner'
    if username.startswith('Maya_DemoPartner'):
        return 'Maya (Demo Partner)'
    return username

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
        "What's a fear you've overcome, and how did you do it?",
        "If you could instantly master one musical instrument, which would it be?",
        "What's the most beautiful place you've ever been?",
        "What would your perfect day look like from morning to night?",
        "If you could witness any historical event firsthand, which would it be?",
        "What's a compliment you received that you still think about?",
        "If your life had a soundtrack, what genre would it be?",
        "What's a habit you're proud of building?",
        "What would you do if you knew you couldn't fail?",
        "What's something you've changed your mind about recently?",
        "If you could have any superpower for just one day, what would you pick?",
        "What's the kindest thing a stranger has ever done for you?",
        "What smell instantly takes you back to a specific memory?",
        "If you had to teach a class on anything, what would it be?",
        "What's a risk you're glad you took?",
        "What's something ordinary that you find deeply satisfying?",
        "If you could send a message to your younger self, what would it say?",
        "What's a question you wish people asked you more often?",
        "What's a tradition you'd like to start?",
        "If you could swap lives with someone for a week, who would it be?",
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
        "When did you first realize you had feelings for me?",
        "What's something about me that surprised you over time?",
        "What's a date we haven't been on that you'd love to try?",
        "If we could learn something together, what would it be?",
        "What does 'home' feel like to you?",
        "What moment between us do you wish you could relive?",
        "What's something you admire about how I handle difficult situations?",
        "What's a goal we should work toward together this year?",
        "How do you want us to celebrate our next milestone?",
        "What's the silliest thing we've ever done together?",
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
        "What's an inside joke between us that still makes you laugh?",
        "If we had a podcast together, what would it be about?",
        "What's the weirdest food combination you secretly enjoy?",
        "If you could bring back one cancelled TV show, which would it be?",
        "What's something you've never told me but have always wanted to?",
        "What's the most useless fact you know?",
        "If our friendship was a movie, what genre would it be?",
        "What's a trip or experience on your bucket list?",
        "What's the most embarrassing thing that's happened to you in public?",
        "If you could only listen to one artist for the rest of your life, who?",
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
        "What's the most mind-blowing concept you've encountered in your studies?",
        "If you could study under any expert alive today, who would it be?",
        "What's a study habit you want to build or break?",
        "How do you reward yourself after a tough study session?",
        "What's a skill outside your field that you think would help your career?",
        "If you could design your own course, what would you teach?",
        "What's the biggest mistake you've made in your studies and what did it teach you?",
        "How do you explain your field to someone who knows nothing about it?",
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
        "What's a family photo or video you'd love to recreate?",
        "What family meal brings back the most memories?",
        "If you could pass one piece of wisdom to future generations, what would it be?",
        "What's a family tradition you'd like to start that we don't have yet?",
        "What's the funniest family moment you remember?",
        "How has your relationship with family changed as you've gotten older?",
        "What's a quality that runs in our family that you're proud of?",
        "If we could all learn something together as a family, what would it be?",
        "What's a holiday memory that stands out the most to you?",
        "What does family mean to you in one sentence?",
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
        "What's the hardest part about being accountable to yourself?",
        "What would you attempt if you had unlimited energy?",
        "What's a small win you had today?",
        "What does your ideal evening routine look like?",
        "What's one thing you keep procrastinating on and why?",
        "How do you recover after a day where nothing went right?",
        "What's a distraction you need to eliminate?",
        "What would your future self thank you for starting today?",
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
    # MongoDB stores tz-naive datetimes; treat as UTC
    if accepted_at.tzinfo is None:
        accepted_at = accepted_at.replace(tzinfo=datetime.timezone.utc)
    delta_days = (now - accepted_at).days
    milestone = None
    for days, label in _ANNIVERSARY_MILESTONES:
        if delta_days >= days:
            milestone = label
    return milestone


def _get_daily_question(bond_doc):
    """Deterministic daily question selection based on bond type + date.

    Uses skip feedback history to deprioritize question types that the bond's
    users have repeatedly skipped (e.g., marking questions as 'too_personal').
    """
    import main as m

    bond_type = bond_doc.get('bond_type', 'custom')
    today_str = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    bond_id_str = str(bond_doc['_id'])

    # Combine type-specific + universal questions
    type_questions = QUESTION_BANK.get(bond_type, [])
    universal = QUESTION_BANK.get('universal', [])
    # Weight type-specific 2:1 over universal
    pool = type_questions + type_questions + universal
    if not pool:
        pool = universal or ["What's on your mind today?"]

    # --- Skip-feedback weighting ---
    # Gather skip reasons from the last 30 days to learn user preferences
    thirty_days_ago = (datetime.datetime.now(datetime.timezone.utc)
                       - datetime.timedelta(days=30)).isoformat()
    try:
        recent_skips = list(m.bond_qotd_conf.find(
            {
                'bond_id': bond_doc['_id'],
                'skips': {'$exists': True, '$ne': []},
                'date': {'$gte': thirty_days_ago[:10]}
            },
            {'skips': 1}
        ))
        # Count reasons
        reason_counts = {}
        for doc in recent_skips:
            for skip in doc.get('skips', []):
                r = skip.get('reason', '')
                if r:
                    reason_counts[r] = reason_counts.get(r, 0) + 1

        # If users frequently skip as 'not_relevant' or 'boring', we reduce
        # universal questions. If 'too_personal', we reduce type-specific ones.
        # Threshold: 3+ skips of the same reason triggers deprioritization.
        personal_skips = reason_counts.get('too_personal', 0)
        boring_skips = reason_counts.get('boring', 0) + reason_counts.get('not_relevant', 0)

        if personal_skips >= 3 and boring_skips < 3:
            # Reduce type-specific weight: use 1:2 ratio instead of 2:1
            pool = type_questions + universal + universal
        elif boring_skips >= 3 and personal_skips < 3:
            # Boost type-specific weight: use 3:1 ratio
            pool = type_questions + type_questions + type_questions + universal
        # If both are high, keep default ratio — they may just skip a lot

        if not pool:
            pool = type_questions + universal or ["What's on your mind today?"]

        # Also try to avoid repeating recently-skipped questions
        skipped_questions = set()
        for doc in recent_skips:
            q = doc.get('question_text', '')
            if q and not doc.get('encrypted'):
                skipped_questions.add(q)
        if skipped_questions and len(pool) > len(skipped_questions):
            filtered = [q for q in pool if q not in skipped_questions]
            if filtered:
                pool = filtered
    except Exception:
        pass  # If skip query fails, proceed with default pool

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


def _get_effective_streak(bond_doc):
    """Return the effective streak count for display, accounting for missed days.

    The stored streak_count is only updated on activity. If no activity happened
    yesterday (and no streak shield is active), the streak is broken and this
    returns 0.  This prevents stale streak counts from being displayed.
    """
    streak_count = bond_doc.get('streak_count', 0)
    if streak_count == 0:
        return 0

    last_streak = bond_doc.get('last_streak_date')
    if not last_streak:
        return 0

    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()

    if isinstance(last_streak, datetime.datetime):
        if last_streak.tzinfo is None:
            last_streak = last_streak.replace(tzinfo=datetime.timezone.utc)
        last_date = last_streak.date()
    else:
        last_date = last_streak

    # Activity was today or yesterday — streak is alive
    if last_date >= today - datetime.timedelta(days=1):
        return streak_count

    # Check if a streak shield bridges the gap (shield sets last_streak_date
    # to yesterday, so if that already passed the check above we're fine).
    # If the shield was used but more than 1 day has passed since last_streak_date,
    # the streak is still broken.

    # More than 1 day gap — streak is broken
    return 0


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
            new_count = bond_doc.get('streak_count', 0) + 1
            m.bonds_conf.update_one(
                {'_id': bond_doc['_id']},
                {
                    '$set': {'streak_count': new_count, 'last_streak_date': now},
                    '$max': {'best_streak': new_count}
                }
            )
        else:
            m.bonds_conf.update_one(
                {'_id': bond_doc['_id']},
                {'$set': {'streak_count': 1, 'last_streak_date': now}, '$max': {'best_streak': 1}}
            )
    else:
        m.bonds_conf.update_one(
            {'_id': bond_doc['_id']},
            {'$set': {'streak_count': 1, 'last_streak_date': now}, '$max': {'best_streak': 1}}
        )


def _update_bond_streak_for_date(bond_id, activity_date):
    """Update streak count for a bond for a specific (possibly past) date.

    Used by the offline-sync endpoint to backdate streak activity.
    All datetimes are timezone-aware UTC per project convention.

    Args:
        bond_id: ObjectId or str of the bond
        activity_date: datetime.date for the day being credited
    """
    import main as m
    bond_oid = ObjectId(bond_id) if not isinstance(bond_id, ObjectId) else bond_id
    # Re-read the bond to get the latest streak state (important when
    # processing multiple days in sequence).
    bond_doc = m.bonds_conf.find_one({'_id': bond_oid})
    if not bond_doc:
        return

    # Build a timezone-aware UTC datetime at noon for this date
    activity_dt = datetime.datetime(
        activity_date.year, activity_date.month, activity_date.day,
        12, 0, 0, tzinfo=datetime.timezone.utc
    )

    last_streak = bond_doc.get('last_streak_date')
    if last_streak:
        if isinstance(last_streak, datetime.datetime):
            if last_streak.tzinfo is None:
                last_streak = last_streak.replace(tzinfo=datetime.timezone.utc)
            last_date = last_streak.date()
        else:
            last_date = last_streak

        if last_date >= activity_date:
            return  # Already counted for this day or later
        elif last_date == activity_date - datetime.timedelta(days=1):
            # Consecutive day — increment streak
            new_count = bond_doc.get('streak_count', 0) + 1
            m.bonds_conf.update_one(
                {'_id': bond_oid},
                {
                    '$set': {'streak_count': new_count, 'last_streak_date': activity_dt},
                    '$max': {'best_streak': new_count}
                }
            )
        else:
            # Gap detected — reset streak to 1
            m.bonds_conf.update_one(
                {'_id': bond_oid},
                {'$set': {'streak_count': 1, 'last_streak_date': activity_dt}, '$max': {'best_streak': 1}}
            )
    else:
        # No streak yet — start at 1
        m.bonds_conf.update_one(
            {'_id': bond_oid},
            {'$set': {'streak_count': 1, 'last_streak_date': activity_dt}, '$max': {'best_streak': 1}}
        )


def _bridge_offline_streak(bond_id, dates):
    """Process offline activity dates and fill gaps to maintain streak continuity.

    Two-phase bridge:
    1. Connect the existing streak to the first offline date (fills any gap
       between the last online activity and the first offline action).
    2. Fill every day from first to last offline activity date (inclusive),
       so skipped days within the offline period don't break the streak.

    Args:
        bond_id: ObjectId or str of the bond
        dates: iterable of datetime.date objects
    """
    import main as m
    sorted_dates = sorted(set(dates))
    if not sorted_dates:
        return

    first_date = sorted_dates[0]
    last_date = sorted_dates[-1]

    # Phase 1: Bridge from last online streak date to first offline date
    bond_oid = ObjectId(bond_id) if not isinstance(bond_id, ObjectId) else bond_id
    bond_doc = m.bonds_conf.find_one({'_id': bond_oid}, {'last_streak_date': 1})
    if bond_doc and bond_doc.get('last_streak_date'):
        last_streak = bond_doc['last_streak_date']
        if isinstance(last_streak, datetime.datetime):
            if last_streak.tzinfo is None:
                last_streak = last_streak.replace(tzinfo=datetime.timezone.utc)
            last_online_date = last_streak.date()
        else:
            last_online_date = last_streak

        # Fill from day after last online activity to day before first offline action
        bridge_day = last_online_date + datetime.timedelta(days=1)
        while bridge_day < first_date:
            _update_bond_streak_for_date(bond_id, bridge_day)
            bridge_day += datetime.timedelta(days=1)

    # Phase 2: Fill every day from first to last offline activity (inclusive)
    current = first_date
    while current <= last_date:
        _update_bond_streak_for_date(bond_id, current)
        current += datetime.timedelta(days=1)


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


def _ai_consent_status(bond_doc, user_id_str):
    """Return dict describing AI QotD consent for this bond.

    Privacy: sending the relationship label + recent questions to an external
    AI provider (JigsawStack/Gemini) requires explicit consent from BOTH bond
    participants. Consent is stored per-user on the bond document; absence of
    the flag means no consent (fail closed).
    """
    consent_map = bond_doc.get('ai_qotd_consent') or {}
    a_id = str(bond_doc['user_a_id'])
    b_id = str(bond_doc['user_b_id'])
    a_consent = bool(consent_map.get(a_id))
    b_consent = bool(consent_map.get(b_id))
    return {
        'a_consented': a_consent,
        'b_consented': b_consent,
        'all_consented': a_consent and b_consent,
        'i_consented': bool(consent_map.get(user_id_str)),
        'i_am_a': user_id_str == a_id,
    }


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

# --- AI Question Generation Helpers ---

# Maximum AI generations per bond per day (quota protection)
_MAX_AI_GENERATIONS_PER_BOND_PER_DAY = 3


def _get_recent_qotd_questions(bond_id, limit=60):
    """Fetch recently asked QOTD questions for a bond (decrypted).

    Used to provide the AI with context about what not to repeat.
    Returns a list of question strings (most recent first).
    Limit raised to 60 to prevent long-running bonds from cycling
    through the same questions when the avoidance window was too small.
    """
    import main as m
    recent = list(m.bond_qotd_conf.find(
        {'bond_id': ObjectId(bond_id)},
        {'question_text': 1, 'encrypted': 1, 'date': 1}
    ).sort('date', -1).limit(limit))

    questions = []
    for doc in recent:
        try:
            if doc.get('encrypted', True):
                q = m.decrypt_bond_data(doc['question_text'], bond_id)
            else:
                q = doc.get('question_text', '')
            if q and q.strip():
                questions.append(q.strip())
        except Exception:
            pass
    return questions


def _get_bond_skip_insights(bond_id):
    """Gather skip feedback insights for this bond to tune AI generation."""
    import main as m
    try:
        recent_skips = list(m.bond_qotd_conf.find(
            {
                'bond_id': ObjectId(bond_id),
                'skips': {'$exists': True, '$ne': []}
            },
            {'skips': 1}
        ).limit(30))
        reason_counts = {}
        for doc in recent_skips:
            for skip in doc.get('skips', []):
                r = skip.get('reason', '')
                if r:
                    reason_counts[r] = reason_counts.get(r, 0) + 1
        return reason_counts
    except Exception:
        return {}


def _clean_ai_question(text):
    """Sanitize, clean, and format raw AI question text."""
    if not text:
        return None
    text = text.strip().strip('"\'`*')
    # Strip common AI preambles
    for prefix in ['Question:', 'Q:', "Here's a question:", "Here is a question:", "Today's question:", "Daily Question:"]:
        if text.lower().startswith(prefix.lower()):
            text = text[len(prefix):].strip().strip('"\'`*')
    # If the text has newlines or multiple paragraphs, take the first non-empty line
    lines = [line.strip().strip('"\'`*') for line in text.split('\n') if line.strip()]
    if lines:
        text = lines[0]
    # Ensure it ends with ?
    if text and not text.endswith('?'):
        if text.endswith('.'):
            text = text[:-1] + '?'
        else:
            text = text + '?'
    return text if len(text) >= 10 and len(text) <= 250 else None


def _build_qotd_ai_prompt(relationship_label, recent_questions, skip_insights=None):
    """Build a prompt for high-quality, natural, human, and grounded QotD generation."""
    rel_lower = relationship_label.lower()
    if 'love' in rel_lower or 'partner' in rel_lower:
        tone_guide = (
            "Focus on warm, romantic, cute, and grounded couple topics: "
            "everyday appreciation, favorite shared memories, cozy date ideas, cute habits, "
            "future travel or home dreams, how you support each other, or fun relationship debates."
        )
    elif 'friend' in rel_lower:
        tone_guide = (
            "Focus on fun, loyal, and nostalgic friend topics: "
            "hilarious shared memories, fun hypothetical debates, bucket list adventures, "
            "favorite hobbies/music/food, childhood throwback memories, or loyal encouragement."
        )
    elif 'study' in rel_lower:
        tone_guide = (
            "Focus on motivating and practical study partner topics: "
            "study routines, handling exam stress, celebrating milestones, favorite subjects, or study breaks."
        )
    elif 'family' in rel_lower:
        tone_guide = (
            "Focus on heartfelt family topics: "
            "family traditions, childhood memories, heartfelt appreciation, or meaningful life updates."
        )
    elif 'accountability' in rel_lower:
        tone_guide = (
            "Focus on growth and habit building: "
            "daily routines, overcoming obstacles, celebrating small wins, weekly priorities, or mindset shifts."
        )
    else:
        tone_guide = (
            "Focus on warm, engaging, and meaningful connection: "
            "personal goals, interesting perspectives, daily joys, or fun debates."
        )

    skip_instructions = []
    if skip_insights:
        if skip_insights.get('too_personal', 0) >= 2:
            skip_instructions.append("Keep the question casual, lighthearted, and easygoing. Avoid heavy, intensely vulnerable, or overly invasive emotional topics.")
        if (skip_insights.get('boring', 0) + skip_insights.get('not_relevant', 0)) >= 2:
            skip_instructions.append("Make the question especially sparky, witty, or intriguing.")

    prompt_lines = [
        f"You are a thoughtful connection assistant creating a daily Question of the Day for two people who have a '{relationship_label}' bond.",
        tone_guide,
        "",
        "STRICT GUIDELINES:",
        "- GROUNDED & NATURAL: Write like a real person warmly chatting with their partner or friend. Use clear, simple, conversational English.",
        "- CONCISE: Exactly ONE question. Maximum 1-2 short sentences. Under 25 words total.",
        "- NO WEIRD SCI-FI / SURREAL POETRY: Absolutely DO NOT write abstract, philosophical metaphors (e.g. NEVER ask about 'physical manifestations of laughter', 'colors beyond physics', 'laughter artifacts', 'cosmic dimensions', or 'tasting sounds').",
        "- ACTIONABLE & RELATABLE: Ask something specific that's easy and enjoyable to answer.",
    ]

    if skip_instructions:
        prompt_lines.append("ADAPTATION: " + " ".join(skip_instructions))

    if recent_questions:
        prompt_lines.append("\nDO NOT repeat or rephrase any of these recent questions:")
        for q in recent_questions[:25]:
            prompt_lines.append(f"- {q}")

    prompt_lines.append("\nReturn ONLY the single question text in plain text. No quotes, intro, explanation, or commentary.")

    return "\n".join(prompt_lines)


def _generate_ai_question_gemini(relationship_label, recent_questions=None, skip_insights=None):
    """Generate a QotD question using Gemini API (fallback when JigsawStack is unavailable).

    Supports multiple comma-separated API keys in GEMINI_API_KEY env var.
    Rotates through keys on 429 quota errors.
    Returns the cleaned question text string, or None on failure.
    """
    import os
    import json
    import urllib.request
    import urllib.error
    from flask import current_app

    raw_keys = os.environ.get('GEMINI_API_KEY', '').strip()
    if not raw_keys:
        return None

    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    if not keys:
        return None

    prompt = _build_qotd_ai_prompt(relationship_label, recent_questions or [], skip_insights=skip_insights)

    payload = json.dumps({
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {
            'temperature': 0.7,
            'maxOutputTokens': 100
        }
    }).encode('utf-8')

    # Try each key; skip to next on 429 quota errors
    for key in keys:
        url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}'
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                raw_text = (data.get('candidates', [{}])[0]
                            .get('content', {})
                            .get('parts', [{}])[0]
                            .get('text', '')).strip()
                cleaned = _clean_ai_question(raw_text)
                if cleaned:
                    return cleaned
        except urllib.error.HTTPError as e:
            status_code = e.code
            if status_code == 429:
                # Quota exhausted on this key, try next
                current_app.logger.info(f'Gemini key ...{key[-6:]} quota exhausted, trying next')
                continue
            current_app.logger.warning(f'Gemini API error HTTP {status_code} with key ...{key[-6:]}')
            return None
        except Exception as e:
            current_app.logger.warning(f'Gemini API request failed: {e}')
            return None

    current_app.logger.warning('All Gemini API keys exhausted (429 on all)')
    return None


def _get_community_bank_question(bond_type, bond_id):
    """Pick a random question from the community bank that this bond hasn't used.

    Excludes questions by both community_question_id AND question_text hash
    so that AI-generated questions that were stored without a bank link are
    also filtered out.

    Returns (question_text, question_id) or (None, None) if no suitable question found.
    """
    import main as m

    # Get ALL questions this bond has ever used (not just 30 days)
    # to prevent any repeat for the lifetime of the bond.
    recent_qotds = list(m.bond_qotd_conf.find(
        {'bond_id': ObjectId(bond_id)},
        {'community_question_id': 1, 'question_text': 1, 'encrypted': 1}
    ))

    used_ids = set()
    used_hashes = set()
    for q in recent_qotds:
        cq_id = q.get('community_question_id')
        if cq_id:
            used_ids.add(cq_id)
        # Also hash the question text to catch questions not linked to bank
        qt = q.get('question_text', '')
        if qt:
            try:
                if q.get('encrypted'):
                    qt = m.decrypt_bond_data(qt, str(bond_id))
            except Exception:
                pass
            if qt and qt.strip():
                used_hashes.add(hashlib.sha256(qt.strip().lower().encode()).hexdigest())

    # Build exclusion query: exclude by _id and by question_hash
    exclude_conditions = []
    if used_ids:
        exclude_conditions.append({'_id': {'$nin': list(used_ids)}})
    if used_hashes:
        exclude_conditions.append({'question_hash': {'$nin': list(used_hashes)}})

    query = {'bond_type': bond_type}
    if exclude_conditions:
        query = {'$and': [query] + exclude_conditions}

    # Use aggregation $sample for random selection
    pipeline = [{'$match': query}, {'$sample': {'size': 1}}]
    results = list(m.community_questions_conf.aggregate(pipeline))

    if results:
        doc = results[0]
        # Increment used_count
        m.community_questions_conf.update_one(
            {'_id': doc['_id']},
            {'$inc': {'used_count': 1}}
        )
        return doc['question_text'], doc['_id']

    return None, None


def _store_in_community_bank(question_text, bond_type, source='ai'):
    """Store an AI-generated question in the community bank for reuse.

    Uses SHA-256 hash of the question text to prevent exact duplicates.
    Questions are stored unencrypted (they're generic prompts, not personal data).
    """
    import main as m

    question_hash = hashlib.sha256(question_text.strip().lower().encode()).hexdigest()

    try:
        m.community_questions_conf.update_one(
            {'question_hash': question_hash},
            {
                '$setOnInsert': {
                    'question_text': question_text,
                    'bond_type': bond_type,
                    'question_hash': question_hash,
                    'source': source,
                    'used_count': 0,
                    'created_at': datetime.datetime.now(datetime.timezone.utc)
                }
            },
            upsert=True
        )
    except Exception as e:
        # Non-critical — don't fail the request if bank storage fails
        from flask import current_app
        current_app.logger.warning(f'Failed to store question in community bank: {e}')


# --- Page Route ---

@bp.route('/bonds')
@login_required
def bonds_page():
    """Render the bonds page."""
    import main as m
    user_oid = ObjectId(current_user.id)

    # Get user tier for max nudges
    user_doc = m.users_conf.find_one({'_id': user_oid})
    user_tier = m.get_user_tier(user_doc) if user_doc else 'free'
    max_nudges = m.TIER_LIMITS.get(user_tier, m.TIER_LIMITS['free']).get('max_nudges_per_day', 3)

    # Get active bonds with partner info
    active_bonds = _get_user_bonds(user_oid, 'active')
    bonds_data = []

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    current_week_iso = now_utc.strftime('%G-W%V')
    today_str = now_utc.date().isoformat()

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

        is_user_a = str(bond.get('user_a_id', '')) == str(current_user.id)
        nudge_key = 'a_to_b' if is_user_a else 'b_to_a'
        nudge_data = bond.get('nudge_data') or {}
        nudge_used = nudge_data.get(nudge_key, 0) if nudge_data.get('date') == today_str else 0
        nudge_remaining = max(0, max_nudges - nudge_used)

        streak_shield = bond.get('streak_shield') or {}
        streak_shield_used_this_week = streak_shield.get('week_iso') == current_week_iso

        bonds_data.append({
            'id': str(bond['_id']),
            'partner_id': partner_id,
            'partner_username': _clean_username(partner['username']),
            'partner_avatar': partner.get('profile_image_url'),
            'label': bond.get('label', ''),
            'bond_type': bond_type,
            'bond_type_label': type_info['label'],
            'bond_type_icon': type_info['icon'],
            'accepted_at': bond.get('accepted_at'),
            'streak_count': _get_effective_streak(bond),
            'goal_count': goal_count,
            'anniversary': anniversary,
            'streak_shield_used_this_week': streak_shield_used_this_week,
            'nudge_remaining': nudge_remaining,
            'unread_sections': _get_unread_sections(bond, str(current_user.id))
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

    # Get broken/past bonds for memory archive
    broken_bonds = _get_user_bonds(user_oid, 'broken')
    past_bonds_data = []
    for bond in broken_bonds:
        dismissed_by = [str(x) for x in bond.get('dismissed_by', [])]
        if str(current_user.id) in dismissed_by:
            continue

        partner_id = _get_partner_id_from_bond(bond, str(current_user.id))
        partner = m.users_conf.find_one(
            {'_id': ObjectId(partner_id)},
            {'username': 1, 'profile_image_url': 1}
        )
        if not partner:
            continue

        bond_type = bond.get('bond_type', 'custom')
        type_info = BOND_TYPES.get(bond_type, BOND_TYPES['custom'])
        anniversary = _get_bond_anniversary(bond.get('accepted_at'))

        past_bonds_data.append({
            'id': str(bond['_id']),
            'partner_id': partner_id,
            'partner_username': _clean_username(partner['username']),
            'partner_avatar': partner.get('profile_image_url'),
            'label': bond.get('label', ''),
            'bond_type': bond_type,
            'bond_type_label': type_info['label'],
            'bond_type_icon': type_info['icon'],
            'accepted_at': bond.get('accepted_at'),
            'broken_at': bond.get('broken_at'),
            'anniversary': anniversary,
            'is_broken': True
        })

    # App Lock PIN checks
    has_app_lock = bool(user_doc.get('app_lock_pin_hash')) if user_doc else False
    unlock_ts = session.get('app_lock_unlocked_at')
    is_unlocked = False
    if unlock_ts and has_app_lock:
        if isinstance(unlock_ts, datetime.datetime):
            if unlock_ts.tzinfo is None:
                unlock_ts = unlock_ts.replace(tzinfo=datetime.timezone.utc)
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
        else:
            elapsed = 999999
        if elapsed < 300:  # 5-minute unlock window
            is_unlocked = True

    return render_template('bonds.html',
                           active_page='bonds',
                           bonds=bonds_data,
                           past_bonds=past_bonds_data,
                           pending_received=pending_data,
                           pending_sent=sent_data,
                           goal_categories=GOAL_CATEGORIES,
                           bond_types=BOND_TYPES,
                           bond_moods=BOND_MOODS,
                           question_bank=QUESTION_BANK,
                           user_tier=user_tier,
                           has_app_lock=has_app_lock,
                           is_unlocked=is_unlocked)


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

        if getattr(current_user, 'is_guest', False):
            return jsonify({'error': 'Sending bond requests to real users is restricted in Tour Mode. Sign up to connect with others!'}), 403

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
                    init_tracking = _new_tracking_dict()
                    ua = str(existing.get('user_a_id', ''))
                    ub = str(existing.get('user_b_id', ''))
                    m.bonds_conf.update_one(
                        {'_id': existing['_id']},
                        {'$set': {'status': 'active', 'accepted_at': now, 'section_activity': init_tracking, 'last_viewed': {ua: dict(init_tracking), ub: dict(init_tracking)}}}
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

        init_tracking = _new_tracking_dict()
        ua = str(bond_doc.get('user_a_id', ''))
        ub = str(bond_doc.get('user_b_id', ''))
        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {'status': 'active', 'accepted_at': now, 'section_activity': init_tracking, 'last_viewed': {ua: dict(init_tracking), ub: dict(init_tracking)}}}
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

        # Check whether the bond partner is a demo bot so we can skip
        # the cooldown penalty — users who break their guest-tour bonds
        # shouldn't be locked out of forming real bonds after registering.
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)}, {'is_demo_bot': 1, 'username': 1})
        is_demo_bond = bool(partner_user and (partner_user.get('is_demo_bot') or (partner_user.get('username', '').startswith('Maya_DemoPartner'))))

        # Archives all shared data
        m.bond_goals_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})
        m.bond_journal_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})
        m.bond_moods_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})
        m.bond_qotd_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})
        m.bond_habits_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})
        m.bond_countdowns_conf.update_many({'bond_id': ObjectId(bond_id)}, {'$set': {'archived_by_bond_break': True}})

        # Mark bond as broken.  Do NOT record broken_by for demo
        # partner bonds — otherwise the 7‑day cooldown in
        # api_bond_request() blocks the user from forming real bonds.
        update_fields = {
            'status': 'broken',
            'broken_at': now,
        }
        if not is_demo_bond:
            update_fields['broken_by'] = ObjectId(user_id_str)
        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': update_fields}
        )

        m.socketio.emit('bond_broken', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} ended your Bond",
            "Your bond has been broken.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-broken-{bond_id}'
        )

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
                    'partner_username': _clean_username(partner['username']),
                    'partner_avatar': partner.get('profile_image_url'),
                    'label': bond.get('label', ''),
                    'accepted_at': _format_datetime(bond.get('accepted_at')),
                    'streak_count': _get_effective_streak(bond)
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
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
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
            decrypted_title = m.decrypt_bond_data(g.get('title', ''), bond_id)
            decrypted_desc = m.decrypt_bond_data(g.get('description', ''), bond_id)
            result.append({
                'id': str(g['_id']),
                'title': decrypted_title,
                'description': decrypted_desc,
                'category': g.get('category', 'Custom'),
                'target_value': g.get('target_value', 0),
                'current_value': g.get('current_value', 0),
                'unit': g.get('unit', ''),
                'deadline': _format_datetime(g.get('deadline')),
                'status': g.get('status', 'active'),
                'proposed_by': str(g['proposed_by']),
                'proposed_by_username': proposer['username'] if proposer else 'User',
                'milestones': [{
                    'title': m.decrypt_bond_data(ms.get('title', ''), bond_id),
                    'completed': ms.get('completed', False),
                    'completed_by': str(ms['completed_by']) if ms.get('completed_by') else None,
                    'completed_at': _format_datetime(ms.get('completed_at'))
                } for ms in g.get('milestones', [])],
                'check_ins': [{
                    'user_id': str(ci['user_id']),
                    'value': ci.get('value', 0),
                    'note': m.decrypt_bond_data(ci.get('note', ''), bond_id),
                    'at': _format_datetime(ci.get('at'))
                } for ci in g.get('check_ins', [])[-10:]],  # last 10 check-ins
                'created_at': _format_datetime(g.get('created_at')),
                'completed_at': _format_datetime(g.get('completed_at'))
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
        encrypted_title = m.encrypt_bond_data(title, bond_id)
        encrypted_desc = m.encrypt_bond_data(description, bond_id) if description else ''
        encrypted_milestones = []
        for ms in milestones:
            encrypted_milestones.append({
                'title': m.encrypt_bond_data(ms['title'], bond_id),
                'completed': ms['completed'],
                'completed_by': ms['completed_by'],
                'completed_at': ms['completed_at']
            })
        goal_doc = {
            'bond_id': ObjectId(bond_id),
            'title': encrypted_title,
            'description': encrypted_desc,
            'category': category,
            'target_value': target_value,
            'current_value': 0,
            'unit': unit,
            'deadline': deadline,
            'status': 'proposed',
            'proposed_by': ObjectId(current_user.id),
            'milestones': encrypted_milestones,
            'encrypted': True,
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

        _on_bond_action(bond_doc, 'goals', current_user.id)

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

        m.send_push_notification_to_user(
            proposer_id,
            f"{current_user.username} approved your goal!",
            "Your shared goal is now active.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-goal-approved-{goal_id}'
        )

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
        bond_id_str = str(goal['bond_id'])
        encrypted_note = m.encrypt_bond_data(note, bond_id_str) if note else ''

        check_in = {
            'user_id': ObjectId(current_user.id),
            'value': value,
            'note': encrypted_note,
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

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} checked in on a goal",
            "Progress has been logged on your shared goal.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-checkin-{goal_id}'
        )

        return jsonify({
            'success': True,
            'current_value': new_current,
            'target_value': goal.get('target_value', 0)
        })

    except Exception as e:
        current_app.logger.error(f"Bond goal checkin error: {e}")
        return jsonify({'error': 'Failed to log check-in'}), 500


@bp.route('/api/bonds/goals/<goal_id>/edit', methods=['PUT'])
@login_required
@limits(calls=20, period=60)
def api_bond_goal_edit(goal_id):
    """Edit an active or proposed goal."""
    import main as m
    try:
        goal_doc = m.bond_goals_conf.find_one({'_id': ObjectId(goal_id)})
        if not goal_doc:
            return jsonify({'error': 'Goal not found'}), 404

        bond_id = str(goal_doc['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Active bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if goal_doc.get('status') == 'proposed' and str(goal_doc.get('proposed_by', '')) != user_id_str:
            return jsonify({'error': 'Only the proposer can edit a proposed goal'}), 403

        if goal_doc.get('status') not in ['proposed', 'active']:
            return jsonify({'error': 'Cannot edit completed or abandoned goals'}), 400

        data = request.get_json() or {}
        
        updates = {}
        
        if 'title' in data:
            title = data['title'].strip()
            if not title or len(title) > 200:
                return jsonify({'error': 'Title required (max 200 chars)'}), 400
            updates['title'] = m.encrypt_bond_data(title, bond_id)
            
        if 'description' in data:
            description = data['description'].strip()[:1000]
            updates['description'] = m.encrypt_bond_data(description, bond_id) if description else ''
            
        if 'target_value' in data:
            try:
                updates['target_value'] = float(data['target_value'])
            except (TypeError, ValueError):
                pass
                
        if 'unit' in data:
            updates['unit'] = data['unit'].strip()[:30]
            
        if 'deadline' in data:
            deadline_str = data['deadline']
            if deadline_str:
                try:
                    deadline = datetime.datetime.fromisoformat(deadline_str.replace('Z', '+00:00'))
                    if deadline.tzinfo is None:
                        deadline = deadline.replace(tzinfo=datetime.timezone.utc)
                    updates['deadline'] = deadline
                except (ValueError, AttributeError):
                    pass
            else:
                updates['deadline'] = None

        if not updates:
            return jsonify({'error': 'No updates provided'}), 400

        updates['updated_at'] = datetime.datetime.now(datetime.timezone.utc)

        m.bond_goals_conf.update_one(
            {'_id': ObjectId(goal_id)},
            {'$set': updates}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_goal_updated', {
            'bond_id': bond_id,
            'goal_id': goal_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"Goal Updated in '{bond_doc.get('label', 'Bond')}'",
            f"{current_user.username} updated a goal.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-goal-edit-{goal_id}'
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond goal edit error: {e}")
        return jsonify({'error': 'Failed to edit goal'}), 500


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

        if ms['completed']:
            m.send_push_notification_to_user(
                partner_id,
                f"{current_user.username} completed a milestone",
                "A goal milestone has been checked off.",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-milestone-{goal_id}-{idx}'
            )

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
        goal_title = m.decrypt_bond_data(goal.get('title', ''), goal['bond_id'])
        m.socketio.emit('bond_goal_completed', {
            'goal_id': goal_id,
            'title': goal_title,
            'completed_by': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            "Goal completed!",
            f'"{goal_title}" has been marked as completed.',
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
        goal_title = m.decrypt_bond_data(goal.get('title', ''), goal['bond_id'])
        m.socketio.emit('bond_goal_abandoned', {
            'goal_id': goal_id,
            'title': goal_title,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} abandoned a goal",
            "A shared goal has been abandoned.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-goal-abandon-{goal_id}'
        )

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
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        entries = list(m.bond_journal_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1).limit(100))

        result = []
        for entry in entries:
            author_id = entry.get('author_id') or entry.get('user_id')
            author = m.users_conf.find_one({'_id': author_id}, {'username': 1}) if author_id else None
            decrypted_content = m.decrypt_bond_data(entry.get('content', ''), bond_id)
            result.append({
                'id': str(entry['_id']),
                'author_id': str(author_id) if author_id else '',
                'author_username': author['username'] if author else 'User',
                'content': decrypted_content,
                'created_at': _format_datetime(entry.get('created_at'))
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

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} wrote in your shared journal",
            "A new journal entry is waiting for you.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-journal-{bond_id}'
        )

        _on_bond_action(bond_doc, 'journal', current_user.id)

        return jsonify({
            'success': True,
            'entry_id': str(result.inserted_id)
        })

    except Exception as e:
        current_app.logger.error(f"Bond journal create error: {e}")
        return jsonify({'error': 'Failed to create entry'}), 500


@bp.route('/api/bonds/journal/<entry_id>/edit', methods=['PUT'])
@login_required
@limits(calls=20, period=60)
def api_bond_journal_edit(entry_id):
    """Edit a journal entry within 24 hours."""
    import main as m
    try:
        entry = m.bond_journal_conf.find_one({'_id': ObjectId(entry_id)})
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        if str(entry['author_id']) != str(current_user.id):
            return jsonify({'error': 'Can only edit your own entries'}), 403

        # Verify the bond is still active
        bond_doc = m.bonds_conf.find_one({'_id': entry['bond_id']})
        if not bond_doc or bond_doc.get('status') not in ('active',):
            return jsonify({'error': 'This bond is no longer active'}), 403

        # Check if within 24 hours
        created_at = entry.get('created_at')
        if not created_at:
            return jsonify({'error': 'Invalid entry date'}), 400
        
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=datetime.timezone.utc)
            
        now = datetime.datetime.now(datetime.timezone.utc)
        if (now - created_at) > datetime.timedelta(hours=24):
            return jsonify({'error': 'Can only edit entries within 24 hours of creation'}), 400

        data = request.get_json() or {}
        content = data.get('content', '').strip()
        if not content or len(content) > 5000:
            return jsonify({'error': 'Content required (max 5000 chars)'}), 400

        bond_id = str(entry['bond_id'])
        encrypted_content = m.encrypt_bond_data(content, bond_id)
        
        m.bond_journal_conf.update_one(
            {'_id': ObjectId(entry_id)},
            {'$set': {
                'content': encrypted_content,
                'updated_at': now,
                'edited': True
            }}
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond journal edit error: {e}")
        return jsonify({'error': 'Failed to edit entry'}), 500


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
        today_str = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

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

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()
        user_oid = ObjectId(current_user.id)

        # Upsert — allows changing mood within the same day
        encrypted_mood = m.encrypt_bond_data(mood, bond_id) if mood else ''
        m.bond_moods_conf.update_one(
            {'bond_id': ObjectId(bond_id), 'date': today_str, 'user_id': user_oid},
            {'$set': {'mood': encrypted_mood, 'encrypted': True, 'created_at': now}},
            upsert=True
        )

        # Mood contributes to streak
        _update_bond_streak(bond_doc)

        # Check if partner also logged today (for mutual reveal)
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)})
        
        # Interactive Demo Bot: auto-log mood for Maya_DemoPartner
        if partner_user and (partner_user.get('is_demo_bot') or partner_user.get('username', '').startswith('Maya_DemoPartner')):
            bot_mood = random.choice(['great', 'good', 'okay'])
            encrypted_bot_mood = m.encrypt_bond_data(bot_mood, bond_id) if bot_mood else ''
            m.bond_moods_conf.update_one(
                {'bond_id': ObjectId(bond_id), 'date': today_str, 'user_id': ObjectId(partner_id)},
                {'$set': {'mood': encrypted_bot_mood, 'encrypted': True, 'created_at': now}},
                upsert=True
            )

        _on_bond_action(bond_doc, 'mood', current_user.id)

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
            partner_mood_plain = partner_mood_doc['mood']
            if partner_mood_doc.get('encrypted'):
                partner_mood_plain = m.decrypt_bond_data(partner_mood_plain, bond_id)
            result['partner_mood'] = partner_mood_plain
            # Notify partner that moods are now revealed
            m.socketio.emit('bond_mood_revealed', {
                'bond_id': bond_id,
                'your_mood': partner_mood_plain,
                'partner_mood': mood,
                'partner_username': current_user.username
            }, room=f"user_{partner_id}")

            m.send_push_notification_to_user(
                partner_id,
                "Moods revealed! 🎭",
                f"{current_user.username} logged their mood — see how you both feel today.",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-mood-{bond_id}'
            )
        else:
            # Partner hasn't logged yet — nudge them
            m.send_push_notification_to_user(
                partner_id,
                f"{current_user.username} logged their mood",
                "Log yours to reveal both moods!",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-mood-{bond_id}'
            )

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
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_str = datetime.datetime.now(datetime.timezone.utc).date().isoformat()

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
        # Decrypt moods if encrypted
        if my_mood and my_mood_doc.get('encrypted'):
            my_mood = m.decrypt_bond_data(my_mood, bond_id)
        partner_mood = partner_mood_doc['mood'] if partner_mood_doc else None
        if partner_mood and partner_mood_doc.get('encrypted'):
            partner_mood = m.decrypt_bond_data(partner_mood, bond_id)
        revealed = my_mood is not None and partner_mood is not None

        # 14-day history (only show days where both logged — mutual reveal)
        fourteen_days_ago = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=14)).isoformat()
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
            raw_mood = md['mood']
            if md.get('encrypted'):
                raw_mood = m.decrypt_bond_data(raw_mood, bond_id)
            by_date[d][uid] = raw_mood

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
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_str = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        is_broken = bond_doc.get('status') == 'broken'

        # Get today's question doc
        qotd_doc = m.bond_qotd_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str
        })

        if not qotd_doc and not is_broken:
            question_text, question_category = _get_daily_question(bond_doc)
            now = datetime.datetime.now(datetime.timezone.utc)
            encrypted_question = m.encrypt_bond_data(question_text, bond_id)
            qotd_doc = {
                'bond_id': ObjectId(bond_id),
                'date': today_str,
                'question_text': encrypted_question,
                'question_category': question_category,
                'encrypted': True,
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

        if not qotd_doc:
            return jsonify({
                'has_question': False,
                'is_archived_bond': is_broken
            })

        answers = qotd_doc.get('answers', {})
        my_answer = answers.get(user_id_str)
        partner_answer = answers.get(partner_id)

        my_answered = my_answer is not None
        partner_answered = partner_answer is not None
        revealed = my_answered and partner_answered

        my_ans_text = m.decrypt_bond_data(my_answer.get('answer'), bond_id) if my_answer else None

        decrypted_question = m.decrypt_bond_data(qotd_doc.get('question_text', ''), bond_id)
        result = {
            'has_question': True,
            'question': decrypted_question,
            'category': qotd_doc.get('question_category', 'Universal'),
            'source': qotd_doc.get('source', 'preset'),
            'my_answer': my_ans_text,
            'my_answered': my_answered,
            'partner_answered': partner_answered,
            'revealed': revealed,
            'is_archived_bond': is_broken
        }

        # Expose AI QotD consent so the frontend can render an opt-in prompt.
        # Old/new bonds that predate the feature have no consent map (fail closed).
        result['ai_consent'] = _ai_consent_status(bond_doc, user_id_str)

        if qotd_doc.get('set_by'):
            set_by_user = m.users_conf.find_one({'_id': qotd_doc['set_by']}, {'username': 1})
            if set_by_user:
                result['set_by_username'] = set_by_user['username']

        if revealed:
            partner_user = m.users_conf.find_one(
                {'_id': ObjectId(partner_id)},
                {'username': 1}
            )
            partner_ans_text = m.decrypt_bond_data(partner_answer.get('answer', ''), bond_id) if partner_answer else ''
            result['partner_answer'] = partner_ans_text
            result['partner_username'] = partner_user['username'] if partner_user else 'Partner'

            # Reactions
            reactions = qotd_doc.get('reactions', {})
            my_react = reactions.get(user_id_str, {})
            partner_react = reactions.get(partner_id, {})
            result['my_reaction'] = my_react.get('emoji', '')
            result['partner_reaction'] = partner_react.get('emoji', '')

        # Skip metadata
        result['skip_count'] = qotd_doc.get('skip_count', 0)
        result['skips_remaining'] = max(0, 3 - qotd_doc.get('skip_count', 0))

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

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

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
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)})

        # Interactive Demo Bot: auto-answer QotD for Maya_DemoPartner
        if partner_user and (partner_user.get('is_demo_bot') or partner_user.get('username') == 'Maya_DemoPartner'):
            bot_answers = [
                "Taking quality time each day to check in with each other and building shared habits matters most to me!",
                "Planning our upcoming trip and celebrating small milestones together!",
                "Being open, supportive, and creating a comfortable space to express thoughts freely."
            ]
            bot_ans_text = random.choice(bot_answers)
            bot_enc_ans = m.encrypt_bond_data(bot_ans_text, bond_id)
            bot_answer_key = f'answers.{partner_id}'
            m.bond_qotd_conf.update_one(
                {'_id': qotd_doc['_id']},
                {'$set': {bot_answer_key: {'answer': bot_enc_ans, 'encrypted': True, 'answered_at': now}}}
            )

        # Re-fetch to get updated answers
        updated_doc = m.bond_qotd_conf.find_one({'_id': qotd_doc['_id']})
        answers = updated_doc.get('answers', {})
        partner_answer = answers.get(partner_id)
        revealed = partner_answer is not None

        _on_bond_action(bond_doc, 'qotd', current_user.id)

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

            m.send_push_notification_to_user(
                partner_id,
                "Answers revealed! 💬",
                f"{current_user.username} answered today's question — see both answers now.",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-qotd-{bond_id}'
            )
        else:
            # Partner hasn't answered yet — nudge them
            m.send_push_notification_to_user(
                partner_id,
                f"{current_user.username} answered today's question",
                "Answer yours to reveal both!",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-qotd-{bond_id}'
            )

        return jsonify(result)

    except Exception as e:
        current_app.logger.error(f"Bond QotD answer error: {e}")
        return jsonify({'error': 'Failed to submit answer'}), 500


@bp.route('/api/bonds/<bond_id>/qotd/generate_ai', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def api_bond_qotd_generate_ai(bond_id):
    """Generate a new AI question of the day.

    Flow:
    1. Check community question bank first (zero API cost)
    2. Try JigsawStack prompt engine
    3. Fall back to Gemini API (multi-key rotation)
    4. Store successful AI questions in community bank for future reuse
    Supports ?force_new=true to skip the community bank and force fresh AI generation.
    """
    import main as m
    from config import get_env_variable

    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        # Privacy consent gate: AI question generation sends the relationship
        # label and recent questions to an external AI provider. Require both
        # bond participants to have explicitly opted in.
        consent = _ai_consent_status(bond_doc, user_id_str)
        if not consent['all_consented']:
            return jsonify({
                'error': 'Both bond partners must opt in to AI-generated questions before the AI can create one.',
                'consent': consent
            }), 428

        # Check if answers already submitted today
        existing_qotd = m.bond_qotd_conf.find_one({'bond_id': ObjectId(bond_id), 'date': today_str})
        if existing_qotd and existing_qotd.get('answers'):
            return jsonify({'error': 'Cannot change today\'s question after an answer has already been submitted.'}), 400

        # Per-bond daily AI generation limit
        ai_gen_count = existing_qotd.get('ai_gen_count', 0) if existing_qotd else 0
        if ai_gen_count >= _MAX_AI_GENERATIONS_PER_BOND_PER_DAY:
            return jsonify({'error': f'AI question limit reached ({_MAX_AI_GENERATIONS_PER_BOND_PER_DAY} per day). Try again tomorrow or use a custom question.'}), 429

        bond_type = bond_doc.get('bond_type', 'custom')
        type_info = BOND_TYPES.get(bond_type, BOND_TYPES['custom'])
        relationship_label = type_info['label']

        force_new = request.args.get('force_new', '').lower() in ('true', '1', 'yes')
        ai_question = None
        source = 'ai'
        community_question_id = None

        # Fetch recent questions so the AI knows what to avoid repeating
        recent_questions = _get_recent_qotd_questions(bond_id)
        skip_insights = _get_bond_skip_insights(bond_id)

        # --- Step 1: Check community question bank (free, zero API cost) ---
        if not force_new:
            bank_question, bank_id = _get_community_bank_question(bond_type, bond_id)
            if bank_question:
                ai_question = bank_question
                source = 'community_bank'
                community_question_id = bank_id
                current_app.logger.info(f'QotD served from community bank for bond {bond_id}')

        # --- Step 2: Try JigsawStack ---
        if not ai_question:
            try:
                from jigsawstack import JigsawStack
                api_key = get_env_variable('JIGSAW_API_KEY')

                prompt = _build_qotd_ai_prompt(relationship_label, recent_questions, skip_insights=skip_insights)

                client = JigsawStack(api_key=api_key)
                res_data = client.prompt_engine.run_prompt_direct({
                    'prompt': prompt,
                    'inputs': [],
                    'input_values': {}
                })

                if res_data and isinstance(res_data, dict):
                    result_text = res_data.get('result', '').strip()
                    cleaned = _clean_ai_question(result_text)
                    if cleaned:
                        ai_question = cleaned
                        source = 'ai'
                        current_app.logger.info(f'QotD generated via JigsawStack for bond {bond_id}')
            except Exception as jigsaw_err:
                current_app.logger.warning(f'JigsawStack QotD failed, trying Gemini fallback: {jigsaw_err}')

        # --- Step 3: Fall back to Gemini API ---
        if not ai_question:
            gemini_result = _generate_ai_question_gemini(relationship_label, recent_questions, skip_insights=skip_insights)
            if gemini_result:
                ai_question = gemini_result
                source = 'ai_gemini'
                current_app.logger.info(f'QotD generated via Gemini fallback for bond {bond_id}')

        # --- All providers failed ---
        if not ai_question:
            return jsonify({'error': 'All AI services are currently unavailable. Try a custom question instead.'}), 502

        # --- Store in community bank for future reuse (non-blocking) ---
        if source in ('ai', 'ai_gemini'):
            _store_in_community_bank(ai_question, bond_type, source=source)

        # --- Save as today's QotD ---
        encrypted_ai_question = m.encrypt_bond_data(ai_question, bond_id)
        update_payload = {
            'bond_id': ObjectId(bond_id),
            'date': today_str,
            'question_text': encrypted_ai_question,
            'question_category': f'AI Generated ({relationship_label})',
            'source': source,
            'encrypted': True,
            'set_by': ObjectId(current_user.id),
            'created_at': now,
            'answers': {}
        }
        if community_question_id:
            update_payload['community_question_id'] = community_question_id

        m.bond_qotd_conf.update_one(
            {'bond_id': ObjectId(bond_id), 'date': today_str},
            {'$set': update_payload, '$inc': {'ai_gen_count': 1}},
            upsert=True
        )

        # Broadcast update to partner via SocketIO
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_qotd_updated', {
            'bond_id': bond_id,
            'question': ai_question,
            'source': source,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} set a new Question of the Day",
            "An AI-generated question is waiting for you.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-qotd-new-{bond_id}'
        )

        return jsonify({
            'success': True,
            'question': ai_question,
            'category': f'AI Generated ({relationship_label})',
            'source': source
        })

    except Exception as e:
        current_app.logger.error(f"Bond QotD AI generation error: {e}")
        return jsonify({'error': 'Failed to generate AI question'}), 500


# Valid QotD reaction emojis
QOTD_REACTIONS = ['❤️', '😂', '🥺', '🤔', '🔥', '💯']

# Valid skip reasons
QOTD_SKIP_REASONS = ['too_personal', 'already_discussed', 'not_relevant', 'boring']


@bp.route('/api/bonds/<bond_id>/qotd/react', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_qotd_react(bond_id):
    """React to a revealed QotD answer with an emoji.

    Body: {"reaction": "❤️"}
    Only allowed after both partners have answered (revealed state).
    Each user can change their reaction; only one reaction per user.
    """
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        reaction = (data.get('reaction') or '').strip()
        if reaction not in QOTD_REACTIONS:
            return jsonify({'error': f'Invalid reaction. Use one of: {", ".join(QOTD_REACTIONS)}'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        qotd_doc = m.bond_qotd_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str
        })
        if not qotd_doc:
            return jsonify({'error': 'No question found for today'}), 404

        # Verify both answers exist (revealed)
        answers = qotd_doc.get('answers', {})
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        if not answers.get(user_id_str) or not answers.get(partner_id):
            return jsonify({'error': 'Both partners must answer before reacting'}), 400

        # Store reaction
        reaction_key = f'reactions.{user_id_str}'
        m.bond_qotd_conf.update_one(
            {'_id': qotd_doc['_id']},
            {'$set': {reaction_key: {'emoji': reaction, 'reacted_at': now}}}
        )

        # Notify partner
        m.socketio.emit('bond_qotd_reaction', {
            'bond_id': bond_id,
            'by_username': current_user.username,
            'reaction': reaction,
        }, room=f"user_{partner_id}")

        return jsonify({'success': True, 'reaction': reaction})

    except Exception as e:
        current_app.logger.error(f"Bond QotD react error: {e}")
        return jsonify({'error': 'Failed to save reaction'}), 500


@bp.route('/api/bonds/<bond_id>/qotd/skip', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_qotd_skip(bond_id):
    """Skip today's question with a reason and get a new one.

    Body: {"reason": "too_personal"|"already_discussed"|"not_relevant"|"boring"}
    Only allowed before either partner has answered.
    Replaces the current question with a new deterministic pick.
    Max 3 skips per bond per day.
    """
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        reason = (data.get('reason') or '').strip().lower()
        if reason not in QOTD_SKIP_REASONS:
            return jsonify({'error': f'Invalid reason. Use one of: {", ".join(QOTD_SKIP_REASONS)}'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        qotd_doc = m.bond_qotd_conf.find_one({
            'bond_id': ObjectId(bond_id),
            'date': today_str
        })

        if qotd_doc:
            # Can't skip if someone already answered
            answers = qotd_doc.get('answers', {})
            if answers:
                return jsonify({'error': "Can't skip after an answer has been submitted"}), 400

            # Max 3 skips per day
            skip_count = qotd_doc.get('skip_count', 0)
            if skip_count >= 3:
                return jsonify({'error': 'Maximum 3 skips per day reached. Answer this question or write a custom one.'}), 429

        # Log the skip
        skip_entry = {
            'by': ObjectId(current_user.id),
            'reason': reason,
            'skipped_at': now,
        }

        # Generate a new question by appending skip count to the hash seed
        skip_num = (qotd_doc.get('skip_count', 0) + 1) if qotd_doc else 1
        bond_type = bond_doc.get('bond_type', 'custom')
        type_questions = QUESTION_BANK.get(bond_type, [])
        universal = QUESTION_BANK.get('universal', [])
        pool = type_questions + type_questions + universal
        if not pool:
            pool = universal or ["What's on your mind today?"]

        # Use bond_id:date:skip_num as the hash seed for the replacement
        hash_input = f"{bond_id}:{today_str}:skip{skip_num}"
        hash_val = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)
        idx = hash_val % len(pool)
        new_question = pool[idx]
        new_category = BOND_TYPES.get(bond_type, {}).get('label', 'Custom') if new_question in type_questions else 'Universal'

        encrypted_question = m.encrypt_bond_data(new_question, bond_id)

        if qotd_doc:
            m.bond_qotd_conf.update_one(
                {'_id': qotd_doc['_id']},
                {
                    '$set': {
                        'question_text': encrypted_question,
                        'question_category': new_category,
                        'encrypted': True,
                        'source': 'preset',
                    },
                    '$inc': {'skip_count': 1},
                    '$push': {'skips': skip_entry},
                }
            )
        else:
            m.bond_qotd_conf.insert_one({
                'bond_id': ObjectId(bond_id),
                'date': today_str,
                'question_text': encrypted_question,
                'question_category': new_category,
                'encrypted': True,
                'source': 'preset',
                'answers': {},
                'created_at': now,
                'skip_count': 1,
                'skips': [skip_entry],
            })

        # Notify partner
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_qotd_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username,
            'source': 'skipped',
        }, room=f"user_{partner_id}")

        return jsonify({
            'success': True,
            'question': new_question,
            'category': new_category,
            'skips_remaining': 3 - skip_num,
        })

    except Exception as e:
        current_app.logger.error(f"Bond QotD skip error: {e}")
        return jsonify({'error': 'Failed to skip question'}), 500

@bp.route('/api/bonds/<bond_id>/qotd/ai_consent', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_qotd_ai_consent(bond_id):
    """Toggle the current user's consent to AI-generated questions for a bond.

    Body: {"consent": true|false}
    AI generation is only permitted once BOTH participants have consented.
    """
    import main as m

    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        consent = bool(data.get('consent', True))

        consent_map = bond_doc.get('ai_qotd_consent') or {}
        if consent:
            consent_map[user_id_str] = True
        else:
            consent_map[user_id_str] = False

        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {'ai_qotd_consent': consent_map}}
        )
        bond_doc['ai_qotd_consent'] = consent_map
        status = _ai_consent_status(bond_doc, user_id_str)
        return jsonify({'success': True, 'consent': status})
    except Exception as e:
        current_app.logger.error(f"Bond QotD AI consent toggle error: {e}")
        return jsonify({'error': 'Failed to update AI consent'}), 500


@bp.route('/api/bonds/<bond_id>/qotd/custom', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_qotd_custom(bond_id):
    """Set a custom question of the day created by a partner."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        question_text = data.get('question', '').strip()
        if not question_text or len(question_text) > 300:
            return jsonify({'error': 'Question required (max 300 chars)'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        qotd_doc = m.bond_qotd_conf.find_one({'bond_id': ObjectId(bond_id), 'date': today_str})

        if qotd_doc and qotd_doc.get('answers'):
            return jsonify({'error': 'Cannot change today\'s question after an answer has already been submitted.'}), 400

        encrypted_question = m.encrypt_bond_data(question_text, bond_id)
        update_payload = {
            'bond_id': ObjectId(bond_id),
            'date': today_str,
            'question_text': encrypted_question,
            'question_category': f'Set by {current_user.username}',
            'source': 'custom',
            'encrypted': True,
            'set_by': ObjectId(current_user.id),
            'created_at': now,
            'answers': {}
        }

        m.bond_qotd_conf.update_one(
            {'bond_id': ObjectId(bond_id), 'date': today_str},
            {'$set': update_payload},
            upsert=True
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_qotd_updated', {
            'bond_id': bond_id,
            'question': question_text,
            'source': 'custom',
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} asked you a question",
            "A custom Question of the Day is waiting for you.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-qotd-new-{bond_id}'
        )

        return jsonify({
            'success': True,
            'question': question_text,
            'category': f'Set by {current_user.username}',
            'source': 'custom'
        })

    except Exception as e:
        current_app.logger.error(f"Bond QotD custom question error: {e}")
        return jsonify({'error': 'Failed to set custom question'}), 500


@bp.route('/api/bonds/<bond_id>/qotd/history', methods=['GET'])
@login_required
def api_bond_qotd_history(bond_id):
    """Get history of past QotD entries where both partners answered."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id_str = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner = m.users_conf.find_one({'_id': ObjectId(partner_id_str)}, {'username': 1})
        partner_username = partner['username'] if partner else 'Partner'

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        history_docs = list(m.bond_qotd_conf.find(
            {
                'bond_id': ObjectId(bond_id),
                'date': {'$ne': today_str}
            }
        ).sort('date', -1).limit(30))

        history = []
        for doc in history_docs:
            answers = doc.get('answers', {})
            if user_id_str in answers and partner_id_str in answers:
                decrypted_q = m.decrypt_bond_data(doc.get('question_text', ''), bond_id) if doc.get('encrypted', True) else doc.get('question_text', '')

                def _parse_ans(a_val):
                    if isinstance(a_val, dict):
                        raw_a = a_val.get('answer', '')
                        if a_val.get('encrypted', True):
                            return m.decrypt_bond_data(raw_a, bond_id)
                        return raw_a or ''
                    elif isinstance(a_val, str):
                        return m.decrypt_bond_data(a_val, bond_id)
                    return ''

                my_ans = _parse_ans(answers.get(user_id_str))
                partner_ans = _parse_ans(answers.get(partner_id_str))

                history.append({
                    'date': doc.get('date'),
                    'question': decrypted_q,
                    'category': doc.get('question_category', ''),
                    'source': doc.get('source', 'app'),
                    'my_username': current_user.username,
                    'my_answer': my_ans,
                    'partner_username': partner_username,
                    'partner_answer': partner_ans,
                    'answers': {
                        user_id_str: {
                            'username': current_user.username,
                            'text': my_ans
                        },
                        partner_id_str: {
                            'username': partner_username,
                            'text': partner_ans
                        }
                    }
                })

        return jsonify({'history': history})

    except Exception as e:
        current_app.logger.error(f"Bond QotD history error: {e}")
        return jsonify({'error': 'Failed to fetch QotD history'}), 500


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

        # Verify the streak is actually at risk (missed yesterday but not more)
        last_streak = bond_doc.get('last_streak_date')
        effective = _get_effective_streak(bond_doc)
        stored_count = bond_doc.get('streak_count', 0)
        today = now.date()

        if stored_count == 0 or not last_streak:
            return jsonify({'error': 'No active streak to shield.'}), 400

        if isinstance(last_streak, datetime.datetime):
            if last_streak.tzinfo is None:
                last_streak = last_streak.replace(tzinfo=datetime.timezone.utc)
            last_date = last_streak.date()
        else:
            last_date = last_streak

        days_gap = (today - last_date).days

        if days_gap <= 1:
            # Streak is still alive (today or yesterday) — no shield needed
            return jsonify({'error': 'Your streak is still active, no shield needed.'}), 400
        elif days_gap > 2:
            # More than 1 day missed — shield can only bridge a single day gap
            return jsonify({'error': 'Streak was broken more than a day ago. Shield cannot restore it.'}), 400

        # Shield bridges the 1-day gap: set last_streak_date to yesterday
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


# --- Daily Habits System (Encrypted) ---

@bp.route('/api/bonds/<bond_id>/habits', methods=['GET'])
@login_required
def api_bond_habits_list(bond_id):
    """List active daily habits for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        today_utc = datetime.datetime.now(datetime.timezone.utc).date()
        today_str = today_utc.isoformat()

        # Last 7 days dates YYYY-MM-DD
        last_7_days = [(today_utc - datetime.timedelta(days=i)).isoformat() for i in range(7)]

        habits = list(m.bond_habits_conf.find({
            'bond_id': ObjectId(bond_id),
            'archived': {'$ne': True}
        }).sort('created_at', -1))

        result = []
        for h in habits:
            decrypted_title = m.decrypt_bond_data(h.get('title', ''), bond_id)
            logs = h.get('logs', {})
            today_logs = logs.get(today_str, {})
            my_today = today_logs.get(user_id_str, {}).get('completed', False)
            partner_today = today_logs.get(partner_id, {}).get('completed', False)

            # Calculate 7-day completion count for user & partner
            my_7d = sum(1 for d in last_7_days if logs.get(d, {}).get(user_id_str, {}).get('completed'))
            partner_7d = sum(1 for d in last_7_days if logs.get(d, {}).get(partner_id, {}).get('completed'))

            result.append({
                'id': str(h['_id']),
                'title': decrypted_title,
                'my_completed': my_today,
                'partner_completed': partner_today,
                'my_7d_count': my_7d,
                'partner_7d_count': partner_7d,
                'created_at': _format_datetime(h.get('created_at'))
            })

        return jsonify({'habits': result})

    except Exception as e:
        current_app.logger.error(f"Bond habits list error: {e}")
        return jsonify({'error': 'Failed to fetch habits'}), 500


@bp.route('/api/bonds/<bond_id>/habits', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_habit_create(bond_id):
    """Create a new encrypted daily habit."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        title = data.get('title', '').strip()
        if not title or len(title) > 200:
            return jsonify({'error': 'Habit title required (max 200 chars)'}), 400

        # Check limit: max 10 active habits per bond
        active_count = m.bond_habits_conf.count_documents({
            'bond_id': ObjectId(bond_id),
            'archived': {'$ne': True}
        })
        if active_count >= 10:
            return jsonify({'error': 'Maximum 10 active habits per bond.'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        encrypted_title = m.encrypt_bond_data(title, bond_id)

        habit_doc = {
            'bond_id': ObjectId(bond_id),
            'title': encrypted_title,
            'encrypted': True,
            'created_by': ObjectId(user_id_str),
            'created_at': now,
            'archived': False,
            'logs': {}
        }
        res = m.bond_habits_conf.insert_one(habit_doc)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_habit_updated', {
            'bond_id': bond_id,
            'habit_id': str(res.inserted_id),
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} added a new habit",
            f'"{title}" — Start tracking it together.',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-habit-new-{res.inserted_id}'
        )

        _on_bond_action(bond_doc, 'habits', current_user.id)

        return jsonify({
            'success': True,
            'habit_id': str(res.inserted_id),
            'title': title
        })

    except Exception as e:
        current_app.logger.error(f"Bond habit create error: {e}")
        return jsonify({'error': 'Failed to create habit'}), 500


@bp.route('/api/bonds/habits/<habit_id>/toggle', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def api_bond_habit_toggle(habit_id):
    """Toggle today's habit completion status."""
    import main as m
    try:
        habit = m.bond_habits_conf.find_one({'_id': ObjectId(habit_id)})
        if not habit or habit.get('archived'):
            return jsonify({'error': 'Habit not found'}), 404

        bond_id = str(habit['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc)
        today_str = now.date().isoformat()

        logs = habit.get('logs', {})
        today_logs = logs.get(today_str, {})
        current_status = today_logs.get(user_id_str, {}).get('completed', False)
        new_status = not current_status

        log_key = f'logs.{today_str}.{user_id_str}'
        m.bond_habits_conf.update_one(
            {'_id': ObjectId(habit_id)},
            {'$set': {log_key: {'completed': new_status, 'completed_at': now}}}
        )

        if new_status:
            # Completing a habit contributes to streak
            _update_bond_streak(bond_doc)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)})

        # Interactive Demo Bot: auto-check habit for Maya_DemoPartner when user completes habit
        if new_status and partner_user and (partner_user.get('is_demo_bot') or partner_user.get('username') == 'Maya_DemoPartner'):
            bot_log_key = f'logs.{today_str}.{partner_id}'
            m.bond_habits_conf.update_one(
                {'_id': ObjectId(habit_id)},
                {'$set': {bot_log_key: {'completed': True, 'completed_at': now}}}
            )

        m.socketio.emit('bond_habit_updated', {
            'bond_id': bond_id,
            'habit_id': habit_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        if new_status:
            m.send_push_notification_to_user(
                partner_id,
                f"{current_user.username} completed a habit ✓",
                "Your partner checked off a daily habit.",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-habit-toggle-{habit_id}'
            )

        _on_bond_action(bond_doc, 'habits', current_user.id)

        return jsonify({'success': True, 'completed': new_status})

    except Exception as e:
        current_app.logger.error(f"Bond habit toggle error: {e}")
        return jsonify({'error': 'Failed to toggle habit'}), 500


@bp.route('/api/bonds/habits/<habit_id>', methods=['DELETE'])
@login_required
def api_bond_habit_delete(habit_id):
    """Archive a habit."""
    import main as m
    try:
        habit = m.bond_habits_conf.find_one({'_id': ObjectId(habit_id)})
        if not habit:
            return jsonify({'error': 'Habit not found'}), 404

        bond_id = str(habit['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        m.bond_habits_conf.update_one(
            {'_id': ObjectId(habit_id)},
            {'$set': {'archived': True}}
        )

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond habit delete error: {e}")
        return jsonify({'error': 'Failed to archive habit'}), 500


# --- Relationship Insights & Monthly Recap ("Echo Together") ---

@bp.route('/api/bonds/<bond_id>/insights', methods=['GET'])
@login_required
def api_bond_insights_get(bond_id):
    """Get 30-day mood comparison and monthly recap stats for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)}, {'username': 1})
        partner_username = partner_user['username'] if partner_user else 'Partner'

        today = datetime.datetime.now(datetime.timezone.utc).date()
        first_of_month = today.replace(day=1).isoformat()

        # --- 1. 30-Day Mood Comparison ---
        last_30_days = [(today - datetime.timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
        mood_entries = list(m.bond_moods_conf.find({
            'bond_id': ObjectId(bond_id),
            'date': {'$in': last_30_days}
        }))

        mood_map = {}
        for me in mood_entries:
            d = me['date']
            u = str(me['user_id'])
            if d not in mood_map:
                mood_map[d] = {}
            mood_map[d][u] = me['mood']
            if me.get('encrypted'):
                mood_map[d][u] = m.decrypt_bond_data(me['mood'], bond_id)

        mood_comparison = []
        for d in last_30_days:
            m_user = mood_map.get(d, {}).get(user_id_str)
            m_partner = mood_map.get(d, {}).get(partner_id)
            mood_comparison.append({
                'date': d,
                'my_mood': m_user,
                'partner_mood': m_partner
            })

        # --- 2. 30-Day Recap Stats ("Echo Together") ---
        import security
        thirty_days_ago = today - datetime.timedelta(days=30)
        thirty_days_ago_str = thirty_days_ago.isoformat()
        thirty_days_ago_dt = datetime.datetime.combine(thirty_days_ago, datetime.time.min, tzinfo=datetime.timezone.utc)

        # Completed goals in the 30-day window (or total bond completed goals)
        completed_goal_docs = list(m.bond_goals_conf.find({
            'bond_id': ObjectId(bond_id),
            'status': 'completed'
        }))
        goals_completed = 0
        for g in completed_goal_docs:
            cat = g.get('completed_at')
            if not cat:
                goals_completed += 1
            else:
                try:
                    dt = cat if isinstance(cat, datetime.datetime) else security.parse_iso_utc(str(cat))
                    if dt and (dt.tzinfo is None or dt >= thirty_days_ago_dt):
                        goals_completed += 1
                except Exception:
                    goals_completed += 1

        # QotD answered in the 30-day window
        all_qotd = list(m.bond_qotd_conf.find({
            'bond_id': ObjectId(bond_id)
        }))
        qotd_answered = 0
        for q in all_qotd:
            q_date = q.get('date')
            answers = q.get('answers', {})
            if answers and len(answers) >= 1:
                if not q_date or q_date >= thirty_days_ago_str:
                    qotd_answered += 1

        # Journal entries in the 30-day window
        all_journals = list(m.bond_journal_conf.find({
            'bond_id': ObjectId(bond_id)
        }))
        journal_count = 0
        for j in all_journals:
            cat = j.get('created_at')
            if not cat:
                journal_count += 1
            else:
                try:
                    dt = cat if isinstance(cat, datetime.datetime) else security.parse_iso_utc(str(cat))
                    if dt and (dt.tzinfo is None or dt >= thirty_days_ago_dt):
                        journal_count += 1
                except Exception:
                    journal_count += 1

        # Top mood for each partner over the 30-day window
        def _get_top_mood(uid):
            month_moods = []
            for me in mood_entries:
                if str(me.get('user_id')) == uid and me.get('date') in last_30_days:
                    mood_val = me.get('mood')
                    if me.get('encrypted'):
                        try:
                            mood_val = m.decrypt_bond_data(mood_val, bond_id)
                        except Exception:
                            continue
                    if mood_val and mood_val in BOND_MOODS:
                        month_moods.append(mood_val)
            if not month_moods:
                return None
            counts = {}
            for mood_k in month_moods:
                counts[mood_k] = counts.get(mood_k, 0) + 1
            return max(counts, key=counts.get)

        my_top_mood = _get_top_mood(user_id_str)
        partner_top_mood = _get_top_mood(partner_id)

        current_streak = _get_effective_streak(bond_doc)
        best_streak = max(bond_doc.get('best_streak', 0), current_streak)

        # --- 3. Anniversary info ---
        accepted_at = bond_doc.get('accepted_at')
        anniversary_label = _get_bond_anniversary(accepted_at)
        days_since = None
        next_milestone_label = None
        next_milestone_days = None
        if accepted_at:
            if accepted_at.tzinfo is None:
                accepted_at_dt = accepted_at.replace(tzinfo=datetime.timezone.utc)
            else:
                accepted_at_dt = accepted_at
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            days_since = (now_dt.date() - accepted_at_dt.date()).days
            # Find next milestone
            for ms_days, ms_label in _ANNIVERSARY_MILESTONES:
                if ms_days > days_since:
                    next_milestone_label = ms_label
                    next_milestone_days = ms_days - days_since
                    break

        return jsonify({
            'partner_username': partner_username,
            'mood_comparison': mood_comparison,
            'anniversary': {
                'label': anniversary_label,
                'days_since': days_since,
                'next_milestone': next_milestone_label,
                'next_milestone_days': next_milestone_days
            },
            'recap': {
                'month_name': f"Last 30 Days ({today.strftime('%B %Y')})",
                'current_streak': current_streak,
                'best_streak': best_streak,
                'goals_completed': goals_completed,
                'qotd_answered': qotd_answered,
                'journal_count': journal_count,
                'my_top_mood': my_top_mood,
                'partner_top_mood': partner_top_mood
            }
        })

    except Exception as e:
        current_app.logger.error(f"Bond insights error: {e}")
        return jsonify({'error': 'Failed to fetch insights'}), 500


@bp.route('/api/bonds/<bond_id>/timeline', methods=['GET'])
@login_required
def api_bond_timeline(bond_id):
    """Unified timeline combining journal, QOTD, mood, goals, and photos.

    Returns a chronological feed (newest first) with pagination.
    Each item has a 'type' field: 'journal', 'qotd', 'mood', 'goal', 'photo'.
    """
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)}, {'username': 1})
        partner_username = _clean_username(partner_user['username'] if partner_user else 'Partner')
        my_username = _clean_username(current_user.username)

        page = max(1, int(request.args.get('page', 1)))
        per_page = 20
        items = []

        bond_oid = ObjectId(bond_id)

        # --- Journal entries ---
        for j in m.bond_journal_conf.find({'bond_id': bond_oid}).sort('created_at', -1).limit(100):
            content = j.get('content', '')
            if j.get('encrypted') and content:
                try:
                    content = m.decrypt_bond_data(content, bond_id)
                except Exception:
                    content = '[Encrypted]'
            author_name = my_username if str(j.get('author_id')) == user_id_str else partner_username
            ts = j.get('created_at')
            items.append({
                'type': 'journal',
                'id': str(j['_id']),
                'timestamp': ts,
                'author': author_name,
                'content': content[:200] + ('...' if len(content) > 200 else '')
            })

        # --- QOTD (answered/revealed only) ---
        for q in m.bond_qotd_conf.find({'bond_id': bond_oid, 'revealed': True}).sort('date', -1).limit(100):
            question_text = q.get('question_text', '')
            if q.get('encrypted') and question_text:
                try:
                    question_text = m.decrypt_bond_data(question_text, bond_id)
                except Exception:
                    question_text = '[Encrypted]'
            answers = q.get('answers', {})
            my_ans_data = answers.get(user_id_str, {})
            my_answer = my_ans_data.get('answer', '') if isinstance(my_ans_data, dict) else (my_ans_data.get('text', '') if isinstance(my_ans_data, dict) else str(my_ans_data or ''))
            partner_ans_data = answers.get(partner_id, {})
            partner_answer = partner_ans_data.get('answer', '') if isinstance(partner_ans_data, dict) else (partner_ans_data.get('text', '') if isinstance(partner_ans_data, dict) else str(partner_ans_data or ''))
            if q.get('encrypted'):
                try:
                    if my_answer:
                        my_answer = m.decrypt_bond_data(my_answer, bond_id)
                except Exception:
                    pass
                try:
                    if partner_answer:
                        partner_answer = m.decrypt_bond_data(partner_answer, bond_id)
                except Exception:
                    pass
            # Build timestamp from date string
            date_str = q.get('date', '')
            ts = None
            if date_str:
                try:
                    ts = datetime.datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    pass
            items.append({
                'type': 'qotd',
                'id': str(q['_id']),
                'timestamp': ts,
                'question': question_text,
                'my_answer': (my_answer[:150] + '...') if len(my_answer) > 150 else my_answer,
                'partner_answer': (partner_answer[:150] + '...') if len(partner_answer) > 150 else partner_answer,
                'my_username': my_username,
                'partner_username': partner_username
            })

        # --- Mood entries ---
        for me in m.bond_moods_conf.find({'bond_id': bond_oid}).sort('date', -1).limit(60):
            mood_val = me.get('mood', '')
            if me.get('encrypted') and mood_val:
                try:
                    mood_val = m.decrypt_bond_data(mood_val, bond_id)
                except Exception:
                    mood_val = ''
            mood_info = BOND_MOODS.get(mood_val, {})
            author_name = my_username if str(me.get('user_id')) == user_id_str else partner_username
            date_str = me.get('date', '')
            ts = None
            if date_str:
                try:
                    ts = datetime.datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    pass
            items.append({
                'type': 'mood',
                'id': str(me['_id']),
                'timestamp': ts,
                'author': author_name,
                'mood': mood_val,
                'emoji': mood_info.get('emoji', ''),
                'label': mood_info.get('label', mood_val)
            })

        # --- Completed goals ---
        for g in m.bond_goals_conf.find({'bond_id': bond_oid, 'status': 'completed'}).limit(50):
            title = g.get('title', '')
            if g.get('encrypted') and title:
                try:
                    title = m.decrypt_bond_data(title, bond_id)
                except Exception:
                    title = '[Encrypted]'
            ts = g.get('completed_at') or g.get('created_at')
            items.append({
                'type': 'goal',
                'id': str(g['_id']),
                'timestamp': ts,
                'title': title,
                'category': g.get('category', '')
            })

        # --- Album photos ---
        for p in m.bond_album_photos_conf.find({'bond_id': bond_oid}).sort('date_taken', -1).limit(50):
            photo_title = p.get('title', '')
            if p.get('encrypted') and photo_title:
                try:
                    photo_title = m.decrypt_bond_data(photo_title, bond_id)
                except Exception:
                    photo_title = ''
            photo_url = p.get('serve_url', '') or p.get('url', '')
            if p.get('encrypted') and photo_url and not p.get('serve_url'):
                try:
                    photo_url = m.decrypt_bond_data(photo_url, bond_id)
                except Exception:
                    pass
            ts = p.get('date_taken') or p.get('uploaded_at')
            items.append({
                'type': 'photo',
                'id': str(p['_id']),
                'timestamp': ts,
                'url': photo_url,
                'title': photo_title,
                'uploader': my_username if str(p.get('uploaded_by')) == user_id_str else partner_username
            })

        # Sort all items by timestamp (newest first), handling None timestamps
        def _sort_key(item):
            ts = item.get('timestamp')
            if ts is None:
                return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
            if isinstance(ts, datetime.datetime):
                if ts.tzinfo is None:
                    return ts.replace(tzinfo=datetime.timezone.utc)
                return ts.astimezone(datetime.timezone.utc)
            if isinstance(ts, str):
                parsed = m.parse_iso_utc(ts)
                if parsed:
                    return parsed
            return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

        items.sort(key=_sort_key, reverse=True)

        # Paginate
        total = len(items)
        start = (page - 1) * per_page
        end = start + per_page
        page_items = items[start:end]

        # Convert timestamps to ISO strings for JSON
        for item in page_items:
            ts = item.get('timestamp')
            if isinstance(ts, datetime.datetime):
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=datetime.timezone.utc)
                else:
                    ts = ts.astimezone(datetime.timezone.utc)
                item['timestamp'] = ts.isoformat().replace('+00:00', 'Z')
            elif isinstance(ts, str):
                parsed = m.parse_iso_utc(ts)
                if parsed:
                    item['timestamp'] = parsed.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
                else:
                    item['timestamp'] = ts
            elif ts is not None:
                item['timestamp'] = str(ts)
            else:
                item['timestamp'] = None

        return jsonify({
            'items': page_items,
            'page': page,
            'total': total,
            'has_more': end < total
        })

    except Exception as e:
        current_app.logger.error(f"Bond timeline error: {e}")
        return jsonify({'error': 'Failed to fetch timeline'}), 500

@bp.route('/api/bonds/<bond_id>/countdowns', methods=['GET'])
@login_required
def api_bond_countdowns_list(bond_id):
    """List active countdowns for a bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        countdowns = list(m.bond_countdowns_conf.find({
            'bond_id': ObjectId(bond_id),
            'archived': {'$ne': True}
        }).sort('event_date', 1))

        now = datetime.datetime.now(datetime.timezone.utc)
        grace_period = now - datetime.timedelta(days=7)
        to_archive = []
        valid_countdowns = []

        for c in countdowns:
            event_date = c.get('event_date')
            if isinstance(event_date, datetime.datetime) and event_date.tzinfo is None:
                event_date = event_date.replace(tzinfo=datetime.timezone.utc)
                
            if isinstance(event_date, datetime.datetime) and event_date < grace_period:
                to_archive.append(c['_id'])
            else:
                valid_countdowns.append(c)

        if to_archive:
            m.bond_countdowns_conf.update_many(
                {'_id': {'$in': to_archive}},
                {'$set': {'archived': True}}
            )
            countdowns = valid_countdowns

        result = []
        for c in countdowns:
            decrypted_title = m.decrypt_bond_data(c.get('title', ''), bond_id)
            result.append({
                'id': str(c['_id']),
                'title': decrypted_title,
                'event_date': c['event_date'].strftime('%Y-%m-%d') if isinstance(c.get('event_date'), datetime.datetime) else str(c.get('event_date', '')),
                'created_by': str(c.get('created_by', '')),
                'created_at': _format_datetime(c.get('created_at'))
            })

        return jsonify({'countdowns': result})

    except Exception as e:
        current_app.logger.error(f"Bond countdowns list error: {e}")
        return jsonify({'error': 'Failed to fetch countdowns'}), 500


@bp.route('/api/bonds/<bond_id>/countdowns', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_bond_countdown_create(bond_id):
    """Create a new encrypted countdown."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json() or {}
        title = data.get('title', '').strip()
        event_date_str = data.get('event_date', '').strip()

        if not title or len(title) > 200:
            return jsonify({'error': 'Event name required (max 200 chars)'}), 400
        if not event_date_str:
            return jsonify({'error': 'Event date is required'}), 400

        try:
            event_date = datetime.datetime.strptime(event_date_str, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return jsonify({'error': 'Invalid date format (YYYY-MM-DD)'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        if event_date.date() < now.date():
            return jsonify({'error': 'Event date must be today or in the future'}), 400

        # Check limit: max 5 active countdowns per bond
        active_count = m.bond_countdowns_conf.count_documents({
            'bond_id': ObjectId(bond_id),
            'archived': {'$ne': True}
        })
        if active_count >= 5:
            return jsonify({'error': 'Maximum 5 active countdowns per bond.'}), 400

        encrypted_title = m.encrypt_bond_data(title, bond_id)

        countdown_doc = {
            'bond_id': ObjectId(bond_id),
            'title': encrypted_title,
            'encrypted': True,
            'event_date': event_date,
            'created_by': ObjectId(user_id_str),
            'created_at': now,
            'archived': False
        }
        res = m.bond_countdowns_conf.insert_one(countdown_doc)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_countdown_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} added a countdown",
            f'"{title}" — {event_date_str}',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-countdown-{res.inserted_id}'
        )

        _on_bond_action(bond_doc, 'countdowns', current_user.id)

        return jsonify({
            'success': True,
            'countdown_id': str(res.inserted_id),
            'title': title
        })

    except Exception as e:
        current_app.logger.error(f"Bond countdown create error: {e}")
        return jsonify({'error': 'Failed to create countdown'}), 500


@bp.route('/api/bonds/countdowns/<countdown_id>', methods=['DELETE'])
@login_required
def api_bond_countdown_delete(countdown_id):
    """Archive a countdown."""
    import main as m
    try:
        countdown = m.bond_countdowns_conf.find_one({'_id': ObjectId(countdown_id)})
        if not countdown:
            return jsonify({'error': 'Countdown not found'}), 404

        bond_id = str(countdown['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        m.bond_countdowns_conf.update_one(
            {'_id': ObjectId(countdown_id)},
            {'$set': {'archived': True}}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_countdown_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})

    except Exception as e:
        current_app.logger.error(f"Bond countdown delete error: {e}")
        return jsonify({'error': 'Failed to archive countdown'}), 500


# ===================================================================
# Shared Photo Album
# ===================================================================

@bp.route('/api/bonds/<bond_id>/album/photos', methods=['GET'])
@login_required
def api_bond_album_list(bond_id):
    """List all photos in the bond's shared album with category filter & sorting."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        category = request.args.get('category', 'all').strip().lower()
        sort_mode = request.args.get('sort', 'date_desc').strip().lower()

        query_filter = {'bond_id': ObjectId(bond_id)}
        if category and category != 'all':
            query_filter['category'] = category

        # Sort modes: date_desc, date_asc, uploaded_desc, uploaded_asc, pinned
        sort_spec = [('is_pinned', -1), ('date_taken', -1)]
        if sort_mode == 'date_asc':
            sort_spec = [('is_pinned', -1), ('date_taken', 1)]
        elif sort_mode == 'uploaded_desc':
            sort_spec = [('is_pinned', -1), ('uploaded_at', -1)]
        elif sort_mode == 'uploaded_asc':
            sort_spec = [('is_pinned', -1), ('uploaded_at', 1)]
        elif sort_mode == 'pinned':
            sort_spec = [('is_pinned', -1), ('date_taken', -1)]

        photos = list(m.bond_album_photos_conf.find(query_filter).sort(sort_spec).limit(200))

        result = []
        for p in photos:
            try:
                decrypted_url = m.decrypt_bond_data(p.get('url', ''), bond_id)
            except Exception:
                decrypted_url = None

            pub_id = p.get('public_id', '')
            if p.get('media_encrypted'):
                decrypted_url = m.build_media_serve_url(pub_id, p.get('mime_type', 'application/octet-stream')) or decrypted_url
            else:
                decrypted_url = m.re_sign_cloudinary_url(pub_id, resource_type='image', delivery_type='authenticated', fallback_url=decrypted_url or '') or decrypted_url

            uploaded_by_id = str(p.get('uploaded_by', ''))
            uploader_name = 'Partner'
            if uploaded_by_id == user_id_str:
                uploader_name = 'You'
            else:
                uploader_doc = m.users_conf.find_one({'_id': ObjectId(uploaded_by_id)}) if uploaded_by_id else None
                if uploader_doc:
                    uploader_name = _clean_username(uploader_doc.get('username', 'Partner'))

            reactions_raw = p.get('reactions', {})
            reactions = {}
            user_reaction = None
            for r_emoji, uids in reactions_raw.items():
                if isinstance(uids, list):
                    uid_strs = [str(u) for u in uids]
                    reactions[r_emoji] = len(uid_strs)
                    if user_id_str in uid_strs:
                        user_reaction = r_emoji

            photo = {
                'id': str(p['_id']),
                'title': m.decrypt_bond_data(p.get('title', ''), bond_id) if p.get('encrypted') else p.get('title', ''),
                'description': m.decrypt_bond_data(p.get('description', ''), bond_id) if p.get('encrypted') else p.get('description', ''),
                'category': p.get('category', 'other'),
                'date_taken': _format_datetime(p.get('date_taken')),
                'url': decrypted_url,
                'uploaded_by': uploaded_by_id,
                'uploaded_by_name': uploader_name,
                'uploaded_by_me': uploaded_by_id == user_id_str,
                'uploaded_at': _format_datetime(p.get('uploaded_at')),
                'is_pinned': bool(p.get('is_pinned', False)),
                'reactions': reactions,
                'user_reaction': user_reaction,
            }
            if decrypted_url:
                result.append(photo)

        return jsonify({
            'success': True,
            'photos': result,
            'total_count': len(result),
            'sort': sort_mode,
            'category': category
        })
    except Exception as e:
        current_app.logger.error(f"Album list error: {e}")
        return jsonify({'error': 'Failed to load album'}), 500


@bp.route('/api/bonds/<bond_id>/album/upload', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def api_bond_album_upload(bond_id):
    """Upload photos (single or batch) to the bond's shared album with past date support and local storage fallback."""
    import main as m
    import uuid
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        title = (request.form.get('title', '') or '')[:100].strip()
        description = (request.form.get('description', '') or '')[:500].strip()
        category = (request.form.get('category', 'other') or 'other').strip().lower()
        if category not in ('memory', 'milestone', 'fun', 'travel', 'special', 'food', 'pets', 'jokes', 'other'):
            category = 'other'

        date_taken_str = request.form.get('date_taken', '').strip()
        date_taken = m.parse_iso_utc(date_taken_str) if date_taken_str else None
        if not date_taken:
            date_taken = datetime.datetime.now(datetime.timezone.utc)

        # Handle multiple file uploads
        files = request.files.getlist('files') or request.files.getlist('file')
        if not files and request.files.get('file'):
            files = [request.files.get('file')]

        # SECURITY/perf: cap the number of files per request and total bytes so
        # a single request can't exhaust server memory (each file is read into
        # memory for encryption before upload).
        MAX_FILES_PER_UPLOAD = 10
        MAX_TOTAL_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
        valid_files = [f for f in files if f and f.filename]
        if not valid_files:
            return jsonify({'error': 'No photo files provided.'}), 400
        if len(valid_files) > MAX_FILES_PER_UPLOAD:
            return jsonify({'error': f'You can upload at most {MAX_FILES_PER_UPLOAD} photos at once.'}), 400
        total_size = 0
        for f in valid_files:
            f.seek(0, os.SEEK_END)
            total_size += f.tell()
            f.seek(0)
        if total_size > MAX_TOTAL_UPLOAD_BYTES:
            return jsonify({'error': 'Total upload size exceeds the 50 MB limit.'}), 400
        files = valid_files

        now = datetime.datetime.now(datetime.timezone.utc)
        uploaded_photos = []

        for file in files:
            if not file or not file.filename:
                continue

            ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
            if ext not in m.ALLOWED_IMAGE_EXTENSIONS:
                continue

            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)
            if size > m.MAX_IMAGE_SIZE or size == 0:
                continue

            photo_url = None
            photo_public_id = ''
            photo_mime = ''
            media_encrypted = False
            # Attempt Cloudinary upload first (server-side encrypted at rest)
            try:
                photo_mime = (file.mimetype or 'image/jpeg')[:200]
                upload_result = m.cloudinary.uploader.upload(
                    m.encrypt_media_bytes(file.read()),
                    folder='echowithin_bond_album',
                    resource_type='raw',
                    type='authenticated'
                )
                photo_public_id = upload_result.get('public_id', '')
                photo_url = m.build_media_serve_url(photo_public_id, photo_mime) or upload_result.get('secure_url', '')
                media_encrypted = bool(photo_public_id)
            except Exception as upload_err:
                current_app.logger.warning(f"Cloudinary upload failed for bond album, trying local fallback: {upload_err}")
                photo_url = None

            # Resilient Local File Storage Fallback (encrypt-at-rest)
            if not photo_url:
                try:
                    os.makedirs(m.UPLOAD_FOLDER, exist_ok=True)
                    unique_filename = f"bond_album_{uuid.uuid4().hex[:12]}.{ext}"
                    file.seek(0)
                    ciphertext = m.encrypt_media_bytes(file.read())
                    save_path = os.path.join(m.UPLOAD_FOLDER, unique_filename)
                    with open(save_path, 'wb') as f:
                        f.write(ciphertext)
                    photo_url = url_for('blog.encrypted_uploaded_file', filename=unique_filename, _external=True)
                except Exception as save_err:
                    current_app.logger.error(f"Local file fallback upload failed: {save_err}")
                    continue

            if not photo_url:
                continue

            encrypted_url = m.encrypt_bond_data(photo_url, bond_id)
            encrypted_title = m.encrypt_bond_data(title, bond_id) if title else ''
            encrypted_desc = m.encrypt_bond_data(description, bond_id) if description else ''
            db_res = m.bond_album_photos_conf.insert_one({
                'bond_id': ObjectId(bond_id),
                'title': encrypted_title,
                'description': encrypted_desc,
                'category': category,
                'date_taken': date_taken,
                'url': encrypted_url,
                'public_id': photo_public_id if photo_public_id else '',
                'resource_type': 'raw' if media_encrypted else 'image',
                'media_encrypted': media_encrypted,
                'mime_type': photo_mime or 'image/jpeg',
                'uploaded_by': ObjectId(user_id_str),
                'uploaded_at': now,
                'is_pinned': False,
                'encrypted': True,
            })

            uploaded_photos.append({
                'id': str(db_res.inserted_id),
                'title': title,
                'description': description,
                'category': category,
                'url': photo_url,
                'uploaded_by_me': True,
                'date_taken': _format_datetime(date_taken)
            })

        if not uploaded_photos:
            return jsonify({'error': 'Failed to upload photos. Please check file format and size.'}), 400

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_album_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        count = len(uploaded_photos)
        notif_msg = f"{current_user.username} added {count} photo{'s' if count > 1 else ''} to your album"
        m.send_push_notification_to_user(
            partner_id,
            notif_msg,
            title if title else "New memories shared.",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-album-{bond_id}'
        )

        _on_bond_action(bond_doc, 'album', current_user.id)
        _update_bond_streak(bond_doc)

        return jsonify({
            'success': True,
            'photos': uploaded_photos,
            'count': count
        })
    except Exception as e:
        current_app.logger.error(f"Album upload error: {e}")
        return jsonify({'error': 'Failed to upload photo'}), 500


@bp.route('/api/bonds/album/photo/<photo_id>/pin', methods=['POST'])
@login_required
def api_bond_album_pin(photo_id):
    """Toggle pinned status for a bond album photo."""
    import main as m
    try:
        photo = m.bond_album_photos_conf.find_one({'_id': ObjectId(photo_id)})
        if not photo:
            return jsonify({'error': 'Photo not found'}), 404

        bond_id = str(photo['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        new_pinned = not bool(photo.get('is_pinned', False))
        m.bond_album_photos_conf.update_one(
            {'_id': ObjectId(photo_id)},
            {'$set': {'is_pinned': new_pinned}}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_album_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True, 'is_pinned': new_pinned})
    except Exception as e:
        current_app.logger.error(f"Album pin error: {e}")
        return jsonify({'error': 'Failed to update pin state'}), 500


@bp.route('/api/bonds/album/photo/<photo_id>/react', methods=['POST'])
@login_required
def api_bond_album_react(photo_id):
    """Toggle an emoji reaction on a bond album photo."""
    import main as m
    try:
        photo = m.bond_album_photos_conf.find_one({'_id': ObjectId(photo_id)})
        if not photo:
            return jsonify({'error': 'Photo not found'}), 404

        bond_id = str(photo['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        emoji = (data.get('emoji', '') or '').strip()
        allowed_emojis = {'❤️', '🥰', '😂', '🔥', '🥺', '✨'}
        if emoji not in allowed_emojis:
            return jsonify({'error': 'Invalid emoji reaction'}), 400

        reactions = photo.get('reactions', {})
        current_uids = reactions.get(emoji, [])
        user_uid_obj = ObjectId(user_id_str)

        # Toggle reaction
        has_reacted = user_uid_obj in current_uids or user_id_str in current_uids
        if has_reacted:
            # Remove
            m.bond_album_photos_conf.update_one(
                {'_id': ObjectId(photo_id)},
                {'$pull': {f'reactions.{emoji}': user_uid_obj}}
            )
            # Also clean if strings were saved
            m.bond_album_photos_conf.update_one(
                {'_id': ObjectId(photo_id)},
                {'$pull': {f'reactions.{emoji}': user_id_str}}
            )
            user_reaction = None
        else:
            # Add
            m.bond_album_photos_conf.update_one(
                {'_id': ObjectId(photo_id)},
                {'$addToSet': {f'reactions.{emoji}': user_uid_obj}}
            )
            user_reaction = emoji

        # Fetch updated counts
        updated_photo = m.bond_album_photos_conf.find_one({'_id': ObjectId(photo_id)})
        updated_reactions_raw = updated_photo.get('reactions', {}) if updated_photo else {}
        reaction_counts = {}
        for r_emoji, uids in updated_reactions_raw.items():
            if isinstance(uids, list) and len(uids) > 0:
                reaction_counts[r_emoji] = len(uids)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_album_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({
            'success': True,
            'reactions': reaction_counts,
            'user_reaction': user_reaction
        })
    except Exception as e:
        current_app.logger.error(f"Album react error: {e}")
        return jsonify({'error': 'Failed to react'}), 500


@bp.route('/api/bonds/album/photo/<photo_id>', methods=['PUT'])
@login_required
def api_bond_album_update(photo_id):
    """Update title, description, category, and date_taken of a photo."""
    import main as m
    try:
        photo = m.bond_album_photos_conf.find_one({'_id': ObjectId(photo_id)})
        if not photo:
            return jsonify({'error': 'Photo not found'}), 404

        bond_id = str(photo['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        title = (data.get('title', '') or '')[:100].strip()
        description = (data.get('description', '') or '')[:500].strip()
        category = (data.get('category', 'other') or 'other').strip().lower()
        if category not in ('memory', 'milestone', 'fun', 'travel', 'special', 'food', 'pets', 'jokes', 'other'):
            category = 'other'

        update_fields = {
            'title': m.encrypt_bond_data(title, bond_id) if title else '',
            'description': m.encrypt_bond_data(description, bond_id) if description else '',
            'category': category,
            'encrypted': True,
        }

        date_taken_str = data.get('date_taken')
        if date_taken_str:
            parsed_dt = m.parse_iso_utc(date_taken_str)
            if parsed_dt:
                update_fields['date_taken'] = parsed_dt

        m.bond_album_photos_conf.update_one(
            {'_id': ObjectId(photo_id)},
            {'$set': update_fields}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_album_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Album update error: {e}")
        return jsonify({'error': 'Failed to update photo details'}), 500


@bp.route('/api/bonds/album/photo/<photo_id>', methods=['DELETE'])
@login_required
def api_bond_album_delete(photo_id):
    """Delete a photo from the bond album (only the uploader can delete)."""
    import main as m
    try:
        photo = m.bond_album_photos_conf.find_one({'_id': ObjectId(photo_id)})
        if not photo:
            return jsonify({'error': 'Photo not found'}), 404

        bond_id = str(photo['bond_id'])
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if str(photo['uploaded_by']) != user_id_str:
            return jsonify({'error': 'Only the uploader can delete this photo.'}), 403

        # Remove the private asset from Cloudinary (authenticated delivery type)
        if photo.get('public_id'):
            try:
                m.cloudinary.uploader.destroy(photo['public_id'], resource_type=photo.get('resource_type', 'image'), type='authenticated')
            except Exception as del_err:
                current_app.logger.warning(f"Cloudinary destroy failed for album photo {photo_id}: {del_err}")

        m.bond_album_photos_conf.delete_one({'_id': ObjectId(photo_id)})

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_album_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Album delete error: {e}")
        return jsonify({'error': 'Failed to delete photo'}), 500


# ===================================================================
# Shared Bucket List
# ===================================================================

BUCKETLIST_CATEGORIES = ('travel', 'adventure', 'learning', 'creative', 'food', 'experience', 'other')


@bp.route('/api/bonds/<bond_id>/bucketlist', methods=['GET'])
@login_required
def api_bond_bucketlist_list(bond_id):
    """List all bucket list items for the bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        items = list(m.bond_bucketlist_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1))

        result = []
        for item in items:
            result.append({
                'id': str(item['_id']),
                'title': m.decrypt_bond_data(item.get('title', ''), bond_id) if item.get('encrypted') else item.get('title', ''),
                'description': m.decrypt_bond_data(item.get('description', ''), bond_id) if item.get('encrypted') else item.get('description', ''),
                'category': item.get('category', 'other'),
                'status': item.get('status', 'dreamt'),
                'proposed_by': str(item.get('proposed_by', '')),
                'proposed_by_me': str(item.get('proposed_by', '')) == str(current_user.id),
                'completed_at': _format_datetime(item.get('completed_at')),
                'created_at': _format_datetime(item.get('created_at')),
            })
        return jsonify({'success': True, 'items': result})
    except Exception as e:
        current_app.logger.error(f"Bucket list error: {e}")
        return jsonify({'error': 'Failed to load bucket list'}), 500


@bp.route('/api/bonds/<bond_id>/bucketlist', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_bucketlist_create(bond_id):
    """Propose a new bucket list item."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        title = (data.get('title', '') or '').strip()[:200]
        if not title:
            return jsonify({'error': 'Title is required.'}), 400

        description = (data.get('description', '') or '').strip()[:500]
        category = data.get('category', 'other').strip()
        if category not in BUCKETLIST_CATEGORIES:
            category = 'other'

        now = datetime.datetime.now(datetime.timezone.utc)
        encrypted_title = m.encrypt_bond_data(title, bond_id) if title else ''
        encrypted_desc = m.encrypt_bond_data(description, bond_id) if description else ''
        item = {
            'bond_id': ObjectId(bond_id),
            'title': encrypted_title,
            'description': encrypted_desc,
            'category': category,
            'status': 'dreamt',
            'proposed_by': ObjectId(user_id_str),
            'created_at': now,
            'encrypted': True,
        }
        result = m.bond_bucketlist_conf.insert_one(item)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_bucketlist_updated', {
            'bond_id': bond_id,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} added to your bucket list",
            f'"{title}" — check it out!',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-bucketlist-{bond_id}'
        )

        _on_bond_action(bond_doc, 'bucketlist', current_user.id)

        return jsonify({
            'success': True,
            'item': {
                'id': str(result.inserted_id),
                'title': title,
                'description': description,
                'category': category,
                'status': 'dreamt',
                'proposed_by_me': True,
            }
        })
    except Exception as e:
        current_app.logger.error(f"Bucket list create error: {e}")
        return jsonify({'error': 'Failed to create bucket list item'}), 500


@bp.route('/api/bonds/bucketlist/<item_id>/agree', methods=['POST'])
@login_required
def api_bond_bucketlist_agree(item_id):
    """Agree to a bucket list item proposed by the partner."""
    import main as m
    try:
        item = m.bond_bucketlist_conf.find_one({'_id': ObjectId(item_id), 'status': 'dreamt'})
        if not item:
            return jsonify({'error': 'Bucket list item not found'}), 404

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(item['bond_id']), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if str(item['proposed_by']) == user_id_str:
            return jsonify({'error': 'You cannot agree to your own proposal.'}), 400

        m.bond_bucketlist_conf.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'status': 'agreed'}}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_bucketlist_updated', {
            'bond_id': str(item['bond_id']),
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True, 'status': 'agreed'})
    except Exception as e:
        current_app.logger.error(f"Bucket list agree error: {e}")
        return jsonify({'error': 'Failed to agree to item'}), 500


@bp.route('/api/bonds/bucketlist/<item_id>/done', methods=['POST'])
@login_required
def api_bond_bucketlist_done(item_id):
    """Mark a bucket list item as done."""
    import main as m
    try:
        item = m.bond_bucketlist_conf.find_one({'_id': ObjectId(item_id), 'status': 'agreed'})
        if not item:
            return jsonify({'error': 'Bucket list item must be agreed by both before marking done.'}), 400

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(item['bond_id']), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc)
        m.bond_bucketlist_conf.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'status': 'done', 'completed_at': now}}
        )

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_bucketlist_updated', {
            'bond_id': str(item['bond_id']),
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        item_title = m.decrypt_bond_data(item.get('title', ''), item['bond_id']) if item.get('encrypted') else item.get('title', '')
        m.send_push_notification_to_user(
            partner_id,
            "Bucket list item completed!",
            f'"{item_title}" has been marked done.',
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-bucketlist-done-{item_id}'
        )

        return jsonify({'success': True, 'status': 'done'})
    except Exception as e:
        current_app.logger.error(f"Bucket list done error: {e}")
        return jsonify({'error': 'Failed to mark item as done'}), 500


@bp.route('/api/bonds/bucketlist/<item_id>', methods=['DELETE'])
@login_required
def api_bond_bucketlist_delete(item_id):
    """Delete a bucket list item (only the proposer can delete)."""
    import main as m
    try:
        item = m.bond_bucketlist_conf.find_one({'_id': ObjectId(item_id)})
        if not item:
            return jsonify({'error': 'Item not found'}), 404

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(item['bond_id']), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if str(item['proposed_by']) != user_id_str:
            return jsonify({'error': 'Only the proposer can delete this item.'}), 403

        m.bond_bucketlist_conf.delete_one({'_id': ObjectId(item_id)})

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_bucketlist_updated', {
            'bond_id': str(item['bond_id']),
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Bucket list delete error: {e}")
        return jsonify({'error': 'Failed to delete item'}), 500


# ===================================================================
# Media Recommendations
# ===================================================================

MEDIA_TYPES = ('book', 'song', 'podcast', 'movie', 'show', 'game', 'other')


@bp.route('/api/bonds/<bond_id>/recommendations', methods=['GET'])
@login_required
def api_bond_recommendations_list(bond_id):
    """List all media recommendations for the bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        recs = list(m.bond_recommendations_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1).limit(60))

        result = []
        for r in recs:
            image_url = ''
            encrypted_img = r.get('image_url', '')
            if encrypted_img:
                try:
                    image_url = m.decrypt_bond_data(encrypted_img, bond_id)
                except Exception:
                    image_url = ''
            if r.get('media_encrypted'):
                image_url = m.build_media_serve_url(r.get('image_public_id', ''), r.get('mime_type', 'application/octet-stream')) or image_url
            else:
                image_url = m.re_sign_cloudinary_url(r.get('image_public_id', ''), resource_type=r.get('image_resource_type', 'image'), delivery_type='authenticated', fallback_url=image_url or '') or image_url
            result.append({
                'id': str(r['_id']),
                'title': m.decrypt_bond_data(r.get('title', ''), bond_id) if r.get('encrypted') else r.get('title', ''),
                'media_type': r.get('media_type', 'other'),
                'link': m.decrypt_bond_data(r.get('link', ''), bond_id) if r.get('encrypted') else r.get('link', ''),
                'note': m.decrypt_bond_data(r.get('note', ''), bond_id) if r.get('encrypted') else r.get('note', ''),
                'image_url': image_url,
                'recommended_by': str(r.get('recommended_by', '')),
                'recommended_by_me': str(r.get('recommended_by', '')) == str(current_user.id),
                'tried_by_partner': r.get('tried_by_partner', False),
                'created_at': _format_datetime(r.get('created_at')),
            })
        return jsonify({'success': True, 'recommendations': result})
    except Exception as e:
        current_app.logger.error(f"Recommendations list error: {e}")
        return jsonify({'error': 'Failed to load recommendations'}), 500


@bp.route('/api/bonds/<bond_id>/recommendations', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def api_bond_recommendations_create(bond_id):
    """Share a media recommendation with optional image."""
    import main as m
    import uuid
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        # Support both JSON and multipart/form-data
        if request.content_type and 'multipart/form-data' in request.content_type:
            title = (request.form.get('title', '') or '').strip()[:200]
            media_type = (request.form.get('media_type', 'other') or '').strip()
            link = (request.form.get('link', '') or '').strip()[:500]
            note = (request.form.get('note', '') or '').strip()[:300]
        else:
            data = request.get_json(silent=True) or {}
            title = (data.get('title', '') or '').strip()[:200]
            media_type = (data.get('media_type', 'other') or '').strip()
            link = (data.get('link', '') or '').strip()[:500]
            note = (data.get('note', '') or '').strip()[:300]

        if not title:
            return jsonify({'error': 'Title is required.'}), 400

        if media_type not in MEDIA_TYPES:
            media_type = 'other'

        if link and not (link.startswith('http://') or link.startswith('https://') or link.startswith('//')):
            link = 'https://' + link

        # Handle optional image upload
        image_url = ''
        image_file = request.files.get('image') if request.files else None
        if image_file and image_file.filename:
            ext = image_file.filename.rsplit('.', 1)[-1].lower() if '.' in image_file.filename else ''
            if ext in m.ALLOWED_IMAGE_EXTENSIONS:
                image_file.seek(0, os.SEEK_END)
                size = image_file.tell()
                image_file.seek(0)
                if 0 < size <= m.MAX_IMAGE_SIZE:
                    # Attempt Cloudinary upload (server-side encrypted at rest)
                    image_url = ''
                    image_public_id = ''
                    image_mime = ''
                    media_encrypted = False
                    try:
                        image_mime = (image_file.mimetype or 'image/jpeg')[:200]
                        upload_result = m.cloudinary.uploader.upload(
                            m.encrypt_media_bytes(image_file.read()),
                            folder='echowithin_bond_recs',
                            resource_type='raw',
                            type='authenticated'
                        )
                        image_public_id = upload_result.get('public_id', '')
                        image_url = m.build_media_serve_url(image_public_id, image_mime) or upload_result.get('secure_url', '')
                        media_encrypted = bool(image_public_id)
                    except Exception as upload_err:
                        current_app.logger.warning(f"Cloudinary upload failed for rec image, trying local fallback: {upload_err}")
                        image_url = ''

                    # Local fallback (encrypt-at-rest)
                    if not image_url:
                        try:
                            os.makedirs(m.UPLOAD_FOLDER, exist_ok=True)
                            unique_filename = f"bond_rec_{uuid.uuid4().hex[:12]}.{ext}"
                            image_file.seek(0)
                            ciphertext = m.encrypt_media_bytes(image_file.read())
                            save_path = os.path.join(m.UPLOAD_FOLDER, unique_filename)
                            with open(save_path, 'wb') as f:
                                f.write(ciphertext)
                            image_url = url_for('blog.encrypted_uploaded_file', filename=unique_filename, _external=True)
                        except Exception as save_err:
                            current_app.logger.error(f"Local fallback for rec image failed: {save_err}")

        now = datetime.datetime.now(datetime.timezone.utc)
        doc = {
            'bond_id': ObjectId(bond_id),
            'title': m.encrypt_bond_data(title, bond_id) if title else '',
            'media_type': media_type,
            'link': m.encrypt_bond_data(link, bond_id) if link else '',
            'note': m.encrypt_bond_data(note, bond_id) if note else '',
            'recommended_by': ObjectId(user_id_str),
            'tried_by_partner': False,
            'created_at': now,
            'encrypted': True,
        }
        if image_url:
            doc['image_url'] = m.encrypt_bond_data(image_url, bond_id)
            if image_public_id:
                doc['image_public_id'] = image_public_id
                doc['image_resource_type'] = 'raw' if media_encrypted else 'image'
                doc['media_encrypted'] = media_encrypted
                doc['mime_type'] = image_mime or 'image/jpeg'

        result = m.bond_recommendations_conf.insert_one(doc)

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        m.socketio.emit('bond_recommendation_added', {
            'bond_id': bond_id,
            'title': title,
            'by_username': current_user.username
        }, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{current_user.username} recommended something for you",
            title,
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-rec-{bond_id}'
        )

        _on_bond_action(bond_doc, 'recommendations', current_user.id)

        return jsonify({
            'success': True,
            'recommendation': {
                'id': str(result.inserted_id),
                'title': title,
                'media_type': media_type,
                'recommended_by_me': True,
                'image_url': image_url,
            }
        })
    except Exception as e:
        current_app.logger.error(f"Recommendation create error: {e}")
        return jsonify({'error': 'Failed to share recommendation'}), 500


@bp.route('/api/bonds/recommendations/<rec_id>/tried', methods=['POST'])
@login_required
def api_bond_recommendations_tried(rec_id):
    """Toggle 'tried it' on a recommendation."""
    import main as m
    try:
        rec = m.bond_recommendations_conf.find_one({'_id': ObjectId(rec_id)})
        if not rec:
            return jsonify({'error': 'Recommendation not found'}), 404

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(rec['bond_id']), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if str(rec['recommended_by']) == user_id_str:
            return jsonify({'error': 'You cannot mark your own recommendation as tried.'}), 400

        new_val = not rec.get('tried_by_partner', False)
        m.bond_recommendations_conf.update_one(
            {'_id': ObjectId(rec_id)},
            {'$set': {'tried_by_partner': new_val}}
        )

        return jsonify({'success': True, 'tried': new_val})
    except Exception as e:
        current_app.logger.error(f"Recommendation tried error: {e}")
        return jsonify({'error': 'Failed to update'}), 500


@bp.route('/api/bonds/recommendations/<rec_id>', methods=['DELETE'])
@login_required
def api_bond_recommendations_delete(rec_id):
    """Delete a recommendation (only the recommender can delete)."""
    import main as m
    try:
        rec = m.bond_recommendations_conf.find_one({'_id': ObjectId(rec_id)})
        if not rec:
            return jsonify({'error': 'Recommendation not found'}), 404

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(rec['bond_id']), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        if str(rec['recommended_by']) != user_id_str:
            return jsonify({'error': 'Only the recommender can delete this.'}), 403

        # Remove the private asset from Cloudinary (authenticated delivery type)
        if rec.get('image_public_id'):
            try:
                m.cloudinary.uploader.destroy(rec['image_public_id'], resource_type=rec.get('image_resource_type', 'image'), type='authenticated')
            except Exception as del_err:
                current_app.logger.warning(f"Cloudinary destroy failed for rec image {rec_id}: {del_err}")

        m.bond_recommendations_conf.delete_one({'_id': ObjectId(rec_id)})
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Recommendation delete error: {e}")
        return jsonify({'error': 'Failed to delete recommendation'}), 500


# ===================================================================
# Quick Pulse (anytime check-in — no daily limit)
# ===================================================================

PULSE_EMOJIS = ['😊', '🥰', '🤗', '💪', '🎉', '🙏', '🤔', '😴', '😤', '😢']


@bp.route('/api/bonds/<bond_id>/pulses', methods=['GET'])
@login_required
def api_bond_pulses_list(bond_id):
    """Get recent quick pulses for the bond."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        if not _is_bond_participant(bond_doc, str(current_user.id)):
            return jsonify({'error': 'Not authorized'}), 403

        pulses = list(m.bond_pulses_conf.find(
            {'bond_id': ObjectId(bond_id)}
        ).sort('created_at', -1).limit(30))

        result = []
        for p in pulses:
            result.append({
                'id': str(p['_id']),
                'user_id': str(p['user_id']),
                'from_me': str(p['user_id']) == str(current_user.id),
                'emoji': p.get('emoji', '😊'),
                'message': m.decrypt_bond_data(p.get('message', ''), bond_id) if p.get('encrypted') else p.get('message', ''),
                'created_at': _format_datetime(p.get('created_at')),
            })
        return jsonify({'success': True, 'pulses': result})
    except Exception as e:
        current_app.logger.error(f"Pulses list error: {e}")
        return jsonify({'error': 'Failed to load pulses'}), 500


@bp.route('/api/bonds/<bond_id>/pulse', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def api_bond_pulse_send(bond_id):
    """Send a quick pulse (anytime check-in)."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        emoji = (data.get('emoji', '😊') or '').strip()
        if emoji not in PULSE_EMOJIS:
            emoji = '😊'
        message = (data.get('message', '') or '').strip()[:140]

        now = datetime.datetime.now(datetime.timezone.utc)
        encrypted_message = m.encrypt_bond_data(message, bond_id) if message else ''
        result = m.bond_pulses_conf.insert_one({
            'bond_id': ObjectId(bond_id),
            'user_id': ObjectId(user_id_str),
            'emoji': emoji,
            'message': encrypted_message,
            'created_at': now,
            'encrypted': True,
        })

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        pulse_data = {
            'bond_id': bond_id,
            'pulse_id': str(result.inserted_id),
            'from_user_id': user_id_str,
            'from_username': current_user.username,
            'emoji': emoji,
            'message': message,
            'created_at': _format_datetime(now),
        }
        m.socketio.emit('bond_pulse_received', pulse_data, room=f"user_{partner_id}")

        m.send_push_notification_to_user(
            partner_id,
            f"{emoji} {current_user.username} sent a pulse",
            message if message else "Thinking of you!",
            url=url_for('bonds.bonds_page', _external=True),
            tag=f'bond-pulse-{bond_id}'
        )

        _on_bond_action(bond_doc, 'pulses', current_user.id)

        return jsonify({'success': True, 'id': str(result.inserted_id)})
    except Exception as e:
        current_app.logger.error(f"Pulse send error: {e}")
        return jsonify({'error': 'Failed to send pulse'}), 500


@bp.route('/api/bonds/<bond_id>/dismiss_archive', methods=['POST'])
@login_required
def api_bond_dismiss_archive(bond_id):
    """Dismiss/hide an archived past bond from current user's past bonds view."""
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'broken'})
        if not bond_doc:
            return jsonify({'error': 'Past bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$addToSet': {'dismissed_by': ObjectId(user_id_str)}}
        )
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"Dismiss archive error: {e}")
        return jsonify({'error': 'Failed to dismiss past bond'}), 500


@bp.route('/api/bonds/<bond_id>/view-section', methods=['POST'])
@login_required
def api_bond_view_section(bond_id):
    """Mark a section as viewed by the current user (clears its unread badge)."""
    import main as m
    try:
        data = request.get_json() or {}
        section = data.get('section', '').strip()
        if section not in BOND_SECTIONS:
            return jsonify({'error': 'Invalid section'}), 400

        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404
        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        now = datetime.datetime.now(datetime.timezone.utc)
        m.bonds_conf.update_one(
            {'_id': ObjectId(bond_id)},
            {'$set': {f'last_viewed.{user_id_str}.{section}': now}}
        )
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.error(f"View section error: {e}")
        return jsonify({'error': 'Failed to mark section as viewed'}), 500


# --- Offline Sync ---

@bp.route('/api/bonds/<bond_id>/offline-sync', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def api_bond_offline_sync(bond_id):
    """Batch-sync offline bond actions (journal, mood, QotD, habit_toggle).

    Accepts an array of actions, each tagged with a UTC date string.
    Actions are processed in chronological order; the streak is bridged
    across all offline days.  Duplicates (e.g. mood already logged for
    that date online) are silently skipped.

    All datetimes are timezone-aware UTC.
    """
    import main as m
    from security import parse_iso_utc

    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': 'active'})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        data = request.get_json(silent=True) or {}
        actions = data.get('actions')
        if not actions or not isinstance(actions, list):
            return jsonify({'error': 'No actions provided'}), 400

        # Safety limits
        MAX_ACTIONS = 120   # ~4 actions/day * 30 days
        MAX_BACKDATE_DAYS = 30
        if len(actions) > MAX_ACTIONS:
            return jsonify({'error': f'Too many actions (max {MAX_ACTIONS})'}), 400

        now = datetime.datetime.now(datetime.timezone.utc)
        today = now.date()
        earliest_allowed = today - datetime.timedelta(days=MAX_BACKDATE_DAYS)
        latest_allowed = today + datetime.timedelta(days=1)  # Timezone offset buffer (+1 to +14)

        results = []
        streak_dates = set()
        user_oid = ObjectId(current_user.id)

        # Sort actions chronologically by date
        def _parse_action_date(action):
            d = action.get('date', '')
            try:
                return datetime.date.fromisoformat(str(d))
            except (ValueError, TypeError):
                return today

        actions_sorted = sorted(actions, key=_parse_action_date)

        for action in actions_sorted:
            action_type = (action.get('type') or '').strip().lower()
            date_str = (action.get('date') or '').strip()

            # Parse and validate date
            try:
                action_date = datetime.date.fromisoformat(date_str)
            except (ValueError, TypeError):
                results.append({'type': action_type, 'date': date_str, 'status': 'error', 'reason': 'invalid date'})
                continue

            if action_date > latest_allowed:
                results.append({'type': action_type, 'date': date_str, 'status': 'error', 'reason': 'future date'})
                continue
            if action_date < earliest_allowed:
                results.append({'type': action_type, 'date': date_str, 'status': 'error', 'reason': 'too far back'})
                continue

            # Build a timezone-aware UTC datetime at noon for this date
            action_dt = datetime.datetime(
                action_date.year, action_date.month, action_date.day,
                12, 0, 0, tzinfo=datetime.timezone.utc
            )

            try:
                if action_type == 'journal':
                    content = (action.get('content') or '').strip()
                    if not content or len(content) > 5000:
                        results.append({'type': 'journal', 'date': date_str, 'status': 'error', 'reason': 'content required (max 5000)'})
                        continue
                    encrypted_content = m.encrypt_bond_data(content, bond_id)
                    m.bond_journal_conf.insert_one({
                        'bond_id': ObjectId(bond_id),
                        'author_id': user_oid,
                        'content': encrypted_content,
                        'encrypted': True,
                        'created_at': action_dt,
                        'updated_at': action_dt,
                        'offline_sync': True,
                    })
                    streak_dates.add(action_date)
                    results.append({'type': 'journal', 'date': date_str, 'status': 'synced'})

                elif action_type == 'mood':
                    mood = (action.get('mood') or '').strip()
                    if mood not in BOND_MOODS:
                        results.append({'type': 'mood', 'date': date_str, 'status': 'error', 'reason': 'invalid mood'})
                        continue
                    # Skip if mood already logged for this date
                    existing = m.bond_moods_conf.find_one({
                        'bond_id': ObjectId(bond_id),
                        'date': date_str,
                        'user_id': user_oid,
                    })
                    if existing:
                        results.append({'type': 'mood', 'date': date_str, 'status': 'skipped', 'reason': 'already logged'})
                        streak_dates.add(action_date)
                        continue
                    encrypted_mood = m.encrypt_bond_data(mood, bond_id)
                    m.bond_moods_conf.insert_one({
                        'bond_id': ObjectId(bond_id),
                        'date': date_str,
                        'user_id': user_oid,
                        'mood': encrypted_mood,
                        'encrypted': True,
                        'created_at': action_dt,
                        'offline_sync': True,
                    })
                    streak_dates.add(action_date)
                    results.append({'type': 'mood', 'date': date_str, 'status': 'synced'})

                elif action_type == 'qotd':
                    answer = (action.get('answer') or '').strip()
                    if not answer or len(answer) > 1000:
                        results.append({'type': 'qotd', 'date': date_str, 'status': 'error', 'reason': 'answer required (max 1000)'})
                        continue
                    # Ensure question doc exists for this date
                    qotd_doc = m.bond_qotd_conf.find_one({
                        'bond_id': ObjectId(bond_id),
                        'date': date_str,
                    })
                    if not qotd_doc:
                        question_text, question_category = _get_daily_question(bond_doc)
                        # Override with the correct date's question using the
                        # deterministic hash
                        hash_input = f"{bond_id}:{date_str}"
                        bond_type = bond_doc.get('bond_type', 'custom')
                        type_questions = QUESTION_BANK.get(bond_type, [])
                        universal = QUESTION_BANK.get('universal', [])
                        pool = type_questions + type_questions + universal
                        if not pool:
                            pool = universal or ["What's on your mind today?"]
                        hash_val = int(hashlib.sha256(hash_input.encode()).hexdigest(), 16)
                        idx = hash_val % len(pool)
                        question_text = pool[idx]
                        question_category = BOND_TYPES.get(bond_type, {}).get('label', 'Custom') if pool[idx] in type_questions else 'Universal'

                        qotd_doc = {
                            'bond_id': ObjectId(bond_id),
                            'date': date_str,
                            'question_text': question_text,
                            'question_category': question_category,
                            'answers': {},
                            'created_at': action_dt,
                        }
                        try:
                            m.bond_qotd_conf.insert_one(qotd_doc)
                        except Exception:
                            qotd_doc = m.bond_qotd_conf.find_one({
                                'bond_id': ObjectId(bond_id),
                                'date': date_str,
                            })

                    # Check if user already answered
                    answer_key = f'answers.{user_id_str}'
                    if qotd_doc and qotd_doc.get('answers', {}).get(user_id_str):
                        results.append({'type': 'qotd', 'date': date_str, 'status': 'skipped', 'reason': 'already answered'})
                        streak_dates.add(action_date)
                        continue

                    encrypted_ans = m.encrypt_bond_data(answer, bond_id)
                    m.bond_qotd_conf.update_one(
                        {'bond_id': ObjectId(bond_id), 'date': date_str},
                        {'$set': {answer_key: {'answer': encrypted_ans, 'encrypted': True, 'answered_at': action_dt, 'offline_sync': True}}},
                        upsert=True
                    )
                    streak_dates.add(action_date)
                    results.append({'type': 'qotd', 'date': date_str, 'status': 'synced'})

                elif action_type == 'habit_toggle':
                    habit_id = action.get('habit_id', '')
                    if not habit_id:
                        results.append({'type': 'habit_toggle', 'date': date_str, 'status': 'error', 'reason': 'habit_id required'})
                        continue
                    habit = m.bond_habits_conf.find_one({'_id': ObjectId(habit_id)})
                    if not habit or str(habit.get('bond_id')) != bond_id:
                        results.append({'type': 'habit_toggle', 'date': date_str, 'status': 'error', 'reason': 'habit not found'})
                        continue
                    log_key = f'logs.{date_str}.{user_id_str}'
                    m.bond_habits_conf.update_one(
                        {'_id': ObjectId(habit_id)},
                        {'$set': {log_key: {'completed': True, 'completed_at': action_dt, 'offline_sync': True}}}
                    )
                    streak_dates.add(action_date)
                    results.append({'type': 'habit_toggle', 'date': date_str, 'status': 'synced'})

                else:
                    results.append({'type': action_type, 'date': date_str, 'status': 'error', 'reason': 'unknown action type'})

            except Exception as e:
                current_app.logger.error(f"Offline sync action error ({action_type}, {date_str}): {e}")
                results.append({'type': action_type, 'date': date_str, 'status': 'error', 'reason': 'server error'})

        # Bridge streak across all offline dates
        if streak_dates:
            _bridge_offline_streak(bond_id, streak_dates)

        # Notify partner about synced activity
        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        synced_count = sum(1 for r in results if r.get('status') == 'synced')
        if synced_count > 0:
            synced_dates = sorted(set(r['date'] for r in results if r.get('status') == 'synced'))
            day_label = f"{len(synced_dates)} day{'s' if len(synced_dates) != 1 else ''}"

            m.socketio.emit('bond_offline_synced', {
                'bond_id': bond_id,
                'by_username': current_user.username,
                'synced_count': synced_count,
                'synced_dates': synced_dates,
            }, room=f"user_{partner_id}")

            m.send_push_notification_to_user(
                partner_id,
                f"{current_user.username} synced {day_label} of bond activity",
                "Check your bond for new journal entries, moods, and more.",
                url=url_for('bonds.bonds_page', _external=True),
                tag=f'bond-offline-sync-{bond_id}'
            )

            # Update section activity for sections that received data
            synced_types = set(r['type'] for r in results if r.get('status') == 'synced')
            section_map = {'journal': 'journal', 'mood': 'mood', 'qotd': 'qotd', 'habit_toggle': 'habits'}
            for atype in synced_types:
                section = section_map.get(atype)
                if section:
                    _on_bond_action(bond_doc, section, current_user.id)

        # Re-read updated streak to return
        updated_bond = m.bonds_conf.find_one({'_id': ObjectId(bond_id)}, {'streak_count': 1, 'last_streak_date': 1})
        streak_info = {
            'streak_count': updated_bond.get('streak_count', 0) if updated_bond else 0,
        }

        return jsonify({
            'success': True,
            'synced': synced_count,
            'total': len(results),
            'results': results,
            'streak': streak_info,
        })

    except Exception as e:
        current_app.logger.error(f"Offline sync error for bond {bond_id}: {e}")
        return jsonify({'error': 'Failed to sync offline actions'}), 500


@bp.route('/api/bonds/<bond_id>/export', methods=['GET'])
@login_required
@limits(calls=10, period=60)
def api_bond_export(bond_id):
    """Export a complete Memory Book of the bond in structured JSON format.

    Decrypts all memories (Q&As, journals, goals, countdowns, bucket list)
    and returns a clean, personal archive.
    """
    import main as m
    try:
        bond_doc = m.bonds_conf.find_one({'_id': ObjectId(bond_id), 'status': {'$in': ['active', 'broken']}})
        if not bond_doc:
            return jsonify({'error': 'Bond not found'}), 404

        user_id_str = str(current_user.id)
        if not _is_bond_participant(bond_doc, user_id_str):
            return jsonify({'error': 'Not authorized'}), 403

        partner_id = _get_partner_id_from_bond(bond_doc, user_id_str)
        partner_user = m.users_conf.find_one({'_id': ObjectId(partner_id)}, {'username': 1})
        partner_username = _clean_username(partner_user['username'] if partner_user else 'Partner')
        my_username = _clean_username(current_user.username)

        bond_oid = ObjectId(bond_id)

        # 1. Journals
        journals = []
        for j in m.bond_journal_conf.find({'bond_id': bond_oid}).sort('created_at', 1):
            content = j.get('content', '')
            if j.get('encrypted') and content:
                try:
                    content = m.decrypt_bond_data(content, bond_id)
                except Exception:
                    content = '[Encrypted]'
            journals.append({
                'date': _format_datetime(j.get('created_at')),
                'author': my_username if str(j.get('author_id')) == user_id_str else partner_username,
                'content': content
            })

        # 2. Q&As
        qotds = []
        for q in m.bond_qotd_conf.find({'bond_id': bond_oid, 'revealed': True}).sort('date', 1):
            q_text = q.get('question_text', '')
            if q.get('encrypted') and q_text:
                try:
                    q_text = m.decrypt_bond_data(q_text, bond_id)
                except Exception:
                    pass
            answers = q.get('answers', {})
            my_ans = answers.get(user_id_str, {}).get('text', '')
            partner_ans = answers.get(partner_id, {}).get('text', '')
            if q.get('encrypted'):
                try:
                    if my_ans:
                        my_ans = m.decrypt_bond_data(my_ans, bond_id)
                    if partner_ans:
                        partner_ans = m.decrypt_bond_data(partner_ans, bond_id)
                except Exception:
                    pass
            qotds.append({
                'date': q.get('date', ''),
                'question': q_text,
                'my_answer': my_ans,
                'partner_answer': partner_ans
            })

        # 3. Goals
        goals = []
        for g in m.bond_goals_conf.find({'bond_id': bond_oid}).sort('created_at', 1):
            title = g.get('title', '')
            if g.get('encrypted') and title:
                try:
                    title = m.decrypt_bond_data(title, bond_id)
                except Exception:
                    pass
            goals.append({
                'title': title,
                'category': g.get('category', 'Custom'),
                'status': g.get('status', 'active'),
                'created_at': _format_datetime(g.get('created_at')),
                'completed_at': _format_datetime(g.get('completed_at')) if g.get('completed_at') else None
            })

        # 4. Countdowns & Milestones
        countdowns = []
        for c in m.bond_countdowns_conf.find({'bond_id': bond_oid}).sort('target_date', 1):
            title = c.get('title', '')
            if c.get('encrypted') and title:
                try:
                    title = m.decrypt_bond_data(title, bond_id)
                except Exception:
                    pass
            countdowns.append({
                'title': title,
                'target_date': str(c.get('target_date', ''))
            })

        export_data = {
            'bond_title': f"{my_username} & {partner_username}'s Memory Book",
            'relationship_type': BOND_TYPES.get(bond_doc.get('bond_type', 'custom'), {}).get('label', 'Bond'),
            'bonded_since': _format_datetime(bond_doc.get('accepted_at') or bond_doc.get('created_at')),
            'current_streak': bond_doc.get('streak_count', 0),
            'best_streak': bond_doc.get('best_streak', 0),
            'exported_at': datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            'journals': journals,
            'daily_questions': qotds,
            'goals': goals,
            'countdowns': countdowns
        }

        return jsonify({'success': True, 'data': export_data})

    except Exception as e:
        current_app.logger.error(f"Bond export error for {bond_id}: {e}")
        return jsonify({'error': 'Failed to export memories'}), 500

