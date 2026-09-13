from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets, math
from security import limits

bp = Blueprint('tournaments', __name__)

ALLOWED_TOURNAMENT_GAMES = ('tic_tac_toe', 'connect_four', 'dots_and_boxes', 'ping_pong', 'slime_volleyball')
MAX_PLAYERS = 32
VALID_SIZES = (4, 8, 16, 32)

GAME_LABELS = {
    'tic_tac_toe': 'Tic-Tac-Toe',
    'connect_four': 'Connect Four',
    'dots_and_boxes': 'Dots & Boxes',
    'ping_pong': 'Ping Pong',
    'slime_volleyball': 'Slime Volleyball',
}


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat().replace('+00:00', 'Z')


def _generate_bracket(participants, game):
    """Generate single-elimination bracket seeded by ELO.

    If participant count isn't a power of 2, top seeds get byes.
    Returns list of match dicts for round 1.
    """
    import main as m
    # Fetch ELO for seeding
    for p in participants:
        stats = m.player_stats_conf.find_one({'user_id': p['user_id'], 'game': game})
        p['elo'] = stats.get('elo', 1200) if stats else 1200

    # Sort by ELO descending (seed 1 = highest)
    participants.sort(key=lambda x: x['elo'], reverse=True)
    for i, p in enumerate(participants):
        p['seed'] = i + 1

    n = len(participants)
    # Next power of 2
    bracket_size = 1
    while bracket_size < n:
        bracket_size *= 2

    # Number of byes
    num_byes = bracket_size - n

    # Standard tournament seeding: seed 1 vs seed N, seed 2 vs seed N-1, etc.
    # Fill with None for byes
    slots = list(participants) + [None] * num_byes

    bracket = []
    total_rounds = int(math.log2(bracket_size))

    for i in range(bracket_size // 2):
        # Standard seeding: pair slot[i] vs slot[bracket_size - 1 - i]
        a = slots[i] if i < len(slots) else None
        b_idx = bracket_size - 1 - i
        b = slots[b_idx] if b_idx < len(slots) else None

        match = {
            'round': 1,
            'match_index': i,
            'player_a': a['user_id'] if a else None,
            'player_a_name': a.get('username') if a else None,
            'player_a_seed': a.get('seed') if a else None,
            'player_b': b['user_id'] if b else None,
            'player_b_name': b.get('username') if b else None,
            'player_b_seed': b.get('seed') if b else None,
            'winner_id': None,
            'match_history_id': None,
            'status': 'pending'
        }

        # Auto-advance byes
        if a and not b:
            match['winner_id'] = a['user_id']
            match['status'] = 'bye'
        elif b and not a:
            match['winner_id'] = b['user_id']
            match['status'] = 'bye'

        bracket.append(match)

    # Pre-create empty slots for future rounds
    remaining = bracket_size // 2
    for r in range(2, total_rounds + 1):
        remaining //= 2
        for j in range(remaining):
            bracket.append({
                'round': r,
                'match_index': j,
                'player_a': None,
                'player_a_name': None,
                'player_a_seed': None,
                'player_b': None,
                'player_b_name': None,
                'player_b_seed': None,
                'winner_id': None,
                'match_history_id': None,
                'status': 'pending'
            })

    return bracket, total_rounds


def _serialize_tournament(doc):
    if not doc:
        return None
    return {
        'id': str(doc['_id']),
        'community_id': str(doc.get('community_id', '')),
        'game': doc.get('game'),
        'game_label': GAME_LABELS.get(doc.get('game'), doc.get('game')),
        'title': doc.get('title', ''),
        'created_by': str(doc.get('created_by', '')),
        'status': doc.get('status', 'registration'),
        'max_players': doc.get('max_players', 16),
        'participants': doc.get('participants', []),
        'participant_count': len(doc.get('participants', [])),
        'bracket': doc.get('bracket', []),
        'current_round': doc.get('current_round', 0),
        'total_rounds': doc.get('total_rounds', 0),
        'champion_id': doc.get('champion_id'),
        'registration_ends_at': _iso(doc.get('registration_ends_at')),
        'created_at': _iso(doc.get('created_at')),
        'completed_at': _iso(doc.get('completed_at')),
    }


@bp.route('/api/community/<community_id>/tournament/create', methods=['POST'])
@login_required
@limits(calls=3, period=3600)
def api_create_tournament(community_id):
    """Create a tournament for a community (admin only)."""
    import main as m
    try:
        comm_oid = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid community ID'}), 400

    community = m.communities_conf.find_one({'_id': comm_oid})
    if not community:
        return jsonify({'error': 'Community not found'}), 404

    # Only admin can create
    if str(community.get('admin_id')) != str(current_user.id):
        return jsonify({'error': 'Only admins can create tournaments'}), 403

    # Check no active tournament
    existing = m.community_tournaments_conf.find_one({
        'community_id': comm_oid,
        'status': {'$in': ['registration', 'in_progress']}
    })
    if existing:
        return jsonify({'error': 'There is already an active tournament. Complete or cancel it first.'}), 409

    data = request.get_json(silent=True) or {}
    game = (data.get('game') or '').strip()
    title = (data.get('title') or '').strip()[:100]
    try:
        max_players = int(data.get('max_players', 16))
    except (ValueError, TypeError):
        max_players = 16
    if max_players not in VALID_SIZES:
        max_players = 16

    if game not in ALLOWED_TOURNAMENT_GAMES:
        return jsonify({'error': 'Invalid game type'}), 400
    if not title:
        title = f"{GAME_LABELS.get(game, game)} Tournament"

    reg_hours = min(max(int(data.get('registration_hours', 48) or 48), 1), 168)
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    doc = {
        'community_id': comm_oid,
        'game': game,
        'title': title,
        'created_by': ObjectId(current_user.id),
        'status': 'registration',
        'max_players': max_players,
        'participants': [],
        'bracket': [],
        'current_round': 0,
        'total_rounds': 0,
        'registration_ends_at': now_utc + datetime.timedelta(hours=reg_hours),
        'created_at': now_utc,
        'completed_at': None,
        'champion_id': None
    }
    m.community_tournaments_conf.insert_one(doc)

    return jsonify({'success': True, 'tournament': _serialize_tournament(doc)})


@bp.route('/api/tournament/<tournament_id>/register', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_register_tournament(tournament_id):
    """Register for a tournament."""
    import main as m
    try:
        t_oid = ObjectId(tournament_id)
    except Exception:
        return jsonify({'error': 'Invalid tournament ID'}), 400

    tourn = m.community_tournaments_conf.find_one({'_id': t_oid})
    if not tourn:
        return jsonify({'error': 'Tournament not found'}), 404
    if tourn.get('status') != 'registration':
        return jsonify({'error': 'Registration is closed'}), 409

    uid = str(current_user.id)
    participants = tourn.get('participants', [])

    # Check if already registered
    if any(p.get('user_id') == uid for p in participants):
        return jsonify({'error': 'Already registered'}), 409

    # Check capacity
    if len(participants) >= tourn.get('max_players', 16):
        return jsonify({'error': 'Tournament is full'}), 409

    # Must be community member
    comm_id = tourn.get('community_id')
    membership = m.community_memberships_conf.find_one({
        'community_id': comm_id,
        'user_id': ObjectId(current_user.id)
    })
    if not membership:
        return jsonify({'error': 'You must be a community member to join'}), 403

    m.community_tournaments_conf.update_one(
        {'_id': t_oid},
        {'$push': {'participants': {
            'user_id': uid,
            'username': current_user.username,
            'seed': 0,
            'elo': 1200
        }}}
    )

    return jsonify({'success': True})


@bp.route('/api/tournament/<tournament_id>/start', methods=['POST'])
@login_required
def api_start_tournament(tournament_id):
    """Start the tournament (admin only). Generates bracket."""
    import main as m
    try:
        t_oid = ObjectId(tournament_id)
    except Exception:
        return jsonify({'error': 'Invalid tournament ID'}), 400

    tourn = m.community_tournaments_conf.find_one({'_id': t_oid})
    if not tourn:
        return jsonify({'error': 'Tournament not found'}), 404
    if tourn.get('status') != 'registration':
        return jsonify({'error': 'Tournament already started or completed'}), 409

    comm = m.communities_conf.find_one({'_id': tourn['community_id']})
    if not comm or str(comm.get('admin_id')) != str(current_user.id):
        return jsonify({'error': 'Only the community admin can start tournaments'}), 403

    participants = tourn.get('participants', [])
    if len(participants) < 2:
        return jsonify({'error': 'Need at least 2 participants'}), 400

    bracket, total_rounds = _generate_bracket(participants, tourn['game'])

    # Advance byes in round 1 to populate round 2
    bracket = _advance_byes(bracket, total_rounds)

    m.community_tournaments_conf.update_one(
        {'_id': t_oid},
        {'$set': {
            'status': 'in_progress',
            'bracket': bracket,
            'current_round': 1,
            'total_rounds': total_rounds,
            'participants': participants  # now seeded
        }}
    )

    return jsonify({'success': True})


def _advance_byes(bracket, total_rounds):
    """After bracket generation, advance bye winners into the next round slots."""
    for r in range(1, total_rounds):
        r_matches = [m for m in bracket if m['round'] == r]
        next_matches = [m for m in bracket if m['round'] == r + 1]
        for i, match in enumerate(r_matches):
            if match.get('status') == 'bye' and match.get('winner_id'):
                next_idx = i // 2
                if next_idx < len(next_matches):
                    nm = next_matches[next_idx]
                    if i % 2 == 0:
                        nm['player_a'] = match['winner_id']
                        nm['player_a_name'] = match.get('player_a_name') if match.get('winner_id') == match.get('player_a') else match.get('player_b_name')
                        nm['player_a_seed'] = match.get('player_a_seed') if match.get('winner_id') == match.get('player_a') else match.get('player_b_seed')
                    else:
                        nm['player_b'] = match['winner_id']
                        nm['player_b_name'] = match.get('player_a_name') if match.get('winner_id') == match.get('player_a') else match.get('player_b_name')
                        nm['player_b_seed'] = match.get('player_a_seed') if match.get('winner_id') == match.get('player_a') else match.get('player_b_seed')
    return bracket


@bp.route('/api/tournament/<tournament_id>', methods=['GET'])
@login_required
def api_get_tournament(tournament_id):
    """Get tournament bracket and details."""
    import main as m
    try:
        t_oid = ObjectId(tournament_id)
    except Exception:
        return jsonify({'error': 'Invalid tournament ID'}), 400

    tourn = m.community_tournaments_conf.find_one({'_id': t_oid})
    if not tourn:
        return jsonify({'error': 'Tournament not found'}), 404

    return jsonify({'tournament': _serialize_tournament(tourn)})


@bp.route('/api/tournament/<tournament_id>/report-match', methods=['POST'])
@login_required
def api_report_tournament_match(tournament_id):
    """Report a tournament match result (auto-called when match concludes)."""
    import main as m
    try:
        t_oid = ObjectId(tournament_id)
    except Exception:
        return jsonify({'error': 'Invalid tournament ID'}), 400

    tourn = m.community_tournaments_conf.find_one({'_id': t_oid})
    if not tourn or tourn.get('status') != 'in_progress':
        return jsonify({'error': 'Tournament not found or not in progress'}), 404

    data = request.get_json(silent=True) or {}
    match_index = data.get('match_index')
    round_num = data.get('round')
    winner_id = data.get('winner_id')

    if match_index is None or round_num is None or not winner_id:
        return jsonify({'error': 'Missing match_index, round, or winner_id'}), 400

    bracket = tourn.get('bracket', [])
    target = None
    for m_entry in bracket:
        if m_entry['round'] == round_num and m_entry['match_index'] == match_index:
            target = m_entry
            break

    if not target:
        return jsonify({'error': 'Match not found in bracket'}), 404
    if target.get('status') == 'completed':
        return jsonify({'error': 'Match already completed'}), 409
    if winner_id not in (target.get('player_a'), target.get('player_b')):
        return jsonify({'error': 'Winner must be one of the match participants'}), 400

    target['winner_id'] = winner_id
    target['status'] = 'completed'
    target['match_history_id'] = data.get('match_history_id')

    # Advance winner to next round
    total_rounds = tourn.get('total_rounds', 0)
    if round_num < total_rounds:
        next_matches = [m_e for m_e in bracket if m_e['round'] == round_num + 1]
        next_idx = match_index // 2
        if next_idx < len(next_matches):
            nm = next_matches[next_idx]
            winner_name = target.get('player_a_name') if winner_id == target.get('player_a') else target.get('player_b_name')
            winner_seed = target.get('player_a_seed') if winner_id == target.get('player_a') else target.get('player_b_seed')
            if match_index % 2 == 0:
                nm['player_a'] = winner_id
                nm['player_a_name'] = winner_name
                nm['player_a_seed'] = winner_seed
            else:
                nm['player_b'] = winner_id
                nm['player_b_name'] = winner_name
                nm['player_b_seed'] = winner_seed

    # Check if tournament is complete (final match has a winner)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    update = {'$set': {'bracket': bracket}}

    if round_num == total_rounds:
        update['$set']['status'] = 'completed'
        update['$set']['champion_id'] = winner_id
        update['$set']['completed_at'] = now_utc
    else:
        # Update current_round to the highest round with pending matches
        for r in range(total_rounds, 0, -1):
            r_matches = [m_e for m_e in bracket if m_e['round'] == r and m_e.get('status') in ('pending', 'in_progress')]
            if r_matches:
                update['$set']['current_round'] = r
                break

    m.community_tournaments_conf.update_one({'_id': t_oid}, update)

    return jsonify({'success': True, 'tournament': _serialize_tournament(
        m.community_tournaments_conf.find_one({'_id': t_oid})
    )})


@bp.route('/api/tournament/<tournament_id>/cancel', methods=['POST'])
@login_required
def api_cancel_tournament(tournament_id):
    """Cancel a tournament (admin only)."""
    import main as m
    try:
        t_oid = ObjectId(tournament_id)
    except Exception:
        return jsonify({'error': 'Invalid tournament ID'}), 400

    tourn = m.community_tournaments_conf.find_one({'_id': t_oid})
    if not tourn:
        return jsonify({'error': 'Tournament not found'}), 404

    comm = m.communities_conf.find_one({'_id': tourn['community_id']})
    if not comm or str(comm.get('admin_id')) != str(current_user.id):
        return jsonify({'error': 'Only the community admin can cancel tournaments'}), 403

    m.community_tournaments_conf.update_one(
        {'_id': t_oid},
        {'$set': {'status': 'cancelled'}}
    )

    return jsonify({'success': True})


@bp.route('/api/community/<community_id>/tournaments', methods=['GET'])
@login_required
def api_list_tournaments(community_id):
    """List tournaments for a community."""
    import main as m
    try:
        comm_oid = ObjectId(community_id)
    except Exception:
        return jsonify({'error': 'Invalid community ID'}), 400

    cursor = m.community_tournaments_conf.find(
        {'community_id': comm_oid}
    ).sort('created_at', -1).limit(20)

    tournaments = [_serialize_tournament(doc) for doc in cursor]
    return jsonify({'tournaments': tournaments})
