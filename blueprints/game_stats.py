from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime
from security import limits

bp = Blueprint('game_stats', __name__)

ELO_TIERS = [
    (1900, 'Diamond'),
    (1600, 'Platinum'),
    (1300, 'Gold'),
    (1000, 'Silver'),
    (0, 'Bronze'),
]

GAME_LABELS = {
    'tic_tac_toe': 'Tic-Tac-Toe',
    'connect_four': 'Connect Four',
    'dots_and_boxes': 'Dots & Boxes',
    'ping_pong': 'Ping Pong',
    'slime_volleyball': 'Slime Volleyball',
}


def _elo_tier(elo):
    for threshold, label in ELO_TIERS:
        if elo >= threshold:
            return label
    return 'Bronze'


def _serialize_stats(doc):
    """Convert a player_stats doc to a JSON-safe dict."""
    if not doc:
        return None
    return {
        'game': doc.get('game'),
        'game_label': GAME_LABELS.get(doc.get('game'), doc.get('game')),
        'wins': doc.get('wins', 0),
        'losses': doc.get('losses', 0),
        'draws': doc.get('draws', 0),
        'total_matches': doc.get('total_matches', 0),
        'win_rate': doc.get('win_rate', 0.0),
        'current_streak': doc.get('current_streak', 0),
        'best_streak': doc.get('best_streak', 0),
        'elo': doc.get('elo', 1200),
        'elo_tier': _elo_tier(doc.get('elo', 1200)),
        'last_played_at': _iso(doc.get('last_played_at')),
    }


def _iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat().replace('+00:00', 'Z')


def _serialize_match(doc, user_id=None):
    """Convert a match history doc to a JSON-safe dict."""
    if not doc:
        return None
    players = doc.get('players', [])
    opponent = None
    if user_id and len(players) >= 2:
        for p in players:
            if p.get('user_id') != user_id:
                opponent = p.get('username', 'Unknown')
                break

    result_for_user = None
    if user_id:
        if doc.get('winner_id') == user_id:
            result_for_user = 'win'
        elif doc.get('loser_id') == user_id:
            result_for_user = 'loss'
        else:
            result_for_user = 'draw'

    elo_change = (doc.get('elo_changes') or {}).get(user_id, 0) if user_id else 0

    return {
        'game': doc.get('game'),
        'game_label': GAME_LABELS.get(doc.get('game'), doc.get('game')),
        'room_id': doc.get('room_id'),
        'result': result_for_user or doc.get('result'),
        'opponent': opponent,
        'score': doc.get('score'),
        'elo_change': elo_change,
        'created_at': _iso(doc.get('created_at')),
    }


@bp.route('/api/games/stats/<game>', methods=['GET'])
@login_required
def api_game_stats(game):
    """Get current user's stats for a specific game."""
    import main as m
    if game not in GAME_LABELS:
        return jsonify({'error': 'Invalid game'}), 400
    doc = m.player_stats_conf.find_one({'user_id': str(current_user.id), 'game': game})
    return jsonify({'stats': _serialize_stats(doc)})


@bp.route('/api/games/stats/all', methods=['GET'])
@login_required
def api_all_game_stats():
    """Get current user's stats across all games."""
    import main as m
    uid = str(current_user.id)
    docs = list(m.player_stats_conf.find({'user_id': uid}))
    stats = [_serialize_stats(d) for d in docs if d]
    return jsonify({'stats': stats})


@bp.route('/api/games/match-history', methods=['GET'])
@login_required
def api_match_history():
    """Get paginated match history for current user."""
    import main as m
    uid = str(current_user.id)
    game = (request.args.get('game') or '').strip()
    try:
        limit = min(int(request.args.get('limit', 20)), 50)
    except (ValueError, TypeError):
        limit = 20
    try:
        offset = max(int(request.args.get('offset', 0)), 0)
    except (ValueError, TypeError):
        offset = 0

    query = {'players.user_id': uid}
    if game and game in GAME_LABELS:
        query['game'] = game

    cursor = m.game_match_history_conf.find(query).sort('created_at', -1).skip(offset).limit(limit)
    matches = [_serialize_match(doc, uid) for doc in cursor if doc]
    total = m.game_match_history_conf.count_documents(query)

    return jsonify({'matches': matches, 'total': total, 'limit': limit, 'offset': offset})


@bp.route('/api/games/profile/<user_id>', methods=['GET'])
@login_required
def api_game_profile(user_id):
    """Get public game profile (stats only, no PII beyond username)."""
    import main as m
    docs = list(m.player_stats_conf.find({'user_id': user_id}))
    stats = [_serialize_stats(d) for d in docs if d]
    return jsonify({'user_id': user_id, 'stats': stats})


@bp.route('/api/games/elo-leaderboard', methods=['GET'])
def api_elo_leaderboard():
    """Get top players by ELO for a specific game."""
    import main as m
    game = (request.args.get('game') or '').strip()
    if game not in GAME_LABELS:
        return jsonify({'leaders': []}), 200
    try:
        limit = min(int(request.args.get('limit', 20)), 50)
    except (ValueError, TypeError):
        limit = 20

    cursor = m.player_stats_conf.find(
        {'game': game, 'total_matches': {'$gte': 5}}
    ).sort('elo', -1).limit(limit)

    leaders = []
    for idx, doc in enumerate(cursor):
        leaders.append({
            'rank': idx + 1,
            'username': doc.get('username', 'Anonymous'),
            'elo': doc.get('elo', 1200),
            'elo_tier': _elo_tier(doc.get('elo', 1200)),
            'wins': doc.get('wins', 0),
            'losses': doc.get('losses', 0),
            'win_rate': doc.get('win_rate', 0.0),
        })

    # Current user's ELO rank
    user_rank = None
    if current_user.is_authenticated:
        uid = str(current_user.id)
        my_doc = m.player_stats_conf.find_one({'user_id': uid, 'game': game})
        if my_doc:
            higher = m.player_stats_conf.count_documents({
                'game': game,
                'total_matches': {'$gte': 5},
                'elo': {'$gt': my_doc.get('elo', 1200)}
            })
            user_rank = {
                'rank': higher + 1,
                'elo': my_doc.get('elo', 1200),
                'elo_tier': _elo_tier(my_doc.get('elo', 1200)),
                'wins': my_doc.get('wins', 0),
                'losses': my_doc.get('losses', 0),
            }

    return jsonify({
        'game': game,
        'game_label': GAME_LABELS.get(game, game),
        'entries': leaders,
        'user_rank': user_rank
    })
