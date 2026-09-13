"""Tests for Game System Improvements: Match History, ELO, Reactions, and Stats."""
import datetime
from unittest.mock import MagicMock, patch
from bson.objectid import ObjectId
import pytest


def test_calc_elo_ratings():
    import main as m
    # Player wins against equal opponent: should gain ~16 points (k=32 for <30 matches)
    new_elo = m._calc_elo(1200, 1200, 1.0, 5)
    assert new_elo == 1216

    # Player loses against equal opponent: should lose ~16 points
    loss_elo = m._calc_elo(1200, 1200, 0.0, 5)
    assert loss_elo == 1184

    # Draw against equal opponent: no change
    draw_elo = m._calc_elo(1200, 1200, 0.5, 5)
    assert draw_elo == 1200

    # Low ELO floor check
    floored = m._calc_elo(105, 1500, 0.0, 10)
    assert floored >= m.ELO_FLOOR


def test_record_match_result():
    import main as m
    p1_uid = 'u_test_player_1'
    p2_uid = 'u_test_player_2'
    bond_id = '507f1f77bcf86cd799439099'

    # Mock DB collections for isolated testing
    matches = []
    stats = {}
    h2h = {}

    def mock_insert_one(doc):
        doc['_id'] = ObjectId()
        matches.append(doc)
        return MagicMock(inserted_id=doc['_id'])

    def mock_find_one(query):
        if 'user_id' in query:
            return stats.get((query['user_id'], query['game']))
        if 'bond_id' in query:
            return h2h.get((str(query['bond_id']), query['game']))
        return None

    def mock_update_one(query, update, upsert=False):
        if 'user_id' in query:
            key = (query['user_id'], query['game'])
            cur = stats.get(key, {
                'user_id': query['user_id'], 'game': query['game'],
                'wins': 0, 'losses': 0, 'draws': 0, 'total_matches': 0,
                'current_streak': 0, 'best_streak': 0, 'win_rate': 0.0, 'elo': 1200
            })
            if '$inc' in update:
                for f, v in update['$inc'].items():
                    cur[f] = cur.get(f, 0) + v
            if '$set' in update:
                cur.update(update['$set'])
            stats[key] = cur
        elif 'bond_id' in query:
            key = (str(query['bond_id']), query['game'])
            cur = h2h.get(key, {
                'bond_id': query['bond_id'], 'game': query['game'],
                'user_a_id': query['user_a_id'], 'user_b_id': query['user_b_id'],
                'user_a_wins': 0, 'user_b_wins': 0, 'draws': 0, 'total_matches': 0
            })
            if '$inc' in update:
                for f, v in update['$inc'].items():
                    cur[f] = cur.get(f, 0) + v
            if '$set' in update:
                cur.update(update['$set'])
            h2h[key] = cur

    def mock_h2h_insert_one(doc):
        doc['_id'] = ObjectId()
        h2h[(str(doc['bond_id']), doc['game'])] = doc
        return MagicMock(inserted_id=doc['_id'])

    mock_history = MagicMock()
    mock_history.insert_one.side_effect = mock_insert_one

    mock_stats_col = MagicMock()
    mock_stats_col.find_one.side_effect = mock_find_one
    mock_stats_col.update_one.side_effect = mock_update_one

    mock_h2h_col = MagicMock()
    mock_h2h_col.find_one.side_effect = mock_find_one
    mock_h2h_col.insert_one.side_effect = mock_h2h_insert_one
    mock_h2h_col.update_one.side_effect = mock_update_one

    with patch.object(m, 'game_match_history_conf', mock_history), \
         patch.object(m, 'player_stats_conf', mock_stats_col), \
         patch.object(m, 'bond_h2h_records_conf', mock_h2h_col):

        # Record a match where p1 wins against p2
        doc = m.record_match_result(
            game='tic_tac_toe',
            room_id='ttt_test_room_1',
            players=[
                {'user_id': p1_uid, 'username': 'PlayerOne', 'side': 'x'},
                {'user_id': p2_uid, 'username': 'PlayerTwo', 'side': 'o'}
            ],
            winner_id=p1_uid,
            score={'x': 1, 'o': 0},
            bond_id=bond_id
        )

        assert doc is not None
        assert doc['result'] == 'win'
        assert doc['winner_id'] == p1_uid
        assert doc['loser_id'] == p2_uid
        assert p1_uid in doc['elo_changes']
        assert doc['elo_changes'][p1_uid] > 0
        assert doc['elo_changes'][p2_uid] < 0

        # Verify stats updated
        p1_stats = stats.get((p1_uid, 'tic_tac_toe'))
        assert p1_stats['wins'] == 1
        assert p1_stats['total_matches'] == 1
        assert p1_stats['current_streak'] == 1
        assert p1_stats['win_rate'] == 1.0

        p2_stats = stats.get((p2_uid, 'tic_tac_toe'))
        assert p2_stats['losses'] == 1
        assert p2_stats['total_matches'] == 1
        assert p2_stats['current_streak'] == -1

        # Verify H2H record updated
        h2h_key = (bond_id, 'tic_tac_toe')
        assert h2h_key in h2h
        assert h2h[h2h_key]['user_a_wins'] == 1
        assert h2h[h2h_key]['total_matches'] == 1


def test_game_reactions_handler():
    import main as m
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    m._game_reaction_timestamps.clear()

    # Find registered socket function when socketio is mocked
    handler = None
    for call in m.socketio.on.mock_calls:
        if len(call.args) > 0 and callable(call.args[0]) and getattr(call.args[0], '__name__', '') == 'handle_game_reaction':
            handler = call.args[0]
            break
    if not handler or not callable(handler):
        handler = m.handle_game_reaction

    req = MagicMock()
    req.sid = 'sid_12345'
    user = MagicMock()
    user.is_authenticated = True
    user.username = 'Reactor'

    # Valid emoji reaction
    with patch.object(m, 'request', req), \
         patch.object(m, 'current_user', user), \
         patch.object(m, 'emit') as mock_emit:
        handler({'room_id': 'room_abc', 'emoji': '🔥'})
        mock_emit.assert_called_once()
        args, kwargs = mock_emit.call_args
        assert args[0] == 'game_reaction'
        assert args[1]['emoji'] == '🔥'
        assert args[1]['sender_name'] == 'Reactor'
        assert kwargs['room'] == 'room_abc'
        assert kwargs['include_self'] is False

    # Second immediate reaction within 2s should be ignored by rate limit
    with patch.object(m, 'request', req), \
         patch.object(m, 'current_user', user), \
         patch.object(m, 'emit') as mock_emit_2:
        handler({'room_id': 'room_abc', 'emoji': '👏'})
        mock_emit_2.assert_not_called()

    # Invalid emoji should be ignored
    req.sid = 'sid_67890'
    with patch.object(m, 'request', req), \
         patch.object(m, 'current_user', user), \
         patch.object(m, 'emit') as mock_emit_3:
        handler({'room_id': 'room_abc', 'emoji': 'INVALID_EMOJI'})
        mock_emit_3.assert_not_called()

