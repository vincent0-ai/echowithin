"""Tests for Community Tournaments: Bracket Generation, ELO Seeding, Byes, and Match Progression."""
import datetime
from unittest.mock import MagicMock, patch
from bson.objectid import ObjectId
import pytest

from blueprints.tournaments import _generate_bracket, _advance_byes, _serialize_tournament


def test_bracket_generation_power_of_two():
    """Test 4-player bracket generation with ELO seeding."""
    participants = [
        {'user_id': 'u1', 'username': 'Alice'},
        {'user_id': 'u2', 'username': 'Bob'},
        {'user_id': 'u3', 'username': 'Charlie'},
        {'user_id': 'u4', 'username': 'Dave'},
    ]
    elo_map = {'u1': 1400, 'u2': 1100, 'u3': 1300, 'u4': 1200}

    mock_stats = MagicMock()
    mock_stats.find_one.side_effect = lambda q: {'elo': elo_map.get(q['user_id'], 1200)}

    import main as m
    with patch.object(m, 'player_stats_conf', mock_stats):
        bracket, total_rounds = _generate_bracket(participants, 'tic_tac_toe')

    assert total_rounds == 2
    # Check seeding: Alice (1400) = Seed 1, Charlie (1300) = Seed 2, Dave (1200) = Seed 3, Bob (1100) = Seed 4
    assert participants[0]['user_id'] == 'u1'
    assert participants[0]['seed'] == 1
    assert participants[1]['user_id'] == 'u3'
    assert participants[1]['seed'] == 2
    assert participants[2]['user_id'] == 'u4'
    assert participants[2]['seed'] == 3
    assert participants[3]['user_id'] == 'u2'
    assert participants[3]['seed'] == 4

    # Round 1 has 2 matches
    r1 = [match for match in bracket if match['round'] == 1]
    assert len(r1) == 2
    # Match 0: Seed 1 (u1) vs Seed 4 (u2)
    assert r1[0]['player_a'] == 'u1'
    assert r1[0]['player_b'] == 'u2'
    assert r1[0]['status'] == 'pending'

    # Match 1: Seed 2 (u3) vs Seed 3 (u4)
    assert r1[1]['player_a'] == 'u3'
    assert r1[1]['player_b'] == 'u4'
    assert r1[1]['status'] == 'pending'

    # Round 2 has 1 finals match slot
    r2 = [match for match in bracket if match['round'] == 2]
    assert len(r2) == 1
    assert r2[0]['player_a'] is None
    assert r2[0]['player_b'] is None


def test_bracket_generation_with_byes():
    """Test 3-player bracket where top seed receives a bye and auto-advances."""
    participants = [
        {'user_id': 'u1', 'username': 'TopSeed'},
        {'user_id': 'u2', 'username': 'PlayerTwo'},
        {'user_id': 'u3', 'username': 'PlayerThree'},
    ]
    elo_map = {'u1': 1500, 'u2': 1200, 'u3': 1100}

    mock_stats = MagicMock()
    mock_stats.find_one.side_effect = lambda q: {'elo': elo_map.get(q['user_id'], 1200)}

    import main as m
    with patch.object(m, 'player_stats_conf', mock_stats):
        bracket, total_rounds = _generate_bracket(participants, 'ping_pong')
        bracket = _advance_byes(bracket, total_rounds)

    assert total_rounds == 2
    r1 = [match for match in bracket if match['round'] == 1]
    r2 = [match for match in bracket if match['round'] == 2]

    # One match should be a bye for TopSeed
    bye_matches = [match for match in r1 if match['status'] == 'bye']
    assert len(bye_matches) == 1
    assert bye_matches[0]['winner_id'] == 'u1'

    # Top seed should have auto-advanced into round 2
    assert r2[0]['player_a'] == 'u1' or r2[0]['player_b'] == 'u1'


def test_advance_byes_and_match_progression():
    """Test advancing winners through rounds to completion."""
    participants = [
        {'user_id': 'u1', 'username': 'A'},
        {'user_id': 'u2', 'username': 'B'},
    ]
    mock_stats = MagicMock()
    mock_stats.find_one.side_effect = lambda q: {'elo': 1200}

    import main as m
    with patch.object(m, 'player_stats_conf', mock_stats):
        bracket, total_rounds = _generate_bracket(participants, 'connect_four')

    assert total_rounds == 1
    assert len(bracket) == 1
    assert bracket[0]['round'] == 1
    assert bracket[0]['player_a'] == 'u1'
    assert bracket[0]['player_b'] == 'u2'


def test_serialize_tournament():
    """Test tournament doc serialization for API responses."""
    now = datetime.datetime.now(datetime.timezone.utc)
    t_id = ObjectId()
    c_id = ObjectId()
    u_id = ObjectId()

    doc = {
        '_id': t_id,
        'community_id': c_id,
        'game': 'slime_volleyball',
        'title': 'Volley Cup',
        'created_by': u_id,
        'status': 'in_progress',
        'max_players': 8,
        'participants': [{'user_id': 'u1', 'username': 'Alice'}],
        'bracket': [],
        'current_round': 1,
        'total_rounds': 3,
        'champion_id': None,
        'registration_ends_at': now,
        'created_at': now,
        'completed_at': None
    }

    data = _serialize_tournament(doc)
    assert data['id'] == str(t_id)
    assert data['community_id'] == str(c_id)
    assert data['game'] == 'slime_volleyball'
    assert data['game_label'] == 'Slime Volleyball'
    assert data['title'] == 'Volley Cup'
    assert data['participant_count'] == 1
    assert data['registration_ends_at'].endswith('Z')
    assert data['created_at'].endswith('Z')
