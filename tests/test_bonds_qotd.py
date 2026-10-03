import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import patch, MagicMock
import hashlib

from blueprints.bonds import (
    QUESTION_BANK,
    QOTD_SKIP_REASONS,
    _normalize_question_hash,
    _get_bond_excluded_question_hashes,
    _get_daily_question,
    _get_community_bank_question,
)


class TestQotdBasicsAndConstants:
    """Test question bank sizes and skip reason constants."""

    def test_skip_reasons_contain_already_answered_and_boring(self):
        assert 'already_answered' in QOTD_SKIP_REASONS
        assert 'boring' in QOTD_SKIP_REASONS
        assert 'already_discussed' in QOTD_SKIP_REASONS
        assert 'too_personal' in QOTD_SKIP_REASONS
        assert 'not_relevant' in QOTD_SKIP_REASONS

    def test_question_bank_expansion(self):
        """Ensure question bank has deep, varied questions for each relationship type."""
        assert len(QUESTION_BANK['universal']) >= 50
        assert len(QUESTION_BANK['partner']) >= 40
        assert len(QUESTION_BANK['friend']) >= 40
        assert len(QUESTION_BANK['study_mate']) >= 25
        assert len(QUESTION_BANK['family']) >= 25
        assert len(QUESTION_BANK['accountability']) >= 25
        assert len(QUESTION_BANK['custom']) >= 10

    def test_normalize_question_hash(self):
        q1 = "What's on your mind today?"
        q2 = "  \"what's on your mind today?\"  "
        assert _normalize_question_hash(q1) == _normalize_question_hash(q2)
        assert _normalize_question_hash("") is None
        assert _normalize_question_hash(None) is None


class TestQotdLifetimeExclusion:
    """Test lifetime exclusion of answered and skipped questions for a bond."""

    def test_get_bond_excluded_hashes_from_bond_doc(self):
        dummy_hash_1 = hashlib.sha256(b"q1").hexdigest()
        dummy_hash_2 = hashlib.sha256(b"q2").hexdigest()
        bond_doc = {
            '_id': ObjectId(),
            'skipped_qotd_hashes': [dummy_hash_1],
            'answered_qotd_hashes': [dummy_hash_2],
        }
        with patch('main.bond_qotd_conf') as mock_conf:
            mock_conf.find.return_value = []
            excluded = _get_bond_excluded_question_hashes(str(bond_doc['_id']), bond_doc)
            assert dummy_hash_1 in excluded
            assert dummy_hash_2 in excluded

    def test_get_bond_excluded_hashes_from_history(self):
        bond_id = ObjectId()
        q_answered = "What is your favorite memory?"
        q_skipped = "What does your ideal Sunday look like?"
        h_answered = _normalize_question_hash(q_answered)
        h_skipped = _normalize_question_hash(q_skipped)

        mock_docs = [
            {
                'question_text': q_answered,
                'encrypted': False,
                'answers': {'user_1': {'answer': 'ans'}},
                'skips': [],
            },
            {
                'question_text': 'Replacement question',
                'encrypted': False,
                'answers': {},
                'skips': [{'question_text': q_skipped, 'question_hash': h_skipped, 'reason': 'boring'}],
            }
        ]

        with patch('main.bond_qotd_conf') as mock_conf:
            mock_conf.find.return_value = mock_docs
            excluded = _get_bond_excluded_question_hashes(str(bond_id))
            assert h_answered in excluded
            assert h_skipped in excluded

    def test_daily_question_excludes_answered_and_skipped(self):
        bond_id = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'bond_type': 'partner',
            'skipped_qotd_hashes': [],
            'answered_qotd_hashes': [],
        }

        # Pick the default first question for today
        with patch('main.bond_qotd_conf') as mock_conf:
            mock_conf.find.return_value = []
            first_q, _ = _get_daily_question(bond_doc)

        # Now mark that first question as skipped
        first_q_hash = _normalize_question_hash(first_q)
        bond_doc['skipped_qotd_hashes'] = [first_q_hash]

        with patch('main.bond_qotd_conf') as mock_conf:
            mock_conf.find.return_value = []
            second_q, _ = _get_daily_question(bond_doc)

        # The new question MUST NOT be the skipped question
        assert second_q != first_q
        assert _normalize_question_hash(second_q) != first_q_hash


class TestCommunityBankFiltering:
    """Test that community bank questions are properly excluded and filtered."""

    def test_community_bank_excludes_non_positive_votes(self):
        bond_id = ObjectId()
        with patch('main.bond_qotd_conf') as mock_qotd, \
             patch('main.community_questions_conf') as mock_comm:
            mock_qotd.find.return_value = []
            mock_comm.aggregate.return_value = []

            _get_community_bank_question('partner', bond_id)

            pipeline = mock_comm.aggregate.call_args[0][0]
            match_stage = pipeline[0]['$match']
            found_vote_filter = False
            if match_stage.get('votes') == {'$gt': 0}:
                found_vote_filter = True
            elif '$and' in match_stage:
                for cond in match_stage['$and']:
                    if cond.get('votes') == {'$gt': 0}:
                        found_vote_filter = True
            assert found_vote_filter is True


class TestQotdDepthAndThemedDays:
    """Test progressive depth tier resolution and themed days filtering."""

    def test_depth_tiers(self):
        from blueprints.bonds import _get_depth_tier
        assert _get_depth_tier(0)[3] == 'Icebreaker'
        assert _get_depth_tier(5)[3] == 'Icebreaker'
        assert _get_depth_tier(10)[3] == 'Building'
        assert _get_depth_tier(24)[3] == 'Building'
        assert _get_depth_tier(25)[3] == 'Deepening'
        assert _get_depth_tier(50)[3] == 'Deep Bond'
        assert _get_depth_tier(100)[3] == 'Deep Bond'

    def test_filter_by_theme(self):
        from blueprints.bonds import _filter_by_theme
        questions = [
            "What is your favorite memory?",
            "Do you remember your first day?",
            "What childhood memory stands out?",
            "What is a story you like to tell?",
            "What tradition do you keep?",
            "What is your dream?",
            "What goal do you have?"
        ]
        # Monday is 0 (Memory Monday)
        themed = _filter_by_theme(questions, 0)
        assert len(themed) >= 5
        assert all(any(kw in q.lower() for kw in ['memory', 'remember', 'childhood', 'past', 'first', 'favourite', 'favorite', 'photo', 'story', 'tradition']) for q in themed)
        # Friday is 4 (Free Friday - no filtering)
        free = _filter_by_theme(questions, 4)
        assert free == questions


class TestQotdHistoryPagination:
    """Test pagination and mutual reveal behavior in api_bond_qotd_history."""

    def test_history_pagination_response_format(self, auth_client, mock_user):
        bond_id = ObjectId()
        partner_id = ObjectId()
        bond_doc = {
            '_id': bond_id,
            'user_a_id': mock_user['_id'],
            'user_b_id': partner_id,
            'status': 'active'
        }

        with patch('main.bonds_conf') as mock_bonds, \
             patch('main.bond_qotd_conf') as mock_qotd, \
             patch('main.users_conf') as mock_users, \
             patch('main.decrypt_bond_data', side_effect=lambda val, bid: f"decrypted_{val}"):

            mock_bonds.find_one.return_value = bond_doc
            mock_users.find_one.return_value = {'_id': partner_id, 'username': 'partneruser'}
            mock_qotd.count_documents.return_value = 25

            # Mock cursor chaining: find().sort().skip().limit()
            mock_cursor = MagicMock()
            mock_cursor.sort.return_value = mock_cursor
            mock_cursor.skip.return_value = mock_cursor
            mock_cursor.limit.return_value = [
                {
                    'date': '2026-10-01',
                    'question_text': 'test_q',
                    'encrypted': True,
                    'answers': {
                        str(partner_id): {'answer': 'enc_ans_partner', 'encrypted': True}
                    }
                }
            ]
            mock_qotd.find.return_value = mock_cursor

            res = auth_client.get(f'/api/bonds/{bond_id}/qotd/history?page=2&per_page=10')
            assert res.status_code == 200
            data = res.get_json()

            assert data['page'] == 2
            assert data['per_page'] == 10
            assert data['total'] == 25
            assert data['total_pages'] == 3
            assert data['has_more'] is True
            assert len(data['history']) == 1

            entry = data['history'][0]
            assert entry['status'] == 'only_partner'
            assert entry['is_revealed'] is False
            assert entry['partner_answer'] is None  # Masked until user answers
            assert entry['can_answer'] is True

