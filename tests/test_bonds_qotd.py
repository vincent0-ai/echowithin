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
