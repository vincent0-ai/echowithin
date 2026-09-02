import pytest
import datetime
from bson.objectid import ObjectId
from unittest.mock import patch, MagicMock
import security
from blueprints.bonds import (
    BOND_TYPES,
    BOND_MOODS,
    BOND_SECTIONS,
    GOAL_CATEGORIES,
    _format_datetime,
    _new_tracking_dict,
    _get_unread_sections,
    _get_bond_status_between
)


class TestBondTypesAndConstants:
    """Tests for bond types, moods, categories, and sections."""

    def test_bond_types_structure(self):
        assert 'partner' in BOND_TYPES
        assert 'friend' in BOND_TYPES
        assert 'study_mate' in BOND_TYPES
        assert 'family' in BOND_TYPES
        assert 'accountability' in BOND_TYPES
        for btype, info in BOND_TYPES.items():
            assert 'label' in info
            assert 'icon' in info

    def test_bond_moods_structure(self):
        assert 'great' in BOND_MOODS
        assert 'good' in BOND_MOODS
        assert 'okay' in BOND_MOODS
        assert 'down' in BOND_MOODS
        assert 'tough' in BOND_MOODS
        for key, mood in BOND_MOODS.items():
            assert 'emoji' in mood
            assert 'label' in mood

    def test_bond_sections_count(self):
        assert len(BOND_SECTIONS) >= 10
        assert 'mood' in BOND_SECTIONS
        assert 'qotd' in BOND_SECTIONS
        assert 'journal' in BOND_SECTIONS
        assert 'goals' in BOND_SECTIONS


class TestBondUnreadAndActivityTracking:
    """Tests for section activity and unread indicator calculation."""

    def test_new_tracking_dict_all_sections_utc(self):
        tracking = _new_tracking_dict()
        for s in BOND_SECTIONS:
            assert s in tracking
            assert tracking[s].tzinfo == datetime.timezone.utc

    def test_get_unread_sections_calculation(self):
        user_a = ObjectId()
        user_b = ObjectId()
        now = datetime.datetime.now(datetime.timezone.utc)
        ten_min_ago = now - datetime.timedelta(minutes=10)
        
        bond_doc = {
            '_id': ObjectId(),
            'user_a_id': user_a,
            'user_b_id': user_b,
            'section_activity': {
                'mood': now,          # User B updated mood recently
                'journal': ten_min_ago # Older activity
            },
            'last_viewed': {
                str(user_a): {
                    'mood': ten_min_ago, # User A hasn't seen new mood
                    'journal': now       # User A has seen latest journal
                }
            }
        }
        
        unread_for_a = _get_unread_sections(bond_doc, user_a)
        assert unread_for_a['mood'] is True
        assert unread_for_a['journal'] is False


class TestBondDatetimeFormatting:
    """Tests for bond datetime formatting and UTC ISO standardization."""

    def test_format_datetime_utc_z_suffix(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        formatted = _format_datetime(now)
        assert formatted.endswith('Z')
        parsed = security.parse_iso_utc(formatted)
        assert parsed.tzinfo == datetime.timezone.utc

    def test_format_datetime_naive_handled_as_utc(self):
        naive = datetime.datetime(2025, 6, 15, 12, 0, 0)
        formatted = _format_datetime(naive)
        assert formatted.endswith('Z')

    def test_format_datetime_empty_and_none(self):
        assert _format_datetime(None) is None
        assert _format_datetime('') is None


class TestBondStatusResolution:
    """Tests for _get_bond_status_between state machine."""

    def test_get_bond_status_none_when_no_doc(self, app):
        import main as m
        from unittest.mock import MagicMock
        with patch.object(m, 'bonds_conf', MagicMock(find_one=MagicMock(return_value=None))):
            user_a = ObjectId()
            user_b = ObjectId()
            status = _get_bond_status_between(user_a, user_b)
            assert status['status'] == 'none'

