"""Live-DB concurrency verification for BUG-015 (exactly-once votes).

Requires a local mongod on 127.0.0.1:27017, otherwise skipped. Uses ONLY the
scratch database ``echowithin_qa_scratch`` via a localhost-only connection
string constructed here — prod credentials in .env are never read or used.

Phase A (no unique index): measures what concurrent same-identity votes do.
Phase B (with the new partial unique indexes): asserts exactly-once + 409s.
"""
import datetime
import threading
from unittest.mock import patch

import pytest
# NOTE: conftest autospec-patches pymongo.MongoClient, so reach the real
# class via its defining submodule for this live-DB test.
from pymongo.mongo_client import MongoClient


def _local_client():
    try:
        client = MongoClient('mongodb://127.0.0.1:27017/', serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
        return client
    except Exception:
        pytest.skip('no local mongod on 127.0.0.1:27017')


def _ensure_fp_index(votes, name='qa_fp_unique'):
    votes.create_index(
        'vote_fp', unique=True, name=name,
        partialFilterExpression={'vote_fp': {'$exists': True}})


def _lobby(lobby_id):
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        'lobby_id': lobby_id, 'pin': '121212',
        'host_id': None, 'host_username': 'Host',
        'title': 'Race', 'game_type': 'poll',
        'question': {'label': 'Pick?', 'options': ['Red', 'Blue'], 'correct_option': None},
        'counts': {'0': {'Red': 0, 'Blue': 0}},
        'status': 'active', 'allow_anonymous': True, 'revealed': False,
        'max_players': 30, 'timer_seconds': 0,
        'expires_at': now + datetime.timedelta(hours=2), 'created_at': now,
    }


def _fire(app, lobby_id, ip, barrier, results, idx):
    client = app.test_client()
    barrier.wait(timeout=15)
    res = client.post('/g/%s/vote' % lobby_id, json={'option': 'Red'},
                      headers={'X-Forwarded-For': ip})
    results[idx] = res.status_code


def _run_race(app, lobby_id, ips):
    import main as m
    n = len(ips)
    barrier = threading.Barrier(n)
    results = [None] * n
    threads = [threading.Thread(target=_fire,
                                args=(app, lobby_id, ip, barrier, results, i))
               for i, ip in enumerate(ips)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert all(t is not None for t in results), results
    return results


class TestLiveVoteRace:
    def test_same_identity_concurrent_votes(self, app):
        """Phase A without index (informational) then Phase B with the
        partial unique indexes (hard exactly-once assertion)."""
        import main as m
        client = _local_client()
        db = client['echowithin_qa_scratch']
        sessions, votes, subs = db['race_sessions'], db['race_votes'], db['race_subs']
        sessions.delete_many({})
        votes.delete_many({})
        try:
            with patch.object(m, 'game_sessions_conf', sessions), \
                    patch.object(m, 'game_votes_conf', votes), \
                    patch.object(m, 'game_submissions_conf', subs):
                sessions.insert_one(_lobby('race_live_1'))
                same_ip = ['10.9.9.9'] * 10
                res_a = _run_race(app, 'race_live_1', same_ip)
                docs_a = votes.count_documents({'lobby_id': 'race_live_1'})
                print('\n[race] phase A (no unique index): statuses=%s docs=%d'
                      % (sorted(res_a), docs_a))
                votes.delete_many({})
                sessions.update_one({'lobby_id': 'race_live_1'},
                                    {'$set': {'counts': {'0': {'Red': 0, 'Blue': 0}}}})
                _ensure_fp_index(votes)
                res_b = _run_race(app, 'race_live_1', same_ip)
                docs_b = votes.count_documents({'lobby_id': 'race_live_1'})
                assert docs_b == 1, 'expected exactly-once, got %d (%s)' % (docs_b, sorted(res_b))
                assert sorted(res_b) == [200] + [409] * 9, sorted(res_b)
                tallies = sessions.find_one({'lobby_id': 'race_live_1'})['counts']
                assert tallies == {'0': {'Red': 1, 'Blue': 0}}, tallies
        finally:
            sessions.delete_many({})
            votes.delete_many({})

    def test_distinct_identities_all_record(self, app):
        """Sanity: 10 distinct voters concurrently -> 10 docs, all 200."""
        import main as m
        client = _local_client()
        db = client['echowithin_qa_scratch']
        sessions, votes, subs = db['race_sessions'], db['race_votes'], db['race_subs']
        sessions.delete_many({})
        votes.delete_many({})
        try:
            with patch.object(m, 'game_sessions_conf', sessions), \
                    patch.object(m, 'game_votes_conf', votes), \
                    patch.object(m, 'game_submissions_conf', subs):
                sessions.insert_one(_lobby('race_live_2'))
                _ensure_fp_index(votes)
                ips = ['10.8.0.%d' % i for i in range(10)]
                res = _run_race(app, 'race_live_2', ips)
                assert sorted(res) == [200] * 10, sorted(res)
                assert votes.count_documents({'lobby_id': 'race_live_2'}) == 10
        finally:
            sessions.delete_many({})
            votes.delete_many({})
