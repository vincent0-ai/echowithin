"""Event-readiness party-lobby suite (Phase 2, Step 4).

HTTP-level lifecycle + guard tests for Trivia/Poll/Story/Caption lobbies using
a dict-backed FakeCollection (no Mongo in this env). Pins sequential guard
behavior; true concurrent races are TRACED (check-then-write, no unique
index — see BUGS.md) and verified post-fix via DuplicateKeyError path.
"""
import datetime
from unittest.mock import MagicMock, patch

from bson import ObjectId

_MISSING = object()


def _get(doc, dotted):
    cur = doc
    for part in str(dotted).split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _set(doc, dotted, value):
    parts = str(dotted).split('.')
    cur = doc
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _match(doc, filt):
    for key, cond in (filt or {}).items():
        if key == '$or':
            if not any(_match(doc, sub) for sub in cond):
                return False
            continue
        if key == '$and':
            if not all(_match(doc, sub) for sub in cond):
                return False
            continue
        val = _get(doc, key)
        if isinstance(cond, dict) and any(str(k).startswith('$') for k in cond):
            for op, arg in cond.items():
                if op == '$exists':
                    if (val is not _MISSING) != bool(arg):
                        return False
                elif op == '$ne':
                    if val == arg:
                        return False
                elif op == '$lt':
                    if val is _MISSING or not (val < arg):
                        return False
                elif op == '$gt':
                    if val is _MISSING or not (val > arg):
                        return False
                elif op == '$in':
                    if val is _MISSING or val not in arg:
                        return False
                elif op == '$nin':
                    if val is not _MISSING and val in arg:
                        return False
                else:
                    return False
        else:
            if val is _MISSING or val != cond:
                return False
    return True


class FakeCursor(list):
    def sort(self, key, direction=-1):
        list.sort(self, key=lambda d: str(_get(d, key)), reverse=(direction < 0))
        return self

    def limit(self, n):
        return FakeCursor(self[:n])


class FakeCollection:
    def __init__(self):
        self.docs = []

    def find_one(self, filt=None, proj=None):
        for d in self.docs:
            if _match(d, filt):
                return d
        return None

    def find(self, filt=None, proj=None):
        return FakeCursor([d for d in self.docs if _match(d, filt)])

    def count_documents(self, filt=None):
        return sum(1 for d in self.docs if _match(d, filt))

    def insert_one(self, doc):
        doc = dict(doc)
        doc.setdefault('_id', ObjectId())
        self.docs.append(doc)
        res = MagicMock()
        res.inserted_id = doc['_id']
        return res

    def update_one(self, filt, update, upsert=False):
        d = self.find_one(filt)
        if d is None:
            if not upsert:
                res = MagicMock()
                res.matched_count = 0
                res.modified_count = 0
                return res
            d = {}
            self.docs.append(d)
        for op, kv in (update or {}).items():
            if op == '$set':
                for k, v in kv.items():
                    _set(d, k, v)
            elif op == '$inc':
                for k, v in kv.items():
                    cur = _get(d, k)
                    _set(d, k, (cur if cur is not _MISSING else 0) + v)
            elif op == '$push':
                for k, v in kv.items():
                    cur = _get(d, k)
                    if cur is _MISSING or not isinstance(cur, list):
                        cur = []
                        _set(d, k, cur)
                    cur.append(v)
        res = MagicMock()
        res.matched_count = 1
        res.modified_count = 1
        return res

    def update_many(self, filt, update):
        n = 0
        for d in list(self.docs):
            if _match(d, filt):
                self.update_one({'_id': d.get('_id')}, update)
                n += 1
        res = MagicMock()
        res.matched_count = n
        res.modified_count = n
        return res

    def delete_many(self, filt):
        self.docs = [d for d in self.docs if not _match(d, filt)]
        return MagicMock()


HOST_OID = ObjectId('507f1f77bcf86cd799439099')
USER_OID = ObjectId('507f1f77bcf86cd799439011')  # conftest mock_user


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _trivia_lobby(lobby_id='t1', phase='question', host_oid=HOST_OID):
    now = _now()
    return {
        'lobby_id': lobby_id, 'pin': '123456',
        'host_id': host_oid, 'host_username': 'Host',
        'title': 'Trivia Night', 'game_type': 'trivia',
        'question': {'label': 'Q1?', 'options': ['Alpha', 'Beta'], 'correct_option': 'Alpha'},
        'questions': [
            {'label': 'Q1?', 'options': ['Alpha', 'Beta'], 'correct_option': 'Alpha'},
            {'label': 'Q2?', 'options': ['Gamma', 'Delta'], 'correct_option': 'Delta'},
        ],
        'counts': {'0': {'Alpha': 0, 'Beta': 0}, '1': {'Gamma': 0, 'Delta': 0}},
        'status': 'active', 'phase': phase, 'current_q_idx': 0,
        'timer_seconds': 20, 'live_scores': {}, 'live_answers': {},
        'allow_anonymous': True, 'revealed': False, 'max_players': 30,
        'expires_at': now + datetime.timedelta(hours=2), 'created_at': now,
    }


def _poll_lobby(lobby_id='p1', host_oid=HOST_OID):
    now = _now()
    return {
        'lobby_id': lobby_id, 'pin': '654321',
        'host_id': host_oid, 'host_username': 'Host',
        'title': 'Lunch Poll', 'game_type': 'poll',
        'question': {'label': 'Eat?', 'options': ['Red', 'Blue'], 'correct_option': None},
        'counts': {'Red': 0, 'Blue': 0},
        'status': 'active', 'allow_anonymous': True, 'revealed': False,
        'max_players': 30, 'timer_seconds': 0,
        'expires_at': now + datetime.timedelta(hours=2), 'created_at': now,
    }


def _patch_db(m, sessions, votes=None, subs=None):
    return (patch.object(m, 'game_sessions_conf', sessions),
            patch.object(m, 'game_votes_conf', votes or FakeCollection()),
            patch.object(m, 'game_submissions_conf', subs or FakeCollection()))


class TestPollVoteGuards:
    def test_vote_then_dupe_409_single_count(self, client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_poll_lobby())
        votes = FakeCollection()
        p1, p2, p3 = _patch_db(m, sessions, votes)
        with p1, p2, p3:
            r1 = client.post('/g/p1/vote', json={'option': 'Red'})
            assert r1.status_code == 200
            # NOTE: _decrypt_lobby wraps legacy single-question lobbies into
            # questions=[...], so the tally lands nested under '0' while the
            # flat template keys stay 0 (see BUG-017).
            assert sessions.find_one({'lobby_id': 'p1'})['counts'] == {
                'Red': 0, 'Blue': 0, '0': {'Red': 1}}
            r2 = client.post('/g/p1/vote', json={'option': 'Blue'})
            assert r2.status_code == 409
            assert sessions.find_one({'lobby_id': 'p1'})['counts'] == {
                'Red': 0, 'Blue': 0, '0': {'Red': 1}}

    def test_invalid_option_400_unknown_lobby_404(self, client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_poll_lobby())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            assert client.post('/g/p1/vote', json={'option': 'Green'}).status_code == 400
            assert client.post('/g/nope/vote', json={'option': 'Red'}).status_code == 404

    def test_wrong_pin_rejected(self, client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_poll_lobby())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            res = client.post('/games/join', data={'pin': '000000'})
            assert res.status_code == 200
            assert b'not found' in res.data.lower() or b'expired' in res.data.lower()


class TestTriviaLiveAnswer:
    def test_double_answer_409_scores_once(self, auth_client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_trivia_lobby())
        votes = FakeCollection()
        p1, p2, p3 = _patch_db(m, sessions, votes)
        with p1, p2, p3:
            r1 = auth_client.post('/g/t1/live/answer',
                                  json={'option': 'Alpha', 'q_idx': 0, 'time_remaining': 15})
            assert r1.status_code == 200
            body = r1.get_json()
            assert body['is_correct'] is True
            assert body['points_earned'] > 500
            r2 = auth_client.post('/g/t1/live/answer',
                                  json={'option': 'Beta', 'q_idx': 0, 'time_remaining': 15})
            assert r2.status_code == 409
            lobby = sessions.find_one({'lobby_id': 't1'})
            assert lobby['counts'] == {'0': {'Alpha': 1, 'Beta': 0},
                                       '1': {'Gamma': 0, 'Delta': 0}}

    def test_stale_q_idx_rejected(self, auth_client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_trivia_lobby())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            res = auth_client.post('/g/t1/live/answer',
                                   json={'option': 'Gamma', 'q_idx': 5, 'time_remaining': 10})
            assert res.status_code == 400

    def test_correct_answer_hidden_from_non_host(self, client):
        """GOOD: anonymous guest live_state has no correct_option during
        question (host gate + phase gate both hold)."""
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_trivia_lobby())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            guest_state = client.get('/api/game/t1/live_state').get_json()
            assert guest_state['phase'] == 'question'
            assert guest_state['is_host'] is False
            assert 'correct_option' not in (guest_state['question'] or {})

    def test_host_sees_answer_then_reveal_opens_it(self, auth_client):
        """GOOD: host sees correct_option in question phase; reveal flips
        the phase and publishes counts + leaderboard."""
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_trivia_lobby(host_oid=USER_OID))
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            host_state = auth_client.get('/api/game/t1/live_state').get_json()
            assert host_state['is_host'] is True
            assert host_state['question']['correct_option'] == 'Alpha'
            rev = auth_client.post('/g/t1/live/reveal')
            assert rev.status_code == 200
            assert rev.get_json()['correct_option'] == 'Alpha'
            after = auth_client.get('/api/game/t1/live_state').get_json()
            assert after['phase'] == 'reveal'
            assert after['question']['correct_option'] == 'Alpha'

    def test_lobby_page_renders_question_phase_for_guest(self, client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(_trivia_lobby())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            res = client.get('/g/t1')
            assert res.status_code == 200
            assert b'Q1?' in res.data


class TestStoryTurnEnforcement:
    def _story(self, lobby_id='s1'):
        now = _now()
        return {
            'lobby_id': lobby_id, 'pin': '111222',
            'host_id': HOST_OID, 'host_username': 'Host',
            'title': 'Story', 'game_type': 'story',
            'question': {'label': 'Story', 'options': [], 'correct_option': None},
            'counts': {}, 'status': 'active', 'sentences': [],
            'turn_order': ['other_user', str(USER_OID)], 'current_turn': 0,
            'allow_anonymous': True, 'max_players': 30,
            'expires_at': now + datetime.timedelta(hours=2), 'created_at': now,
        }

    def test_out_of_turn_blocked_then_accepted(self, auth_client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(self._story())
        p1, p2, p3 = _patch_db(m, sessions)
        with p1, p2, p3:
            r1 = auth_client.post('/g/s1/story/add', data={'sentence': 'Too soon.'})
            assert r1.status_code == 302
            assert sessions.find_one({'lobby_id': 's1'})['sentences'] == []
            sessions.update_one({'lobby_id': 's1'}, {'$set': {'current_turn': 1}})
            r2 = auth_client.post('/g/s1/story/add', data={'sentence': 'My turn now.'})
            assert r2.status_code == 302
            lobby = sessions.find_one({'lobby_id': 's1'})
            assert len(lobby['sentences']) == 1
            assert lobby['current_turn'] == 2


class TestCaptionLockGate:
    def _caption(self, lobby_id='c1'):
        now = _now()
        return {
            'lobby_id': lobby_id, 'pin': '333444',
            'host_id': USER_OID, 'host_username': 'testuser',
            'title': 'Captions', 'game_type': 'caption',
            'question': {'label': 'Caption this', 'options': [], 'correct_option': None},
            'prompt': 'Caption this', 'counts': {},
            'status': 'submit', 'phase': 'submit',
            'allow_anonymous': True, 'max_players': 30,
            'expires_at': now + datetime.timedelta(hours=2), 'created_at': now,
        }

    def test_lock_needs_two_captions(self, auth_client):
        import main as m
        sessions = FakeCollection()
        sessions.insert_one(self._caption())
        subs = FakeCollection()
        p1, p2, p3 = _patch_db(m, sessions, FakeCollection(), subs)
        with p1, p2, p3:
            auth_client.post('/g/c1/caption/submit', data={'caption': 'First!'})
            r1 = auth_client.post('/g/c1/caption/lock')
            assert r1.status_code == 302
            assert sessions.find_one({'lobby_id': 'c1'})['phase'] == 'submit'
            subs.insert_one({'lobby_id': 'c1', 'type': 'caption',
                             'user_id': ObjectId(), 'username': 'Other',
                             'content': {'caption': 'Second!'}})
            r2 = auth_client.post('/g/c1/caption/lock')
            assert r2.status_code == 302
            assert sessions.find_one({'lobby_id': 'c1'})['phase'] == 'voting'


class TestLeaderboardMatrix:
    def test_submit_matrix(self, auth_client):
        import main as m
        fake = FakeCollection()
        with patch.object(m, 'arcade_leaderboards_conf', fake):
            ok = auth_client.post('/api/games/leaderboard/submit',
                                  json={'game': 'snake', 'category': 'high_score',
                                        'score': 500})
            assert ok.status_code == 200
            bad_game = auth_client.post('/api/games/leaderboard/submit',
                                        json={'game': 'nope', 'category': 'high_score',
                                              'score': 500})
            assert bad_game.status_code == 400
            bad_cat = auth_client.post('/api/games/leaderboard/submit',
                                       json={'game': 'snake', 'category': 'nope',
                                             'score': 500})
            assert bad_cat.status_code == 400
            oob = auth_client.post('/api/games/leaderboard/submit',
                                   json={'game': 'floppy_bird', 'category': 'campaign_stars',
                                         'score': 43})
            assert oob.status_code == 400
            zero = auth_client.post('/api/games/leaderboard/submit',
                                    json={'game': 'snake', 'category': 'high_score',
                                          'score': 0})
            assert zero.status_code == 400
            local = auth_client.post('/api/games/leaderboard/submit',
                                     json={'game': 'snake', 'category': 'high_score',
                                           'score': 500,
                                           'metadata': {'mode': 'local'}})
            assert local.status_code == 400
            malformed = auth_client.post('/api/games/leaderboard/submit',
                                         json={'game': 'snake'})
            assert malformed.status_code == 400
            text_score = auth_client.post('/api/games/leaderboard/submit',
                                          json={'game': 'snake', 'category': 'high_score',
                                                'score': 'lots'})
            assert text_score.status_code == 400

    def test_submit_requires_login(self, client):
        import main as m
        with patch.object(m, 'arcade_leaderboards_conf', FakeCollection()):
            guest = client.post('/api/games/leaderboard/submit',
                                json={'game': 'snake', 'category': 'high_score',
                                      'score': 500})
            assert guest.status_code == 401

    def test_leaderboard_get_matrix(self, auth_client):
        import main as m
        fake = FakeCollection()
        with patch.object(m, 'arcade_leaderboards_conf', fake):
            assert auth_client.get('/api/games/leaderboard?game=nope').status_code == 400
            res = auth_client.get('/api/games/leaderboard?game=snake&category=high_score&period=weekly')
            assert res.status_code == 200
            body = res.get_json()
            assert body['entries'] == [] and body['user_record'] is None


class TestPinJoinGuards:
    def test_join_has_no_rate_limit_decorator(self):
        """DOCUMENT (area J): /games/join has no @limits (unlike create/vote);
        6-digit PIN space is enumerable without throttling. See BUG-018."""
        import blueprints.game as g
        import inspect
        src = inspect.getsource(g.games_join)
        assert 'limits' not in src

    def test_room_churn_leaves_no_residue(self):
        """200 join/leave cycles across duel rooms: dicts fully drained
        (no memory growth across repeated matches at room-table level)."""
        import time
        import main as m
        h = {}
        for call in m.socketio.on.mock_calls:
            if len(call.args) > 0 and callable(call.args[0]):
                h[getattr(call.args[0], '__name__', '')] = call.args[0]
        pairs = [
            ('active_pong_rooms', 'handle_join_pong_room', 'handle_leave_pong_room'),
            ('active_slime_rooms', 'handle_join_slime_room', 'handle_leave_slime_room'),
            ('active_ttt_rooms', 'handle_join_ttt_room', 'handle_leave_ttt_room'),
            ('active_c4_rooms', 'handle_join_c4_room', 'handle_leave_c4_room'),
        ]
        saved = {n: dict(getattr(m, n)) for n, _, _ in pairs}
        try:
            t0 = time.perf_counter()
            for i in range(50):
                for dict_name, join_name, leave_name in pairs:
                    rid = 'churn_%d' % i
                    req = MagicMock()
                    req.sid = 'A%d' % i
                    with patch.object(m, 'request', req), \
                            patch.object(m, 'current_user', _authed_for_churn('uh', 'H')), \
                            patch.object(m, 'emit'), patch.object(m, 'join_room'), \
                            patch.object(m, 'leave_room'):
                        h[join_name]({'room_id': rid})
                    req2 = MagicMock()
                    req2.sid = 'A%d' % i
                    with patch.object(m, 'request', req2), \
                            patch.object(m, 'current_user', _authed_for_churn('uh', 'H')), \
                            patch.object(m, 'emit'), patch.object(m, 'join_room'), \
                            patch.object(m, 'leave_room'):
                        h[leave_name]({'room_id': rid})
            dt = time.perf_counter() - t0
            for dict_name, _, _ in pairs:
                assert getattr(m, dict_name) == {}, dict_name
            assert dt < 10, 'room churn too slow: %.2fs' % dt
        finally:
            for n, rooms in saved.items():
                getattr(m, n).clear()
                getattr(m, n).update(rooms)


def _authed_for_churn(uid, name):
    stub = MagicMock()
    stub.is_authenticated = True
    stub.id = uid
    stub.username = name
    return stub
