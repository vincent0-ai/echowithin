from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, session
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets, hashlib
from security import limits
import database

bp = Blueprint('game', __name__)

MAX_PLAYERS = 30
MAX_OPTIONS = 5
MAX_QUESTION_LEN = 200
MAX_OPTION_LEN = 100
MAX_SENTENCE_LEN = 280
MAX_CAPTION_LEN = 200
ALLOWED_GAME_TYPES = ('poll', 'trivia', 'wyr', 'ttal', 'story', 'caption')

def _get_lobby(lobby_id):
    import main as m
    lobby = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    if lobby and lobby.get('game_type') in ('poll', 'trivia') and 'questions' not in lobby:
        # Backward compat: wrap single question into questions array
        q = lobby.get('question', {})
        if q and q.get('label'):
            lobby['questions'] = [q]
    return lobby

def _is_lobby_active(lobby):
    if not lobby:
        return False
    if lobby.get('deactivated'):
        return False
    if lobby.get('expires_at'):
        exp = lobby['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return False
    return True

def _game_access(lobby_id):
    lobby = _get_lobby(lobby_id)
    if not lobby or not _is_lobby_active(lobby):
        return None
    return lobby

def _is_host(lobby):
    if not lobby: return False
    if not current_user.is_authenticated:
        return False
    return str(lobby.get('host_id')) == str(current_user.id) or getattr(current_user, 'is_admin', False)

@bp.route('/games')
@login_required
def games_list():
    import main as m
    lobbies = list(m.game_sessions_conf.find({'host_id': ObjectId(current_user.id)}).sort('created_at', -1).limit(50))
    return render_template('games_list.html', lobbies=lobbies, active_page='games')

@bp.route('/games/create', methods=['GET', 'POST'])
@login_required
@limits(calls=10, period=60)
def games_create():
    import main as m
    if getattr(current_user, 'is_guest', False):
        flash('Sign up to create games.', 'warning')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        game_type = (request.form.get('game_type') or 'poll').strip()
        if game_type not in ALLOWED_GAME_TYPES:
            game_type = 'poll'
        expires_in = (request.form.get('expires_in') or '').strip()

        if not title or len(title) > 100:
            flash('Title required (max 100).', 'danger')
            return render_template('game_create.html', active_page='games')

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = None
        if expires_in == '1h': expires_at = now + datetime.timedelta(hours=1)
        elif expires_in == '1d': expires_at = now + datetime.timedelta(days=1)
        elif expires_in == '7d': expires_at = now + datetime.timedelta(days=7)
        allow_anon_raw = (request.form.get('allow_anonymous') or '1').strip()
        allow_anonymous = allow_anon_raw != '0'
        timer_seconds_raw = (request.form.get('timer_seconds') or '0').strip()
        try:
            timer_seconds = max(0, min(300, int(timer_seconds_raw)))
        except (ValueError, TypeError):
            timer_seconds = 0
        lobby_id = secrets.token_urlsafe(16)

        # --- Build doc per game type ---
        if game_type in ('poll', 'trivia', 'wyr'):
            import json as js
            questions = []
            questions_json_str = request.form.get('questions_json') or ''
            
            if game_type in ('poll', 'trivia') and questions_json_str:
                try:
                    parsed_qs = js.loads(questions_json_str)
                    if not isinstance(parsed_qs, list) or not parsed_qs:
                        raise ValueError()
                    
                    for q in parsed_qs:
                        q_label = (q.get('label') or '').strip()
                        if not q_label or len(q_label) > MAX_QUESTION_LEN:
                            flash('Question required (max 200).', 'danger')
                            return render_template('game_create.html', active_page='games')
                        
                        opts = [str(o).strip() for o in q.get('options', []) if str(o).strip()]
                        if len(opts) < 2 or len(opts) > MAX_OPTIONS:
                            flash(f'Need 2-{MAX_OPTIONS} options.', 'danger')
                            return render_template('game_create.html', active_page='games')
                        for o in opts:
                            if len(o) > MAX_OPTION_LEN:
                                flash('Option too long (max 100).', 'danger')
                                return render_template('game_create.html', active_page='games')
                        if len(set(opts)) != len(opts):
                            flash('Options must be unique.', 'danger')
                            return render_template('game_create.html', active_page='games')
                        
                        correct = (q.get('correct_option') or '').strip() if game_type == 'trivia' else None
                        if game_type == 'trivia' and correct and correct not in opts:
                            flash('Correct option must be one of the options.', 'danger')
                            return render_template('game_create.html', active_page='games')
                            
                        questions.append({'label': q_label, 'options': opts, 'correct_option': correct})
                except Exception as e:
                    flash('Invalid questions format.', 'danger')
                    return render_template('game_create.html', active_page='games')
            else:
                # Single question fallback
                question = (request.form.get('question') or '').strip()
                if not question or len(question) > MAX_QUESTION_LEN:
                    flash('Question required (max 200).', 'danger')
                    return render_template('game_create.html', active_page='games')
                opts_raw = request.form.getlist('options') or []
                if not opts_raw:
                    try:
                        qj = request.form.get('options_json') or ''
                        if qj: opts_raw = js.loads(qj)
                    except: pass
                opts = [str(o).strip() for o in opts_raw if str(o).strip()]
    
                if game_type == 'wyr':
                    if len(opts) != 2:
                        flash('Would You Rather needs exactly 2 options.', 'danger')
                        return render_template('game_create.html', active_page='games')
                else:
                    if len(opts) < 2 or len(opts) > MAX_OPTIONS:
                        flash(f'Need 2-{MAX_OPTIONS} options.', 'danger')
                        return render_template('game_create.html', active_page='games')
                for o in opts:
                    if len(o) > MAX_OPTION_LEN:
                        flash('Option too long (max 100).', 'danger')
                        return render_template('game_create.html', active_page='games')
                if len(set(opts)) != len(opts):
                    flash('Options must be unique.', 'danger')
                    return render_template('game_create.html', active_page='games')
    
                correct = (request.form.get('correct_option') or '').strip() if game_type == 'trivia' else None
                if game_type == 'trivia' and correct and correct not in opts:
                    flash('Correct option must be one of the options.', 'danger')
                    return render_template('game_create.html', active_page='games')
                    
                questions.append({'label': question, 'options': opts, 'correct_option': correct})

            # Create counts object, indexed by question index
            counts = {str(i): {o: 0 for o in q['options']} for i, q in enumerate(questions)}

            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': game_type,
                'question': questions[0],
                'questions': questions,
                'counts': counts,
                'status': 'active',
                'max_players': MAX_PLAYERS,
                'expires_at': expires_at,
                'created_at': now,
                'revealed': False,
            }

        elif game_type == 'ttal':
            # Two Truths and a Lie — no preset question/options; players submit in-lobby
            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': 'ttal',
                'question': {'label': title, 'options': [], 'correct_option': None},
                'counts': {},
                'status': 'submit',   # submit → guess → revealed
                'phase': 'submit',
                'max_players': MAX_PLAYERS,
                'expires_at': expires_at,
                'created_at': now,
                'revealed': False,
            }

        elif game_type == 'story':
            # Story Chain — collaborative writing
            starter = (request.form.get('starter_sentence') or '').strip()
            if not starter or len(starter) > MAX_SENTENCE_LEN:
                flash(f'Starter sentence required (max {MAX_SENTENCE_LEN} chars).', 'danger')
                return render_template('game_create.html', active_page='games')
            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': 'story',
                'question': {'label': title, 'options': [], 'correct_option': None},
                'counts': {},
                'status': 'active',
                'sentences': [{
                    'user_id': str(current_user.id),
                    'username': current_user.username,
                    'text': starter,
                    'added_at': now.isoformat().replace('+00:00', 'Z') + 'Z'
                }],
                'turn_order': [str(current_user.id)],
                'current_turn': 0,
                'max_players': MAX_PLAYERS,
                'expires_at': expires_at,
                'created_at': now,
                'revealed': False,
            }

        elif game_type == 'caption':
            # Caption This — host sets a prompt, players submit captions
            prompt = (request.form.get('prompt') or '').strip()
            if not prompt or len(prompt) > MAX_QUESTION_LEN:
                flash('Prompt/scenario required (max 200).', 'danger')
                return render_template('game_create.html', active_page='games')
            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': 'caption',
                'question': {'label': prompt, 'options': [], 'correct_option': None},
                'prompt': prompt,
                'counts': {},
                'status': 'submit',   # submit → voting → revealed
                'phase': 'submit',
                'max_players': MAX_PLAYERS,
                'expires_at': expires_at,
                'created_at': now,
                'revealed': False,
            }

        doc['allow_anonymous'] = allow_anonymous
        doc['timer_seconds'] = timer_seconds
        m.game_sessions_conf.insert_one(doc)
        flash('Game lobby created — share the link.', 'success')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    return render_template('game_create.html', active_page='games')

@bp.route('/api/game/poll/create', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_create_poll():
    import main as m
    if getattr(current_user, 'is_guest', False):
        return jsonify({'error':'Guest cannot create games'}),403
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    question = (data.get('question') or data.get('label') or '').strip()
    game_type = (data.get('game_type') or 'poll')
    if game_type not in ALLOWED_GAME_TYPES: game_type='poll'
    opts = [str(o).strip() for o in (data.get('options') or []) if str(o).strip()]
    correct = (data.get('correct_option') or '').strip() if game_type=='trivia' else None
    if not title or len(title)>100: return jsonify({'error':'Title max 100'}),400
    if not question or len(question)>MAX_QUESTION_LEN: return jsonify({'error':'Question max 200'}),400
    if game_type == 'wyr':
        if len(opts) != 2: return jsonify({'error':'WYR needs exactly 2 options'}),400
    else:
        if len(opts)<2 or len(opts)>MAX_OPTIONS: return jsonify({'error':f'2-{MAX_OPTIONS} options'}),400
    if len(set(opts))!=len(opts): return jsonify({'error':'Options unique'}),400
    if game_type=='trivia' and correct and correct not in opts: return jsonify({'error':'Correct must be option'}),400
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_in = (data.get('expires_in') or '')
    expires_at = None
    if expires_in=='1h': expires_at=now+datetime.timedelta(hours=1)
    elif expires_in=='1d': expires_at=now+datetime.timedelta(days=1)
    elif expires_in=='7d': expires_at=now+datetime.timedelta(days=7)
    lobby_id = secrets.token_urlsafe(16)
    allow_anonymous = data.get('allow_anonymous', True)
    if isinstance(allow_anonymous, str):
        allow_anonymous = allow_anonymous.lower() not in ('0', 'false', 'no')
    try:
        timer_seconds = max(0, min(300, int(data.get('timer_seconds', 0) or 0)))
    except (ValueError, TypeError):
        timer_seconds = 0
    doc={'lobby_id':lobby_id,'host_id':ObjectId(current_user.id),'host_username':current_user.username,'title':title,'game_type':game_type,'question':{'label':question,'options':opts,'correct_option':correct},'counts':{o:0 for o in opts},'status':'active','max_players':MAX_PLAYERS,'expires_at':expires_at,'created_at':now,'revealed':False,'allow_anonymous':bool(allow_anonymous),'timer_seconds':timer_seconds}
    m.game_sessions_conf.insert_one(doc)
    share_url = url_for('game.view_lobby', lobby_id=lobby_id, _external=True)
    return jsonify({'success':True,'lobby_id':lobby_id,'share_url':share_url}),201


@bp.route('/g/<lobby_id>', methods=['GET'])
@limits(calls=30, period=60)
def view_lobby(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return render_template('game_lobby.html', expired=True, msg='Game lobby not found'), 404
    is_host = _is_host(lobby)
    if not _is_lobby_active(lobby):
        is_deactivated = bool(lobby.get('deactivated'))
        msg = 'This lobby has been deactivated by the host.' if is_deactivated else 'This game lobby has expired.'
        can_view_results = lobby.get('revealed') or is_host
        return render_template('game_lobby.html', lobby=lobby, expired=True, msg=msg, can_view_results=can_view_results, is_host=is_host), 200

    if not lobby.get('allow_anonymous', True) and not current_user.is_authenticated:
        return render_template('game_lobby.html', lobby=lobby, login_required=True, msg='Account required. The host requires players to log in.', is_host=False), 200

    gt = lobby.get('game_type', 'poll')
    total = m.game_votes_conf.count_documents({'lobby_id': lobby_id})
    ip = (request.headers.get('X-Forwarded-For','').split(',')[0].strip() or request.remote_addr or '')
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ''

    # Multi-question vote state for poll/trivia
    questions = lobby.get('questions', [])
    if gt in ('poll', 'trivia') and questions:
        has_voted = {}
        my_vote = {}
        for qi in range(len(questions)):
            v = None
            if current_user.is_authenticated:
                v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'question_index': qi, 'vote_type': {'$exists': False}})
            elif ip_hash:
                v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'ip_hash': ip_hash, 'question_index': qi, 'vote_type': {'$exists': False}})
            if not v and (qi == 0):
                # Backward compat: old votes don't have question_index
                if current_user.is_authenticated:
                    v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'question_index': {'$exists': False}, 'vote_type': {'$exists': False}})
                elif ip_hash:
                    v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'ip_hash': ip_hash, 'question_index': {'$exists': False}, 'vote_type': {'$exists': False}})
            has_voted[qi] = bool(v)
            my_vote[qi] = v.get('option') if v else None
    else:
        has_voted = False
        my_vote = None
        if current_user.is_authenticated:
            v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': {'$exists': False}})
            if v: has_voted=True; my_vote=v.get('option')
        elif ip_hash:
            v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'ip_hash': ip_hash, 'vote_type': {'$exists': False}})
            if v: has_voted=True; my_vote=v.get('option')

    # Type-specific context
    extra = {}
    if gt == 'ttal':
        subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'}))
        my_sub = None
        if current_user.is_authenticated:
            my_sub = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'ttal', 'user_id': ObjectId(current_user.id)})
        # Guesses this user has made
        my_guesses = {}
        if current_user.is_authenticated:
            for g in m.game_votes_conf.find({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': 'ttal_guess'}):
                my_guesses[g.get('target_user_id')] = g.get('option')
        extra = {'submissions': subs, 'my_submission': my_sub, 'my_guesses': my_guesses}

    elif gt == 'story':
        extra = {'sentences': lobby.get('sentences', []), 'turn_order': lobby.get('turn_order', []), 'current_turn': lobby.get('current_turn', 0)}

    elif gt == 'caption':
        subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}))
        my_caption = None
        if current_user.is_authenticated:
            my_caption = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'caption', 'user_id': ObjectId(current_user.id)})
        extra = {'captions': subs, 'my_caption': my_caption}

    return render_template('game_lobby.html', lobby=lobby, is_host=is_host, has_voted=has_voted, my_vote=my_vote, total_votes=total, **extra)


@bp.route('/g/<lobby_id>/vote', methods=['POST'])
@limits(calls=10, period=60)
def vote_lobby(lobby_id):
    import main as m
    if (request.form.get('website') or (request.get_json(silent=True) or {}).get('website')):
        return jsonify({'error':'Bot detected'}),400
    lobby = _game_access(lobby_id)
    if not lobby: return jsonify({'error':'Lobby not found'}),404

    data = request.get_json(silent=True)
    if not lobby.get('allow_anonymous', True) and not current_user.is_authenticated:
        if data: return jsonify({'error': 'Authentication required. This game requires you to log in.'}), 401
        flash('Log in to vote in this game.', 'warning')
        return redirect(url_for('auth.login', next=url_for('game.view_lobby', lobby_id=lobby_id)))

    gt = lobby.get('game_type', 'poll')
    # Caption voting requires 'voting' phase
    if gt == 'caption' and lobby.get('phase') != 'voting':
        return jsonify({'error': 'Not in voting phase'}), 400
    if gt not in ('caption',) and lobby.get('status') not in ('active',):
        return jsonify({'error':'Game not active'}),400
    # per-IP 5/600
    ip = (request.headers.get('X-Forwarded-For','').split(',')[0].strip() or request.remote_addr or '')
    rate_key = f'game_vote_rate_{lobby_id}:{ip}'
    if m.redis_cache:
        try:
            cnt = m.redis_cache.incr(rate_key)
            if cnt==1: m.redis_cache.expire(rate_key,600)
            if cnt>5: return jsonify({'error':'Too many votes — try later'}),429
        except: pass
    option = (data.get('option') if data else request.form.get('option') or '').strip() if (data or request.form) else ''
    if not option: 
        if data: return jsonify({'error':'Option required'}),400
        flash('Pick an option','danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    # Parse question_index for multi-question games
    qi_raw = (data.get('question_index') if data else request.form.get('question_index')) if (data or request.form) else None
    question_index = int(qi_raw) if qi_raw is not None else 0
    questions = lobby.get('questions', [])

    # For caption voting, options are dynamic (submitted captions)
    if gt == 'caption':
        valid_captions = [str(s.get('_id')) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}, {'_id': 1})]
        if option not in valid_captions:
            if data: return jsonify({'error': 'Invalid caption'}), 400
            flash('Invalid caption', 'danger')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    elif gt in ('poll', 'trivia') and questions and question_index < len(questions):
        if option not in questions[question_index]['options']:
            if data: return jsonify({'error':'Invalid option'}),400
            flash('Invalid option','danger')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    else:
        if option not in lobby['question']['options']:
            if data: return jsonify({'error':'Invalid option'}),400
            flash('Invalid option','danger')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ''
    # one vote per user (or per IP if anonymous) per lobby per question
    dupe_filter = {'lobby_id': lobby_id, 'vote_type': {'$exists': False}}
    if gt in ('poll', 'trivia') and questions:
        dupe_filter['question_index'] = question_index
    if current_user.is_authenticated:
        dupe_filter['user_id'] = ObjectId(current_user.id)
        existing = m.game_votes_conf.find_one(dupe_filter)
        voter_user_id = ObjectId(current_user.id)
        voter_username = current_user.username
    else:
        if ip_hash:
            dupe_filter['ip_hash'] = ip_hash
            existing = m.game_votes_conf.find_one(dupe_filter)
        else:
            existing = None
        voter_user_id = None
        voter_username = 'Anonymous'

    if existing:
        if data: return jsonify({'error': 'Already voted'}), 409
        flash('You already voted', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    vote_doc = {'lobby_id': lobby_id, 'user_id': voter_user_id, 'username': voter_username, 'option': option, 'submitted_at': datetime.datetime.now(datetime.timezone.utc), 'ip_hash': ip_hash}
    if gt in ('poll', 'trivia') and questions:
        vote_doc['question_index'] = question_index
    m.game_votes_conf.insert_one(vote_doc)
    # increment count
    if gt in ('poll', 'trivia') and questions:
        m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$inc':{f'counts.{question_index}.{option}':1}})
    else:
        m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$inc':{f'counts.{option}':1}})

    # live broadcast
    try:
        lobby2 = m.game_sessions_conf.find_one({'lobby_id':lobby_id},{'counts':1})
        counts = lobby2.get('counts',{}) if lobby2 else {}
        m.socketio.emit('game_vote', {'lobby_id':lobby_id,'counts':counts,'total': sum(counts.values())}, room=lobby_id)
        # presence update
        if current_user.is_authenticated:
            players = database.active_game_players.get(lobby_id, {})
            if str(current_user.id) not in players:
                players[str(current_user.id)] = {'name':current_user.username,'avatar':getattr(current_user,'profile_image_url',None),'id':str(current_user.id)}
                database.active_game_players[lobby_id]=players
                m.socketio.emit('game_presence_update', {'players': list(players.values())}, room=lobby_id)
    except: pass
    if data:
        return jsonify({'success':True,'message':'Vote recorded'})
    flash('Vote recorded — waiting for host reveal.' if gt in ('trivia',) and not lobby.get('revealed') else 'Vote recorded','success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/reveal', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def reveal_lobby(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby: return jsonify({'error':'Not found'}),404
    if not _is_host(lobby) and not getattr(current_user, 'is_admin', False): return jsonify({'error':'Not host'}),403
    m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$set':{'revealed':True,'status':'revealed','phase':'revealed','revealed_at':datetime.datetime.now(datetime.timezone.utc)}})
    try:
        lobby_fresh = m.game_sessions_conf.find_one({'lobby_id':lobby_id})
        counts = lobby_fresh.get('counts',{})
        emit_data = {'lobby_id':lobby_id,'counts':counts,'correct': lobby['question'].get('correct_option'), 'question': lobby['question']}
        # For TTAL, include submission data for reveal
        gt = lobby.get('game_type', 'poll')
        if gt == 'ttal':
            subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'}))
            emit_data['submissions'] = [{'username': s.get('username'), 'statements': s.get('content', {}).get('statements', []), 'lie_index': s.get('content', {}).get('lie_index')} for s in subs]
        elif gt == 'caption':
            subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}))
            caption_votes = {}
            for s in subs:
                sid = str(s['_id'])
                vote_count = m.game_votes_conf.count_documents({'lobby_id': lobby_id, 'option': sid})
                caption_votes[sid] = {'caption': s.get('content', {}).get('caption', ''), 'username': s.get('username', ''), 'votes': vote_count}
            emit_data['caption_results'] = caption_votes
        m.socketio.emit('game_reveal', emit_data, room=lobby_id)
    except: pass
    if request.is_json: return jsonify({'success':True})
    flash('Results revealed to all players.','success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/results')
@login_required
def lobby_results(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby: flash('Game lobby not found.','danger'); return redirect(url_for('game.games_list'))
    if str(lobby['host_id']) != str(current_user.id) and not getattr(current_user,'is_admin',False):
        # players can also see after reveal
        if not lobby.get('revealed'):
            flash('Results not yet revealed by host.','warning')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    total = m.game_votes_conf.count_documents({'lobby_id':lobby_id})
    votes = list(m.game_votes_conf.find({'lobby_id':lobby_id}).sort('submitted_at',-1).limit(100))
    # per-day for chart
    pipeline=[{'$match':{'lobby_id':lobby_id}}, {'$group':{'_id':'$option','count':{'$sum':1}}}, {'$sort':{'_id':1}}]
    per_option=list(m.game_votes_conf.aggregate(pipeline))

    # Type-specific results
    extra = {}
    gt = lobby.get('game_type', 'poll')
    if gt == 'ttal':
        subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'}))
        guesses = list(m.game_votes_conf.find({'lobby_id': lobby_id, 'vote_type': 'ttal_guess'}))
        extra = {'submissions': subs, 'guesses': guesses}
    elif gt == 'story':
        extra = {'sentences': lobby.get('sentences', [])}
    elif gt == 'caption':
        subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}))
        extra = {'captions': subs}

    return render_template('game_results.html', lobby=lobby, total=total, votes=votes, per_option=per_option, is_host=_is_host(lobby), **extra)

@bp.route('/g/<lobby_id>/export')
@login_required
def lobby_export(lobby_id):
    import main as m, csv, io
    lobby = _get_lobby(lobby_id)
    if not lobby: return jsonify({'error':'Not found'}),404
    if str(lobby['host_id']) != str(current_user.id) and not getattr(current_user,'is_admin',False):
        return jsonify({'error':'Not host'}),403
    fmt = (request.args.get('format') or 'csv').lower()
    votes = list(m.game_votes_conf.find({'lobby_id':lobby_id}).sort('submitted_at',-1))
    if fmt=='json':
        out=[{'username':v.get('username'),'option':v.get('option'),'submitted_at': v['submitted_at'].isoformat().replace('+00:00','Z')+'Z' if v.get('submitted_at') else None} for v in votes]
        return jsonify({'lobby':{'title':lobby['title'],'lobby_id':lobby_id,'question':lobby['question']},'count':len(out),'votes':out})
    # csv
    import csv as csvm, io as iom
    output=iom.StringIO()
    w=csvm.writer(output)
    w.writerow(['username','option','submitted_at'])
    for v in votes:
        w.writerow([v.get('username',''), v.get('option',''), v['submitted_at'].isoformat().replace('+00:00','Z')+'Z' if v.get('submitted_at') else ''])
    resp=make_response(output.getvalue())
    resp.headers['Content-Type']='text/csv'
    resp.headers['Content-Disposition']=f'attachment; filename=game_{lobby_id}_votes.csv'
    return resp

@bp.route('/g/<lobby_id>/deactivate', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def deactivate_lobby(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby: flash('Not found','danger'); return redirect(url_for('game.games_list'))
    if not _is_host(lobby) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized','danger')
        return redirect(url_for('game.games_list'))
    m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$set':{'deactivated':True}})
    flash('Lobby deactivated.','success')
    referrer = request.referrer or ''
    if 'personal_space' in referrer:
        return redirect(url_for('pages.personal_space') + '#games')
    return redirect(url_for('game.games_list'))


@bp.route('/g/<lobby_id>/delete', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def delete_lobby(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        flash('Lobby not found', 'danger')
        return redirect(url_for('game.games_list'))
    if not _is_host(lobby) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('game.games_list'))
    m.game_votes_conf.delete_many({'lobby_id': lobby_id})
    m.game_submissions_conf.delete_many({'lobby_id': lobby_id})
    m.game_sessions_conf.delete_one({'lobby_id': lobby_id})
    flash('Game lobby deleted.', 'success')
    referrer = request.referrer or ''
    if 'personal_space' in referrer:
        return redirect(url_for('pages.personal_space') + '#games')
    return redirect(url_for('game.games_list'))

# ─── TTAL: Two Truths and a Lie ───

@bp.route('/g/<lobby_id>/ttal/submit', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def ttal_submit(lobby_id):
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'ttal':
        return jsonify({'error': 'Not found'}), 404
    if lobby.get('phase') != 'submit':
        flash('Submissions are closed.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # Check if already submitted
    existing = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'ttal', 'user_id': ObjectId(current_user.id)})
    if existing:
        flash('You already submitted your statements.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    s1 = (request.form.get('statement_1') or '').strip()
    s2 = (request.form.get('statement_2') or '').strip()
    s3 = (request.form.get('statement_3') or '').strip()
    lie_index = request.form.get('lie_index', '')
    if not s1 or not s2 or not s3:
        flash('All 3 statements are required.', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    if len(s1) > 200 or len(s2) > 200 or len(s3) > 200:
        flash('Statements must be under 200 characters each.', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    try:
        lie_index = int(lie_index)
        if lie_index not in (0, 1, 2):
            raise ValueError
    except (ValueError, TypeError):
        flash('Select which statement is the lie (1, 2, or 3).', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    m.game_submissions_conf.insert_one({
        'lobby_id': lobby_id,
        'user_id': ObjectId(current_user.id),
        'username': current_user.username,
        'type': 'ttal',
        'content': {'statements': [s1, s2, s3], 'lie_index': lie_index},
        'submitted_at': datetime.datetime.now(datetime.timezone.utc)
    })
    # Broadcast update
    try:
        count = m.game_submissions_conf.count_documents({'lobby_id': lobby_id, 'type': 'ttal'})
        m.socketio.emit('game_ttal_submit', {'lobby_id': lobby_id, 'count': count, 'username': current_user.username}, room=lobby_id)
    except: pass
    flash('Statements submitted! Wait for the guessing phase.', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/ttal/start_guessing', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def ttal_start_guessing(lobby_id):
    """Host moves from submit to guess phase."""
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'ttal':
        return jsonify({'error': 'Not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Not host'}), 403
    m.game_sessions_conf.update_one({'lobby_id': lobby_id}, {'$set': {'phase': 'guess', 'status': 'active'}})
    try:
        m.socketio.emit('game_phase_change', {'lobby_id': lobby_id, 'phase': 'guess'}, room=lobby_id)
    except: pass
    flash('Guessing phase started!', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/ttal/guess', methods=['POST'])
@login_required
@limits(calls=30, period=60)
def ttal_guess(lobby_id):
    """Player guesses which statement is the lie for a specific submitter."""
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'ttal':
        return jsonify({'error': 'Not found'}), 404
    if lobby.get('phase') != 'guess':
        flash('Not in guessing phase.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    target_user_id = (request.form.get('target_user_id') or '').strip()
    guess_index = request.form.get('guess_index', '')
    if not target_user_id:
        flash('Missing target.', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # Can't guess your own
    if target_user_id == str(current_user.id):
        flash("You can't guess your own lie!", 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    try:
        guess_index = int(guess_index)
        if guess_index not in (0, 1, 2):
            raise ValueError
    except (ValueError, TypeError):
        flash('Select a statement (1, 2, or 3).', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # Check not already guessed this person
    existing = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': 'ttal_guess', 'target_user_id': target_user_id})
    if existing:
        flash('You already guessed for this player.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    m.game_votes_conf.insert_one({
        'lobby_id': lobby_id,
        'user_id': ObjectId(current_user.id),
        'username': current_user.username,
        'vote_type': 'ttal_guess',
        'target_user_id': target_user_id,
        'option': str(guess_index),
        'submitted_at': datetime.datetime.now(datetime.timezone.utc)
    })
    flash('Guess recorded!', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

# ─── Story Chain ───

@bp.route('/g/<lobby_id>/story/add', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def story_add(lobby_id):
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'story':
        return jsonify({'error': 'Not found'}), 404
    if lobby.get('status') != 'active':
        flash('Story is closed.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    sentence = (request.form.get('sentence') or '').strip()
    if not sentence or len(sentence) > MAX_SENTENCE_LEN:
        flash(f'Sentence required (max {MAX_SENTENCE_LEN} chars).', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    # Turn enforcement: check if it's this user's turn
    turn_order = lobby.get('turn_order', [])
    current_turn = lobby.get('current_turn', 0)
    uid = str(current_user.id)

    # If user not in turn_order yet, add them
    if uid not in turn_order:
        m.game_sessions_conf.update_one({'lobby_id': lobby_id}, {'$push': {'turn_order': uid}})
        turn_order.append(uid)

    if turn_order and turn_order[current_turn % len(turn_order)] != uid:
        flash("It's not your turn yet!", 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    now = datetime.datetime.now(datetime.timezone.utc)
    entry = {
        'user_id': uid,
        'username': current_user.username,
        'text': sentence,
        'added_at': now.isoformat().replace('+00:00', 'Z') + 'Z'
    }
    m.game_sessions_conf.update_one({'lobby_id': lobby_id}, {
        '$push': {'sentences': entry},
        '$inc': {'current_turn': 1}
    })
    # Broadcast
    try:
        updated = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
        m.socketio.emit('game_story_update', {
            'lobby_id': lobby_id,
            'sentences': updated.get('sentences', []),
            'current_turn': updated.get('current_turn', 0),
            'turn_order': updated.get('turn_order', []),
            'added_by': current_user.username
        }, room=lobby_id)
    except: pass
    flash('Sentence added!', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

# ─── Caption This ───

@bp.route('/g/<lobby_id>/caption/submit', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def caption_submit(lobby_id):
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'caption':
        return jsonify({'error': 'Not found'}), 404
    if lobby.get('phase') != 'submit':
        flash('Submissions are closed.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # Check already submitted
    existing = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'caption', 'user_id': ObjectId(current_user.id)})
    if existing:
        flash('You already submitted a caption.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    caption = (request.form.get('caption') or '').strip()
    if not caption or len(caption) > MAX_CAPTION_LEN:
        flash(f'Caption required (max {MAX_CAPTION_LEN} chars).', 'danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    m.game_submissions_conf.insert_one({
        'lobby_id': lobby_id,
        'user_id': ObjectId(current_user.id),
        'username': current_user.username,
        'type': 'caption',
        'content': {'caption': caption},
        'submitted_at': datetime.datetime.now(datetime.timezone.utc)
    })
    try:
        count = m.game_submissions_conf.count_documents({'lobby_id': lobby_id, 'type': 'caption'})
        m.socketio.emit('game_caption_submit', {'lobby_id': lobby_id, 'count': count}, room=lobby_id)
    except: pass
    flash('Caption submitted!', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/caption/lock', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def caption_lock(lobby_id):
    """Host closes submissions, starts voting on captions."""
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby or lobby.get('game_type') != 'caption':
        return jsonify({'error': 'Not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Not host'}), 403
    # Build options from submitted captions
    subs = list(m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}))
    if len(subs) < 2:
        flash('Need at least 2 captions before voting.', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    m.game_sessions_conf.update_one({'lobby_id': lobby_id}, {'$set': {'phase': 'voting', 'status': 'active'}})
    try:
        m.socketio.emit('game_phase_change', {'lobby_id': lobby_id, 'phase': 'voting'}, room=lobby_id)
    except: pass
    flash('Voting phase started! Players can now vote for their favorite caption.', 'success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/api/game/<lobby_id>/stats')
@login_required
def api_game_stats(lobby_id):
    import main as m
    lobby = m.game_sessions_conf.find_one({'lobby_id':lobby_id})
    if not lobby or str(lobby['host_id']) != str(current_user.id):
        return jsonify({'error':'Not found'}),404
    total = m.game_votes_conf.count_documents({'lobby_id':lobby_id})
    pipeline=[{'$match':{'lobby_id':lobby_id}}, {'$group':{'_id':'$option','count':{'$sum':1}}}]
    per_option=list(m.game_votes_conf.aggregate(pipeline))
    return jsonify({'total':total,'per_option':per_option,'counts':lobby.get('counts',{}),'revealed':bool(lobby.get('revealed'))})


@bp.route('/api/games/my_lobbies')
@login_required
def api_my_game_lobbies():
    """Retrieve active game lobbies hosted by current user for sharing / DM invites."""
    import main as m
    lobbies = list(m.game_sessions_conf.find({
        'host_id': ObjectId(current_user.id),
        'deactivated': {'$ne': True}
    }).sort('created_at', -1).limit(25))

    active = []
    for l in lobbies:
        if _is_lobby_active(l):
            created_dt = l.get('created_at')
            created_str = (created_dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
                           if created_dt and created_dt.tzinfo is None
                           else (created_dt.isoformat().replace('+00:00', 'Z') if created_dt else ''))
            active.append({
                'lobby_id': l['lobby_id'],
                'game_type': l.get('game_type', 'poll'),
                'title': l.get('title', 'Game Lobby'),
                'created_at': created_str
            })
    return jsonify({'lobbies': active})

