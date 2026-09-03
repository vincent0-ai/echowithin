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

def _game_access(lobby_id):
    import main as m
    lobby = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    if not lobby:
        return None
    if lobby.get('expires_at'):
        exp = lobby['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return None
    if lobby.get('deactivated'):
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
        lobby_id = secrets.token_urlsafe(16)

        # --- Build doc per game type ---
        if game_type in ('poll', 'trivia', 'wyr'):
            question = (request.form.get('question') or '').strip()
            if not question or len(question) > MAX_QUESTION_LEN:
                flash('Question required (max 200).', 'danger')
                return render_template('game_create.html', active_page='games')
            opts_raw = request.form.getlist('options') or []
            import json as js
            if not opts_raw:
                try:
                    qj = request.form.get('options_json') or ''
                    if qj: opts_raw = js.loads(qj)
                except: pass
            opts = [str(o).strip() for o in opts_raw if str(o).strip()]

            # WYR: exactly 2 options
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

            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': game_type,
                'question': {'label': question, 'options': opts, 'correct_option': correct},
                'counts': {o: 0 for o in opts},
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
    doc={'lobby_id':lobby_id,'host_id':ObjectId(current_user.id),'host_username':current_user.username,'title':title,'game_type':game_type,'question':{'label':question,'options':opts,'correct_option':correct},'counts':{o:0 for o in opts},'status':'active','max_players':MAX_PLAYERS,'expires_at':expires_at,'created_at':now,'revealed':False}
    m.game_sessions_conf.insert_one(doc)
    share_url = url_for('game.view_lobby', lobby_id=lobby_id, _external=True)
    return jsonify({'success':True,'lobby_id':lobby_id,'share_url':share_url}),201

@bp.route('/g/<lobby_id>', methods=['GET'])
@limits(calls=30, period=60)
def view_lobby(lobby_id):
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby:
        return render_template('game_lobby.html', expired=True, msg='Lobby not found or expired'),404
    is_host = _is_host(lobby)
    gt = lobby.get('game_type', 'poll')
    total = m.game_votes_conf.count_documents({'lobby_id': lobby_id})
    has_voted = False
    my_vote = None
    if current_user.is_authenticated:
        v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id)})
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
@login_required
@limits(calls=10, period=60)
def vote_lobby(lobby_id):
    import main as m
    if (request.form.get('website') or (request.get_json(silent=True) or {}).get('website')):
        return jsonify({'error':'Bot detected'}),400
    lobby = _game_access(lobby_id)
    if not lobby: return jsonify({'error':'Lobby not found'}),404
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
    data = request.get_json(silent=True)
    option = (data.get('option') if data else request.form.get('option') or '').strip() if (data or request.form) else ''
    if not option: 
        if data: return jsonify({'error':'Option required'}),400
        flash('Pick an option','danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

    # For caption voting, options are dynamic (submitted captions)
    if gt == 'caption':
        valid_captions = [str(s.get('_id')) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'}, {'_id': 1})]
        if option not in valid_captions:
            if data: return jsonify({'error': 'Invalid caption'}), 400
            flash('Invalid caption', 'danger')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    else:
        if option not in lobby['question']['options']:
            if data: return jsonify({'error':'Invalid option'}),400
            flash('Invalid option','danger')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # one vote per user per lobby (check before insert — no unique index)
    existing = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': {'$exists': False}})
    if existing:
        if data: return jsonify({'error': 'Already voted'}), 409
        flash('You already voted', 'warning')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    m.game_votes_conf.insert_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'username': current_user.username, 'option': option, 'submitted_at': datetime.datetime.now(datetime.timezone.utc), 'ip_hash': hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ''})
    # increment count
    m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$inc':{f'counts.{option}':1}})
    # live broadcast
    try:
        lobby2 = m.game_sessions_conf.find_one({'lobby_id':lobby_id},{'counts':1})
        counts = lobby2.get('counts',{}) if lobby2 else {}
        m.socketio.emit('game_vote', {'lobby_id':lobby_id,'counts':counts,'total': sum(counts.values())}, room=lobby_id)
        # presence update
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
    lobby = _game_access(lobby_id)
    if not lobby: return jsonify({'error':'Not found'}),404
    if not _is_host(lobby): return jsonify({'error':'Not host'}),403
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
    lobby = _game_access(lobby_id)
    if not lobby: flash('Not found','danger'); return redirect(url_for('game.games_list'))
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
    lobby = _game_access(lobby_id)
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
    lobby = _game_access(lobby_id)
    if not lobby: flash('Not found','danger'); return redirect(url_for('game.games_list'))
    if not _is_host(lobby): flash('Not host','danger'); return redirect(url_for('game.games_list'))
    m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$set':{'deactivated':True}})
    flash('Lobby deactivated.','success')
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
