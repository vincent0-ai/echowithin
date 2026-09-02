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
        question = (request.form.get('question') or '').strip()
        game_type = (request.form.get('game_type') or 'poll').strip()
        if game_type not in ('poll', 'trivia'):
            game_type = 'poll'
        expires_in = (request.form.get('expires_in') or '').strip()
        opts_raw = request.form.getlist('options') or []
        # also support JSON fallback
        import json as js
        if not opts_raw:
            try:
                qj = request.form.get('options_json') or ''
                if qj: opts_raw = js.loads(qj)
            except: pass
        opts = [str(o).strip() for o in opts_raw if str(o).strip()]
        if not title or len(title) > 100:
            flash('Title required (max 100).', 'danger')
            return render_template('game_create.html', active_page='games')
        if not question or len(question) > MAX_QUESTION_LEN:
            flash('Question required (max 200).', 'danger')
            return render_template('game_create.html', active_page='games')
        if len(opts) < 2 or len(opts) > MAX_OPTIONS:
            flash(f'Need 2-{MAX_OPTIONS} options.', 'danger')
            return render_template('game_create.html', active_page='games')
        for o in opts:
            if len(o) > MAX_OPTION_LEN: 
                flash('Option too long (max 100).','danger')
                return render_template('game_create.html', active_page='games')
        correct = (request.form.get('correct_option') or '').strip() if game_type=='trivia' else None
        if game_type=='trivia' and correct and correct not in opts:
            flash('Correct option must be one of the options.','danger')
            return render_template('game_create.html', active_page='games')
        # dedupe options
        if len(set(opts)) != len(opts):
            flash('Options must be unique.','danger')
            return render_template('game_create.html', active_page='games')
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = None
        if expires_in == '1h': expires_at = now + datetime.timedelta(hours=1)
        elif expires_in == '1d': expires_at = now + datetime.timedelta(days=1)
        elif expires_in == '7d': expires_at = now + datetime.timedelta(days=7)
        lobby_id = secrets.token_urlsafe(16)
        doc = {
            'lobby_id': lobby_id,
            'host_id': ObjectId(current_user.id),
            'host_username': current_user.username,
            'title': title,
            'game_type': game_type,
            'question': {'label': question, 'options': opts, 'correct_option': correct},
            'counts': {o:0 for o in opts},
            'status': 'active',
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
    if game_type not in ('poll','trivia'): game_type='poll'
    opts = [str(o).strip() for o in (data.get('options') or []) if str(o).strip()]
    correct = (data.get('correct_option') or '').strip() if game_type=='trivia' else None
    if not title or len(title)>100: return jsonify({'error':'Title max 100'}),400
    if not question or len(question)>MAX_QUESTION_LEN: return jsonify({'error':'Question max 200'}),400
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
    total = m.game_votes_conf.count_documents({'lobby_id': lobby_id})
    has_voted = False
    my_vote = None
    if current_user.is_authenticated:
        v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id)})
        if v: has_voted=True; my_vote=v.get('option')
    return render_template('game_lobby.html', lobby=lobby, is_host=is_host, has_voted=has_voted, my_vote=my_vote, total_votes=total)

@bp.route('/g/<lobby_id>/vote', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def vote_lobby(lobby_id):
    import main as m
    if (request.form.get('website') or (request.get_json(silent=True) or {}).get('website')):
        return jsonify({'error':'Bot detected'}),400
    lobby = _game_access(lobby_id)
    if not lobby: return jsonify({'error':'Lobby not found'}),404
    if lobby.get('status') not in ('active',):
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
    if option not in lobby['question']['options']:
        if data: return jsonify({'error':'Invalid option'}),400
        flash('Invalid option','danger')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    # one vote per user per lobby (unique)
    try:
        m.game_votes_conf.insert_one({'lobby_id':lobby_id,'user_id':ObjectId(current_user.id),'username':current_user.username,'option':option,'submitted_at':datetime.datetime.now(datetime.timezone.utc),'ip_hash': hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ''})
    except Exception as e:
        if 'duplicate' in str(e).lower():
            if data: return jsonify({'error':'Already voted'}),409
            flash('You already voted','warning')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
        # also check existing
        existing = m.game_votes_conf.find_one({'lobby_id':lobby_id,'user_id':ObjectId(current_user.id)})
        if existing:
            if data: return jsonify({'error':'Already voted'}),409
            flash('Already voted','warning')
            return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
        raise
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
    flash('Vote recorded — waiting for host reveal.' if lobby['game_type']=='trivia' and not lobby.get('revealed') else 'Vote recorded','success')
    return redirect(url_for('game.view_lobby', lobby_id=lobby_id))

@bp.route('/g/<lobby_id>/reveal', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def reveal_lobby(lobby_id):
    import main as m
    lobby = _game_access(lobby_id)
    if not lobby: return jsonify({'error':'Not found'}),404
    if not _is_host(lobby): return jsonify({'error':'Not host'}),403
    m.game_sessions_conf.update_one({'lobby_id':lobby_id},{'$set':{'revealed':True,'status':'revealed','revealed_at':datetime.datetime.now(datetime.timezone.utc)}})
    try:
        counts = m.game_sessions_conf.find_one({'lobby_id':lobby_id},{'counts':1,'question':1}).get('counts',{})
        m.socketio.emit('game_reveal', {'lobby_id':lobby_id,'counts':counts,'correct': lobby['question'].get('correct_option'), 'question': lobby['question']}, room=lobby_id)
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
    return render_template('game_results.html', lobby=lobby, total=total, votes=votes, per_option=per_option, is_host=_is_host(lobby))

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
