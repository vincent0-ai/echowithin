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

def _decrypt_lobby(lobby):
    """Return a copy of a game lobby doc with any at-rest encrypted fields decrypted for display.

    Legacy plaintext rows pass through (decrypt falls back when not a Fernet
    token). Never mutates the stored doc — callers must not write this back.
    """
    if not lobby or not isinstance(lobby, dict):
        return lobby
    import main as m
    lobby = dict(lobby)
    lobby_id = str(lobby.get('lobby_id', ''))
    if lobby.get('game_type') in ('poll', 'trivia') and 'questions' not in lobby:
        # Backward compat: wrap single question into questions array
        q = lobby.get('question', {})
        if q and q.get('label'):
            lobby['questions'] = [q]
    try:
        if lobby.get('title'):
            lobby['title'] = m.decrypt_game_data(lobby['title'], lobby_id)
        q0 = lobby.get('question')
        if isinstance(q0, dict):
            q0 = dict(q0)
            if q0.get('label'):
                q0['label'] = m.decrypt_game_data(q0['label'], lobby_id)
            if q0.get('correct_option'):
                q0['correct_option'] = m.decrypt_game_data(q0['correct_option'], lobby_id)
            lobby['question'] = q0
        dec_qs = []
        for q in (lobby.get('questions') or []):
            if isinstance(q, dict):
                q = dict(q)
                if q.get('label'):
                    q['label'] = m.decrypt_game_data(q['label'], lobby_id)
                if q.get('correct_option'):
                    q['correct_option'] = m.decrypt_game_data(q['correct_option'], lobby_id)
                dec_qs.append(q)
            else:
                dec_qs.append(q)
        if dec_qs:
            lobby['questions'] = dec_qs
        if lobby.get('prompt'):
            lobby['prompt'] = m.decrypt_game_data(lobby['prompt'], lobby_id)
        dec_sentences = []
        for s in (lobby.get('sentences') or []):
            if isinstance(s, dict):
                s = dict(s)
                if s.get('text'):
                    s['text'] = m.decrypt_game_data(s['text'], lobby_id)
                dec_sentences.append(s)
            else:
                dec_sentences.append(s)
        if dec_sentences:
            lobby['sentences'] = dec_sentences
    except Exception:
        pass
    return lobby

def _get_lobby(lobby_id):
    import main as m
    lobby = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    return _decrypt_lobby(lobby)

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

def _decrypt_submission(sub, lobby_id):
    """Return a copy of a game submission with content decrypted for display.

    Legacy plaintext rows pass through unchanged (decrypt_game_data falls back
    when the value is not a Fernet token). Never mutates the stored doc.
    """
    import main as m
    if not sub or not isinstance(sub, dict):
        return sub
    sub = dict(sub)
    content = dict(sub.get('content') or {})
    if isinstance(content.get('statements'), list):
        content['statements'] = [m.decrypt_game_data(s, lobby_id) for s in content['statements']]
    if 'lie_index' in content and isinstance(content['lie_index'], str):
        try:
            content['lie_index'] = int(m.decrypt_game_data(content['lie_index'], lobby_id))
        except (ValueError, TypeError):
            pass
    if isinstance(content.get('caption'), str) and content['caption']:
        content['caption'] = m.decrypt_game_data(content['caption'], lobby_id)
    sub['content'] = content
    return sub

def _generate_game_pin():
    import main as m
    for _ in range(15):
        pin = str(secrets.randbelow(900000) + 100000)
        if not m.game_sessions_conf.find_one({'pin': pin, 'deactivated': {'$ne': True}}):
            return pin
    return str(secrets.randbelow(900000) + 100000)

def _get_player_identity():
    """Returns (player_id, player_name, player_avatar) for the current user or guest."""
    if current_user.is_authenticated:
        return (str(current_user.id), current_user.username, getattr(current_user, 'profile_image_url', None))
    pid = session.get('game_player_id')
    if not pid:
        pid = secrets.token_urlsafe(10)
        session['game_player_id'] = pid
    pname = session.get('game_nickname') or 'Player'
    return (pid, pname, None)

@bp.route('/games')
@login_required
def games_list():
    import main as m
    raw_lobbies = list(m.game_sessions_conf.find({'host_id': ObjectId(current_user.id)}).sort('created_at', -1).limit(50))
    lobbies = [_decrypt_lobby(l) for l in raw_lobbies]
    return render_template('games_list.html', lobbies=lobbies, active_page='games')

@bp.route('/games/join', methods=['GET', 'POST'])
@bp.route('/join', methods=['GET', 'POST'])
def games_join():
    import main as m
    pin = (request.args.get('pin') or (request.form.get('pin') if request.method == 'POST' else '') or '').strip()
    nickname = (request.form.get('nickname') or '').strip()

    if request.method == 'POST':
        if not pin:
            flash('Please enter a 6-digit Game PIN.', 'warning')
            return render_template('game_join.html', pin=pin, active_page='games')
        lobby = m.game_sessions_conf.find_one({'pin': pin, 'deactivated': {'$ne': True}})
        if not lobby or not _is_lobby_active(lobby):
            flash('Game PIN not found or lobby has expired.', 'danger')
            return render_template('game_join.html', pin=pin, active_page='games')

        if not current_user.is_authenticated:
            if nickname:
                session['game_nickname'] = nickname[:30]
            if 'game_player_id' not in session:
                session['game_player_id'] = secrets.token_urlsafe(12)
        return redirect(url_for('game.view_lobby', lobby_id=lobby['lobby_id']))

    return render_template('game_join.html', pin=pin, active_page='games')

@bp.route('/g/join')
def g_join_redirect():
    pin = request.args.get('pin', '')
    return redirect(url_for('game.games_join', pin=pin))

@bp.route('/api/game/trivia/categories', methods=['GET'])
def api_trivia_categories():
    from blueprints.trivia_decks import TRIVIA_CATEGORIES
    return jsonify({'categories': TRIVIA_CATEGORIES})

@bp.route('/api/game/trivia/fetch', methods=['POST'])
@limits(calls=30, period=60)
def api_trivia_fetch():
    from blueprints.trivia_decks import fetch_community_trivia
    data = request.get_json(silent=True) or {}
    amount = data.get('amount', 10)
    category = data.get('category')
    difficulty = data.get('difficulty')
    questions = fetch_community_trivia(amount=amount, category=category, difficulty=difficulty)
    return jsonify({'success': True, 'questions': questions, 'count': len(questions)})

@bp.route('/games/floppy-bird')
def floppy_bird():
    return render_template('floppy_bird.html', active_page='games')

@bp.route('/games/slime-volleyball')
def slime_volleyball():
    return render_template('slime_volleyball.html', active_page='games')

@bp.route('/games/tic-tac-toe')
def tic_tac_toe():
    return render_template('tic_tac_toe.html', active_page='games')

@bp.route('/games/connect-four')
def connect_four():
    return render_template('connect_four.html', active_page='games')

@bp.route('/games/dots-and-boxes')
def dots_and_boxes():
    return render_template('dots_and_boxes.html', active_page='games')

@bp.route('/games/ping-pong')
def ping_pong():
    return render_template('ping_pong.html', active_page='games')

@bp.route('/games/snake')
def snake():
    return render_template('snake.html', active_page='games')

@bp.route('/games/create', methods=['GET', 'POST'])
@login_required
@limits(calls=10, period=60)
def games_create():
    import main as m
    if getattr(current_user, 'is_guest', False):
        flash('Sign up to create games.', 'warning')
        return redirect(url_for('auth.login'))
    selected_type = (request.args.get('type') or request.args.get('game_type') or 'poll').strip().lower()
    if selected_type not in ALLOWED_GAME_TYPES:
        selected_type = 'poll'
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
                        if correct:
                            # At-rest only: decrypted via _get_lobby for host view + reveal
                            correct = m.encrypt_game_data(correct, lobby_id)

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
                if correct:
                    # At-rest only: decrypted via _get_lobby for host view + reveal
                    correct = m.encrypt_game_data(correct, lobby_id)

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
                    'text': m.encrypt_game_data(starter, lobby_id),
                    'added_at': now.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
                }],
                'turn_order': [str(current_user.id)],
                'current_turn': 0,
                'max_players': MAX_PLAYERS,
                'expires_at': expires_at,
                'created_at': now,
                'revealed': False,
            }

        elif game_type == 'caption':
            # Caption This — host sets an image and/or prompt, players submit captions
            prompt = (request.form.get('prompt') or '').strip()
            caption_image_url = (request.form.get('caption_image_url') or '').strip()
            caption_file = request.files.get('caption_image')

            image_url = None
            image_public_id = None

            if caption_file and caption_file.filename:
                try:
                    upload_result = m.cloudinary.uploader.upload(caption_file, folder="echowithin_games")
                    image_url = m.optimize_cloudinary_url(upload_result.get('secure_url'))
                    image_public_id = upload_result.get('public_id')
                except Exception as ex:
                    logger.warning("Cloudinary upload failed for game caption photo: %s", ex)

            if not image_url and caption_image_url:
                image_url = caption_image_url

            if not prompt and not image_url:
                flash('Please provide a photo (upload/link) or a prompt for players to caption.', 'danger')
                return render_template('game_create.html', active_page='games')

            if not prompt:
                prompt = 'Caption this photo!'

            if len(prompt) > MAX_QUESTION_LEN:
                flash(f'Prompt/scenario too long (max {MAX_QUESTION_LEN}).', 'danger')
                return render_template('game_create.html', active_page='games')

            doc = {
                'lobby_id': lobby_id,
                'host_id': ObjectId(current_user.id),
                'host_username': current_user.username,
                'title': title,
                'game_type': 'caption',
                'question': {'label': prompt, 'options': [], 'correct_option': None},
                'prompt': prompt,
                'image_url': image_url,
                'image_public_id': image_public_id,
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
        doc['pin'] = _generate_game_pin()
        if game_type == 'trivia':
            doc['is_live'] = True
            doc['phase'] = 'lobby'
            doc['current_q_idx'] = 0
            doc['live_scores'] = {}
            doc['live_answers'] = {}
            if not timer_seconds:
                doc['timer_seconds'] = 20
        m.game_sessions_conf.insert_one(doc)
        flash('Game lobby created — share the link.', 'success')
        return redirect(url_for('game.view_lobby', lobby_id=lobby_id))
    return render_template('game_create.html', active_page='games', selected_type=selected_type)

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
    pin = _generate_game_pin()
    if game_type == 'trivia' and not timer_seconds:
        timer_seconds = 20
    doc={'lobby_id':lobby_id,'pin':pin,'host_id':ObjectId(current_user.id),'host_username':current_user.username,'title':title,'game_type':game_type,'question':{'label':question,'options':opts,'correct_option':correct},'counts':{o:0 for o in opts},'status':'active','max_players':MAX_PLAYERS,'expires_at':expires_at,'created_at':now,'revealed':False,'allow_anonymous':bool(allow_anonymous),'timer_seconds':timer_seconds}
    if game_type == 'trivia':
        doc['is_live'] = True
        doc['phase'] = 'lobby'
        doc['current_q_idx'] = 0
        doc['live_scores'] = {}
        doc['live_answers'] = {}
    m.game_sessions_conf.insert_one(doc)
    share_url = url_for('game.view_lobby', lobby_id=lobby_id, _external=True)
    return jsonify({'success':True,'lobby_id':lobby_id,'share_url':share_url}),201


@bp.route('/g/<lobby_id>', methods=['GET'])
@limits(calls=30, period=60)
def view_lobby(lobby_id):
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return render_template('game_lobby.html', lobby=None, expired=True, msg='Game lobby not found'), 404
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
            my_vote[qi] = m.decrypt_game_data(v.get('option'), lobby_id) if v else None
    else:
        has_voted = False
        my_vote = None
        if current_user.is_authenticated:
            v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': {'$exists': False}})
            if v: has_voted=True; my_vote=m.decrypt_game_data(v.get('option'), lobby_id)
        elif ip_hash:
            v = m.game_votes_conf.find_one({'lobby_id': lobby_id, 'ip_hash': ip_hash, 'vote_type': {'$exists': False}})
            if v: has_voted=True; my_vote=m.decrypt_game_data(v.get('option'), lobby_id)

    # Type-specific context
    extra = {}
    if gt == 'ttal':
        subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'})]
        my_sub = None
        if current_user.is_authenticated:
            my_sub = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'ttal', 'user_id': ObjectId(current_user.id)})
            my_sub = _decrypt_submission(my_sub, lobby_id)
        # Guesses this user has made
        my_guesses = {}
        if current_user.is_authenticated:
            for g in m.game_votes_conf.find({'lobby_id': lobby_id, 'user_id': ObjectId(current_user.id), 'vote_type': 'ttal_guess'}):
                my_guesses[g.get('target_user_id')] = m.decrypt_game_data(g.get('option'), lobby_id)
        extra = {'submissions': subs, 'my_submission': my_sub, 'my_guesses': my_guesses}

    elif gt == 'story':
        extra = {'sentences': lobby.get('sentences', []), 'turn_order': lobby.get('turn_order', []), 'current_turn': lobby.get('current_turn', 0)}

    elif gt == 'caption':
        subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'})]
        my_caption = None
        if current_user.is_authenticated:
            my_caption = m.game_submissions_conf.find_one({'lobby_id': lobby_id, 'type': 'caption', 'user_id': ObjectId(current_user.id)})
            my_caption = _decrypt_submission(my_caption, lobby_id)
        extra = {'captions': subs, 'my_caption': my_caption}

    player_id, player_name, player_avatar = _get_player_identity()
    is_live = bool(lobby.get('is_live') or (gt == 'trivia'))
    lobby_render = dict(lobby)
    if is_live and not is_host and lobby.get('phase') == 'question':
        safe_qs = []
        for q in (lobby.get('questions') or []):
            sq = dict(q)
            sq.pop('correct_option', None)
            safe_qs.append(sq)
        lobby_render['questions'] = safe_qs
        if 'question' in lobby_render and isinstance(lobby_render['question'], dict):
            sq0 = dict(lobby_render['question'])
            sq0.pop('correct_option', None)
            lobby_render['question'] = sq0

    live_leaderboard = _build_live_leaderboard(lobby.get('live_scores', {}))
    return render_template(
        'game_lobby.html',
        lobby=lobby_render,
        is_host=is_host,
        has_voted=has_voted,
        my_vote=my_vote,
        total_votes=total,
        is_live=is_live,
        player_id=player_id,
        player_name=player_name,
        player_avatar=player_avatar,
        leaderboard=live_leaderboard,
        **extra
    )


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

    # NOTE: counts keys stay plaintext (atomic $inc tally needs stable keys).
    # The vote doc option below is encrypted to break the voter↔choice linkage at rest.
    # Exception: caption votes store a submission _id reference (needed for lookup/tally), not content.
    stored_option = option if gt == 'caption' else m.encrypt_game_data(option, lobby_id)
    vote_doc = {'lobby_id': lobby_id, 'user_id': voter_user_id, 'username': voter_username, 'option': stored_option, 'submitted_at': datetime.datetime.now(datetime.timezone.utc), 'ip_hash': ip_hash}
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
            subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'})]
            emit_data['submissions'] = [{'username': s.get('username'), 'statements': s.get('content', {}).get('statements', []), 'lie_index': s.get('content', {}).get('lie_index')} for s in subs]
        elif gt == 'caption':
            subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'})]
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
    for v in votes:
        # Caption options are plaintext submission-_id references and pass through;
        # poll/trivia/guess options are per-lobby ciphertext decrypted here.
        v['option'] = m.decrypt_game_data(v.get('option'), lobby_id) if v.get('option') else v.get('option')
    # per-option chart: Fernet is randomized so Mongo can't group ciphertext — group decrypted values in Python.
    _counts = {}
    for v in votes:
        _counts[v.get('option')] = _counts.get(v.get('option'), 0) + 1
    per_option=[{'_id':opt,'count':cnt} for opt, cnt in sorted(_counts.items(), key=lambda kv: str(kv[0]))]

    # Type-specific results
    extra = {}
    gt = lobby.get('game_type', 'poll')
    if gt == 'ttal':
        subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'ttal'})]
        guesses = list(m.game_votes_conf.find({'lobby_id': lobby_id, 'vote_type': 'ttal_guess'}))
        for g in guesses:
            g['option'] = m.decrypt_game_data(g.get('option'), lobby_id) if g.get('option') else g.get('option')
        extra = {'submissions': subs, 'guesses': guesses}
    elif gt == 'story':
        extra = {'sentences': lobby.get('sentences', [])}
    elif gt == 'caption':
        subs = [_decrypt_submission(s, lobby_id) for s in m.game_submissions_conf.find({'lobby_id': lobby_id, 'type': 'caption'})]
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
    for v in votes:
        v['option'] = m.decrypt_game_data(v.get('option'), lobby_id) if v.get('option') else v.get('option')
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
    if lobby.get('image_public_id'):
        try:
            m.destroy_cloudinary_media(lobby['image_public_id'], resource_type='image', delivery_type='upload')
        except Exception:
            pass
    m.game_votes_conf.delete_many({'lobby_id': lobby_id})
    m.game_submissions_conf.delete_many({'lobby_id': lobby_id})
    m.game_sessions_conf.delete_one({'lobby_id': lobby_id})
    flash('Game lobby deleted.', 'success')
    referrer = request.referrer or ''
    if 'personal_space' in referrer:
        return redirect(url_for('pages.personal_space') + '#games')
    return redirect(url_for('game.games_list'))


# ─── Live Multiplayer Trivia (Kahoot-Style) Engine ───

def _build_live_leaderboard(scores):
    """Sort and rank participants by score descending."""
    board = []
    for pid, pdata in (scores or {}).items():
        board.append({
            'id': pid,
            'name': pdata.get('name', 'Player'),
            'avatar': pdata.get('avatar'),
            'score': int(pdata.get('score', 0)),
            'streak': int(pdata.get('streak', 0)),
            'last_points': int(pdata.get('last_points', 0)),
            'last_correct': bool(pdata.get('last_correct', False)),
            'correct_count': int(pdata.get('correct_count', 0)),
            'total_answered': int(pdata.get('total_answered', 0))
        })
    board.sort(key=lambda x: x['score'], reverse=True)
    for rank, p in enumerate(board, 1):
        p['rank'] = rank
    return board

@bp.route('/g/<lobby_id>/live/start', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def live_start_game(lobby_id):
    """Host starts live game show, broadcasting Question 0."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Host authorization required'}), 403

    questions = lobby.get('questions', [])
    if not questions:
        return jsonify({'error': 'No questions in this trivia game'}), 400

    now = datetime.datetime.now(datetime.timezone.utc)
    m.game_sessions_conf.update_one(
        {'lobby_id': lobby_id},
        {'$set': {
            'phase': 'question',
            'current_q_idx': 0,
            'q_started_at': now,
            'status': 'active',
            'revealed': False
        }}
    )

    q0 = questions[0]
    payload = {
        'lobby_id': lobby_id,
        'phase': 'question',
        'q_idx': 0,
        'current_q_idx': 0,
        'total_q': len(questions),
        'total_questions': len(questions),
        'label': q0.get('label', ''),
        'options': q0.get('options', []),
        'question': {
            'label': q0.get('label', ''),
            'options': q0.get('options', [])
        },
        'timer_seconds': lobby.get('timer_seconds', 20) or 20,
        'started_at': now.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    }
    try:
        m.socketio.emit('live_trivia_state', payload, room=lobby_id)
    except Exception:
        pass
    return jsonify({'ok': True, 'success': True, 'state': payload})

@bp.route('/g/<lobby_id>/live/answer', methods=['POST'])
@limits(calls=60, period=60)
def live_submit_answer(lobby_id):
    """Player submits answer during live question phase with speed + streak scoring."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if lobby.get('phase') != 'question':
        return jsonify({'error': 'Not in question answering phase'}), 400

    data = request.get_json(silent=True) or {}
    option = (data.get('option') or request.form.get('option') or '').strip()
    q_idx = int(data.get('q_idx') or request.form.get('q_idx') or 0)
    current_q_idx = int(lobby.get('current_q_idx', 0))

    if q_idx != current_q_idx:
        return jsonify({'error': 'Question mismatch'}), 400

    questions = lobby.get('questions', [])
    if q_idx >= len(questions):
        return jsonify({'error': 'Invalid question index'}), 400

    q_data = questions[q_idx]
    if option not in q_data.get('options', []):
        return jsonify({'error': 'Option not found in choices'}), 400

    player_id, player_name, player_avatar = _get_player_identity()

    # Check if this player already answered
    live_answers = lobby.get('live_answers', {}).get(str(q_idx), {})
    if player_id in live_answers:
        return jsonify({'error': 'Already answered this question'}), 409

    correct_option = (q_data.get('correct_option') or '').strip()
    is_correct = (option.strip() == correct_option)

    timer_total = float(lobby.get('timer_seconds', 20) or 20)
    raw_time_rem = data.get('time_remaining') or request.form.get('time_remaining') or 0
    try:
        time_rem = max(0.0, min(timer_total, float(raw_time_rem)))
    except (ValueError, TypeError):
        time_rem = 0.0

    scores = lobby.get('live_scores', {})
    player_stats = scores.get(player_id, {'score': 0, 'streak': 0, 'correct_count': 0, 'total_answered': 0})

    if is_correct:
        base_points = 500
        speed_bonus = round(500 * (time_rem / timer_total)) if timer_total > 0 else 250
        streak = int(player_stats.get('streak', 0)) + 1
        streak_bonus = min(250, streak * 50)
        points_earned = base_points + speed_bonus + streak_bonus
    else:
        streak = 0
        points_earned = 0

    new_score = int(player_stats.get('score', 0)) + points_earned
    new_correct = int(player_stats.get('correct_count', 0)) + (1 if is_correct else 0)
    new_total = int(player_stats.get('total_answered', 0)) + 1

    now = datetime.datetime.now(datetime.timezone.utc)

    # Save to MongoDB
    m.game_sessions_conf.update_one(
        {'lobby_id': lobby_id},
        {
            '$set': {
                f'live_scores.{player_id}': {
                    'name': player_name,
                    'avatar': player_avatar,
                    'score': new_score,
                    'streak': streak,
                    'last_points': points_earned,
                    'last_correct': is_correct,
                    'correct_count': new_correct,
                    'total_answered': new_total,
                    'last_answered_at': now
                },
                f'live_answers.{q_idx}.{player_id}': {
                    'option': m.encrypt_game_data(option, lobby_id),
                    'is_correct': is_correct,
                    'points': points_earned,
                    'time_remaining': time_rem
                }
            },
            '$inc': {
                f'counts.{q_idx}.{option}': 1
            }
        }
    )

    # Record persistent vote document
    ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr or '')
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16] if ip else ''
    m.game_votes_conf.insert_one({
        'lobby_id': lobby_id,
        'user_id': ObjectId(current_user.id) if current_user.is_authenticated else None,
        'player_id': player_id,
        'username': player_name,
        'question_index': q_idx,
        'option': m.encrypt_game_data(option, lobby_id),
        'is_correct': is_correct,
        'points': points_earned,
        'submitted_at': now,
        'ip_hash': ip_hash
    })

    # Broadcast answer count update to room
    try:
        fresh = m.game_sessions_conf.find_one({'lobby_id': lobby_id}, {'live_answers': 1})
        fresh_answers = fresh.get('live_answers', {}).get(str(q_idx), {}) if fresh else {}
        m.socketio.emit('live_trivia_answer_count', {
            'q_idx': q_idx,
            'answered': len(fresh_answers),
            'total_answers': len(fresh_answers)
        }, room=lobby_id)
    except Exception:
        pass

    return jsonify({
        'ok': True,
        'success': True,
        'option': option,
        'correct': is_correct,
        'is_correct': is_correct,
        'points_awarded': points_earned,
        'points_earned': points_earned,
        'streak': streak,
        'new_score': new_score
    })

@bp.route('/g/<lobby_id>/live/reveal', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def live_reveal_question(lobby_id):
    """Host reveals the answer distribution and correct answer for current question."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Host authorization required'}), 403

    current_q_idx = int(lobby.get('current_q_idx', 0))
    questions = lobby.get('questions', [])
    if current_q_idx >= len(questions):
        return jsonify({'error': 'Invalid question index'}), 400

    q_data = questions[current_q_idx]
    correct_option = (q_data.get('correct_option') or '').strip()

    m.game_sessions_conf.update_one(
        {'lobby_id': lobby_id},
        {'$set': {'phase': 'reveal'}}
    )

    fresh = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    counts_raw = dict(fresh.get('counts', {}).get(str(current_q_idx), {})) if fresh else {}
    if not counts_raw and fresh:
        ans_bucket = fresh.get('live_answers', {})
        q_ans = ans_bucket.get(str(current_q_idx), ans_bucket)
        if isinstance(q_ans, dict):
            for p_info in q_ans.values():
                if isinstance(p_info, dict):
                    opt = p_info.get('option')
                    if opt:
                        try:
                            dec = m.decrypt_game_data(opt, lobby_id)
                            opt = dec if dec else opt
                        except Exception:
                            pass
                        counts_raw[opt] = counts_raw.get(opt, 0) + 1

    leaderboard = _build_live_leaderboard(fresh.get('live_scores', {}) if fresh else {})

    payload = {
        'lobby_id': lobby_id,
        'phase': 'reveal',
        'q_idx': current_q_idx,
        'correct_option': correct_option,
        'counts': counts_raw,
        'leaderboard': leaderboard[:5]
    }
    try:
        m.socketio.emit('live_trivia_reveal', payload, room=lobby_id)
    except Exception:
        pass
    return jsonify({
        'ok': True,
        'success': True,
        'correct_option': correct_option,
        'counts': counts_raw,
        'leaderboard': leaderboard[:5],
        'state': payload
    })

@bp.route('/g/<lobby_id>/live/leaderboard', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def live_show_leaderboard(lobby_id):
    """Host transitions to leaderboard screen."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Host authorization required'}), 403

    m.game_sessions_conf.update_one(
        {'lobby_id': lobby_id},
        {'$set': {'phase': 'leaderboard'}}
    )

    fresh = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    leaderboard = _build_live_leaderboard(fresh.get('live_scores', {}) if fresh else {})

    payload = {
        'lobby_id': lobby_id,
        'phase': 'leaderboard',
        'q_idx': int(lobby.get('current_q_idx', 0)),
        'total_q': len(lobby.get('questions', [])),
        'leaderboard': leaderboard[:10]
    }
    try:
        m.socketio.emit('live_trivia_leaderboard', payload, room=lobby_id)
    except Exception:
        pass
    return jsonify({
        'ok': True,
        'success': True,
        'leaderboard': leaderboard[:10],
        'state': payload
    })

@bp.route('/g/<lobby_id>/live/next', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def live_next_question(lobby_id):
    """Host advances to next question or concludes game to podium."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Host authorization required'}), 403

    questions = lobby.get('questions', [])
    current_q_idx = int(lobby.get('current_q_idx', 0))
    next_idx = current_q_idx + 1

    now = datetime.datetime.now(datetime.timezone.utc)

    if next_idx < len(questions):
        m.game_sessions_conf.update_one(
            {'lobby_id': lobby_id},
            {'$set': {
                'phase': 'question',
                'current_q_idx': next_idx,
                'q_started_at': now
            }}
        )
        q_next = questions[next_idx]
        payload = {
            'lobby_id': lobby_id,
            'phase': 'question',
            'q_idx': next_idx,
            'current_q_idx': next_idx,
            'total_q': len(questions),
            'total_questions': len(questions),
            'label': q_next.get('label', ''),
            'options': q_next.get('options', []),
            'question': {
                'label': q_next.get('label', ''),
                'options': q_next.get('options', [])
            },
            'timer_seconds': lobby.get('timer_seconds', 20) or 20,
            'started_at': now.astimezone(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        try:
            m.socketio.emit('live_trivia_state', payload, room=lobby_id)
        except Exception:
            pass
        return jsonify({'ok': True, 'success': True, 'phase': 'question', 'q_idx': next_idx, 'state': payload})
    else:
        # All questions completed -> Finale Podium!
        m.game_sessions_conf.update_one(
            {'lobby_id': lobby_id},
            {'$set': {
                'phase': 'podium',
                'status': 'finished',
                'revealed': True,
                'revealed_at': now
            }}
        )
        fresh = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
        leaderboard = _build_live_leaderboard(fresh.get('live_scores', {}) if fresh else {})
        podium = leaderboard[:3]

        payload = {
            'lobby_id': lobby_id,
            'phase': 'podium',
            'podium': podium,
            'leaderboard': leaderboard
        }
        try:
            m.socketio.emit('live_trivia_podium', payload, room=lobby_id)
        except Exception:
            pass
        return jsonify({'ok': True, 'success': True, 'phase': 'podium', 'podium': podium, 'leaderboard': leaderboard, 'state': payload})

@bp.route('/g/<lobby_id>/live/podium', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def live_show_podium(lobby_id):
    """Host manually triggers podium celebration."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby:
        return jsonify({'error': 'Lobby not found'}), 404
    if not _is_host(lobby):
        return jsonify({'error': 'Host authorization required'}), 403

    now = datetime.datetime.now(datetime.timezone.utc)
    m.game_sessions_conf.update_one(
        {'lobby_id': lobby_id},
        {'$set': {
            'phase': 'podium',
            'status': 'finished',
            'revealed': True,
            'revealed_at': now
        }}
    )

    fresh = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
    leaderboard = _build_live_leaderboard(fresh.get('live_scores', {}) if fresh else {})
    podium = leaderboard[:3]

    payload = {
        'lobby_id': lobby_id,
        'phase': 'podium',
        'podium': podium,
        'leaderboard': leaderboard
    }
    try:
        m.socketio.emit('live_trivia_podium', payload, room=lobby_id)
    except Exception:
        pass
    return jsonify({
        'ok': True,
        'success': True,
        'podium': podium,
        'leaderboard': leaderboard,
        'state': payload
    })

@bp.route('/api/game/<lobby_id>/live_state', methods=['GET'])
def api_game_live_state(lobby_id):
    """Sync endpoint for clients joining mid-game or recovering connection."""
    import main as m
    lobby = _get_lobby(lobby_id)
    if not lobby or not _is_lobby_active(lobby):
        return jsonify({'error': 'Lobby not found or expired'}), 404

    is_host = _is_host(lobby)
    phase = lobby.get('phase', 'lobby')
    current_q_idx = int(lobby.get('current_q_idx', 0))
    questions = lobby.get('questions', [])
    player_id, player_name, _ = _get_player_identity()

    current_q = None
    if questions and current_q_idx < len(questions):
        raw_q = questions[current_q_idx]
        current_q = {
            'label': raw_q.get('label', ''),
            'options': raw_q.get('options', [])
        }
        if is_host or phase in ('reveal', 'podium', 'leaderboard'):
            current_q['correct_option'] = raw_q.get('correct_option')

    counts = lobby.get('counts', {}).get(str(current_q_idx), {})
    live_scores = lobby.get('live_scores', {})
    leaderboard = _build_live_leaderboard(live_scores)
    my_answered = lobby.get('live_answers', {}).get(str(current_q_idx), {}).get(player_id)
    my_stats = live_scores.get(player_id, {'score': 0, 'streak': 0, 'rank': len(leaderboard)})

    return jsonify({
        'lobby_id': lobby_id,
        'pin': lobby.get('pin', ''),
        'game_type': lobby.get('game_type', 'trivia'),
        'phase': phase,
        'current_q_idx': current_q_idx,
        'total_q': len(questions),
        'question': current_q,
        'timer_seconds': lobby.get('timer_seconds', 20) or 20,
        'counts': counts,
        'leaderboard': leaderboard[:10],
        'podium': leaderboard[:3],
        'is_host': is_host,
        'my_answered': bool(my_answered),
        'my_answer_info': my_answered if (phase in ('reveal', 'leaderboard', 'podium') or not my_answered) else {'option': 'locked'},
        'my_stats': my_stats
    })


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
        'content': {
            'statements': [m.encrypt_game_data(s, lobby_id) for s in (s1, s2, s3)],
            'lie_index': m.encrypt_game_data(str(lie_index), lobby_id),
        },
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
        'option': m.encrypt_game_data(str(guess_index), lobby_id),
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
        'text': m.encrypt_game_data(sentence, lobby_id),
        'added_at': now.isoformat().replace('+00:00', 'Z') + 'Z'
    }
    m.game_sessions_conf.update_one({'lobby_id': lobby_id}, {
        '$push': {'sentences': entry},
        '$inc': {'current_turn': 1}
    })
    # Broadcast (decrypt sentences for the live payload — at rest they stay ciphertext)
    try:
        updated = m.game_sessions_conf.find_one({'lobby_id': lobby_id})
        _live = []
        for s in (updated.get('sentences', []) if updated else []):
            s = dict(s)
            if s.get('text'):
                s['text'] = m.decrypt_game_data(s['text'], lobby_id)
            _live.append(s)
        m.socketio.emit('game_story_update', {
            'lobby_id': lobby_id,
            'sentences': _live,
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
        'content': {'caption': m.encrypt_game_data(caption, lobby_id)},
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
    # Fernet is randomized so Mongo can't group ciphertext — group decrypted values in Python.
    _opts = [m.decrypt_game_data(v.get('option'), lobby_id) for v in m.game_votes_conf.find({'lobby_id':lobby_id}, {'option': 1}) if v.get('option')]
    _hist = {}
    for _o in _opts:
        _hist[_o] = _hist.get(_o, 0) + 1
    per_option=[{'_id':opt,'count':cnt} for opt, cnt in _hist.items()]
    return jsonify({'total':total,'per_option':per_option,'counts':lobby.get('counts',{}),'revealed':bool(lobby.get('revealed'))})


@bp.route('/api/games/my_lobbies')
@login_required
def api_my_game_lobbies():
    """Retrieve active game lobbies hosted by current user for sharing / DM invites."""
    import main as m
    raw_lobbies = list(m.game_sessions_conf.find({
        'host_id': ObjectId(current_user.id),
        'deactivated': {'$ne': True}
    }).sort('created_at', -1).limit(25))
    lobbies = [_decrypt_lobby(l) for l in raw_lobbies]

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


# --- 2D Arcade Leaderboards (Floppy Bird, Slime Volleyball, Tic-Tac-Toe, Connect Four, Dots-and-Boxes, Ping Pong & Snake) ---
VALID_ARCADE_CATEGORIES = {
    'floppy_bird': ('campaign_stars', 'endless_score'),
    'slime_volleyball': ('win_streak', 'volleys_returned', 'ranked_score'),
    'tic_tac_toe': ('win_streak', 'total_wins', 'ranked_score'),
    'connect_four': ('win_streak', 'total_wins', 'ranked_score'),
    'dots_and_boxes': ('win_streak', 'total_wins', 'ranked_score'),
    'ping_pong': ('win_streak', 'volleys_returned', 'total_wins', 'ranked_score'),
    'snake': ('high_score', 'ranked_score', 'food_eaten')
}

@bp.route('/api/games/leaderboard/submit', methods=['POST'])
@limits(calls=60, period=60)
def api_leaderboard_submit():
    """Submit a high score, win streak, or ranked score for 2D arcade games with daily/weekly partitions."""
    import main as m
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid payload'}), 400

    game = (data.get('game') or '').strip()
    category = (data.get('category') or '').strip()
    if game not in VALID_ARCADE_CATEGORIES or category not in VALID_ARCADE_CATEGORIES[game]:
        return jsonify({'error': 'Invalid game or category'}), 400

    try:
        score = int(data.get('score', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Score must be an integer'}), 400

    # Bounds validation to prevent unrealistic / cheated submissions
    if category == 'campaign_stars' and not (0 <= score <= 42):
        return jsonify({'error': 'Campaign stars must be between 0 and 42'}), 400
    if category in ('endless_score', 'high_score') and not (0 <= score <= 1000000):
        return jsonify({'error': 'Score out of valid bounds'}), 400
    if category == 'win_streak' and not (1 <= score <= 500):
        return jsonify({'error': 'Win streak out of valid bounds'}), 400
    if category == 'volleys_returned' and not (1 <= score <= 1000000):
        return jsonify({'error': 'Volleys returned out of valid bounds'}), 400
    if category == 'total_wins' and not (1 <= score <= 100000):
        return jsonify({'error': 'Total wins out of valid bounds'}), 400
    if category == 'food_eaten' and not (0 <= score <= 100000):
        return jsonify({'error': 'Food eaten out of valid bounds'}), 400
    if category == 'ranked_score' and not (1 <= score <= 10000000):
        return jsonify({'error': 'Ranked score out of valid bounds'}), 400

    raw_metadata = data.get('metadata')
    if not isinstance(raw_metadata, dict):
        raw_metadata = {}

    # Disallow local two-player pass-and-play matches from submitting to global leaderboards
    if raw_metadata.get('mode') == 'local':
        return jsonify({'error': 'Local two-player scores cannot be submitted to global leaderboards'}), 400

    metadata = {}
    if 'difficulty' in raw_metadata and isinstance(raw_metadata['difficulty'], str):
        metadata['difficulty'] = raw_metadata['difficulty'].strip().lower()[:16]
    if 'mode' in raw_metadata and isinstance(raw_metadata['mode'], str):
        metadata['mode'] = raw_metadata['mode'].strip().lower()[:16]
    if 'returns' in raw_metadata and isinstance(raw_metadata['returns'], (int, float)):
        metadata['returns'] = int(raw_metadata['returns'])
    if 'multiplier' in raw_metadata and isinstance(raw_metadata['multiplier'], (int, float, str)):
        metadata['multiplier'] = str(raw_metadata['multiplier'])[:8]

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    day_key = now_utc.strftime('%Y-%m-%d')
    week_key = now_utc.strftime('%Y-W%U')

    is_auth = current_user.is_authenticated
    user_id = str(current_user.id) if is_auth else None
    username = (current_user.username if is_auth else (data.get('username') or 'Guest')).strip()[:24] or 'Guest'
    avatar_url = getattr(current_user, 'profile_image_url', None) if is_auth else None
    guest_token = (data.get('guest_token') or '').strip()[:64] if not is_auth else None

    if not is_auth and not guest_token:
        return jsonify({'error': 'Guest token required for unauthenticated submissions'}), 400

    # Upsert across daily, weekly, and all-time partitions
    partitions = [
        ('daily', day_key),
        ('weekly', week_key),
        ('all_time', 'all')
    ]

    for p_type, p_key in partitions:
        query = {
            'game': game,
            'category': category,
            'period_key': p_key
        }
        if is_auth:
            query['user_id'] = user_id
        elif guest_token:
            query['guest_token'] = guest_token
        else:
            query = None

        if query:
            existing = m.arcade_leaderboards_conf.find_one(query)
            if existing and existing.get('score', 0) >= score:
                continue
            m.arcade_leaderboards_conf.update_one(
                query,
                {
                    '$set': {
                        'username': username,
                        'avatar_url': avatar_url,
                        'is_guest': not is_auth,
                        'game': game,
                        'category': category,
                        'period': p_type,
                        'period_key': p_key,
                        'score': score,
                        'metadata': metadata,
                        'updated_at': now_utc
                    },
                    '$setOnInsert': {
                        'created_at': now_utc
                    }
                },
                upsert=True
            )
        else:
            m.arcade_leaderboards_conf.insert_one({
                'user_id': None,
                'guest_token': None,
                'username': username,
                'avatar_url': None,
                'is_guest': True,
                'game': game,
                'category': category,
                'period': p_type,
                'period_key': p_key,
                'score': score,
                'metadata': metadata,
                'created_at': now_utc,
                'updated_at': now_utc
            })

    return jsonify({
        'success': True,
        'game': game,
        'category': category,
        'score': score
    })


@bp.route('/api/games/leaderboard', methods=['GET'])
def api_leaderboard_get():
    """Retrieve top 10 leaderboard entries for a given game, category, and period, with optional difficulty filter."""
    import main as m
    game = (request.args.get('game') or 'floppy_bird').strip()
    category = (request.args.get('category') or '').strip()
    if game not in VALID_ARCADE_CATEGORIES:
        return jsonify({'error': 'Invalid game'}), 400
    if not category or category not in VALID_ARCADE_CATEGORIES[game]:
        category = VALID_ARCADE_CATEGORIES[game][0]

    period = (request.args.get('period') or 'weekly').strip()
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    if period == 'daily':
        period_key = now_utc.strftime('%Y-%m-%d')
    elif period == 'all_time':
        period_key = 'all'
    else:
        period = 'weekly'
        period_key = now_utc.strftime('%Y-W%U')

    difficulty = (request.args.get('difficulty') or '').strip().lower()
    query = {
        'game': game,
        'category': category,
        'period_key': period_key
    }
    if difficulty and difficulty != 'all':
        query['metadata.difficulty'] = difficulty

    cursor = m.arcade_leaderboards_conf.find(query).sort('score', -1).limit(10)

    leaders = []
    for idx, doc in enumerate(cursor):
        dt = doc.get('updated_at') or doc.get('created_at') or now_utc
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        ts = dt.isoformat().replace('+00:00', 'Z')
        leaders.append({
            'rank': idx + 1,
            'username': doc.get('username', 'Anonymous'),
            'avatar_url': doc.get('avatar_url'),
            'is_guest': bool(doc.get('is_guest')),
            'score': doc.get('score', 0),
            'metadata': doc.get('metadata') or {},
            'updated_at': ts
        })

    user_record = None
    guest_token = (request.args.get('guest_token') or '').strip()[:64]
    user_query = None
    if current_user.is_authenticated:
        user_query = {
            'user_id': str(current_user.id),
            'game': game,
            'category': category,
            'period_key': period_key
        }
    elif guest_token:
        user_query = {
            'guest_token': guest_token,
            'game': game,
            'category': category,
            'period_key': period_key
        }
    if user_query:
        if difficulty and difficulty != 'all':
            user_query['metadata.difficulty'] = difficulty
        my_doc = m.arcade_leaderboards_conf.find_one(user_query)
        if my_doc:
            count_query = {
                'game': game,
                'category': category,
                'period_key': period_key,
                'score': {'$gt': my_doc.get('score', 0)}
            }
            if difficulty and difficulty != 'all':
                count_query['metadata.difficulty'] = difficulty
            higher = m.arcade_leaderboards_conf.count_documents(count_query)
            user_record = {
                'rank': higher + 1,
                'score': my_doc.get('score', 0),
                'metadata': my_doc.get('metadata') or {}
            }

    return jsonify({
        'game': game,
        'category': category,
        'period': period,
        'period_key': period_key,
        'entries': leaders,
        'leaders': leaders,
        'user_record': user_record
    })

