from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets, hashlib, re
from security import limits, encrypt_form_response, decrypt_form_response
import database

bp = Blueprint('forms', __name__)

ALLOWED_TYPES = {'short_text', 'paragraph', 'single_choice', 'multiple_choice', 'rating'}
MAX_QUESTIONS = 15
MAX_FORMS_PER_USER = 20

def _owner_or_404(form):
    if not form:
        return None
    if str(form.get('owner_id')) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        return None
    return form

def _parse_expires(expires_in):
    if not expires_in:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_in == '1h':
        return now + datetime.timedelta(hours=1)
    if expires_in == '1d':
        return now + datetime.timedelta(days=1)
    if expires_in == '7d':
        return now + datetime.timedelta(days=7)
    return None

def _validate_questions(raw):
    if not isinstance(raw, list) or not raw:
        return None, 'At least one question required'
    if len(raw) > MAX_QUESTIONS:
        return None, f'Max {MAX_QUESTIONS} questions'
    cleaned = []
    for idx, q in enumerate(raw):
        if not isinstance(q, dict):
            return None, f'Question {idx+1} invalid'
        label = (q.get('label') or q.get('title') or '').strip()
        qtype = (q.get('type') or '').strip()
        if not label or len(label) > 200:
            return None, f'Question {idx+1} label required (max 200)'
        if qtype not in ALLOWED_TYPES:
            return None, f'Question {idx+1} invalid type'
        required = bool(q.get('required'))
        opts = []
        if qtype in ('single_choice', 'multiple_choice'):
            raw_opts = q.get('options') or []
            if not isinstance(raw_opts, list) or len(raw_opts) < 2 or len(raw_opts) > 10:
                return None, f'Question {idx+1} needs 2-10 options'
            for o in raw_opts:
                o = str(o).strip()
                if not o or len(o) > 100:
                    return None, f'Question {idx+1} option invalid (max 100)'
                opts.append(o)
        qid = q.get('id') or secrets.token_hex(4)
        cleaned.append({'id': qid, 'label': label, 'type': qtype, 'required': required, 'options': opts})
    return cleaned, None


@bp.route('/forms')
@login_required
def forms_list():
    import main as m
    forms = list(m.forms_conf.find({'owner_id': ObjectId(current_user.id)}).sort('created_at', -1))
    # enrich with response counts already stored
    return render_template('forms_list.html', forms=forms, active_page='forms')


@bp.route('/forms/create', methods=['GET', 'POST'])
@login_required
@limits(calls=10, period=60)
def forms_create():
    import main as m
    if getattr(current_user, 'is_guest', False):
        flash('Sign up to create forms — tour mode is read-only.', 'warning')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        expires_in = (request.form.get('expires_in') or '').strip()
        max_res_raw = (request.form.get('max_responses') or '').strip()
        if not title or len(title) > 100:
            flash('Title required (max 100).', 'danger')
            return render_template('form_create.html', active_page='forms')
        if len(description) > 500:
            flash('Description max 500.', 'danger')
            return render_template('form_create.html', active_page='forms')
        # questions come as JSON string in hidden field (built by JS)
        import json
        q_json = request.form.get('questions_json') or '[]'
        try:
            raw_q = json.loads(q_json)
        except Exception:
            flash('Invalid questions payload.', 'danger')
            return render_template('form_create.html', active_page='forms')
        questions, err = _validate_questions(raw_q)
        if err:
            flash(err, 'danger')
            return render_template('form_create.html', active_page='forms')
        # cap forms per user
        if m.forms_conf.count_documents({'owner_id': ObjectId(current_user.id)}) >= MAX_FORMS_PER_USER:
            flash(f'Max {MAX_FORMS_PER_USER} forms reached.', 'danger')
            return redirect(url_for('forms.forms_list'))
        expires_at = _parse_expires(expires_in)
        max_responses = None
        if max_res_raw:
            try:
                max_responses = int(max_res_raw)
                if max_responses < 1 or max_responses > 10000:
                    max_responses = None
            except Exception:
                max_responses = None
        allow_anon_raw = (request.form.get('allow_anonymous') or '1').strip()
        allow_anonymous = allow_anon_raw != '0'
        share_id = secrets.token_urlsafe(16)
        doc = {
            'owner_id': ObjectId(current_user.id),
            'owner_username': current_user.username,
            'title': title,
            'description': description,
            'questions': questions,
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'expires_at': expires_at,
            'is_active': True,
            'deactivated': False,
            'response_count': 0,
            'max_responses': max_responses,
            'allow_anonymous': allow_anonymous,
        }
        m.forms_conf.insert_one(doc)
        flash(f'Form created — share link copied.', 'success')
        return redirect(url_for('forms.form_responses_view', share_id=share_id))
    return render_template('form_create.html', active_page='forms')


@bp.route('/api/forms/create', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_create_form():
    import main as m
    import json
    if getattr(current_user, 'is_guest', False):
        return jsonify({'error': 'Guest cannot create forms'}), 403
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    description = (data.get('description') or '').strip()
    expires_in = (data.get('expires_in') or '').strip()
    max_responses = data.get('max_responses')
    raw_q = data.get('questions') or []
    if not title or len(title) > 100:
        return jsonify({'error': 'Title required (max 100)'}), 400
    if len(description) > 500:
        return jsonify({'error': 'Description max 500'}), 400
    questions, err = _validate_questions(raw_q)
    if err:
        return jsonify({'error': err}), 400
    if m.forms_conf.count_documents({'owner_id': ObjectId(current_user.id)}) >= MAX_FORMS_PER_USER:
        return jsonify({'error': f'Max {MAX_FORMS_PER_USER} forms reached'}), 429
    expires_at = _parse_expires(expires_in)
    if max_responses is not None:
        try:
            max_responses = int(max_responses)
            if max_responses < 1 or max_responses > 10000:
                max_responses = None
        except Exception:
            max_responses = None
    share_id = secrets.token_urlsafe(16)
    doc = {
        'owner_id': ObjectId(current_user.id),
        'owner_username': current_user.username,
        'title': title,
        'description': description,
        'questions': questions,
        'share_id': share_id,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'expires_at': expires_at,
        'is_active': True,
        'deactivated': False,
        'response_count': 0,
        'max_responses': max_responses,
        'allow_anonymous': bool(data.get('allow_anonymous', True) if not isinstance(data.get('allow_anonymous'), str) else data.get('allow_anonymous', '1') not in ('0', 'false', 'no')),
    }
    m.forms_conf.insert_one(doc)
    share_url = url_for('forms.view_form', share_id=share_id, _external=True)
    return jsonify({'success': True, 'share_id': share_id, 'share_url': share_url, 'form_id': str(doc['_id'])}), 201


# --- Public form view/submit (no login) ---

@bp.route('/f/<share_id>', methods=['GET'])
@limits(calls=30, period=60)
def view_form(share_id):
    import main as m
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        return render_template('form_submit.html', expired=True, msg='Form not found'), 404
    is_owner = current_user.is_authenticated and (str(form['owner_id']) == str(current_user.id) or getattr(current_user, 'is_admin', False))
    if form.get('deactivated'):
        return render_template('form_submit.html', form=form, expired=True, msg='This form has been deactivated by the owner', can_view_responses=is_owner), 410
    if form.get('expires_at'):
        exp = form['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return render_template('form_submit.html', form=form, expired=True, msg='This form has expired', can_view_responses=is_owner), 410
    if form.get('max_responses') and form.get('response_count', 0) >= form['max_responses']:
        return render_template('form_submit.html', form=form, expired=True, msg='This form has reached its response limit', can_view_responses=is_owner), 410
    if not form.get('allow_anonymous', True) and not current_user.is_authenticated:
        return render_template('form_submit.html', form=form, login_required=True, msg='Account required. The creator of this form requires respondents to log in.', share_id=share_id), 200
    # success param shows thank-you state
    submitted = request.args.get('submitted') == '1'
    return render_template('form_submit.html', form=form, submitted=submitted, share_id=share_id)


@bp.route('/f/<share_id>/submit', methods=['POST'])
@limits(calls=10, period=60)
def submit_form(share_id):
    import main as m
    # Honeypot
    if (request.form.get('website') or (request.get_json(silent=True) or {}).get('website')):
        return jsonify({'error': 'Bot detected'}), 400
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        return jsonify({'error': 'Form not found'}), 404
    if form.get('deactivated'):
        return jsonify({'error': 'Form deactivated'}), 410
    if form.get('expires_at'):
        exp = form['expires_at']
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > exp:
            return jsonify({'error': 'Form expired'}), 410
    if form.get('max_responses') and form.get('response_count', 0) >= form['max_responses']:
        return jsonify({'error': 'Response limit reached'}), 410
    if not form.get('allow_anonymous', True) and not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required. This form does not allow anonymous submissions.'}), 401
    # Per-IP per-form 5/600 like proposal
    ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr or '')
    rate_key = f'form_submit_rate_{share_id}:{ip}'
    if m.redis_cache:
        try:
            cnt = m.redis_cache.incr(rate_key)
            if cnt == 1:
                m.redis_cache.expire(rate_key, 600)
            if cnt > 5:
                return jsonify({'error': 'Too many submissions — try again in a few minutes'}), 429
        except Exception:
            pass
    else:
        # session fallback
        sess_key = f'form_submit_{share_id}'
        scnt = session.get(sess_key, 0)
        if scnt >= 5:
            return jsonify({'error': 'Too many submissions'}), 429
        session[sess_key] = scnt + 1
    # Parse answers
    data = request.get_json(silent=True)
    answers_raw = {}
    if data and isinstance(data.get('answers'), dict):
        answers_raw = data['answers']
    else:
        # form-encoded: keys like q_<id>
        for k, v in request.form.items():
            if k.startswith('q_'):
                qid = k[2:]
                answers_raw[qid] = v
                # for multiple_choice, form sends multiple q_<id> entries; collect list
                # Flask's request.form will give last value; use getlist for those
        # handle multiple_choice getlist
        for q in form.get('questions', []):
            if q['type'] == 'multiple_choice':
                vals = request.form.getlist(f"q_{q['id']}")
                if vals:
                    answers_raw[q['id']] = vals
    # Validate against form definition
    answers = []
    for q in form.get('questions', []):
        qid = q['id']
        qtype = q['type']
        required = q['required']
        raw_val = answers_raw.get(qid)
        # normalize
        if qtype == 'multiple_choice':
            if raw_val is None:
                vals = []
            elif isinstance(raw_val, list):
                vals = [str(v).strip() for v in raw_val if str(v).strip()]
            else:
                vals = [str(raw_val).strip()] if str(raw_val).strip() else []
            if required and not vals:
                msg = f'Question "{q["label"]}" is required'
                if data: return jsonify({'error': msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('forms.view_form', share_id=share_id))
            if vals:
                # bleach + options check
                cleaned = []
                for v in vals:
                    if len(v) > 500:
                        v = v[:500]
                    v = v.strip()
                    if v not in q['options']:
                        msg = f'Invalid option for "{q["label"]}"'
                        if data: return jsonify({'error': msg}), 400
                        flash(msg, 'danger')
                        return redirect(url_for('forms.view_form', share_id=share_id))
                    cleaned.append(v)
                raw_val = ','.join(cleaned)
            else:
                raw_val = ''
        elif qtype == 'single_choice':
            raw_val = str(raw_val).strip() if raw_val is not None else ''
            if required and not raw_val:
                msg = f'Question "{q["label"]}" is required'
                if data: return jsonify({'error': msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('forms.view_form', share_id=share_id))
            if raw_val and raw_val not in q['options']:
                msg = f'Invalid option for "{q["label"]}"'
                if data: return jsonify({'error': msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('forms.view_form', share_id=share_id))
            if len(raw_val) > 500:
                raw_val = raw_val[:500]
        elif qtype == 'rating':
            raw_val = str(raw_val).strip() if raw_val is not None else ''
            if required and not raw_val:
                msg = f'Question "{q["label"]}" is required'
                if data: return jsonify({'error': msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('forms.view_form', share_id=share_id))
            if raw_val:
                try:
                    iv = int(raw_val)
                    if iv < 1 or iv > 5:
                        raise ValueError()
                except Exception:
                    msg = f'Rating for "{q["label"]}" must be 1-5'
                    if data: return jsonify({'error': msg}), 400
                    flash(msg, 'danger')
                    return redirect(url_for('forms.view_form', share_id=share_id))
        else: # short_text, paragraph
            raw_val = str(raw_val).strip() if raw_val is not None else ''
            if required and not raw_val:
                msg = f'Question "{q["label"]}" is required'
                if data: return jsonify({'error': msg}), 400
                flash(msg, 'danger')
                return redirect(url_for('forms.view_form', share_id=share_id))
            if raw_val:
                if len(raw_val) > 2000:
                    raw_val = raw_val[:2000]
                # bleach strip tags
                import bleach
                raw_val = bleach.clean(raw_val, tags=[], strip=True)
        # encrypt at rest
        enc_val = encrypt_form_response(raw_val, str(form['_id'])) if raw_val else ''
        answers.append({'question_id': qid, 'type': qtype, 'value': enc_val, 'label': q['label']})
    # store submitter identity if logged in
    ip_hash = hashlib.sha256((ip or '').encode()).hexdigest()[:16] if ip else ''
    is_auth = current_user.is_authenticated
    submitter_id = current_user.id if is_auth else None
    submitter_username = getattr(current_user, 'username', None) if is_auth else None
    submitter_name = (getattr(current_user, 'display_name', '') or getattr(current_user, 'full_name', '') or getattr(current_user, 'username', '')) if is_auth else None
    submitter_avatar = getattr(current_user, 'profile_image_url', None) if is_auth else None

    doc = {
        'form_id': form['_id'],
        'share_id': share_id,
        'answers': answers,
        'submitted_at': datetime.datetime.now(datetime.timezone.utc),
        'submitter_id': submitter_id,
        'submitter_username': submitter_username,
        'submitter_name': submitter_name,
        'submitter_avatar': submitter_avatar,
        'is_authenticated': is_auth,
        'submitter_ip_hash': ip_hash,
        'user_agent': (request.headers.get('User-Agent') or '')[:300],
    }
    m.form_responses_conf.insert_one(doc)
    m.forms_conf.update_one({'_id': form['_id']}, {'$inc': {'response_count': 1}})
    # live update via socket (reuse note pattern)
    try:
        m.socketio.emit('form_response', {'share_id': share_id, 'form_id': str(form['_id']), 'count': (form.get('response_count',0)+1)}, room=f"form_{share_id}")
    except Exception:
        pass

    # Notify form owner via push and user socket room
    owner_id = form.get('owner_id')
    if owner_id and (not submitter_id or str(owner_id) != str(submitter_id)):
        form_title = form.get('title', 'Untitled Form')
        submitter_disp = submitter_username or (submitter_name if submitter_name else 'Someone')
        owner_id_str = str(owner_id)
        try:
            responses_url = url_for('forms.form_responses_view', share_id=share_id, _external=True)
            m.send_push_notification_to_user(
                owner_id_str,
                f"New response: {form_title}",
                f"{submitter_disp} just submitted a response.",
                url=responses_url,
                tag=f"form-response-{form['_id']}",
                category='forms'
            )
        except Exception as e:
            current_app.logger.warning(f"Failed to dispatch form response push: {e}")

        try:
            m.socketio.emit('form_new_submission', {
                'share_id': share_id,
                'form_id': str(form['_id']),
                'form_title': form_title,
                'submitter': submitter_disp
            }, room=f"user_{owner_id_str}")
        except Exception:
            pass
    if data:
        return jsonify({'success': True, 'message': 'Response recorded'})
    flash('Response recorded. Thank you!', 'success')
    return redirect(url_for('forms.view_form', share_id=share_id, submitted='1'))


# --- Owner views ---

@bp.route('/forms/<share_id>/responses')
@login_required
def form_responses_view(share_id):
    import main as m
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        flash('Form not found', 'danger')
        return redirect(url_for('forms.forms_list'))
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('forms.forms_list'))
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 20
    total = m.form_responses_conf.count_documents({'form_id': form['_id']})
    responses = list(m.form_responses_conf.find({'form_id': form['_id']}).sort('submitted_at', -1).skip((page-1)*per_page).limit(per_page))
    # decrypt for display
    for r in responses:
        for a in r.get('answers', []):
            try:
                a['value_plain'] = decrypt_form_response(a.get('value',''), str(form['_id']))
            except Exception:
                a['value_plain'] = a.get('value','')
        if r.get('submitted_at'):
            ts = r['submitted_at']
            if ts.tzinfo is None: ts = ts.replace(tzinfo=datetime.timezone.utc)
            r['submitted_at_iso'] = ts.isoformat().replace('+00:00','Z')
            r['submitted_at_formatted'] = ts.strftime('%b %d, %Y, %I:%M %p')
        else:
            r['submitted_at_formatted'] = '—'
    # stats for charts: per single_choice counts and rating avg
    stats = {}
    if responses:
        for q in form.get('questions', []):
            if q['type'] == 'single_choice':
                counts = {o:0 for o in q['options']}
                total_q = 0
                for r in m.form_responses_conf.find({'form_id': form['_id']}, {'answers':1}):
                    for a in r.get('answers', []):
                        if a['question_id']==q['id']:
                            v = decrypt_form_response(a.get('value',''), str(form['_id']))
                            if v in counts:
                                counts[v]+=1
                                total_q+=1
                stats[q['id']] = {'type':'single_choice','label':q['label'],'counts':counts,'total':total_q}
            elif q['type'] == 'rating':
                vals=[]
                for r in m.form_responses_conf.find({'form_id': form['_id']}, {'answers':1}):
                    for a in r.get('answers', []):
                        if a['question_id']==q['id']:
                            v=decrypt_form_response(a.get('value',''), str(form['_id']))
                            try: vals.append(int(v))
                            except: pass
                avg = round(sum(vals)/len(vals),2) if vals else None
                stats[q['id']] = {'type':'rating','label':q['label'],'avg':avg,'count':len(vals),'distribution':{str(i):vals.count(i) for i in range(1,6)}}
    total_pages = max(1, (total + per_page -1)//per_page)
    return render_template('form_responses.html', form=form, responses=responses, total=total, page=page, per_page=per_page, total_pages=total_pages, stats=stats)


@bp.route('/forms/<share_id>/responses/export')
@login_required
def form_responses_export(share_id):
    import main as m
    import csv, io, json
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        return jsonify({'error':'Form not found'}),404
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        return jsonify({'error':'Not authorized'}),403
    fmt = (request.args.get('format') or 'csv').lower()
    responses = list(m.form_responses_conf.find({'form_id': form['_id']}).sort('submitted_at', -1))
    if fmt == 'json':
        out=[]
        for r in responses:
            ts = r.get('submitted_at')
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=datetime.timezone.utc)
            row = {
                'submitted_at': ts.isoformat().replace('+00:00','Z') if ts else None,
                'respondent': r.get('submitter_username') or 'Anonymous',
                'is_authenticated': bool(r.get('is_authenticated'))
            }
            for a in r.get('answers', []):
                row[a.get('label') or a['question_id']] = decrypt_form_response(a.get('value',''), str(form['_id']))
            out.append(row)
        return jsonify({'form':{'title':form['title'],'share_id':share_id},'count':len(out),'responses':out})
    # csv
    q_labels = [q['label'] for q in form.get('questions',[])]
    headers = ['submitted_at', 'respondent'] + q_labels
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(headers)
    for r in responses:
        ans_map={}
        for a in r.get('answers',[]):
            ans_map[a['question_id']] = decrypt_form_response(a.get('value',''), str(form['_id']))
        ts = r.get('submitted_at')
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
        sub_str = ts.strftime('%Y-%m-%d %H:%M:%S UTC') if ts else ''
        resp_str = r.get('submitter_username') or 'Anonymous'
        row=[sub_str, resp_str]
        for q in form.get('questions',[]):
            row.append(ans_map.get(q['id'],''))
        w.writerow(row)
    csv_data = output.getvalue()
    resp = make_response(csv_data)
    resp.headers['Content-Type']='text/csv'
    resp.headers['Content-Disposition']=f"attachment; filename=form_{share_id}_responses.csv"
    return resp


@bp.route('/forms/<share_id>/deactivate', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def form_deactivate(share_id):
    import main as m
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        flash('Form not found','danger')
        return redirect(url_for('forms.forms_list'))
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized','danger')
        return redirect(url_for('forms.forms_list'))
    m.forms_conf.update_one({'_id': form['_id']}, {'$set':{'deactivated':True}})
    flash('Form deactivated. The link will no longer accept responses.','success')
    referrer = request.referrer or ''
    if 'personal_space' in referrer:
        return redirect(url_for('pages.personal_space') + '#forms')
    return redirect(url_for('forms.form_responses_view', share_id=share_id))


@bp.route('/forms/<share_id>/delete', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def form_delete(share_id):
    import main as m
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form:
        flash('Form not found', 'danger')
        return redirect(url_for('forms.forms_list'))
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('forms.forms_list'))
    m.form_responses_conf.delete_many({'form_id': form['_id']})
    m.forms_conf.delete_one({'_id': form['_id']})
    flash('Form and all associated responses deleted.', 'success')
    referrer = request.referrer or ''
    if 'personal_space' in referrer:
        return redirect(url_for('pages.personal_space') + '#forms')
    return redirect(url_for('forms.forms_list'))


@bp.route('/api/forms/<share_id>/stats')
@login_required
def api_form_stats(share_id):
    import main as m
    form = m.forms_conf.find_one({'share_id': share_id})
    if not form or str(form['owner_id']) != str(current_user.id):
        return jsonify({'error':'Not found'}),404
    total = m.form_responses_conf.count_documents({'form_id': form['_id']})
    # per-day
    pipeline=[{'$match':{'form_id':form['_id']}}, {'$group':{'_id':{'$dateToString':{'format':'%Y-%m-%d','date':'$submitted_at'}},'count':{'$sum':1}}}, {'$sort':{'_id':1}}]
    per_day=list(m.form_responses_conf.aggregate(pipeline))
    return jsonify({'total':total,'per_day':per_day})
