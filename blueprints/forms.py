from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, make_response, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, secrets, hashlib, re
from security import limits, encrypt_form_response, decrypt_form_response

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


def _encrypt_form_definition(form_id_str, title, description, questions):
    """Encrypt creator-authored form text at rest (per-form key, same as answers).

    Returns (enc_title, enc_description, enc_questions). Structure/keys
    (id/type/required) stay plaintext — only human-readable text is encrypted.
    """
    enc_questions = []
    for q in questions or []:
        enc_questions.append({
            'id': q.get('id'),
            'label': encrypt_form_response(q.get('label') or '', form_id_str),
            'type': q.get('type'),
            'required': bool(q.get('required')),
            'options': [encrypt_form_response(o, form_id_str) for o in (q.get('options') or [])],
        })
    return (
        encrypt_form_response(title or '', form_id_str),
        encrypt_form_response(description or '', form_id_str),
        enc_questions,
    )


def _decrypt_form_definition(form):
    """Return a copy of a form doc with definition text decrypted for render/validate.

    Legacy plaintext rows pass through (decrypt falls back when not a Fernet
    token). Never mutates the stored doc — callers must not write this back.
    """
    if not form or not isinstance(form, dict):
        return form
    form = dict(form)
    fid = str(form.get('_id', ''))
    if form.get('title'):
        form['title'] = decrypt_form_response(form['title'], fid)
    if form.get('description'):
        form['description'] = decrypt_form_response(form['description'], fid)
    dec_q = []
    for q in (form.get('questions') or []):
        q = dict(q)
        if q.get('label'):
            q['label'] = decrypt_form_response(q['label'], fid)
        q['options'] = [decrypt_form_response(o, fid) for o in (q.get('options') or [])]
        dec_q.append(q)
    form['questions'] = dec_q

    dec_versions = []
    for v in (form.get('versions') or []):
        v = dict(v)
        if v.get('title'):
            v['title'] = decrypt_form_response(v['title'], fid)
        if v.get('description'):
            v['description'] = decrypt_form_response(v['description'], fid)
        v_qs = []
        for vq in (v.get('questions') or []):
            vq = dict(vq)
            if vq.get('label'):
                vq['label'] = decrypt_form_response(vq['label'], fid)
            vq['options'] = [decrypt_form_response(o, fid) for o in (vq.get('options') or [])]
            v_qs.append(vq)
        v['questions'] = v_qs
        dec_versions.append(v)
    form['versions'] = dec_versions

    return form


@bp.route('/forms')
@login_required
def forms_list():
    import main as m
    forms = [_decrypt_form_definition(f) for f in m.forms_conf.find({'owner_id': ObjectId(current_user.id)}).sort('created_at', -1)]
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
        # Pre-generate _id so the per-form key exists before insert (single write).
        form_oid = ObjectId()
        enc_title, enc_description, enc_questions = _encrypt_form_definition(str(form_oid), title, description, questions)
        doc = {
            '_id': form_oid,
            'owner_id': ObjectId(current_user.id),
            'owner_username': current_user.username,
            'title': enc_title,
            'description': enc_description,
            'questions': enc_questions,
            'share_id': share_id,
            'created_at': datetime.datetime.now(datetime.timezone.utc),
            'expires_at': expires_at,
            'is_active': True,
            'deactivated': False,
            'response_count': 0,
            'max_responses': max_responses,
            'allow_anonymous': allow_anonymous,
            'version': 1,
            'versions': [],
        }
        m.forms_conf.insert_one(doc)
        flash('Form created — share link copied.', 'success')
        return redirect(url_for('forms.form_responses_view', share_id=share_id))
    return render_template('form_create.html', active_page='forms')


@bp.route('/api/forms/create', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_create_form():
    import main as m
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
    # Pre-generate _id so the per-form key exists before insert (single write).
    form_oid = ObjectId()
    enc_title, enc_description, enc_questions = _encrypt_form_definition(str(form_oid), title, description, questions)
    doc = {
        '_id': form_oid,
        'owner_id': ObjectId(current_user.id),
        'owner_username': current_user.username,
        'title': enc_title,
        'description': enc_description,
        'questions': enc_questions,
        'share_id': share_id,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'expires_at': expires_at,
        'is_active': True,
        'deactivated': False,
        'response_count': 0,
        'max_responses': max_responses,
        'allow_anonymous': bool(data.get('allow_anonymous', True) if not isinstance(data.get('allow_anonymous'), str) else data.get('allow_anonymous', '1') not in ('0', 'false', 'no')),
        'version': 1,
        'versions': [],
    }
    m.forms_conf.insert_one(doc)
    share_url = url_for('forms.view_form', share_id=share_id, _external=True)
    return jsonify({'success': True, 'share_id': share_id, 'share_url': share_url, 'form_id': str(doc['_id'])}), 201


@bp.route('/forms/<share_id>/edit', methods=['GET', 'POST'])
@login_required
@limits(calls=15, period=60)
def forms_edit(share_id):
    import main as m
    if getattr(current_user, 'is_guest', False):
        flash('Sign up to edit forms — tour mode is read-only.', 'warning')
        return redirect(url_for('auth.login'))

    raw_form = m.forms_conf.find_one({'share_id': share_id})
    if not raw_form:
        flash('Form not found.', 'danger')
        return redirect(url_for('forms.forms_list'))
    if not _owner_or_404(raw_form):
        flash('Not authorized to edit this form.', 'danger')
        return redirect(url_for('forms.forms_list'))

    form = _decrypt_form_definition(raw_form)
    response_count = m.form_responses_conf.count_documents({'form_id': raw_form['_id']})

    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        description = (request.form.get('description') or '').strip()
        expires_in = (request.form.get('expires_in') or 'keep').strip()
        max_res_raw = (request.form.get('max_responses') or '').strip()

        if not title or len(title) > 100:
            flash('Title required (max 100).', 'danger')
            return render_template('form_edit.html', form=form, response_count=response_count, active_page='forms')
        if len(description) > 500:
            flash('Description max 500.', 'danger')
            return render_template('form_edit.html', form=form, response_count=response_count, active_page='forms')

        import json
        q_json = request.form.get('questions_json') or '[]'
        try:
            raw_q = json.loads(q_json)
        except Exception:
            flash('Invalid questions payload.', 'danger')
            return render_template('form_edit.html', form=form, response_count=response_count, active_page='forms')

        questions, err = _validate_questions(raw_q)
        if err:
            flash(err, 'danger')
            return render_template('form_edit.html', form=form, response_count=response_count, active_page='forms')

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

        now = datetime.datetime.now(datetime.timezone.utc)
        enc_title, enc_description, enc_questions = _encrypt_form_definition(
            str(raw_form['_id']), title, description, questions
        )

        current_version = raw_form.get('version', 1)
        existing_versions = list(raw_form.get('versions') or [])
        version_snapshot = {
            'version': current_version,
            'title': raw_form.get('title'),
            'description': raw_form.get('description'),
            'questions': raw_form.get('questions'),
            'archived_at': now,
            'created_at': raw_form.get('created_at') if current_version == 1 else raw_form.get('updated_at', now)
        }
        existing_versions.append(version_snapshot)
        new_version = current_version + 1

        update_fields = {
            'title': enc_title,
            'description': enc_description,
            'questions': enc_questions,
            'version': new_version,
            'versions': existing_versions,
            'updated_at': now,
            'max_responses': max_responses,
            'allow_anonymous': allow_anonymous,
        }

        if expires_in == 'never':
            update_fields['expires_at'] = None
        elif expires_in in ('1h', '1d', '7d'):
            update_fields['expires_at'] = _parse_expires(expires_in)

        m.forms_conf.update_one({'_id': raw_form['_id']}, {'$set': update_fields})
        flash('Form updated successfully.', 'success')
        return redirect(url_for('forms.form_responses_view', share_id=share_id))

    return render_template('form_edit.html', form=form, response_count=response_count, active_page='forms')


@bp.route('/api/forms/<share_id>/edit', methods=['POST'])
@login_required
@limits(calls=15, period=60)
def api_edit_form(share_id):
    import main as m
    if getattr(current_user, 'is_guest', False):
        return jsonify({'error': 'Guest cannot edit forms'}), 403

    raw_form = m.forms_conf.find_one({'share_id': share_id})
    if not raw_form:
        return jsonify({'error': 'Form not found'}), 404
    if not _owner_or_404(raw_form):
        return jsonify({'error': 'Not authorized'}), 403

    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    description = (data.get('description') or '').strip()
    expires_in = (data.get('expires_in') or 'keep').strip()
    max_responses = data.get('max_responses')
    raw_q = data.get('questions') or []

    if not title or len(title) > 100:
        return jsonify({'error': 'Title required (max 100)'}), 400
    if len(description) > 500:
        return jsonify({'error': 'Description max 500'}), 400

    questions, err = _validate_questions(raw_q)
    if err:
        return jsonify({'error': err}), 400

    if max_responses is not None:
        try:
            max_responses = int(max_responses)
            if max_responses < 1 or max_responses > 10000:
                max_responses = None
        except Exception:
            max_responses = None

    now = datetime.datetime.now(datetime.timezone.utc)
    enc_title, enc_description, enc_questions = _encrypt_form_definition(
        str(raw_form['_id']), title, description, questions
    )

    current_version = raw_form.get('version', 1)
    existing_versions = list(raw_form.get('versions') or [])
    version_snapshot = {
        'version': current_version,
        'title': raw_form.get('title'),
        'description': raw_form.get('description'),
        'questions': raw_form.get('questions'),
        'archived_at': now,
        'created_at': raw_form.get('created_at') if current_version == 1 else raw_form.get('updated_at', now)
    }
    existing_versions.append(version_snapshot)
    new_version = current_version + 1

    update_fields = {
        'title': enc_title,
        'description': enc_description,
        'questions': enc_questions,
        'version': new_version,
        'versions': existing_versions,
        'updated_at': now,
        'max_responses': max_responses,
        'allow_anonymous': bool(data.get('allow_anonymous', True) if not isinstance(data.get('allow_anonymous'), str) else data.get('allow_anonymous', '1') not in ('0', 'false', 'no')),
    }

    if expires_in == 'never':
        update_fields['expires_at'] = None
    elif expires_in in ('1h', '1d', '7d'):
        update_fields['expires_at'] = _parse_expires(expires_in)

    m.forms_conf.update_one({'_id': raw_form['_id']}, {'$set': update_fields})
    return jsonify({'success': True, 'share_id': share_id, 'message': 'Form updated successfully'})


# --- Public form view/submit (no login) ---

@bp.route('/f/<share_id>', methods=['GET'])
@limits(calls=30, period=60)
def view_form(share_id):
    import main as m
    form = _decrypt_form_definition(m.forms_conf.find_one({'share_id': share_id}))
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
    prior_submission = None
    if current_user.is_authenticated:
        prior_submission = m.form_responses_conf.find_one(
            {'form_id': form['_id'], 'submitter_id': current_user.id},
            sort=[('submitted_at', -1)]
        )
    return render_template('form_submit.html', form=form, submitted=submitted, share_id=share_id, prior_submission=prior_submission)


@bp.route('/f/<share_id>/submit', methods=['POST'])
@limits(calls=10, period=60)
def submit_form(share_id):
    import main as m
    # Honeypot
    if (request.form.get('website') or (request.get_json(silent=True) or {}).get('website')):
        return jsonify({'error': 'Bot detected'}), 400
    # Decrypt in memory for validation/rendering; response_count updates below are
    # targeted $inc writes so the decrypted copy is never persisted.
    form = _decrypt_form_definition(m.forms_conf.find_one({'share_id': share_id}))
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
        'form_version': form.get('version', 1),
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


# --- Question Alignment & Response Matching ---

STOPWORDS = {'what', 'is', 'are', 'your', 'you', 'the', 'a', 'an', 'in', 'of', 'for', 'to', 'do', 'how', 'please', 'enter', 'rate'}

def _clean_text(s):
    if not s:
        return ''
    s = s.lower().strip()
    s = re.sub(r'[^a-z0-9\s]', '', s)
    return ' '.join(s.split())

def _substantive_words(s):
    cleaned = _clean_text(s)
    return set(w for w in cleaned.split() if w not in STOPWORDS and len(w) > 1)

def _labels_are_compatible(lbl1, lbl2):
    t1 = _clean_text(lbl1)
    t2 = _clean_text(lbl2)
    if not t1 or not t2:
        return True
    if t1 == t2:
        return True
    if t1 in t2 or t2 in t1:
        return True
    w1 = _substantive_words(lbl1)
    w2 = _substantive_words(lbl2)
    if not w1 or not w2:
        return t1 == t2
    overlap = len(w1 & w2)
    min_len = min(len(w1), len(w2))
    return (overlap / min_len) >= 0.5


def _align_response_answers(form_questions, answers):
    """Align answers from a submission against current form questions.

    Returns:
      (aligned_dict, retired_list)
      - aligned_dict: {q_id: answer_dict or None}
      - retired_list: list of answer_dict for questions that were replaced or removed
    """
    claimed_answers = set()
    aligned = {}

    # Pass 1: Exact ID + Compatible Label
    for q in form_questions:
        q_id = q['id']
        q_lbl = q.get('label', '')
        for idx, a in enumerate(answers):
            if idx in claimed_answers:
                continue
            if a.get('question_id') == q_id and _labels_are_compatible(q_lbl, a.get('label', '')):
                aligned[q_id] = a
                claimed_answers.add(idx)
                break

    # Pass 2: Exact Normalized Label Match (handles retained questions whose ID changed during edit)
    for q in form_questions:
        q_id = q['id']
        if q_id in aligned:
            continue
        q_clean = _clean_text(q.get('label', ''))
        for idx, a in enumerate(answers):
            if idx in claimed_answers:
                continue
            if q_clean and q_clean == _clean_text(a.get('label', '')):
                aligned[q_id] = a
                claimed_answers.add(idx)
                break

    # Pass 3: Substantive Word Overlap Match (minor phrasing edits to retained questions)
    for q in form_questions:
        q_id = q['id']
        if q_id in aligned:
            continue
        q_lbl = q.get('label', '')
        for idx, a in enumerate(answers):
            if idx in claimed_answers:
                continue
            if _labels_are_compatible(q_lbl, a.get('label', '')):
                aligned[q_id] = a
                claimed_answers.add(idx)
                break

    # Pass 4: Unanswered current questions (e.g. newly added questions)
    for q in form_questions:
        q_id = q['id']
        if q_id not in aligned:
            aligned[q_id] = None

    retired = [answers[idx] for idx in range(len(answers)) if idx not in claimed_answers]
    return aligned, retired


def _resolve_form_versions(form, responses):
    """Organize form definitions and responses into discrete versions.

    Returns:
      (sorted_versions, version_map)
      - sorted_versions: list of version dicts, sorted with current version first, then historical versions descending (e.g. v2, v1)
      - version_map: dict mapping version_num (int) -> version dict
    """
    raw_versions = form.get('versions') or []
    current_version_num = form.get('version') or (len(raw_versions) + 1 if raw_versions else 1)

    version_dict = {}

    # 1. Register historical versions from form['versions']
    for v in raw_versions:
        v_num = v.get('version', 1)
        version_dict[v_num] = {
            'version': v_num,
            'is_current': False,
            'title': v.get('title') or form.get('title'),
            'description': v.get('description') or form.get('description'),
            'questions': v.get('questions', []),
            'created_at': v.get('created_at'),
            'archived_at': v.get('archived_at'),
            'responses': [],
            'label': f"Version {v_num}"
        }

    # 2. Register current version
    current_created = form.get('updated_at') if raw_versions else form.get('created_at')
    version_dict[current_version_num] = {
        'version': current_version_num,
        'is_current': True,
        'title': form.get('title'),
        'description': form.get('description'),
        'questions': form.get('questions', []),
        'created_at': current_created,
        'archived_at': None,
        'responses': [],
        'label': f"Version {current_version_num} (Current)" if raw_versions or current_version_num > 1 else "Version 1 (Current)"
    }

    # 3. Detect legacy edits: if form['versions'] is empty, but we have responses
    # whose question IDs differ from current questions or were submitted before updated_at:
    if not raw_versions and responses:
        curr_qids = set(q['id'] for q in form.get('questions', []))
        legacy_responses = []
        for r in responses:
            r_qids = set(a.get('question_id') for a in r.get('answers', []) if a.get('question_id'))
            if (r_qids and not r_qids.issubset(curr_qids)) or (form.get('updated_at') and r.get('submitted_at') and r['submitted_at'] < form['updated_at']):
                legacy_responses.append(r)

        if legacy_responses:
            # Reconstruct Version 1 from the legacy response's questions
            v1_questions = []
            seen_qids = set()
            for r in legacy_responses:
                for a in r.get('answers', []):
                    qid = a.get('question_id')
                    if qid and qid not in seen_qids:
                        seen_qids.add(qid)
                        v1_questions.append({
                            'id': qid,
                            'label': a.get('label') or qid,
                            'type': a.get('type') or 'short_text',
                            'required': False,
                            'options': []
                        })

            version_dict[1] = {
                'version': 1,
                'is_current': False,
                'title': form.get('title'),
                'description': form.get('description'),
                'questions': v1_questions,
                'created_at': form.get('created_at'),
                'archived_at': form.get('updated_at'),
                'responses': [],
                'label': "Version 1 (Initial)"
            }
            version_dict[2] = {
                'version': 2,
                'is_current': True,
                'title': form.get('title'),
                'description': form.get('description'),
                'questions': form.get('questions', []),
                'created_at': form.get('updated_at'),
                'archived_at': None,
                'responses': [],
                'label': "Version 2 (Current)"
            }
            current_version_num = 2

    # 4. Map each response to its version
    for r in responses:
        target_v = None
        if r.get('form_version') and r['form_version'] in version_dict:
            target_v = r['form_version']
        else:
            r_qids = set(a.get('question_id') for a in r.get('answers', []) if a.get('question_id'))
            best_v = None
            best_overlap = -1
            for v_num, v_data in version_dict.items():
                v_qids = set(q['id'] for q in v_data.get('questions', []))
                overlap = len(r_qids & v_qids)
                if overlap > best_overlap:
                    best_overlap = overlap
                    best_v = v_num
            target_v = best_v or current_version_num

        r['form_version'] = target_v
        r['version_label'] = version_dict[target_v]['label']
        version_dict[target_v]['responses'].append(r)

    # 5. Check multi-submissions by same user across versions
    user_submissions = {}
    for r in responses:
        uid = r.get('submitter_id') or r.get('submitter_username') or r.get('submitter_ip_hash')
        if uid:
            user_submissions.setdefault(str(uid), []).append(r)

    for uid, u_resps in user_submissions.items():
        if len(u_resps) > 1:
            for r in u_resps:
                r['has_multiple_submissions'] = True
                r['other_submissions'] = [
                    {
                        'id': str(other['_id']),
                        'version': other.get('form_version'),
                        'version_label': other.get('version_label'),
                        'submitted_at_formatted': other.get('submitted_at_formatted')
                    }
                    for other in u_resps if str(other['_id']) != str(r['_id'])
                ]

    # 6. Set response count and formatted date
    for v_num, v_data in version_dict.items():
        v_data['response_count'] = len(v_data['responses'])
        if v_data.get('created_at'):
            ts = v_data['created_at']
            if ts.tzinfo is None: ts = ts.replace(tzinfo=datetime.timezone.utc)
            v_data['created_at_formatted'] = ts.strftime('%b %d, %Y')
        else:
            v_data['created_at_formatted'] = ''

    sorted_versions = sorted(
        version_dict.values(),
        key=lambda v: (0 if v['is_current'] else 1, -v['version'])
    )

    return sorted_versions, version_dict


# --- Owner views ---

@bp.route('/forms/<share_id>/responses')
@login_required
def form_responses_view(share_id):
    import main as m
    form = _decrypt_form_definition(m.forms_conf.find_one({'share_id': share_id}))
    if not form:
        flash('Form not found', 'danger')
        return redirect(url_for('forms.forms_list'))
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        flash('Not authorized', 'danger')
        return redirect(url_for('forms.forms_list'))

    # Load all responses for this form to properly resolve versions and counts
    all_responses = list(m.form_responses_conf.find({'form_id': form['_id']}).sort('submitted_at', -1))

    for r in all_responses:
        if '_id' in r:
            r['_id'] = str(r['_id'])
        if 'form_id' in r:
            r['form_id'] = str(r['form_id'])
        if 'user_id' in r:
            r['user_id'] = str(r['user_id'])
        for a in r.get('answers', []):
            try:
                a['value_plain'] = decrypt_form_response(a.get('value', ''), str(form['_id']))
            except Exception:
                a['value_plain'] = a.get('value', '')
        if r.get('submitted_at'):
            ts = r['submitted_at']
            if ts.tzinfo is None: ts = ts.replace(tzinfo=datetime.timezone.utc)
            r['submitted_at_iso'] = ts.isoformat().replace('+00:00', 'Z')
            r['submitted_at_formatted'] = ts.strftime('%b %d, %Y, %I:%M %p')
        else:
            r['submitted_at_formatted'] = '—'

    versions_list, version_map = _resolve_form_versions(form, all_responses)

    selected_version_arg = (request.args.get('version') or '').strip()
    if selected_version_arg == 'all':
        selected_version = 'all'
        target_responses = all_responses
        display_questions = form.get('questions', [])
    elif selected_version_arg.isdigit() and int(selected_version_arg) in version_map:
        selected_version = int(selected_version_arg)
        v_data = version_map[selected_version]
        target_responses = v_data['responses']
        display_questions = v_data['questions']
    else:
        # Default version: current if it has responses, else latest version that has responses
        current_v = next((v for v in versions_list if v['is_current']), versions_list[0])
        if current_v['response_count'] > 0:
            selected_version = current_v['version']
            target_responses = current_v['responses']
            display_questions = current_v['questions']
        else:
            v_with_resps = next((v for v in versions_list if v['response_count'] > 0), None)
            if v_with_resps:
                selected_version = v_with_resps['version']
                target_responses = v_with_resps['responses']
                display_questions = v_with_resps['questions']
            else:
                selected_version = current_v['version']
                target_responses = current_v['responses']
                display_questions = current_v['questions']

    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 20
    total = len(target_responses)
    start_idx = (page - 1) * per_page
    paginated_responses = target_responses[start_idx : start_idx + per_page]

    # Map answers to display_questions
    for r in paginated_responses:
        ans_map = {a.get('question_id'): a for a in r.get('answers', [])}
        r['aligned_answers'] = {q['id']: ans_map.get(q['id']) for q in display_questions}

    raw_responses = []
    for r in paginated_responses:
        raw_responses.append({
            'submitter_username': r.get('submitter_username'),
            'submitted_at_formatted': r.get('submitted_at_formatted'),
            'submitted_at_iso': r.get('submitted_at_iso'),
            'version_label': r.get('version_label'),
            'has_multiple_submissions': r.get('has_multiple_submissions', False),
            'other_submissions': r.get('other_submissions', []),
            'answers': [
                {
                    'label': a.get('label') or 'Question',
                    'value_plain': a.get('value_plain', '')
                }
                for a in r.get('answers', [])
            ]
        })

    # Stats for charts
    stats = {}
    if target_responses:
        for q in display_questions:
            qtype = q.get('type')
            if qtype == 'single_choice':
                counts = {o: 0 for o in q.get('options', [])}
                total_q = 0
                for r in target_responses:
                    ans_map = {a.get('question_id'): a for a in r.get('answers', [])}
                    matched_a = ans_map.get(q['id'])
                    if matched_a:
                        v = matched_a.get('value_plain', '')
                        if v in counts:
                            counts[v] += 1
                            total_q += 1
                stats[q['id']] = {'type': 'single_choice', 'label': q.get('label', ''), 'counts': counts, 'total': total_q}
            elif qtype == 'rating':
                vals = []
                for r in target_responses:
                    ans_map = {a.get('question_id'): a for a in r.get('answers', [])}
                    matched_a = ans_map.get(q['id'])
                    if matched_a:
                        v = matched_a.get('value_plain', '')
                        try: vals.append(int(v))
                        except Exception: pass
                avg = round(sum(vals)/len(vals), 2) if vals else None
                stats[q['id']] = {'type': 'rating', 'label': q['label'], 'avg': avg, 'count': len(vals), 'distribution': {str(i): vals.count(i) for i in range(1, 6)}}

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template(
        'form_responses.html',
        form=form,
        versions_list=versions_list,
        selected_version=selected_version,
        display_questions=display_questions,
        responses=paginated_responses,
        raw_responses=raw_responses,
        total=total,
        total_all_versions=len(all_responses),
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        stats=stats
    )


@bp.route('/forms/<share_id>/responses/export')
@login_required
def form_responses_export(share_id):
    import main as m
    import csv, io
    form = _decrypt_form_definition(m.forms_conf.find_one({'share_id': share_id}))
    if not form:
        return jsonify({'error': 'Form not found'}), 404
    if str(form['owner_id']) != str(current_user.id) and not getattr(current_user, 'is_admin', False):
        return jsonify({'error': 'Not authorized'}), 403
    fmt = (request.args.get('format') or 'csv').lower()
    all_responses = list(m.form_responses_conf.find({'form_id': form['_id']}).sort('submitted_at', -1))

    # Decrypt all
    for r in all_responses:
        for a in r.get('answers', []):
            try:
                a['value_plain'] = decrypt_form_response(a.get('value', ''), str(form['_id']))
            except Exception:
                a['value_plain'] = a.get('value', '')

    versions_list, version_map = _resolve_form_versions(form, all_responses)
    version_arg = (request.args.get('version') or '').strip()

    if version_arg.isdigit() and int(version_arg) in version_map:
        target_v = version_map[int(version_arg)]
        export_responses = target_v['responses']
        export_questions = target_v['questions']
        is_single_version = True
    else:
        export_responses = all_responses
        export_questions = form.get('questions', [])
        is_single_version = False

    if fmt == 'json':
        out = []
        for r in export_responses:
            ts = r.get('submitted_at')
            if ts and ts.tzinfo is None: ts = ts.replace(tzinfo=datetime.timezone.utc)
            row = {
                'submitted_at': ts.isoformat().replace('+00:00', 'Z') if ts else None,
                'respondent': r.get('submitter_username') or 'Anonymous',
                'is_authenticated': bool(r.get('is_authenticated')),
                'form_version': r.get('form_version'),
                'version_label': r.get('version_label'),
            }
            ans_map = {a.get('question_id'): a.get('value_plain', '') for a in r.get('answers', [])}
            for q in export_questions:
                row[q['label']] = ans_map.get(q['id'])
            out.append(row)
        return jsonify({'form': {'title': form['title'], 'share_id': share_id}, 'count': len(out), 'responses': out})

    # CSV export
    output = io.StringIO()
    w = csv.writer(output)
    q_labels = [q['label'] for q in export_questions]
    if is_single_version:
        headers = ['submitted_at', 'respondent'] + q_labels
    else:
        headers = ['submitted_at', 'respondent', 'version'] + q_labels
    w.writerow(headers)

    for r in export_responses:
        ts = r.get('submitted_at')
        if ts and ts.tzinfo is None: ts = ts.replace(tzinfo=datetime.timezone.utc)
        sub_str = ts.strftime('%Y-%m-%d %H:%M:%S UTC') if ts else ''
        resp_str = r.get('submitter_username') or 'Anonymous'
        ans_map = {a.get('question_id'): a.get('value_plain', '') for a in r.get('answers', [])}
        if is_single_version:
            row = [sub_str, resp_str]
        else:
            row = [sub_str, resp_str, r.get('version_label') or f"v{r.get('form_version', 1)}"]
        for q in export_questions:
            row.append(ans_map.get(q['id'], ''))
        w.writerow(row)

    csv_data = output.getvalue()
    resp = make_response(csv_data)
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f"attachment; filename=form_{share_id}_responses.csv"
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
