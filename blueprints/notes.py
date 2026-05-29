from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, math, hashlib, secrets
from security import limits

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('', __name__, template_folder='templates')


@bp.route('/personal_space')
@login_required
def personal_space():
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    try:
        notes_page = max(1, int(request.args.get('notes_page', 1)))
    except ValueError:
        notes_page = 1
    try:
        saved_page = max(1, int(request.args.get('saved_page', 1)))
    except ValueError:
        saved_page = 1
    per_page = 10
    saved_post_ids = user.get('saved_posts', [])
    saved_posts = []
    total_saved = len(saved_post_ids)
    if saved_post_ids:
        saved_post_ids = list(reversed(saved_post_ids))
        skip_saved = (saved_page - 1) * per_page
        paginated_saved_ids = saved_post_ids[skip_saved: skip_saved + per_page]
        posts_map = {post['_id']: post for post in m.posts_conf.find({'_id': {'$in': paginated_saved_ids}})}
        ordered_posts = [posts_map[pid] for pid in paginated_saved_ids if pid in posts_map]
        with current_app.app_context():
            saved_posts = m.prepare_posts(ordered_posts)
    total_notes_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'is_locked': {'$ne': True}})
    skip_notes = (notes_page - 1) * per_page
    personal_posts_raw = list(m.personal_posts_conf.aggregate([
        {'$match': {'user_id': ObjectId(current_user.id), 'is_locked': {'$ne': True}}},
        {'$lookup': {'from': 'personal_posts', 'localField': 'source_note_id', 'foreignField': '_id', 'as': 'original'}},
        {'$addFields': {'original_doc': {'$arrayElemAt': ['$original', 0]}}},
        {'$lookup': {'from': 'users', 'localField': 'original_doc.user_id', 'foreignField': '_id', 'as': 'original_user'}},
        {'$addFields': {'original_user_doc': {'$arrayElemAt': ['$original_user', 0]}}},
        {'$addFields': {'_sort_ts': {'$cond': {'if': {'$gt': ['$original_doc', None]}, 'then': {'$max': [{'$ifNull': ['$updated_at', '$created_at']}, {'$ifNull': ['$original_doc.updated_at', '$original_doc.created_at']}]}, 'else': {'$ifNull': ['$updated_at', '$created_at']}}}}},
        {'$sort': {'_sort_ts': -1, 'created_at': -1}},
        {'$skip': skip_notes},
        {'$limit': per_page}
    ]))
    personal_posts = []
    for note in personal_posts_raw:
        note['content'] = m._decrypt_note_record(note)
        note['update_available'] = False
        if note.get('source_note_id') and note.get('original_doc'):
            orig = note['original_doc']
            orig_ts = orig.get('updated_at') or orig.get('created_at')
            clone_ts = note.get('updated_at') or note.get('created_at')
            if orig_ts and clone_ts:
                if orig_ts.tzinfo is None:
                    orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                if clone_ts.tzinfo is None:
                    clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                if orig_ts > clone_ts:
                    try:
                        orig_decrypted = m._decrypt_note_record(orig)
                        if note['content'] != orig_decrypted:
                            note['update_available'] = True
                    except Exception:
                        note['update_available'] = True
        personal_posts.append(note)
    has_app_lock = bool(user.get('app_lock_pin_hash'))
    unlock_ts = session.get('app_lock_unlocked_at')
    is_unlocked = False
    if unlock_ts and has_app_lock:
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
        if elapsed < 300:
            is_unlocked = True
        else:
            session.pop('app_lock_unlocked_at', None)
    locked_notes_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'is_locked': True})
    locked_notes = []
    locked_shares_map = {}
    locked_clones_map = {}
    if is_unlocked and locked_notes_count > 0:
        locked_notes_raw = list(m.personal_posts_conf.aggregate([
            {'$match': {'user_id': ObjectId(current_user.id), 'is_locked': True}},
            {'$lookup': {'from': 'personal_posts', 'localField': 'source_note_id', 'foreignField': '_id', 'as': 'original'}},
            {'$addFields': {'original_doc': {'$arrayElemAt': ['$original', 0]}}},
            {'$lookup': {'from': 'users', 'localField': 'original_doc.user_id', 'foreignField': '_id', 'as': 'original_user'}},
            {'$addFields': {'original_user_doc': {'$arrayElemAt': ['$original_user', 0]}}},
            {'$addFields': {'_sort_ts': {'$cond': {'if': {'$gt': ['$original_doc', None]}, 'then': {'$max': [{'$ifNull': ['$updated_at', '$created_at']}, {'$ifNull': ['$original_doc.updated_at', '$original_doc.created_at']}]}, 'else': {'$ifNull': ['$updated_at', '$created_at']}}}}},
            {'$sort': {'_sort_ts': -1, 'created_at': -1}},
            {'$limit': 50}
        ]))
        for note_opts in locked_notes_raw:
            note_opts['content'] = m._decrypt_note_record(note_opts)
            note_opts['update_available'] = False
            if note_opts.get('source_note_id') and note_opts.get('original_doc'):
                orig = note_opts['original_doc']
                orig_ts = orig.get('updated_at') or orig.get('created_at')
                clone_ts = note_opts.get('updated_at') or note_opts.get('created_at')
                if orig_ts and clone_ts:
                    if orig_ts.tzinfo is None:
                        orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                    if clone_ts.tzinfo is None:
                        clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                    if orig_ts > clone_ts:
                        try:
                            orig_decrypted = m._decrypt_note_record(orig)
                            if note_opts['content'] != orig_decrypted:
                                note_opts['update_available'] = True
                        except Exception:
                            note_opts['update_available'] = True
            locked_notes.append(note_opts)
        locked_note_ids = [n['_id'] for n in locked_notes]
        if locked_note_ids:
            now_l = datetime.datetime.now(datetime.timezone.utc)
            for share in m.note_shares_conf.find({'owner_id': ObjectId(current_user.id), 'note_id': {'$in': locked_note_ids}}).sort('created_at', -1):
                if share.get('expires_at'):
                    exp = share['expires_at']
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=datetime.timezone.utc)
                    if now_l > exp:
                        continue
                nid = str(share['note_id'])
                if nid not in locked_shares_map:
                    locked_shares_map[nid] = []
                locked_shares_map[nid].append({'share_id': share['share_id'], 'share_url': url_for('view_shared_note', share_id=share['share_id'], _external=True), 'permissions': share.get('permissions', 'view'), 'surprise_theme': share.get('surprise_theme', 'none'), 'created_at': share.get('created_at')})
            for doc in m.personal_posts_conf.aggregate([
                {'$match': {'source_note_id': {'$in': locked_note_ids}, 'user_id': {'$ne': ObjectId(current_user.id)}}},
                {'$group': {'_id': '$source_note_id', 'count': {'$sum': 1}}}
            ]):
                locked_clones_map[str(doc['_id'])] = doc['count']
    now = datetime.datetime.now(datetime.timezone.utc)
    note_ids = [note['_id'] for note in personal_posts]
    active_shares_map = {}
    if note_ids:
        active_shares_raw = list(m.note_shares_conf.find({'owner_id': ObjectId(current_user.id), 'note_id': {'$in': note_ids}}).sort('created_at', -1))
        for share in active_shares_raw:
            if share.get('expires_at'):
                exp = share['expires_at']
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                if now > exp:
                    continue
            nid = str(share['note_id'])
            if nid not in active_shares_map:
                active_shares_map[nid] = []
            active_shares_map[nid].append({'share_id': share['share_id'], 'share_url': url_for('view_shared_note', share_id=share['share_id'], _external=True), 'permissions': share.get('permissions', 'view'), 'surprise_theme': share.get('surprise_theme', 'none'), 'created_at': share.get('created_at')})
    page_title = "My Personal Space"
    page_description = "Your private collection of saved posts and personal notes."
    has_clones_map = {}
    if note_ids:
        clone_pipeline = [
            {'$match': {'source_note_id': {'$in': note_ids}, 'user_id': {'$ne': ObjectId(current_user.id)}}},
            {'$group': {'_id': '$source_note_id', 'count': {'$sum': 1}}}
        ]
        for doc in m.personal_posts_conf.aggregate(clone_pipeline):
            has_clones_map[str(doc['_id'])] = doc['count']
    total_notes_pages = math.ceil(total_notes_count / per_page) if per_page else 0
    total_saved_pages = math.ceil(total_saved / per_page) if per_page else 0
    show_icon_labels = (total_notes_count + locked_notes_count) < 5
    activity_raw = list(m.note_versions_conf.find({'content_owner_id': ObjectId(current_user.id), 'is_read_by_owner': False}).sort('created_at', -1))
    activity_notifications = []
    for item in activity_raw:
        if item.get('event_type') == 'proposal':
            candidates = m._candidate_user_ids(item.get('content_owner_id'), item.get('editor_id'), current_user.id)
            item['proposed_content_plain'] = m._decrypt_with_candidate_ids(item.get('proposed_content', ''), candidates) or '[Content unavailable]'
        note_info = m.personal_posts_conf.find_one({'_id': item['note_id']}, {'created_at': 1})
        item['original_note_date'] = note_info.get('created_at') if note_info else None
        activity_notifications.append(item)
    pending_proposals_list = [a for a in activity_notifications if a.get('event_type') == 'proposal' and a.get('status') == 'pending']
    pending_proposals_map = {}
    for p in pending_proposals_list:
        nid = str(p.get('note_id', ''))
        if nid:
            if nid not in pending_proposals_map:
                pending_proposals_map[nid] = []
            pending_proposals_map[nid].append(p)
    return render_template('personal_space.html', saved_posts=saved_posts, personal_posts=personal_posts, active_shares_map=active_shares_map, has_clones_map=has_clones_map, active_page='personal_space', title=page_title, description=page_description, notes_page=notes_page, saved_page=saved_page, total_notes_pages=total_notes_pages, total_saved_pages=total_saved_pages, total_notes_count=total_notes_count, total_saved=total_saved, has_app_lock=has_app_lock, is_unlocked=is_unlocked, locked_notes=locked_notes, locked_notes_count=locked_notes_count, locked_shares_map=locked_shares_map, locked_clones_map=locked_clones_map, show_icon_labels=show_icon_labels, activity_notifications=activity_notifications, pending_proposals=pending_proposals_list, reviewed_proposals=[a for a in activity_notifications if a.get('event_type') == 'proposal' and a.get('status') in ('accepted', 'rejected')], auto_approved_activity=[{**a, 'has_active_auto_approve': m._has_active_auto_approve(a.get('share_id'), a.get('editor_id'))} for a in activity_notifications if a.get('event_type') == 'snapshot' and a.get('is_auto_approved')], pending_proposals_map=pending_proposals_map)


@bp.route('/api/activity/mark_read', methods=['POST'])
@login_required
@csrf_exempt
def api_mark_activity_read():
    import main as m
    try:
        result = m.note_versions_conf.update_many(
            {'content_owner_id': ObjectId(current_user.id), 'is_read_by_owner': False},
            {'$set': {'is_read_by_owner': True}}
        )
        m.note_versions_conf.update_many(
            {'content_owner_id': ObjectId(current_user.id), 'is_read_by_owner': {'$exists': False}},
            {'$set': {'is_read_by_owner': True}}
        )
        return jsonify({'success': True, 'marked_read': result.modified_count})
    except Exception as e:
        current_app.logger.error(f"Failed to mark activity read: {e}")
        return jsonify({'error': 'Failed to mark activity as read'}), 500


@bp.route('/personal_post/create', methods=['POST'])
@login_required
def create_personal_post():
    import main as m
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if not content:
        flash('Content is required.', 'danger')
        return redirect(url_for('personal_space'))
    encrypted = m.encrypt_note(content)
    note_data = {
        'user_id': ObjectId(current_user.id),
        'title': title or None,
        'content': encrypted,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc),
        'is_locked': False,
    }
    result = m.personal_posts_conf.insert_one(note_data)
    m.index_note_to_typesense(str(result.inserted_id))
    return redirect(url_for('personal_space'))


@bp.route('/personal_post/create_json', methods=['POST'])
@login_required
def create_personal_post_json():
    import main as m
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content is required'}), 400
    encrypted = m.encrypt_note(content)
    result = m.personal_posts_conf.insert_one({
        'user_id': ObjectId(current_user.id),
        'title': title or None,
        'content': encrypted,
        'created_at': datetime.datetime.now(datetime.timezone.utc),
        'updated_at': datetime.datetime.now(datetime.timezone.utc),
        'is_locked': False,
    })
    m.index_note_to_typesense(str(result.inserted_id))
    return jsonify({'success': True, 'note_id': str(result.inserted_id)})


@bp.route('/personal_post/search')
@login_required
def search_personal_notes():
    import main as m
    query = request.args.get('q', '').strip()
    if not query:
        return render_template('personal_search.html', query='', results=[])
    results = []
    if m.redis_cache:
        try:
            user_id_str = str(current_user.id)
            all_notes = list(m.personal_posts_conf.find({'user_id': ObjectId(current_user.id), 'is_locked': {'$ne': True}}))
            for note in all_notes:
                decrypted = m._decrypt_note_record(note)
                note_title = note.get('title') or ''
                if query.lower() in decrypted.lower() or query.lower() in note_title.lower():
                    results.append({'_id': note['_id'], 'title': note_title, 'content': decrypted[:300], 'updated_at': note.get('updated_at') or note.get('created_at')})
        except Exception as e:
            current_app.logger.error(f"Personal note search error: {e}")
    return render_template('personal_search.html', query=query, results=results)


@bp.route('/personal_post/reindex_notes', methods=['POST'])
@login_required
def reindex_my_notes():
    import main as m
    try:
        count = m.reindex_user_notes_to_typesense(str(current_user.id))
        return jsonify({'success': True, 'message': f'Reindexed {count} notes'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/merge/ai', methods=['POST'])
@login_required
def merge_conflict_ai():
    import main as m
    data = request.get_json() or {}
    local_text = data.get('local', '')
    remote_text = data.get('remote', '')
    if not local_text or not remote_text:
        return jsonify({'error': 'Both local and remote text required'}), 400
    try:
        api_key = m.get_env_variable('JIGSAW_API_KEY')
        prompt = f"Merge these two versions of a note, preserving all important content from both:\n\n--- Local version ---\n{local_text}\n\n--- Remote version ---\n{remote_text}\n\n--- Merged result ---"
        resp = requests.post('https://api.jigsawstack.com/v1/llm', json={'prompt': prompt, 'max_tokens': 2000}, headers={'x-api-key': api_key}, timeout=30)
        if resp.status_code == 200:
            merged = resp.json().get('response', '').strip()
            if merged:
                return jsonify({'merged': merged, 'method': 'ai'})
    except Exception as e:
        current_app.logger.warning(f"AI merge failed, falling back: {e}")
    merged = m.build_unified_diff_text(local_text, remote_text)
    return jsonify({'merged': merged, 'method': 'diff'})


@bp.route('/personal_post/edit/<post_id>', methods=['POST'])
@login_required
def edit_personal_post(post_id):
    import main as m
    note = m.personal_posts_conf.find_one({'_id': ObjectId(post_id), 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    if not content:
        flash('Content is required.', 'danger')
        return redirect(url_for('personal_space'))
    encrypted = m.encrypt_note(content)
    m.personal_posts_conf.update_one(
        {'_id': ObjectId(post_id)},
        {'$set': {'title': title or None, 'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc)}}
    )
    m.index_note_to_typesense(post_id)
    flash('Note updated.', 'success')
    return redirect(url_for('personal_space'))


@bp.route('/personal_post/sync/<post_id>', methods=['POST'])
@login_required
def sync_personal_post(post_id):
    import main as m
    data = request.get_json() or {}
    local_content = data.get('content', '')
    local_version = data.get('version', 0)
    note = m.personal_posts_conf.find_one({'_id': ObjectId(post_id), 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    remote_content = m._decrypt_note_record(note)
    remote_version = note.get('version', 0)
    if local_content == remote_content:
        return jsonify({'status': 'identical', 'content': remote_content, 'version': remote_version})
    if local_version >= remote_version:
        encrypted = m.encrypt_note(local_content)
        m.personal_posts_conf.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {'content': encrypted, 'updated_at': datetime.datetime.now(datetime.timezone.utc), 'version': local_version + 1}}
        )
        m.index_note_to_typesense(post_id)
        return jsonify({'status': 'saved', 'content': local_content, 'version': local_version + 1})
    else:
        merged = m.build_merge_preview_text(remote_content, local_content)
        conflict = (local_content != remote_content)
        return jsonify({'status': 'conflict' if conflict else 'remote_newer', 'remote_content': remote_content, 'remote_version': remote_version, 'local_content': local_content, 'local_version': local_version, 'merged_preview': merged})


@bp.route('/personal_post/delete/<post_id>', methods=['POST'])
@login_required
def delete_personal_post(post_id):
    import main as m
    note = m.personal_posts_conf.find_one({'_id': ObjectId(post_id), 'user_id': ObjectId(current_user.id)})
    if not note:
        flash('Note not found.', 'danger')
        return redirect(url_for('personal_space'))
    m.personal_posts_conf.delete_one({'_id': ObjectId(post_id)})
    m.note_shares_conf.delete_many({'note_id': ObjectId(post_id)})
    m.note_versions_conf.delete_many({'note_id': ObjectId(post_id)})
    m.note_discussions_conf.delete_many({'note_id': ObjectId(post_id)})
    m.remove_note_from_typesense(post_id)
    flash('Note deleted.', 'success')
    return redirect(url_for('personal_space'))


@bp.route('/personal_post/toggle_lock/<post_id>', methods=['POST'])
@login_required
def toggle_note_lock(post_id):
    import main as m
    note = m.personal_posts_conf.find_one({'_id': ObjectId(post_id), 'user_id': ObjectId(current_user.id)})
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    new_locked = not note.get('is_locked', False)
    m.personal_posts_conf.update_one({'_id': ObjectId(post_id)}, {'$set': {'is_locked': new_locked}})
    return jsonify({'success': True, 'is_locked': new_locked})


@bp.route('/api/app_lock/setup', methods=['POST'])
@login_required
def app_lock_setup():
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()
    if not pin or not pin.isdigit() or len(pin) < 4:
        return jsonify({'error': 'PIN must be at least 4 digits'}), 400
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'app_lock_pin_hash': pin_hash}})
    session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
    return jsonify({'success': True})


@bp.route('/api/app_lock/verify', methods=['POST'])
@login_required
def app_lock_verify():
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'App lock not configured'}), 400
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    if pin_hash != user['app_lock_pin_hash']:
        return jsonify({'error': 'Incorrect PIN'}), 403
    session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
    return jsonify({'success': True})


@bp.route('/api/app_lock/remove', methods=['POST'])
@login_required
def app_lock_remove():
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'App lock not configured'}), 400
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    if pin_hash != user['app_lock_pin_hash']:
        return jsonify({'error': 'Incorrect PIN'}), 403
    m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$unset': {'app_lock_pin_hash': ''}})
    session.pop('app_lock_unlocked_at', None)
    return jsonify({'success': True})


@bp.route('/api/app_lock/relock', methods=['POST'])
@login_required
def app_lock_relock():
    session.pop('app_lock_unlocked_at', None)
    return jsonify({'success': True})


@bp.route('/api/app_lock/check_status')
@login_required
def app_lock_check_status():
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'app_lock_pin_hash': 1})
    has_lock = bool(user and user.get('app_lock_pin_hash'))
    unlock_ts = session.get('app_lock_unlocked_at')
    is_unlocked = False
    if unlock_ts and has_lock:
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
        if elapsed < 300:
            is_unlocked = True
        else:
            session.pop('app_lock_unlocked_at', None)
    return jsonify({'has_lock': has_lock, 'is_unlocked': is_unlocked})


@bp.route('/api/ai/suggest-tags', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_suggest_tags():
    import main as m
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    if not title and not content:
        return jsonify({'tags': []})
    clean_text = f"{title}\n\n{content[:800]}"
    try:
        api_key = m.get_env_variable('JIGSAW_API_KEY')
        batch1 = m.PREDEFINED_TAGS[:18]
        batch2 = m.PREDEFINED_TAGS[18:]
        all_tags = []
        for batch in [batch1, batch2]:
            api_response = requests.post(
                'https://api.jigsawstack.com/v1/classification',
                json={'dataset': [{'type': 'text', 'value': clean_text}], 'labels': [{'type': 'text', 'value': t} for t in batch], 'multiple_labels': True},
                headers={'x-api-key': api_key},
                timeout=10,
            )
            if api_response.status_code == 200:
                result = api_response.json()
                predictions = result.get('predictions', [])
                batch_tags = []
                if predictions and isinstance(predictions[0], list):
                    batch_tags = predictions[0]
                elif predictions and isinstance(predictions[0], str):
                    batch_tags = predictions
                for item in batch_tags:
                    if isinstance(item, dict) and 'label' in item:
                        all_tags.append(item['label'])
                    elif isinstance(item, str):
                        all_tags.append(item)
        unique_tags = []
        for tag in all_tags:
            if tag and tag not in unique_tags and tag in m.PREDEFINED_TAGS:
                unique_tags.append(tag)
        if unique_tags:
            return jsonify({'tags': unique_tags[:4]})
    except Exception as e:
        current_app.logger.warning(f'JigsawStack classify failed, falling back to NLP: {e}')
    tags = m._nlp_suggest_tags(clean_text)
    return jsonify({'tags': tags})


@bp.route('/api/users/suggest')
@login_required
def api_user_suggest():
    import main as m
    query = request.args.get('q', '').strip()
    exclude_username = request.args.get('exclude', '').strip()
    if len(query) < 1:
        return jsonify({'suggestions': []})
    safe_query = m.re.escape(query)
    filter_query = {'username': {'$regex': f'^{safe_query}', '$options': 'i'}}
    cursor = m.users_conf.find(filter_query, {'password': 0, 'email': 0, 'notification_preference': 0, 'last_active': 0}).sort('username', 1).limit(6)
    suggestions = []
    for candidate in cursor:
        if exclude_username and candidate.get('username') == exclude_username:
            continue
        suggestions.append({
            'username': candidate.get('username'),
            'bio': candidate.get('bio', ''),
            'profile_image_url': candidate.get('profile_image_url') or url_for('static', filename='default_avatar.png'),
            'profile_url': url_for('profile', username=candidate.get('username')),
        })
    return jsonify({'suggestions': suggestions})
