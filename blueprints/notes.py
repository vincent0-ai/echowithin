from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
import datetime, math, hashlib, secrets, requests
from security import limits
from config import get_env_variable

def csrf_exempt(view):
    """Mark view as exempt from CSRF protection."""
    view._csrf_exempt = True
    return view

bp = Blueprint('notes', __name__, template_folder='templates')


@bp.route('/personal_space')
@login_required
def personal_space():
    """Renders the user's personal space with saved posts and personal notes."""
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})

    # Pagination parameters
    try:
        notes_page = max(1, int(request.args.get('notes_page', 1)))
    except ValueError:
        notes_page = 1
        
    try:
        saved_page = max(1, int(request.args.get('saved_page', 1)))
    except ValueError:
        saved_page = 1

    per_page = 10

    # Fetch saved posts
    saved_post_ids = user.get('saved_posts', [])
    saved_posts = []
    total_saved = len(saved_post_ids)
    
    if saved_post_ids:
        saved_post_ids = list(reversed(saved_post_ids))
        skip_saved = (saved_page - 1) * per_page
        paginated_saved_ids = saved_post_ids[skip_saved : skip_saved + per_page]
        
        posts_map = {post['_id']: post for post in m.posts_conf.find({'_id': {'$in': paginated_saved_ids}})}
        ordered_posts = [posts_map[pid] for pid in paginated_saved_ids if pid in posts_map]
        
        with current_app.app_context():
            saved_posts = m.prepare_posts(ordered_posts)

    # Fetch personal posts (notes) - Paginated! Exclude locked notes from the main list.
    total_notes_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'is_locked': {'$ne': True}})
    skip_notes = (notes_page - 1) * per_page

    # OPTIMIZATION: Use projection to only fetch needed fields (exclude heavy 'content' field)
    personal_posts_raw = list(m.personal_posts_conf.aggregate([
        {'$match': {'user_id': ObjectId(current_user.id), 'is_locked': {'$ne': True}}},
        {'$project': {
            'content': 1,
            'encrypted': 1,
            'user_id': 1,
            'content_owner_id': 1,
            'owner_id': 1,
            'source_owner_id': 1,
            'saved_from_owner_id': 1,
            'source_note_id': 1,
            'source_share_id': 1,
            'reference': 1,
            'tags': 1,
            'created_at': 1,
            'updated_at': 1,
            'is_locked': 1
        }},
        {'$lookup': {
            'from': 'personal_posts',
            'let': {'source_note_id': '$source_note_id'},
            'pipeline': [
                {'$match': {'$expr': {'$eq': ['$_id', '$$source_note_id']}}},
                {'$project': {
                    'content': 1,
                    'user_id': 1,
                    'content_owner_id': 1,
                    'created_at': 1,
                    'updated_at': 1
                }}
            ],
            'as': 'original'
        }},
        {'$addFields': {
            'original_doc': {'$arrayElemAt': ['$original', 0]}
        }},
        {'$lookup': {
            'from': 'users',
            'localField': 'original_doc.user_id',
            'foreignField': '_id',
            'as': 'original_user'
        }},
        {'$addFields': {
            'original_user_doc': {'$arrayElemAt': ['$original_user', 0]}
        }},
        {'$addFields': {
            '_sort_ts': {
                '$cond': {
                    'if': {'$gt': ['$original_doc', None]},
                    'then': {
                        '$max': [
                            {'$ifNull': ['$updated_at', '$created_at']},
                            {'$ifNull': ['$original_doc.updated_at', '$original_doc.created_at']}
                        ]
                    },
                    'else': {'$ifNull': ['$updated_at', '$created_at']}
                }
            }
        }},
        {'$sort': {'_sort_ts': -1, 'created_at': -1}},
        {'$skip': skip_notes},
        {'$limit': per_page}
    ]))
    personal_posts = []
    for note in personal_posts_raw:
        # OPTIMIZATION: Defer decryption to the client via lazy-loading.
        # Use the reference field if available; otherwise set content to empty
        # and let JS fetch the preview via /api/v1/notes/previews after page load.
        ref = (note.get('reference') or '').strip()
        if ref:
            note['content'] = ref
            note['content_preview'] = True
            note['lazy_content'] = False
        else:
            note['content'] = ''
            note['content_preview'] = True
            note['lazy_content'] = True  # Flag: JS will fetch this note's preview

        # Determine if an update is available on the original note
        note['update_available'] = False
        if note.get('source_note_id') and note.get('original_doc'):
            orig = note['original_doc']
            orig_ts = orig.get('updated_at') or orig.get('created_at')
            clone_ts = note.get('updated_at') or note.get('created_at')
            if orig_ts and clone_ts:
                if hasattr(orig_ts, 'tzinfo') and orig_ts.tzinfo is None:
                    orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                if hasattr(clone_ts, 'tzinfo') and clone_ts.tzinfo is None:
                    clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                if orig_ts > clone_ts:
                    # Timestamp says original is newer — verify content is actually different
                    try:
                        clone_decrypted = m._decrypt_note_record(note)
                        orig_decrypted = m._decrypt_note_record(orig)
                        if clone_decrypted != orig_decrypted:
                            note['update_available'] = True
                        else:
                            # Content is the same but timestamps drifted — fix silently
                            m.personal_posts_conf.update_one(
                                {'_id': note['_id']},
                                {'$set': {'updated_at': orig_ts}}
                            )
                    except Exception:
                        note['update_available'] = True
        personal_posts.append(note)

    # --- Locked Notes ---
    has_app_lock = bool(user.get('app_lock_pin_hash'))
    # Check if unlocked AND not expired (5-minute window)
    unlock_ts = session.get('app_lock_unlocked_at')
    is_unlocked = False
    if unlock_ts and has_app_lock:
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
        if elapsed < 300:  # 5-minute unlock window
            is_unlocked = True
        else:
            # Auto-expire: clear stale unlock
            session.pop('app_lock_unlocked_at', None)
    locked_notes_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id), 'is_locked': True})
    locked_notes = []
    locked_shares_map = {}
    locked_clones_map = {}
    if is_unlocked and locked_notes_count > 0:
        locked_notes_raw = list(m.personal_posts_conf.aggregate([
            {'$match': {'user_id': ObjectId(current_user.id), 'is_locked': True}},
            {'$lookup': {
                'from': 'personal_posts',
                'localField': 'source_note_id',
                'foreignField': '_id',
                'as': 'original'
            }},
            {'$addFields': {
                'original_doc': {'$arrayElemAt': ['$original', 0]}
            }},
            {'$lookup': {
                'from': 'users',
                'localField': 'original_doc.user_id',
                'foreignField': '_id',
                'as': 'original_user'
            }},
            {'$addFields': {
                'original_user_doc': {'$arrayElemAt': ['$original_user', 0]}
            }},
            {'$addFields': {
                '_sort_ts': {
                    '$cond': {
                        'if': {'$gt': ['$original_doc', None]},
                        'then': {
                            '$max': [
                                {'$ifNull': ['$updated_at', '$created_at']},
                                {'$ifNull': ['$original_doc.updated_at', '$original_doc.created_at']}
                            ]
                        },
                        'else': {'$ifNull': ['$updated_at', '$created_at']}
                    }
                }
            }},
            {'$sort': {'_sort_ts': -1, 'created_at': -1}},
            {'$limit': 50}
        ]))
        for note in locked_notes_raw:
            # OPTIMIZATION: Use reference field when available to skip decryption
            ref = (note.get('reference') or '').strip()
            if ref:
                note['content'] = ref
            else:
                note['content'] = m._decrypt_note_record(note)
            note['update_available'] = False
            if note.get('source_note_id') and note.get('original_doc'):
                orig = note['original_doc']
                orig_ts = orig.get('updated_at') or orig.get('created_at')
                clone_ts = note.get('updated_at') or note.get('created_at')
                if orig_ts and clone_ts:
                    if hasattr(orig_ts, 'tzinfo') and orig_ts.tzinfo is None:
                        orig_ts = orig_ts.replace(tzinfo=datetime.timezone.utc)
                    if hasattr(clone_ts, 'tzinfo') and clone_ts.tzinfo is None:
                        clone_ts = clone_ts.replace(tzinfo=datetime.timezone.utc)
                    if orig_ts > clone_ts:
                        try:
                            clone_decrypted = m._decrypt_note_record(note)
                            orig_decrypted = m._decrypt_note_record(orig)
                            if clone_decrypted != orig_decrypted:
                                note['update_available'] = True
                            else:
                                m.personal_posts_conf.update_one(
                                    {'_id': note['_id']},
                                    {'$set': {'updated_at': orig_ts}}
                                )
                        except Exception:
                            note['update_available'] = True
            locked_notes.append(note)
        # Fetch shares for locked notes
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
                locked_shares_map[nid].append({
                    'share_id': share['share_id'],
                    'share_url': url_for('sharing.view_shared_note', share_id=share['share_id'], _external=True),
                    'permissions': share.get('permissions', 'view'),
                    'surprise_theme': share.get('surprise_theme', 'none'),
                    'created_at': share.get('created_at')
                })
            # Clones for locked notes
            for doc in m.personal_posts_conf.aggregate([
                {'$match': {'source_note_id': {'$in': locked_note_ids}, 'user_id': {'$ne': ObjectId(current_user.id)}}},
                {'$group': {'_id': '$source_note_id', 'count': {'$sum': 1}}}
            ]):
                locked_clones_map[str(doc['_id'])] = doc['count']

    # Fetch active share links for the notes on this page (skip if no notes)
    now = datetime.datetime.now(datetime.timezone.utc)
    note_ids = [note['_id'] for note in personal_posts]
    active_shares_map = {}
    if note_ids:
        active_shares_raw = list(m.note_shares_conf.find({
            'owner_id': ObjectId(current_user.id),
            'note_id': {'$in': note_ids}
        }).sort('created_at', -1))
        
        # Build a map: note_id_str -> list of active share info
        for share in active_shares_raw:
            # Skip expired links
            if share.get('expires_at'):
                exp = share['expires_at']
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                if now > exp:
                    continue
            nid = str(share['note_id'])
            if nid not in active_shares_map:
                active_shares_map[nid] = []
            share_url = url_for('sharing.view_shared_note', share_id=share['share_id'], _external=True)
            active_shares_map[nid].append({
                'share_id': share['share_id'],
                'share_url': share_url,
                'permissions': share.get('permissions', 'view'),
                'surprise_theme': share.get('surprise_theme', 'none'),
                'created_at': share.get('created_at')
            })

    page_title = "My Personal Space"
    page_description = "Your private collection of saved posts and personal notes."

    # Build a map of note_ids that have clones saved by other users
    has_clones_map = {}
    if note_ids:
        clone_pipeline = [
            {'$match': {'source_note_id': {'$in': note_ids}, 'user_id': {'$ne': ObjectId(current_user.id)}}},
            {'$group': {'_id': '$source_note_id', 'count': {'$sum': 1}}}
        ]
        for doc in m.personal_posts_conf.aggregate(clone_pipeline):
            has_clones_map[str(doc['_id'])] = doc['count']

    # Pagination metadata
    import math
    total_notes_pages = math.ceil(total_notes_count / per_page) if per_page else 0
    total_saved_pages = math.ceil(total_saved / per_page) if per_page else 0

    # New users (fewer than 5 notes) see text labels beside action icons
    show_icon_labels = (total_notes_count + locked_notes_count) < 5

    # --- Fetch Activity for the User's Notes ---
    activity_raw = list(m.note_versions_conf.find(
        {
            'content_owner_id': ObjectId(current_user.id),
            'is_read_by_owner': False
        }
    ).sort('created_at', -1))
    
    activity_notifications = []
    for item in activity_raw:
        # Decrypt necessary fields for the preview if it's a proposal
        if item.get('event_type') == 'proposal':
            # Use multi-candidate decryption for proposals
            candidates = m._candidate_user_ids(
                item.get('content_owner_id'), 
                item.get('editor_id'), 
                current_user.id
            )
            item['proposed_content_plain'] = m._decrypt_with_candidate_ids(item.get('proposed_content', ''), candidates) or '[Content unavailable \u2014 decryption error]'
        
        # Fetch original note basic info
        note_info = m.personal_posts_conf.find_one({'_id': item['note_id']}, {'created_at': 1})
        item['original_note_date'] = note_info.get('created_at') if note_info else None
        activity_notifications.append(item)

    # Build a per-note map of pending proposals for badge display on note cards
    pending_proposals_list = [a for a in activity_notifications if a.get('event_type') == 'proposal' and a.get('status') == 'pending']
    pending_proposals_map = {}
    for p in pending_proposals_list:
        nid = str(p.get('note_id', ''))
        if nid:
            if nid not in pending_proposals_map:
                pending_proposals_map[nid] = []
            pending_proposals_map[nid].append(p)

    return render_template(
        'personal_space.html', 
        saved_posts=saved_posts, 
        personal_posts=personal_posts, 
        active_shares_map=active_shares_map, 
        has_clones_map=has_clones_map, 
        active_page='personal_space', 
        title=page_title, 
        description=page_description,
        notes_page=notes_page,
        saved_page=saved_page,
        total_notes_pages=total_notes_pages,
        total_saved_pages=total_saved_pages,
        total_notes_count=total_notes_count,
        total_saved=total_saved,
        has_app_lock=has_app_lock,
        is_unlocked=is_unlocked,
        locked_notes=locked_notes,
        locked_notes_count=locked_notes_count,
        locked_shares_map=locked_shares_map,
        locked_clones_map=locked_clones_map,
        show_icon_labels=show_icon_labels,
        activity_notifications=activity_notifications,
        pending_proposals=pending_proposals_list,
        reviewed_proposals=[a for a in activity_notifications if a.get('event_type') == 'proposal' and a.get('status') in ('accepted', 'rejected')],
        auto_approved_activity=[
            {
                **a,
                'has_active_auto_approve': m._has_active_auto_approve(
                    a.get('share_id'), a.get('editor_id')
                )
            }
            for a in activity_notifications
            if a.get('event_type') == 'snapshot' and a.get('is_auto_approved')
        ],
        pending_proposals_map=pending_proposals_map
    )


@bp.route('/api/note/content/<note_id>', methods=['GET'])
@login_required
def api_note_full_content(note_id):
    """Fetch the FULL decrypted content of a note (used by JS when user expands a preview)."""
    import main as m
    try:
        obj_id = m.safe_object_id(note_id)
        if not obj_id:
            return jsonify({'error': 'Invalid note ID'}), 400

        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Note not found or unauthorized'}), 404

        # _decrypt_note_record will check Redis cache first, avoiding re-decryption
        full_content = m._decrypt_note_record(note)
        return jsonify({
            'success': True,
            'content': full_content,
            'note_id': note_id
        })
    except Exception as e:
        current_app.logger.error(f"Error fetching full note content {note_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/api/activity/feed')
@login_required
def api_activity_feed():
    """Lightweight activity feed endpoint - loaded lazily via AJAX to avoid slow page loads."""
    import main as m
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(20, max(1, int(request.args.get('per_page', 10))))

        activity_raw = list(m.note_versions_conf.find(
            {'content_owner_id': ObjectId(current_user.id)}
        ).sort('created_at', -1).skip((page - 1) * per_page).limit(per_page))

        items = []
        for item in activity_raw:
            entry = {
                'id': str(item['_id']),
                'event_type': item.get('event_type'),
                'editor_name': item.get('editor_name', 'Unknown'),
                'edit_summary': (item.get('edit_summary') or '')[:120],
                'status': item.get('status'),
                'created_at': item.get('created_at').isoformat() if item.get('created_at') else None,
                'is_read_by_owner': item.get('is_read_by_owner', False),
            }
            # Decrypt proposal preview
            if item.get('event_type') == 'proposal' and item.get('proposed_content'):
                candidates = m._candidate_user_ids(
                    item.get('content_owner_id'),
                    item.get('editor_id'),
                    current_user.id
                )
                decrypted = m._decrypt_with_candidate_ids(item.get('proposed_content', ''), candidates)
                entry['proposed_content_preview'] = (decrypted or '')[:200]
            items.append(entry)

        return jsonify({
            'success': True,
            'items': items,
            'page': page,
            'has_more': len(items) == per_page
        })
    except Exception as e:
        current_app.logger.error(f"Error fetching activity feed: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/api/activity/mark_read', methods=['POST'])
@login_required
@csrf_exempt
def api_mark_activity_read():
    """Marks all unread note activity as read for the current user."""
    import main as m
    try:
        result = m.note_versions_conf.update_many(
            {'content_owner_id': ObjectId(current_user.id), 'is_read_by_owner': False},
            {'$set': {'is_read_by_owner': True}}
        )

        # Also mark documents that lack the field entirely as read
        m.note_versions_conf.update_many(
            {'content_owner_id': ObjectId(current_user.id), 'is_read_by_owner': {'$exists': False}},
            {'$set': {'is_read_by_owner': True}}
        )

        # Clear Redis cache keys so that badge counts are recomputed instantly
        if m.redis_cache:
            try:
                m.redis_cache.delete(f"unread_notif_count:{current_user.id}")
                m.redis_cache.delete(f"badge_counts:{current_user.id}")
            except Exception:
                pass

        return jsonify({'success': True, 'cleared': result.modified_count})
    except Exception as e:
        current_app.logger.error(f"Error marking activity as read: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/personal_post/create', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def create_personal_post():
    """Creates a new personal note/post with encryption."""
    import main as m
    content = request.form.get('content')
    if content and content.strip():
        # --- Premium tier enforcement ---
        user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        # Safety: if DB lookup fails, fall back to current_user's cached tier
        max_notes = m.get_limit(user_doc, 'max_notes') if user_doc else current_user.get_limit('max_notes')
        max_chars = m.get_limit(user_doc, 'max_chars_per_note') if user_doc else current_user.get_limit('max_chars_per_note')
        current_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id)})
        if current_count >= max_notes:
            flash(f'You have reached the limit of {max_notes} notes on your current plan. Upgrade to Premium for unlimited notes!', 'warning')
            return redirect(url_for('notes.personal_space'))
        raw_content = content.strip()
        content = raw_content[:max_chars]
        if len(raw_content) > max_chars:
            current_app.logger.warning(f"Note content truncated for user {current_user.username} (tier={current_user.account_tier}): {len(raw_content)} -> {max_chars} chars")
        # Encrypt the note content before storing
        encrypted_content = m.encrypt_note(content, user_id=current_user.id)
        result = m.personal_posts_conf.insert_one({
            'user_id': ObjectId(current_user.id),
            'content_owner_id': ObjectId(current_user.id),
            'content': encrypted_content,
            'encrypted': True,
            'reference': request.form.get('reference', '').strip()[:200],
            'tags': [t.strip() for t in request.form.get('tags', '').split(',') if t.strip()][:10],
            'created_at': datetime.datetime.now(datetime.timezone.utc)
        })
        # Index decrypted content to Typesense for search
        m.index_note_to_typesense(str(result.inserted_id), decrypted_content=content)
        flash('Personal note added securely.', 'success')
    else:
        flash('Content cannot be empty.', 'danger')
    return redirect(url_for('notes.personal_space'))


@bp.route('/personal_post/create_json', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def create_personal_post_json():
    """Creates a new personal note via JSON API (for offline sync)."""
    import main as m
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Content cannot be empty'}), 400

    # --- Premium tier enforcement ---
    user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    # Safety: if DB lookup fails, fall back to current_user's cached tier
    max_notes = m.get_limit(user_doc, 'max_notes') if user_doc else current_user.get_limit('max_notes')
    max_chars = m.get_limit(user_doc, 'max_chars_per_note') if user_doc else current_user.get_limit('max_chars_per_note')
    current_count = m.personal_posts_conf.count_documents({'user_id': ObjectId(current_user.id)})
    if current_count >= max_notes:
        return jsonify({'error': f'Note limit reached ({max_notes}). Upgrade to Premium for unlimited notes.', 'upgrade': True}), 403

    raw_len = len(content)
    content = content[:max_chars]
    if raw_len > max_chars:
        current_app.logger.warning(f"Note content truncated for user {current_user.username} (tier={current_user.account_tier}): {raw_len} -> {max_chars} chars")
    encrypted_content = m.encrypt_note(content, user_id=current_user.id)
    result = m.personal_posts_conf.insert_one({
        'user_id': ObjectId(current_user.id),
        'content_owner_id': ObjectId(current_user.id),
        'content': encrypted_content,
        'encrypted': True,
        'reference': data.get('reference', '').strip()[:200],
        'tags': [t.strip() for t in data.get('tags', '').split(',') if t.strip()] if isinstance(data.get('tags'), str) else (data.get('tags') or []),
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })
    # Index decrypted content to Typesense for search
    m.index_note_to_typesense(str(result.inserted_id), decrypted_content=content)
    return jsonify({'success': True, 'id': str(result.inserted_id)})


@bp.route('/personal_post/search')
@login_required
def search_personal_notes():
    """Search personal notes using Typesense with highlighting and tenant-isolated scoped keys."""
    import main as m
    import typesense_client as _t
    query = request.args.get('q', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(50, max(1, int(request.args.get('per_page', 20))))

    if not query:
        return jsonify({'results': [], 'total': 0, 'query': ''})

    if not _t.ts_notes:
        # Fallback: simple MongoDB text search on decrypted notes
        try:
            notes_raw = list(m.personal_posts_conf.find({
                'user_id': ObjectId(current_user.id),
                'is_locked': {'$ne': True}
            }).sort('created_at', -1))
            q_lower = query.lower()
            results = []
            for note in notes_raw:
                content = m._decrypt_note_record(note)
                if q_lower in content.lower():
                    import m.re as re_mod
                    highlighted = re_mod.sub(
                        f'({re_mod.escape(query)})',
                        r'<mark class="search-highlight">\1</mark>',
                        content,
                        flags=re_mod.IGNORECASE
                    )
                    match_pos = content.lower().find(q_lower)
                    start = max(0, match_pos - 80)
                    end = min(len(content), match_pos + len(query) + 80)
                    snippet_raw = content[start:end]
                    snippet_hl = re_mod.sub(
                        f'({re_mod.escape(query)})',
                        r'<mark class="search-highlight">\1</mark>',
                        snippet_raw,
                        flags=re_mod.IGNORECASE
                    )
                    if start > 0:
                        snippet_hl = '...' + snippet_hl
                    if end < len(content):
                        snippet_hl = snippet_hl + '...'
                    results.append({
                        'id': str(note['_id']),
                        'content_highlighted': highlighted,
                        'snippet': snippet_hl,
                        'created_at': note.get('created_at').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00', 'Z') if note.get('created_at') else None
                    })
            total = len(results)
            paginated = results[(page - 1) * per_page: page * per_page]
            return jsonify({'results': paginated, 'total': total, 'query': query})
        except Exception as e:
            current_app.logger.error(f'Fallback note search error: {e}')
            return jsonify({'results': [], 'total': 0, 'query': query, 'error': 'Search failed'}), 500

    try:
        search_params = {
            'q': query,
            'query_by': 'content',
            'filter_by': f'user_id:={current_user.id}',
            'per_page': per_page,
            'page': page,
            'sort_by': 'created_at:desc',
            'highlight_full_fields': 'content',
            'highlight_start_tag': '<mark class="search-highlight">',
            'highlight_end_tag': '</mark>',
        }

        search_result = _t._ts_search('personal_notes', search_params)
        hits = search_result.get('hits', [])

        # Enforce lock gate at the source-of-truth DB layer so locked notes can never leak
        # through stale or partially indexed search documents.
        candidate_ids = []
        for h in hits:
            doc = h.get('document', h)
            hid = doc.get('id')
            if isinstance(hid, str) and ObjectId.is_valid(hid):
                candidate_ids.append(ObjectId(hid))

        allowed_note_ids = set()
        if candidate_ids:
            allowed_docs = m.personal_posts_conf.find({
                '_id': {'$in': candidate_ids},
                'user_id': ObjectId(current_user.id),
                'is_locked': {'$ne': True}
            }, {'_id': 1})
            allowed_note_ids = {str(doc['_id']) for doc in allowed_docs}

        results = []
        for h in hits:
            doc = h.get('document', h)
            hit_id = doc.get('id')
            if hit_id not in allowed_note_ids:
                continue
            highlights = h.get('highlights', [])
            content_highlighted = doc.get('content', '')
            snippet = doc.get('content', '')[:300]
            for hl in highlights:
                if hl.get('field') == 'content' and hl.get('snippet'):
                    content_highlighted = hl['snippet']
                    snippet = hl['snippet']
            results.append({
                'id': doc.get('id'),
                'content_highlighted': content_highlighted,
                'snippet': snippet,
                'created_at': datetime.datetime.fromtimestamp(
                    doc.get('created_at'), tz=datetime.timezone.utc
                ).isoformat() if doc.get('created_at') else None,
            })
        total = len(results)
        return jsonify({
            'results': results,
            'total': total,
            'query': query,
            'page': page,
            'per_page': per_page,
            'processing_time_ms': search_result.get('search_time_ms', 0)
        })
    except Exception as e:
        current_app.logger.error(f'Typesense note search error: {e}')
        return jsonify({'results': [], 'total': 0, 'query': query, 'error': 'Search failed'}), 500


@bp.route('/personal_post/reindex_notes', methods=['POST'])
@login_required
def reindex_my_notes():
    """Reindex the current user's notes into Typesense."""
    import main as m
    try:
        success = m.reindex_user_notes_to_typesense(current_user.id)
        if success:
            return jsonify({'success': True, 'message': 'Notes reindexed successfully'})
        return jsonify({'error': 'Typesense not configured'}), 500
    except Exception as e:
        current_app.logger.error(f'Error reindexing notes for user {current_user.id}: {e}')
        return jsonify({'error': 'Reindex failed'}), 500


@bp.route('/api/merge/ai', methods=['POST'])
@limits(calls=20, period=60)
def merge_conflict_ai():
    """Uses JigsawStack AI to intelligently resolve merge conflicts between two versions."""
    import main as m
    try:
        data = request.get_json() or {}
        current_content = data.get('current_content', '')
        incoming_content = data.get('incoming_content', '')

        # Safe string conversion and stripping
        current_content = current_content.strip() if isinstance(current_content, str) else ''
        incoming_content = incoming_content.strip() if isinstance(incoming_content, str) else ''

        if not current_content and not incoming_content:
            return jsonify({'error': 'Both note versions are empty.'}), 400

        # JigsawStack's schema validation requires input_values to contain at least 1 character.
        # If one version is empty, we fall back to a descriptive "(empty)" label.
        current_content = current_content if current_content else "(empty)"
        incoming_content = incoming_content if incoming_content else "(empty)"

        try:
            api_key = get_env_variable('JIGSAW_API_KEY')
        except Exception:
            return jsonify({
                'error': 'JigsawStack AI key is not configured. Please resolve the conflict manually.'
            }), 400

        # Construct a detailed prompt template for direct merging
        prompt_text = (
            "You are an expert editor. Resolve a conflict between two versions of a note.\n\n"
            "Version A (Current Saved Version):\n"
            "{current_version}\n\n"
            "Version B (User's Incoming Version):\n"
            "{incoming_version}\n\n"
            "Intelligently merge these two versions into a single, cohesive note.\n"
            "Guidelines:\n"
            "- Keep all unique facts, ideas, and additions from BOTH versions.\n"
            "- Remove duplicate sentences or paragraphs.\n"
            "- Ensure the tone is consistent and the narrative flows logically.\n"
            "- Return ONLY the merged text of the note. Do not include any intro, explanations, markdown code block wrappers (like ```), or comments."
        )

        try:
            client = JigsawStack(api_key=api_key)
            res_data = client.prompt_engine.run_prompt_direct({
                'prompt': prompt_text,
                'inputs': [
                    {'key': 'current_version'},
                    {'key': 'incoming_version'}
                ],
                'input_values': {
                    'current_version': current_content,
                    'incoming_version': incoming_content
                }
            })
        except Exception as sdk_err:
            current_app.logger.error(f"JigsawStack SDK run_prompt_direct failed: {sdk_err}")
            return jsonify({'error': 'AI merging service returned an error. Please resolve manually.'}), 502

        if res_data:
            if isinstance(res_data, dict):
                merged_text = res_data.get('result') or res_data.get('output') or res_data.get('response')
            else:
                merged_text = getattr(res_data, 'result', None) or getattr(res_data, 'output', None) or getattr(res_data, 'response', None)

            if merged_text:
                return jsonify({
                    'success': True,
                    'merged_content': merged_text.strip()
                })

            current_app.logger.warning(f"JigsawStack prompt direct returned empty response: {res_data}")
            return jsonify({'error': 'AI returned an empty response. Please resolve conflicts manually.'}), 500
        else:
            current_app.logger.error("JigsawStack prompt direct returned no response data")
            return jsonify({'error': 'AI merging service returned an empty response. Please resolve manually.'}), 502

    except Exception as e:
        current_app.logger.error(f"AI merge exception: {e}")
        return jsonify({'error': 'Failed to connect to the AI merging helper.'}), 500


@bp.route('/personal_post/edit/<post_id>', methods=['POST'])
@login_required
@limits(calls=15, period=60)
def edit_personal_post(post_id):
    """Edits an existing personal note with version control."""
    import main as m
    try:
        data = request.get_json() or {}
        content = data.get('content', '').strip()
        edit_summary = (data.get('edit_summary') or '').strip()[:180]
        force_overwrite = bool(data.get('force_overwrite', False))
        base_updated_at = m.parse_iso_utc(data.get('base_updated_at'))
        if not content:
            return jsonify({'error': 'Content cannot be empty'}), 400

        # Enforce max length
        max_chars = current_user.get_limit('max_chars_per_note')
        raw_len = len(content)
        content = content[:max_chars]
        if raw_len > max_chars:
            current_app.logger.warning(f"Edit truncated for user {current_user.username} (tier={current_user.account_tier}): {raw_len} -> {max_chars} chars")
        obj_id = m.safe_object_id(post_id)
        if not obj_id:
            return jsonify({'error': 'Invalid note ID'}), 400

        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Note not found or unauthorized'}), 404

        note_updated_at = note.get('updated_at') or note.get('created_at')
        if isinstance(note_updated_at, datetime.datetime) and note_updated_at.tzinfo is None:
            note_updated_at = note_updated_at.replace(tzinfo=datetime.timezone.utc)

        # Conflict-aware editing: warn and return merge preview instead of silently overwriting.
        if base_updated_at and note_updated_at and (note_updated_at > base_updated_at) and not force_overwrite:
            current_plain = m._decrypt_note_record(note)
            return jsonify({
                'error': 'conflict',
                'message': 'This note was updated by someone else after you opened the editor.',
                'current_content': current_plain,
                'incoming_content': content,
                'merge_preview': m.build_merge_preview_text(current_plain, content),
                'diff_text': m.build_unified_diff_text(current_plain, content),
                'current_updated_at': note_updated_at.isoformat() if isinstance(note_updated_at, datetime.datetime) else None
            }), 409

        # Version control: snapshot previous content before overwriting
        if note.get('content'):
            editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)
            m.note_versions_conf.insert_one({
                'note_id': obj_id,
                'share_id': None,
                'editor_name': editor_name,
                'editor_id': ObjectId(current_user.id),
                'content': note['content'],
                'content_owner_id': note.get('content_owner_id', note.get('user_id')),
                'encrypted': note.get('encrypted', True),
                'event_type': 'snapshot',
                'status': 'applied',
                'edit_summary': edit_summary or 'Edited note',
                'created_at': datetime.datetime.now(datetime.timezone.utc),
                'is_read_by_owner': True
            })
            # Cap at 50 versions per note
            version_count = m.note_versions_conf.count_documents({'note_id': obj_id})
            if version_count > 50:
                oldest = m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', 1).limit(version_count - 50)
                for old_ver in oldest:
                    m.note_versions_conf.delete_one({'_id': old_ver['_id']})

        encrypted_content = m.encrypt_note(content, user_id=current_user.id)
        now = datetime.datetime.now(datetime.timezone.utc)
        m.personal_posts_conf.update_one(
            {'_id': obj_id},
            {'$set': {
                'content': encrypted_content, 
                'encrypted': True, 
                'content_owner_id': ObjectId(current_user.id),
                'reference': data.get('reference', '').strip()[:200],
                'tags': [t.strip() for t in data.get('tags', '').split(',') if t.strip()] if isinstance(data.get('tags'), str) else (data.get('tags') or []),
                'updated_at': now
            }}
        )

        # --- Free-tier share link content-change enforcement ---
        # Increment content_changes counter on all active shares for this note.
        # Free users are capped at 3 content changes per link.
        try:
            user_doc = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
            is_premium = m.is_premium(user_doc) if user_doc else False
            active_shares = list(m.note_shares_conf.find({'note_id': obj_id}))
            for share in active_shares:
                new_count = share.get('content_changes', 0) + 1
                update_fields = {'content_changes': new_count}
                if not is_premium and new_count > 3:
                    update_fields['deactivated'] = True
                    update_fields['deactivated_reason'] = 'content_change_limit'
                m.note_shares_conf.update_one(
                    {'_id': share['_id']},
                    {'$set': update_fields}
                )
            # Warn user if any links were deactivated
            deactivated_count = sum(1 for s in active_shares if not is_premium and s.get('content_changes', 0) + 1 > 3 and not s.get('deactivated'))
            warn_msg = None
            if deactivated_count > 0:
                warn_msg = f'{deactivated_count} share link(s) deactivated — free accounts can change shared content up to 3 times per link. Upgrade to Premium for unlimited changes.'
        except Exception as share_err:
            current_app.logger.error(f"Error enforcing share content-change limit: {share_err}")
            warn_msg = None

        # Re-index with updated decrypted content
        m.index_note_to_typesense(post_id, decrypted_content=content)

        # Invalidate decryption cache so next load gets fresh content
        m.invalidate_note_decryption_cache(post_id)

        # Broadcast update to other devices/sessions for real-time sync
        m.socketio.emit('note_changed', {
            'note_id': post_id, 
            'content': content,
            'reference': data.get('reference', ''),
            'tags': data.get('tags', []),
            'updated_at': now.isoformat()
        }, room=str(current_user.id))

        result = {'success': True, 'updated_at': now.isoformat()}
        if warn_msg:
            result['warning'] = warn_msg
        return jsonify(result)
    except Exception as e:
        current_app.logger.error(f"Error editing personal post {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/personal_post/sync/<post_id>', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def sync_personal_post(post_id):
    """Bidirectional sync: pushes clone changes to original if newer, or pulls original changes to clone."""
    import main as m
    try:
        obj_id = m.safe_object_id(post_id)
        if not obj_id:
            return jsonify({'error': 'Invalid note ID'}), 400

        # Find the cloned note owned by current user
        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Note not found or unauthorized'}), 404

        source_note_id = note.get('source_note_id')
        source_share_id = note.get('source_share_id')
        if not source_note_id:
            return jsonify({'error': 'This note is not a saved copy ΓÇö nothing to sync'}), 400

        # Verify the share still exists and grants edit permission
        if source_share_id:
            share = m.note_shares_conf.find_one({'share_id': source_share_id})
            if not share:
                return jsonify({'error': 'The original share link no longer exists'}), 404
            if share.get('permissions') != 'edit':
                return jsonify({'error': 'You need edit permission to sync with the original'}), 403
            # Check expiration
            if share.get('expires_at'):
                expires_at = share['expires_at']
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
                if datetime.datetime.now(datetime.timezone.utc) > expires_at:
                    return jsonify({'error': 'The share link has expired'}), 410
        else:
            return jsonify({'error': 'No share link associated with this copy'}), 400

        # Fetch the original note
        original_note = m.personal_posts_conf.find_one({'_id': source_note_id})
        if not original_note:
            return jsonify({'error': 'Original note no longer exists', 'code': 'original_missing'}), 410

        now = datetime.datetime.now(datetime.timezone.utc)
        editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)

        # Determine sync direction by comparing last-modified timestamps
        clone_modified = note.get('updated_at') or note.get('created_at') or now
        original_modified = original_note.get('updated_at') or original_note.get('created_at') or now
        # Ensure timezone-aware comparison
        if clone_modified.tzinfo is None:
            clone_modified = clone_modified.replace(tzinfo=datetime.timezone.utc)
        if original_modified.tzinfo is None:
            original_modified = original_modified.replace(tzinfo=datetime.timezone.utc)

        # Check if content is actually different by comparing decrypted plaintexts
        clone_decrypted = m._decrypt_note_record(note)
        original_decrypted = m._decrypt_note_record(original_note, share)
        if clone_decrypted == original_decrypted:
            # Content matches but timestamps might differ — sync the clone's timestamp
            # so update_available won't trigger again on the next page load.
            m.personal_posts_conf.update_one(
                {'_id': obj_id},
                {'$set': {'updated_at': now}}
            )
            return jsonify({
                'success': True,
                'content': clone_decrypted,
                'direction': 'none',
                'message': 'Already in sync.'
            })

        if clone_modified > original_modified:
            # --- PUSH: Clone is newer push clone's content to the original ---
            
            # SECURITY CHECK: If user is not the owner of the source note and hasn't been auto-approved, create a proposal.
            original_owner_id = str(original_note.get('user_id', ''))
            is_owner_of_original = str(current_user.id) == original_owner_id

            auto_approved_users = share.get('auto_approved_users', [])
            is_user_auto_approved = ObjectId(current_user.id) in auto_approved_users

            if not is_owner_of_original and not share.get('auto_approve', False) and not is_user_auto_approved:
                # Contributor flow: create a pending proposal instead of overwriting.
                editor_name = current_user.username if hasattr(current_user, 'username') else str(current_user.id)
                m.note_versions_conf.insert_one({
                    'note_id': source_note_id,
                    'share_id': source_share_id,
                    'editor_name': editor_name + ' (Sync)',
                    'editor_id': ObjectId(current_user.id),
                    'content': original_note.get('content', ''),
                    'base_content': original_note.get('content', ''),
                    'content_owner_id': ObjectId(original_owner_id),
                    'proposed_content': note.get('content'),
                    'encrypted': True,
                    'event_type': 'proposal',
                    'status': 'pending',
                    'edit_summary': 'Synced changes from my saved copy',
                    'created_at': now,
                    'is_read_by_owner': False
                })
                
                # Notify original owner sessions.
                try:
                    m.socketio.emit('note_proposal_created', {
                        'share_id': source_share_id,
                        'note_id': str(source_note_id),
                        'editor_name': editor_name,
                        'summary': 'Synced changes from a saved copy'
                    }, room=original_owner_id)
                except Exception:
                    pass

                # Push notification for owner devices (PWA + native app)
                try:
                    if original_owner_id:
                        m.send_push_notification_to_user(
                            original_owner_id,
                            f"{editor_name} proposed note changes",
                            "A collaborator submitted updates for your review.",
                            url=url_for('notes.personal_space', _external=True) + '#activity',
                            tag=f'note-proposal-{source_note_id}',
                            extra_data={'type': 'note_proposal', 'note_id': str(source_note_id), 'share_id': source_share_id}
                        )
                except Exception as notify_err:
                    current_app.logger.error(f"Failed to send proposal push notification to owner {original_owner_id}: {notify_err}")

                return jsonify({
                    'success': True,
                    'pending_approval': True,
                    'message': 'Changes submitted to the note owner for review.'
                })

            # Owner flow: direct push permitted.
            # Version-snapshot the original before overwriting
            if original_note.get('content'):
                m.note_versions_conf.insert_one({
                    'note_id': source_note_id,
                    'share_id': source_share_id,
                    'editor_name': editor_name + ' (sync push)',
                    'editor_id': ObjectId(current_user.id),
                    'content': original_note['content'],
                    'content_owner_id': original_note.get('content_owner_id', original_note.get('user_id')),
                    'encrypted': original_note.get('encrypted', True),
                    'created_at': now,
                    'is_read_by_owner': False if not is_owner_of_original else True,
                    'is_auto_approved': True if not is_owner_of_original else False,
                    'event_type': 'snapshot'
                })
                
                # Notify original owner of auto-approval push
                if not is_owner_of_original:
                    try:
                        m.socketio.emit('note_auto_approved', {
                            'share_id': source_share_id,
                            'note_id': str(source_note_id),
                            'editor_name': editor_name,
                            'summary': 'Auto-synced changes from a saved copy'
                        }, room=original_owner_id)
                    except Exception:
                        pass
                version_count = m.note_versions_conf.count_documents({'note_id': source_note_id})
                if version_count > 50:
                    oldest = m.note_versions_conf.find({'note_id': source_note_id}).sort('created_at', 1).limit(version_count - 50)
                    for old_ver in oldest:
                        m.note_versions_conf.delete_one({'_id': old_ver['_id']})

            # Push clone content to original
            m.personal_posts_conf.update_one(
                {'_id': source_note_id},
                {'$set': {
                    'content': note.get('content'),
                    'encrypted': note.get('encrypted', True),
                    'content_owner_id': note.get('content_owner_id', note.get('user_id')),
                    'reference': note.get('reference', ''),
                    'tags': note.get('tags', []),
                    'updated_at': now
                }}
            )

            # Re-index original in Typesense
            decrypted = m._decrypt_note_record(note)
            m.index_note_to_typesense(str(source_note_id), decrypted_content=decrypted)

            # Broadcast update to participants in the share room
            m.socketio.emit('note_changed', {'content': decrypted}, room=source_share_id)

            return jsonify({
                'success': True,
                'content': decrypted,
                'direction': 'push',
                'message': 'Your changes have been pushed to the original note.'
            })
        else:
            # --- PULL: Original is newer ΓåÆ pull original's content to the clone ---
            # Version-snapshot the clone before overwriting
            if note.get('content'):
                m.note_versions_conf.insert_one({
                    'note_id': obj_id,
                    'share_id': None,
                    'editor_name': editor_name + ' (sync pull)',
                    'editor_id': ObjectId(current_user.id),
                    'content': note['content'],
                    'content_owner_id': note.get('content_owner_id', note.get('user_id')),
                    'encrypted': note.get('encrypted', True),
                    'created_at': now,
                    'is_read_by_owner': True
                })
                version_count = m.note_versions_conf.count_documents({'note_id': obj_id})
                if version_count > 50:
                    oldest = m.note_versions_conf.find({'note_id': obj_id}).sort('created_at', 1).limit(version_count - 50)
                    for old_ver in oldest:
                        m.note_versions_conf.delete_one({'_id': old_ver['_id']})

            # Pull original content to clone
            m.personal_posts_conf.update_one(
                {'_id': obj_id},
                {'$set': {
                    'content': original_note.get('content'),
                    'encrypted': original_note.get('encrypted', True),
                    'content_owner_id': original_note.get('content_owner_id', original_note.get('user_id')),
                    'reference': original_note.get('reference', ''),
                    'tags': original_note.get('tags', []),
                    'updated_at': now
                }}
            )

            # Re-index clone in Typesense
            decrypted = m._decrypt_note_record(original_note)
            m.index_note_to_typesense(post_id, decrypted_content=decrypted)

            # Broadcast to other sessions of the SAME USER for real-time sync
            m.socketio.emit('note_changed', {
                'note_id': post_id, 
                'content': decrypted,
                'reference': original_note.get('reference', ''),
                'tags': original_note.get('tags', [])
            }, room=str(current_user.id))

            return jsonify({
                'success': True,
                'content': decrypted,
                'direction': 'pull',
                'message': 'Note updated with latest changes from the original.'
            })
    except Exception as e:
        current_app.logger.error(f"Error syncing personal post {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


@bp.route('/personal_post/delete/<post_id>', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def delete_personal_post(post_id):
    """Deletes a personal note/post with mode support (me/everyone)."""
    import main as m
    try:
        mode = request.form.get('mode', 'me')  # Default to 'me' for safety
        obj_id = m.safe_object_id(post_id)
        if not obj_id:
            flash('Invalid note ID.', 'danger')
            return redirect(url_for('notes.personal_space'))

        # Fetch the note to verify ownership
        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            flash('Note not found or unauthorized.', 'danger')
            return redirect(url_for('notes.personal_space'))

        # --- Cascading Deletion Logic ---
        if mode == 'everyone':
            # Purge original + all descendants recursively.
            target_ids = []
            frontier = [obj_id]
            visited = set()
            while frontier:
                next_frontier = []
                for note_id in frontier:
                    if note_id in visited:
                        continue
                    visited.add(note_id)
                    target_ids.append(note_id)
                    child_ids = [c['_id'] for c in m.personal_posts_conf.find({'source_note_id': note_id}, {'_id': 1})]
                    next_frontier.extend(child_ids)
                frontier = next_frontier
            msg_suffix = f"and {max(0, len(target_ids) - 1)} copy/copies deleted for everyone."
        else:
            # Delete only this specific note (clones remain if they exists)
            target_ids = [obj_id]
            msg_suffix = "deleted from your space."

        # 1. Cleanup all share links and their media for target notes
        shares = m.note_shares_conf.find({'note_id': {'$in': target_ids}})
        for share in shares:
            m.cleanup_share_media(share)
            m.note_shares_conf.delete_one({'_id': share['_id']})

        # 1.5. Cleanup media from the posts themselves before deleting
        target_posts = m.personal_posts_conf.find({'_id': {'$in': target_ids}})
        for post in target_posts:
            m.cleanup_post_media(post)

        # 2. Cleanup all versions for target notes
        m.note_versions_conf.delete_many({'note_id': {'$in': target_ids}})

        # 3. Cleanup all unlock notifications for target notes
        m.unlock_notifications_conf.delete_many({'note_id': {'$in': target_ids}})

        # 4. Remove from Typesense index
        m.remove_notes_from_typesense(target_ids)

        # 5. Final: Delete entries from m.personal_posts_conf
        m.personal_posts_conf.delete_many({'_id': {'$in': target_ids}})

        flash(f'Personal note {msg_suffix}', 'success')
    except Exception as e:
        current_app.logger.error(f"Error deleting personal post {post_id} (Mode: {mode}): {e}")
        flash('Could not delete note.', 'danger')
    return redirect(url_for('notes.personal_space'))


# ----------------- App Lock & Note Locking -----------------


@bp.route('/personal_post/toggle_lock/<post_id>', methods=['POST'])
@login_required
@limits(calls=20, period=60)
def toggle_note_lock(post_id):
    """Toggle the is_locked flag on a personal note. Premium feature."""
    import main as m
    try:
        obj_id = m.safe_object_id(post_id)
        if not obj_id:
            return jsonify({'error': 'Invalid note ID'}), 400

        # --- Premium tier enforcement ---
        user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
        if not m.is_premium(user):
            return jsonify({
                'error': 'Note Locking is a Premium feature. Upgrade to keep your sensitive notes behind a PIN.',
                'upgrade': True
            }), 403

        # Verify the user has a PIN set up
        if not user or not user.get('app_lock_pin_hash'):
            return jsonify({'error': 'You need to set up an App Lock PIN first. Go to Profile Settings ΓåÆ App Lock.'}), 400

        note = m.personal_posts_conf.find_one({'_id': obj_id, 'user_id': ObjectId(current_user.id)})
        if not note:
            return jsonify({'error': 'Note not found or unauthorized'}), 404

        new_locked = not note.get('is_locked', False)
        m.personal_posts_conf.update_one({'_id': obj_id}, {'$set': {'is_locked': new_locked}})

        return jsonify({
            'success': True,
            'is_locked': new_locked,
            'message': 'Note locked' if new_locked else 'Note unlocked'
        })
    except Exception as e:
        current_app.logger.error(f"Error toggling lock for note {post_id}: {e}")
        return jsonify({'error': 'Internal error'}), 500


# ----------------- Note Sharing Endpoints -----------------


@bp.route('/api/app_lock/setup', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def app_lock_setup():
    """Set or update the user's 4-digit app lock PIN."""
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()
    current_pin = data.get('current_pin', '').strip()

    if not pin or len(pin) != 4 or not pin.isdigit():
        return jsonify({'error': 'PIN must be exactly 4 digits'}), 400

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)})
    # If user already has a PIN, require the current one to change it
    if user.get('app_lock_pin_hash'):
        if not current_pin:
            return jsonify({'error': 'Current PIN is required to change your PIN'}), 400
        if not m.check_password_hash(user['app_lock_pin_hash'], current_pin):
            return jsonify({'error': 'Current PIN is incorrect'}), 403

    pin_hash = m.generate_password_hash(pin)
    m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'app_lock_pin_hash': pin_hash}})
    session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
    return jsonify({'success': True, 'message': 'App lock PIN set successfully'})


@bp.route('/api/app_lock/verify', methods=['POST'])
@login_required
@limits(calls=15, period=60)
def app_lock_verify():
    """Verify the user's PIN and unlock the locked notes tab for this session."""
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()

    if not pin:
        return jsonify({'error': 'PIN is required'}), 400

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No app lock PIN is set'}), 400

    if m.check_password_hash(user['app_lock_pin_hash'], pin):
        session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Incorrect PIN'}), 403


@bp.route('/api/app_lock/remove', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def app_lock_remove():
    """Remove the user's app lock PIN (requires current PIN)."""
    import main as m
    data = request.get_json() or {}
    pin = data.get('pin', '').strip()

    if not pin:
        return jsonify({'error': 'Current PIN is required'}), 400

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No app lock PIN is set'}), 400

    if not m.check_password_hash(user['app_lock_pin_hash'], pin):
        return jsonify({'error': 'Incorrect PIN'}), 403

    m.users_conf.update_one({'_id': ObjectId(current_user.id)}, {'$unset': {'app_lock_pin_hash': ''}})
    # Unlock any locked notes back to regular notes when PIN is removed
    m.personal_posts_conf.update_many(
        {'user_id': ObjectId(current_user.id), 'is_locked': True},
        {'$set': {'is_locked': False}}
    )
    session.pop('app_lock_unlocked_at', None)
    return jsonify({'success': True, 'message': 'App lock removed. All locked notes have been unlocked.'})


@bp.route('/api/app_lock/check_status')
@login_required
def app_lock_check_status():
    """Check if the app lock session is still valid (for visibility change m.re-checks)."""
    import main as m
    unlock_ts = session.get('app_lock_unlocked_at')
    if not unlock_ts:
        return jsonify({'unlocked': False})
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - unlock_ts).total_seconds()
    if elapsed >= 300:
        session.pop('app_lock_unlocked_at', None)
        return jsonify({'unlocked': False})
    return jsonify({'unlocked': True, 'remaining': int(300 - elapsed)})


@bp.route('/api/app_lock/relock', methods=['POST'])
@login_required
def app_lock_relock():
    """Clear the app lock session state to relock the locked notes tab."""
    import main as m
    session.pop('app_lock_unlocked_at', None)
    return jsonify({'success': True})


@bp.route('/api/app_lock/forgot', methods=['POST'])
@login_required
@limits(calls=5, period=60)
def app_lock_forgot():
    """Send a 6-digit verification code to the user's email for PIN reset."""
    import main as m
    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'email': 1, 'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No app lock PIN is set on this account'}), 400
    email = user.get('email')
    if not email:
        return jsonify({'error': 'No email address associated with this account'}), 400

    # Generate a 6-digit code, hash it, store with 15-minute expiry
    gen_code = str(secrets.randbelow(10**6)).zfill(6)
    hashed_code = hashlib.sha256(gen_code.encode()).hexdigest()
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)

    m.auth_conf.update_one(
        {'email': email},
        {'$set': {
            'pin_reset_code': hashed_code,
            'pin_reset_expiry': expiry
        }},
        upsert=True
    )

    # Send the code via email using the pin_reset_email template
    try:
        from notifications import _get_mail, _get_app
        from flask_mail import Message as MailMessage
        sender = f"EchoWithin <{get_env_variable('MAIL_USERNAME')}>"
        msg = MailMessage(
            subject="EchoWithin App Lock PIN Reset",
            sender=sender,
            recipients=[email]
        )
        msg.html = render_template("pin_reset_email.html", code=gen_code)
        msg.body = f"Your EchoWithin App Lock PIN reset code is: {gen_code}\n\nThis code expires in 15 minutes. If you didn't request this, please ignore this email."
        _get_mail().send(msg)
        current_app.logger.info(f"PIN reset code sent to {email}. DEV CODE: {gen_code}")
    except Exception as e:
        current_app.logger.error(f"Failed to send PIN reset email to {email}: {e}")
        return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500

    # Mask email for display (e.g., u***r@example.com)
    parts = email.split('@')
    if len(parts[0]) > 2:
        masked = parts[0][0] + '***' + parts[0][-1] + '@' + parts[1]
    else:
        masked = parts[0][0] + '***@' + parts[1]

    return jsonify({'success': True, 'masked_email': masked, 'message': 'Verification code sent to your email.'})


@bp.route('/api/app_lock/reset_verify', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def app_lock_reset_verify():
    """Verify the emailed code and set a new APP Lock PIN."""
    import main as m
    data = request.get_json() or {}
    code = data.get('code', '').strip()
    new_pin = data.get('new_pin', '').strip()

    if not code:
        return jsonify({'error': 'Verification code is required'}), 400
    if not new_pin or len(new_pin) != 4 or not new_pin.isdigit():
        return jsonify({'error': 'New PIN must be exactly 4 digits'}), 400

    user = m.users_conf.find_one({'_id': ObjectId(current_user.id)}, {'email': 1, 'app_lock_pin_hash': 1})
    if not user or not user.get('app_lock_pin_hash'):
        return jsonify({'error': 'No app lock PIN is set'}), 400

    email = user.get('email')
    if not email:
        return jsonify({'error': 'No email on this account'}), 400

    # Look up the stored reset code
    auth_record = m.auth_conf.find_one({'email': email, 'pin_reset_code': {'$exists': True}})
    if not auth_record:
        return jsonify({'error': 'No reset request found. Please request a new code.'}), 400

    # Check expiry
    expiry = auth_record.get('pin_reset_expiry')
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) > expiry:
            # Clean up expired code
            m.auth_conf.update_one({'email': email}, {'$unset': {'pin_reset_code': '', 'pin_reset_expiry': ''}})
            return jsonify({'error': 'Reset code has expired. Please request a new one.'}), 400

    # Verify the code
    hashed_input = hashlib.sha256(code.encode()).hexdigest()
    if hashed_input != auth_record.get('pin_reset_code'):
        return jsonify({'error': 'Incorrect verification code'}), 403

    # Code is valid — update the PIN
    new_pin_hash = m.generate_password_hash(new_pin)
    m.users_conf.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'app_lock_pin_hash': new_pin_hash}}
    )

    # Clean up the used code
    m.auth_conf.update_one({'email': email}, {'$unset': {'pin_reset_code': '', 'pin_reset_expiry': ''}})

    # Unlock the session
    session['app_lock_unlocked_at'] = datetime.datetime.now(datetime.timezone.utc)

    return jsonify({'success': True, 'message': 'PIN has been reset successfully.'})


@bp.route('/api/ai/suggest-tags', methods=['POST'])
@login_required
@limits(calls=10, period=60)
def api_suggest_tags():
    """Suggest tags for a blog post by classifying content against predefined tags."""
    import main as m
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title and not content:
        return jsonify({'tags': []})

    clean_text = f"{title}\n\n{content[:800]}"

    # Try JigsawStack Classification API first
    try:
        api_key = get_env_variable('JIGSAW_API_KEY')
        
        # Split m.PREDEFINED_TAGS into two batches to respect JigsawStack's limit of 24 labels per request
        batch1 = m.PREDEFINED_TAGS[:18]
        batch2 = m.PREDEFINED_TAGS[18:]
        
        all_tags = []
        for batch in [batch1, batch2]:
            api_response = requests.post(
                'https://api.jigsawstack.com/v1/classification',
                json={
                    'dataset': [{'type': 'text', 'value': clean_text}],
                    'labels': [{'type': 'text', 'value': t} for t in batch],
                    'multiple_labels': True,
                },
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
                
                # Extract and clean tags from predictions
                for item in batch_tags:
                    if isinstance(item, dict) and 'label' in item:
                        all_tags.append(item['label'])
                    elif isinstance(item, str):
                        all_tags.append(item)
            else:
                current_app.logger.info(f'JigsawStack batch classify returned status {api_response.status_code}')

        # Unique and valid predefined tags
        unique_tags = []
        for tag in all_tags:
            if tag and tag not in unique_tags and tag in m.PREDEFINED_TAGS:
                unique_tags.append(tag)

        if unique_tags:
            return jsonify({'tags': unique_tags[:4]})

    except Exception as e:
        current_app.logger.warning(f'JigsawStack classify failed, falling back to NLP: {e}')

    # ---- Free NLP fallback (no API tokens used) ----
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

    cursor = m.users_conf.find(
        filter_query,
        {'password': 0, 'email': 0, 'notification_preference': 0, 'last_active': 0}
    ).sort('username', 1).limit(6)

    suggestions = []
    for candidate in cursor:
        if exclude_username and candidate.get('username') == exclude_username:
            continue
        suggestions.append({
            'username': candidate.get('username'),
            'bio': candidate.get('bio', ''),
            'profile_image_url': candidate.get('profile_image_url') or url_for('static', filename='default_avatar.png'),
            'profile_url': url_for('profile.profile', username=candidate.get('username')),
        })

    return jsonify({'suggestions': suggestions})
