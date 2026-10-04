    // ========== Offline Notes Sync System ==========
    (function () {
        const DB_NAME = 'echowithin_offline';
        const STORE_NAME = 'pending_notes';
        const CACHED_STORE = 'cached_notes';
        const DB_VERSION = 2;
        let CSRF = (window.EW_CONFIG && window.EW_CONFIG.csrfToken) || (document.querySelector('meta[name="csrf-token"]') ? document.querySelector('meta[name="csrf-token"]').getAttribute('content') : '') || '';

        // Fetch a fresh CSRF token from the lightweight API endpoint.
        // Falls back to the global auto-refresh helper added in base.html.
        async function getFreshCsrf() {
            try {
                const resp = await echoFetch('/api/csrf-token', { credentials: 'same-origin' });
                if (!resp.ok) return CSRF;
                const data = await resp.json();
                if (data && data.csrf_token) {
                    CSRF = data.csrf_token;
                    // Update the meta tag and hidden inputs on the page
                    const meta = document.querySelector('meta[name="csrf-token"]');
                    if (meta) meta.setAttribute('content', CSRF);
                    const inputs = document.querySelectorAll('input[name="csrf_token"]');
                    inputs.forEach(function(el){ el.value = CSRF; });
                }
            } catch (e) {
                // Network still down — keep existing token
            }
            return CSRF;
        }

        // --- IndexedDB Helpers ---
        function openDB() {
            return new Promise((resolve, reject) => {
                const req = indexedDB.open(DB_NAME, DB_VERSION);
                req.onupgradeneeded = (e) => {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains(STORE_NAME)) {
                        db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
                    }
                    if (!db.objectStoreNames.contains(CACHED_STORE)) {
                        const cachedStore = db.createObjectStore(CACHED_STORE, { keyPath: 'noteId' });
                        cachedStore.createIndex('updatedAt', 'updatedAt', { unique: false });
                    }
                };
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => reject(req.error);
            });
        }

        function getAllPending() {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(STORE_NAME, 'readonly');
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.getAll();
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = () => reject(req.error);
                });
            });
        }

        function addPending(note) {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.add(note);
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = () => reject(req.error);
                });
            });
        }

        function updatePending(id, data) {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    const getReq = store.get(id);
                    getReq.onsuccess = () => {
                        const existing = getReq.result;
                        if (!existing) {
                            resolve();
                            return;
                        }
                        const updated = { ...existing, ...data };
                        const putReq = store.put(updated);
                        putReq.onsuccess = () => resolve(updated);
                        putReq.onerror = () => reject(putReq.error);
                    };
                    getReq.onerror = () => reject(getReq.error);
                });
            });
        }

        function deletePending(id) {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.delete(id);
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
            });
        }

        function clearAllPending() {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(STORE_NAME, 'readwrite');
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.clear();
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
            });
        }

        // Export helper functions to window for global access
        window.openOfflineDB = openDB;
        window.getAllPending = getAllPending;
        window.addPending = addPending;
        window.updatePending = updatePending;
        window.deletePending = deletePending;
        window.clearAllPending = clearAllPending;

        // --- Cached Notes Mirror (IndexedDB) ---
        // Saves server-rendered notes to IndexedDB for offline access
        function saveNotesToCache(notesData) {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(CACHED_STORE, 'readwrite');
                    const store = tx.objectStore(CACHED_STORE);
                    const userId = (window.EW_CONFIG && window.EW_CONFIG.userId) || '';
                    notesData.forEach(note => {
                        store.put({ ...note, userId: userId, cachedAt: new Date().toISOString() });
                    });
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
            });
        }

        function getCachedNotes() {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(CACHED_STORE, 'readonly');
                    const store = tx.objectStore(CACHED_STORE);
                    const index = store.index('updatedAt');
                    const req = index.openCursor(null, 'prev');
                    const notes = [];
                    req.onsuccess = (e) => {
                        const cursor = e.target.result;
                        if (cursor) {
                            notes.push(cursor.value);
                            cursor.continue();
                        } else {
                            resolve(notes);
                        }
                    };
                    req.onerror = () => reject(req.error);
                });
            });
        }

        function clearCachedNotes() {
            return openDB().then(db => {
                return new Promise((resolve, reject) => {
                    const tx = db.transaction(CACHED_STORE, 'readwrite');
                    const store = tx.objectStore(CACHED_STORE);
                    const req = store.clear();
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
            });
        }

        // Extract notes from server-rendered DOM (present when page loads with data)
        function extractNotesFromDOM() {
            const noteCards = document.querySelectorAll('.note-card[data-note-id]:not(.pending-note)');
            const notes = [];
            noteCards.forEach(card => {
                const noteId = card.getAttribute('data-note-id');
                const contentEl = card.querySelector('.note-content[data-raw]');
                const content = contentEl ? contentEl.getAttribute('data-raw') : '';
                const renderedHtml = contentEl ? contentEl.innerHTML : '';
                const dateEl = card.querySelector('.note-date');
                const dateText = dateEl ? dateEl.textContent.trim() : '';
                const isPinned = card.classList.contains('pinned');
                const hasUpdate = card.classList.contains('update-available');
                const refEl = card.querySelector('.note-ref-display');
                const reference = refEl ? refEl.textContent.trim() : '';
                const tagEls = card.querySelectorAll('.note-tag-badge');
                const tags = Array.from(tagEls).map(t => t.textContent.trim());

                const noteFooter = card.querySelector('.note-footer');
                let noteFooterHtml = '';
                if (noteFooter) {
                    const footerClone = noteFooter.cloneNode(true);
                    const actionsEl = footerClone.querySelector('.note-actions');
                    if (actionsEl) actionsEl.remove();
                    const syncBtn = footerClone.querySelector('.sync-update-btn');
                    if (syncBtn) syncBtn.parentElement ? syncBtn.parentElement.remove() : syncBtn.remove();
                    noteFooterHtml = footerClone.innerHTML;
                }

                notes.push({
                    noteId: noteId,
                    content: content,
                    renderedHtml: renderedHtml,
                    reference: reference,
                    tags: tags,
                    isPinned: isPinned,
                    updatedAt: dateText,
                    noteFooterHtml: noteFooterHtml,
                    cachedAt: new Date().toISOString()
                });
            });
            return notes;
        }

        // Render notes from cached data into the notes list
        function renderCachedNotes(notes) {
            const container = document.getElementById('notes-list-container');
            if (!container) return;
            if (!notes || !notes.length) {
                container.innerHTML = '<div style="text-align:center; padding:2rem; color:#888;"><i class="fas fa-sticky-note" style="font-size:2rem; display:block; margin-bottom:0.5rem;"></i>No cached notes available yet.<br><small>Visit this page while online to cache your notes for offline access.</small></div>';
                return;
            }
            container.innerHTML = notes.map(note => {
                const rawAttr = note.content ? `data-raw="${note.content.replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')}"` : '';
                const pinClass = note.isPinned ? ' pinned' : '';
                let metaHtml = '';
                if (note.reference || (note.tags && note.tags.length)) {
                    metaHtml = '<div class="note-metadata-display" style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.25rem;">';
                    if (note.reference) {
                        metaHtml += `<div class="note-ref-display" style="font-size:0.75rem;color:#555;font-weight:600;">${note.reference.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
                    }
                    if (note.tags && note.tags.length) {
                        metaHtml += '<div class="note-tags-display" style="display:flex;gap:0.3rem;flex-wrap:wrap;">';
                        note.tags.forEach(tag => {
                            metaHtml += `<span class="note-tag-badge" style="background:#f0f0f0;color:#666;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.65rem;border:1px solid #ddd;">${tag.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>`;
                        });
                        metaHtml += '</div>';
                    }
                    metaHtml += '</div>';
                }
                return `
                    <div class="note-card cached-note${pinClass}" data-note-id="${note.noteId}" style="opacity:0.85;">
                        <div class="note-content rendered-note" ${rawAttr}>${note.renderedHtml || (note.content ? note.content.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '')}</div>
                        ${metaHtml}
                        <div class="note-footer" style="display:flex;justify-content:space-between;align-items:center;">
                            <span class="note-date">
                                <i class="far fa-clock"></i> ${note.updatedAt}
                                <span class="cached-badge" style="display:inline-flex;align-items:center;gap:0.2rem;background:#e8f5e9;color:#2e7d32;padding:2px 8px;border-radius:12px;font-size:0.65rem;border:1px solid #c8e6c9;margin-left:0.3rem;">
                                    <i class="fas fa-database"></i> Cached
                                </span>
                            </span>
                            <div class="note-actions">
                                <button type="button" class="btn-icon edit-note-btn" title="Edit note" aria-label="Edit note" data-id="${note.noteId}" data-reference="${(note.reference || '').replace(/"/g, '&quot;')}" data-tags="${JSON.stringify(note.tags || []).replace(/"/g, '&quot;')}" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 6px;border-radius:4px;font-size:0.85rem;">
                                    <i class="fas fa-edit"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
            if (typeof window.formatDecryptionErrors === 'function') {
                window.formatDecryptionErrors(container);
            }
        }

        // --- UI Helpers ---
        const banner = document.getElementById('offline-banner');
        const bannerText = document.getElementById('offline-banner-text');
        const pendingContainer = document.getElementById('pending-notes-container');

        function setBanner(state, extraMsg) {
            banner.className = 'offline-banner';
            if (state === 'offline') {
                banner.classList.add('offline');
                const icon = banner.querySelector('i');
                if (icon) icon.className = 'fas fa-wifi';
                bannerText.textContent = extraMsg || "You're offline — viewing cached notes";
                banner.style.display = 'flex';
            } else if (state === 'offline-empty') {
                banner.classList.add('offline');
                const icon = banner.querySelector('i');
                if (icon) icon.className = 'fas fa-wifi';
                bannerText.textContent = "You're offline — no cached notes available. Connect to the internet to load your notes.";
                banner.style.display = 'flex';
            } else if (state === 'syncing') {
                banner.classList.add('syncing');
                const icon = banner.querySelector('i');
                if (icon) icon.className = 'fas fa-sync fa-spin';
                bannerText.textContent = 'Syncing your offline notes...';
                banner.style.display = 'flex';
            } else {
                banner.style.display = 'none';
            }
        }
        window.setOfflineBannerState = setBanner;

        function renderPendingNotes(notes) {
            if (!notes || !notes.length) {
                pendingContainer.innerHTML = '';
                return;
            }
            pendingContainer.innerHTML = notes.map(n => {
                const escaped = (n.content || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                const preview = escaped.substring(0, 300) + (escaped.length > 300 ? '...' : '');
                const rawDate = n.created_at || n.queued_at || new Date().toISOString();
                const ts = (window.parseServerTime ? window.parseServerTime(rawDate) : new Date(rawDate)).toLocaleString();
                const typeLabel = n.type === 'edit' ? 'Pending edit' : (n.type === 'delete' ? 'Pending deletion' : 'Pending sync');
                const badgeColor = n.type === 'edit' ? '#e65100' : (n.type === 'delete' ? '#c62828' : '#e65100');
                const badgeBg = n.type === 'edit' ? '#fff3e0' : (n.type === 'delete' ? '#ffebee' : '#fff3e0');
                const badgeBorder = n.type === 'edit' ? '#ffe0b2' : (n.type === 'delete' ? '#ffcdd2' : '#ffe0b2');

                let actionBtns = '';
                if (n.type !== 'delete') {
                    actionBtns = `
                        <div class="note-actions" style="display:flex;gap:0.3rem;align-items:center;">
                            <button type="button" class="btn-icon edit-pending-btn" title="Edit pending note" aria-label="Edit pending note" onclick="window.editPendingNote(${n.id})" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 6px;border-radius:4px;font-size:0.85rem;">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button type="button" class="btn-icon delete-pending-btn" title="Discard pending note" aria-label="Discard pending note" onclick="window.deletePendingNote(${n.id})" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 6px;border-radius:4px;font-size:0.85rem;">
                                <i class="fas fa-trash-alt"></i>
                            </button>
                        </div>
                    `;
                } else {
                    actionBtns = `
                        <div class="note-actions" style="display:flex;gap:0.3rem;align-items:center;">
                            <button type="button" class="btn-icon delete-pending-btn" title="Undo pending deletion" aria-label="Undo pending deletion" onclick="window.deletePendingNote(${n.id})" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:4px 6px;border-radius:4px;font-size:0.85rem;">
                                <i class="fas fa-undo"></i>
                            </button>
                        </div>
                    `;
                }

                return `
                    <div class="note-card pending-note" id="pending-note-${n.id}">
                        <div class="note-content"><pre style="white-space:pre-wrap;margin:0;font-family:inherit;">${preview}</pre></div>
                        <div class="note-footer" style="display:flex;justify-content:space-between;align-items:center;">
                            <span class="note-date">
                                <i class="far fa-clock"></i> ${ts}
                                <span class="pending-badge" style="display:inline-flex;align-items:center;gap:0.2rem;background:${badgeBg};color:${badgeColor};padding:2px 8px;border-radius:12px;font-size:0.65rem;border:1px solid ${badgeBorder};margin-left:0.3rem;">
                                    <i class="fas fa-spinner fa-spin"></i> ${typeLabel}
                                </span>
                            </span>
                            ${actionBtns}
                        </div>
                    </div>
                `;
            }).join('');
        }
        window.renderPendingNotes = renderPendingNotes;

        window.editPendingNote = async function(id) {
            const all = await getAllPending();
            const note = all.find(n => n.id === id);
            if (!note) return;
            window.openEditModal(
                note.noteId || ('pending_' + note.id),
                note.content || '',
                note.reference || '',
                note.tags || [],
                '',
                true,
                id
            );
        };

        window.deletePendingNote = async function(id) {
            if (confirm('Discard this pending note action?')) {
                await deletePending(id);
                const pending = await getAllPending();
                renderPendingNotes(pending);
                if (pending.length) {
                    setBanner('offline', `You're offline — ${pending.length} note(s) pending sync`);
                } else {
                    const cachedNotes = await getCachedNotes();
                    if (cachedNotes.length) {
                        setBanner('offline', `You're offline — viewing ${cachedNotes.length} cached note(s)`);
                    } else {
                        setBanner('offline-empty');
                    }
                }
                if (window.showCustomToast) {
                    window.showCustomToast('Pending note discarded.', 'info');
                }
            }
        };

        // --- Form Intercept ---
        // Always intercept form submission and use fetch + offline fallback.
        // Try the network first and save to IndexedDB if it fails.
        const form = document.getElementById('create-note-form');
        if (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                const textarea = document.getElementById('note-input');
                const content = textarea.value.trim();
                if (!content) return;

                const refInput = document.getElementById('note-reference');
                const tagsInput = document.getElementById('note-tags');
                const addBtn = document.getElementById('add-note-btn');
                if (addBtn) {
                    addBtn.disabled = true;
                    addBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
                }

                // Try sending to server first
                fetch('/personal_post/create_json', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': CSRF
                    },
                    body: JSON.stringify({
                        content: content,
                        reference: refInput ? refInput.value.trim() : '',
                        tags: tagsInput ? tagsInput.value.trim() : ''
                    })
                }).then(resp => {
                    if (resp.ok) {
                        // Success — set flash and reload to show new note
                        if (window.EW_CONFIG && window.EW_CONFIG.isGuest) {
                            if (!localStorage.getItem('ew_guest_first_note')) {
                                localStorage.setItem('ew_guest_first_note', '1');
                                sessionStorage.setItem('ew_pending_flash', JSON.stringify({
                                    message: 'Your first note — encrypted and saved securely.',
                                    category: 'success'
                                }));
                            } else {
                                sessionStorage.setItem('ew_pending_flash', JSON.stringify({
                                    message: 'Personal note added securely.',
                                    category: 'success'
                                }));
                            }
                        } else {
                            sessionStorage.setItem('ew_pending_flash', JSON.stringify({
                                message: 'Personal note added securely.',
                                category: 'success'
                            }));
                        }
                        window.location.reload();
                    } else {
                        throw new Error('Server error');
                    }
                }).catch(() => {
                    // Network failed — save offline
                    const note = {
                        type: 'create',
                        content: content,
                        reference: refInput ? refInput.value.trim() : '',
                        tags: tagsInput ? tagsInput.value.trim() : '',
                        created_at: new Date().toISOString()
                    };
                    addPending(note).then(() => {
                        textarea.value = '';
                        if (refInput) refInput.value = '';
                        if (tagsInput) tagsInput.value = '';
                        document.getElementById('char-count').textContent = '0';
                        return getAllPending().then(notes => {
                            setBanner('offline', `You're offline — ${notes.length} note(s) pending sync`);
                            renderPendingNotes(notes);
                            // Register Background Sync so the browser retries
                            // when connectivity returns, even if the tab is closed.
                            if ('serviceWorker' in navigator && 'SyncManager' in window) {
                                navigator.serviceWorker.ready.then(reg => {
                                    reg.sync.register('sync-pending-notes').catch(() => {});
                                });
                            }
                        });
                    }).catch(err => {
                        console.error('Failed to save offline note:', err);
                        alert('Failed to save note offline. Please try again.');
                    }).finally(() => {
                        if (addBtn) {
                            addBtn.disabled = false;
                            addBtn.innerHTML = '<i class="fas fa-plus"></i> Add Note';
                        }
                    });
                });
            });
        }

        // --- Sync Logic ---
        let _syncInProgress = false;
        async function syncPendingNotes() {
            if (_syncInProgress) return;
            _syncInProgress = true;
            try {
                const pending = await getAllPending();
                if (!pending.length) return;

                setBanner('syncing');
                // Refresh CSRF token before syncing — the embedded one is
                // likely expired if the page was loaded from cache.
                await getFreshCsrf();
                let allSynced = true;

                for (const note of pending) {
                    try {
                        if (note.type === 'edit') {
                            const resp = await fetch(`/personal_post/edit/${note.noteId}`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-CSRFToken': CSRF
                                },
                                body: JSON.stringify({
                                    content: note.content,
                                    reference: note.reference || '',
                                    tags: note.tags || [],
                                    edit_summary: note.edit_summary || '',
                                    base_updated_at: note.base_updated_at || null,
                                    force_overwrite: false
                                })
                            });
                            if (resp.ok || resp.status === 404) {
                                await deletePending(note.id);
                            } else {
                                allSynced = false;
                            }
                        } else if (note.type === 'delete') {
                            const resp = await fetch(`/personal_post/delete/${note.noteId}`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-CSRFToken': CSRF,
                                    'Accept': 'application/json'
                                },
                                body: JSON.stringify({ mode: note.mode || 'me' })
                            });
                            if (resp.ok || resp.status === 404 || resp.redirected) {
                                await deletePending(note.id);
                            } else {
                                allSynced = false;
                            }
                        } else {
                            // Default: create
                            const resp = await fetch('/personal_post/create_json', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'X-CSRFToken': CSRF
                                },
                                body: JSON.stringify({
                                    content: note.content,
                                    reference: note.reference || '',
                                    tags: note.tags || ''
                                })
                            });
                            if (resp.ok) {
                                await deletePending(note.id);
                            } else {
                                allSynced = false;
                            }
                        }
                    } catch {
                        allSynced = false;
                    }
                }

                if (allSynced) {
                    setBanner('hidden');
                    // Reload to show the synced notes from server
                    window.location.reload();
                } else {
                    setBanner('offline', 'Some notes failed to sync. Will retry when connection improves.');
                }
            } finally {
                _syncInProgress = false;
            }
        }

        // --- Connectivity Events ---
        async function updateOnlineStatus() {
            if (navigator.onLine) {
                const pending = await getAllPending();
                if (pending.length) {
                    // Only sync and reload if there were pending notes
                    await syncPendingNotes();
                }
                // Refresh cached notes from server data
                // Re-cache notes from server data on reconnect
                try {
                    const domNotes = extractNotesFromDOM();
                    if (domNotes.length) {
                        clearCachedNotes().catch(() => {});
                        saveNotesToCache(domNotes);
                    }
                } catch (e) {
                    console.warn('Failed to re-cache notes from DOM:', e);
                }
            } else {
                getAllPending().then(notes => {
                    if (notes.length) {
                        setBanner('offline', `You're offline — ${notes.length} note(s) pending sync`);
                    } else {
                        getCachedNotes().then(cachedNotes => {
                            if (cachedNotes.length) {
                                setBanner('offline', `You're offline — viewing ${cachedNotes.length} cached note(s)`);
                            } else {
                                setBanner('offline-empty');
                            }
                        });
                    }
                    renderPendingNotes(notes);
                });
            }
        }

        window.addEventListener('online', updateOnlineStatus);
        window.addEventListener('offline', updateOnlineStatus);

        // Sync when user switches back to the app/tab. The 'online' event
        // does NOT fire if the device was already online when the app resumes
        // from background, so visibilitychange is essential.
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && navigator.onLine) {
                getAllPending().then(notes => {
                    if (notes.length) syncPendingNotes();
                });
            }
        });

        // Listen for Background Sync message from the service worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.addEventListener('message', event => {
                if (event.data && event.data.type === 'SYNC_PENDING_NOTES') {
                    syncPendingNotes();
                }
            });
        }

        // --- Init: cache notes on load and handle offline state ---
        (async function initOfflineSupport() {
            // Always cache current notes from DOM when page loads (online or cached HTML)
            if (document.querySelectorAll('.note-card[data-note-id]:not(.pending-note)').length > 0) {
                const domNotes = extractNotesFromDOM();
                if (domNotes.length) {
                    const cachedNotes = await getCachedNotes();
                    const cacheSig = cachedNotes.map(n => n.id + (n.updated_at || n.created_at)).join('|');
                    const domSig = domNotes.map(n => n.id + (n.updated_at || n.created_at)).join('|');
                    if (cacheSig !== domSig) {
                        clearCachedNotes().catch(() => { });
                        saveNotesToCache(domNotes);
                    }
                }
            }

            // Show pending notes if any
            const pending = await getAllPending();
            if (pending.length) {
                renderPendingNotes(pending);
                if (navigator.onLine) {
                    syncPendingNotes();
                } else {
                    setBanner('offline', `You're offline — ${pending.length} note(s) pending sync`);
                }
            }

            // If offline and no server-rendered notes (e.g. cached HTML without data),
            // load notes from IndexedDB cache and render them
            if (!navigator.onLine) {
                const hasServerNotes = document.querySelectorAll('.note-card[data-note-id]:not(.pending-note):not(.cached-note)').length > 0;
                if (!hasServerNotes) {
                    const cachedNotes = await getCachedNotes();
                    if (cachedNotes.length) {
                        renderCachedNotes(cachedNotes);
                        setBanner('offline', `You're offline — viewing ${cachedNotes.length} cached note(s)`);
                    } else if (!pending.length) {
                        setBanner('offline-empty');
                    }
                } else if (!pending.length) {
                    setBanner('offline', "You're offline — viewing cached page");
                }
            }
        })();
        // Valentine toggle helper
        const vToggle = document.getElementById('share-valentine');
        if (vToggle) {
            vToggle.addEventListener('change', () => {
                const opts = document.getElementById('valentine-options');
                if (opts) opts.style.display = vToggle.checked ? 'block' : 'none';
            });
        }
    })();

    // --- Share Feature Promo & Onboarding Logic ---
    (function initSharePromo() {
        // 1. For temporary promos (other pages), honor persisted dismissal.
        // Personal Space uses data-promo-mode="permanent" and always shows on reload.
        const promoCard = document.getElementById('share-promo-card');
        if (promoCard && promoCard.dataset.promoMode === 'temporary' && localStorage.getItem('ew_share_promo_dismissed') === '1') {
            promoCard.style.display = 'none';
        }

        // Alternate promotion between surprise links and standard collaboration notes.
        const promoTitle = document.getElementById('share-promo-title');
        const promoCopy = document.getElementById('share-promo-copy');
        const promoCta = document.getElementById('share-promo-cta');
        if (promoTitle && promoCopy && promoCta) {
            const variants = [
                {
                    title: 'Surprise someone special!',
                    copy: 'Write a note, pick a Celebration/Birthday theme with music & photos, then share a magic link.',
                    cta: 'Try it now ->'
                },
                {
                    title: 'Need a standard collaboration note?',
                    copy: 'Share a normal note for teamwork: comments, co-editing, and version history in one place.',
                    cta: 'Start collaborating ->'
                }
            ];

            let variantIndex = 0;
            const applyVariant = (index) => {
                const item = variants[index];
                promoTitle.textContent = item.title;
                promoCopy.textContent = item.copy;
                promoCta.textContent = item.cta;
            };

            applyVariant(variantIndex);
            setInterval(() => {
                variantIndex = (variantIndex + 1) % variants.length;
                applyVariant(variantIndex);
            }, 9000);
        }

        // 2. Show tooltip on the FIRST note's share button (once per user)
        if (!localStorage.getItem('ew_share_tooltip_seen')) {
            const firstTip = document.querySelector('.share-onboard-tip');
            if (firstTip) {
                firstTip.style.display = 'block';

                // Dismiss tooltip on any share button click
                document.querySelectorAll('.share-note-btn').forEach(btn => {
                    btn.addEventListener('click', () => {
                        document.querySelectorAll('.share-onboard-tip').forEach(t => t.style.display = 'none');
                        localStorage.setItem('ew_share_tooltip_seen', '1');
                    }, { once: true });
                });

                // Auto-dismiss after 8 seconds
                setTimeout(() => {
                    if (firstTip.style.display !== 'none') {
                        firstTip.style.display = 'none';
                        localStorage.setItem('ew_share_tooltip_seen', '1');
                    }
                }, 8000);
            }
        }
    })();

    // --- Share Modal Guided Flow ---
    (function initShareGuidedFlow() {
        const modeSelector = document.getElementById('share-mode-selector');
        const shareConfig = document.getElementById('share-config');
        const communityPicker = document.getElementById('share-community-picker');
        const backBtn = document.getElementById('back-to-share-modes');
        const backFromCommunityBtn = document.getElementById('back-from-community');
        const showAllBtn = document.getElementById('show-all-share-options');
        const permSelect = document.getElementById('share-permissions');
        const expirySelect = document.getElementById('share-expiry');

        if (!modeSelector || !shareConfig) return;

        function showConfig() {
            modeSelector.style.display = 'none';
            shareConfig.style.display = 'block';
            if (communityPicker) communityPicker.style.display = 'none';
        }

        function showCommunityPicker() {
            modeSelector.style.display = 'none';
            shareConfig.style.display = 'none';
            if (communityPicker) {
                communityPicker.style.display = 'block';
                loadCommunities();
            }
        }

        function showModes() {
            shareConfig.style.display = 'none';
            if (communityPicker) communityPicker.style.display = 'none';
            modeSelector.style.display = 'block';
        }

        // Load communities for the picker
        function loadCommunities() {
            const list = document.getElementById('community-picker-list');
            const empty = document.getElementById('community-picker-empty');
            if (!list) return;
            list.innerHTML = '<div style="text-align: center; padding: 1rem; color: #999; font-size: 0.85rem;">Loading...</div>';
            if (empty) empty.style.display = 'none';

            echoFetch('/api/communities/mine')
                .then(r => r.json())
                .then(data => {
                    if (!data.success || !data.communities || data.communities.length === 0) {
                        list.innerHTML = '';
                        if (empty) empty.style.display = 'block';
                        return;
                    }
                    list.innerHTML = '';
                    data.communities.forEach(comm => {
                        const card = document.createElement('button');
                        card.type = 'button';
                        card.style.cssText = 'display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; border: 2px solid #eee; border-radius: 10px; background: white; cursor: pointer; text-align: left; transition: all 0.2s; width: 100%;';
                        card.innerHTML = `
                            <div style="width: 36px; height: 36px; border-radius: 50%; background: #f0ebe7; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                                <span style="font-size: 1rem;">👥</span>
                            </div>
                            <div style="flex: 1; min-width: 0;">
                                <div style="font-weight: 600; font-size: 0.88rem; color: #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${comm.name}</div>
                                <div style="font-size: 0.72rem; color: #888;">${comm.member_count} member${comm.member_count !== 1 ? 's' : ''}${comm.is_admin ? ' · Admin' : ''}</div>
                            </div>
                        `;
                        card.addEventListener('mouseenter', () => { card.style.borderColor = 'var(--primary-color)'; card.style.background = '#faf8f7'; });
                        card.addEventListener('mouseleave', () => { card.style.borderColor = '#eee'; card.style.background = 'white'; });
                        card.addEventListener('click', () => shareToCommunity(comm.id, comm.name));
                        list.appendChild(card);
                    });
                })
                .catch(() => {
                    list.innerHTML = '<div style="text-align: center; padding: 1rem; color: #c0392b; font-size: 0.82rem;">Failed to load communities.</div>';
                });
        }

        // Share note to selected community
        function shareToCommunity(communityId, communityName) {
            const noteId = window._shareModalNoteId;
            if (!noteId) return;

            const list = document.getElementById('community-picker-list');
            if (list) list.innerHTML = '<div style="text-align: center; padding: 1rem; color: #666; font-size: 0.85rem;">Sharing to ' + communityName + '...</div>';

            echoFetch(`/api/personal_post/${noteId}/share-to-community`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
                },
                body: JSON.stringify({ community_id: communityId })
            })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        if (typeof showCustomAlert === 'function') {
                            showCustomAlert(data.message || 'Note shared to community!', 'success');
                        } else {
                            alert(data.message || 'Note shared to community!');
                        }
                        closeShareModal();
                    } else {
                        if (typeof showCustomAlert === 'function') {
                            showCustomAlert(data.error || 'Failed to share', 'danger');
                        } else {
                            alert(data.error || 'Failed to share');
                        }
                        loadCommunities(); // Reload the list
                    }
                })
                .catch(() => {
                    if (typeof showCustomAlert === 'function') {
                        showCustomAlert('Network error. Please try again.', 'danger');
                    }
                    loadCommunities();
                });
        }

        // Mode button clicks
        document.querySelectorAll('.share-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const mode = btn.dataset.mode;
                if (mode === 'simple') {
                    if (permSelect) permSelect.value = 'view';
                    if (expirySelect) expirySelect.value = 'never';
                    showConfig();
                } else if (mode === 'collaborate') {
                    if (permSelect) permSelect.value = 'edit';
                    if (expirySelect) expirySelect.value = 'never';
                    showConfig();
                } else if (mode === 'community') {
                    showCommunityPicker();
                }
            });

            // Hover effect
            btn.addEventListener('mouseenter', () => {
                btn.style.borderColor = 'var(--primary-color)';
                btn.style.background = '#faf8f7';
            });
            btn.addEventListener('mouseleave', () => {
                btn.style.borderColor = '#eee';
                btn.style.background = 'white';
            });
        });

        // Back buttons
        if (backBtn) {
            backBtn.addEventListener('click', showModes);
        }
        if (backFromCommunityBtn) {
            backFromCommunityBtn.addEventListener('click', showModes);
        }

        // Observe the share modal visibility to reset guided flow
        const shareModal = document.getElementById('share-modal');
        if (shareModal) {
            const observer = new MutationObserver(() => {
                if (shareModal.style.display === 'flex') {
                    // Reset to mode selector when modal opens
                    showModes();
                }
            });
            observer.observe(shareModal, { attributes: true, attributeFilter: ['style'] });
        }
    })();
    window.reviewActivityProposal = async function (versionId, action, noteId) {
        const autoApproveCheckbox = document.getElementById(`auto-allow-${versionId}`);
        const autoApprove = autoApproveCheckbox ? autoApproveCheckbox.checked : false;

        if (!confirm(`Are you sure you want to ${action} these proposed changes?`)) {
            return;
        }

        const notify = function (message, level) {
            if (typeof window.showFlashMessage === 'function') {
                window.showFlashMessage(message, level === 'error' ? 'danger' : level);
            } else if (typeof window.showCustomAlert === 'function') {
                window.showCustomAlert(message, level === 'error' ? 'danger' : level);
            } else {
                alert(message);
            }
        };

        try {
            const response = await fetch(`/personal_post/proposal/${versionId}/decision`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
                },
                body: JSON.stringify({ action: action, auto_approve_subsequent: autoApprove })
            });

            const data = await response.json();
            if (response.ok && data.success) {
                notify(`Proposal ${action}ed successfully.`, 'success');
                // Reload to update the tab count and list
                setTimeout(() => window.location.reload(), 1000);
            } else if (response.status === 409 || data.error === 'conflict') {
                if (typeof window.openMergeConflictModal === 'function') {
                    window.openMergeConflictModal(data);
                    window.onSaveMergeConflict = async (mergedText) => {
                        const mResponse = await fetch(`/personal_post/proposal/${versionId}/decision`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
                            },
                            body: JSON.stringify({ action: action, auto_approve_subsequent: autoApprove, merged_content: mergedText })
                        });
                        const mData = await mResponse.json();
                        if (mResponse.ok && mData.success) {
                            notify(`Proposal ${action}ed successfully with merge.`, 'success');
                            window.closeMergeConflictModal();
                            setTimeout(() => window.location.reload(), 1000);
                        } else {
                            notify(mData.error || `Failed to ${action} proposal.`, 'error');
                        }
                    };
                } else {
                    notify('Merge conflict detected. Please review from the version history.', 'error');
                }
            } else {
                notify(data.error || `Failed to ${action} proposal.`, 'error');
            }
        } catch (err) {
            console.error('Error reviewing proposal:', err);
            notify('An error occurred while reviewing the proposal.', 'error');
        }
    };

    // --- Feature Tips Card Dismiss ---
    (function () {
        const tipsCard = document.getElementById('feature-tips-card');
        const dismissBtn = document.getElementById('dismiss-feature-tips');
        if (tipsCard) {
            if (localStorage.getItem('ew_feature_tips_dismissed')) {
                tipsCard.classList.add('tips-hidden');
            }
            if (dismissBtn) {
                dismissBtn.addEventListener('click', function () {
                    tipsCard.style.animation = 'none';
                    tipsCard.style.transition = 'opacity 0.3s, max-height 0.3s, margin 0.3s, padding 0.3s';
                    tipsCard.style.opacity = '0';
                    tipsCard.style.maxHeight = '0';
                    tipsCard.style.margin = '0';
                    tipsCard.style.padding = '0';
                    tipsCard.style.overflow = 'hidden';
                    setTimeout(function () {
                        tipsCard.classList.add('tips-hidden');
                    }, 300);
                    localStorage.setItem('ew_feature_tips_dismissed', '1');
                });
            }
        }
    })();

    // --- Step-by-Step Onboarding Tooltip for New Users ---
    (function initOnboardingTour() {
        // Only show for new users (fewer than 5 notes)
        if (localStorage.getItem('ew_onboarding_complete')) return;

        const firstNoteCard = document.querySelector('.note-card[data-note-id]');
        if (!firstNoteCard) return;

        const steps = [
            { selector: '.note-actions .copy-btn', text: 'Copy note text to clipboard' },
            { selector: '.note-actions .edit-note-btn', text: 'Edit note with full markdown formatting' },
            { selector: '.note-actions .export-note-btn', text: 'Export note as Plain Text or Word document' },
            { selector: '.note-actions .share-note-btn', text: 'Share note link or choose a surprise theme with music and photos' },
            { selector: '.note-actions .lock-note-btn', text: 'Lock note behind 4-digit PIN for privacy' },
            { selector: '.note-actions .version-history-btn', text: 'View edit history and restore previous versions' },
            { selector: '.note-actions .sync-note-btn', text: 'Sync changes from original shared note' },
            { selector: '.note-actions .delete-btn', text: 'Delete note from your personal space' }
        ];

        let currentStep = 0;

        // Create tooltip element
        const tooltip = document.createElement('div');
        tooltip.id = 'onboarding-tooltip';
        tooltip.style.cssText = `
            position: absolute;
            background: var(--card-bg, #ffffff);
            color: var(--text-dark-color, #333);
            padding: 0.8rem 1rem;
            border-radius: 12px;
            font-size: 0.82rem;
            max-width: 260px;
            z-index: 10000;
            box-shadow: 0 4px 18px var(--shadow-color, rgba(0,0,0,0.1));
            pointer-events: auto;
            transition: opacity 0.2s, transform 0.2s;
            opacity: 0;
            border: 1px solid var(--primary-color, #3e2217);
            font-family: var(--font-family, 'Poppins', sans-serif);
        `;
        document.body.appendChild(tooltip);

        function repositionTooltip() {
            if (currentStep >= steps.length) return;
            const step = steps[currentStep];
            const target = firstNoteCard.querySelector(step.selector);
            if (!target) return;

            const rect = target.getBoundingClientRect();
            const scrollX = window.scrollX || window.pageXOffset;
            const scrollY = window.scrollY || window.pageYOffset;

            // Position tooltip below the target, ensuring horizontal fit in viewport
            tooltip.style.top = (rect.bottom + scrollY + 12) + 'px';
            tooltip.style.left = Math.max(10, Math.min(window.innerWidth - 270, rect.left + scrollX + rect.width / 2 - 130)) + 'px';
        }

        function showStep(index) {
            if (index >= steps.length) {
                cleanUpTour();
                localStorage.setItem('ew_onboarding_complete', '1');
                return;
            }

            // Remove previous highlights
            document.querySelectorAll('.onboarding-highlight').forEach(el => {
                el.classList.remove('onboarding-highlight');
                el.style.outline = '';
                el.style.outlineOffset = '';
            });

            const step = steps[index];
            const target = firstNoteCard.querySelector(step.selector);
            if (!target) {
                // Skip missing buttons
                currentStep++;
                showStep(currentStep);
                return;
            }

            // Highlight target
            target.classList.add('onboarding-highlight');
            target.style.outline = '2px solid var(--primary-color, #3e2217)';
            target.style.outlineOffset = '3px';
            target.style.borderRadius = '6px';

            tooltip.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.4rem; gap: 0.5rem;">
                    <div style="line-height: 1.45; color: var(--text-dark-color, #333);">${step.text}</div>
                    <button id="onboarding-exit" style="background: transparent; border: none; color: var(--text-muted, #999); font-size: 0.9rem; cursor: pointer; padding: 0; line-height: 1;" title="Exit tour" aria-label="Exit tour">✕</button>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.6rem; border-top: 1px solid var(--border-color, #ddd); padding-top: 0.45rem;">
                    <span style="font-size: 0.7rem; color: var(--text-muted, #999);">${index + 1} of ${steps.length}</span>
                    <div style="display: flex; gap: 0.35rem;">
                        <button id="onboarding-skip" style="background: transparent; border: 1px solid var(--border-color, #ddd); color: var(--text-secondary, #555); padding: 0.2rem 0.55rem; border-radius: 6px; font-size: 0.72rem; cursor: pointer; font-weight: 600;">Skip</button>
                        <button id="onboarding-next" style="background: var(--primary-color, #3e2217); color: var(--text-light-color, #fff); border: none; padding: 0.2rem 0.7rem; border-radius: 6px; font-size: 0.75rem; cursor: pointer; font-weight: 600;">
                            ${index === steps.length - 1 ? 'Done' : 'Next'}
                        </button>
                    </div>
                </div>
            `;

            repositionTooltip();
            tooltip.style.opacity = '1';

            // Wire action buttons
            const exitBtn = document.getElementById('onboarding-exit');
            if (exitBtn) {
                exitBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    cleanUpTour();
                    localStorage.setItem('ew_onboarding_complete', '1');
                });
            }

            const skipBtn = document.getElementById('onboarding-skip');
            if (skipBtn) {
                skipBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    cleanUpTour();
                    localStorage.setItem('ew_onboarding_complete', '1');
                });
            }

            const nextBtn = document.getElementById('onboarding-next');
            if (nextBtn) {
                nextBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    currentStep++;
                    showStep(currentStep);
                });
            }
        }

        function cleanUpTour() {
            tooltip.remove();
            window.removeEventListener('scroll', repositionTooltip);
            window.removeEventListener('resize', repositionTooltip);
            document.querySelectorAll('.onboarding-highlight').forEach(el => {
                el.classList.remove('onboarding-highlight');
                el.style.outline = '';
                el.style.outlineOffset = '';
            });
        }

        // Keep tooltip aligned during scroll or viewport resizing
        window.addEventListener('scroll', repositionTooltip);
        window.addEventListener('resize', repositionTooltip);

        // Start tour after window load and brief settle to get correct DOM layout positions
        window.addEventListener('load', () => {
            setTimeout(() => showStep(0), 1000);
        });
    })();

    // Clear notifications — defined globally so the button always works
    window.markAllActivityRead = async function (reload = false) {
        try {
            const response = await echoFetch('/api/activity/mark_read', {
                method: 'POST',
                headers: {
                    'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value,
                    'Content-Type': 'application/json'
                }
            });
            const data = await response.json();
            if (response.ok && data.success) {
                document.querySelectorAll('.activity-badge').forEach(b => {
                    b.textContent = '0';
                });
                if (reload) {
                    window.location.reload();
                }
            } else {
                alert(data.error || 'Failed to clear notifications.');
            }
        } catch (err) {
            console.error('Failed to mark activity as read:', err);
            alert('Network error. Please try again.');
        }
    };
