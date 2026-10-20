/*
 * EchoWithin Interactive Tour
 * - Guest mode: compact right-docked tip panel per page (Notes -> Bonds ->
 *   Messages -> Explore-more hub), plus standalone tips for Communities,
 *   Blog and Profile. Shown only while the tour-mode banner is present.
 * - Onboarding mode: step-by-step walk through the first note's action
 *   buttons for new registered users (or ?tour=1 to replay).
 * All dismissals use localStorage; keys are reset when a fresh tour
 * session starts (?tour_fresh=1).
 */
(function () {
    'use strict';

    var ONBOARDING_KEY = 'ew_onboarding_complete';
    var TIP_KEY_PREFIX = 'dismissed_tour-tooltip-';

    /* ---------------- helpers ---------------- */

    function lsGet(k) {
        try { return localStorage.getItem(k); } catch (e) { return null; }
    }

    function lsSet(k, v) {
        try { localStorage.setItem(k, v); } catch (e) { /* private mode */ }
    }

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text != null) n.textContent = text;
        return n;
    }

    function clearNode(node) {
        while (node.firstChild) node.removeChild(node.firstChild);
    }

    function closeBtn(onClose) {
        var b = el('button', 'ew-tour-close', '\u00d7');
        b.type = 'button';
        b.title = 'Dismiss';
        b.setAttribute('aria-label', 'Dismiss');
        b.addEventListener('click', onClose);
        return b;
    }

    function makeBtn(action, onClick) {
        var cls = 'ew-tour-btn ' + (action.cls || 'ew-tour-btn--ghost');
        var node;
        if (action.href) {
            node = el('a', cls, action.label);
            node.href = action.href;
        } else {
            node = el('button', cls, action.label);
            node.type = 'button';
            node.addEventListener('click', onClick);
        }
        return node;
    }

    function urgentNote() {
        var n = el('div', 'ew-tour-urgent-note');
        n.hidden = true;
        n.textContent = 'Tour ending soon \u2014 sign up to keep your data.';
        return n;
    }

    function ensurePanel() {
        var panel = document.getElementById('ew-tour-panel');
        if (!panel) {
            panel = el('div', 'ew-tour-panel');
            panel.id = 'ew-tour-panel';
            panel.setAttribute('role', 'region');
            panel.setAttribute('aria-label', 'Tour tip');
            panel.setAttribute('aria-live', 'polite');
            panel.hidden = true;
            document.body.appendChild(panel);
        }
        return panel;
    }

    function hidePanel() {
        var panel = document.getElementById('ew-tour-panel');
        if (panel) panel.hidden = true;
    }

    /* ---------------- fresh-tour flag ---------------- */

    function consumeFreshFlag() {
        try {
            var url = new URL(window.location.href);
            if (url.searchParams.get('tour_fresh') === '1') {
                Object.keys(localStorage).forEach(function (k) {
                    if (k.indexOf(TIP_KEY_PREFIX) === 0) localStorage.removeItem(k);
                });
                url.searchParams.delete('tour_fresh');
                history.replaceState(null, '', url.pathname + url.search + url.hash);
            }
        } catch (e) { /* ignore */ }
    }

    /* ---------------- page detection ---------------- */

    function currentPage() {
        var p = window.location.pathname;
        if (p.indexOf('/personal_space') === 0) return 'notes';
        if (p === '/bonds') return 'bonds';
        if (p === '/messages') return 'messages';
        if (p === '/communities') return 'communities';
        if (p === '/blog') return 'blog';
        if (p.indexOf('/profile') === 0) return 'profile';
        return null;
    }

    /* ---------------- guest tour content ---------------- */

    var TIPS = {
        notes: {
            progress: '1 / 3',
            title: 'Notes: Your Private Encrypted Space',
            pill: 'Guest Session',
            body: 'Try writing a note below \u2014 use <code>**bold**</code> or <code># heading</code> for formatting. Your pre-seeded notes show what\u2019s possible.',
            chips: [
                ['Try Writing:', 'Use the form below to create your first note.'],
                ['Try Locking:', 'Click the lock icon on any note to set a PIN.'],
                ['Try Editing:', 'Click the edit icon to modify a note with markdown.'],
                ['Export:', 'Download any note as plain text or Word document.']
            ],
            secondary: { label: 'How Sharing Works', cls: 'ew-tour-btn--link', action: 'share-lesson' },
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' },
            next: {
                lead: 'You\u2019ve explored Notes.',
                strong: 'Next: Meet Maya, your demo bond partner',
                href: '/bonds',
                cta: 'Go to Bonds'
            }
        },
        bonds: {
            progress: '2 / 3',
            title: 'Bonds: Your Shared Space with Maya',
            pill: 'Guest Session',
            body: 'You\u2019re bonded with Maya, your demo partner. Try sending her a Pulse, checking your shared Goals, or writing a Journal entry together.',
            chips: [
                ['Try Pulses:', 'Send a quick emotional check-in to Maya.'],
                ['Set a Goal:', 'Start a savings or project target together.'],
                ['Daily Question:', 'Answer today\u2019s prompt and compare with Maya.'],
                ['Shared Album:', 'Upload a photo memory to your bond.']
            ],
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' },
            next: {
                lead: 'You\u2019ve explored Bonds.',
                strong: 'Next: Send Maya a private message',
                href: '/messages',
                cta: 'Go to Messages'
            }
        },
        messages: {
            progress: '3 / 3',
            title: 'Messages: Chat with Maya',
            pill: 'Guest Session',
            body: 'Maya is online and ready to chat. Send her a message and watch for her real-time reply with typing indicators.',
            chips: [
                ['Send a Message:', 'Type anything to Maya and see her auto-reply.'],
                ['Whisper Mode:', 'Self-destructing chats with session watermarks & capture alerts.'],
                ['Real-Time:', 'Messages deliver instantly with read receipts.']
            ],
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' },
            final: true
        },
        communities: {
            title: 'Communities: Shared Spaces',
            pill: 'Guest Session',
            body: 'Browse existing communities to see how members collaborate through shared notes, writing challenges, and polls. Sign up to create or join one.',
            chips: [
                ['Browse:', 'Explore public community spaces and their content.'],
                ['Challenges:', 'View writing challenges and community activity.'],
                ['Polls:', 'See community polls and discussions in action.']
            ],
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' }
        },
        blog: {
            title: 'Blog: Community Stories',
            pill: 'Guest Session',
            body: 'Read stories and reflections shared by the community. Sign up to publish your own posts and interact with others.',
            chips: [
                ['Read:', 'Browse published posts from the EchoWithin community.'],
                ['React:', 'Sign up to like, comment, and bookmark posts.'],
                ['Write:', 'Sign up to publish your own stories and reflections.']
            ],
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' }
        },
        profile: {
            title: 'Profile: Your Public Identity',
            pill: 'Guest Session',
            body: 'This is your public profile page. Customize your avatar, bio, and view your activity stats. Visit Account Settings to change your theme and privacy preferences.',
            chips: [
                ['Avatar:', 'Upload a profile picture in Account Settings.'],
                ['Bio:', 'Add a short bio that others can see.'],
                ['Theme:', 'Switch between light and dark mode in Settings.'],
                ['Private Vault:', 'Hold down your profile picture to open your secret vault.']
            ],
            primary: { label: 'Got it', cls: 'ew-tour-btn--primary' }
        }
    };

    /* ---------------- shared panel rendering ---------------- */

    function renderHead(panel, tip, onClose) {
        var head = el('div', 'ew-tour-head');
        var left = el('div');
        left.appendChild(el('h4', 'ew-tour-title', tip.title));
        if (tip.pill) left.appendChild(el('span', 'ew-tour-pill', tip.pill));
        head.appendChild(left);
        head.appendChild(closeBtn(onClose));
        panel.appendChild(head);
    }

    function renderFooter(panel, progressText, actions) {
        var foot = el('div', 'ew-tour-footer');
        if (progressText) foot.appendChild(el('span', 'ew-tour-progress', progressText));
        var wrap = el('div', 'ew-tour-actions');
        actions.forEach(function (a) { wrap.appendChild(a); });
        foot.appendChild(wrap);
        panel.appendChild(foot);
    }

    /* ---------------- guest tour flow ---------------- */

    function initGuestTour() {
        var page = currentPage();
        if (!page) return;
        var tip = TIPS[page];
        if (!tip) return;
        var key = TIP_KEY_PREFIX + page;
        if (lsGet(key) === '1') return;

        var panel = ensurePanel();
        var banner = document.querySelector('.tour-mode-banner');

        function dismiss() { lsSet(key, '1'); }

        function renderTip() {
            clearNode(panel);
            panel.hidden = false;
            renderHead(panel, tip, function () { dismiss(); hidePanel(); });
            if (tip.body) {
                var p = el('p', 'ew-tour-body');
                p.innerHTML = tip.body;
                panel.appendChild(p);
            }
            if (tip.chips) {
                var ul = el('ul', 'ew-tour-chips');
                tip.chips.forEach(function (chip) {
                    var li = el('li');
                    li.appendChild(el('strong', null, chip[0]));
                    li.appendChild(document.createTextNode(' ' + chip[1]));
                    ul.appendChild(li);
                });
                panel.appendChild(ul);
            }
            panel.appendChild(urgentNote());

            var actions = [];
            if (tip.secondary && tip.secondary.action === 'share-lesson') {
                actions.push(makeBtn(tip.secondary, function () {
                    if (typeof window.openInteractiveShareLesson === 'function') {
                        window.openInteractiveShareLesson();
                    }
                }));
            }
            actions.push(makeBtn(tip.primary, function () {
                dismiss();
                if (tip.next) renderNext();
                else if (tip.final) renderFinal();
                else hidePanel();
            }));
            renderFooter(panel, tip.progress, actions);
        }

        function renderNext() {
            clearNode(panel);
            panel.hidden = false;
            var next = tip.next;
            renderHead(panel, { title: 'Up next' }, function () { hidePanel(); });
            var p = el('p', 'ew-tour-body', next.lead);
            panel.appendChild(p);
            panel.appendChild(el('p', 'ew-tour-subline', next.strong));
            panel.appendChild(urgentNote());
            renderFooter(panel, tip.progress, [
                el('a', 'ew-tour-btn ew-tour-btn--ghost', 'Not now'),
                (function () {
                    var a = el('a', 'ew-tour-btn ew-tour-btn--primary', next.cta);
                    a.href = next.href;
                    return a;
                })()
            ]);
            var notNow = panel.querySelector('.ew-tour-btn--ghost');
            if (notNow) {
                notNow.addEventListener('click', function (e) { e.preventDefault(); hidePanel(); });
            }
        }

        function renderFinal() {
            clearNode(panel);
            panel.hidden = false;
            var finalCfg = {
                title: 'You\u2019ve explored the core features'
            };
            renderHead(panel, finalCfg, function () { hidePanel(); });
            var p = el('p', 'ew-tour-body');
            p.innerHTML = 'Sign up to keep your notes, connect with real people, and unlock sharing, ' +
                'communities, and more. Confirm your email within 24 hours to keep your data.';
            panel.appendChild(p);

            var links = el('div', 'ew-tour-links');
            [['Communities', '/communities'], ['Blog', '/blog']].forEach(function (l) {
                var a = el('a', null, l[0]);
                a.href = l[1];
                links.appendChild(a);
            });
            if (banner && banner.dataset.profileHref) {
                var pa = el('a', null, 'Profile');
                pa.href = banner.dataset.profileHref;
                links.appendChild(pa);
            }
            panel.appendChild(links);
            panel.appendChild(urgentNote());

            renderFooter(panel, null, [
                el('a', 'ew-tour-btn ew-tour-btn--ghost', 'Keep Exploring'),
                (function () {
                    var a = el('a', 'ew-tour-btn ew-tour-btn--primary', 'Sign Up Free');
                    a.href = '/register';
                    return a;
                })()
            ]);
            var keep = panel.querySelector('.ew-tour-btn--ghost');
            if (keep) {
                keep.addEventListener('click', function (e) { e.preventDefault(); hidePanel(); });
            }
        }

        renderTip();
    }

    /* ---------------- session countdown ---------------- */

    function initCountdown() {
        var banner = document.querySelector('.tour-mode-banner');
        if (!banner || !banner.dataset.expiresAt) return;
        var exp = Date.parse(banner.dataset.expiresAt);
        if (isNaN(exp)) return;
        var out = banner.querySelector('.ew-tour-countdown');
        var note = banner.querySelector('.ew-tour-expiry-note');
        var lastText = '';

        function tick() {
            var left = Math.max(0, Math.round((exp - Date.now()) / 1000));
            var m = Math.floor(left / 60);
            var s = left % 60;
            var text = m + ':' + (s < 10 ? '0' : '') + s;
            if (out && text !== lastText) {
                out.textContent = text;
                lastText = text;
            }
            var urgent = left <= 120;
            if (out) out.classList.toggle('is-urgent', urgent);
            banner.classList.toggle('is-urgent', urgent);
            if (note) note.hidden = !urgent;
            var panelNotes = document.querySelectorAll('.ew-tour-urgent-note');
            for (var i = 0; i < panelNotes.length; i++) panelNotes[i].hidden = !urgent;
        }

        tick();
        setInterval(tick, 1000);
    }

    /* ---------------- new-user onboarding ---------------- */

    var STEP_TEXT = {
        '.copy-btn': 'Copy note text to clipboard',
        '.export-note-btn': 'Export note as Plain Text or Word document',
        '.edit-note-btn': 'Edit note with full markdown formatting',
        '.share-note-btn': 'Share note link or choose a surprise theme with music and photos',
        '.lock-note-btn': 'Lock note behind 4-digit PIN for privacy',
        '.version-history-btn': 'View edit history and restore previous versions',
        '.sync-note-btn': 'Sync changes from original shared note',
        '.delete-btn': 'Delete note from your personal space'
    };

    function buildSteps(noteCard) {
        var row = noteCard.querySelector('.note-actions');
        if (!row) return [];
        var out = [];
        var nodes = row.querySelectorAll('button, a');
        Array.prototype.forEach.call(nodes, function (n) {
            if (!n.matches) return;
            for (var sel in STEP_TEXT) {
                if (n.matches(sel)) {
                    out.push({ target: n, text: STEP_TEXT[sel] });
                    break;
                }
            }
        });
        return out;
    }

    function initOnboarding() {
        var cfg = window.EW_CONFIG;
        if (!cfg || cfg.isGuest) return;

        var force = false;
        try { force = new URLSearchParams(window.location.search).get('tour') === '1'; } catch (e) { }
        if (!force) {
            if (!cfg.isNewUser || lsGet(ONBOARDING_KEY)) return;
        }

        var noteCard = document.querySelector('.note-card[data-note-id]');
        if (!noteCard) return;
        var steps = buildSteps(noteCard);
        if (!steps.length) return;

        var panel = ensurePanel();
        var idx = 0;
        var finished = false;

        function clearHighlights() {
            var prev = document.querySelectorAll('.ew-tour-highlight');
            Array.prototype.forEach.call(prev, function (n) { n.classList.remove('ew-tour-highlight'); });
        }

        function finish() {
            if (finished) return;
            finished = true;
            clearHighlights();
            document.removeEventListener('keydown', onKey);
            lsSet(ONBOARDING_KEY, '1');
            hidePanel();
            try { window.history.replaceState(null, '', window.location.pathname + window.location.search.replace(/[?&]tour=1/, '') + window.location.hash); } catch (e) { }
        }

        function onKey(e) {
            if (finished || panel.hidden) return;
            if (e.key === 'Escape') { finish(); }
            else if (e.key === 'ArrowRight') { show(idx + 1); }
            else if (e.key === 'ArrowLeft') { show(idx - 1); }
        }

        function show(i) {
            if (finished) return;
            if (i >= steps.length) { finish(); return; }
            if (i < 0) i = 0;
            idx = i;

            clearHighlights();
            var step = steps[idx];
            step.target.classList.add('ew-tour-highlight');
            try {
                var r = step.target.getBoundingClientRect();
                if (r.top < 90 || r.bottom > window.innerHeight - 24) {
                    step.target.scrollIntoView({ block: 'center', behavior: 'smooth' });
                }
            } catch (e) { /* ignore */ }

            clearNode(panel);
            panel.hidden = false;
            renderHead(panel, { title: 'Note actions', pill: 'Quick Tour' }, finish);

            var p = el('p', 'ew-tour-body');
            p.textContent = step.text;
            panel.appendChild(p);
            panel.appendChild(urgentNote());

            var actions = [];
            if (idx > 0) {
                actions.push(makeBtn({ label: 'Back', cls: 'ew-tour-btn--ghost' }, function () { show(idx - 1); }));
            }
            actions.push(makeBtn({ label: 'Skip', cls: 'ew-tour-btn--link' }, finish));
            actions.push(makeBtn({
                label: idx === steps.length - 1 ? 'Done' : 'Next',
                cls: 'ew-tour-btn--primary'
            }, function () { show(idx + 1); }));
            renderFooter(panel, (idx + 1) + ' / ' + steps.length, actions);
        }

        document.addEventListener('keydown', onKey);

        var started = false;
        function start() {
            if (started) return;
            started = true;
            setTimeout(function () { show(0); }, 800);
        }
        if (document.readyState === 'complete') start();
        else window.addEventListener('load', start);
    }

    /* ---------------- boot ---------------- */

    consumeFreshFlag();
    if (document.querySelector('.tour-mode-banner')) {
        initCountdown();
        initGuestTour();
    } else {
        initOnboarding();
    }
})();
