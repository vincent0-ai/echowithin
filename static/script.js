'use strict';

// ==================== Scroll Position Restore ==
// Save scroll position when clicking a post link, restore when navigating back
(function() {
    var LIST_PAGES = ['/blog', '/all_posts', '/home', '/personal_space'];
    var path = location.pathname;
    var key = 'ew_scroll_' + path;

    // On list pages: restore saved scroll position
    var isListPage = LIST_PAGES.some(function(p) { return path === p || path.startsWith(p + '?'); });
    if (isListPage) {
        var saved = sessionStorage.getItem(key);
        if (saved) {
            sessionStorage.removeItem(key);
            var y = parseInt(saved, 10);
            // Script runs after DOMContentLoaded (defer), so content is parsed.
            // Wait for images/layout to settle, then scroll.
            requestAnimationFrame(function() {
                window.scrollTo(0, y);
                // Second attempt after a short delay in case lazy content shifts layout
                setTimeout(function() { window.scrollTo(0, y); }, 200);
            });
        }
    }

    // Capture scroll position when clicking a post link
    document.addEventListener('click', function(e) {
        var link = e.target.closest('a.record-view-link');
        if (!link) return;
        sessionStorage.setItem('ew_scroll_' + location.pathname, window.scrollY);
    });
})();

// ==================== Local Timezone Conversion ====================
// Server timestamps from MongoDB are persisted as naive UTC. Python's
// .isoformat() on a naive datetime renders without a 'Z' / '+00:00' suffix,
// so the browser's `new Date(iso)` constructor interprets the string in the
// *local* timezone — producing a visible offset of `(localOffset - 0)` hours.
// This helper guarantees the string is always parsed as UTC by appending a
// 'Z' when no timezone designator is present. Use this for ANY datetime that
// originated from the server (REST, socketio, data-timestamp attribute).
function parseServerTime(iso) {
    if (!iso) return null;
    if (iso instanceof Date) return iso;
    let s = String(iso).trim();
    if (!s) return null;
    // Already has a timezone designator (Z, +hh:mm, -hh:mm after the time part)?
    var hasTz = /[zZ]$/.test(s) || /[+\-]\d{2}:?\d{2}$/.test(s);
    if (!hasTz) s += 'Z';
    var d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
}
window.parseServerTime = parseServerTime;

// Convert all timestamps to user's local timezone
function convertToLocalTime() {
    const timeElements = document.querySelectorAll('time.local-time');
    
    timeElements.forEach(el => {
        // Skip if already converted to prevent infinite loops from MutationObserver
        if (el.hasAttribute('data-converted')) return;
        
        const isoString = el.getAttribute('datetime');
        if (!isoString) return;
        
        try {
            const date = parseServerTime(isoString);
            if (!date) return; // Invalid date
            
            // Format options for display
            const options = {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            };
            
            // Format to user's local timezone
            const localTimeString = date.toLocaleDateString('en-US', options);
            el.textContent = localTimeString;
            el.title = date.toLocaleString(); // Full date on hover
            el.setAttribute('data-converted', 'true'); // Mark as converted
        } catch (e) {
            console.error('Error converting time:', e);
        }
    });
}

// Run on page load
document.addEventListener('DOMContentLoaded', convertToLocalTime);

// Also run after any dynamic content loads (for AJAX-loaded posts)
if (typeof MutationObserver !== 'undefined') {
    let _convertTimer = null;
    const observer = new MutationObserver((mutations) => {
        // Only schedule conversion if new nodes actually contain time elements
        let hasTimeNodes = false;
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === 1 && (node.matches?.('time.local-time') ||
                    node.querySelector?.('time.local-time'))) {
                    hasTimeNodes = true;
                    break;
                }
            }
            if (hasTimeNodes) break;
        }
        if (hasTimeNodes) {
            clearTimeout(_convertTimer);
            _convertTimer = setTimeout(convertToLocalTime, 50);
        }
    });
    
    // Start observing once DOM is ready
    document.addEventListener('DOMContentLoaded', () => {
        observer.observe(document.body, { childList: true, subtree: true });
    });
}

// ==================== Auth Tab Switching ====================
const loginTab = document.getElementById('login-tab');
const registerTab = document.getElementById('register-tab');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');

const showLogin = () => {
    loginTab.classList.add('active');
    registerTab.classList.remove('active');
    loginForm.classList.add('active');
    registerForm.classList.remove('active');
};

const showRegister = () => {
    registerTab.classList.add('active');
    loginTab.classList.remove('active');
    registerForm.classList.add('active');
    loginForm.classList.remove('active');
};

// Only add event listeners if the tab elements exist on the page
if (loginTab && registerTab) {
    loginTab.addEventListener('click', showLogin);
    registerTab.addEventListener('click', showRegister);
}

// === Dark Mode / Theme Toggle ===
window.toggleTheme = function() {
    var html = document.documentElement;
    var current = html.getAttribute('data-theme') || 'light';
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('echowithin-theme', next);
    updateThemeIcon(next);
    updateThemeColor(next);
    // Sync to backend if logged in
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
        fetch('/api/profile/theme', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfMeta.getAttribute('content') },
            body: JSON.stringify({ theme: next })
        }).catch(function() {});
    }
};

function updateThemeIcon(theme) {
    var icons = document.querySelectorAll('#theme-icon');
    icons.forEach(function(icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    });
}

function updateThemeColor(theme) {
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
        meta.setAttribute('content', theme === 'dark' ? '#1a1410' : '#ffffff');
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    var theme = document.documentElement.getAttribute('data-theme') || 'light';
    updateThemeIcon(theme);
    updateThemeColor(theme);
    // Listen for system preference changes
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
            if (!localStorage.getItem('echowithin-theme')) {
                var newTheme = e.matches ? 'dark' : 'light';
                document.documentElement.setAttribute('data-theme', newTheme);
                updateThemeIcon(newTheme);
                updateThemeColor(newTheme);
            }
        });
    }
});
