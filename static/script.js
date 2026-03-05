'use strict'

// ==================== Scroll Position Restore ====================
// Save scroll position when clicking a post link, restore when navigating back
(function() {
    var LIST_PAGES = ['/blog', '/all_posts', '/home', '/personal_space'];
    var path = location.pathname;

    // On list pages: restore saved scroll position
    var isListPage = LIST_PAGES.some(function(p) { return path === p || path.startsWith(p + '?'); });
    if (isListPage) {
        var saved = sessionStorage.getItem('ew_scroll_' + path);
        if (saved) {
            sessionStorage.removeItem('ew_scroll_' + path);
            // Use requestAnimationFrame to wait for layout, then scroll
            window.addEventListener('DOMContentLoaded', function() {
                requestAnimationFrame(function() {
                    window.scrollTo(0, parseInt(saved, 10));
                });
            });
        }
    }

    // On any page: capture scroll position when clicking a post link
    document.addEventListener('click', function(e) {
        var link = e.target.closest('a.record-view-link');
        if (!link) return;
        var refPage = location.pathname;
        sessionStorage.setItem('ew_scroll_' + refPage, window.scrollY);
    });
})();

// ==================== Local Timezone Conversion ====================
// Convert all timestamps to user's local timezone
function convertToLocalTime() {
    const timeElements = document.querySelectorAll('time.local-time');
    
    timeElements.forEach(el => {
        // Skip if already converted to prevent infinite loops from MutationObserver
        if (el.hasAttribute('data-converted')) return;
        
        const isoString = el.getAttribute('datetime');
        if (!isoString) return;
        
        try {
            const date = new Date(isoString);
            if (isNaN(date.getTime())) return; // Invalid date
            
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
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.addedNodes.length) {
                convertToLocalTime();
            }
        });
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
