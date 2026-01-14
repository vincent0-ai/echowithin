'use strict'

// ==================== Local Timezone Conversion ====================
// Convert all timestamps to user's local timezone
function convertToLocalTime() {
    const timeElements = document.querySelectorAll('time.local-time');
    
    timeElements.forEach(el => {
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
