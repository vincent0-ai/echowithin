// iOS Notification Helper - Add this to your script.js or create a separate file

/**
 * iOS-friendly notification enrollment
 * Call this function when a user clicks a button to enable notifications
 */
async function enableNotificationsIOS() {
    // Check if notifications are supported
    if (!('Notification' in window)) {
        alert('Notifications are not supported on this device');
        return false;
    }
    
    // Check if service worker is supported
    if (!('serviceWorker' in navigator)) {
        alert('Service workers are not supported on this device');
        return false;
    }
    
    try {
        // Request permission (requires user interaction on iOS)
        const permission = await Notification.requestPermission();
        
        if (permission === 'granted') {
            // Get the service worker registration
            const registration = await navigator.serviceWorker.ready;
            
            // Check if push manager is available
            if (!('PushManager' in window)) {
                console.log('Push notifications not supported');
                // Still show success message since we have notification permission
                return true;
            }
            
            // Get VAPID key from server
            const response = await fetch('/api/push/vapid-public-key');
            if (!response.ok) {
                console.log('Push notifications not configured on server');
                return true;
            }
            
            const { publicKey } = await response.json();
            if (!publicKey) return true;
            
            // Convert the public key to Uint8Array
            const applicationServerKey = urlBase64ToUint8Array(publicKey);
            
            // Subscribe to push
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: applicationServerKey
            });
            
            // Send subscription to server
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            const subResponse = await fetch('/api/push/subscribe', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify(subscription.toJSON())
            });
            
            if (subResponse.ok) {
                console.log('Successfully subscribed to push notifications');
                return true;
            } else {
                console.warn('Failed to save subscription on server');
                return false;
            }
        } else if (permission === 'denied') {
            alert('Notifications are blocked. Please enable them in your browser settings.');
            return false;
        } else {
            // User dismissed the dialog
            return false;
        }
    } catch (error) {
        console.error('Error enabling notifications:', error);
        alert('Failed to enable notifications. Please try again.');
        return false;
    }
}

/**
 * Helper function to convert VAPID key
 */
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');
    
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

/**
 * Check if user is on iOS
 */
function isIOSDevice() {
    return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
}

/**
 * Get notification permission status
 */
function getNotificationStatus() {
    if (!('Notification' in window)) {
        return 'not-supported';
    }
    return Notification.permission; // 'default', 'granted', or 'denied'
}

// Example: Add this to your page to show a notification button for iOS users
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is logged in and on iOS
    const isLoggedIn = document.body.dataset.userLoggedIn === 'true'; // Set this in your template
    
    if (isLoggedIn && isIOSDevice()) {
        const notificationStatus = getNotificationStatus();
        
        if (notificationStatus === 'default') {
            // Show a UI element prompting the user to enable notifications
            showNotificationPrompt();
        }
    }
});

/**
 * Show a custom notification prompt UI
 * You can customize this to match your app's design
 */
function showNotificationPrompt() {
    // Only show if we haven't shown it before in this session
    if (sessionStorage.getItem('notificationPromptShown')) {
        return;
    }
    
    // Create a simple banner
    const banner = document.createElement('div');
    banner.id = 'notification-banner';
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: #007AFF;
        color: white;
        padding: 15px;
        text-align: center;
        z-index: 10000;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    `;
    
    banner.innerHTML = `
        <div style="max-width: 600px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
            <span style="flex: 1; min-width: 200px;">📱 Get notified about new posts and updates</span>
            <div style="display: flex; gap: 10px;">
                <button id="enable-notifications-btn" style="background: white; color: #007AFF; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; font-weight: bold;">
                    Enable
                </button>
                <button id="dismiss-notifications-btn" style="background: transparent; color: white; border: 1px solid white; padding: 8px 16px; border-radius: 5px; cursor: pointer;">
                    Not Now
                </button>
            </div>
        </div>
    `;
    
    document.body.prepend(banner);
    
    // Add event listeners
    document.getElementById('enable-notifications-btn').addEventListener('click', async function() {
        const success = await enableNotificationsIOS();
        if (success) {
            banner.innerHTML = '<div style="padding: 5px;">✅ Notifications enabled!</div>';
            setTimeout(() => banner.remove(), 2000);
        }
        sessionStorage.setItem('notificationPromptShown', 'true');
    });
    
    document.getElementById('dismiss-notifications-btn').addEventListener('click', function() {
        banner.remove();
        sessionStorage.setItem('notificationPromptShown', 'true');
    });
}
