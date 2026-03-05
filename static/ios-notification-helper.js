// iOS Notification Helper
// Provides utility functions for iOS push notification support.
// The main notification prompt flow is handled in base.html's initPushNotifications.

/**
 * iOS-friendly notification enrollment
 * Call this function when a user clicks a button to enable notifications.
 * Must be called from a user gesture handler (tap/click) on iOS.
 */
async function enableNotificationsIOS() {
    if (!('Notification' in window)) {
        alert('Notifications are not supported on this device');
        return false;
    }
    
    if (!('serviceWorker' in navigator)) {
        alert('Service workers are not supported on this device');
        return false;
    }
    
    try {
        const permission = await Notification.requestPermission();
        
        if (permission === 'granted') {
            const registration = await navigator.serviceWorker.ready;
            
            if (!('PushManager' in window)) {
                console.log('Push notifications not supported');
                return true;
            }
            
            const response = await fetch('/api/push/vapid-public-key');
            if (!response.ok) {
                console.log('Push notifications not configured on server');
                return true;
            }
            
            const { publicKey } = await response.json();
            if (!publicKey) return true;
            
            const applicationServerKey = urlBase64ToUint8Array(publicKey);
            
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: applicationServerKey
            });
            
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
                // Clear any banner dismissal so user sees success next time
                localStorage.setItem('iosNotifBannerDismissed', 'true');
                return true;
            } else {
                console.warn('Failed to save subscription on server');
                return false;
            }
        } else if (permission === 'denied') {
            alert('Notifications are blocked. Please enable them in Settings > Safari > Notifications.');
            return false;
        } else {
            return false;
        }
    } catch (error) {
        console.error('Error enabling notifications:', error);
        alert('Failed to enable notifications. Please try again.');
        return false;
    }
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
    return Notification.permission;
}
