// Service worker for EchoWithin PWA
// Provides offline support, faster loads via caching, and push notifications

const CACHE_NAME = 'echowithin-v1';
const URLS_TO_CACHE = [
  '/',
  '/static/style.css',
  '/static/custom_styles.css',
  '/static/script.js',
  '/static/logo.png',
  '/static/coffee-bean.png'
];

// Install event: cache critical assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(URLS_TO_CACHE).catch(err => {
        console.warn('Cache addAll failed:', err);
        // Continue even if some assets fail to cache
      });
    })
  );
  self.skipWaiting();
});

// Activate event: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event: serve from cache, fallback to network
self.addEventListener('fetch', event => {
  const { request } = event;
  
  // Skip requests that are not GET
  if (request.method !== 'GET') {
    return;
  }

  event.respondWith(
    caches.match(request).then(response => {
      if (response) {
        return response;
      }
      return fetch(request)
        .then(response => {
          // Cache successful responses for static assets
          if (response && response.status === 200 && request.url.includes('/static/')) {
            const respClone = response.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(request, respClone);
            });
          }
          return response;
        })
        .catch(err => {
          console.log('Fetch failed; returning offline page or cached response', err);
          // Could return a custom offline page here
          return null;
        });
    })
  );
});

// Push notification event handler
self.addEventListener('push', event => {
  console.log('Push notification received:', event);
  
  let data = {
    title: 'EchoWithin',
    body: 'You have a new notification',
    url: '/',
    tag: 'echowithin',
    icon: '/static/logo.png',
    badge: '/static/logo.png'
  };
  
  if (event.data) {
    try {
      data = { ...data, ...event.data.json() };
    } catch (e) {
      console.warn('Failed to parse push data:', e);
      data.body = event.data.text();
    }
  }
  
  const options = {
    body: data.body,
    icon: data.icon || '/static/logo.png',
    badge: data.badge || '/static/logo.png',
    tag: data.tag || 'echowithin',
    data: { url: data.url || '/' },
    vibrate: [100, 50, 100],
    requireInteraction: false,
    actions: [
      { action: 'open', title: 'Open' },
      { action: 'close', title: 'Dismiss' }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Notification click event handler
self.addEventListener('notificationclick', event => {
  console.log('Notification clicked:', event);
  event.notification.close();
  
  if (event.action === 'close') {
    return;
  }
  
  const urlToOpen = event.notification.data?.url || '/';
  
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      // Check if there's already a window open with this URL
      for (let client of windowClients) {
        if (client.url === urlToOpen && 'focus' in client) {
          return client.focus();
        }
      }
      // If no matching window, open a new one
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});

// Handle push subscription change (e.g., when browser refreshes subscription)
self.addEventListener('pushsubscriptionchange', event => {
  console.log('Push subscription changed:', event);
  
  event.waitUntil(
    // Re-subscribe and update the server
    self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: event.oldSubscription?.options?.applicationServerKey
    }).then(subscription => {
      // Send the new subscription to the server
      return fetch('/api/push/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(subscription.toJSON())
      });
    }).catch(err => {
      console.error('Failed to re-subscribe:', err);
    })
  );
});
