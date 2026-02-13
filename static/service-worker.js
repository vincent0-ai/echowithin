// Service worker for EchoWithin PWA
// Provides offline support, faster loads via caching, and push notifications
// Note: iOS has limited push notification support (requires iOS 16.4+ and user interaction)

const CACHE_NAME = 'echowithin-v7';
const STATIC_CACHE = 'echowithin-static-v7';
const PAGES_CACHE = 'echowithin-pages-v7';
const POSTS_CACHE = 'echowithin-posts-v7';

// Static assets to cache immediately on install
const STATIC_ASSETS = [
  '/static/style.css',
  '/static/custom_styles.css',
  '/static/script.js',
  '/static/logo.png',
  '/static/manifest.json'
];

// Pages to cache for offline access
const PAGES_TO_CACHE = [
  '/',
  '/offline',
  '/home',
  '/blog',
  '/about',
  '/personal_space'
];

// Install event: cache critical assets
self.addEventListener('install', event => {
  event.waitUntil(
    Promise.all([
      // Cache static assets
      caches.open(STATIC_CACHE).then(cache => {
        return cache.addAll(STATIC_ASSETS).catch(err => {
          console.warn('Static cache addAll failed:', err);
        });
      }),
      // Cache main pages
      caches.open(PAGES_CACHE).then(cache => {
        return cache.addAll(PAGES_TO_CACHE).catch(err => {
          console.warn('Pages cache addAll failed:', err);
        });
      })
    ])
  );
  self.skipWaiting();
});

// Activate event: clean up old caches
self.addEventListener('activate', event => {
  const currentCaches = [STATIC_CACHE, PAGES_CACHE, POSTS_CACHE];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (!currentCaches.includes(cacheName) && cacheName.startsWith('echowithin')) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event: Network-first for pages, Cache-first for static assets
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip external requests
  if (url.origin !== location.origin) {
    return;
  }

  // Skip API requests - they should always go to network
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Static assets: Cache-first strategy
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(request).then(cachedResponse => {
        if (cachedResponse) {
          // Return cached, but also update cache in background
          event.waitUntil(
            fetch(request).then(response => {
              if (response && response.status === 200) {
                caches.open(STATIC_CACHE).then(cache => {
                  cache.put(request, response);
                });
              }
            }).catch(() => { })
          );
          return cachedResponse;
        }
        return fetch(request).then(response => {
          if (response && response.status === 200) {
            const respClone = response.clone();
            caches.open(STATIC_CACHE).then(cache => {
              cache.put(request, respClone);
            });
          }
          return response;
        });
      })
    );
    return;
  }

  // Post pages: Network-first with cache fallback, and cache successful responses
  if (url.pathname.startsWith('/post/')) {
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response && response.status === 200) {
            const respClone = response.clone();
            caches.open(POSTS_CACHE).then(cache => {
              cache.put(request, respClone);
            });
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then(cachedResponse => {
            if (cachedResponse) {
              return cachedResponse;
            }
            // Return offline page if post not cached
            return caches.match('/offline');
          });
        })
    );
    return;
  }

  // Navigation requests: Network-first with cache fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response && response.status === 200) {
            const respClone = response.clone();
            caches.open(PAGES_CACHE).then(cache => {
              cache.put(request, respClone);
            });
          }
          return response;
        })
        .catch(() => {
          return caches.match(request).then(cachedResponse => {
            if (cachedResponse) {
              return cachedResponse;
            }
            // Try to match the pathname without query params
            return caches.match(url.pathname).then(pathMatch => {
              if (pathMatch) {
                return pathMatch;
              }
              return caches.match('/offline');
            });
          });
        })
    );
    return;
  }

  // Default: Network with cache fallback
  event.respondWith(
    fetch(request)
      .then(response => {
        return response;
      })
      .catch(() => {
        return caches.match(request);
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
