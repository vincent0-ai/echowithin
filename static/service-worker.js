// Service worker for EchoWithin PWA
// Provides offline support, faster loads via caching, and push notifications
// Note: iOS has limited push notification support (requires iOS 16.4+ and user interaction)

const CACHE_NAME = 'echowithin-v18';
const STATIC_CACHE = 'echowithin-static-v18';
const PAGES_CACHE = 'echowithin-pages-v18';
const POSTS_CACHE = 'echowithin-posts-v18';

// Static assets to cache immediately on install
const STATIC_ASSETS = [
  '/static/style.css',
  '/static/custom_styles.css',
  '/static/script.js',
  '/static/logo-192.png',
  '/static/manifest.json'
];

// Pages to cache for offline access
// Note: /home, /personal_space are login-required so they can't be pre-cached.
// They get cached on first authenticated visit via the fetch handler.
const PAGES_TO_CACHE = [
  '/',
  '/offline',
  '/blog',
  '/about'
];

// Minimal offline HTML served when /offline isn't cached
const FALLBACK_OFFLINE_HTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline - EchoWithin</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f9fa;color:#1e293b;text-align:center}button{margin-top:1rem;padding:.75rem 1.5rem;background:#667eea;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer}</style></head><body><div><h1>You're Offline</h1><p>Please check your connection and try again.</p><button onclick="location.reload()">Try Again</button></div><script>window.addEventListener('online',()=>location.reload());if(window.Capacitor&&window.Capacitor.isNativePlatform&&window.Capacitor.isNativePlatform()&&window.Capacitor.Plugins&&window.Capacitor.Plugins.SplashScreen){window.Capacitor.Plugins.SplashScreen.hide();}</script></body></html>`;

async function putFallbackOfflinePage() {
  const pagesCache = await caches.open(PAGES_CACHE);
  await pagesCache.put('/offline', new Response(FALLBACK_OFFLINE_HTML, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    }
  }));
}

async function safePrecache(cacheName, urls) {
  const cache = await caches.open(cacheName);
  for (const url of urls) {
    try {
      const request = new Request(url, { cache: 'reload' });
      const response = await fetch(request);
      if (response && (response.ok || response.type === 'opaqueredirect')) {
        await cache.put(url, response);
      } else {
        console.warn('Precache skipped (bad response):', url, response && response.status);
      }
    } catch (err) {
      console.warn('Precache failed:', url, err);
    }
  }
}

function offlineFallbackResponse() {
  return caches.match('/offline').then(offlinePage => {
    return offlinePage || new Response(FALLBACK_OFFLINE_HTML, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  });
}

// Install event: cache critical assets
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    // Ensure a local offline fallback is present even if network precache fails.
    await putFallbackOfflinePage();
    await safePrecache(STATIC_CACHE, STATIC_ASSETS);
    await safePrecache(PAGES_CACHE, PAGES_TO_CACHE);
    await putFallbackOfflinePage();
  })());
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

  // For non-GET requests (e.g. form POSTs), try network and fall back to offline page
  if (request.method !== 'GET') {
    if (request.mode === 'navigate') {
      event.respondWith(
        fetch(request).catch(() => offlineFallbackResponse())
      );
    }
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

  // Key pages: Network-first with cache fallback.
  // Always fetch fresh HTML so auth state (logged-in navbar) is correct,
  // but cache responses for offline access.
  const KEY_PAGES = ['/blog', '/home', '/personal_space', '/'];
  if (KEY_PAGES.includes(url.pathname) && !url.search) {
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
            if (cachedResponse) return cachedResponse;
            return offlineFallbackResponse();
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
            return offlineFallbackResponse();
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
              // Always return a valid Response — never undefined
              return offlineFallbackResponse();
            });
          });
        })
    );
    return;
  }

  // Default: Network only for remaining requests
  event.respondWith(
    fetch(request)
      .then(response => {
        return response;
      })
      .catch(() => {
        const acceptHeader = request.headers.get('accept') || '';
        if (request.mode === 'navigate' || acceptHeader.includes('text/html')) {
          return offlineFallbackResponse();
        }
        return caches.match(request);
      })
  );
});

// Push notification event handler
self.addEventListener('push', event => {
  console.log('Push notification received:', event);

  function normalizeNotificationTarget(payload) {
    const rawTarget = payload.url || payload.path || payload.deepLink || payload.deeplink || '/';
    if (!rawTarget) return '/';
    if (typeof rawTarget !== 'string') return '/';
    if (rawTarget.startsWith('http://') || rawTarget.startsWith('https://')) {
      try {
        const targetUrl = new URL(rawTarget);
        if (targetUrl.origin === self.location.origin) {
          return targetUrl.pathname + targetUrl.search + targetUrl.hash;
        }
      } catch (_) {
        return '/';
      }
      return '/';
    }
    return rawTarget.startsWith('/') ? rawTarget : `/${rawTarget}`;
  }

  let data = {
    title: 'EchoWithin',
    body: 'You have a new notification',
    url: '/',
    tag: 'echowithin',
    icon: '/static/logo-192.png',
    badge: '/static/logo-96.png'
  };

  if (event.data) {
    try {
      data = { ...data, ...event.data.json() };
    } catch (e) {
      console.warn('Failed to parse push data:', e);
      data.body = event.data.text();
    }
  }

  const targetUrl = normalizeNotificationTarget(data);

  const tag = data.tag || 'echowithin';
  const isDM = tag.startsWith('dm-');

  // Resolve relative paths to absolute URLs (fixes PWA notification icons)
  function toAbsoluteUrl(path) {
    if (!path) return path;
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    return self.location.origin + path;
  }
  const icon = toAbsoluteUrl(data.icon || '/static/logo-192.png');
  const badge = toAbsoluteUrl(data.badge || '/static/logo-96.png');

  event.waitUntil(
    (isDM
      ? // For DM notifications: check existing ones with same tag and collapse
        self.registration.getNotifications({ tag }).then(existing => {
          // Count how many we've already shown from this sender
          const prevCount = existing.length > 0 && existing[0].data?.messageCount
            ? existing[0].data.messageCount
            : (existing.length > 0 ? 1 : 0);
          const newCount = prevCount + 1;

          // Extract sender name from title like "New message from Username"
          const senderMatch = data.title.match(/from (.+)$/);
          const senderName = senderMatch ? senderMatch[1] : 'someone';

          const title = newCount > 1
            ? `${newCount} new messages from ${senderName}`
            : data.title;
          const body = newCount > 1
            ? `Tap to open conversation`
            : data.body;

          // Close old ones first
          existing.forEach(n => n.close());

          return self.registration.showNotification(title, {
            body,
            icon,
            badge,
            tag,
            renotify: true,
            data: { url: targetUrl, messageCount: newCount },
            vibrate: [100, 50, 100],
            requireInteraction: false,
            actions: [
              { action: 'open', title: 'Open' },
              { action: 'close', title: 'Dismiss' }
            ]
          });
        })
      : // For non-DM notifications: keep default behavior
        self.registration.showNotification(data.title, {
          body: data.body,
          icon,
          badge,
          tag,
          renotify: !!data.tag,
          data: { url: targetUrl },
          vibrate: [100, 50, 100],
          requireInteraction: false,
          actions: [
            { action: 'open', title: 'Open' },
            { action: 'close', title: 'Dismiss' }
          ]
        })
    ).then(() => updateBadgeFromServer())
  );
});

// Fetch unread count from server and set app badge
async function updateBadgeFromServer() {
  if (!('setAppBadge' in navigator)) return;
  try {
    const response = await fetch('/api/notifications/unread-count', { credentials: 'same-origin' });
    if (response.ok) {
      const data = await response.json();
      const count = data.count || 0;
      if (count > 0) {
        await navigator.setAppBadge(count);
      } else {
        await navigator.clearAppBadge();
      }
    }
  } catch (err) {
    // Non-critical - silently fail
  }
}

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
      // Navigate an existing window to the URL instead of opening a new one.
      // This is critical for iOS PWA where openWindow opens Safari instead of
      // navigating the standalone PWA window.
      for (let client of windowClients) {
        if ('navigate' in client) {
          return client.navigate(urlToOpen).then(c => c ? c.focus() : null);
        }
      }
      // Fallback: open a new window (desktop browsers)
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
        credentials: 'same-origin',
        body: JSON.stringify(subscription.toJSON())
      });
    }).catch(err => {
      console.error('Failed to re-subscribe:', err);
    })
  );
});
