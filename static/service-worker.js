// Service worker for EchoWithin PWA
// Provides offline support and faster loads via caching

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
