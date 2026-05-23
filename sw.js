
importScripts('./version.js');

const CONFIG = {
    version: APP_VERSION, 
    cachePrefix: 'mexe-',
    tileCacheLimit: 2000,
    tileCachePrefix: 'tiles-',
    maxRetries: 3,
    retryDelay: 1000,
};

const CACHE_NAMES = {
    static: `${CONFIG.cachePrefix}static-${CONFIG.version}`,
    dynamic: `${CONFIG.cachePrefix}dynamic-${CONFIG.version}`,
    tiles: `${CONFIG.tileCachePrefix}${CONFIG.version}`
};

const CRITICAL_ASSETS = [
    './',
    './index.html',
    './styles.css',
    './scripts.js',
    './auth.js',
    './env.js',
    './sw-register.js',
    './oauth-callback.html',
    './manifest.json',
    './imagens/logo.png',
    './libs/leaflet-1.7.1/leaflet.css',
    './libs/leaflet-1.7.1/leaflet.js',
    './libs/d3-7.8.5/d3.min.js',
    './libs/localforage-1.10.0/localforage.min.js'
];

const OPTIONAL_ASSETS = [
    './icons/icon-72x72.png',
    './icons/icon-96x96.png',
    './icons/icon-144x144.png',
    './icons/icon-152x152.png',
    './icons/icon-192.png',
    './icons/icon-384x384.png',
    './icons/icon-512x512.png',
    './libs/leaflet-1.7.1/images/marker-icon.png',
    './libs/leaflet-1.7.1/images/marker-icon-2x.png',
    './libs/leaflet-1.7.1/images/marker-shadow.png',
    './libs/leaflet-1.7.1/images/layers.png',
    './libs/leaflet-1.7.1/images/layers-2x.png'
];

async function retry(fn, retries = CONFIG.maxRetries, delay = CONFIG.retryDelay) {
    try {
        return await fn();
    } catch (error) {
        if (retries > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
            return retry(fn, retries - 1, delay * 2);
        }
        throw error;
    }
}

async function cleanupOldCaches() {
    const cacheKeys = await caches.keys();
    const oldCaches = cacheKeys.filter(key => 
        (key.startsWith(CONFIG.cachePrefix) || key.startsWith(CONFIG.tileCachePrefix)) && !Object.values(CACHE_NAMES).includes(key)
    );
    console.log('Cleaning old caches:', oldCaches);
    return Promise.all(oldCaches.map(key => caches.delete(key)));
}

self.addEventListener('install', event => {
    event.waitUntil(
        (async () => {
            try {
                const cache = await caches.open(CACHE_NAMES.static);
                await retry(() => cache.addAll(CRITICAL_ASSETS));
                cache.addAll(OPTIONAL_ASSETS).catch(console.warn);
                await self.skipWaiting();
            } catch (error) {
                console.error('Error during SW install:', error);
                throw error;
            }
        })()
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        (async () => {
            try {
                await cleanupOldCaches();
                await self.clients.claim();
                console.log('Service Worker activated successfully');
            } catch (error) {
                console.error('Error during SW activation:', error);
                throw error;
            }
        })()
    );
});

async function networkFirst(request, cacheName) {
    try {
        const response = await fetch(request);
        if (response.ok) {
            const cache = await caches.open(cacheName);
            await cache.put(request.clone(), response.clone());
            return response;
        }
    } catch (error) {
        console.warn(`Network failed for ${request.url}, trying cache:`, error);
    }
    
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    
    if (cached) {
        return cached;
    }
    
    if (request.mode === 'navigate') {
       return new Response("You are offline and this page is not cached.", {
           status: 404,
           statusText: "Offline",
           headers: {'Content-Type': 'text/plain'}
       });
    }

    return new Response('', { status: 503, statusText: 'Service Unavailable' });
}

async function handleMapTile(request) {
    try {
        const cache = await caches.open(CACHE_NAMES.tiles);
        let response = await cache.match(request);
        
        if (response) {
            return response;
        }
        
        response = await fetch(request);
        if (response.ok) {
            await cache.put(request, response.clone());
        }
        
        return response;
    } catch (error) {
        console.error('Error handling map tile:', error);
        throw error;
    }
}

self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);

    if (!url.protocol.startsWith('http')) {
        return;
    }

    // Ignore auth requests to avoid caching sensitive payloads
    if (url.pathname.startsWith('/api/auth/') || url.pathname.startsWith('/api-proxy/')) {
        event.respondWith(fetch(request));
        return;
    }

    // Always prefer fresh auth/client bootstrap files to avoid stale OAuth/login logic.
    if (
        url.pathname === '/auth.js' ||
        url.pathname === '/oauth-callback.html' ||
        url.pathname === '/index.html' ||
        url.pathname === '/scripts.js' ||
        url.pathname === '/version.js' ||
        url.pathname === '/env.js' ||
        url.pathname === '/sw-register.js'
    ) {
        event.respondWith(networkFirst(request, CACHE_NAMES.dynamic));
        return;
    }

    if (url.hostname.includes('tile.openstreetmap.org')) {
        event.respondWith(handleMapTile(request));
        return;
    }

    event.respondWith(
        caches.open(CACHE_NAMES.static).then(staticCache => {
            return staticCache.match(request).then(cachedResponse => {
                if (cachedResponse) {
                    return cachedResponse;
                }

                return networkFirst(request, CACHE_NAMES.dynamic);
            });
        })
    );
});

self.addEventListener('message', event => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});
