/// <reference lib="webworker" />

const STATIC_CACHE = "intelfeed-static-v2";
const ARTICLE_CACHE = "intelfeed-articles-v1";

// Static assets to precache on install
const PRECACHE_URLS = ["/", "/manifest.webmanifest", "/theme-init.js"];

// Install: precache shell (non-fatal — SW installs even if precaching fails)
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then((cache) =>
        Promise.allSettled(
          PRECACHE_URLS.map((url) =>
            cache.add(url).catch(() => {
              // Individual precache failure is non-fatal
            })
          )
        )
      )
      .then(() => self.skipWaiting())
  );
});

// Activate: clean old caches, claim clients immediately
self.addEventListener("activate", (event) => {
  const CURRENT_CACHES = [STATIC_CACHE, ARTICLE_CACHE];
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => !CURRENT_CACHES.includes(name))
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

// Fetch strategy:
// - API requests: network only (don't cache dynamic data)
// - Static assets (JS/CSS/images): stale-while-revalidate
// - Navigation: network-first with offline fallback
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET and cross-origin
  if (request.method !== "GET" || url.origin !== self.location.origin) {
    return;
  }

  // API requests: network only
  if (url.pathname.startsWith("/api/")) {
    return;
  }

  // Static assets: stale-while-revalidate
  if (
    url.pathname.match(
      /\.(js|css|png|jpg|jpeg|svg|ico|woff2?|ttf|webmanifest)$/
    )
  ) {
    event.respondWith(
      caches.open(STATIC_CACHE).then((cache) =>
        cache.match(request).then((cached) => {
          const fetched = fetch(request).then((response) => {
            if (response.ok) {
              cache.put(request, response.clone());
            }
            return response;
          });
          return cached || fetched;
        })
      )
    );
    return;
  }

  // Navigation: network-first with offline fallback
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match("/") || new Response("Offline"))
    );
    return;
  }
});

// Handle messages from the app
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "CACHE_ARTICLE") {
    const { url, html } = event.data;
    caches.open(ARTICLE_CACHE).then((cache) => {
      cache.put(
        new Request(url),
        new Response(html, {
          headers: { "Content-Type": "text/html" },
        })
      );
    });
  }

  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});
