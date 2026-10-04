// SPDX-License-Identifier: MIT
// functions/_middleware.js — Cloudflare Pages middleware
//
// Runs on every request to every URL on wallet.qwertycoin.org. We use it to
// override Cloudflare Pages' built-in static-asset Cache-Control default
// (which sets max-age=14400 / 4 hours on .js files and ignores _headers
// rules for those paths). For an actively-developing wallet that default
// is wrong — every push to main needs users to wait up to 4 hours or
// hard-reload before they see the fix.
//
// What this does:
//   • For missing extensionless page routes → redirect to /verify
//     (missing assets and API routes remain real 404 responses)
//   • For HTML, JS, JSON, MANIFEST.txt, /api/* → max-age=0, must-revalidate
//     (browser asks Cloudflare on every reload; Cloudflare returns 304 via
//      ETag if unchanged — cheap)
//   • For /fonts/* → keep the long immutable cache (filename-hashed)
//   • For everything else → leave Pages' default in place
//
// Cost per request: ~0 (we just rewrite a header on the existing response;
// no extra network or storage). Counts toward Functions invocations but
// only marginally because Cloudflare Pages serves static assets from the
// edge cache anyway — the function only re-headers them.

export async function onRequest (context) {
  const response = await context.next();
  const url = new URL(context.request.url);
  const path = url.pathname;

  // A top-level 404.html disables Cloudflare Pages' implicit SPA fallback,
  // which otherwise serves the legacy index.html with status 200 for typos
  // such as /ver. Send browser-like page routes to the canonical wallet entry
  // while preserving real 404s for missing assets and API endpoints.
  const isPageRoute =
    (context.request.method === 'GET' || context.request.method === 'HEAD') &&
    !path.startsWith('/api/') &&
    !/\.[a-z0-9]+$/i.test(path);

  if (response.status === 404 && isPageRoute) {
    return Response.redirect(new URL('/verify', url), 302);
  }

  // Long cache for content-addressed fonts (filename hash → URL changes
  // when content changes, so any cached copy is automatically invalidated).
  if (path.startsWith('/fonts/')) {
    const r = new Response(response.body, response);
    r.headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    return r;
  }

  // Force revalidation on everything that can change between deploys:
  // HTML pages (clean URLs and .html), all JS, JSON, the manifest, and
  // the API proxy responses.
  const needsRevalidation =
    path.endsWith('.html') ||
    path.endsWith('.js')   ||
    path.endsWith('.json') ||
    path === '/MANIFEST.txt' ||
    path.startsWith('/api/') ||
    // Clean URLs (no extension) — every Pages route that resolves to an
    // HTML file. The catch-all is "any path that doesn't have an extension".
    !/\.[a-z0-9]+$/i.test(path);

  if (needsRevalidation) {
    const r = new Response(response.body, response);
    r.headers.set('Cache-Control', 'public, max-age=0, must-revalidate');
    return r;
  }

  return response;
}
