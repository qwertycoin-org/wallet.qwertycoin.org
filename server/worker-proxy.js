// Cloudflare Worker: monero-proxy.rosawands4.workers.dev
//
// Validates Turnstile token before forwarding requests to the VPS.
// After a successful Turnstile check, issues a short-lived session
// token (HMAC-signed) so the client doesn't need a new Turnstile
// token for every API call (Turnstile tokens are single-use).
//
// Set these environment variables in the Worker dashboard:
//   NODE_SECRET    — shared secret for nginx header validation
//   TURNSTILE_KEY  — Turnstile secret key (set in Cloudflare dashboard)

const SESSION_TTL = 300; // 5 minutes

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': 'https://monero-web.com',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Turnstile-Token, X-Session-Token',
          'Access-Control-Expose-Headers': 'X-Session-Token',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const secret = env.NODE_SECRET || '';

    // Check for a valid session token first (avoids re-verifying Turnstile)
    const sessionToken = request.headers.get('X-Session-Token') || '';
    let sessionValid = false;
    if (sessionToken) {
      sessionValid = await verifySession(sessionToken, secret);
    }

    // If no valid session, require a Turnstile token
    if (!sessionValid) {
      const token = request.headers.get('X-Turnstile-Token') || '';
      if (!token) {
        return jsonResponse(403, { error: 'Missing verification token' });
      }
      const turnstileResult = await verifyTurnstile(token, env.TURNSTILE_KEY || '');
      if (!turnstileResult.success) {
        return jsonResponse(403, {
          error: 'Verification failed',
          codes: turnstileResult['error-codes'] || [],
        });
      }
    }

    // Session-only endpoint: exchange Turnstile token for session token
    const pathname = new URL(request.url).pathname;
    if (pathname === '/session' || pathname === '/lws/session') {
      const newSessionToken = await createSession(secret);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': 'https://monero-web.com',
          'Access-Control-Expose-Headers': 'X-Session-Token',
          'X-Session-Token': newSessionToken,
        },
      });
    }

    // Forward to VPS
    const url = new URL(request.url);
    url.hostname = 'node.monero-web.com';
    url.protocol = 'https:';

    const newHeaders = new Headers(request.headers);
    newHeaders.set('X-Worker-Secret', secret);
    newHeaders.set('Host', 'node.monero-web.com');
    newHeaders.delete('X-Turnstile-Token');
    newHeaders.delete('X-Session-Token');

    const newRequest = new Request(url.toString(), {
      method: request.method,
      headers: newHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'manual',
    });

    const response = await fetch(newRequest);

    // Add CORS + session headers to response
    const newResponse = new Response(response.body, response);
    newResponse.headers.set('Access-Control-Allow-Origin', 'https://monero-web.com');
    newResponse.headers.set('Access-Control-Expose-Headers', 'X-Session-Token');

    // Issue or refresh the session token on every successful forward
    const newSessionToken = await createSession(secret);
    newResponse.headers.set('X-Session-Token', newSessionToken);

    return newResponse;
  },
};

// ── Session token: HMAC-SHA256( expiry | secret ) ──────────────────
async function createSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const key = await getSigningKey(secret);
  const sig = await sign(key, String(expires));
  return expires + '.' + sig;
}

async function verifySession(token, secret) {
  const dot = token.indexOf('.');
  if (dot === -1) return false;
  const expires = parseInt(token.substring(0, dot), 10);
  if (isNaN(expires) || expires < Math.floor(Date.now() / 1000)) return false;
  const sig = token.substring(dot + 1);
  const key = await getSigningKey(secret);
  const expected = await sign(key, String(expires));
  return sig === expected;
}

async function getSigningKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function sign(key, message) {
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=+$/, '');
}

// ── Turnstile verification ─────────────────────────────────────────
async function verifyTurnstile(token, secretKey) {
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(secretKey)}&response=${encodeURIComponent(token)}`,
    });
    return await resp.json();
  } catch (e) {
    return { success: false, 'error-codes': ['fetch-error'] };
  }
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': 'https://monero-web.com',
    },
  });
}
