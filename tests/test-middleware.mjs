import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

const source = await fs.readFile(new URL('../functions/_middleware.js', import.meta.url), 'utf8');
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const { onRequest } = await import(moduleUrl);

async function run(path, { method = 'GET', status = 404 } = {}) {
  const request = new Request(`https://wallet.qwertycoin.org${path}`, { method });
  return onRequest({
    request,
    next: async () => new Response(status === 204 ? null : 'upstream', { status }),
  });
}

const typo = await run('/ver');
assert.equal(typo.status, 404);
assert.equal(typo.headers.get('location'), null);
assert.equal(typo.headers.get('x-robots-tag'), 'noindex, nofollow');
assert.equal(typo.headers.get('cache-control'), 'public, max-age=0, must-revalidate');

const nestedTypo = await run('/missing/page', { method: 'HEAD' });
assert.equal(nestedTypo.status, 404);

for (const [path, options] of [
  ['/api/missing', {}],
  ['/assets/missing.js', {}],
  ['/ver', { method: 'POST' }],
]) {
  const response = await run(path, options);
  assert.equal(response.status, 404, `${options.method || 'GET'} ${path} must remain a 404`);
}

const wallet = await run('/verify', { status: 200 });
assert.equal(wallet.status, 200);
assert.equal(wallet.headers.get('cache-control'), 'public, max-age=0, must-revalidate');

const font = await run('/fonts/example.woff2', { status: 200 });
assert.equal(font.headers.get('cache-control'), 'public, max-age=31536000, immutable');

console.log('  ok   middleware 404 preservation and cache policy');
