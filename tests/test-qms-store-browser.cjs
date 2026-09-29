/* Optional real-browser IndexedDB/Web Locks regression:
 * PLAYWRIGHT_CORE_PATH=/app/node_modules/playwright-core \
 * CHROMIUM_PATH=/ms-playwright/chromium-1243/chrome-linux64/chrome \
 * npm run test:browser-qms-store
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const executablePath = process.env.CHROMIUM_PATH;
if (!executablePath) throw new Error('CHROMIUM_PATH is required');

const contentTypes = {
  '.js': 'text/javascript; charset=utf-8',
  '.html': 'text/html; charset=utf-8'
};

(async function () {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': contentTypes['.html'] });
      response.end('<!doctype html><meta charset="utf-8"><title>QMS store regression</title>');
      return;
    }
    const relative = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname).replace(/^\/+/, '');
    const resolved = path.resolve(root, relative);
    if (!resolved.startsWith(root + path.sep) || !fs.existsSync(resolved)) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { 'content-type': contentTypes[path.extname(resolved)] || 'application/octet-stream' });
    fs.createReadStream(resolved).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;

  const { chromium } = require(playwrightPath);
  const xdgConfig = '/tmp/qwc-qms-store-xdg-config';
  const xdgCache = '/tmp/qwc-qms-store-xdg-cache';
  fs.mkdirSync(xdgConfig, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    env: Object.assign({}, process.env, {
      XDG_CONFIG_HOME: xdgConfig,
      XDG_CACHE_HOME: xdgCache
    }),
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  const requests = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('request', request => requests.push(request.url()));
  try {
    await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(async () => {
      localStorage.clear();
      await new Promise((resolve, reject) => {
        const request = indexedDB.deleteDatabase('qwc-qms1-fast');
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        request.onblocked = () => reject(new Error('test database deletion blocked'));
      });
    });
    for (const script of [
      'vendor/libsodium/libsodium-sumo.js',
      'vendor/libsodium/libsodium-wrappers.js',
      'js/qms-kdf.js',
      'js/wallet-vault.js',
      'js/qms-store.js'
    ]) await page.addScriptTag({ url: `${origin}/${script}` });

    const result = await page.evaluate(async () => {
      await sodium.ready;
      const longTasks = [];
      const observer = typeof PerformanceObserver !== 'undefined'
        ? new PerformanceObserver(list => longTasks.push(...list.getEntries().map(entry => entry.duration)))
        : null;
      if (observer) observer.observe({ type: 'longtask', buffered: true });
      const wallet = { address: 'QWC-browser-indexeddb-regression', network: 'mainnet', privateSpendKeyHex: '7b'.repeat(32) };
      const password = 'browser IndexedDB regression password';
      const kdfStartedAt = performance.now();
      const benchmarkKey = await QmsKdf.derive(password, sodium.randombytes_buf(16), 2, 64 * 1024 * 1024, 32);
      const kdfMs = performance.now() - kdfStartedAt;
      sodium.memzero(benchmarkKey);
      await WalletVault.store(wallet, password);
      const key = WalletVault.qmsKey();
      const active = await QmsStore.open(wallet, key, WalletVault.qmsKdf());
      active.state.contacts.push({ id: 'browser-contact', name: 'encrypted browser contact' });
      active.state.messages.push({ id: 'browser-message', text: 'encrypted browser message' });
      const pending = active.save();
      const duplicateError = await QmsStore.open(wallet, key).then(() => '', error => error.message);
      await pending;
      const locator = JSON.parse(localStorage.getItem(active.storageKey));
      const storageKey = active.storageKey;
      await active.close();

      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('qwc-qms1-fast', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const rows = await new Promise((resolve, reject) => {
        const request = db.transaction('records', 'readonly').objectStore('records').getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      db.close();
      const serialized = JSON.stringify(rows);

      localStorage.clear();
      WalletVault.clear();
      await WalletVault.store(wallet, password);
      const reopened = await QmsStore.open(wallet, WalletVault.qmsKey(), WalletVault.qmsKdf());
      const contactId = reopened.state.contacts[0].id;
      const messageId = reopened.state.messages[0].id;
      const indexedKdfRecovered = WalletVault.qmsKdf().salt === locator.kdf.salt;
      const nextPassword = 'replacement browser Session password';
      const passwordChange = await WalletVault.preparePasswordChange(password, nextPassword);
      const changeResult = await reopened.changeWrappingKey(
        passwordChange.qmsKey,
        passwordChange.qmsKdf,
        () => passwordChange.commit()
      );
      passwordChange.dispose();
      await reopened.close();
      WalletVault.clear();
      await WalletVault.store(wallet, nextPassword);
      const changedPasswordStore = await QmsStore.open(wallet, WalletVault.qmsKey(), WalletVault.qmsKdf());
      const changedPasswordMessageId = changedPasswordStore.state.messages[0].id;
      await changedPasswordStore.close();
      const wrongPasswordError = await QmsStore.open(wallet, new Uint8Array(32))
        .then(() => '', error => error.message);
      if (observer) observer.disconnect();
      return {
        contactId,
        messageId,
        duplicateError,
        wrongPasswordError,
        locator,
        indexedKdfRecovered,
        passwordChangeCleanupPending: changeResult.cleanupPending,
        changedPasswordMessageId,
        rowCount: rows.filter(row => row.key.startsWith(storageKey + '\u0000')).length,
        plaintextLeaked: serialized.includes('encrypted browser contact') || serialized.includes('encrypted browser message'),
        kdfMs,
        maxMainThreadLongTaskMs: longTasks.length ? Math.max(...longTasks) : 0
      };
    });

    assert.strictEqual(result.contactId, 'browser-contact');
    assert.strictEqual(result.messageId, 'browser-message');
    assert.match(result.duplicateError, /already open/);
    assert.match(result.wrongPasswordError, /Unable to decrypt|metadata does not match/);
    assert.strictEqual(result.locator.version, 3);
    assert.strictEqual(result.locator.profile, 'qms1-fast');
    assert.strictEqual(result.locator.backend, 'indexeddb');
    assert.strictEqual(result.locator.kdf.name, 'argon2id13');
    assert.strictEqual(result.indexedKdfRecovered, true);
    assert.strictEqual(result.passwordChangeCleanupPending, false);
    assert.strictEqual(result.changedPasswordMessageId, 'browser-message');
    assert(result.rowCount >= 4, `expected separate encrypted records, got ${result.rowCount}`);
    assert.strictEqual(result.plaintextLeaked, false);
    assert(result.kdfMs > 0, 'Argon2id duration must be measured');
    assert(requests.some(url => url.endsWith('/js/qms-kdf-worker.js')), 'Argon2id worker was not loaded');
    assert.strictEqual(result.maxMainThreadLongTaskMs, 0, `unexpected QMS main-thread long task: ${result.maxMainThreadLongTaskMs}ms`);
    assert.deepStrictEqual(pageErrors, []);
    console.log(JSON.stringify({ indexedDb: true, webLocks: true, ...result }));
  } finally {
    await context.close();
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
