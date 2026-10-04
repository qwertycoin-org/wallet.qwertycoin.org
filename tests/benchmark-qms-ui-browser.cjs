/* Reproducible Chromium benchmark for the QMS1 chat surface. */
'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const root = path.resolve(process.env.QMS_BENCH_ROOT || path.join(__dirname, '..'));
const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const executablePath = process.env.CHROMIUM_PATH;
if (!executablePath) throw new Error('CHROMIUM_PATH is required');

const dashboard = fs.readFileSync(path.join(root, 'dashboard.html'), 'utf8');
const fragmentStart = dashboard.indexOf('<div class="wallet-tabs');
const fragmentEnd = dashboard.indexOf('<!-- Balance -->');
if (fragmentStart < 0 || fragmentEnd < 0) throw new Error('Unable to locate Messenger dashboard fixture');
const fixture = `<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/assets/wallet-ui.50dd4ba.css"><link rel="stylesheet" href="/assets/qms-messenger.css"><div id="dashboard"><div class="wallet-header"></div>${dashboard.slice(fragmentStart, fragmentEnd)}</div>`;

function percentile(values, percentage) {
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * percentage) - 1)];
}

(async function () {
  const server = http.createServer((request, response) => {
    if (request.url === '/') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); response.end(fixture); return; }
    const relative = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname).replace(/^\/+/, '');
    const resolved = path.resolve(root, relative);
    if (!resolved.startsWith(root + path.sep) || !fs.existsSync(resolved)) { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-type': path.extname(resolved) === '.js' ? 'text/javascript' : 'text/css' });
    fs.createReadStream(resolved).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const { chromium } = require(playwrightPath);
  const runId = process.env.QMS_BENCH_LABEL || 'current';
  const contactCount = 100;
  const messageCount = Number(process.env.QMS_BENCH_MESSAGES || 10000);
  if (!Number.isSafeInteger(messageCount) || messageCount < contactCount) throw new Error('QMS_BENCH_MESSAGES must be an integer of at least 100');
  const xdgConfig = `/tmp/qwc-qms-benchmark-${runId}-xdg-config`;
  const xdgCache = `/tmp/qwc-qms-benchmark-${runId}-xdg-cache`;
  fs.mkdirSync(xdgConfig, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    env: Object.assign({}, process.env, { XDG_CONFIG_HOME: xdgConfig, XDG_CACHE_HOME: xdgCache }),
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  try {
    await page.goto(origin + '/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(async () => {
      localStorage.clear();
      await new Promise(resolve => {
        const request = indexedDB.deleteDatabase('qwc-qms1-fast');
        request.onsuccess = request.onerror = request.onblocked = () => resolve();
      });
      window.qmsLongTasks = [];
      if (typeof PerformanceObserver !== 'undefined') {
        try { new PerformanceObserver(list => window.qmsLongTasks.push(...list.getEntries().map(entry => entry.duration))).observe({ type: 'longtask', buffered: true }); } catch (_) {}
      }
    });
    for (const script of [
      'vendor/libsodium/libsodium-sumo.js', 'vendor/libsodium/libsodium-wrappers.js',
      'js/qms-kdf.js', 'js/qms-protocol.js', 'js/qms-store.js', 'js/qms-messenger.js'
    ].filter(script => fs.existsSync(path.join(root, script)))) await page.addScriptTag({ url: `${origin}/${script}` });

    const setup = await page.evaluate(async ({ contactCount, messageCount }) => {
      await QmsProtocol.ready();
      const startedAt = performance.now();
      const wallet = { address: 'QWC-qms-ui-performance-reference', network: 'mainnet', privateSpendKeyHex: '73'.repeat(32) };
      const key = QmsProtocol.random(32);
      const owner = QmsProtocol.createIdentity();
      const store = await QmsStore.open(wallet, key);
      store.state.identity = {
        boxPublic: QmsProtocol.hex(owner.boxPublic), boxSecret: QmsProtocol.hex(owner.boxSecret),
        signPublic: QmsProtocol.hex(owner.signPublic), signSecret: QmsProtocol.hex(owner.signSecret)
      };
      store.state.ownInvitation = QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(owner)));
      const contacts = [];
      for (let index = 0; index < contactCount; index++) {
        const identity = QmsProtocol.createIdentity();
        const invitation = QmsProtocol.createInvitation(identity);
        const id = QmsProtocol.hex(QmsProtocol.fingerprint(identity.boxPublic, identity.signPublic));
        contacts.push({ id, fingerprint: id, name: `Contact ${String(index).padStart(3, '0')}`, invitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(invitation)), verifiedAt: new Date(1700000000000).toISOString(), addedAt: new Date(1700000000000 + index).toISOString() });
      }
      store.state.contacts.push(...contacts);
      const heavyMessageCount = messageCount - (contactCount - 1);
      for (let index = 0; index < heavyMessageCount; index++) store.state.messages.push({
        id: index.toString(16).padStart(64, '0'), contactId: contacts[0].id, direction: 'out',
        text: `heavy history message ${index}`, createdAt: new Date(1700000000000 + index).toISOString(), status: 'confirmed'
      });
      for (let index = 1; index < contactCount; index++) store.state.messages.push({
        id: (messageCount + index).toString(16).padStart(64, '0'), contactId: contacts[index].id, direction: 'out',
        text: `contact history ${index}`, createdAt: new Date(1700010000000 + index).toISOString(), status: 'confirmed'
      });
      const persistStartedAt = performance.now();
      await store.save();
      const persistMs = performance.now() - persistStartedAt;
      await Promise.resolve(store.close());
      document.getElementById('wallet-tab-messenger').hidden = false;
      const mountStartedAt = performance.now();
      window.qmsBenchmarkController = await QmsMessenger.mount({
        getWalletKeys: () => wallet,
        getQmsKey: () => key,
        getQmsKdf: () => null,
        getRestoreHeight: () => 0,
        getWallet: async () => ({ reconnectDaemon: async () => {}, sync: async () => {} }),
        createScanner: async () => ({ getHeight: async () => 0, getBlocksByRange: async () => [] }),
        setWalletSpendBlocked: () => {}
      });
      return { setupMs: performance.now() - startedAt, persistMs, mountMs: performance.now() - mountStartedAt };
    }, { contactCount, messageCount });

    await page.locator('#wallet-tab-messenger').click();
    await page.evaluate(async () => {
      window.qmsLongTasks = [];
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    const interaction = await page.evaluate(async () => {
      const contacts = Array.from(document.querySelectorAll('#qms-contact-list .qms-contact'));
      const switchSamples = [];
      for (let index = 0; index < 20; index++) {
        const target = contacts[index % 2];
        const start = performance.now();
        target.click();
        await new Promise(resolve => requestAnimationFrame(resolve));
        switchSamples.push(performance.now() - start);
      }
      contacts[0].click();
      await new Promise(resolve => requestAnimationFrame(resolve));
      const input = document.getElementById('qms-message-input');
      const inputSamples = [];
      for (let index = 0; index < 30; index++) {
        const start = performance.now();
        input.value = `benchmark ${index}`;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        await new Promise(resolve => requestAnimationFrame(resolve));
        inputSamples.push(performance.now() - start);
      }
      return {
        switchSamples,
        inputSamples,
        renderedMessages: document.querySelectorAll('#qms-message-list .qms-message').length,
        contactButtons: contacts.length,
        longTasks: window.qmsLongTasks.slice()
      };
    });
    await page.evaluate(() => Promise.resolve(window.qmsBenchmarkController.clear()));
    const result = {
      label: runId,
      dataset: { contacts: interaction.contactButtons, messages: messageCount },
      setupMs: Number(setup.setupMs.toFixed(1)),
      persistMs: Number(setup.persistMs.toFixed(1)),
      mountMs: Number(setup.mountMs.toFixed(1)),
      switchP50Ms: Number(percentile(interaction.switchSamples, 0.50).toFixed(1)),
      switchP95Ms: Number(percentile(interaction.switchSamples, 0.95).toFixed(1)),
      inputP50Ms: Number(percentile(interaction.inputSamples, 0.50).toFixed(1)),
      inputP95Ms: Number(percentile(interaction.inputSamples, 0.95).toFixed(1)),
      renderedMessages: interaction.renderedMessages,
      maxLongTaskMs: Number(Math.max(0, ...interaction.longTasks).toFixed(1))
    };
    if (process.env.QMS_BENCH_ENFORCE === '1') {
      assert.strictEqual(result.dataset.contacts, 100);
      assert.strictEqual(result.renderedMessages, 100);
      assert(result.switchP95Ms < 100, `chat switch p95 ${result.switchP95Ms}ms exceeds 100ms`);
      assert(result.inputP95Ms < 100, `input p95 ${result.inputP95Ms}ms exceeds 100ms`);
      assert(result.maxLongTaskMs <= 50, `QMS long task ${result.maxLongTaskMs}ms exceeds 50ms`);
    }
    console.log(JSON.stringify(result));
  } finally {
    await context.close();
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error && error.stack ? error.stack : error); process.exitCode = 1; });
