/* Real Chromium/Firefox/WebKit QMS chat/UI regression. */
'use strict';

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');

const root = path.resolve(__dirname, '..');
const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const browserName = process.env.QMS_BROWSER || 'chromium';
const executablePath = process.env.QMS_BROWSER_PATH || process.env.CHROMIUM_PATH;
if (!['chromium', 'firefox', 'webkit'].includes(browserName)) throw new Error(`Unsupported QMS_BROWSER: ${browserName}`);
if (browserName === 'chromium' && !executablePath) throw new Error('CHROMIUM_PATH or QMS_BROWSER_PATH is required');

const dashboard = fs.readFileSync(path.join(root, 'dashboard.html'), 'utf8');
const fragmentStart = dashboard.indexOf('<div class="wallet-tabs');
const fragmentEnd = dashboard.indexOf('<!-- Balance -->');
if (fragmentStart < 0 || fragmentEnd < 0) throw new Error('Unable to locate Messenger dashboard fixture');
const fixture = `<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/assets/wallet-ui.50dd4ba.css"><link rel="stylesheet" href="/assets/qms-messenger.css"><div id="dashboard"><div class="wallet-header"></div>${dashboard.slice(fragmentStart, fragmentEnd)}</div>`;

(async function () {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(fixture);
      return;
    }
    const relative = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname).replace(/^\/+/, '');
    const resolved = path.resolve(root, relative);
    if (!resolved.startsWith(root + path.sep) || !fs.existsSync(resolved)) { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-type': path.extname(resolved) === '.js' ? 'text/javascript' : 'text/css' });
    fs.createReadStream(resolved).pipe(response);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browserType = require(playwrightPath)[browserName];
  const xdgConfig = `/tmp/qwc-qms-ui-${browserName}-xdg-config`;
  const xdgCache = `/tmp/qwc-qms-ui-${browserName}-xdg-cache`;
  fs.mkdirSync(xdgConfig, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  const launchOptions = {
    headless: true,
    env: Object.assign({}, process.env, { XDG_CONFIG_HOME: xdgConfig, XDG_CACHE_HOME: xdgCache })
  };
  if (executablePath) launchOptions.executablePath = executablePath;
  if (browserName === 'chromium') launchOptions.args = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'];
  let browser;
  let context;
  const pageErrors = [];
  try {
    browser = await browserType.launch(launchOptions);
    context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const page = await context.newPage();
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('dialog', dialog => dialog.accept());
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
      'vendor/libsodium/libsodium-sumo.js', 'vendor/libsodium/libsodium-wrappers.js',
      'js/qrcodegen.js', 'js/qms-kdf.js', 'js/qms-protocol.js', 'js/qms-store.js', 'js/qms-messenger.js'
    ]) await page.addScriptTag({ url: `${origin}/${script}` });

    const setup = await page.evaluate(async () => {
      await QmsProtocol.ready();
      const wallet = { address: 'QWC-qms-ui-browser-regression', network: 'mainnet', privateSpendKeyHex: '71'.repeat(32) };
      const key = QmsProtocol.random(32);
      const ownIdentity = QmsProtocol.createIdentity();
      const ownInvitation = QmsProtocol.createInvitation(ownIdentity);
      const contactIdentity = QmsProtocol.createIdentity();
      const contactInvitation = QmsProtocol.createInvitation(contactIdentity);
      const contactId = QmsProtocol.hex(QmsProtocol.fingerprint(contactIdentity.boxPublic, contactIdentity.signPublic));
      const unreadIdentity = QmsProtocol.createIdentity();
      const unreadInvitation = QmsProtocol.createInvitation(unreadIdentity);
      const unreadId = QmsProtocol.hex(QmsProtocol.fingerprint(unreadIdentity.boxPublic, unreadIdentity.signPublic));
      const store = await QmsStore.open(wallet, key);
      store.state.identity = {
        boxPublic: QmsProtocol.hex(ownIdentity.boxPublic), boxSecret: QmsProtocol.hex(ownIdentity.boxSecret),
        signPublic: QmsProtocol.hex(ownIdentity.signPublic), signSecret: QmsProtocol.hex(ownIdentity.signSecret)
      };
      store.state.ownInvitation = QmsProtocol.hex(QmsProtocol.encodeInvitation(ownInvitation));
      store.state.contacts.push({
        id: contactId,
        fingerprint: contactId,
        name: 'Existing Contact',
        invitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(contactInvitation)),
        localInvitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(ownIdentity))),
        verifiedAt: new Date().toISOString(),
        addedAt: new Date().toISOString()
      });
      store.state.contacts.push({
        id: unreadId,
        fingerprint: unreadId,
        name: 'Unread Contact',
        invitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(unreadInvitation)),
        localInvitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(ownIdentity))),
        verifiedAt: new Date().toISOString(),
        addedAt: new Date().toISOString()
      });
      for (let index = 0; index < 250; index++) store.state.messages.push({
        id: String(index).padStart(64, '0'),
        contactId,
        direction: index % 2 ? 'in' : 'out',
        text: `history message ${index}`,
        createdAt: new Date(1700000000000 + index * 1000).toISOString(),
        status: 'confirmed'
      });
      store.state.messages.push({
        id: 'f'.repeat(64), contactId: unreadId, direction: 'in', text: 'unread filter probe',
        createdAt: new Date(1700001000000).toISOString(), status: 'confirmed', readAt: null
      });
      await store.save();
      await store.close();
      const importedIdentity = QmsProtocol.createIdentity();
      const importedInvitation = QmsProtocol.createInvitation(importedIdentity);
      window.qmsTestKey = key;
      window.qmsTestWallet = wallet;
      window.qmsImportedInvitation = QmsProtocol.hex(QmsProtocol.encodeInvitation(importedInvitation));
      document.getElementById('wallet-tab-messenger').hidden = false;
      window.qmsController = await QmsMessenger.mount({
        getWalletKeys: () => wallet,
        getQmsKey: () => key,
        getQmsKdf: () => null,
        getRestoreHeight: () => 0,
        getWallet: async () => ({ reconnectDaemon: async () => {}, sync: async () => {} }),
        createScanner: async () => ({ getHeight: async () => 0, getBlocksByRange: async () => [] }),
        setWalletSpendBlocked: () => {},
        preparePasswordChange: async () => { throw new Error('not used in UI regression'); }
      });
      return { importedInvitation: window.qmsImportedInvitation };
    });

    await page.locator('#wallet-tab-messenger').click();
    assert.strictEqual(await page.locator('.qms-message').count(), 100);
    assert.strictEqual(await page.locator('.qms-load-older').count(), 1);
    await page.locator('.qms-load-older').click();
    assert.strictEqual(await page.locator('.qms-message').count(), 200);

    const unreadContact = page.getByRole('button', { name: /Unread Contact/ });
    assert.strictEqual(await unreadContact.locator('.qms-unread').innerText(), '1');
    assert.match(await unreadContact.locator('.qms-contact-preview').innerText(), /unread filter probe/);
    await page.locator('#qms-contact-filter').fill('unread filter');
    assert.strictEqual(await page.locator('#qms-contact-list .qms-contact').count(), 1);
    await page.locator('#qms-contact-filter').fill('');
    await page.locator('#qms-message-input').fill('draft for existing contact');
    await unreadContact.click();
    assert.strictEqual(await page.locator('#qms-message-input').inputValue(), '');
    assert.strictEqual(await unreadContact.locator('.qms-unread').count(), 0);
    await page.locator('#qms-message-input').fill('draft for unread contact');
    await page.getByRole('button', { name: /Existing Contact/ }).click();
    assert.strictEqual(await page.locator('#qms-message-input').inputValue(), 'draft for existing contact');

    await page.locator('#qms-manage-toggle').click();
    await page.locator('#qms-toggle-invitation-qr').click();
    assert.strictEqual(await page.locator('#qms-own-invitation-qr canvas').count(), 1);
    assert.strictEqual(await page.locator('#qms-toggle-invitation-qr').getAttribute('aria-expanded'), 'true');
    const invitationDownload = page.waitForEvent('download');
    await page.locator('#qms-export-invitation').click();
    assert.strictEqual((await invitationDownload).suggestedFilename(), 'qms1-bootstrap-invitation.json');
    await page.locator('#qms-contact-name').fill('Unverified Contact');
    await page.locator('#qms-contact-invitation-file').setInputFiles({
      name: 'contact-invitation.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({
        type: 'qwc-qms1-invitation', version: 1, profile: 'qms1-fast', invitation: setup.importedInvitation
      }))
    });
    assert.strictEqual(await page.locator('#qms-contact-invitation').inputValue(), setup.importedInvitation);
    await page.locator('#qms-import-contact').click();
    await page.locator('#qms-status').filter({ hasText: 'as unverified' }).waitFor();
    await page.locator('#qms-manage-back').click();
    await page.locator('#qms-message-input').fill('Hello');
    assert.strictEqual(await page.locator('#qms-prepare').isDisabled(), true);
    assert.match(await page.locator('#qms-byte-count').innerText(), /5 \/ 4,096 UTF-8 bytes · 1 carrier transaction/);

    await page.locator('#qms-manage-toggle').click();
    const importedRow = page.locator('.qms-manage-row').last();
    assert.strictEqual(await importedRow.locator('input').inputValue(), 'Unverified Contact');
    await importedRow.getByRole('button', { name: 'Mark fingerprint verified' }).click();
    await page.locator('#qms-manage-back').click();
    await page.locator('#qms-message-input').fill('Hello');
    assert.strictEqual(await page.locator('#qms-prepare').isEnabled(), true);

    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#qms-mobile-chat-back').click();
    assert.strictEqual(await page.locator('.qms-contacts').isVisible(), true);
    assert.strictEqual(await page.locator('.qms-conversation').isVisible(), false);
    await page.getByRole('button', { name: /Unread Contact/ }).click();
    assert.strictEqual(await page.locator('.qms-contacts').isVisible(), false);
    assert.strictEqual(await page.locator('.qms-conversation').isVisible(), true);
    const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    assert.strictEqual(horizontalOverflow, false);
    assert.deepStrictEqual(pageErrors, []);
    await page.evaluate(() => window.qmsController.clear());
    const persistedUiState = await page.evaluate(async () => {
      const store = await QmsStore.open(window.qmsTestWallet, window.qmsTestKey);
      const result = {
        drafts: Object.fromEntries(store.state.contacts.map(contact => [contact.name, contact.draft || ''])),
        unreadReadAt: store.state.messages.find(message => message.id === 'f'.repeat(64)).readAt
      };
      await store.close();
      return result;
    });
    assert.strictEqual(persistedUiState.drafts['Existing Contact'], 'draft for existing contact');
    assert.strictEqual(persistedUiState.drafts['Unread Contact'], 'draft for unread contact');
    assert.match(persistedUiState.unreadReadAt, /^\d{4}-\d{2}-\d{2}T/);
    console.log(JSON.stringify({ browser: browserName, pagination: [100, 200], drafts: true, unread: true, filter: true, mobileNavigation: true, verificationGate: true, invitationQr: true, invitationFile: true, carrierPreview: 1, mobileWidth: 390, horizontalOverflow }));
  } finally {
    if (context) await context.close();
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
