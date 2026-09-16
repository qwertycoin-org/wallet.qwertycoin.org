/* Optional local Chromium smoke:
 * PLAYWRIGHT_CORE_PATH=/app/node_modules/playwright-core \
 * CHROMIUM_PATH=/ms-playwright/chromium-1243/chrome-linux64/chrome \
 * node tests/test-message-signing-ui.cjs
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const executablePath = process.env.CHROMIUM_PATH;
const screenshotDir = process.env.QWC_SCREENSHOT_DIR || '/tmp';

if (!executablePath) throw new Error('CHROMIUM_PATH is required');

(async function () {
  const xdgConfig = '/tmp/qwc-signing-xdg-config';
  const xdgCache = '/tmp/qwc-signing-xdg-cache';
  fs.mkdirSync(xdgConfig, { recursive: true });
  fs.mkdirSync(xdgCache, { recursive: true });
  const { chromium } = require(playwrightPath);
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    env: Object.assign({}, process.env, {
      XDG_CONFIG_HOME: xdgConfig,
      XDG_CACHE_HOME: xdgCache
    }),
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  const requests = [];
  const pageErrors = [];
  const consoleErrors = [];

  page.on('request', request => requests.push(request.url()));
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });

  try {
    await page.goto('http://127.0.0.1:8765/verify.html', { waitUntil: 'networkidle' });
    await page.locator('[data-tab="create"]').click();
    await page.locator('#btn-create').click();
    await page.locator('#btn-open-wallet-create').waitFor({ state: 'visible' });
    await page.locator('#btn-open-wallet-create').click();
    await page.waitForURL(/\/dashboard(?:\.html)?$/, { timeout: 5000 }).catch(() => {});
    await page.goto('http://127.0.0.1:8765/dashboard.html', { waitUntil: 'networkidle' });
    await page.locator('#dashboard').waitFor({ state: 'visible' });

    const preSigningExternalRequests = requests.filter(url => {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:'
        ? parsed.hostname !== '127.0.0.1'
        : false;
    });
    requests.length = 0;
    pageErrors.length = 0;
    consoleErrors.length = 0;

    await page.locator('#btn-sign-verify').click();
    const exactMessage = ' exact browser message\nline 2: e\u0301 ';
    const rejectedCrlfPaste = await page.locator('#message-signing-input').evaluate(input => {
      const transfer = new DataTransfer();
      transfer.setData('text/plain', 'must\r\nremain exact');
      const event = new ClipboardEvent('paste', {
        bubbles: true,
        cancelable: true,
        clipboardData: transfer
      });
      input.dispatchEvent(event);
      return event.defaultPrevented;
    });
    assert.strictEqual(rejectedCrlfPaste, true);
    await page.locator('#message-signing-status').filter({ hasText: 'silently change those bytes to LF' }).waitFor();
    assert.strictEqual(await page.locator('#message-signing-input').inputValue(), '');
    await page.locator('#message-signing-input').fill(exactMessage);
    await page.locator('#message-signing-create').click();
    await page.locator('#message-signing-status').filter({ hasText: 'Spend-key signature created locally' }).waitFor();
    const signature = await page.locator('#message-signing-output').inputValue();
    assert.match(signature, /^SigV2/);

    await page.locator('#message-signing-input').fill(exactMessage + ' ');
    assert.strictEqual(await page.locator('#message-signing-output').inputValue(), '');
    await page.locator('#message-signing-input').fill(exactMessage);
    await page.locator('#message-signing-create').click();
    await page.locator('#message-signing-status').filter({ hasText: 'Spend-key signature created locally' }).waitFor();
    const verifiedSignature = await page.locator('#message-signing-output').inputValue();

    await page.locator('#message-signing-tab-verify').click();
    await page.locator('#message-verify-input').fill(exactMessage);
    await page.locator('#message-verify-signature').fill(verifiedSignature);
    await page.locator('#message-verify-check').click();
    await page.locator('#message-verify-status').filter({ hasText: 'Valid spend-key signature' }).waitFor();

    await context.setOffline(true);
    await page.locator('#message-signing-tab-sign').click();
    await page.locator('#message-signing-input').fill('offline-after-worker-load');
    await page.locator('#message-signing-create').click();
    await page.locator('#message-signing-status').filter({ hasText: 'Spend-key signature created locally' }).waitFor();
    const offlineSignature = await page.locator('#message-signing-output').inputValue();
    assert.match(offlineSignature, /^SigV2/);
    await context.setOffline(false);

    const address = (await page.locator('#receive-addr').innerText()).trim();
    const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const challenge = [
      'Qwertycoin pool payout threshold',
      'Address: ' + address,
      'Threshold: 2500.125 QWC',
      'Nonce: ' + 'ab'.repeat(24),
      'Expires: ' + expires,
      'Domain: pool.qwertycoin.org'
    ].join('\n');
    await page.locator('#message-signing-tab-pool').click();
    await page.locator('#pool-challenge-input').fill(challenge);
    await page.locator('#pool-challenge-confirm').check();
    await page.locator('#pool-challenge-sign').click();
    await page.locator('#pool-challenge-status').filter({ hasText: 'signed locally with the spend key' }).waitFor();
    assert.match(await page.locator('#pool-challenge-signature').inputValue(), /^SigV2/);

    const desktopOverflow = await page.evaluate(() =>
      document.documentElement.scrollWidth > document.documentElement.clientWidth);
    assert.strictEqual(desktopOverflow, false);
    await page.screenshot({
      path: path.join(screenshotDir, 'qwc-signing-desktop.png'),
      fullPage: true
    });

    await page.setViewportSize({ width: 390, height: 844 });
    const mobileOverflow = await page.evaluate(() =>
      document.documentElement.scrollWidth > document.documentElement.clientWidth);
    assert.strictEqual(mobileOverflow, false);
    await page.screenshot({
      path: path.join(screenshotDir, 'qwc-signing-mobile.png'),
      fullPage: true
    });

    const externalRequests = requests.filter(url => {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:'
        ? parsed.hostname !== '127.0.0.1'
        : false;
    });
    assert.deepStrictEqual(externalRequests, []);
    assert.deepStrictEqual(pageErrors, []);
    assert.deepStrictEqual(consoleErrors, []);

    console.log(JSON.stringify({
      desktop: { width: 1440, height: 1000, horizontalOverflow: desktopOverflow },
      mobile: { width: 390, height: 844, horizontalOverflow: mobileOverflow },
      offlineSignVerify: true,
      externalRequests,
      preSigningExternalRequests,
      pageErrors,
      consoleErrors,
      screenshots: [
        path.join(screenshotDir, 'qwc-signing-desktop.png'),
        path.join(screenshotDir, 'qwc-signing-mobile.png')
      ]
    }));
  } finally {
    await context.close();
    await browser.close();
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
