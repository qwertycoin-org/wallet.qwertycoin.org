'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
let passed = 0;

function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok   ${name}`);
}

function linked(html, value) {
  assert(html.includes(value), `missing ${value}`);
}

console.log('\n  Qwertycoin Web Wallet — presentation contract\n');

const appPages = {
  'verify.html': 'wallet-app wallet-verify',
  'dashboard.html': 'wallet-app wallet-dashboard',
  'privacy.html': 'wallet-app wallet-article',
  'self-host.html': 'wallet-app wallet-article',
};

test('all active pages load the shared visual system after legacy inline styles', () => {
  for (const [file, bodyClass] of Object.entries(appPages)) {
    const html = read(file);
    linked(html, `<body class="${bodyClass}">`);
    linked(html, 'href="/assets/wallet-ui.css"');
    assert(html.lastIndexOf('/assets/wallet-ui.css') > html.lastIndexOf('</style>'), `${file}: common CSS must follow legacy CSS`);
  }
});

test('all active pages use the approved local Qwertycoin mark and brand lockup', () => {
  for (const file of Object.keys(appPages)) {
    const html = read(file);
    linked(html, 'src="/assets/qwertycoin-mark.svg"');
    linked(html, '<strong>QWERTYCOIN</strong><span>Web Wallet</span>');
    assert(!html.includes('/assets/classic/logo.png'), `${file}: legacy logo remains`);
  }
});

test('favicon matrix is complete and consistently linked', () => {
  const requiredFiles = [
    'favicon.svg', 'favicon.ico', 'assets/favicon-16x16.png',
    'assets/favicon-32x32.png', 'assets/favicon-192x192.png',
    'assets/apple-touch-icon.png',
  ];
  for (const file of requiredFiles) {
    const stat = fs.statSync(path.join(root, file));
    assert(stat.size > 100, `${file}: unexpectedly small`);
  }
  for (const file of [...Object.keys(appPages), 'index.html']) {
    const html = read(file);
    linked(html, 'href="/favicon.svg"');
    linked(html, 'href="/assets/favicon-32x32.png"');
    linked(html, 'href="/assets/favicon-16x16.png"');
    linked(html, 'href="/assets/apple-touch-icon.png"');
    linked(html, 'href="/favicon.ico"');
  }
});

test('brand fonts are local, content-addressed, and preloaded on active pages', () => {
  const fontCss = read('fonts/fonts.css');
  for (const font of [
    'archivo-latin-900.e915040a27c5.woff2',
    'inter-latin-400.8909904ab6c8.woff2',
    'inter-latin-600.f9a06e79cd3a.woff2',
  ]) {
    assert(fs.statSync(path.join(root, 'fonts', font)).size > 1000, `${font}: unexpectedly small`);
    linked(fontCss, font);
  }
  linked(fontCss, "font-family: 'Archivo'");
  linked(fontCss, "font-family: 'Inter'");
  assert(fs.existsSync(path.join(root, 'fonts/LICENSES.md')), 'font licenses missing');
  for (const file of Object.keys(appPages)) {
    const html = read(file);
    linked(html, '/fonts/archivo-latin-900.e915040a27c5.woff2');
    linked(html, '/fonts/inter-latin-400.8909904ab6c8.woff2');
  }
});

test('shared CSS contains the approved semantic palette and accessibility hooks', () => {
  const css = read('assets/wallet-ui.css').toLowerCase();
  for (const token of ['#f5f1e7', '#fffdf7', '#fff8e8', '#141414', '#ffaf00', '#ffe7a3', '#7952ff']) {
    linked(css, token);
  }
  linked(css, ':focus-visible');
  linked(css, 'prefers-reduced-motion');
  assert(!css.includes('@import'), 'runtime CSS imports are not allowed');
  assert(!/url\(\s*["']?https?:/i.test(css), 'external CSS assets are not allowed');
});

test('functional wallet anchors remain present', () => {
  const verify = read('verify.html');
  for (const id of [
    'tab-seed', 'tab-keys', 'tab-watch', 'tab-create', 'seed-input',
    'restore-height', 'adv-node-url', 'btn-derive-seed', 'btn-derive-key',
    'btn-derive-watch', 'btn-create',
  ]) linked(verify, `id="${id}"`);

  const dashboard = read('dashboard.html');
  for (const id of [
    'dashboard', 'wallet-address', 'balance-xmr', 'btn-send', 'btn-receive',
    'receive-modal', 'send-modal', 'send-step-form', 'send-step-confirm',
    'send-step-result', 'unlock-overlay', 'btn-export', 'btn-disconnect',
  ]) linked(dashboard, `id="${id}"`);
});

test('unsupported swap integration is absent from the shipped wallet', () => {
  for (const file of [...Object.keys(appPages), 'index.html']) {
    const html = read(file);
    assert(!/swap crypto/i.test(html), `${file}: unsupported swap navigation remains`);
    assert(!html.includes('swap-popup'), `${file}: unsupported swap widget remains`);
  }
  assert(!fs.existsSync(path.join(root, 'js/swap-popup.js')), 'unsupported swap widget is still shipped');
  assert(!read('_headers').includes('trocador.app'), 'swap provider remains allowed by CSP');
  assert(!read('README.md').includes('Swap integration'), 'unsupported swap integration remains on the roadmap');
});

test('asset build and cache policy cover the new local presentation files', () => {
  const build = read('tools/build-manifest.sh');
  const headers = read('_headers');
  linked(build, '"assets/*.css"');
  linked(build, '"fonts/LICENSES.md"');
  linked(headers, '/assets/*');
});

test('self-host guide is Qwertycoin-specific and describes the current RPC architecture', () => {
  const guide = read('self-host.html');
  for (const value of [
    'https://wallet.qwertycoin.org/self-host',
    'https://github.com/qwertycoin-org/wallet.qwertycoin.org',
    'https://github.com/qwertycoin-org/qwertycoin.git',
    'qwertycoind',
    '--rpc-restricted-bind-port 8198',
    'functions/_qwcRpcProxy.js',
    'functions/api/proxy.js',
  ]) linked(guide, value);
  for (const legacy of [
    'monero-web.com',
    'Medtabka/monero-web',
    'monerod',
    'monero-lws',
    'node.monero-web.com',
  ]) assert(!guide.includes(legacy), `self-host.html: legacy reference remains: ${legacy}`);
});

console.log(`\n  ${passed} presentation-contract tests passed\n`);
