/**
 * test-new-paths.js — sanity tests for the additions to the crypto engine.
 *
 * Run with:  node tests/test-new-paths.js
 *
 * Covers:
 *   • BIP-39 → SLIP-0010 ed25519 → Monero spend-key derivation
 *   • Polyseed decode (canonical phrase + 4-char-prefix variant)
 *   • Polyseed full key derivation (PBKDF2-SHA256)
 *   • Subaddress generation (correct netbyte, length, distinct from primary,
 *     deterministic across calls)
 *   • Round-trip: 25-word generate → derive → addresses match
 *   • WalletVault encrypt / decrypt / wrong-password rejection
 *
 * No external deps. Just node ≥ 16 (needs WebCrypto, BigInt, sessionStorage shim).
 */

'use strict';

const fs = require('fs');
const path = require('path');

// ── Minimal browser shims ────────────────────────────────────────────
if (!global.crypto) global.crypto = require('crypto').webcrypto;
const _store = new Map();
global.sessionStorage = {
  getItem:    k => _store.has(k) ? _store.get(k) : null,
  setItem:    (k, v) => _store.set(k, String(v)),
  removeItem: k => _store.delete(k),
  clear:      () => _store.clear(),
};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');

// ── Engine modules (load order matches the HTML pages) ──────────────
global.Keccak256       = require('../js/keccak256.js');
global.QwertycoinEd25519   = require('../js/qwertycoin-ed25519.js');
global.QwertycoinWordList  = require('../js/qwertycoin-wordlist.js');
require('../js/qwertycoin-english-wordlist.js');
require('../js/qwertycoin-wordlists-all.js');
global.BIP39_WORDLIST  = require('../js/bip39-wordlist.js');
global.Bip39           = require('../js/bip39.js');
global.Polyseed        = require('../js/polyseed.js');
global.QwertycoinKeys      = require('../js/qwertycoin-keys.js');
global.QwertycoinSubaddress = require('../js/qwertycoin-subaddress.js');
global.WalletVault     = require('../js/wallet-vault.js');
// LwsClient relies on `localStorage` and a few browser globals; provide
// minimal shims so the require() doesn't blow up under Node.
global.localStorage = {
  _s: {},
  getItem(k) { return this._s[k] || null; },
  setItem(k, v) { this._s[k] = String(v); },
  removeItem(k) { delete this._s[k]; },
};
global.location = { hostname: 'localhost' };
global.LwsClient = require('../js/lws-client.js');

// ── Tiny test harness ───────────────────────────────────────────────
let pass = 0, fail = 0;
function test(name, fn) {
  return Promise.resolve().then(fn).then(
    () => { pass++; console.log('  ok   ' + name); },
    e  => { fail++; console.log('  FAIL ' + name + '\n         ' + (e && e.message || e)); }
  );
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}
function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error((msg || 'assertEq failed') +
      '\n           expected: ' + expected +
      '\n           actual:   ' + actual);
  }
}

// ── Tests ───────────────────────────────────────────────────────────
(async () => {
console.log('\n  Qwertycoin Web Wallet — compatibility and wallet paths\n');

  // 25-word round-trip — sanity check the generate → derive loop is unbroken
  await test('25-word generate → re-derive matches', () => {
    const w = QwertycoinKeys.generateWallet('english', 'mainnet');
    const k = QwertycoinKeys.deriveFromMnemonic(w.mnemonic, 'english', 'mainnet');
    assertEq(k.address,            w.address,            'address');
    assertEq(k.privateSpendKeyHex, w.privateSpendKeyHex, 'spend key');
    assertEq(k.privateViewKeyHex,  w.privateViewKeyHex,  'view key');
    assertEq(k.mnemonic,           w.mnemonic,           'mnemonic retained for browser sync');
  });

  // BIP-39
  await test('BIP-39 12 words → produces a valid QWC mainnet address', async () => {
    const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const k = await QwertycoinKeys.deriveFromBip39(m, '', 'mainnet');
    assertEq(k.address.length, 98, 'mainnet length');
    assertEq(k.address.slice(0, 3), 'QWC', 'mainnet prefix');
    assertEq(k.privateSpendKeyHex.length, 64);
    assertEq(k.privateViewKeyHex.length,  64);
    // Determinism: re-derive
    const k2 = await QwertycoinKeys.deriveFromBip39(m, '', 'mainnet');
    assertEq(k2.address, k.address, 'deterministic');
  });

  await test('BIP-39 passphrase changes the derived address', async () => {
    const m = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const a = await QwertycoinKeys.deriveFromBip39(m, '',     'mainnet');
    const b = await QwertycoinKeys.deriveFromBip39(m, 'salt', 'mainnet');
    assert(a.address !== b.address, 'passphrase should change output');
  });

  // Polyseed
  await test('Polyseed canonical phrase decodes', () => {
    const ps = 'raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport language';
    const d  = Polyseed.decode(ps);
    assertEq(d.features, 0, 'features');
    assert(typeof d.birthday === 'number', 'birthday is number');
  });

  await test('Polyseed 4-char-prefix variant decodes identically', () => {
    const full   = 'raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport language';
    const prefix = 'rave tail swea infa grie assi regu lamp duck vali some litt hars pupp airp lang';
    const a = Polyseed.decode(full);
    const b = Polyseed.decode(prefix);
    assertEq(b.birthday, a.birthday, 'birthday');
    assertEq(b.features, a.features, 'features');
    assertEq(Buffer.from(b.secret).toString('hex'),
             Buffer.from(a.secret).toString('hex'), 'secret');
  });

  await test('Polyseed bad checksum is rejected', () => {
    // Swap two words → checksum should fail
    const bad = 'raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy language airport';
    let threw = false;
    try { Polyseed.decode(bad); } catch (e) { threw = true; }
    assert(threw, 'bad checksum should throw');
  });

  await test('Polyseed → full QWC address derivation', async () => {
    const ps = 'raven tail swear infant grief assist regular lamp duck valid someone little harsh puppy airport language';
    const k  = await QwertycoinKeys.deriveFromPolyseed(ps, 'mainnet');
    assertEq(k.address.length, 98);
    assertEq(k.address.slice(0, 3), 'QWC');
    assertEq(k.seedFormat,     'polyseed');
    assertEq(k.wordCount,      16);
  });

  // Subaddresses
  await test('Subaddress (0,1) starts with 8 and differs from primary', () => {
    const w = QwertycoinKeys.generateWallet('english', 'mainnet');
    const sub = QwertycoinSubaddress.generate({
      privateViewKey: QwertycoinKeys.hexToBytes(w.privateViewKeyHex),
      publicSpendKey: QwertycoinKeys.hexToBytes(w.publicSpendKeyHex),
    }, 0, 1);
    assertEq(sub.address.length, 95);
    assertEq(sub.address[0],     '8', 'subaddress netbyte');
    assert(sub.address !== w.address, 'subaddress != primary');
  });

  await test('Subaddress generation is deterministic', () => {
    const w = QwertycoinKeys.generateWallet('english', 'mainnet');
    const k = {
      privateViewKey: QwertycoinKeys.hexToBytes(w.privateViewKeyHex),
      publicSpendKey: QwertycoinKeys.hexToBytes(w.publicSpendKeyHex),
    };
    const a = QwertycoinSubaddress.generate(k, 1, 7);
    const b = QwertycoinSubaddress.generate(k, 1, 7);
    assertEq(a.address, b.address, 'same index → same address');
    const c = QwertycoinSubaddress.generate(k, 1, 8);
    assert(a.address !== c.address, 'different minor → different address');
    const d = QwertycoinSubaddress.generate(k, 2, 7);
    assert(a.address !== d.address, 'different major → different address');
  });

  await test('Subaddress (0,0) is rejected as the primary address', () => {
    const w = QwertycoinKeys.generateWallet('english', 'mainnet');
    let threw = false;
    try {
      QwertycoinSubaddress.generate({
        privateViewKey: QwertycoinKeys.hexToBytes(w.privateViewKeyHex),
        publicSpendKey: QwertycoinKeys.hexToBytes(w.publicSpendKeyHex),
      }, 0, 0);
    } catch (e) { threw = true; }
    assert(threw, '(0,0) should throw');
  });

  // 13-language round-trip — guards against the wordlist regression we
  // had earlier where the all-languages JS file was malformed and only the
  // English wordlist actually loaded in the browser. If any of these break,
  // a real seed in that language can't be imported.
  const ALL_LANGUAGES = [
    'english',  'spanish',  'french',     'german',
    'italian',  'portuguese', 'russian', 'japanese',
    'chinese_simplified', 'dutch', 'esperanto', 'lojban', 'english_old',
  ];
  for (const lang of ALL_LANGUAGES) {
    await test(`25-word round-trip — ${lang}`, () => {
      assert(QwertycoinWordList.isLoaded(lang), `wordlist "${lang}" failed to load`);
      const w = QwertycoinKeys.generateWallet(lang, 'mainnet');
      assert(w.mnemonic.split(/\s+/).length === 25, '25 words expected');
      const k = QwertycoinKeys.deriveFromMnemonic(w.mnemonic, lang, 'mainnet');
      assertEq(k.address,            w.address,            'address');
      assertEq(k.privateSpendKeyHex, w.privateSpendKeyHex, 'spend key');
      assertEq(k.privateViewKeyHex,  w.privateViewKeyHex,  'view key');
    });
  }

  // Network selection
  await test('Stagenet derivation produces a 5… address', () => {
    const w = QwertycoinKeys.generateWallet('english', 'stagenet');
    assertEq(w.address[0], '5');
  });
  await test('Testnet derivation produces a 9… or A… address', () => {
    const w = QwertycoinKeys.generateWallet('english', 'testnet');
    assert(w.address[0] === '9' || w.address[0] === 'A',
      'testnet prefix was: ' + w.address[0]);
  });

  // WalletVault
  await test('WalletVault plaintext round-trip', async () => {
    sessionStorage.clear();
    const k = { address: 'demo', privateSpendKeyHex: 'aa', privateViewKeyHex: 'bb',
                publicSpendKeyHex: 'cc', publicViewKeyHex: 'dd' };
    await WalletVault.store(k, '');
    assert(WalletVault.hasBlob(),  'has blob');
    assert(!WalletVault.isLocked(), 'not locked');
    const out = WalletVault.readPlain();
    assertEq(out.address, 'demo');
  });

  await test('WalletVault migrates the retired session key to the Qwertycoin namespace', () => {
    sessionStorage.clear();
    sessionStorage.setItem('monero-web-wallet', JSON.stringify({
      encrypted: false,
      keys: { address: 'legacy-session' }
    }));
    assertEq(WalletVault.readPlain().address, 'legacy-session');
    assert(sessionStorage.getItem('qwertycoin-web-wallet'), 'branded session key was not created');
    assertEq(sessionStorage.getItem('monero-web-wallet'), null, 'retired session key was not removed');
  });

  await test('WalletVault encrypted round-trip', async () => {
    sessionStorage.clear();
    const k = { address: 'demo-enc', privateSpendKeyHex: '11', privateViewKeyHex: '22',
                publicSpendKeyHex: '33', publicViewKeyHex: '44' };
    await WalletVault.store(k, 'correct horse battery staple');
    assert(WalletVault.isLocked(), 'should be locked');
    assertEq(WalletVault.readPlain(), null, 'readPlain returns null when locked');
    const out = await WalletVault.unlock('correct horse battery staple');
    assertEq(out.address, 'demo-enc');
  });

  await test('WalletVault wrong password is rejected', async () => {
    sessionStorage.clear();
    const k = { address: 'x', privateSpendKeyHex: '0', privateViewKeyHex: '0',
                publicSpendKeyHex: '0', publicViewKeyHex: '0' };
    await WalletVault.store(k, 'right');
    let threw = false;
    try { await WalletVault.unlock('wrong'); } catch (e) { threw = true; }
    assert(threw, 'wrong password should throw');
  });

  // ── Mnemonic language auto-detection ───────────────────────────────
  // Regression test for the bug where a user picked the wrong language
  // in the dropdown and got "Invalid checksum word" because lookup()
  // returned random matches via prefix collisions across wordlists.
  await test('Italian seed + lang=english → auto-detected as italian', () => {
    const w = QwertycoinKeys.generateWallet('italian', 'mainnet');
    const k = QwertycoinKeys.deriveFromMnemonic(w.mnemonic, 'english', 'mainnet');
    assertEq(k.address, w.address, 'auto-detect should pick italian');
  });
  await test('Spanish seed + lang=french → auto-detected as spanish', () => {
    const w = QwertycoinKeys.generateWallet('spanish', 'mainnet');
    const k = QwertycoinKeys.deriveFromMnemonic(w.mnemonic, 'french', 'mainnet');
    assertEq(k.address, w.address, 'auto-detect should pick spanish');
  });
  await test('25-word seed with no language hint → auto-detects', () => {
    const w = QwertycoinKeys.generateWallet('german', 'mainnet');
    const k = QwertycoinKeys.deriveFromMnemonic(w.mnemonic, null, 'mainnet');
    assertEq(k.address, w.address);
  });
  await test('Garbage 25-word input → friendly error, not silent corruption', () => {
    let threw = false, msg = '';
    try {
      QwertycoinKeys.deriveFromMnemonic(
        'one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive',
        null, 'mainnet'
      );
    } catch (e) { threw = true; msg = e.message; }
    assert(threw, 'should throw on bogus input');
    assert(/wordlist/i.test(msg) || /checksum/i.test(msg) || /unknown/i.test(msg),
      'error message should mention wordlist/checksum/unknown — got: ' + msg);
  });

  // ── LwsClient (mock-mode behaviour) ────────────────────────────────
  await test('LwsClient.formatQwc — atomic units → human QWC', () => {
    assertEq(LwsClient.formatQwc('100000000'), '1');
    assertEq(LwsClient.formatQwc('123456789'), '1.23456789');
    assertEq(LwsClient.formatQwc('0'), '0');
    assertEq(LwsClient.formatQwc('1'), '0.00000001');
  });

  await test('LwsClient.availableBalance — total - sent - locked', () => {
    const info = { total_received: '5000000000000', total_sent: '2000000000000', locked_funds: '500000000000' };
    assertEq(LwsClient.availableBalance(info).toString(), '2500000000000');
  });

  await test('LwsClient.availableBalance — never negative', () => {
    const info = { total_received: '0', total_sent: '1000', locked_funds: '0' };
    assertEq(LwsClient.availableBalance(info).toString(), '0');
  });

  await test('LwsClient.scanProgress — partway through', () => {
    const info = { start_height: 1000, scanned_block_height: 1500, blockchain_height: 2000 };
    assertEq(LwsClient.scanProgress(info), 0.5);
  });

  await test('LwsClient.scanProgress — fully synced', () => {
    const info = { start_height: 1000, scanned_block_height: 2000, blockchain_height: 2000 };
    assertEq(LwsClient.scanProgress(info), 1);
  });

  await test('LwsClient mock mode is on for localhost', () => {
    assert(LwsClient.isMock(), 'mock should auto-enable on localhost');
  });

  await test('QWC proxy uses the dedicated production wallet gateway and Turnstile site key', () => {
    const proxy = fs.readFileSync(path.join(__dirname, '../functions/api/proxy.js'), 'utf8');
    const pathProxy = fs.readFileSync(path.join(__dirname, '../functions/_qwcRpcProxy.js'), 'utf8');
    const blockScanRoute = fs.readFileSync(path.join(__dirname, '../functions/get_blocks_by_height.bin.js'), 'utf8');
    const lws = fs.readFileSync(path.join(__dirname, '../js/lws-client.js'), 'utf8');
    const rpcClient = fs.readFileSync(path.join(__dirname, '../js/qwertycoin-rpc.js'), 'utf8');
    const walletEngine = fs.readFileSync(path.join(__dirname, '../js/qwc-wallet-engine.js'), 'utf8');
    const dashboard = fs.readFileSync(path.join(__dirname, '../dashboard.html'), 'utf8');

    assert(proxy.includes('https://wallet-rpc.qwertycoin.org/api/v1/wallet-rpc'),
      'production QWC RPC endpoint missing');
    assert(pathProxy.includes('https://wallet-rpc.qwertycoin.org/api/v1/wallet-rpc'),
      'path-based production QWC RPC endpoint missing');
    assert(!proxy.includes('https://explorer.qwertycoin.org/api/v1/wallet-rpc'),
      'Explorer wallet RPC endpoint must not be used by the production candidate');
    assert(!pathProxy.includes('https://explorer.qwertycoin.org/api/v1/wallet-rpc'),
      'path-based Explorer wallet RPC endpoint must not be used by the production candidate');
    assert(proxy.includes('"Origin": OFFICIAL_WALLET_ORIGIN'),
      'production proxy must identify the official wallet origin to the dedicated gateway');
    assert(pathProxy.includes('"Origin": OFFICIAL_WALLET_ORIGIN'),
      'path-based proxy must identify the official wallet origin to the dedicated gateway');
    assert(proxy.includes('"X-QWC-Client-IP": clientIp'),
      'production proxy must forward Cloudflare client identity for per-client limits');
    assert(pathProxy.includes('"X-QWC-Client-IP": clientIp'),
      'path-based proxy must forward Cloudflare client identity for per-client limits');
    assert(proxy.includes('"/get_transaction_pool_hashes.bin"') && pathProxy.includes('"/get_transaction_pool_hashes.bin"'),
      'Messenger transaction-pool hash route must remain explicitly allowlisted');
    assert(walletEngine.includes('postDaemonPath("/get_transaction_pool_hashes.bin"'),
      'Messenger scanner must use the restricted JSON-over-HTTP transaction-pool route');
    assert(walletEngine.includes('postDaemonPath("/get_transactions"'),
      'Messenger scanner must load only explicitly requested transaction-pool carriers');
    assert(rpcClient.includes("name: 'wallet-rpc.qwertycoin.org'"),
      'wallet UI does not identify the active production gateway');
    assert(dashboard.includes('<span class="label">Gateway</span>'),
      'network card does not label the active endpoint as a gateway');
    assert(!proxy.includes('https://integration-explorer.qwertycoin.org'),
      'integration QWC RPC endpoint must not be used by the production candidate');
    assert(!pathProxy.includes('https://integration-explorer.qwertycoin.org'),
      'path-based integration QWC RPC endpoint must not be used by the production candidate');
    assert(pathProxy.includes('"/get_blocks_by_height.bin"'),
      'canonical block scan RPC path is not allowed');
    assert(pathProxy.includes('path === "/get_blocks_by_height.bin" ? "/getblocks_by_height.bin" : path'),
      'canonical block scan RPC path is not adapted to the dedicated gateway alias');
    assert(proxy.includes('/get_outs'), 'get outs RPC path missing');
    assert(proxy.includes('/get_output_distribution.bin'), 'output distribution RPC path missing');
    assert(blockScanRoute.includes('proxyQwcRpc(context, "/get_blocks_by_height.bin")'),
      'canonical block scan RPC route missing');
    assert(proxy.includes('/send_raw_transaction'), 'send RPC path missing');
    assert(proxy.includes('get_output_histogram'), 'output histogram RPC missing');
    assert(!proxy.includes('xmr-node.cakewallet.com'), 'legacy Monero public node should not be used');
    assert(lws.includes('0x4AAAAAAEkKWLZIa61TTy18'), 'Turnstile site key missing');
  });

  await test('Messenger decodes every byte of a non-empty binary tx-pool hash response', async () => {
    const originalFetch = global.fetch;
    const originalWorker = global.Worker;
    const originalLocation = global.location;
    const hashBytes = Uint8Array.from({ length: 32 }, (_, index) => index);
    const escapeMap = new Map([[8, 'b'], [9, 't'], [10, 'n'], [11, 'v'], [12, 'f'], [13, 'r']]);
    const prefix = Buffer.from('{"status":"OK","tx_hashes":"', 'ascii');
    const encoded = [];
    for (const byte of hashBytes) {
      if (escapeMap.has(byte)) encoded.push(0x5c, escapeMap.get(byte).charCodeAt(0));
      else encoded.push(byte);
    }
    const suffix = Buffer.from('"}', 'ascii');
    try {
      global.location = { hostname: 'localhost', origin: 'https://wallet.example' };
      global.Worker = class {
        postMessage(message) {
          const callbackId = message[2];
          queueMicrotask(() => this.onmessage({ data: [null, callbackId, { result: true }] }));
        }
      };
      global.fetch = async url => {
        assert(String(url).includes('path=%2Fget_transaction_pool_hashes.bin'), 'unexpected tx-pool RPC URL');
        return new Response(Buffer.concat([prefix, Buffer.from(encoded), suffix]), {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' }
        });
      };
      delete require.cache[require.resolve('../js/qwc-wallet-engine.js')];
      const engine = require('../js/qwc-wallet-engine.js');
      const scanner = await engine.createDaemonScanner();
      assertEq((await scanner.getTxPoolHashes())[0], Buffer.from(hashBytes).toString('hex'));
    } finally {
      global.fetch = originalFetch;
      global.Worker = originalWorker;
      global.location = originalLocation;
      delete require.cache[require.resolve('../js/qwc-wallet-engine.js')];
    }
  });

  await test('Bundled QWC wallet worker is bound to the Reset-1 mainnet genesis', () => {
    const buildInfo = fs.readFileSync(path.join(__dirname, '../vendor/qwertycoin-ts/BUILDINFO.txt'), 'utf8');
    const engine = fs.readFileSync(path.join(__dirname, '../js/qwc-wallet-engine.js'), 'utf8');

    assert(buildInfo.includes('genesis_hash=4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39'),
      'Reset-1 mainnet genesis is missing from bundled worker provenance');
    assert(buildInfo.includes('core_revision=890e295f02ca1e6e989221ccf97c2ec24fbec52c'),
      'QMS-enabled Reset-1 core revision is missing from bundled worker provenance');
    assert(buildInfo.includes('qwertycoin_cpp_revision=d4a8cc78ac80e96a2e362ac0ad2630bf99a0759c'),
      'qwertycoin-cpp custom-extra source binding is missing');
    assert(buildInfo.includes('qwertycoin_ts_revision=42050b20f13089251d1aa7d117a1eea515da0444'),
      'qwertycoin-ts custom-extra source binding is missing');
    assert(buildInfo.includes('unbound_1_22_0_source_sha256=c5dd1bdef5d5685b2cedb749158dd152c52d44f65529a34ac15cd88d4b1b3d43'),
      'verified Unbound source provenance is missing');
    assert(buildInfo.includes('translation_files_sha256=320ecf8874eaad13b97c2d98f5f6bdde5fa3e37fbfac21a78ea4184a63b57dcb'),
      'generated translation header provenance is missing');
    assert(buildInfo.includes('qwertycoin_js_sha256=65b20e67c11d6b42ce3c3431dd40fa3d966540b23cdcc931930a05761a8a9e26'),
      'Qwertycoin browser bundle artifact hash is missing');
    assert(buildInfo.includes('qwertycoin_worker_js_sha256=d8121227e81fe7d0320a6ba66d1ada829de3ab7c1785cda1555821831624ac95'),
      'worker artifact hash is missing');
    assert(!buildInfo.includes('=pending'), 'WASM provenance contains unresolved hashes');
    assert(engine.includes('qwertycoin.worker.js?v=d8121227e81fe7d0'),
      'wallet worker cache key is not bound to the reviewed artifact');
  });

  await test('Dashboard QWC history sums wallet transfers and miner outputs', () => {
    const dashboard = fs.readFileSync(path.join(__dirname, '../js/dashboard-page.js'), 'utf8');
    const qmsHistory = fs.readFileSync(path.join(__dirname, '../js/qms-transaction-history.js'), 'utf8');

    assert(dashboard.includes('function getQwcTxDisplayAmount'), 'history amount normalizer missing');
    assert(dashboard.includes('tx.incomingTransfers || tx.incoming_transfers'), 'incoming transfer amounts are not summed');
    assert(dashboard.includes('tx.outgoingTransfer || tx.outgoing_transfer'), 'outgoing transfer amount is not read');
    assert(dashboard.includes('transfer.destinations || transfer.recipients'), 'outgoing destination amounts are not summed');
    assert(dashboard.includes('function qwcGetSelfTransferAmount'), 'self-transfer handling is missing');
    assert(dashboard.includes('Their order') && dashboard.includes('return 0n;'),
      'ambiguous wallet-owned outputs must not be guessed from array order');
    assert(dashboard.includes('qwcMergeWalletOutputDetails'), 'wallet output details are not merged into history txs');
    assert(dashboard.includes('outputSum - changeAmount'), 'outgoing output/change fallback is missing');
    assert(dashboard.includes('tx.isMinerTx === true || tx.is_miner_tx === true'), 'miner tx outputs are not treated as received funds');
    assert(dashboard.includes('https://explorer.qwertycoin.org/tx/'), 'QWC history explorer links are missing');
    assert(dashboard.includes('qwcBindTransactionDetails(listEl)'), 'QWC history rows are not clickable');
    assert(dashboard.includes('controller.transactionHistoryGroups()'), 'Messenger carrier hashes are not loaded from encrypted QMS state');
    assert(dashboard.includes('qwcRefreshChainQmsHistory'), 'restored wallets do not recover Messenger carriers from confirmed blocks');
    assert(dashboard.includes('QmsProtocol.decodeSegments'), 'historical Messenger classification does not validate the QMS fragment structure');
    assert(dashboard.includes('qwcAtomicToBigInt(output && output.amount) === 1n'), 'historical Messenger candidates do not require the one-atomic self-transfer output');
    assert(dashboard.includes('QmsTransactionHistory.buildItems'), 'Messenger history classification does not use the exact-hash grouping contract');
    assert(qmsHistory.includes('function buildChainGroups'), 'on-chain Messenger history grouping is missing');
    assert(qmsHistory.includes('function mergeGroups'), 'local and on-chain Messenger history groups are not merged');
    assert(dashboard.includes('Outgoing Messenger message'), 'Messenger transactions are not labelled in history details');
    assert(qmsHistory.includes("filter === 'payments'"), 'payment-only history filter is missing');
    assert(qmsHistory.includes("filter !== 'messenger'"), 'Messenger-only history filter is missing');
    assert(!dashboard.includes('txDisplay.amount === 1n'), 'one-atomic transactions must never be guessed to be Messenger carriers');
    assert(!dashboard.includes("tx.incomingAmount || tx.outgoingAmount || tx.amount || '0'"), 'old flat amount fallback still controls QWC history rendering');
  });

  await test('Dashboard shows spendable balance separately from locked funds', () => {
    const html = fs.readFileSync(path.join(__dirname, '../dashboard.html'), 'utf8');
    const dashboard = fs.readFileSync(path.join(__dirname, '../js/dashboard-page.js'), 'utf8');

    assert(html.includes('Available Balance'), 'main balance label should describe spendable funds');
    assert(html.includes('id="balance-breakdown"'), 'locked/total balance breakdown is missing');
    assert(dashboard.includes('function renderBalanceSummary'), 'shared balance renderer is missing');
    assert(dashboard.includes('renderBalanceSummary(balance, unlocked)'), 'QWC wallet balance should render unlocked funds as available');
    assert(dashboard.includes('renderBalanceSummary(avail + locked, avail, LwsClient.formatQwc)'), 'LWS balance should render spendable funds as available');
    assert(dashboard.includes('setSendAvailableDisplay(qwcLastAvailableDisplay)'), 'send dialog should preserve spendable balance');
    assert(!dashboard.includes("const balText = document.getElementById('balance-qwc').textContent"), 'send dialog should not copy total balance from the header');
  });

  await test('LwsClient.login (mock) returns plausible response', async () => {
    const r = await LwsClient.login('4ABC', 'deadbeef', { generatedLocally: true });
    assert(typeof r.start_height === 'number', 'start_height present');
    assert(r.generated_locally === true, 'echoes generated_locally');
  });

  await test('LwsClient.getAddressInfo (mock) returns scanning state', async () => {
    const r = await LwsClient.getAddressInfo('4ABC', 'deadbeef');
    assert(r.blockchain_height > 0, 'blockchain_height set');
    assert(r.total_received !== undefined, 'total_received present');
    const avail = LwsClient.availableBalance(r);
    assert(avail > 0n, 'mock balance > 0');
  });

  console.log('\n  ' + pass + ' passed, ' + fail + ' failed\n');
  process.exit(fail === 0 ? 0 : 1);
})();
