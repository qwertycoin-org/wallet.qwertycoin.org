#!/usr/bin/env node
'use strict';

const assert = require('assert');
const cryptoNode = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { pathToFileURL } = require('url');
const { webcrypto } = cryptoNode;

const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const sha256 = file => cryptoNode.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex');

async function loadSignalModule() {
  const dist = path.resolve(process.env.QMS2_WASM_DIST || path.join(root, 'vendor/qwertycoin-ts/qms2'));
  const jsPath = path.join(dist, 'qwc_qms_crypto.js');
  const wasmPath = path.join(dist, 'qwc_qms_crypto_bg.wasm');
  if (!fs.existsSync(jsPath) || !fs.existsSync(wasmPath)) throw new Error(`QMS2 WASM artifact missing at ${dist}`);
  const source = fs.readFileSync(jsPath).toString('base64');
  const module = await import(`data:text/javascript;base64,${source}`);
  await module.default({ module_or_path: fs.readFileSync(wasmPath) });
  return { module, dist };
}

function browserContext(signalModule, sharedLocal = new Map(), sharedSession = new Map()) {
  const storage = values => ({
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
    clear: () => values.clear()
  });
  const ctx = {
    console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    setTimeout, clearTimeout, localStorage: storage(sharedLocal), sessionStorage: storage(sharedSession),
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    btoa: value => Buffer.from(value, 'binary').toString('base64')
  };
  ctx.window = ctx; ctx.self = ctx;
  vm.createContext(ctx);
  for (const file of ['vendor/libsodium/libsodium-sumo.js', 'vendor/libsodium/libsodium-wrappers.js', 'js/wallet-vault.js', 'js/qms-protocol.js', 'js/qms-store.js', 'js/qms-messenger.js']) vm.runInContext(read(file), ctx, { filename: file });
  const qms = vm.runInContext('QmsProtocol', ctx);
  qms.setSignalModuleForTesting(signalModule);
  return {
    ctx, sharedLocal, sharedSession,
    vault: vm.runInContext('WalletVault', ctx), qms,
    store: vm.runInContext('QmsStore', ctx), messenger: vm.runInContext('QmsMessenger', ctx)
  };
}

let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log(`  ok   ${name}`); }
function key(byte) { return new Uint8Array(32).fill(byte); }

(async () => {
  console.log('\n  Qwertycoin Web Wallet — QMS2 Messenger\n');
  const signalArtifact = await loadSignalModule();
  const env = browserContext(signalArtifact.module);
  const { qms, store, messenger, vault } = env;
  await qms.ready();

  await test('pinned libsignal WASM exposes ABI 3 and real PQXDH contact packages', async () => {
    assert.strictEqual(signalArtifact.module.qwc_qms_wasm_abi_version(), 3);
    const engine = await qms.signal.engineNew();
    const prepared = await qms.signal.prepareContactPackage(engine, qms.genesis());
    assert.strictEqual(prepared.invitationId.length, 16);
    assert.strictEqual(prepared.fingerprint.length, 32);
    assert(prepared.package.length > 1000, 'contact package must carry the hybrid pre-key material');
    assert(prepared.nextState.length > engine.length / 2);
  });

  await test('outer framing matches the independently asserted Core transport vector', async () => {
    const sequence = (length, offset) => Uint8Array.from({ length }, (_, index) => (offset + index) & 255);
    const context = { genesis: sequence(32, 1), invitationId: sequence(16, 33), sessionId: sequence(16, 49), rootSecret: sequence(32, 65), direction: 1 };
    const fragments = qms.fragmentEnvelope(context, sequence(16, 17), sequence(1200, 97));
    const digest = value => cryptoNode.createHash('sha256').update(value).digest('hex');
    assert.strictEqual(qms.hex(fragments[0].discoveryHint), 'd6d84ae3dab889b69d24f3cbf8ad1dab');
    assert.strictEqual(qms.hex(fragments[0].mac), 'caea82ceba3fbdfea07ea3509793de21');
    assert.strictEqual(digest(qms.encodeFragment(fragments[0])), 'f630dacd23e94ded3c9159be1e43b2ab50151f447a024044e8f59d289c4fb3d6');
    assert.strictEqual(digest(qms.encodeFragment(fragments[1])), '4ee38c6ea74047b292516bf8f6760c1dc9ab5e3cd18aedbf7f387c503fcf6b7e');
    assert.strictEqual(qms.carrierExtra(fragments[0]).length, 726);
    assert.strictEqual(digest(qms.carrierExtra(fragments[0])), '2db1d2f44112122f360cd42c82e340cffa5b6630a872d7bdc994db3a64547a9f');
  });

  await test('wallet vault derives an independent Argon2id QMS key only for password sessions', async () => {
    const wallet = { address: 'QWC-vault', privateSpendKeyHex: '11'.repeat(32) };
    await vault.store(wallet, 'correct horse battery staple');
    assert.strictEqual(vault.qmsKey().length, 32);
    const blob = JSON.parse(env.sharedSession.get('monero-web-wallet'));
    assert.strictEqual(blob.qmsKdf.name, 'argon2id13');
    assert(blob.qmsKdf.memlimit <= 128 * 1024 * 1024);
    vault.clear();
    await vault.store(wallet, '');
    assert.strictEqual(vault.qmsKey(), null);
  });

  const aliceStore = await store.open({ address: 'QWC-Alice' }, key(0x11));
  const bobStore = await store.open({ address: 'QWC-Bob' }, key(0x22));
  const alice = messenger.makeClient(aliceStore);
  const bob = messenger.makeClient(bobStore);

  await test('activation creates independent encrypted QMS2 identities and survives restart', async () => {
    const aliceFp = await alice.activate();
    const bobFp = await bob.activate();
    assert.match(aliceFp, /^[0-9a-f]{64}$/);
    assert.match(bobFp, /^[0-9a-f]{64}$/);
    assert.notStrictEqual(aliceFp, bobFp);
    assert(!Array.from(env.sharedLocal.values()).join('').includes(aliceStore.state.cryptoState));
    const reopened = await store.open({ address: 'QWC-Alice' }, key(0x11));
    assert.strictEqual(reopened.state.ownFingerprint, aliceFp);
    reopened.close();
  });

  await test('contact packages import idempotently and reject self or conflicting identity data', async () => {
    const aliceContact = await alice.importContact('Bob', bobStore.state.ownPackage, 1700000000);
    const bobContact = await bob.importContact('Alice', aliceStore.state.ownPackage, 1700000000);
    assert.strictEqual(aliceContact, bobStore.state.ownFingerprint);
    assert.strictEqual(bobContact, aliceStore.state.ownFingerprint);
    assert.strictEqual(await alice.importContact('Bob renamed', bobStore.state.ownPackage, 1700000001), aliceContact);
    assert.strictEqual(aliceStore.state.contacts.length, 1);
    await assert.rejects(alice.importContact('Self', aliceStore.state.ownPackage, 1700000001), /self contact package|own QMS2 invitation/);
  });

  let firstPlan;
  await test('4,096-byte PQXDH first message fits 7,200 bytes and canonical 0x72 carriers', async () => {
    firstPlan = await alice.prepareOffline(bobStore.state.ownFingerprint, 'x'.repeat(4096), 1700000002);
    assert.strictEqual(firstPlan.envelopeSize, 7200);
    assert.strictEqual(firstPlan.encodedFragments.length, 12);
    assert.strictEqual(firstPlan.carrierExtras.length, 12);
    assert(firstPlan.carrierExtras.every(value => qms.unhex(value).length === 726));
    for (const value of firstPlan.carrierExtras) {
      const extra = qms.unhex(value);
      const fragment = qms.decodeSegments(qms.extractSegmentsFromExtra(extra));
      assert.strictEqual(fragment.version, 2);
      assert.strictEqual(fragment.profile, 2);
      assert.strictEqual(fragment.data.length, 600);
    }
    await assert.rejects(alice.prepareOffline(bobStore.state.ownFingerprint, '😀'.repeat(1025), 1700000002), /4,096/);
  });

  await test('out-of-order fragments atomically advance receiver state once and ignore duplicates', async () => {
    await messenger.testing.commitPreparedStateForTesting(aliceStore, firstPlan);
    const before = bobStore.state.cryptoState;
    const fragments = firstPlan.encodedFragments.slice().reverse();
    let received = null;
    for (let index = 0; index < fragments.length; index++) received = await bob.acceptFragment(qms.unhex(fragments[index]), { txHash: String(index).padStart(64, '0'), blockHeight: 100 + index, blockHash: `block-${index}` });
    assert(received);
    assert.strictEqual(received.text.length, 4096);
    assert.notStrictEqual(bobStore.state.cryptoState, before);
    assert.strictEqual(bobStore.state.historyEnabled, false);
    assert.strictEqual(bobStore.state.messages.length, 0, 'history-off plaintext must not persist');
    assert.strictEqual(bob.messages().length, 1, 'history-off plaintext remains session-only');
    const committed = bobStore.state.cryptoState;
    assert.strictEqual(await bob.acceptFragment(qms.unhex(fragments[0]), {}), null);
    assert.strictEqual(bobStore.state.cryptoState, committed);
  });

  await test('ongoing Triple Ratchet reply crosses clients and reorg never rolls ratchet state back', async () => {
    const reply = await bob.prepareOffline(aliceStore.state.ownFingerprint, 'ongoing ratchet reply', 1700000003);
    assert(reply.envelopeSize <= 2400);
    await messenger.testing.commitPreparedStateForTesting(bobStore, reply);
    let received = null;
    for (const fragment of reply.encodedFragments) received = await alice.acceptFragment(qms.unhex(fragment), { blockHash: 'reply-block', blockHeight: 200 });
    assert.strictEqual(received.text, 'ongoing ratchet reply');
    const ratchetAfterReceive = aliceStore.state.cryptoState;
    await alice.markReorg(['reply-block']);
    assert.strictEqual(aliceStore.state.cryptoState, ratchetAfterReceive);
    assert.strictEqual(alice.messages().find(item => item.id === reply.messageId).status, 'reorged');
  });

  await test('outer secret rotation survives a lost offer and confirms through the new discovery context', async () => {
    const aliceContact = aliceStore.state.contacts[0];
    const bobContact = bobStore.state.contacts[0];
    const initialIncoming = (await qms.signal.transportContexts(qms.unhex(aliceStore.state.cryptoState), aliceContact.contactId, false))[0];
    const deliver = async (sender, senderStore, recipient, text, at) => {
      const plan = await sender.prepareOffline(recipient === bob ? bobStore.state.ownFingerprint : aliceStore.state.ownFingerprint, text, at);
      await messenger.testing.commitPreparedStateForTesting(senderStore, plan);
      let received = null;
      for (const fragment of plan.encodedFragments) received = await recipient.acceptFragment(qms.unhex(fragment), { blockHash: `rotation-${at}`, blockHeight: at });
      return { plan, received };
    };

    // Alice has sent one message already. Fifteen more reach the rotation
    // interval; the following committed plan carries the first offer.
    for (let index = 0; index < 15; index++) await deliver(alice, aliceStore, bob, `advance-${index}`, 1700000100 + index);
    const lost = await alice.prepareOffline(bobStore.state.ownFingerprint, 'lost rotation offer', 1700000200);
    await messenger.testing.commitPreparedStateForTesting(aliceStore, lost);
    let aliceIncoming = await qms.signal.transportContexts(qms.unhex(aliceStore.state.cryptoState), aliceContact.contactId, false);
    assert.strictEqual(aliceIncoming.length, 2, 'active and offered secrets must both be accepted');

    await deliver(alice, aliceStore, bob, 'repeated rotation offer', 1700000201);
    const bobOutgoing = await qms.signal.transportContext(qms.unhex(bobStore.state.cryptoState), bobContact.contactId, true);
    assert(aliceIncoming.some(context => qms.equal(context.rootSecret, bobOutgoing.rootSecret)), 'receiver must switch to offered discovery secret');
    assert(!qms.equal(initialIncoming.rootSecret, bobOutgoing.rootSecret));

    await deliver(bob, bobStore, alice, 'rotation acknowledgement', 1700000202);
    aliceIncoming = await qms.signal.transportContexts(qms.unhex(aliceStore.state.cryptoState), aliceContact.contactId, false);
    assert.strictEqual(aliceIncoming.length, 2, 'confirmed active plus one retiring grace secret');
    assert(aliceIncoming.some(context => qms.equal(context.rootSecret, initialIncoming.rootSecret)));
    assert(aliceIncoming.some(context => qms.equal(context.rootSecret, bobOutgoing.rootSecret)));
  });

  await test('plaintext history is opt-in and can be deleted independently of ratchet state', async () => {
    await alice.setHistoryEnabled(true);
    const plan = await bob.prepareOffline(aliceStore.state.ownFingerprint, 'persist only by opt-in', 1700000004);
    await messenger.testing.commitPreparedStateForTesting(bobStore, plan);
    let received = null;
    for (const fragment of plan.encodedFragments) received = await alice.acceptFragment(qms.unhex(fragment), { blockHash: 'history-block', blockHeight: 201 });
    assert.strictEqual(received.text, 'persist only by opt-in');
    assert(aliceStore.state.messages.some(item => item.text === 'persist only by opt-in'));
    const cryptoBeforeDelete = aliceStore.state.cryptoState;
    await alice.clearHistory();
    assert.strictEqual(aliceStore.state.messages.length, 0);
    assert.strictEqual(aliceStore.state.cryptoState, cryptoBeforeDelete, 'history deletion must not roll back ratchet state');
  });

  await test('wrong direction, tampering, missing fragments and conflicting duplicates fail closed', async () => {
    const plan = await alice.prepareOffline(bobStore.state.ownFingerprint, 'integrity', 1700000004);
    const current = qms.unhex(aliceStore.state.cryptoState);
    const contact = aliceStore.state.contacts[0];
    const context = await qms.signal.transportContext(current, contact.contactId, true);
    const fragment = qms.decodeFragment(qms.unhex(plan.encodedFragments[0]));
    const wrongDirection = Object.assign({}, context, { direction: context.direction ^ 1 });
    assert(!qms.verifyEnvelopeFragment(wrongDirection, fragment));
    const tampered = qms.unhex(plan.encodedFragments[0]); tampered[tampered.length - 1] ^= 1;
    assert(!qms.verifyEnvelopeFragment(context, qms.decodeFragment(tampered)));
    assert.throws(() => qms.reassemble(plan.encodedFragments.slice(1).map(value => qms.decodeFragment(qms.unhex(value)))), /incomplete/);
    const conflicting = qms.decodeFragment(qms.unhex(plan.encodedFragments[0])); conflicting.mac = new Uint8Array(conflicting.mac); conflicting.mac[0] ^= 1;
    assert.throws(() => qms.reassemble([fragment, conflicting]), /conflicting/);
  });

  await test('an outer-envelope key holder still cannot forge libsignal-authenticated plaintext', async () => {
    const plan = await alice.prepareOffline(bobStore.state.ownFingerprint, 'inner authentication', 1700000005);
    const current = qms.unhex(aliceStore.state.cryptoState);
    const contact = aliceStore.state.contacts[0];
    const context = await qms.signal.transportContext(current, contact.contactId, true);
    const messageId = qms.unhex(plan.messageId);
    const originalFragments = plan.encodedFragments.map(value => qms.decodeFragment(qms.unhex(value)));
    const inner = qms.openOuterEnvelope(context, messageId, qms.reassemble(originalFragments));

    // Model compromise of the independently derived outer transport secret:
    // the attacker can create a fully valid outer AEAD envelope and fragment
    // MACs, but cannot forge the inner libsignal authentication tag.
    const forgedInner = new Uint8Array(inner);
    forgedInner[forgedInner.length - 1] ^= 1;
    const forgedEnvelope = qms.sealOuterEnvelope(context, messageId, forgedInner);
    const forgedFragments = qms.fragmentEnvelope(context, messageId, forgedEnvelope);
    assert(forgedFragments.every(fragment => qms.verifyEnvelopeFragment(context, fragment)));

    const ratchetBefore = bobStore.state.cryptoState;
    const messagesBefore = bob.messages().length;
    for (let index = 0; index + 1 < forgedFragments.length; index++) {
      assert.strictEqual(await bob.acceptFragment(qms.encodeFragment(forgedFragments[index]), {}), null);
    }
    await assert.rejects(
      bob.acceptFragment(qms.encodeFragment(forgedFragments[forgedFragments.length - 1]), {}),
      /decrypt|ciphertext|authentication|MAC|invalid/i
    );
    assert.strictEqual(bobStore.state.cryptoState, ratchetBefore, 'failed inner authentication must not advance ratchet state');
    assert.strictEqual(bob.messages().length, messagesBefore, 'failed inner authentication must not expose plaintext');
  });

  await test('store ciphertext rejects wrong wrapping keys and corruption without plaintext leakage', async () => {
    const serialized = env.sharedLocal.get(aliceStore.storageKey);
    assert(serialized && !serialized.includes('ongoing ratchet reply') && !serialized.includes(aliceStore.state.cryptoState));
    await assert.rejects(store.open({ address: 'QWC-Alice' }, key(0x44)), /Unable to decrypt/);
    const parsed = JSON.parse(serialized);
    parsed.ciphertext = parsed.ciphertext.slice(0, -2) + (parsed.ciphertext.endsWith('AA') ? 'BB' : 'AA');
    env.sharedLocal.set(aliceStore.storageKey, JSON.stringify(parsed));
    await assert.rejects(store.open({ address: 'QWC-Alice' }, key(0x11)), /Unable to decrypt/);
    env.sharedLocal.set(aliceStore.storageKey, serialized);
  });

  await test('explicit restore reset deletes session state and requires fresh contact packages', async () => {
    const previousCryptoState = aliceStore.state.cryptoState;
    await alice.resetState();
    assert.strictEqual(aliceStore.state.active, false);
    assert.strictEqual(aliceStore.state.cryptoState, '');
    assert.strictEqual(aliceStore.state.contacts.length, 0);
    assert.strictEqual(aliceStore.state.messages.length, 0);
    assert(!env.sharedLocal.get(aliceStore.storageKey).includes(previousCryptoState));
  });

  await test('ordinary-browser UI is explicitly QMS2 and cannot invoke wallet or network transport', async () => {
    const html = read('dashboard.html');
    const script = read('js/qms-messenger.js');
    assert(html.includes('QMS2 · Experimental'));
    assert(html.includes('id="qms-activate"'));
    assert(html.includes('cannot prove Tor-only routing without direct fallback'));
    assert(script.includes('Sending and chain sync are blocked in a normal browser'));
    assert(!script.includes('reconnectDaemon'));
    assert(!script.includes('createTransaction'));
    assert(!script.includes('sendTransaction'));
    assert(!script.includes('getWallet()'));
    assert(script.includes('scan: async () => false'));
    assert(script.includes('MAX_REASSEMBLIES = 64'));
    assert(script.includes('MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024'));
    assert(64 * qms.C.MAX_CIPHERTEXT_BYTES <= 8 * 1024 * 1024,
      'the 64-message cap must remain stricter than the aggregate byte cap for canonical envelopes');
  });

  await test('artifact pins and source graph are recorded for independent CI reproduction', async () => {
    const sums = fs.readFileSync(path.join(signalArtifact.dist, 'QMS2-SHA256SUMS'), 'utf8');
    for (const line of sums.trim().split(/\n/)) {
      const [expected, file] = line.trim().split(/\s+/);
      if (!file || file === '-') continue;
      assert.strictEqual(cryptoNode.createHash('sha256').update(fs.readFileSync(path.join(signalArtifact.dist, file))).digest('hex'), expected);
    }
    const html = read('dashboard.html');
    assert(html.indexOf('vendor/libsodium/libsodium-sumo.js') < html.indexOf('js/wallet-vault.js'));
    assert(html.indexOf('js/qms-protocol.js') < html.indexOf('js/qms-messenger.js'));
    assert.strictEqual(sha256('vendor/libsodium/libsodium-wrappers.js'), Object.fromEntries(read('vendor/libsodium/BUILDINFO.txt').trim().split(/\n/).slice(1).map(line => line.split('='))).libsodium_wrappers_js_sha256);
  });

  alice.close(); bob.close();
  console.log(`\n  ${passed} QMS2 Messenger tests passed\n`);
})().catch(error => { console.error(error); process.exit(1); });
