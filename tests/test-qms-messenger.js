#!/usr/bin/env node
'use strict';

const assert = require('assert');
const cryptoNode = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { webcrypto } = cryptoNode;

const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const sha256 = file => cryptoNode.createHash('sha256').update(fs.readFileSync(path.join(root, file))).digest('hex');

function browserContext() {
  const values = new Map();
  const sessionValues = new Map();
  const heldLocks = new Set();
  let nextLocalWriteError = null;
  const localStorage = {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => {
      if (nextLocalWriteError) {
        const error = nextLocalWriteError;
        nextLocalWriteError = null;
        throw error;
      }
      values.set(key, String(value));
    },
    removeItem: key => values.delete(key),
    clear: () => values.clear()
  };
  const sessionStorage = {
    getItem: key => sessionValues.has(key) ? sessionValues.get(key) : null,
    setItem: (key, value) => sessionValues.set(key, String(value)),
    removeItem: key => sessionValues.delete(key),
    clear: () => sessionValues.clear()
  };
  const ctx = {
    console,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    setTimeout,
    clearTimeout,
    navigator: {
      locks: {
        request: async (name, options, callback) => {
          const available = !heldLocks.has(name);
          if (!available && options && options.ifAvailable) return callback(null);
          if (!available) throw new Error('test lock queueing is not implemented');
          heldLocks.add(name);
          try { return await callback({ name, mode: options.mode }); }
          finally { heldLocks.delete(name); }
        }
      }
    },
    localStorage,
    sessionStorage,
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    btoa: value => Buffer.from(value, 'binary').toString('base64')
  };
  ctx.window = ctx;
  ctx.self = ctx;
  vm.createContext(ctx);
  for (const file of [
    'vendor/libsodium/libsodium-sumo.js',
    'vendor/libsodium/libsodium-wrappers.js',
    'js/wallet-vault.js',
    'js/qms-protocol.js',
    'js/qms-store.js',
    'js/qms-messenger.js'
  ]) vm.runInContext(read(file), ctx, { filename: file });
  return {
    ctx,
    values,
    failNextLocalWrite: error => { nextLocalWriteError = error; },
    qms: vm.runInContext('QmsProtocol', ctx),
    vault: vm.runInContext('WalletVault', ctx),
    store: vm.runInContext('QmsStore', ctx),
    messenger: vm.runInContext('QmsMessenger', ctx)
  };
}

function invitationHex(qms, invitation) {
  return qms.hex(qms.encodeInvitation(invitation));
}

let passed = 0;
async function test(name, fn) {
  await fn();
  passed += 1;
  console.log(`  ok   ${name}`);
}

(async () => {
  console.log('\n  Qwertycoin Web Wallet — QMS1 Messenger\n');
  const env = browserContext();
  const { qms, store, messenger, vault } = env;
  await qms.ready();

  const sodiumBuildInfo = Object.fromEntries(read('vendor/libsodium/BUILDINFO.txt').trim().split(/\n/).slice(1).map(line => {
    const split = line.indexOf('=');
    return [line.slice(0, split), line.slice(split + 1)];
  }));
  assert.strictEqual(env.ctx.sodium.sodium_version_string(), sodiumBuildInfo.libsodium_runtime_version);

  const alice = qms.createIdentity();
  const bob = qms.createIdentity();
  const mallory = qms.createIdentity();
  const aliceInvite = qms.createInvitation(alice);
  const bobInvite = qms.createInvitation(bob);
  const malloryInvite = qms.createInvitation(mallory);

  await test('signed personal invitations have the desktop-compatible encoding', async () => {
    const encoded = qms.encodeInvitation(aliceInvite);
    assert.strictEqual(encoded.length, 214);
    assert.strictEqual(qms.hex(encoded).length, 428);
    assert(qms.verifyInvitation(qms.decodeInvitation(encoded)));
    const tampered = Uint8Array.from(encoded);
    tampered[40] ^= 1;
    assert.throws(() => qms.decodeInvitation(tampered));
  });

  await test('sealed, signed UTF-8 text round-trips only for the pinned recipient and sender', async () => {
    const messageId = Uint8Array.from({ length: 16 }, (_, index) => index + 7);
    const text = 'QMS: Grüße 👋 — encrypted end to end';
    const ciphertext = qms.sealText(alice, bobInvite, messageId, text);
    assert.strictEqual(qms.openText(bob, aliceInvite, bobInvite, messageId, ciphertext).text, text);
    assert.throws(() => qms.openText(bob, malloryInvite, bobInvite, messageId, ciphertext));
    const tampered = Uint8Array.from(ciphertext);
    tampered[tampered.length - 1] ^= 1;
    assert.throws(() => qms.openText(bob, aliceInvite, bobInvite, messageId, tampered));
  });

  await test('UTF-8 and genesis bounds reject ambiguous or incompatible messages', async () => {
    const messageId = qms.random(16);
    assert.throws(() => qms.sealText(alice, bobInvite, messageId, '\ud800'));
    assert.throws(() => qms.sealText(alice, bobInvite, messageId, '😀'.repeat(1025)));
    const foreignInvite = qms.createInvitation(bob, new Uint8Array(32).fill(1));
    assert.throws(() => qms.sealText(alice, foreignInvite, messageId, 'wrong network'));
  });

  await test('maximum text fragments, nonce segments and tx_extra round-trip canonically', async () => {
    const messageId = qms.random(16);
    const text = 'x'.repeat(4096);
    const ciphertext = qms.sealText(alice, bobInvite, messageId, text);
    const fragments = qms.fragmentCiphertext(bobInvite, messageId, ciphertext).reverse();
    assert(fragments.length > 1 && fragments.length <= 16);
    for (const fragment of fragments) {
      assert(qms.verifyFragment(bobInvite, fragment));
      const segments = qms.encodeSegments(fragment).reverse();
      assert(qms.equal(qms.encodeFragment(fragment), qms.encodeFragment(qms.decodeSegments(segments))));
      const carrier = qms.carrierExtra(fragment);
      assert(carrier.length <= 1060);
      const finalExtra = new Uint8Array(33 + carrier.length);
      finalExtra[0] = 0x01;
      finalExtra.set(carrier, 33);
      assert(qms.equal(qms.encodeFragment(fragment), qms.encodeFragment(qms.decodeSegments(qms.extractSegmentsFromExtra(finalExtra)))));
      // Core tx_extra_additional_pub_keys serializes a vector count followed by
      // exactly count * 32 raw public-key bytes (not a byte-length field).
      const withAdditionalKeys = new Uint8Array(finalExtra.length + 34);
      withAdditionalKeys.set(Uint8Array.from([0x04, 0x01]));
      withAdditionalKeys.set(new Uint8Array(32).fill(0x42), 2);
      withAdditionalKeys.set(finalExtra, 34);
      assert(qms.equal(qms.encodeFragment(fragment), qms.encodeFragment(qms.decodeSegments(qms.extractSegmentsFromExtra(withAdditionalKeys)))));
      const withLegacyField = new Uint8Array(finalExtra.length + 4);
      withLegacyField.set(Uint8Array.from([0xde, 0x01, 0x01, 0x00]));
      withLegacyField.set(finalExtra, 4);
      assert(qms.equal(qms.encodeFragment(fragment), qms.encodeFragment(qms.decodeSegments(qms.extractSegmentsFromExtra(withLegacyField)))));
    }
    assert.strictEqual(qms.openText(bob, aliceInvite, bobInvite, messageId, qms.reassemble(fragments)).text.length, 4096);
  });

  await test('a short Fast Profile message uses one compact carrier transaction', async () => {
    const messageId = Uint8Array.from({ length: 16 }, (_, index) => index + 13);
    const ciphertext = qms.sealText(alice, bobInvite, messageId, 'Hello');
    assert.strictEqual(ciphertext.length, 277);
    const fragments = qms.fragmentCiphertext(bobInvite, messageId, ciphertext);
    assert.strictEqual(fragments.length, 1);
    assert.strictEqual(qms.carrierExtra(fragments[0]).length, 393);
  });

  await test('malformed segments, extras and fragment MACs are rejected', async () => {
    const messageId = qms.random(16);
    const fragments = qms.fragmentCiphertext(bobInvite, messageId, qms.sealText(alice, bobInvite, messageId, 'integrity'));
    const missing = qms.encodeSegments(fragments[0]);
    missing.pop();
    assert.throws(() => qms.decodeSegments(missing));
    const duplicateSegment = qms.encodeSegments(fragments[0]);
    if (duplicateSegment.length > 1) {
      duplicateSegment[1] = Uint8Array.from(duplicateSegment[0]);
      assert.throws(() => qms.decodeSegments(duplicateSegment));
    }
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x01, 0x00])));
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x02, 0x80])));
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x02, 0x81, 0x00, 0x72])), /non-canonical/);
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x82, 0x00])), /non-canonical/);
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x00, 0x01])), /terminal/);
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x7f])));
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x04, 0x01, 0x42])), /additional tx public keys/);
    assert.throws(() => qms.extractSegmentsFromExtra(Uint8Array.from([0x04, 0xff, 0xff, 0xff, 0xff, 0x0f])), /additional tx public keys/);
    const badMac = Object.assign({}, fragments[0], { data: Uint8Array.from(fragments[0].data) });
    badMac.data[0] ^= 1;
    assert(!qms.verifyFragment(bobInvite, badMac));
    assert.throws(() => qms.encodeFragment(Object.assign({}, fragments[0], { messageId: new Uint8Array(15) })), /message id/);
    const trailing = new Uint8Array(qms.encodeFragment(fragments[0]).length + 1);
    trailing.set(qms.encodeFragment(fragments[0]));
    assert.throws(() => qms.decodeFragment(trailing));
  });

  await test('out-of-order confirmed fragments produce one contact-filtered message', async () => {
    const messageId = qms.random(16);
    const text = 'contact-isolated '.repeat(120);
    const fragments = qms.fragmentCiphertext(bobInvite, messageId, qms.sealText(alice, bobInvite, messageId, text)).reverse();
    const state = {
      contacts: [
        { id: 'mallory', invitationHex: invitationHex(qms, malloryInvite) },
        { id: 'alice', invitationHex: invitationHex(qms, aliceInvite) }
      ],
      messages: [], plans: [], reassembly: [], scan: { height: 0, blockHash: '' }
    };
    for (let index = 0; index < fragments.length; index++) {
      messenger.testing.acceptFragment(state, bob, bobInvite, fragments[index], {
        txHash: String(index).padStart(64, '0'),
        blockHeight: 100 + index,
        blockHash: `block-${index}`,
        createdAt: new Date(1700000000000 + index * 1000).toISOString()
      });
      assert(state.reassembly.length <= 1, 'one ciphertext must not be duplicated per contact');
    }
    assert.strictEqual(state.messages.length, 1);
    assert.strictEqual(state.messages[0].contactId, 'alice');
    assert.strictEqual(state.messages[0].text, text);
    assert.strictEqual(state.messages[0].status, 'confirmed');
    assert.strictEqual(state.reassembly.length, 0);
    assert.strictEqual(messenger.testing.acceptFragment(state, bob, bobInvite, fragments[0], {}), null);
  });

  await test('incomplete ciphertext state is capped before contact amplification', async () => {
    const state = { contacts: [], messages: [], plans: [], reassembly: [], scan: { height: 0, blockHash: '' } };
    const payload = new Uint8Array(601).fill(9);
    for (let index = 0; index < 64; index++) {
      const first = qms.fragmentCiphertext(bobInvite, qms.random(16), payload)[0];
      messenger.testing.acceptFragment(state, bob, bobInvite, first, {});
    }
    assert.strictEqual(state.reassembly.length, 64);
    const overflow = qms.fragmentCiphertext(bobInvite, qms.random(16), payload)[0];
    assert.throws(
      () => messenger.testing.acceptFragment(state, bob, bobInvite, overflow, {}),
      error => error && error.code === 'QMS_CAPACITY' && /cursor was not advanced/.test(error.message)
    );
  });

  await test('block continuity checks hashes across batch boundaries', async () => {
    const zero = '00'.repeat(32), first = '11'.repeat(32), second = '22'.repeat(32), third = '33'.repeat(32);
    assert.strictEqual(messenger.testing.validateBlockSequence([
      { height: 0, hash: first, prevHash: zero },
      { height: 1, hash: second, prevHash: first }
    ], 0, ''), second);
    assert.strictEqual(messenger.testing.validateBlockSequence([
      { height: 2, hash: third, prevHash: second }
    ], 2, second), third);
    assert.throws(() => messenger.testing.validateBlockSequence([
      { height: 2, hash: third, prevHash: first }
    ], 2, second), /disconnected/);
  });

  await test('reorg rollback retains messages and confirmations before the common ancestor', async () => {
    const state = {
      contacts: [],
      messages: [
        { id: 'old-in', direction: 'in', sourceFragments: [{ blockHeight: 90 }] },
        { id: 'new-in', direction: 'in', sourceFragments: [{ blockHeight: 110 }] },
        { id: 'old-out', direction: 'out', status: 'confirmed' },
        { id: 'new-out', direction: 'out', status: 'confirmed' }
      ],
      plans: [
        { id: 'old-out', status: 'confirmed', txs: [{ status: 'confirmed', blockHeight: 90, blockHash: 'old' }] },
        { id: 'new-out', status: 'confirmed', txs: [{ status: 'confirmed', blockHeight: 110, blockHash: 'new' }] }
      ],
      reassembly: [],
      scan: { height: 120, blockHash: 'tip', startHeight: 0, checkpoints: [{ height: 99, hash: 'common' }, { height: 119, hash: 'tip' }] }
    };
    messenger.testing.rollbackForReorg(state, 100, 'common');
    assert.deepStrictEqual(state.messages.map(message => message.id), ['old-in', 'old-out', 'new-out']);
    assert.strictEqual(state.plans[0].status, 'confirmed');
    assert.strictEqual(state.plans[1].status, 'broadcast');
    assert.strictEqual(state.messages.find(message => message.id === 'new-out').status, 'broadcast');
    assert.deepStrictEqual(state.scan, { height: 100, blockHash: 'common', startHeight: 0, checkpoints: [{ height: 99, hash: 'common' }] });
  });

  await test('prepared-plan cancellation deletes its message and safely releases unique inputs', async () => {
    const plan = {
      id: 'draft', contactId: 'alice', status: 'prepared',
      txs: [
        { status: 'prepared', keyImages: ['a', 'b'] },
        { status: 'prepared', keyImages: ['b', 'c'] }
      ]
    };
    const state = { plans: [plan], messages: [{ id: 'draft', direction: 'out' }] };
    const thawed = [];
    await messenger.testing.releasePlanInputs({ thawOutput: async keyImage => thawed.push(keyImage) }, plan);
    assert.deepStrictEqual(thawed, ['a', 'b', 'c']);
    messenger.testing.removeDraft(state, plan);
    assert.strictEqual(state.plans.length, 0);
    assert.strictEqual(state.messages.length, 0);
    await assert.rejects(
      messenger.testing.releasePlanInputs({ thawOutput: async () => { throw new Error('locked'); } }, plan),
      /Unable to release/
    );
  });

  await test('Messenger operations are mutually exclusive beyond button state', async () => {
    const mutex = messenger.testing.createOperationMutex();
    let release;
    const blocker = new Promise(resolve => { release = resolve; });
    const first = mutex.run('send', async () => blocker);
    await assert.rejects(mutex.run('cancel', async () => {}), /already in progress: send/);
    release();
    await first;
    assert.strictEqual(mutex.current, null);
  });

  await test('broadcast timeout journals an unknown outcome and retries identical signed bytes', async () => {
    const metadata = 'signed-payload-do-not-rebuild';
    const hash = 'ab'.repeat(32);
    const tx = { hash, metadata, status: 'prepared' };
    const plan = { id: 'outbox-timeout', status: 'prepared', txs: [tx] };
    const durableStatuses = [];
    let relayedMetadata = null;
    await assert.rejects(messenger.testing.relayPlan(plan, {
      persist: async () => { durableStatuses.push(tx.status); },
      relay: async entries => { relayedMetadata = entries[0]; throw new Error('network timeout'); },
      assertActive: () => {},
      updateStatus: () => {}
    }), /network timeout/);
    assert.deepStrictEqual(durableStatuses, ['broadcasting', 'broadcast_unknown']);
    assert.strictEqual(plan.status, 'broadcast_unknown');
    assert.strictEqual(messenger.testing.statusLabel(plan.status), 'Broadcast outcome unknown');
    assert.strictEqual(tx.status, 'broadcast_unknown');
    assert.strictEqual(relayedMetadata, metadata);
    assert.strictEqual(tx.hash, hash);

    let retryMetadata = null;
    await messenger.testing.relayPlan(plan, {
      persist: async () => {},
      relay: async entries => { retryMetadata = entries[0]; return [hash]; },
      assertActive: () => {},
      updateStatus: () => {}
    });
    assert.strictEqual(retryMetadata, metadata);
    assert.strictEqual(tx.hash, hash);
    assert.strictEqual(tx.broadcastAttempts, 2);
    assert.strictEqual(tx.status, 'broadcast');
    assert.strictEqual(plan.status, 'broadcast');
  });

  await test('partially relayed batches remain recoverable without rebuilding carriers', async () => {
    const plan = {
      status: 'broadcast_unknown',
      txs: [
        { hash: '01'.repeat(32), metadata: 'already-relayed', status: 'broadcast' },
        { hash: '02'.repeat(32), metadata: 'same-second-carrier', status: 'prepared' }
      ]
    };
    assert.strictEqual(messenger.testing.recomputePlanStatus(plan), 'broadcast_unknown');
    const relayed = [];
    await messenger.testing.relayPlan(plan, {
      persist: async () => {},
      relay: async entries => { relayed.push(entries[0]); return ['02'.repeat(32)]; },
      assertActive: () => {},
      updateStatus: () => {}
    });
    assert.deepStrictEqual(relayed, ['same-second-carrier']);
    assert.strictEqual(plan.txs[0].broadcastAttempts, undefined);
    assert.strictEqual(plan.txs[1].broadcastAttempts, 1);
    assert.strictEqual(plan.status, 'broadcast');
  });

  await test('relay never starts when the broadcasting journal cannot be persisted', async () => {
    const tx = { hash: 'cd'.repeat(32), metadata: 'signed', status: 'prepared' };
    const plan = { id: 'outbox-persist-failure', status: 'prepared', txs: [tx] };
    let relayCalls = 0;
    await assert.rejects(messenger.testing.relayPlan(plan, {
      persist: async () => { throw new Error('quota exceeded'); },
      relay: async () => { relayCalls += 1; return [tx.hash]; },
      assertActive: () => {},
      updateStatus: () => {}
    }), /quota exceeded/);
    assert.strictEqual(relayCalls, 0);
    assert.strictEqual(tx.status, 'recovery_required');
    assert.strictEqual(plan.status, 'recovery_required');
  });

  await test('outgoing status and reorg rollback retain only chain-independent data', async () => {
    const plan = { id: 'p', status: 'confirmed', txs: [{ status: 'confirmed', blockHeight: 9, blockHash: 'old' }] };
    const state = {
      plans: [plan],
      messages: [
        { id: 'p', direction: 'out', status: 'confirmed' },
        { id: 'incoming', direction: 'in', status: 'confirmed' }
      ],
      reassembly: [{ messageId: 'partial' }],
      scan: { height: 10, blockHash: 'old' }
    };
    messenger.testing.rollbackForReorg(state, 4);
    assert.strictEqual(state.messages.length, 1);
    assert.strictEqual(state.messages[0].status, 'broadcast');
    assert.strictEqual(plan.status, 'broadcast');
    assert.strictEqual(state.reassembly.length, 0);
    assert.strictEqual(state.scan.height, 4);
  });

  await test('session password derives a dedicated QMS1/Fast key', async () => {
    const wallet = { address: 'QWC-password-test', privateSpendKeyHex: '33'.repeat(32) };
    await vault.store(wallet, 'correct horse battery staple');
    assert.strictEqual(vault.hasQmsKey(), true);
    assert.strictEqual(vault.qmsKey().length, 32);
    vault.clear();
    assert.strictEqual(vault.hasQmsKey(), false);
    await vault.store(wallet, '');
    assert.strictEqual(vault.hasQmsKey(), false);
  });

  await test('same wallet and Session password reopen Messenger history after reimport', async () => {
    const wallet = { address: 'QWC-reimport-test', privateSpendKeyHex: '44'.repeat(32) };
    const password = 'persistent test password';
    await vault.store(wallet, password);
    const first = await store.open(wallet, vault.qmsKey(), vault.qmsKdf());
    first.state.messages.push({ id: 'persisted', direction: 'out', text: 'survives reimport' });
    await first.save();
    first.close();

    vault.clear();
    await vault.store(wallet, password);
    const reopened = await store.open(wallet, vault.qmsKey(), vault.qmsKdf());
    assert.strictEqual(reopened.state.messages.length, 1);
    assert.strictEqual(reopened.state.messages[0].id, 'persisted');
    reopened.close();

    const encryptedHistory = env.values.get(reopened.storageKey);
    vault.clear();
    await vault.store(wallet, 'different password');
    await assert.rejects(store.open(wallet, vault.qmsKey(), vault.qmsKdf()), /Unable to decrypt/);
    assert.strictEqual(env.values.get(reopened.storageKey), encryptedHistory, 'wrong password must not overwrite Messenger history');
  });

  await test('an active legacy session migrates its ephemeral KDF metadata before reimport', async () => {
    const wallet = { address: 'QWC-legacy-reimport-test', privateSpendKeyHex: '55'.repeat(32) };
    const password = 'legacy migration password';
    await vault.store(wallet, password);
    const legacy = await store.open(wallet, vault.qmsKey());
    legacy.state.messages.push({ id: 'legacy', direction: 'out', text: 'migrate me' });
    await legacy.save();
    assert.strictEqual(JSON.parse(env.values.get(legacy.storageKey)).kdf, undefined);
    legacy.close();

    const migrated = await store.open(wallet, vault.qmsKey(), vault.qmsKdf());
    await migrated.save();
    assert.strictEqual(JSON.parse(env.values.get(migrated.storageKey)).kdf.name, 'argon2id13');
    migrated.close();

    vault.clear();
    await vault.store(wallet, password);
    const reopened = await store.open(wallet, vault.qmsKey(), vault.qmsKdf());
    assert.strictEqual(reopened.state.messages[0].id, 'legacy');
    reopened.close();
  });

  await test('password-bound QMS state is encrypted and serialized in save order', async () => {
    const wallet = { address: 'QWC-test-wallet', privateSpendKeyHex: '11'.repeat(32) };
    const key = env.ctx.sodium.randombytes_buf(32);
    const first = await store.open(wallet, key);
    first.state.messages.push({ id: 'one', text: 'plaintext must not leak' });
    const saveOne = first.save();
    first.state.messages.push({ id: 'two', text: 'latest snapshot' });
    const saveTwo = first.save();
    await Promise.all([saveOne, saveTwo]);
    const envelope = env.values.get(first.storageKey);
    assert(envelope && !envelope.includes('plaintext must not leak') && !envelope.includes('latest snapshot'));
    await first.close();
    const reopened = await store.open(wallet, key);
    assert.strictEqual(reopened.state.messages.length, 2);
    await reopened.close();
    await assert.rejects(store.open(wallet, env.ctx.sodium.randombytes_buf(32)), /Unable to decrypt/);
  });

  await test('closing waits for accepted writes and never encrypts with destroyed keys', async () => {
    const wallet = { address: 'QWC-close-race-test', privateSpendKeyHex: '66'.repeat(32) };
    const key = env.ctx.sodium.randombytes_buf(32);
    const active = await store.open(wallet, key);
    active.state.messages.push({ id: 'before-close', text: 'confidential close-race probe' });
    const pending = active.save();
    const closing = active.close();
    assert.throws(() => active.save(), /closed/);
    await Promise.all([pending, closing]);

    const reopened = await store.open(wallet, key);
    assert.strictEqual(reopened.state.messages[0].id, 'before-close');
    await reopened.close();
    await assert.rejects(store.open(wallet, new Uint8Array(32)), /Unable to decrypt/);
  });

  await test('a second active writer for the same wallet is rejected fail-closed', async () => {
    const wallet = { address: 'QWC-exclusive-writer-test', privateSpendKeyHex: '77'.repeat(32) };
    const key = env.ctx.sodium.randombytes_buf(32);
    const first = await store.open(wallet, key);
    first.state.messages.push({ id: 'first-writer', text: 'must survive' });
    await first.save();
    await assert.rejects(store.open(wallet, key), /already open/);
    await first.close();

    const second = await store.open(wallet, key);
    assert.strictEqual(second.state.messages[0].id, 'first-writer');
    await second.close();
  });

  await test('atomic scan commit keeps the in-memory cursor unchanged on quota failure', async () => {
    const wallet = { address: 'QWC-atomic-scan-test', privateSpendKeyHex: '88'.repeat(32) };
    const key = env.ctx.sodium.randombytes_buf(32);
    const active = await store.open(wallet, key);
    await active.save();
    const snapshot = active.snapshot();
    snapshot.state.scan = { height: 20, blockHash: 'aa'.repeat(32), startHeight: 0, checkpoints: [] };
    env.failNextLocalWrite(new Error('quota exceeded'));
    await assert.rejects(active.commit(snapshot.state, snapshot.revision), /quota exceeded/);
    assert.strictEqual(active.state.scan.height, 0);

    const stale = active.snapshot();
    active.state.messages.push({ id: 'concurrent-change', text: 'preserve me' });
    await active.save();
    stale.state.scan.height = 40;
    await assert.rejects(active.commit(stale.state, stale.revision), /changed while/);
    assert.strictEqual(active.state.scan.height, 0);
    assert.strictEqual(active.state.messages[0].id, 'concurrent-change');
    await active.close();
  });

  await test('shipped UI, worker and provenance are bound to the reviewed Messenger assets', async () => {
    const html = read('dashboard.html');
    const engine = read('js/qwc-wallet-engine.js');
    const dashboardScript = read('js/dashboard-page.js');
    const messengerScript = read('js/qms-messenger.js');
    const worker = read('vendor/qwertycoin-ts/monero.worker.js');
    const css = read('assets/qms-messenger.css');
    const buildInfo = Object.fromEntries(read('vendor/qwertycoin-ts/BUILDINFO.txt').trim().split(/\n/).slice(1).map(line => line.split('=')));
    for (const value of [
      'id="wallet-tab-messenger" type="button" role="tab" aria-selected="false" hidden',
      'id="qms-section"', 'Manage contacts',
      'Encrypt &amp; review', 'Send encrypted message', 'Copy complete invitation'
    ]) assert(html.includes(value), `missing Messenger UI contract: ${value}`);
    assert(html.indexOf('vendor/libsodium/libsodium-sumo.js') < html.indexOf('js/qms-protocol.js'));
    assert(html.indexOf('js/qms-messenger.js') < html.indexOf('js/dashboard-page.js'));
    assert(engine.includes('monero.worker.js?v=6e067bb0fd551614'));
    assert(engine.includes('invoke(walletId, "freezeOutput", [keyImage])'));
    assert(engine.includes('daemonGetBlocksByRangeChunked'));
    assert(engine.includes('daemonGetBlockHeadersByRange'));
    assert(engine.includes('mismatched Messenger block header data'));
    assert(engine.includes('Object.assign({}, block, { hash: header.hash })'));
    assert(engine.includes('server: getDefaultServerConfig()'));
    assert(engine.includes('proxyToWorker: false'));
    assert(engine.includes('const DAEMON_CHUNK_BYTES = 3000000'));
    assert(messengerScript.includes("'broadcast_unknown'"));
    assert(messengerScript.includes("operations.run('send'"));
    assert(messengerScript.includes("operations.run('cancel'"));
    assert(!messengerScript.includes('scanning || recovering || activePlan(state)'), 'prepared sends must not stop receive scanning');
    assert(messengerScript.includes('overviewTab.disabled = recovering'));
    assert(dashboardScript.includes('await qmsController.scan()'));
    assert(dashboardScript.includes('WalletVault.hasQmsKey()'));
    assert(dashboardScript.includes('getQmsKdf: () => WalletVault.qmsKdf()'));
    assert(dashboardScript.includes('setWalletSpendBlocked: setQmsSpendBlocked'));
    assert(dashboardScript.includes('qmsTab.hidden = true'));
    assert(dashboardScript.indexOf('qmsPasswordProtected') < dashboardScript.indexOf('QmsMessenger.mount'));
    assert(worker.includes('extraHex'));
    assert(worker.includes('freezeOutput'));
    assert(worker.includes('daemonGetBlocksByRangeChunked'));
    assert.strictEqual(sha256('vendor/qwertycoin-ts/monero.js'), buildInfo.monero_js_sha256);
    assert.strictEqual(sha256('vendor/qwertycoin-ts/monero.worker.js'), buildInfo.monero_worker_js_sha256);
    assert.strictEqual(sha256('vendor/qwertycoin-ts/monero.worker.js.LICENSE.txt'), buildInfo.monero_worker_license_sha256);
    assert.strictEqual(buildInfo.qwertycoin_ts_revision, '42050b20f13089251d1aa7d117a1eea515da0444');
    assert.strictEqual(buildInfo.qwertycoin_cpp_revision, 'd4a8cc78ac80e96a2e362ac0ad2630bf99a0759c');
    assert.strictEqual(sodiumBuildInfo.libsodium_wrappers_sumo_package, 'libsodium-wrappers-sumo@0.8.4');
    assert.strictEqual(sodiumBuildInfo.libsodium_sumo_package, 'libsodium-sumo@0.8.4');
    assert.strictEqual(sha256('vendor/libsodium/libsodium-wrappers.js'), sodiumBuildInfo.libsodium_wrappers_js_sha256);
    assert.strictEqual(sha256('vendor/libsodium/libsodium-sumo.js'), sodiumBuildInfo.libsodium_sumo_js_sha256);
    assert.strictEqual(sha256('vendor/libsodium/LICENSE.libsodium-wrappers-sumo'), sodiumBuildInfo.license_sha256);
    assert(!/@import|url\(\s*["']?https?:/i.test(css), 'Messenger CSS must not load external assets');
    assert(fs.statSync(path.join(root, 'vendor/libsodium/LICENSE.libsodium-wrappers-sumo')).size > 500);
  });

  console.log(`\n  ${passed} QMS1 Messenger tests passed\n`);
})().catch(error => {
  console.error(error);
  process.exit(1);
});
