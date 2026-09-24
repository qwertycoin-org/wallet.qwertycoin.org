// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Authenticated, password-wrapped QMS2 browser state. */
const QmsStore = (() => {
  'use strict';
  const PREFIX = 'qwc-qms-store-v2:';
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });

  function sodiumApi() {
    if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded');
    return sodium;
  }
  function b64(input) { return sodiumApi().to_base64(input, sodiumApi().base64_variants.ORIGINAL); }
  function unb64(value) { return sodiumApi().from_base64(String(value), sodiumApi().base64_variants.ORIGINAL); }
  function ad(storageKey, purpose) { return te.encode(`QWC-QMS2-WEB-STORE\u0000${purpose}\u0000${storageKey}`); }
  async function walletId(address) { return QmsProtocol.hex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(String(address))))); }
  function blank() {
    return {
      version: 2,
      active: false,
      cryptoState: '',
      invitationId: '',
      ownPackage: '',
      ownFingerprint: '',
      contacts: [],
      historyEnabled: false,
      messages: [],
      prepared: null,
      reassembly: []
    };
  }
  function validateState(state) {
    if (state && typeof state.historyEnabled === 'undefined') state.historyEnabled = false;
    if (!state || state.version !== 2 || typeof state.active !== 'boolean'
        || typeof state.historyEnabled !== 'boolean'
        || !Array.isArray(state.contacts) || !Array.isArray(state.messages)
        || !Array.isArray(state.reassembly)) throw new Error('invalid encrypted QMS2 store');
    if (state.active && (!/^[0-9a-f]+$/i.test(state.cryptoState) || !/^[0-9a-f]{32}$/i.test(state.invitationId)
        || !/^[0-9a-f]+$/i.test(state.ownPackage) || !/^[0-9a-f]{64}$/i.test(state.ownFingerprint))) throw new Error('invalid active QMS2 store');
    return state;
  }
  function encrypt(key, nonce, plaintext, additionalData) {
    return sodiumApi().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, additionalData, null, nonce, key);
  }
  function decrypt(key, nonce, ciphertext, additionalData, label) {
    try { return sodiumApi().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, additionalData, nonce, key); }
    catch (_) { throw new Error(`Unable to decrypt this wallet's ${label}`); }
  }
  function requireKey(value, label) {
    value = value instanceof Uint8Array ? value : new Uint8Array(value || []);
    if (value.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
    return value;
  }

  async function open(wallet, wrappingKey) {
    await sodiumApi().ready;
    if (!wallet || !wallet.address) throw new Error('QMS2 requires an unlocked wallet');
    wrappingKey = requireKey(wrappingKey, 'QMS2 unlock key');
    const storageKey = PREFIX + await walletId(wallet.address);
    let envelope = null;
    try { envelope = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (_) { throw new Error('Invalid QMS2 store envelope'); }
    let dataKey, state = blank();
    if (envelope) {
      if (envelope.version !== 2 || envelope.cipher !== 'xchacha20poly1305-ietf') throw new Error('Unsupported QMS2 store version');
      dataKey = decrypt(wrappingKey, unb64(envelope.wrapNonce), unb64(envelope.wrappedKey), ad(storageKey, 'data-key'), 'Messenger key');
      requireKey(dataKey, 'QMS2 data key');
      const plain = decrypt(dataKey, unb64(envelope.stateNonce), unb64(envelope.ciphertext), ad(storageKey, 'state'), 'Messenger store');
      try { state = validateState(JSON.parse(td.decode(plain))); }
      finally { sodiumApi().memzero(plain); }
    } else {
      dataKey = sodiumApi().randombytes_buf(32);
    }

    let saveQueue = Promise.resolve();
    let closed = false;
    function ensureOpen() { if (closed) throw new Error('QMS2 store is closed'); }
    function buildEnvelope(snapshot, keyForWrap) {
      const plain = te.encode(JSON.stringify(validateState(snapshot)));
      const wrapNonce = sodiumApi().randombytes_buf(24);
      const stateNonce = sodiumApi().randombytes_buf(24);
      try {
        return JSON.stringify({
          version: 2,
          cipher: 'xchacha20poly1305-ietf',
          wrapNonce: b64(wrapNonce),
          wrappedKey: b64(encrypt(keyForWrap, wrapNonce, dataKey, ad(storageKey, 'data-key'))),
          stateNonce: b64(stateNonce),
          ciphertext: b64(encrypt(dataKey, stateNonce, plain, ad(storageKey, 'state')))
        });
      } finally { sodiumApi().memzero(plain); }
    }
    function save() {
      ensureOpen();
      const snapshot = JSON.parse(JSON.stringify(state));
      saveQueue = saveQueue.then(() => localStorage.setItem(storageKey, buildEnvelope(snapshot, wrappingKey)));
      return saveQueue;
    }
    function rewrap(nextWrappingKey) {
      ensureOpen(); nextWrappingKey = requireKey(nextWrappingKey, 'new QMS2 unlock key');
      const snapshot = JSON.parse(JSON.stringify(state));
      saveQueue = saveQueue.then(() => {
        localStorage.setItem(storageKey, buildEnvelope(snapshot, nextWrappingKey));
        sodiumApi().memzero(wrappingKey); wrappingKey = new Uint8Array(nextWrappingKey);
      });
      return saveQueue;
    }
    function close() {
      if (closed) return;
      closed = true;
      sodiumApi().memzero(dataKey); sodiumApi().memzero(wrappingKey);
    }
    return { storageKey, state, save, rewrap, close };
  }

  return { open, blank, validateState };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsStore;
