// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Password-wrapped, authenticated QMS1/Fast browser state. */
const QmsStore = (() => {
  'use strict';

  const PREFIX = 'qwc-qms1-fast-store:';
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });

  function sodiumApi() {
    if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded');
    return sodium;
  }
  function b64(input) { return sodiumApi().to_base64(input, sodiumApi().base64_variants.ORIGINAL); }
  function unb64(value) { return sodiumApi().from_base64(String(value), sodiumApi().base64_variants.ORIGINAL); }
  function associatedData(storageKey, purpose) {
    return te.encode(`QWC-QMS1-FAST-WEB-STORE\u0000${purpose}\u0000${storageKey}`);
  }
  async function walletId(address) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(String(address))));
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function blank() {
    return {
      version: 1,
      identity: null,
      ownInvitation: null,
      contacts: [],
      messages: [],
      plans: [],
      reassembly: [],
      scan: { height: 0, blockHash: '' }
    };
  }
  function validateState(state) {
    if (!state || state.version !== 1 || !Array.isArray(state.contacts)
        || !Array.isArray(state.messages) || !Array.isArray(state.plans)
        || !Array.isArray(state.reassembly) || !state.scan) {
      throw new Error('invalid encrypted QMS1/Fast store');
    }
    return state;
  }
  function requireKey(value, label) {
    const key = value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value || []);
    if (key.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
    return key;
  }
  function encrypt(key, nonce, plaintext, additionalData) {
    return sodiumApi().crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, additionalData, null, nonce, key);
  }
  function decrypt(key, nonce, ciphertext, additionalData, label) {
    try {
      return sodiumApi().crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ciphertext, additionalData, nonce, key);
    } catch (_) {
      throw new Error(`Unable to decrypt this wallet's ${label}`);
    }
  }

  async function open(wallet, unlockKey) {
    await sodiumApi().ready;
    if (!wallet || !wallet.address || !wallet.privateSpendKeyHex) {
      throw new Error('QMS1/Fast requires an unlocked full wallet');
    }
    let wrappingKey = requireKey(unlockKey, 'QMS1/Fast session key');
    const storageKey = PREFIX + await walletId(wallet.address);
    let envelope = null;
    try {
      envelope = JSON.parse(localStorage.getItem(storageKey) || 'null');
    } catch (_) {
      throw new Error('Invalid QMS1/Fast store envelope');
    }

    let dataKey;
    let state = blank();
    if (envelope) {
      if (envelope.version !== 2 || envelope.profile !== 'qms1-fast'
          || envelope.cipher !== 'xchacha20poly1305-ietf') {
        throw new Error('Unsupported QMS1/Fast store version');
      }
      dataKey = requireKey(decrypt(
        wrappingKey,
        unb64(envelope.wrapNonce),
        unb64(envelope.wrappedKey),
        associatedData(storageKey, 'data-key'),
        'Messenger key'
      ), 'QMS1/Fast data key');
      const plaintext = decrypt(
        dataKey,
        unb64(envelope.stateNonce),
        unb64(envelope.ciphertext),
        associatedData(storageKey, 'state'),
        'Messenger store'
      );
      try {
        state = validateState(JSON.parse(td.decode(plaintext)));
      } finally {
        sodiumApi().memzero(plaintext);
      }
    } else {
      dataKey = sodiumApi().randombytes_buf(32);
    }

    let saveQueue = Promise.resolve();
    let closed = false;
    function ensureOpen() {
      if (closed) throw new Error('QMS1/Fast store is closed');
    }
    function buildEnvelope(snapshot) {
      const plaintext = te.encode(JSON.stringify(validateState(snapshot)));
      const wrapNonce = sodiumApi().randombytes_buf(24);
      const stateNonce = sodiumApi().randombytes_buf(24);
      try {
        return JSON.stringify({
          version: 2,
          profile: 'qms1-fast',
          cipher: 'xchacha20poly1305-ietf',
          wrapNonce: b64(wrapNonce),
          wrappedKey: b64(encrypt(
            wrappingKey, wrapNonce, dataKey,
            associatedData(storageKey, 'data-key'))),
          stateNonce: b64(stateNonce),
          ciphertext: b64(encrypt(
            dataKey, stateNonce, plaintext,
            associatedData(storageKey, 'state')))
        });
      } finally {
        sodiumApi().memzero(plaintext);
      }
    }
    function save() {
      ensureOpen();
      const snapshot = JSON.parse(JSON.stringify(state));
      const pending = saveQueue.then(() => {
        localStorage.setItem(storageKey, buildEnvelope(snapshot));
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    function close() {
      if (closed) return;
      closed = true;
      sodiumApi().memzero(dataKey);
      sodiumApi().memzero(wrappingKey);
    }

    return { get state() { return state; }, save, close, storageKey };
  }

  return { open, blank, validateState };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsStore;
