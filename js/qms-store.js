// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Password-wrapped, authenticated QMS1/Fast browser state. */
const QmsStore = (() => {
  'use strict';

  const PREFIX = 'qwc-qms1-fast-store:';
  const LOCK_PREFIX = 'qwc-qms1-fast-writer:';
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });
  const localLocks = new Set();

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
  function normalizeKdf(value) {
    if (!value) return null;
    if (value.name !== 'argon2id13'
        || !Number.isInteger(value.opslimit) || value.opslimit < 1 || value.opslimit > 4
        || !Number.isInteger(value.memlimit) || value.memlimit < 8 * 1024 * 1024 || value.memlimit > 128 * 1024 * 1024
        || typeof value.salt !== 'string') throw new Error('Invalid QMS1/Fast KDF metadata');
    let salt;
    try { salt = unb64(value.salt); } catch (_) { throw new Error('Invalid QMS1/Fast KDF salt'); }
    if (salt.length !== 16) throw new Error('Invalid QMS1/Fast KDF salt');
    return {
      name: 'argon2id13',
      opslimit: value.opslimit,
      memlimit: value.memlimit,
      salt: value.salt
    };
  }
  function sameKdf(left, right) {
    return !!left === !!right && (!left || (left.name === right.name
      && left.opslimit === right.opslimit && left.memlimit === right.memlimit
      && left.salt === right.salt));
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

  async function acquireWriterLock(storageKey) {
    const lockName = LOCK_PREFIX + storageKey.slice(PREFIX.length);
    if (typeof navigator !== 'undefined') {
      if (!navigator.locks || typeof navigator.locks.request !== 'function') {
        throw new Error('This browser cannot safely coordinate Messenger storage across tabs');
      }
      let settleAcquired;
      let releaseLock;
      const acquired = new Promise(resolve => { settleAcquired = resolve; });
      const request = navigator.locks.request(
        lockName,
        { mode: 'exclusive', ifAvailable: true },
        lock => {
          if (!lock) {
            settleAcquired(false);
            return undefined;
          }
          settleAcquired(true);
          return new Promise(resolve => { releaseLock = resolve; });
        }
      ).catch(error => {
        settleAcquired(error);
        throw error;
      });
      const acquisition = await acquired;
      if (acquisition instanceof Error) throw acquisition;
      if (!acquisition) {
        await request;
        throw new Error('Messenger is already open for this wallet in another tab');
      }
      let released = false;
      return {
        release() {
          if (released) return;
          released = true;
          releaseLock();
        },
        done: request.catch(() => {})
      };
    }

    // Node-based regression tests do not expose navigator.locks. Keep the same
    // single-writer invariant within that realm without pretending that this
    // fallback provides browser cross-tab coordination.
    if (localLocks.has(lockName)) throw new Error('Messenger is already open for this wallet in another tab');
    localLocks.add(lockName);
    let released = false;
    return {
      release() {
        if (released) return;
        released = true;
        localLocks.delete(lockName);
      },
      done: Promise.resolve()
    };
  }

  async function open(wallet, unlockKey, kdfMetadata) {
    await sodiumApi().ready;
    if (!wallet || !wallet.address || !wallet.privateSpendKeyHex) {
      throw new Error('QMS1/Fast requires an unlocked full wallet');
    }
    let wrappingKey = requireKey(unlockKey, 'QMS1/Fast session key');
    const kdf = normalizeKdf(kdfMetadata);
    const storageKey = PREFIX + await walletId(wallet.address);
    const writerLock = await acquireWriterLock(storageKey);
    let envelope = null;
    let dataKey;
    let state = blank();
    try {
      try {
        envelope = JSON.parse(localStorage.getItem(storageKey) || 'null');
      } catch (_) {
        throw new Error('Invalid QMS1/Fast store envelope');
      }

      if (envelope) {
        if (envelope.version !== 2 || envelope.profile !== 'qms1-fast'
            || envelope.cipher !== 'xchacha20poly1305-ietf') {
          throw new Error('Unsupported QMS1/Fast store version');
        }
        const persistedKdf = normalizeKdf(envelope.kdf);
        if (persistedKdf && !sameKdf(persistedKdf, kdf)) {
          throw new Error('QMS1/Fast Session password metadata does not match this wallet store');
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
    } catch (error) {
      sodiumApi().memzero(wrappingKey);
      if (dataKey) sodiumApi().memzero(dataKey);
      writerLock.release();
      throw error;
    }

    let saveQueue = Promise.resolve();
    let closed = false;
    let closePromise = null;
    function ensureOpen() {
      if (closed) throw new Error('QMS1/Fast store is closed');
    }
    function buildEnvelope(snapshot) {
      const plaintext = te.encode(JSON.stringify(validateState(snapshot)));
      const wrapNonce = sodiumApi().randombytes_buf(24);
      const stateNonce = sodiumApi().randombytes_buf(24);
      try {
        const envelope = {
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
        };
        if (kdf) envelope.kdf = kdf;
        return JSON.stringify(envelope);
      } finally {
        sodiumApi().memzero(plaintext);
      }
    }
    function save() {
      ensureOpen();
      const snapshot = JSON.parse(JSON.stringify(state));
      // Encryption is completed while the store is open. The queued operation
      // performs only the ordered storage write and never touches key material.
      const serializedEnvelope = buildEnvelope(snapshot);
      const pending = saveQueue.then(() => {
        localStorage.setItem(storageKey, serializedEnvelope);
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    function close() {
      if (closePromise) return closePromise;
      closed = true;
      closePromise = saveQueue.finally(() => {
        sodiumApi().memzero(dataKey);
        sodiumApi().memzero(wrappingKey);
        writerLock.release();
      });
      return closePromise;
    }

    return { get state() { return state; }, save, close, storageKey };
  }

  return { open, blank, validateState };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsStore;
