// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** AES-GCM encrypted, wallet-bound QMS state. No private QMS material is stored in plaintext. */
const QmsStore = (() => {
  'use strict';
  const PREFIX = 'qwc-qms-store-v1:';
  const te = new TextEncoder();
  const td = new TextDecoder();

  function b64(input) { let s = ''; for (const b of input) s += String.fromCharCode(b); return btoa(s); }
  function unb64(value) { const s = atob(value), out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
  async function digestHex(value) { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(value))), b => b.toString(16).padStart(2, '0')).join(''); }
  async function deriveKey(privateSpendKeyHex, salt) {
    const material = await crypto.subtle.importKey('raw', QmsProtocol.unhex(privateSpendKeyHex), 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('QWC-QMS-LOCAL-STORE-V1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  function blank() { return { version: 1, identity: null, ownInvitation: null, contacts: [], messages: [], plans: [], reassembly: [], scan: { height: 0, blockHash: '' } }; }
  function serializeState(state) { return JSON.stringify(state); }
  function validateState(state) {
    if (!state || state.version !== 1 || !Array.isArray(state.contacts) || !Array.isArray(state.messages) || !Array.isArray(state.plans)) throw new Error('invalid encrypted QMS store');
    return state;
  }

  async function open(walletKeys) {
    if (!walletKeys || !walletKeys.address || !walletKeys.privateSpendKeyHex) throw new Error('QMS requires an unlocked full wallet');
    const walletId = await digestHex(walletKeys.address); const storageKey = PREFIX + walletId;
    let envelope = null; try { envelope = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (_) {}
    const salt = envelope && envelope.salt ? unb64(envelope.salt) : crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(walletKeys.privateSpendKeyHex, salt); let state = blank();
    if (envelope) {
      try {
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(envelope.iv), additionalData: te.encode(storageKey) }, key, unb64(envelope.ciphertext));
        state = validateState(JSON.parse(td.decode(plain)));
      } catch (_) { throw new Error('Unable to decrypt this wallet’s Messenger store'); }
    }
    let saveQueue = Promise.resolve();
    function save() {
      const snapshot = serializeState(state);
      const pending = saveQueue.then(async () => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(storageKey) }, key, te.encode(snapshot)));
        localStorage.setItem(storageKey, JSON.stringify({ version: 1, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) }));
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    return { get state() { return state; }, save, storageKey };
  }
  return { open };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsStore;
