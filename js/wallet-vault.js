// SPDX-License-Identifier: MIT
/**
 * wallet-vault.js — encrypted sessionStorage for derived wallet keys
 *
 * Two storage modes:
 *   • Plaintext   — { encrypted: false, keys: {...} }
 *   • Encrypted   — { encrypted: true, salt, iv, ciphertext } where
 *                   ciphertext = AES-GCM(
 *                     key   = PBKDF2-SHA256(password, salt, 250000, 32 bytes),
 *                     iv    = 12 random bytes,
 *                     plain = JSON.stringify(keys)
 *                   )
 *
 * The vault never holds the password — only the user does. If the user
 * supplies an empty password we fall back to plaintext (the same threat
 * model as the original implementation).
 *
 * Stored keys object shape (matches what verify.html / dashboard.html
 * already use):
 *   {
 *     address, network,
 *     privateSpendKeyHex, privateViewKeyHex,
 *     publicSpendKeyHex,  publicViewKeyHex
 *   }
 */

const WalletVault = (function () {
  'use strict';

  const STORAGE_KEY = 'monero-web-wallet';
  const PBKDF2_ITERATIONS = 250000;
  const QMS_PWHASH_OPSLIMIT = 2;
  const QMS_PWHASH_MEMLIMIT = 64 * 1024 * 1024;
  const QMS_PWHASH_BYTES = 32;
  const QMS_STORE_PREFIX = 'qwc-qms1-fast-store:';
  const QMS_DATABASE_NAME = 'qwc-qms1-fast';
  const QMS_DATABASE_VERSION = 1;
  const QMS_OBJECT_STORE = 'records';
  let qmsUnlockKey = null;
  let qmsKdfMetadata = null;

  function b64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function unb64(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function deriveQmsUnlockKey(password, salt, opslimit, memlimit) {
    if (typeof sodium === 'undefined') throw new Error('QMS1 password protection is unavailable');
    await sodium.ready;
    const key = sodium.crypto_pwhash(
      QMS_PWHASH_BYTES,
      String(password),
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    if (!(key instanceof Uint8Array) || key.length !== QMS_PWHASH_BYTES) throw new Error('QMS1 Argon2id key derivation failed');
    return key;
  }

  function replaceQmsUnlockKey(value) {
    if (qmsUnlockKey && typeof sodium !== 'undefined' && sodium.memzero) sodium.memzero(qmsUnlockKey);
    qmsUnlockKey = value ? new Uint8Array(value) : null;
  }

  function validateQmsKdf(value) {
    if (!value || value.name !== 'argon2id13'
        || !Number.isInteger(value.opslimit) || value.opslimit < 1 || value.opslimit > 4
        || !Number.isInteger(value.memlimit) || value.memlimit < 8 * 1024 * 1024 || value.memlimit > 128 * 1024 * 1024
        || typeof value.salt !== 'string') return null;
    let salt;
    try { salt = unb64(value.salt); } catch (_) { return null; }
    if (salt.length !== 16) return null;
    return {
      name: 'argon2id13',
      opslimit: value.opslimit,
      memlimit: value.memlimit,
      salt: value.salt
    };
  }

  function replaceQmsKdfMetadata(value) {
    qmsKdfMetadata = validateQmsKdf(value);
  }

  async function qmsStorageKey(address) {
    const bytes = new TextEncoder().encode(String(address || ''));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return QMS_STORE_PREFIX + Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  async function indexedQmsKdf(storageKey) {
    if (typeof indexedDB === 'undefined') return null;
    return new Promise(resolve => {
      let settled = false;
      const finish = value => {
        if (settled) return;
        settled = true;
        resolve(value || null);
      };
      let request;
      try { request = indexedDB.open(QMS_DATABASE_NAME, QMS_DATABASE_VERSION); }
      catch (_) { finish(null); return; }
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(QMS_OBJECT_STORE)) db.createObjectStore(QMS_OBJECT_STORE, { keyPath: 'key' });
      };
      request.onerror = () => finish(null);
      request.onblocked = () => finish(null);
      request.onsuccess = () => {
        const db = request.result;
        let tx;
        try { tx = db.transaction(QMS_OBJECT_STORE, 'readonly'); }
        catch (_) { db.close(); finish(null); return; }
        const get = tx.objectStore(QMS_OBJECT_STORE).get(`${storageKey}\u0000meta`);
        get.onsuccess = () => {
          const row = get.result;
          db.close();
          finish(row && row.record && row.record.version === 3 && row.record.profile === 'qms1-fast'
            ? validateQmsKdf(row.record.kdf) : null);
        };
        get.onerror = () => { db.close(); finish(null); };
      };
    });
  }

  async function persistedQmsKdf(address) {
    if (!address) return null;
    const storageKey = await qmsStorageKey(address);
    const indexed = await indexedQmsKdf(storageKey);
    if (indexed) return indexed;
    if (typeof localStorage === 'undefined') return null;
    try {
      const envelope = JSON.parse(localStorage.getItem(storageKey) || 'null');
      return envelope && (envelope.version === 2 || envelope.version === 3) && envelope.profile === 'qms1-fast'
        ? validateQmsKdf(envelope.kdf)
        : null;
    } catch (_) {
      return null;
    }
  }

  /**
   * Store wallet keys. If password is empty/falsy the keys are stored
   * in plaintext (encrypted:false). Otherwise they are AES-GCM encrypted.
   */
  async function store(keys, password) {
    replaceQmsUnlockKey(null);
    replaceQmsKdfMetadata(null);
    // If this is a freshly-created wallet, set the sessionStorage flag
    // here so it's impossible to miss regardless of which UI button
    // triggers the store.
    if (keys && keys.createdAtCurrentTip) {
      try { sessionStorage.setItem('monero-web-fresh-wallet', '1'); } catch (e) {}
    }
    if (!password) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
        encrypted: false,
        keys
      }));
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const persistedKdf = (typeof sodium !== 'undefined') ? await persistedQmsKdf(keys && keys.address) : null;
    const qmsKdf = (typeof sodium !== 'undefined') ? (persistedKdf || {
      name: 'argon2id13',
      opslimit: QMS_PWHASH_OPSLIMIT,
      memlimit: QMS_PWHASH_MEMLIMIT,
      salt: b64(crypto.getRandomValues(new Uint8Array(16)))
    }) : null;
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKey(password, salt, PBKDF2_ITERATIONS);
    const ct   = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(keys))
    ));
    const qmsKey = qmsKdf
      ? await deriveQmsUnlockKey(password, unb64(qmsKdf.salt), qmsKdf.opslimit, qmsKdf.memlimit)
      : null;
    replaceQmsUnlockKey(qmsKey);
    replaceQmsKdfMetadata(qmsKdf);
    const envelope = {
      encrypted:  true,
      version:    1,
      iterations: PBKDF2_ITERATIONS,
      salt:       b64(salt),
      iv:         b64(iv),
      ciphertext: b64(ct)
    };
    if (qmsKdf) envelope.qmsKdf = qmsKdf;
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  }

  function readBlob() {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  function hasBlob()    { return readBlob() !== null; }
  function isLocked()   { const b = readBlob(); return !!(b && b.encrypted); }

  /**
   * Read plaintext keys directly. Returns null if no blob, or if the
   * blob is encrypted (in which case the caller must call unlock()).
   */
  function readPlain() {
    const b = readBlob();
    if (!b || b.encrypted) return null;
    return b.keys;
  }

  /**
   * Decrypt an encrypted blob with the supplied password.
   * Throws on wrong password / corrupted ciphertext.
   */
  async function unlock(password) {
    replaceQmsUnlockKey(null);
    replaceQmsKdfMetadata(null);
    const b = readBlob();
    if (!b || !b.encrypted) throw new Error('No encrypted vault to unlock');
    const salt       = unb64(b.salt);
    const iv         = unb64(b.iv);
    const ct         = unb64(b.ciphertext);
    const iterations = (typeof b.iterations === 'number') ? b.iterations : PBKDF2_ITERATIONS;
    const key        = await deriveKey(password, salt, iterations);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    } catch (e) {
      throw new Error('Wrong password');
    }
    const qmsKdf = validateQmsKdf(b.qmsKdf);
    if (!qmsKdf) {
      replaceQmsUnlockKey(null);
      replaceQmsKdfMetadata(null);
    } else {
      replaceQmsUnlockKey(await deriveQmsUnlockKey(password, unb64(qmsKdf.salt), qmsKdf.opslimit, qmsKdf.memlimit));
      replaceQmsKdfMetadata(qmsKdf);
    }
    return JSON.parse(new TextDecoder().decode(plain));
  }

  function qmsKey() {
    return qmsUnlockKey ? new Uint8Array(qmsUnlockKey) : null;
  }

  function hasQmsKey() {
    return !!(qmsUnlockKey && qmsUnlockKey.length === QMS_PWHASH_BYTES);
  }

  function qmsKdf() {
    return qmsKdfMetadata ? Object.assign({}, qmsKdfMetadata) : null;
  }

  function clear() {
    replaceQmsUnlockKey(null);
    replaceQmsKdfMetadata(null);
    sessionStorage.removeItem(STORAGE_KEY);
  }

  return { store, hasBlob, isLocked, readPlain, unlock, qmsKey, qmsKdf, hasQmsKey, clear };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = WalletVault;
