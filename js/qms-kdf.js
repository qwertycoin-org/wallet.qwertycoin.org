// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Argon2id dispatch for QMS secrets. Browser work runs outside the UI thread. */
const QmsKdf = (() => {
  'use strict';

  let worker = null;
  let sequence = 0;
  const pending = new Map();

  function requireSalt(value) {
    const salt = value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value || []);
    if (salt.length !== 16) throw new Error('QMS Argon2id salt must be 16 bytes');
    return salt;
  }
  function fallback(password, salt, opslimit, memlimit, bytes) {
    if (typeof sodium === 'undefined') throw new Error('QMS Argon2id is unavailable');
    const result = sodium.crypto_pwhash(
      bytes, String(password), salt, opslimit, memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13);
    if (!(result instanceof Uint8Array) || result.length !== bytes) throw new Error('QMS Argon2id derivation failed');
    return new Uint8Array(result);
  }
  function rejectPending(error) {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
    if (worker) worker.terminate();
    worker = null;
  }
  function getWorker() {
    if (worker) return worker;
    worker = new Worker('js/qms-kdf-worker.js');
    worker.addEventListener('message', event => {
      const message = event.data || {};
      const request = pending.get(message.id);
      if (!request) return;
      pending.delete(message.id);
      if (message.error) request.reject(new Error(message.error));
      else request.resolve(new Uint8Array(message.key));
    });
    worker.addEventListener('error', event => rejectPending(new Error(event.message || 'QMS Argon2id worker failed')));
    return worker;
  }
  async function derive(password, saltValue, opslimit, memlimit, bytes = 32) {
    const salt = requireSalt(saltValue);
    if (!Number.isInteger(opslimit) || opslimit < 1 || opslimit > 4
        || !Number.isInteger(memlimit) || memlimit < 8 * 1024 * 1024 || memlimit > 128 * 1024 * 1024
        || !Number.isInteger(bytes) || bytes < 16 || bytes > 64) {
      throw new Error('Invalid QMS Argon2id parameters');
    }
    if (typeof Worker === 'undefined') return fallback(password, salt, opslimit, memlimit, bytes);
    const id = ++sequence;
    const workerInstance = getWorker();
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      workerInstance.postMessage({ id, password: String(password), salt, opslimit, memlimit, bytes }, [salt.buffer]);
    });
  }

  return { derive };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsKdf;
