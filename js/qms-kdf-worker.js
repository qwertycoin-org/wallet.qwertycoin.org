// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT
'use strict';

importScripts('../vendor/libsodium/libsodium-sumo.js', '../vendor/libsodium/libsodium-wrappers.js');

self.addEventListener('message', async event => {
  const message = event.data || {};
  try {
    await sodium.ready;
    const salt = new Uint8Array(message.salt || []);
    if (salt.length !== 16
        || !Number.isInteger(message.opslimit) || message.opslimit < 1 || message.opslimit > 4
        || !Number.isInteger(message.memlimit) || message.memlimit < 8 * 1024 * 1024 || message.memlimit > 128 * 1024 * 1024
        || !Number.isInteger(message.bytes) || message.bytes < 16 || message.bytes > 64) {
      throw new Error('Invalid QMS Argon2id worker request');
    }
    const key = sodium.crypto_pwhash(
      message.bytes,
      String(message.password),
      salt,
      message.opslimit,
      message.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const output = new Uint8Array(key);
    self.postMessage({ id: message.id, key: output }, [output.buffer]);
  } catch (error) {
    self.postMessage({ id: message.id, error: error && error.message ? error.message : String(error) });
  }
});
