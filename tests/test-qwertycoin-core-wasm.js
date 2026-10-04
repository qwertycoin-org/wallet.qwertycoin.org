'use strict';

const assert = require('assert');
const path = require('path');

const artifactDir = path.resolve(__dirname, '../vendor/qwertycoin-core-wasm');
const factory = require(path.join(artifactDir, 'qwertycoin-core-wasm.js'));

(async () => {
  assert.strictEqual(typeof factory, 'function', 'Qwertycoin Core WASM factory export is missing');
  const module = await factory({
    locateFile: filename => path.join(artifactDir, filename),
  });
  assert.strictEqual(typeof module.decode_address, 'function', 'decode_address WASM export is missing');
  assert.strictEqual(typeof module.send_step2__try_create_transaction, 'function',
    'send-step-2 WASM export is missing');
  console.log('  branded Qwertycoin Core WASM factory and binary load passed');
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
