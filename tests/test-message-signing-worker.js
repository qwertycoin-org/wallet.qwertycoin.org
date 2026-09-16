'use strict';

const assert = require('assert');
const path = require('path');
const { Worker: NodeWorker } = require('worker_threads');

let workerInstance;
class BrowserWorker {
  constructor(scriptUrl) {
    const relativeScript = scriptUrl.replace(/^\/+/, '').split('?')[0];
    this.worker = new NodeWorker(path.join(__dirname, 'qwc-worker-node-shim.js'), {
      workerData: { script: path.resolve(__dirname, '..', relativeScript) }
    });
    this.worker.unref();
    workerInstance = this.worker;
    this.worker.on('message', data => {
      if (this.onmessage) this.onmessage({ data });
    });
    this.worker.on('error', error => {
      if (this.onerror) this.onerror(error);
    });
  }

  postMessage(data) {
    this.worker.postMessage(data);
  }

  terminate() {
    return this.worker.terminate();
  }
}

global.Worker = BrowserWorker;
const QwcWalletEngine = require('../js/qwc-wallet-engine.js');

(async function () {
  const message = ' QWC worker/WASM exact-byte test\nline 2: e\u0301 ';
  let generatedWallet;
  let signingWallet;
  let watchOnlyVerifier;
  try {
    generatedWallet = await QwcWalletEngine.createRandomWallet('English');
    const address = await generatedWallet.getAddress(0, 0);
    const privateSpendKey = await generatedWallet.getPrivateSpendKey();
    const privateViewKey = await generatedWallet.getPrivateViewKey();
    await generatedWallet.close();
    generatedWallet = null;

    // Exercise the exact in-memory path used by the dashboard. The signing
    // wallet has no daemon configuration, and the verifier deliberately has
    // no spend key so watch-only wallets remain verification-only.
    signingWallet = await QwcWalletEngine.createFromKeys({
      primaryAddress: address,
      privateSpendKey,
      privateViewKey
    });
    watchOnlyVerifier = await QwcWalletEngine.createFromKeys({
      primaryAddress: address,
      privateViewKey
    });

    assert.strictEqual(await signingWallet.getAddress(0, 0), address);
    assert.strictEqual(await watchOnlyVerifier.getAddress(0, 0), address);

    const signature = await signingWallet.signMessage(message, 0, 0, 0);
    const valid = await watchOnlyVerifier.verifyMessage(message, address, signature);
    const tampered = await watchOnlyVerifier.verifyMessage(message + ' ', address, signature);

    assert.strictEqual(valid.isGood, true);
    assert.strictEqual(valid.signatureType, 0);
    assert.strictEqual(tampered.isGood, false);

    if (process.argv.includes('--evidence')) {
      console.log(JSON.stringify({
        address,
        message,
        signature,
        signatureType: valid.signatureType,
        tamperRejected: true
      }));
    } else {
      console.log('  actual qwertycoin-ts worker/WASM signing checks passed');
    }
  } finally {
    if (watchOnlyVerifier) await watchOnlyVerifier.close();
    if (signingWallet) await signingWallet.close();
    if (generatedWallet) await generatedWallet.close();
    if (workerInstance) await workerInstance.terminate();
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
