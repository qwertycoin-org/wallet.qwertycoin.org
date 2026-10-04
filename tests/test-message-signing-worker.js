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
const QmsProtocol = require('../js/qms-protocol.js');

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

    const txBase = {
      accountIndex: 0,
      destinations: [{ address, amount: '1' }],
      priority: 1,
      relay: false,
      canSplit: false
    };
    await assert.rejects(
      signingWallet.createTx(Object.assign({}, txBase, { extraHex: '0' })),
      /Invalid custom tx extra hex/
    );
    await assert.rejects(
      signingWallet.createTx(Object.assign({}, txBase, { extraHex: '02' })),
      /Custom tx extra is not structurally valid/
    );
    await assert.rejects(
      signingWallet.createTx(Object.assign({}, txBase, { extraHex: '00'.repeat(1061) })),
      /Custom tx extra exceeds the relay limit/
    );
    await assert.rejects(
      signingWallet.createTx(Object.assign({}, txBase, { extraHex: '02017201' + '00'.repeat(32) })),
      /Custom tx extra is not canonically ordered/
    );
    let acceptedExtraError = null;
    try {
      const fragment = {
        version: 1,
        profile: 1,
        flags: 0,
        messageId: new Uint8Array(16).fill(2),
        index: 0,
        count: 1,
        ciphertextSize: 600,
        discoveryHint: new Uint8Array(16).fill(3),
        ciphertextHash: new Uint8Array(32).fill(4),
        mac: new Uint8Array(16).fill(5),
        data: new Uint8Array(600).fill(6)
      };
      const qmsExtraHex = QmsProtocol.hex(QmsProtocol.carrierExtra(fragment));
      assert(qmsExtraHex.includes('72514d5331'), 'carrier must contain the QMS subtype and magic');
      // The empty wallet must fail later for lack of funds, proving the full
      // three-segment carrier crossed JavaScript → worker → TS → C++/WASM and
      // passed Core's structural and canonical-order checks unchanged.
      await signingWallet.createTx(Object.assign({}, txBase, { extraHex: qmsExtraHex }));
    } catch (error) {
      acceptedExtraError = error;
    }
    assert(acceptedExtraError, 'an unfunded wallet unexpectedly constructed a transaction');
    assert(!/custom tx extra/i.test(acceptedExtraError.message), acceptedExtraError.message);

    if (process.argv.includes('--evidence')) {
      console.log(JSON.stringify({
        address,
        message,
        signature,
        signatureType: valid.signatureType,
        tamperRejected: true
      }));
    } else {
      console.log('  actual qwertycoin-ts worker/WASM signing and custom-extra bridge checks passed');
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
