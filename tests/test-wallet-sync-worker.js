'use strict';

const path = require('path');
const assert = require('assert');
const { Worker: NodeWorker } = require('worker_threads');

global.location = { origin: process.env.QWC_SYNC_ORIGIN || 'https://feature-qms-messenger-web.qwertycoin-web-wallet.pages.dev' };

let workerInstance;
class BrowserWorker {
  constructor(scriptUrl) {
    const relativeScript = scriptUrl.replace(/^\/+/, '').split('?')[0];
    this.worker = new NodeWorker(path.join(__dirname, 'qwc-worker-node-shim.js'), {
      workerData: { script: path.resolve(__dirname, '..', relativeScript) }
    });
    workerInstance = this.worker;
    this.worker.on('message', data => {
      if (this.onmessage) this.onmessage({ data });
    });
    this.worker.on('error', error => {
      console.error('[worker error]', error);
      if (this.onerror) this.onerror(error);
    });
  }
  postMessage(data) { this.worker.postMessage(data); }
}

global.Worker = BrowserWorker;
const QwcWalletEngine = require('../js/qwc-wallet-engine.js');

(async () => {
  let generated;
  let restored;
  try {
    generated = await QwcWalletEngine.createRandomWallet('English');
    const seed = await generated.getSeed();
    await generated.close();
    generated = null;
    restored = await QwcWalletEngine.restoreFromSeed(seed, 0);
    const daemonHeight = await restored.getDaemonHeight();
    assert(Number.isSafeInteger(daemonHeight) && daemonHeight > 0, 'daemon height must be positive');
    await restored.sync(0);
    const walletHeight = await restored.getHeight();
    assert.strictEqual(walletHeight, daemonHeight, 'wallet must reach the daemon height');
    console.log(`  actual QWC worker/WASM genesis sync passed at height ${walletHeight}`);
  } finally {
    if (restored) await restored.close();
    if (generated) await generated.close();
    if (workerInstance) await workerInstance.terminate();
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
