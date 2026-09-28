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
      workerData: {
        script: path.resolve(__dirname, '..', relativeScript),
        browserLike: true,
        origin: global.location.origin
      }
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
    const daemonHeightBefore = await restored.getDaemonHeight();
    assert(Number.isSafeInteger(daemonHeightBefore) && daemonHeightBefore > 0, 'daemon height must be positive');
    await restored.sync(0);
    const walletHeight = await restored.getHeight();
    const daemonHeightAfter = await restored.getDaemonHeight();
    assert(
      walletHeight >= daemonHeightBefore && walletHeight <= daemonHeightAfter,
      `wallet height ${walletHeight} must fall within the observed daemon window ${daemonHeightBefore}..${daemonHeightAfter}`
    );
    const scanner = await QwcWalletEngine.createDaemonScanner();
    const scannerHeight = await scanner.getHeight();
    const blocks = await scanner.getBlocksByRange(scannerHeight - 1, scannerHeight - 1);
    assert(Array.isArray(blocks) && blocks.length === 1, 'Messenger scanner must return the requested block');
    assert.strictEqual(Number(blocks[0].height), scannerHeight - 1, 'Messenger scanner returned the wrong block');
    const rangeStart = Math.max(0, scannerHeight - 20);
    const rangeEnd = scannerHeight - 1;
    const range = await scanner.getBlocksByRange(rangeStart, rangeEnd);
    assert.strictEqual(range.length, rangeEnd - rangeStart + 1,
      'Messenger scanner must return the complete requested block range');
    for (let offset = 0; offset < range.length; offset++) {
      assert.strictEqual(Number(range[offset].height), rangeStart + offset,
        `Messenger scanner returned a non-contiguous block at offset ${offset}`);
      assert.strictEqual(typeof range[offset].hash, 'string',
        `Messenger scanner returned a block without a hash at offset ${offset}`);
      assert.match(range[offset].prevHash, /^[0-9a-f]{64}$/i,
        `Messenger scanner returned a block without a previous hash at offset ${offset}`);
    }
    const genesisRangeEnd = Math.min(19, scannerHeight - 1);
    const genesisRange = await scanner.getBlocksByRange(0, genesisRangeEnd);
    assert.strictEqual(genesisRange.length, genesisRangeEnd + 1,
      'Messenger scanner must return the complete genesis block range');
    for (let offset = 0; offset < genesisRange.length; offset++) {
      assert.strictEqual(Number(genesisRange[offset].height), offset,
        `Messenger scanner returned a non-contiguous genesis block at offset ${offset}`);
      assert.strictEqual(typeof genesisRange[offset].hash, 'string',
        `Messenger scanner returned a genesis block without a hash at offset ${offset}`);
      assert.match(genesisRange[offset].prevHash, /^[0-9a-f]{64}$/i,
        `Messenger scanner returned a genesis block without a previous hash at offset ${offset}`);
    }
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
