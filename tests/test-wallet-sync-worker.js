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
    const messengerRegressionBlocks = await scanner.getBlocksByRange(10602, 10645);
    const messengerRegressionCases = [
      { height: 10602, txHash: 'b24727104f05efbdfc825061dbbca9daa03b6bb2ffd7b4c0e78a2b69e34ee024' },
      { height: 10645, txHash: '83b4636857b9dcb94a76eaae16d7305de1ca3f52bd53287f688410b60d2fbe54' }
    ];
    for (const regression of messengerRegressionCases) {
      const block = messengerRegressionBlocks.find(candidate => Number(candidate.height) === regression.height);
      assert(block, `Messenger regression block ${regression.height} is missing`);
      const txs = [].concat(block.minerTx ? [block.minerTx] : [], Array.isArray(block.txs) ? block.txs : []);
      const tx = txs.find(candidate => candidate && candidate.hash === regression.txHash);
      assert(tx, `Messenger regression transaction ${regression.txHash} is missing`);
      assert((Array.isArray(tx.extra) && tx.extra.length > 0) || (typeof tx.extraHex === 'string' && tx.extraHex.length > 0),
        `Messenger regression transaction ${regression.txHash} has no carrier extra`);
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
