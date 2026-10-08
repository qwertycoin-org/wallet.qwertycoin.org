'use strict';

const assert = require('assert');
const path = require('path');
const { Worker: NodeWorker } = require('worker_threads');

global.Keccak256 = require('../js/keccak256.js');
global.QwertycoinEd25519 = require('../js/qwertycoin-ed25519.js');
global.QwertycoinWordList = require('../js/qwertycoin-wordlist.js');
require('../js/qwertycoin-english-wordlist.js');
require('../js/qwertycoin-wordlists-all.js');
global.QwertycoinKeys = require('../js/qwertycoin-keys.js');

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

function legacyBrowserCrc32(str) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i);
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function legacyGermanPhrase(canonicalPhrase) {
  const dataWords = canonicalPhrase.trim().split(/\s+/).slice(0, 24);
  const checksumInput = dataWords
    .map(word => word.toLowerCase().substring(0, 4))
    .join('');
  const checksumIndex = legacyBrowserCrc32(checksumInput) % dataWords.length;
  return [...dataWords, dataWords[checksumIndex]].join(' ');
}

const LANGUAGES = [
  ['english', 'English'],
  ['spanish', 'Spanish'],
  ['french', 'French'],
  ['german', 'German'],
  ['italian', 'Italian'],
  ['portuguese', 'Portuguese'],
  ['russian', 'Russian'],
  ['japanese', 'Japanese'],
  ['chinese_simplified', 'Chinese (simplified)'],
  ['dutch', 'Dutch'],
  ['esperanto', 'Esperanto'],
  ['lojban', 'Lojban'],
];

(async function () {
  try {
    for (const [browserLanguage, coreLanguage] of LANGUAGES) {
      let generatedWallet;
      let restoredWallet;
      try {
        // Core/WASM is the source of truth for canonical word spelling and
        // checksum selection. No seed is logged or persisted by this test.
        generatedWallet = await QwcWalletEngine.createRandomWallet(coreLanguage);
        const expectedAddress = await generatedWallet.getAddress(0, 0);
        const privateSpendKey = await generatedWallet.getPrivateSpendKey();
        const canonicalSeed = await generatedWallet.getSeed();

        const browserKeys = QwertycoinKeys.deriveFromMnemonic(
          canonicalSeed,
          null,
          'mainnet'
        );
        assert.strictEqual(browserKeys.address, expectedAddress, `${browserLanguage}: Core seed address`);
        assert.strictEqual(browserKeys.privateSpendKeyHex, privateSpendKey, `${browserLanguage}: Core seed spend key`);
        assert.strictEqual(browserKeys.mnemonic, canonicalSeed, `${browserLanguage}: canonical phrase preserved`);

        const reconstructed = QwertycoinKeys.deriveFromSpendKey(
          privateSpendKey,
          'mainnet',
          browserLanguage
        );
        assert.strictEqual(reconstructed.mnemonic, canonicalSeed, `${browserLanguage}: browser checksum matches Core`);

        restoredWallet = await QwcWalletEngine.restoreFromSeed(reconstructed.mnemonic, 0);
        assert.strictEqual(
          await restoredWallet.getAddress(0, 0),
          expectedAddress,
          `${browserLanguage}: browser phrase restores through Worker/WASM`
        );

        if (browserLanguage === 'german') {
          const lowerCaseKeys = QwertycoinKeys.deriveFromMnemonic(
            canonicalSeed.toLowerCase(),
            null,
            'mainnet'
          );
          assert.strictEqual(lowerCaseKeys.address, expectedAddress, 'german: case-insensitive import');

          const lowerCaseWallet = await QwcWalletEngine.restoreFromSeed(
            canonicalSeed.toLowerCase(),
            0
          );
          try {
            assert.strictEqual(
              await lowerCaseWallet.getAddress(0, 0),
              expectedAddress,
              'german: lowercase phrase restores through Worker/WASM'
            );
          } finally {
            await lowerCaseWallet.close();
          }
        }
      } finally {
        if (restoredWallet) await restoredWallet.close();
        if (generatedWallet) await generatedWallet.close();
      }
    }

    let canonical;
    let legacy;
    let expected;
    for (let byte = 1; byte < 256; byte++) {
      expected = QwertycoinKeys.deriveFromSpendKey(
        byte.toString(16).padStart(2, '0').repeat(32),
        'mainnet',
        'german'
      );
      canonical = expected.mnemonic;
      legacy = legacyGermanPhrase(canonical);
      if (legacy !== canonical) break;
    }
    assert.notStrictEqual(legacy, canonical, 'legacy checksum fixture');
    const migrated = QwertycoinKeys.deriveFromMnemonic(legacy, null, 'mainnet');
    assert.strictEqual(migrated.address, expected.address, 'legacy German address');
    assert.strictEqual(migrated.mnemonic, canonical, 'legacy German canonical backup');
    assert.strictEqual(migrated.mnemonicMigratedFromLegacyBrowserChecksum, true);

    const migratedWallet = await QwcWalletEngine.restoreFromSeed(migrated.mnemonic, 0);
    try {
      assert.strictEqual(
        await migratedWallet.getAddress(0, 0),
        expected.address,
        'migrated German phrase restores through Worker/WASM'
      );
    } finally {
      await migratedWallet.close();
    }

    console.log('  all 12 Core/CLI/GUI seed languages and the retired browser checksum round-trip through Worker/WASM');
  } finally {
    if (workerInstance) await workerInstance.terminate();
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
