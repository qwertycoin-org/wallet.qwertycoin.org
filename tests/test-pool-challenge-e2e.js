'use strict';

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { Worker: NodeWorker } = require('worker_threads');

const QwcMessageSigning = require('../js/message-signing.js');

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

function buildChallenge(address, nonce, expiresAt, threshold) {
  return [
    'Qwertycoin pool payout threshold',
    'Address: ' + address,
    'Threshold: ' + (threshold || '2500.125') + ' QWC',
    'Nonce: ' + nonce,
    'Expires: ' + expiresAt,
    'Domain: pool.qwertycoin.org'
  ].join('\n');
}

class LocalPool {
  constructor(verifierWallet, now) {
    this.verifierWallet = verifierWallet;
    this.now = now;
    this.issued = new Map();
  }

  issue(address, expiresAt) {
    const nonce = crypto.randomBytes(24).toString('hex');
    const message = buildChallenge(
      address,
      nonce,
      expiresAt || new Date(this.now() + 5 * 60 * 1000).toISOString()
    );
    this.issued.set(nonce, { address, message, consumed: false });
    return message;
  }

  async accept(address, message, signature) {
    const parsed = QwcMessageSigning.parsePoolChallenge(message, address, this.now());
    const record = this.issued.get(parsed.nonce);
    if (!record || record.address !== address || record.message !== message) {
      throw new Error('challenge bytes were not issued by this pool');
    }
    if (record.consumed) throw new Error('challenge nonce was already consumed');
    const verification = await this.verifierWallet.verifyMessage(message, address, signature);
    QwcMessageSigning.requireSpendVerification(verification);
    record.consumed = true;
    return { accepted: true, nonce: parsed.nonce };
  }
}

(async function () {
  let generatedWallet;
  let signingWallet;
  let wrongWallet;
  let watchOnlyWallet;
  try {
    generatedWallet = await QwcWalletEngine.createRandomWallet('English');
    const address = await generatedWallet.getAddress(0, 0);
    const privateSpendKey = await generatedWallet.getPrivateSpendKey();
    const privateViewKey = await generatedWallet.getPrivateViewKey();
    await generatedWallet.close();
    generatedWallet = null;

    signingWallet = await QwcWalletEngine.createFromKeys({
      primaryAddress: address,
      privateSpendKey,
      privateViewKey
    });
    watchOnlyWallet = await QwcWalletEngine.createFromKeys({
      primaryAddress: address,
      privateViewKey
    });
    wrongWallet = await QwcWalletEngine.createRandomWallet('English');
    const wrongAddress = await wrongWallet.getAddress(0, 0);

    const nowMs = Date.parse('2026-09-16T12:30:00.000Z');
    const pool = new LocalPool(watchOnlyWallet, () => nowMs);
    const challenge = pool.issue(address);
    const parsed = QwcMessageSigning.parsePoolChallenge(challenge, address, nowMs);
    assert.strictEqual(parsed.address, address);
    const signature = await signingWallet.signMessage(challenge, 0, 0, 0);

    const tampered = challenge.replace('Threshold: 2500.125 QWC', 'Threshold: 2500.126 QWC');
    await assert.rejects(() => pool.accept(address, tampered, signature), /not issued|did not verify/);

    assert.throws(
      () => QwcMessageSigning.parsePoolChallenge(challenge, wrongAddress, nowMs),
      /does not match/
    );
    const wrongSignature = await wrongWallet.signMessage(challenge, 0, 0, 0);
    await assert.rejects(() => pool.accept(address, challenge, wrongSignature), /did not verify/);

    await assert.rejects(
      () => watchOnlyWallet.signMessage(challenge, 0, 0, 0),
      /view.only|spend key|sign/i
    );

    const crlf = challenge.replaceAll('\n', '\r\n');
    assert.throws(() => QwcMessageSigning.parsePoolChallenge(crlf, address, nowMs), /line endings/);
    await assert.rejects(() => pool.accept(address, crlf, signature), /line endings/);

    const expired = pool.issue(address, new Date(nowMs - 1).toISOString());
    assert.throws(() => QwcMessageSigning.parsePoolChallenge(expired, address, nowMs), /expired/);
    const expiredSignature = await signingWallet.signMessage(expired, 0, 0, 0);
    await assert.rejects(() => pool.accept(address, expired, expiredSignature), /expired/);

    const accepted = await pool.accept(address, challenge, signature);
    assert.strictEqual(accepted.accepted, true);
    await assert.rejects(() => pool.accept(address, challenge, signature), /already consumed/);

    console.log(JSON.stringify({
      localPool: 'isolated in-process acceptance fixture',
      signer: 'bundled qwertycoin-ts worker/WASM',
      acceptedOnce: true,
      negatives: {
        tamper: 'rejected',
        expiry: 'rejected',
        replay: 'rejected',
        wrongWallet: 'rejected',
        watchOnly: 'rejected',
        crlf: 'rejected'
      },
      productionMutation: false
    }));
  } finally {
    if (wrongWallet) await wrongWallet.close();
    if (watchOnlyWallet) await watchOnlyWallet.close();
    if (signingWallet) await signingWallet.close();
    if (generatedWallet) await generatedWallet.close();
    if (workerInstance) await workerInstance.terminate();
  }
})().catch(error => {
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
});
