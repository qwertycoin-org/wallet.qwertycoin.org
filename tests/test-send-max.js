'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const QwertycoinSend = require('../js/qwertycoin-send.js');

let passed = 0;

function test (name, fn) {
  fn();
  passed += 1;
  console.log(`  ok   ${name}`);
}

console.log('\n  Qwertycoin Web Wallet — send max contract\n');

test('ordinary sends do not subtract their fee from the recipient', () => {
  const config = QwertycoinSend.createWalletTxConfig(
    'QWC-destination', 98172400n, undefined, 2, false
  );
  assert.strictEqual(config.destinations[0].amount, '98172400');
  assert.strictEqual(config.priority, 2);
  assert.strictEqual(config.relay, false);
  assert.strictEqual(config.canSplit, false);
  assert(!Object.prototype.hasOwnProperty.call(config, 'subtractFeeFrom'));
});

test('send max delegates exact fee subtraction to the wallet core', () => {
  const config = QwertycoinSend.createWalletTxConfig(
    'QWC-destination', 98172400n, undefined, 2, true
  );
  assert.deepStrictEqual(config.subtractFeeFrom, [0]);
  assert.strictEqual(config.destinations[0].amount, '98172400');
});

test('send max reports the exact net amount and preserves the full-balance invariant', () => {
  const preview = {
    signedTxHex: 'deadbeef',
    txs: [{
      fee: '40000',
      changeAmount: '0',
      outgoingTransfer: {
        destinations: [{ address: 'QWC-destination', amount: '98132400' }]
      }
    }]
  };
  const summary = QwertycoinSend.summarizeWalletTxPreview(preview, 98172400n, true);
  assert.strictEqual(summary.amount_atomic, 98132400n);
  assert.strictEqual(summary.fee_atomic, 40000n);
  assert.strictEqual(summary.total_atomic, 98172400n);
});

test('send max fails closed when the core returns an inconsistent recipient amount', () => {
  assert.throws(() => QwertycoinSend.summarizeWalletTxPreview({
    txs: [{
      fee: '40000',
      outgoingTransfer: { destinations: [{ amount: '98132399' }] }
    }]
  }, 98172400n, true), /unexpected recipient amount/);
});

test('send max rejects split, change-producing, and fee-exhausted previews', () => {
  assert.throws(() => QwertycoinSend.summarizeWalletTxPreview({ txs: [{}, {}] }, 10n, true),
    /exactly one transaction/);
  assert.throws(() => QwertycoinSend.summarizeWalletTxPreview({
    txs: [{ fee: '4', changeAmount: '1', outgoingTransfer: { destinations: [{ amount: '6' }] } }]
  }, 10n, true), /unexpectedly created change/);
  assert.throws(() => QwertycoinSend.summarizeWalletTxPreview({
    txs: [{ fee: '10', outgoingTransfer: { destinations: [{ amount: '0' }] } }]
  }, 10n, true), /does not cover the network fee/);
});

test('the dashboard calculates send max instead of copying the displayed balance', () => {
  const dashboard = fs.readFileSync(path.join(__dirname, '..', 'js', 'dashboard-page.js'), 'utf8');
  assert(dashboard.includes('sendMaxBtn.addEventListener(\'click\', async () =>'));
  assert(dashboard.includes('QwertycoinSend.createWalletTxConfig('));
  assert(dashboard.includes('QwertycoinSend.summarizeWalletTxPreview('));
  assert(dashboard.includes('sendAmountEl.value = qwcAtomicToDisplay(maximumAtomic)'));
  assert(!dashboard.includes('sendAmountEl.value = bal'));
});

console.log(`\n  ${passed} send-max tests passed\n`);
