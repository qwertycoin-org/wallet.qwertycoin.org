#!/usr/bin/env node
'use strict';

const assert = require('assert');
const history = require('../js/qms-transaction-history.js');

const firstHash = 'ab'.repeat(32);
const secondHash = 'cd'.repeat(32);
const ordinaryAtomicHash = 'ef'.repeat(32);
const rows = [
  { hash: firstHash, amount: '1' },
  { hash: secondHash.toUpperCase(), amount: '1' },
  { hash: ordinaryAtomicHash, amount: '1' }
];
const groups = [{
  messageId: 'message-1',
  transactionHashes: [firstHash.toUpperCase(), secondHash]
}];

const all = history.buildItems(rows, groups, 'all');
assert.strictEqual(all.length, 2);
assert.strictEqual(all[0].kind, 'messenger');
assert.strictEqual(all[0].matchedRows.length, 2);
assert.strictEqual(all[1].kind, 'payment');
assert.strictEqual(all[1].row.hash, ordinaryAtomicHash,
  'an ordinary one-atomic payment must not be guessed to be a Messenger carrier');

const payments = history.buildItems(rows, groups, 'payments');
assert.deepStrictEqual(payments.map(item => item.row.hash), [ordinaryAtomicHash]);

const messenger = history.buildItems(rows, groups, 'messenger');
assert.strictEqual(messenger.length, 1);
assert.strictEqual(messenger[0].kind, 'messenger');

const duplicateClaim = history.buildItems(
  [{ hash: firstHash, amount: '1' }],
  [
    { messageId: 'message-1', transactionHashes: [firstHash] },
    { messageId: 'message-2', transactionHashes: [firstHash] }
  ],
  'all'
);
assert.strictEqual(duplicateClaim.length, 1);
assert.strictEqual(duplicateClaim[0].kind, 'payment',
  'ambiguous local journals must fail open as normal history');

assert.strictEqual(history.normalizeHash('not-a-hash'), '');
assert.strictEqual(history.normalizeHash(firstHash.toUpperCase()), firstHash);

const chainRows = [
  { hash: firstHash, outgoing: true, selfTransfer: true, oneAtomicOutput: true, timestamp: 1700000000000 },
  { hash: secondHash, outgoing: true, selfTransfer: true, oneAtomicOutput: true, timestamp: 1700000001000 },
  { hash: ordinaryAtomicHash, outgoing: true, selfTransfer: true, oneAtomicOutput: true, timestamp: 1700000002000 }
];
const chainGroups = history.buildChainGroups(chainRows, [
  { hash: firstHash, extra: { messageId: '12'.repeat(16), index: 0, count: 2 } },
  { hash: secondHash, extra: { messageId: '12'.repeat(16), index: 1, count: 2 } },
  { hash: ordinaryAtomicHash, extra: { invalid: true } }
], {
  eligible: row => row.outgoing && row.selfTransfer && row.oneAtomicOutput,
  decodeExtra: extra => {
    if (extra.invalid) throw new Error('not a structurally valid QMS carrier');
    return extra;
  },
  timestampOf: row => row.timestamp
});
assert.strictEqual(chainGroups.length, 1);
assert.strictEqual(chainGroups[0].messageId, '12'.repeat(16));
assert.deepStrictEqual(chainGroups[0].transactionHashes, [firstHash, secondHash]);
assert.strictEqual(chainGroups[0].transactionCount, 2);
assert.strictEqual(chainGroups[0].createdAt, 1700000000000);

const restored = history.buildItems(chainRows, chainGroups, 'all');
assert.strictEqual(restored[0].kind, 'messenger', 'valid on-chain carriers should survive a missing local journal');
assert.strictEqual(restored[0].matchedRows.length, 2);
assert.strictEqual(restored[1].kind, 'payment',
  'an ordinary one-atomic self-transfer must remain a payment without a structurally valid QMS extra');

const ineligible = history.buildChainGroups(
  [{ hash: firstHash, outgoing: false, selfTransfer: true, oneAtomicOutput: true }],
  [{ hash: firstHash, extra: { messageId: '34'.repeat(16), index: 0, count: 1 } }],
  { eligible: row => row.outgoing, decodeExtra: extra => extra }
);
assert.strictEqual(ineligible.length, 0, 'incoming QMS-shaped transactions must not be labelled as outgoing messages');

const duplicateChainRecord = history.buildChainGroups(
  [{ hash: firstHash, outgoing: true }],
  [
    { hash: firstHash, extra: { messageId: '56'.repeat(16), index: 0, count: 1 } },
    { hash: firstHash, extra: { messageId: '56'.repeat(16), index: 0, count: 1 } }
  ],
  { eligible: row => row.outgoing, decodeExtra: extra => extra }
);
assert.strictEqual(duplicateChainRecord.length, 0, 'duplicate daemon records must fail open as payments');

const merged = history.mergeGroups([
  { messageId: '12'.repeat(16), createdAt: 'local', transactionHashes: [firstHash] }
], chainGroups);
assert.strictEqual(merged.length, 1);
assert.strictEqual(merged[0].createdAt, 'local', 'encrypted local metadata should remain authoritative');
assert.deepStrictEqual(merged[0].transactionHashes, [firstHash, secondHash]);
assert.strictEqual(history.mergeGroups([
  { messageId: 'legacy-local-message-id', transactionHashes: [ordinaryAtomicHash] }
], []).length, 1, 'valid encrypted local journal groups must not depend on the on-chain ID format');

console.log('  exact-hash Messenger transaction-history grouping checks passed');
