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

console.log('  exact-hash Messenger transaction-history grouping checks passed');
