// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Qwertycoin Project

'use strict';

const QmsTransactionHistory = (() => {
  function normalizeHash(value) {
    value = String(value || '');
    return /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : '';
  }

  function normalizeMessageId(value) {
    value = String(value || '');
    return /^[0-9a-f]{32}$/i.test(value) ? value.toLowerCase() : '';
  }

  function mergeGroups(primary, fallback) {
    const merged = [];
    const byMessageId = new Map();
    for (const source of [primary, fallback]) {
      for (const value of Array.isArray(source) ? source : []) {
        if (!value || typeof value !== 'object') continue;
        const rawMessageId = String(value.messageId || '').trim();
        const messageId = normalizeMessageId(rawMessageId) || (rawMessageId.length <= 128 ? rawMessageId : '');
        const hashes = Array.from(new Set((value.transactionHashes || []).map(normalizeHash).filter(Boolean)));
        if (!messageId || !hashes.length) continue;
        const current = byMessageId.get(messageId);
        if (current) {
          current.transactionHashes = Array.from(new Set(current.transactionHashes.concat(hashes)));
          current.transactionCount = current.transactionHashes.length;
          continue;
        }
        const group = Object.assign({}, value, {
          messageId,
          transactionHashes: hashes,
          transactionCount: hashes.length
        });
        byMessageId.set(messageId, group);
        merged.push(group);
      }
    }
    return merged;
  }

  function buildChainGroups(rows, transactions, options) {
    rows = Array.isArray(rows) ? rows : [];
    transactions = Array.isArray(transactions) ? transactions : [];
    options = options || {};
    const hashOf = typeof options.hashOf === 'function' ? options.hashOf : row => row && row.hash;
    const eligible = typeof options.eligible === 'function' ? options.eligible : () => false;
    const decodeExtra = typeof options.decodeExtra === 'function' ? options.decodeExtra : () => null;
    const timestampOf = typeof options.timestampOf === 'function' ? options.timestampOf : () => 0;

    const rowsByHash = new Map();
    const duplicateRows = new Set();
    for (const row of rows) {
      const hash = normalizeHash(hashOf(row));
      if (!hash || duplicateRows.has(hash)) continue;
      if (rowsByHash.has(hash)) {
        rowsByHash.delete(hash);
        duplicateRows.add(hash);
      } else {
        rowsByHash.set(hash, row);
      }
    }

    const seenTransactions = new Set();
    const invalidTransactions = new Set();
    const groups = new Map();
    for (const transaction of transactions) {
      const hash = normalizeHash(transaction && transaction.hash);
      if (!hash || invalidTransactions.has(hash)) continue;
      if (seenTransactions.has(hash)) {
        invalidTransactions.add(hash);
        for (const group of groups.values()) {
          group.transactionHashes = group.transactionHashes.filter(value => value !== hash);
        }
        continue;
      }
      seenTransactions.add(hash);
      const row = rowsByHash.get(hash);
      if (!row || !eligible(row)) continue;
      let decoded;
      try { decoded = decodeExtra(transaction.extra); } catch (_) { continue; }
      const messageId = normalizeMessageId(decoded && decoded.messageId);
      const index = Number(decoded && decoded.index);
      const count = Number(decoded && decoded.count);
      if (!messageId || !Number.isSafeInteger(index) || !Number.isSafeInteger(count)
          || count < 1 || count > 16 || index < 0 || index >= count) continue;
      let group = groups.get(messageId);
      if (!group) {
        group = {
          messageId,
          createdAt: Number(timestampOf(row)) || 0,
          status: 'confirmed',
          transactionHashes: []
        };
        groups.set(messageId, group);
      }
      group.transactionHashes.push(hash);
      const timestamp = Number(timestampOf(row)) || 0;
      if (timestamp && (!group.createdAt || timestamp < group.createdAt)) group.createdAt = timestamp;
    }

    return Array.from(groups.values())
      .filter(group => group.transactionHashes.length)
      .map(group => Object.assign(group, { transactionCount: group.transactionHashes.length }));
  }

  function buildItems(rows, groups, filter, hashOf) {
    rows = Array.isArray(rows) ? rows : [];
    groups = Array.isArray(groups) ? groups : [];
    filter = ['payments', 'messenger', 'all'].includes(filter) ? filter : 'all';
    hashOf = typeof hashOf === 'function' ? hashOf : row => row && row.hash;

    const rowByHash = new Map();
    for (const row of rows) {
      const hash = normalizeHash(hashOf(row));
      if (hash) rowByHash.set(hash, row);
    }

    // A hash claimed by more than one local message journal is ambiguous.
    // Fail open as a normal payment rather than mislabelling wallet history.
    const groupByHash = new Map();
    const ambiguous = new Set();
    for (const group of groups) {
      for (const value of (group && group.transactionHashes) || []) {
        const hash = normalizeHash(value);
        if (!hash || ambiguous.has(hash)) continue;
        if (groupByHash.has(hash)) {
          groupByHash.delete(hash);
          ambiguous.add(hash);
        } else {
          groupByHash.set(hash, group);
        }
      }
    }

    const renderedGroups = new Set();
    const items = [];
    for (const row of rows) {
      const hash = normalizeHash(hashOf(row));
      const group = hash && groupByHash.get(hash);
      if (!group) {
        if (filter !== 'messenger') items.push({ kind: 'payment', row });
        continue;
      }
      if (filter === 'payments' || renderedGroups.has(group)) continue;
      renderedGroups.add(group);
      const matchedRows = (group.transactionHashes || [])
        .map(value => rowByHash.get(normalizeHash(value)))
        .filter(Boolean);
      items.push({ kind: 'messenger', group, matchedRows });
    }
    return items;
  }

  return { buildItems, buildChainGroups, mergeGroups, normalizeHash, normalizeMessageId };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsTransactionHistory;
