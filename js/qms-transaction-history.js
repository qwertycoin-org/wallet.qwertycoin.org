// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Qwertycoin Project

'use strict';

const QmsTransactionHistory = (() => {
  function normalizeHash(value) {
    value = String(value || '');
    return /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : '';
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

  return { buildItems, normalizeHash };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsTransactionHistory;
