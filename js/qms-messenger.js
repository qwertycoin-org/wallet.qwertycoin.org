// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const QmsMessenger = (() => {
  'use strict';

  const ACTIVE_PLAN_STATUSES = new Set(['building', 'prepared', 'broadcasting', 'broadcast_unknown', 'recovery_required']);
  const STATUS_LABELS = Object.freeze({
    building: 'Preparing',
    prepared: 'Ready to send',
    broadcasting: 'Broadcasting',
    broadcast_unknown: 'Broadcast outcome unknown',
    broadcast: 'In the network',
    partially_confirmed: 'Partially confirmed',
    confirmed: 'Confirmed',
    cancelled: 'Cancelled',
    recovery_required: 'Recovery required'
  });
  const MAX_REASSEMBLIES = 64;
  const MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024;
  const MAX_UNMATCHED_MESSAGES = 32;
  const MAX_UNMATCHED_BYTES = 4 * 1024 * 1024;
  const REASSEMBLY_RETENTION_BLOCKS = 2048;
  const MAX_MESSAGES = 10000;
  const MAX_CONTACTS = 1000;
  const MAX_PLANS = 128;
  const MESSAGE_PAGE_SIZE = 100;

  function nowIso() { return new Date().toISOString(); }
  function messengerError(code, message) { const error = new Error(message); error.code = code; return error; }
  function short(value) { return value ? value.slice(0, 16) + '…' : ''; }
  function groupedFingerprint(value) { return (String(value || '').match(/.{1,8}/g) || []).join(' '); }
  function atomic(value) {
    const n = BigInt(String(value || 0));
    const whole = n / 100000000n;
    const frac = (n % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return whole.toString() + (frac ? '.' + frac : '');
  }
  function invitationFromHex(value) { return QmsProtocol.decodeInvitation(QmsProtocol.unhex(String(value || '').trim())); }
  function identityToJson(id) { return { boxPublic: QmsProtocol.hex(id.boxPublic), boxSecret: QmsProtocol.hex(id.boxSecret), signPublic: QmsProtocol.hex(id.signPublic), signSecret: QmsProtocol.hex(id.signSecret) }; }
  function identityFromJson(id) { return { boxPublic: QmsProtocol.unhex(id.boxPublic), boxSecret: QmsProtocol.unhex(id.boxSecret), signPublic: QmsProtocol.unhex(id.signPublic), signSecret: QmsProtocol.unhex(id.signSecret) }; }
  function allKeyImages(tx) { return (tx.inputs || []).map(input => input && input.keyImage && input.keyImage.hex).filter(Boolean); }
  function statusLabel(status) { return STATUS_LABELS[status] || String(status || 'Unknown'); }
  function activePlan(state) { return state.plans.find(plan => ACTIVE_PLAN_STATUSES.has(plan.status)) || null; }
  function createOperationMutex() {
    let current = null;
    return {
      get current() { return current; },
      async run(name, operation) {
        if (current) throw new Error(`Messenger operation already in progress: ${current}`);
        current = name;
        try { return await operation(); }
        finally { current = null; }
      }
    };
  }
  function finalFragmentMatches(extraHex, expected) {
    try {
      const segments = QmsProtocol.extractSegmentsFromExtra(QmsProtocol.unhex(extraHex));
      return QmsProtocol.equal(QmsProtocol.encodeFragment(QmsProtocol.decodeSegments(segments)), QmsProtocol.encodeFragment(expected));
    } catch (_) { return false; }
  }

  function normalizeState(state) {
    if (!Array.isArray(state.reassembly)) state.reassembly = [];
    if (!Array.isArray(state.unmatched)) state.unmatched = [];
    if (!state.scan || !Number.isSafeInteger(Number(state.scan.height)) || Number(state.scan.height) < 0) state.scan = { height: 0, blockHash: '', startHeight: null, checkpoints: [] };
    if (!Array.isArray(state.scan.checkpoints)) state.scan.checkpoints = [];

    // Early development builds keyed one copy of the same ciphertext by every
    // contact. Merge those copies into one recipient-authenticated reassembly.
    const merged = new Map();
    for (const candidate of state.reassembly) {
      if (!candidate || typeof candidate.messageId !== 'string' || typeof candidate.hash !== 'string' || !candidate.fragments) continue;
      const key = candidate.messageId + ':' + candidate.hash;
      const partial = merged.get(key) || {
        messageId: candidate.messageId,
        hash: candidate.hash,
        count: 0,
        ciphertextSize: 0,
        recipientInvitationHex: candidate.recipientInvitationHex || '',
        fragments: {},
        bytes: 0
      };
      if (!partial.recipientInvitationHex && candidate.recipientInvitationHex) partial.recipientInvitationHex = candidate.recipientInvitationHex;
      for (const [index, rawRecord] of Object.entries(candidate.fragments)) {
        const record = typeof rawRecord === 'string' ? { encoded: rawRecord, txHash: '', blockHeight: 0, blockHash: '', createdAt: '' } : rawRecord;
        if (!record || typeof record.encoded !== 'string') continue;
        try {
          const fragment = QmsProtocol.decodeFragment(QmsProtocol.unhex(record.encoded));
          if (QmsProtocol.hex(fragment.messageId) !== candidate.messageId || QmsProtocol.hex(fragment.ciphertextHash) !== candidate.hash) continue;
          partial.count = fragment.count;
          partial.ciphertextSize = fragment.ciphertextSize;
          if (!partial.fragments[index]) { partial.fragments[index] = record; partial.bytes += fragment.data.length; }
        } catch (_) {}
      }
      if (Object.keys(partial.fragments).length) merged.set(key, partial);
    }
    state.reassembly = Array.from(merged.values()).slice(0, MAX_REASSEMBLIES);
    state.unmatched = state.unmatched.filter(item => item && typeof item.messageId === 'string'
      && typeof item.ciphertext === 'string' && typeof item.recipientInvitationHex === 'string')
      .slice(-MAX_UNMATCHED_MESSAGES);
    for (const contact of state.contacts || []) {
      try {
        const invitation = invitationFromHex(contact.invitationHex);
        const fingerprint = QmsProtocol.hex(QmsProtocol.fingerprint(invitation.boxPublic, invitation.signPublic));
        contact.id = fingerprint;
        contact.fingerprint = fingerprint;
      } catch (_) {}
      if (typeof contact.verifiedAt !== 'string') contact.verifiedAt = null;
      if (typeof contact.draft !== 'string') contact.draft = '';
      if (contact.draft.length > QmsProtocol.C.MAX_TEXT_BYTES * 2) contact.draft = '';
    }
    for (const message of state.messages || []) {
      if (message.status === 'partially confirmed') message.status = 'partially_confirmed';
      if (message.direction === 'in' && !Object.prototype.hasOwnProperty.call(message, 'readAt')) {
        message.readAt = message.createdAt || nowIso();
      }
      if (message.direction === 'in' && message.readAt !== null && typeof message.readAt !== 'string') message.readAt = null;
    }
    for (const plan of state.plans || []) {
      const legacyRecovery = plan.status === 'rollback required';
      for (const tx of plan.txs || []) {
        if (tx.status === 'preparing') tx.status = 'recovery_required';
        if (tx.status === 'broadcasting') tx.status = 'broadcast_unknown';
      }
      plan.status = recomputePlanStatus(plan);
      if (legacyRecovery) plan.status = 'recovery_required';
    }
    return state;
  }

  function totalReassemblyBytes(state) { return state.reassembly.reduce((sum, partial) => sum + Number(partial.bytes || 0), 0); }
  function sourceHeights(records) {
    return (records || []).map(record => Number(record && record.blockHeight || 0)).filter(height => Number.isSafeInteger(height) && height >= 0);
  }
  function rememberDeferredRescan(state, heights) {
    if (!heights.length) return;
    const earliest = Math.min(...heights);
    const existing = Number(state.scan && state.scan.rescanFrom);
    state.scan.rescanFrom = Number.isSafeInteger(existing) && existing >= 0 ? Math.min(existing, earliest) : earliest;
  }
  function evictStaleInboundState(state, currentHeight) {
    const height = Number(currentHeight);
    if (!Number.isSafeInteger(height) || height < REASSEMBLY_RETENTION_BLOCKS) return 0;
    const cutoff = height - REASSEMBLY_RETENTION_BLOCKS;
    let removed = 0;
    state.reassembly = state.reassembly.filter(partial => {
      const heights = sourceHeights(Object.values(partial.fragments || {}));
      if (!heights.length || Math.max(...heights) > cutoff) return true;
      rememberDeferredRescan(state, heights); removed += 1; return false;
    });
    state.unmatched = (state.unmatched || []).filter(message => {
      const heights = sourceHeights(message.sourceFragments);
      if (!heights.length || Math.max(...heights) > cutoff) return true;
      rememberDeferredRescan(state, heights); removed += 1; return false;
    });
    return removed;
  }
  function resetDeferredRescan(state) {
    const from = Number(state.scan && state.scan.rescanFrom);
    if (!Number.isSafeInteger(from) || from < 0) return null;
    state.scan.height = Math.min(Number(state.scan.height || from), from);
    state.scan.blockHash = '';
    state.scan.checkpoints = (state.scan.checkpoints || []).filter(checkpoint => Number(checkpoint.height) < from);
    delete state.scan.rescanFrom;
    return from;
  }
  function invitationCandidates(state, fallbackInvitation) {
    const result = [], seen = new Set();
    const add = invitation => {
      if (!invitation) return;
      const id = QmsProtocol.hex(invitation.invitationId);
      if (!seen.has(id)) { seen.add(id); result.push(invitation); }
    };
    add(fallbackInvitation);
    for (const contact of state.contacts || []) {
      if (!contact.localInvitationHex) continue;
      try { add(invitationFromHex(contact.localInvitationHex)); } catch (_) {}
    }
    return result;
  }
  function addFragmentRecord(state, fragment, source, recipientInvitation) {
    const messageId = QmsProtocol.hex(fragment.messageId);
    const hash = QmsProtocol.hex(fragment.ciphertextHash);
    const recipientInvitationHex = QmsProtocol.hex(QmsProtocol.encodeInvitation(recipientInvitation));
    let partial = state.reassembly.find(item => item.messageId === messageId && item.hash === hash);
    if (!partial) {
      evictStaleInboundState(state, source.blockHeight);
      if (state.reassembly.length >= MAX_REASSEMBLIES) throw messengerError('QMS_CAPACITY', 'Messenger reassembly limit reached; scan cursor was not advanced');
      partial = { messageId, hash, count: fragment.count, ciphertextSize: fragment.ciphertextSize, recipientInvitationHex, fragments: {}, bytes: 0 };
      state.reassembly.push(partial);
    }
    if (partial.count !== fragment.count || partial.ciphertextSize !== fragment.ciphertextSize
        || (partial.recipientInvitationHex && partial.recipientInvitationHex !== recipientInvitationHex)) {
      throw messengerError('QMS_INVALID_FRAGMENT', 'Conflicting Messenger fragment metadata');
    }
    if (!partial.recipientInvitationHex) partial.recipientInvitationHex = recipientInvitationHex;

    const index = String(fragment.index);
    const encoded = QmsProtocol.hex(QmsProtocol.encodeFragment(fragment));
    if (partial.fragments[index]) {
      if (partial.fragments[index].encoded !== encoded) throw messengerError('QMS_INVALID_FRAGMENT', 'Conflicting Messenger fragment duplicate');
      return partial;
    }
    if (totalReassemblyBytes(state) + fragment.data.length > MAX_REASSEMBLY_BYTES) throw messengerError('QMS_CAPACITY', 'Messenger reassembly byte limit reached; scan cursor was not advanced');
    partial.fragments[index] = {
      encoded,
      txHash: source.txHash || '',
      blockHeight: Number(source.blockHeight || 0),
      blockHash: source.blockHash || '',
      createdAt: source.createdAt || nowIso()
    };
    partial.bytes += fragment.data.length;
    return partial;
  }

  function openCompletePartial(state, partial, identity, ownInvitation) {
    if (Object.keys(partial.fragments).length !== partial.count) return null;
    const records = Array.from({ length: partial.count }, (_, index) => partial.fragments[String(index)]);
    if (records.some(record => !record)) throw new Error('Incomplete Messenger fragment set');
    const fragments = records.map(record => QmsProtocol.decodeFragment(QmsProtocol.unhex(record.encoded)));
    const ciphertext = QmsProtocol.reassemble(fragments);
    const recipientInvitation = partial.recipientInvitationHex
      ? invitationFromHex(partial.recipientInvitationHex)
      : ownInvitation;
    const envelope = QmsProtocol.openTextEnvelope(identity, recipientInvitation, fragments[0].messageId, ciphertext);
    const senderId = QmsProtocol.hex(envelope.senderFingerprint);
    const senderContact = state.contacts.find(contact => {
      if (contact.fingerprint === senderId || contact.id === senderId) return true;
      try {
        const invitation = invitationFromHex(contact.invitationHex);
        return QmsProtocol.hex(QmsProtocol.fingerprint(invitation.boxPublic, invitation.signPublic)) === senderId;
      } catch (_) { return false; }
    });
    if (!senderContact) {
      return {
        unmatched: true,
        messageId: partial.messageId,
        hash: partial.hash,
        senderFingerprint: senderId,
        recipientInvitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(recipientInvitation)),
        ciphertext: QmsProtocol.hex(ciphertext),
        bytes: ciphertext.length,
        sourceFragments: records,
        receivedAt: nowIso()
      };
    }
    const opened = QmsProtocol.authenticateTextEnvelope(envelope, invitationFromHex(senderContact.invitationHex));
    const newest = records.slice().sort((a, b) => Number(a.blockHeight || 0) - Number(b.blockHeight || 0)).pop();
    return {
      id: partial.messageId,
      contactId: senderContact.id,
      direction: 'in',
      text: opened.text,
      createdAt: newest.createdAt || nowIso(),
      status: 'confirmed',
      readAt: null,
      txHash: newest.txHash || '',
      sourceFragments: records
    };
  }

  function acceptFragment(state, identity, ownInvitation, fragment, source) {
    if (!Array.isArray(state.unmatched)) state.unmatched = [];
    const recipientInvitation = invitationCandidates(state, ownInvitation)
      .find(invitation => QmsProtocol.verifyFragment(invitation, fragment));
    if (!recipientInvitation) return null;
    const messageId = QmsProtocol.hex(fragment.messageId);
    if (state.messages.some(message => message.id === messageId && message.direction === 'in')) return null;
    if ((state.unmatched || []).some(message => message.messageId === messageId)) return null;
    const partial = addFragmentRecord(state, fragment, source, recipientInvitation);
    let message;
    try { message = openCompletePartial(state, partial, identity, ownInvitation); }
    catch (error) {
      state.reassembly = state.reassembly.filter(item => item !== partial);
      throw messengerError('QMS_INVALID_PAYLOAD', `Invalid authenticated Messenger payload: ${error && error.message ? error.message : error}`);
    }
    if (message && message.unmatched) {
      const newestHeight = Math.max(0, ...sourceHeights(message.sourceFragments));
      evictStaleInboundState(state, newestHeight);
      const unmatchedBytes = state.unmatched.reduce((sum, item) => sum + Number(item.bytes || 0), 0);
      if (state.unmatched.length >= MAX_UNMATCHED_MESSAGES || unmatchedBytes + message.bytes > MAX_UNMATCHED_BYTES) {
        throw messengerError('QMS_CAPACITY', 'Messenger unknown-sender queue is full; scan cursor was not advanced');
      }
      state.unmatched.push(message);
      state.reassembly = state.reassembly.filter(item => item !== partial);
      return null;
    }
    if (message) {
      if (state.messages.length >= MAX_MESSAGES) throw messengerError('QMS_CAPACITY', 'Messenger message limit reached; scan cursor was not advanced');
      state.messages.push(message);
      state.reassembly = state.reassembly.filter(item => item !== partial);
    }
    return message;
  }

  function retryCompleteReassemblies(state, identity, ownInvitation) {
    if (!Array.isArray(state.unmatched)) state.unmatched = [];
    const opened = [];
    for (const pending of (state.unmatched || []).slice()) {
      try {
        const recipient = invitationFromHex(pending.recipientInvitationHex);
        const envelope = QmsProtocol.openTextEnvelope(
          identity, recipient, QmsProtocol.unhex(pending.messageId), QmsProtocol.unhex(pending.ciphertext));
        const senderId = QmsProtocol.hex(envelope.senderFingerprint);
        const contact = state.contacts.find(item => item.fingerprint === senderId || item.id === senderId);
        if (!contact) continue;
        const decoded = QmsProtocol.authenticateTextEnvelope(envelope, invitationFromHex(contact.invitationHex));
        const records = pending.sourceFragments || [];
        const newest = records.slice().sort((a, b) => Number(a.blockHeight || 0) - Number(b.blockHeight || 0)).pop() || {};
        const message = {
          id: pending.messageId,
          contactId: contact.id,
          direction: 'in',
          text: decoded.text,
          createdAt: newest.createdAt || pending.receivedAt || nowIso(),
          status: 'confirmed',
          readAt: null,
          txHash: newest.txHash || '',
          sourceFragments: records
        };
        if (!state.messages.some(item => item.id === message.id && item.direction === 'in')) {
          if (state.messages.length >= MAX_MESSAGES) throw messengerError('QMS_CAPACITY', 'Messenger message limit reached while matching a stored sender');
          state.messages.push(message);
          opened.push(message);
        }
        state.unmatched = state.unmatched.filter(item => item !== pending);
      } catch (_) { /* Keep authenticated ciphertext for a later matching contact. */ }
    }
    for (const partial of state.reassembly.slice()) {
      const message = openCompletePartial(state, partial, identity, ownInvitation);
      if (!message || message.unmatched || state.messages.some(item => item.id === message.id && item.direction === 'in')) continue;
      if (state.messages.length >= MAX_MESSAGES) throw messengerError('QMS_CAPACITY', 'Messenger message limit reached while completing fragments');
      state.messages.push(message); opened.push(message);
      state.reassembly = state.reassembly.filter(item => item !== partial);
    }
    return opened;
  }

  function recomputePlanStatus(plan) {
    if (!plan.txs.length) return plan.status;
    const statuses = plan.txs.map(tx => tx.status);
    if (statuses.every(status => status === 'confirmed')) return 'confirmed';
    if (statuses.some(status => status === 'recovery_required')) return 'recovery_required';
    if (statuses.some(status => status === 'broadcast_unknown')) return 'broadcast_unknown';
    if (statuses.some(status => status === 'broadcasting')) return 'broadcasting';
    if (statuses.every(status => status === 'prepared')) return 'prepared';
    if (statuses.some(status => status === 'confirmed')) return 'partially_confirmed';
    if (statuses.some(status => status === 'prepared')) return 'broadcast_unknown';
    return 'broadcast';
  }

  function beginBroadcastAttempt(plan, tx, at = nowIso()) {
    if (!['prepared', 'broadcast_unknown'].includes(tx.status)) throw new Error('Transaction is not retryable');
    if (typeof tx.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(tx.hash) || !tx.metadata) {
      tx.status = 'recovery_required';
      plan.status = recomputePlanStatus(plan);
      throw new Error('Prepared transaction journal is incomplete');
    }
    tx.hash = tx.hash.toLowerCase();
    tx.status = 'broadcasting';
    tx.broadcastAttempts = Number(tx.broadcastAttempts || 0) + 1;
    tx.broadcastAttemptedAt = at;
    delete tx.broadcastError;
    plan.status = recomputePlanStatus(plan);
    return tx;
  }

  function completeBroadcastAttempt(plan, tx, returnedHash, at = nowIso()) {
    if (typeof returnedHash !== 'string' || !/^[0-9a-f]{64}$/i.test(returnedHash)) throw new Error('Wallet did not return a valid broadcast transaction hash');
    if (tx.hash.toLowerCase() !== returnedHash.toLowerCase()) throw new Error('Broadcast hash does not match the prepared transaction');
    tx.status = 'broadcast';
    tx.broadcastAt = at;
    delete tx.broadcastError;
    plan.status = recomputePlanStatus(plan);
    return tx;
  }

  function markBroadcastUnknown(plan, tx, error) {
    tx.status = 'broadcast_unknown';
    tx.broadcastError = error && error.message ? error.message : String(error || 'Broadcast outcome is unknown');
    plan.status = recomputePlanStatus(plan);
    return tx;
  }

  async function relayPlan(plan, dependencies) {
    for (const tx of plan.txs || []) {
      if (tx.status === 'broadcast' || tx.status === 'confirmed') continue;
      beginBroadcastAttempt(plan, tx, dependencies.now ? dependencies.now() : nowIso());
      dependencies.updateStatus();
      try {
        await dependencies.persist();
      } catch (error) {
        tx.status = 'recovery_required';
        tx.broadcastError = error && error.message ? error.message : String(error);
        plan.status = recomputePlanStatus(plan);
        dependencies.updateStatus();
        throw error;
      }

      try {
        const hashes = await dependencies.relay([tx.metadata]);
        dependencies.assertActive();
        const hash = Array.isArray(hashes) ? hashes[0] : hashes;
        completeBroadcastAttempt(plan, tx, hash, dependencies.now ? dependencies.now() : nowIso());
        dependencies.updateStatus();
        await dependencies.persist();
      } catch (error) {
        markBroadcastUnknown(plan, tx, error);
        dependencies.updateStatus();
        await dependencies.persist();
        throw error;
      }
    }
    plan.status = recomputePlanStatus(plan);
    dependencies.updateStatus();
    await dependencies.persist();
    return plan;
  }

  function updateOutgoingMessageStatus(state, plan) {
    const message = state.messages.find(item => item.id === plan.id && item.direction === 'out');
    if (message) message.status = plan.status;
  }

  function markOutgoingConfirmed(state, txHash, block) {
    if (!txHash) return false;
    let changed = false;
    for (const plan of state.plans) {
      let planChanged = false;
      for (const tx of plan.txs || []) {
        if (!tx.hash || tx.hash.toLowerCase() !== String(txHash).toLowerCase()) continue;
        tx.status = 'confirmed'; tx.blockHeight = Number(block.height); tx.blockHash = block.hash || ''; changed = true; planChanged = true;
      }
      if (planChanged) { plan.status = recomputePlanStatus(plan); updateOutgoingMessageStatus(state, plan); }
    }
    return changed;
  }

  function rollbackForReorg(state, restoreHeight, anchorHash = '') {
    state.messages = state.messages.filter(message => {
      if (message.direction !== 'in') return true;
      const heights = (message.sourceFragments || []).map(record => Number(record.blockHeight || 0));
      return heights.length > 0 && Math.max(...heights) < restoreHeight;
    });
    for (const partial of state.reassembly || []) {
      for (const [index, record] of Object.entries(partial.fragments || {})) {
        if (Number(record.blockHeight || 0) >= restoreHeight) delete partial.fragments[index];
      }
    }
    state.reassembly = (state.reassembly || []).filter(partial => Object.keys(partial.fragments || {}).length > 0);
    state.unmatched = (state.unmatched || []).filter(item => {
      const heights = (item.sourceFragments || []).map(record => Number(record.blockHeight || 0));
      return heights.length > 0 && Math.max(...heights) < restoreHeight;
    });
    normalizeState(state);
    for (const plan of state.plans) {
      for (const tx of plan.txs || []) {
        if (tx.status === 'confirmed' && Number(tx.blockHeight || 0) >= restoreHeight) { tx.status = 'broadcast'; delete tx.blockHeight; delete tx.blockHash; }
      }
      if (plan.status === 'confirmed' || plan.status === 'partially_confirmed') plan.status = recomputePlanStatus(plan);
      updateOutgoingMessageStatus(state, plan);
    }
    state.scan.height = restoreHeight;
    state.scan.blockHash = anchorHash;
    state.scan.checkpoints = (state.scan.checkpoints || []).filter(checkpoint => Number(checkpoint.height) < restoreHeight);
  }

  function validateBlockSequence(blocks, startHeight, expectedPrevHash) {
    let previousHash = expectedPrevHash ? String(expectedPrevHash).toLowerCase() : '';
    for (let offset = 0; offset < blocks.length; offset++) {
      const block = blocks[offset], expectedHeight = startHeight + offset;
      if (Number(block && block.height) !== expectedHeight
          || typeof block.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(block.hash)
          || typeof block.prevHash !== 'string' || !/^[0-9a-f]{64}$/i.test(block.prevHash)) {
        throw new Error('Daemon returned a non-contiguous Messenger block range');
      }
      if ((previousHash && block.prevHash.toLowerCase() !== previousHash)
          || (!previousHash && expectedHeight === 0 && !/^0{64}$/i.test(block.prevHash))) {
        throw new Error('Daemon returned a disconnected Messenger block range');
      }
      previousHash = block.hash.toLowerCase();
    }
    return previousHash;
  }

  async function findCommonCheckpoint(scanner, scan) {
    const checkpoints = (scan.checkpoints || []).slice(-64).reverse();
    for (const checkpoint of checkpoints) {
      const blocks = await scanner.getBlocksByRange(Number(checkpoint.height), Number(checkpoint.height));
      if (Array.isArray(blocks) && blocks.length === 1
          && Number(blocks[0].height) === Number(checkpoint.height)
          && String(blocks[0].hash || '').toLowerCase() === String(checkpoint.hash || '').toLowerCase()) return checkpoint;
    }
    return null;
  }

  function removeDraft(state, plan) {
    state.plans = state.plans.filter(item => item.id !== plan.id);
    state.messages = state.messages.filter(message => !(message.id === plan.id && message.direction === 'out'));
  }

  async function releasePlanInputs(wallet, plan) {
    const failures = [];
    const seen = new Set();
    for (const tx of plan.txs || []) {
      if (tx.status !== 'prepared' && tx.status !== 'recovery_required') continue;
      for (const keyImage of tx.keyImages || []) {
        if (seen.has(keyImage)) continue;
        seen.add(keyImage);
        try { await wallet.thawOutput(keyImage); } catch (error) { failures.push(error && error.message ? error.message : String(error)); }
      }
    }
    if (failures.length) throw new Error(`Unable to release ${failures.length} reserved input(s): ${failures[0]}`);
  }

  async function mount(options) {
    const signal = options.signal || null;
    let closed = false;
    function abortError() {
      const error = new Error('Messenger session is closed');
      error.name = 'AbortError';
      return error;
    }
    function assertActive() {
      if (closed || (signal && signal.aborted)) throw abortError();
    }
    assertActive();
    await QmsProtocol.ready();
    assertActive();
    const walletKeys = options.getWalletKeys();
    if (!walletKeys || !walletKeys.privateSpendKeyHex) throw new Error('Messenger requires an unlocked full wallet');
    const qmsKey = options.getQmsKey && options.getQmsKey();
    if (!(qmsKey instanceof Uint8Array) || qmsKey.length !== 32) throw new Error('Messenger requires a non-empty Session password');
    const qmsKdf = options.getQmsKdf && options.getQmsKdf();
    const store = await QmsStore.open(walletKeys, qmsKey, qmsKdf);
    if (signal && signal.aborted) {
      await store.close();
      throw abortError();
    }
    let identity = null;
    let closePromise = null;
    function closeStore() {
      if (closePromise) return closePromise;
      closed = true;
      if (identity) {
        try { sodium.memzero(identity.boxSecret); sodium.memzero(identity.signSecret); } catch (_) {}
      }
      closePromise = store.close();
      return closePromise;
    }
    const onAbort = () => { closeStore().catch(() => {}); };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    let state = normalizeState(store.state);
    const configuredStartHeight = Math.max(0, Number(options.getRestoreHeight() || 0));
    if (!Number.isSafeInteger(Number(state.scan.startHeight)) || Number(state.scan.startHeight) < 0) state.scan.startHeight = configuredStartHeight;
    if (Number(state.scan.height) < Number(state.scan.startHeight)) {
      state.scan.height = Number(state.scan.startHeight);
      state.scan.blockHash = '';
      state.scan.checkpoints = [];
    }
    if (!state.identity) state.identity = identityToJson(QmsProtocol.createIdentity());
    identity = identityFromJson(state.identity);
    if (!state.ownInvitation) state.ownInvitation = QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(identity)));
    for (const contact of state.contacts) {
      if (!contact.localInvitationHex) {
        contact.localInvitationHex = QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(identity)));
      }
    }
    async function persist() {
      assertActive();
      await store.save();
      assertActive();
    }
    try {
      await persist();
    } catch (error) {
      await closeStore();
      throw error;
    }

    const firstActiveContact = () => state.contacts.find(item => !item.archivedAt) || null;
    let selectedId = activePlan(state) ? activePlan(state).contactId : (firstActiveContact() ? firstActiveContact().id : null);
    let scanning = false;
    let recovering = true;
    let scannerPromise = null;
    let scanFailures = 0;
    let nextScanAt = 0;
    const messageLimits = new Map();
    let renderedMessageKey = '';
    let renderedContactId = null;
    let mobileConversationOpen = false;
    let uiSaveTimer = null;
    const operations = createOperationMutex();
    const el = id => document.getElementById(id);
    const section = el('qms-section'), overviewTab = el('wallet-tab-overview'), messengerTab = el('wallet-tab-messenger');
    const dashboard = el('dashboard');
    const overviewNodes = Array.from(dashboard.children).filter(node => node !== section && node.id !== 'wallet-tabs' && !node.classList.contains('wallet-header'));
    const originalHidden = new Map(overviewNodes.map(node => [node, node.hidden]));

    function showStatus(message, type) { if (closed) return; const node = el('qms-status'); node.textContent = message || ''; node.className = 'qms-status' + (type ? ' ' + type : ''); }
    function showError(error) { if (closed || (error && error.name === 'AbortError')) return; showStatus(error && error.message ? error.message : String(error), 'error'); }
    function emptyNotice(message) { const node = document.createElement('div'); node.className = 'qms-empty'; node.textContent = message; return node; }
    function withTimeout(promise, label, timeoutMs = 20000) {
      let timer;
      return Promise.race([
        Promise.resolve(promise),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(timeoutMs / 1000)} seconds`)), timeoutMs);
        })
      ]).finally(() => clearTimeout(timer));
    }
    async function synchronizedWallet(statusMessage) {
      assertActive();
      if (statusMessage) showStatus(statusMessage);
      const wallet = await options.getWallet();
      assertActive();
      if (wallet.reconnectDaemon) await wallet.reconnectDaemon();
      assertActive();
      if (wallet.sync) await wallet.sync(Math.max(0, Number(options.getRestoreHeight() || 0)));
      assertActive();
      return wallet;
    }
    function contact() { return state.contacts.find(item => item.id === selectedId && !item.archivedAt) || null; }
    function preparedForSelected() { return state.plans.find(plan => plan.contactId === selectedId && ACTIVE_PLAN_STATUSES.has(plan.status) && plan.status !== 'building') || null; }
    function formatDate(value) { try { return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)); } catch (_) { return value; } }
    function messageByteCount() { return new TextEncoder().encode(el('qms-message-input').value).length; }
    function scheduleUiPersist() {
      clearTimeout(uiSaveTimer);
      uiSaveTimer = setTimeout(() => {
        uiSaveTimer = null;
        persist().catch(showError);
      }, 400);
    }
    function restoreDraft() { el('qms-message-input').value = contact() ? contact().draft || '' : ''; }
    function markSelectedRead() {
      if (section.hidden || !selectedId || (window.innerWidth <= 720 && !mobileConversationOpen)) return false;
      const at = nowIso(); let changed = false;
      for (const message of state.messages) {
        if (message.contactId === selectedId && message.direction === 'in' && !message.readAt) {
          message.readAt = at; changed = true;
        }
      }
      if (changed) scheduleUiPersist();
      return changed;
    }
    function downloadJson(filename, value) {
      const blob = new Blob([JSON.stringify(value)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = filename; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    }
    function invitationDocument(invitationHex) {
      invitationFromHex(invitationHex);
      return { type: 'qwc-qms1-invitation', version: 1, profile: 'qms1-fast', invitation: invitationHex };
    }
    function renderInvitationQr(container, invitationHex) {
      container.replaceChildren();
      const qr = qrcode(0, 'L');
      qr.addData(`qwc-qms1-invite:${invitationHex}`); qr.make();
      const modules = qr.getModuleCount(), scale = 4, margin = 4;
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = (modules + margin * 2) * scale;
      canvas.setAttribute('aria-label', 'QMS1 invitation QR code');
      const context = canvas.getContext('2d');
      context.fillStyle = '#fff'; context.fillRect(0, 0, canvas.width, canvas.height);
      context.fillStyle = '#000';
      for (let row = 0; row < modules; row++) for (let column = 0; column < modules; column++) {
        if (qr.isDark(row, column)) context.fillRect((column + margin) * scale, (row + margin) * scale, scale, scale);
      }
      container.appendChild(canvas);
    }

    function setTab(name) {
      const messenger = name === 'messenger'; section.hidden = !messenger;
      overviewNodes.forEach(node => { node.hidden = messenger ? true : originalHidden.get(node); });
      overviewTab.classList.toggle('active', !messenger); messengerTab.classList.toggle('active', messenger);
      overviewTab.setAttribute('aria-selected', String(!messenger)); messengerTab.setAttribute('aria-selected', String(messenger));
      if (messenger && !recovering) { render(); scan().catch(showError); }
    }
    overviewTab.addEventListener('click', () => setTab('overview'));
    messengerTab.addEventListener('click', () => setTab('messenger'));

    function renderContacts() {
      const list = el('qms-contact-list'); list.replaceChildren();
      const query = el('qms-contact-filter').value.trim().toLocaleLowerCase();
      const summaries = new Map();
      for (const message of state.messages) {
        let summary = summaries.get(message.contactId);
        if (!summary) { summary = { latest: null, unread: 0, matches: false }; summaries.set(message.contactId, summary); }
        if (!summary.latest || summary.latest.createdAt.localeCompare(message.createdAt) < 0) summary.latest = message;
        if (message.direction === 'in' && !message.readAt) summary.unread += 1;
        if (query && !summary.matches && String(message.text || '').toLocaleLowerCase().includes(query)) summary.matches = true;
      }
      const activeContacts = state.contacts.filter(item => {
        if (item.archivedAt) return false;
        if (!query) return true;
        return item.name.toLocaleLowerCase().includes(query) || String(item.fingerprint || '').toLowerCase().includes(query)
          || (summaries.get(item.id) && summaries.get(item.id).matches);
      });
      if (!activeContacts.length) { list.appendChild(emptyNotice('No contacts yet')); return; }
      for (const item of activeContacts) {
        const button = document.createElement('button'); button.className = 'qms-contact' + (item.id === selectedId ? ' active' : ''); button.type = 'button';
        button.setAttribute('aria-pressed', String(item.id === selectedId));
        button.disabled = recovering;
        const title = document.createElement('div'); title.className = 'qms-contact-title';
        const name = document.createElement('strong'); name.textContent = item.name; title.appendChild(name);
        const summary = summaries.get(item.id) || { latest: null, unread: 0 };
        const unreadCount = summary.unread;
        if (unreadCount) { const unread = document.createElement('span'); unread.className = 'qms-unread'; unread.textContent = unreadCount > 99 ? '99+' : String(unreadCount); title.appendChild(unread); }
        const latest = summary.latest;
        const preview = document.createElement('span'); preview.className = 'qms-contact-preview'; preview.textContent = latest ? `${latest.direction === 'out' ? 'You: ' : ''}${latest.text}` : `${short(item.fingerprint)} · ${item.verifiedAt ? 'verified' : 'unverified'}`;
        button.append(title, preview);
        button.addEventListener('click', () => {
          if (selectedId === item.id && mobileConversationOpen) return;
          selectedId = item.id;
          mobileConversationOpen = true;
          el('qms-chat-view').classList.add('qms-mobile-conversation');
          renderedMessageKey = '';
          restoreDraft();
          markSelectedRead();
          render();
        });
        list.appendChild(button);
      }
    }

    function updateComposer() {
      const item = contact(), lockedPlan = activePlan(state), size = messageByteCount();
      const carriers = size ? Math.ceil((size + 272) / 600) : 0;
      el('qms-byte-count').textContent = `${size.toLocaleString()} / 4,096 UTF-8 bytes · ${carriers} carrier transaction${carriers === 1 ? '' : 's'} · fees calculated during preparation`;
      el('qms-message-input').disabled = recovering || !item || !!lockedPlan;
      let requirement = '';
      if (recovering) requirement = 'Restoring Messenger state…';
      else if (!item) requirement = 'Select or import a contact before composing a message.';
      else if (!item.verifiedAt) requirement = 'Sending is locked: open Manage contacts, compare the complete fingerprint through a trusted channel, then mark this contact as verified.';
      else if (lockedPlan) requirement = 'Send or cancel the existing prepared message before creating another one.';
      else if (size > QmsProtocol.C.MAX_TEXT_BYTES) requirement = 'Message exceeds the 4,096-byte limit.';
      const requirementNode = el('qms-compose-requirement');
      requirementNode.textContent = requirement;
      const prepare = el('qms-prepare');
      prepare.disabled = recovering || !item || !item.verifiedAt || !!lockedPlan || !size || size > QmsProtocol.C.MAX_TEXT_BYTES;
      prepare.title = requirement;
    }

    function renderMessages() {
      const item = contact();
      const messages = state.messages.filter(message => message.contactId === selectedId).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      el('qms-chat-name').textContent = item ? item.name : 'Select a contact'; el('qms-chat-fingerprint').textContent = item ? item.fingerprint : '';
      const limit = messageLimits.get(selectedId) || MESSAGE_PAGE_SIZE;
      const visible = messages.slice(-limit);
      const messageKey = JSON.stringify(visible.map(message => [message.id, message.status, message.createdAt, message.text]));
      const list = el('qms-message-list');
      if (renderedContactId !== selectedId || renderedMessageKey !== messageKey) {
        const sameContact = renderedContactId === selectedId;
        const nearBottom = !sameContact || list.scrollHeight - list.scrollTop - list.clientHeight < 48;
        const previousHeight = list.scrollHeight;
        const previousTop = list.scrollTop;
        list.replaceChildren();
        if (!messages.length) list.appendChild(emptyNotice(item ? 'No messages in this chat yet.' : 'Import a personal invitation to begin.'));
        if (visible.length < messages.length) {
          const loadOlder = document.createElement('button');
          loadOlder.type = 'button';
          loadOlder.className = 'action-btn qms-load-older';
          loadOlder.textContent = `Load ${Math.min(MESSAGE_PAGE_SIZE, messages.length - visible.length)} older messages`;
          loadOlder.addEventListener('click', () => {
            messageLimits.set(selectedId, limit + MESSAGE_PAGE_SIZE);
            renderedMessageKey = '';
            renderMessages();
          });
          list.appendChild(loadOlder);
        }
        for (const message of visible) {
          const row = document.createElement('div'); row.className = 'qms-message ' + (message.direction === 'out' ? 'me' : 'them');
          const bubble = document.createElement('div'); bubble.className = 'qms-bubble';
          const text = document.createElement('div'); text.textContent = message.text; bubble.appendChild(text);
          const meta = document.createElement('div'); meta.className = 'qms-bubble-meta';
          const who = document.createElement('span'); who.textContent = message.direction === 'out' ? 'Me' : item.name;
          const when = document.createElement('span'); when.textContent = formatDate(message.createdAt);
          const status = document.createElement('span');
          status.className = 'qms-message-status' + (['broadcast_unknown', 'recovery_required'].includes(message.status) ? ' error' : '');
          status.textContent = statusLabel(message.status);
          meta.append(who, when, status); bubble.appendChild(meta); row.appendChild(bubble); list.appendChild(row);
        }
        if (nearBottom) list.scrollTop = list.scrollHeight;
        else list.scrollTop = previousTop + Math.max(0, list.scrollHeight - previousHeight);
        renderedContactId = selectedId;
        renderedMessageKey = messageKey;
      }
      const plan = preparedForSelected(); el('qms-review').hidden = !plan;
      if (plan) {
        el('qms-review-count').textContent = `${plan.txs.length} transaction${plan.txs.length === 1 ? '' : 's'}`;
        el('qms-review-fee').textContent = `Fee ${atomic(plan.totalFee)} QWC`;
        el('qms-review-note').textContent = plan.recoveryError
          ? `This draft is blocked: ${plan.recoveryError}`
          : plan.status === 'broadcast_unknown'
          ? 'The last relay outcome is unknown. Retry submits the identical signed transaction; it does not create a new carrier.'
          : plan.status === 'recovery_required'
          ? 'The transaction journal requires recovery before any relay is allowed.'
          : 'Review the complete carrier batch. Nothing is broadcast until you select Send encrypted message.';
        el('qms-send').disabled = recovering || !!plan.recoveryError || plan.status === 'recovery_required' || plan.status === 'broadcasting';
        el('qms-cancel').disabled = recovering || plan.txs.some(tx => !['prepared', 'recovery_required'].includes(tx.status));
      }
      el('qms-manage-toggle').disabled = recovering;
      overviewTab.disabled = recovering;
      overviewTab.setAttribute('aria-disabled', String(overviewTab.disabled));
      if (options.setWalletSpendBlocked) options.setWalletSpendBlocked(!!activePlan(state));
      updateComposer();
    }

    function renderManage() {
      if (el('qms-manage-view').hidden) return;
      el('qms-own-invitation').value = state.ownInvitation;
      const own = invitationFromHex(state.ownInvitation);
      el('qms-own-fingerprint').textContent = 'Fingerprint: ' + QmsProtocol.hex(QmsProtocol.fingerprint(own.boxPublic, own.signPublic));
      const list = el('qms-manage-list'); list.replaceChildren();
      for (const item of state.contacts.filter(contactItem => !contactItem.archivedAt)) {
        const row = document.createElement('div'); row.className = 'qms-manage-row';
        const input = document.createElement('input'); input.value = item.name; input.maxLength = 80; input.disabled = recovering;
        const rename = document.createElement('button'); rename.className = 'action-btn'; rename.textContent = 'Rename'; rename.disabled = input.disabled;
        rename.addEventListener('click', async () => { assertActive(); const value = input.value.trim(); if (!value) return; item.name = value; await persist(); render(); showStatus('Contact renamed.', 'ok'); });
        const fingerprint = document.createElement('div'); fingerprint.className = 'qms-contact-verification';
        fingerprint.textContent = `${item.verifiedAt ? 'Verified' : 'Unverified'} · ${groupedFingerprint(item.fingerprint)}`;
        const verify = document.createElement('button'); verify.className = 'action-btn'; verify.textContent = item.verifiedAt ? 'Verified' : 'Mark fingerprint verified'; verify.disabled = recovering || !!item.verifiedAt;
        verify.addEventListener('click', async () => {
          if (!confirm(`Have you compared this complete fingerprint with ${item.name} through an independent trusted channel?\n\n${groupedFingerprint(item.fingerprint)}`)) return;
          item.verifiedAt = nowIso();
          await persist(); render(); showStatus(`${item.name} fingerprint marked as verified.`, 'ok');
        });
        const copyInvitation = document.createElement('button'); copyInvitation.className = 'action-btn'; copyInvitation.textContent = 'Copy my invitation for this contact'; copyInvitation.disabled = recovering;
        copyInvitation.addEventListener('click', async () => {
          await navigator.clipboard.writeText(item.localInvitationHex);
          showStatus(`Dedicated invitation for ${item.name} copied. Share it confidentially.`, 'ok');
        });
        const exportInvitation = document.createElement('button'); exportInvitation.className = 'action-btn'; exportInvitation.textContent = 'Export invitation file'; exportInvitation.disabled = recovering;
        exportInvitation.addEventListener('click', () => {
          downloadJson(`qms1-invitation-${item.id.slice(0, 12)}.json`, invitationDocument(item.localInvitationHex));
          showStatus(`Dedicated invitation file for ${item.name} exported. Share it privately.`, 'ok');
        });
        const showQr = document.createElement('button'); showQr.className = 'action-btn'; showQr.textContent = 'Show local QR'; showQr.disabled = recovering; showQr.setAttribute('aria-expanded', 'false');
        const qr = document.createElement('div'); qr.className = 'qms-invitation-qr'; qr.hidden = true;
        showQr.addEventListener('click', () => {
          qr.hidden = !qr.hidden; showQr.textContent = qr.hidden ? 'Show local QR' : 'Hide local QR'; showQr.setAttribute('aria-expanded', String(!qr.hidden));
          if (!qr.hidden && !qr.firstChild) renderInvitationQr(qr, item.localInvitationHex);
        });
        const remove = document.createElement('button'); remove.className = 'action-btn'; remove.textContent = 'Remove'; remove.disabled = input.disabled;
        remove.addEventListener('click', async () => {
          if ((state.plans || []).some(plan => plan.contactId === item.id && ACTIVE_PLAN_STATUSES.has(plan.status))) {
            showStatus('Resolve this contact’s prepared Messenger transaction before removing the contact.', 'error');
            return;
          }
          if (!confirm(`Remove ${item.name}? Existing local chat history will be retained and will reappear if this invitation is imported again.`)) return;
          item.archivedAt = nowIso();
          if (selectedId === item.id) { selectedId = firstActiveContact() ? firstActiveContact().id : null; renderedMessageKey = ''; restoreDraft(); }
          await persist(); render(); showStatus('Contact removed from the chat list. Its local invitation and history were retained for compatibility.', 'ok');
        });
        row.append(input, rename, fingerprint, verify, copyInvitation, exportInvitation, showQr, remove, qr); list.appendChild(row);
      }
    }
    function render() { if (closed) return; markSelectedRead(); renderContacts(); renderMessages(); renderManage(); }

    el('qms-manage-toggle').addEventListener('click', () => {
      el('qms-chat-view').hidden = true; el('qms-manage-view').hidden = false;
      renderManage();
    });
    el('qms-manage-back').addEventListener('click', () => { el('qms-manage-view').hidden = true; el('qms-chat-view').hidden = false; render(); });
    el('qms-copy-invitation').addEventListener('click', async () => { await navigator.clipboard.writeText(state.ownInvitation); showStatus('Complete personal invitation copied.', 'ok'); });
    el('qms-export-invitation').addEventListener('click', () => {
      downloadJson('qms1-bootstrap-invitation.json', invitationDocument(state.ownInvitation));
      showStatus('Bootstrap invitation file exported. Share it privately.', 'ok');
    });
    el('qms-toggle-invitation-qr').addEventListener('click', event => {
      const qr = el('qms-own-invitation-qr');
      qr.hidden = !qr.hidden;
      event.currentTarget.textContent = qr.hidden ? 'Show local QR' : 'Hide local QR';
      event.currentTarget.setAttribute('aria-expanded', String(!qr.hidden));
      if (!qr.hidden && !qr.firstChild) renderInvitationQr(qr, state.ownInvitation);
    });
    el('qms-contact-invitation-file').addEventListener('change', async event => {
      try {
        const file = event.target.files && event.target.files[0];
        if (!file) return;
        if (file.size > 4096) throw new Error('Invitation file exceeds the 4 KiB limit');
        const value = JSON.parse(await file.text());
        if (!value || value.type !== 'qwc-qms1-invitation' || value.version !== 1
            || value.profile !== 'qms1-fast' || typeof value.invitation !== 'string') {
          throw new Error('Unsupported Messenger invitation file');
        }
        invitationFromHex(value.invitation);
        el('qms-contact-invitation').value = value.invitation.toLowerCase();
        showStatus('Invitation file loaded. Import it, then verify the fingerprint independently.', 'ok');
      } catch (error) { event.target.value = ''; showError(error); }
    });
    el('qms-backup-file').addEventListener('change', event => {
      const file = event.target.files && event.target.files[0];
      el('qms-backup-file-name').textContent = file ? `${file.name} · ${file.size.toLocaleString()} bytes` : 'No backup file selected.';
      el('qms-import-backup').disabled = !file || file.size > 16 * 1024 * 1024;
      if (file && file.size > 16 * 1024 * 1024) showStatus('Messenger backup exceeds the 16 MiB import limit.', 'error');
    });
    el('qms-export-backup').addEventListener('click', () => operations.run('backup export', async () => {
      const passwordInput = el('qms-backup-password');
      const button = el('qms-export-backup');
      button.disabled = true;
      try {
        const serialized = await store.exportBackup(passwordInput.value);
        assertActive();
        const blob = new Blob([serialized], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `qwertycoin-messenger-backup-${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 0);
        showStatus('Encrypted Messenger backup exported. Store the file and its separate password privately.', 'ok');
      } finally {
        passwordInput.value = '';
        button.disabled = false;
      }
    }).catch(showError));
    el('qms-import-backup').addEventListener('click', () => operations.run('backup import', async () => {
      const passwordInput = el('qms-backup-password');
      const fileInput = el('qms-backup-file');
      const file = fileInput.files && fileInput.files[0];
      if (!file) throw new Error('Choose an encrypted Messenger backup file');
      if (file.size > 16 * 1024 * 1024) throw new Error('Messenger backup exceeds the 16 MiB import limit');
      if (!confirm('Replace this browser’s Messenger identity, contacts and local history with the authenticated backup? Nothing will be sent automatically.')) return;
      const button = el('qms-import-backup');
      button.disabled = true;
      try {
        const imported = normalizeState(await store.importBackup(await file.text(), passwordInput.value));
        assertActive();
        try { sodium.memzero(identity.boxSecret); sodium.memzero(identity.signSecret); } catch (_) {}
        state = imported;
        identity = identityFromJson(state.identity);
        selectedId = activePlan(state) ? activePlan(state).contactId : (state.contacts[0] ? state.contacts[0].id : null);
        restoreDraft();
        fileInput.value = '';
        el('qms-backup-file-name').textContent = 'No backup file selected.';
        render();
        showStatus(activePlan(state)
          ? 'Backup imported. The transaction journal is locked in recovery mode; review it before any wallet spending.'
          : 'Encrypted Messenger backup imported.', activePlan(state) ? 'error' : 'ok');
      } finally {
        passwordInput.value = '';
        button.disabled = !(fileInput.files && fileInput.files[0]);
      }
    }).catch(showError));
    el('qms-change-session-password').addEventListener('click', () => operations.run('password change', async () => {
      if (typeof options.preparePasswordChange !== 'function') throw new Error('Session password change is unavailable');
      const currentInput = el('qms-current-session-password');
      const nextInput = el('qms-new-session-password');
      const button = el('qms-change-session-password');
      button.disabled = true;
      let prepared = null;
      try {
        prepared = await options.preparePasswordChange(currentInput.value, nextInput.value);
        assertActive();
        const result = await store.changeWrappingKey(
          prepared.qmsKey,
          prepared.qmsKdf,
          () => prepared.commit()
        );
        assertActive();
        showStatus(result.cleanupPending
          ? 'Session password changed. Messenger key cleanup will finish on the next save or unlock.'
          : 'Session password and Messenger data-key wrapping changed atomically.', 'ok');
      } finally {
        currentInput.value = '';
        nextInput.value = '';
        button.disabled = false;
        if (prepared) prepared.dispose();
      }
    }).catch(showError));
    el('qms-import-contact').addEventListener('click', async () => {
      try {
        const name = el('qms-contact-name').value.trim(), invitationHex = el('qms-contact-invitation').value.trim().toLowerCase();
        if (!name) throw new Error('Enter a contact name');
        const inv = invitationFromHex(invitationHex); if (!QmsProtocol.equal(inv.genesis, QmsProtocol.genesis())) throw new Error('Invitation belongs to a different network');
        const fp = QmsProtocol.hex(QmsProtocol.fingerprint(inv.boxPublic, inv.signPublic));
        const own = invitationFromHex(state.ownInvitation);
        const ownFingerprint = QmsProtocol.hex(QmsProtocol.fingerprint(own.boxPublic, own.signPublic));
        if (fp === ownFingerprint) throw new Error('You cannot import this wallet’s own Messenger invitation');
        let imported = state.contacts.find(item => item.id === fp || item.fingerprint === fp);
        if (imported) {
          if (imported.invitationHex === invitationHex && !imported.archivedAt) throw new Error('This contact invitation is already imported');
          imported.name = name;
          imported.invitationHex = invitationHex;
          imported.verifiedAt = null;
          delete imported.archivedAt;
          if (!imported.localInvitationHex) imported.localInvitationHex = QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(identity)));
        } else {
          if (state.contacts.length >= MAX_CONTACTS) throw new Error('Messenger contact limit reached');
          imported = {
            id: fp,
            fingerprint: fp,
            name,
            invitationHex,
            localInvitationHex: QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(identity))),
            verifiedAt: null,
            addedAt: nowIso()
          };
          state.contacts.push(imported);
        }
        selectedId = fp;
        restoreDraft();
        retryCompleteReassemblies(state, identity, own);
        const deferredRescanFrom = resetDeferredRescan(state);
        await persist(); el('qms-contact-name').value = ''; el('qms-contact-invitation').value = ''; render(); showStatus(`Imported ${name} as unverified. Compare the complete fingerprint before sending: ${fp}`, 'ok');
        if (deferredRescanFrom !== null) showStatus(`Imported ${name} as unverified. A bounded Messenger rescan will resume at block ${deferredRescanFrom.toLocaleString()} for previously deferred unknown senders. Verify the complete fingerprint before sending: ${fp}`, 'ok');
      } catch (error) { showError(error); }
    });
    el('qms-contact-filter').addEventListener('input', renderContacts);
    el('qms-mobile-chat-back').addEventListener('click', () => {
      mobileConversationOpen = false;
      el('qms-chat-view').classList.remove('qms-mobile-conversation');
      renderContacts();
    });
    el('qms-message-input').addEventListener('input', () => {
      const item = contact();
      if (item) { item.draft = el('qms-message-input').value; scheduleUiPersist(); }
      updateComposer();
    });

    el('qms-prepare').addEventListener('click', () => operations.run('prepare', async () => {
      const button = el('qms-prepare'); button.disabled = true; button.textContent = 'Encrypting…';
      const frozen = [], reserved = new Set(); let plan = null;
      try {
        const recipientContact = contact(); if (!recipientContact) throw new Error('Select a contact');
        if (!recipientContact.verifiedAt) throw new Error('Verify this contact’s complete fingerprint before preparing a message');
        if (activePlan(state)) throw new Error('Send or cancel the existing prepared message first');
        if (state.messages.length >= MAX_MESSAGES) throw new Error('Messenger local message limit reached; export a backup before compacting history');
        if (state.plans.length >= MAX_PLANS) throw new Error('Messenger transaction journal limit reached; resolve or archive older plans first');
        const text = el('qms-message-input').value;
        const textSize = new TextEncoder().encode(text).length;
        if (!textSize || textSize > QmsProtocol.C.MAX_TEXT_BYTES) throw new Error('Enter a message of at most 4,096 UTF-8 bytes');
        const messageId = QmsProtocol.random(16), recipient = invitationFromHex(recipientContact.invitationHex);
        const ciphertext = QmsProtocol.sealText(identity, recipient, messageId, text), fragments = QmsProtocol.fragmentCiphertext(recipient, messageId, ciphertext);
        plan = { id: QmsProtocol.hex(messageId), contactId: recipientContact.id, createdAt: nowIso(), status: 'building', ciphertext: QmsProtocol.hex(ciphertext), fragments: fragments.map(fragment => QmsProtocol.hex(QmsProtocol.encodeFragment(fragment))), txs: [], totalFee: '0' };
        state.plans.push(plan); await persist(); render();
        const wallet = await synchronizedWallet('Synchronizing spendable outputs before preparing the encrypted carrier batch…');
        for (const fragment of fragments) {
          const txSet = await wallet.createTx({ accountIndex: 0, destinations: [{ address: walletKeys.address, amount: '1' }], extraHex: QmsProtocol.hex(QmsProtocol.carrierExtra(fragment)), priority: 1, relay: false, canSplit: false });
          assertActive();
          if (!txSet || !Array.isArray(txSet.txs) || txSet.txs.length !== 1) throw new Error('Each Messenger carrier must produce exactly one transaction');
          const tx = txSet.txs[0];
          if (!tx.metadata || typeof tx.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(tx.hash)
              || !tx.extraHex || !finalFragmentMatches(tx.extraHex, fragment)) {
            throw new Error('Wallet construction did not preserve a complete signed Messenger carrier');
          }
          const keyImages = allKeyImages(tx); if (!keyImages.length) throw new Error('Prepared carrier did not expose reserved inputs');
          for (const keyImage of keyImages) { if (reserved.has(keyImage)) throw new Error('Prepared carrier batch attempted to reuse an input'); reserved.add(keyImage); }
          const txEntry = { hash: tx.hash || '', metadata: tx.metadata, extraHex: tx.extraHex, fee: String(tx.fee || 0), keyImages, status: 'preparing' };
          plan.txs.push(txEntry); await persist();
          for (const keyImage of keyImages) { await wallet.freezeOutput(keyImage); assertActive(); frozen.push(keyImage); }
          txEntry.status = 'prepared';
          plan.totalFee = (BigInt(plan.totalFee) + BigInt(tx.fee || 0)).toString(); await persist();
        }
        plan.status = 'prepared'; state.messages.push({ id: plan.id, contactId: recipientContact.id, direction: 'out', text, createdAt: plan.createdAt, status: 'prepared' });
        recipientContact.draft = '';
        await persist(); el('qms-message-input').value = ''; render(); showStatus(`Prepared ${plan.txs.length} carrier transaction(s). Review the total fee before sending.`, 'ok');
      } catch (error) {
        if (closed || (error && error.name === 'AbortError')) return;
        let rollbackError = null;
        if (plan && frozen.length) {
          try { await releasePlanInputs(await options.getWallet(), plan); } catch (releaseError) { rollbackError = releaseError; }
        }
        if (plan) {
          if (rollbackError) {
            plan.status = 'recovery_required';
            for (const tx of plan.txs || []) if (tx.status !== 'broadcast' && tx.status !== 'confirmed') tx.status = 'recovery_required';
            plan.recoveryError = rollbackError.message;
          } else {
            removeDraft(state, plan);
          }
        }
        await persist();
        showError(rollbackError ? `${error.message || error}. ${rollbackError.message}` : error);
      } finally { button.textContent = 'Encrypt & review'; render(); }
    }).catch(showError));

    el('qms-send').addEventListener('click', () => operations.run('send', async () => {
      const plan = preparedForSelected(); if (!plan || plan.recoveryError) return;
      const button = el('qms-send'); button.disabled = true; button.textContent = 'Sending…';
      try {
        const wallet = await options.getWallet();
        assertActive();
        await relayPlan(plan, {
          relay: metadata => wallet.relayTxs(metadata),
          persist,
          assertActive,
          updateStatus: () => updateOutgoingMessageStatus(state, plan)
        });
        render(); showStatus('Encrypted message broadcast. Confirmation status will update during scanning.', 'ok');
      } catch (error) {
        if (closed || (error && error.name === 'AbortError')) return;
        render(); showError(plan.status === 'broadcast_unknown'
          ? new Error(`Broadcast outcome is unknown. Retry will submit the identical signed transaction. ${error.message || error}`)
          : error);
      } finally { button.disabled = false; button.textContent = 'Send encrypted message'; }
    }).catch(showError));
    el('qms-cancel').addEventListener('click', () => operations.run('cancel', async () => {
      const plan = preparedForSelected(); if (!plan || plan.txs.some(tx => !['prepared', 'recovery_required'].includes(tx.status))) return;
      try {
        await releasePlanInputs(await options.getWallet(), plan);
        assertActive(); removeDraft(state, plan); await persist(); render(); showStatus('Prepared draft deleted and unbroadcast inputs released.', 'ok');
      } catch (error) {
        if (closed || (error && error.name === 'AbortError')) return;
        plan.status = 'recovery_required';
        for (const tx of plan.txs || []) if (tx.status === 'prepared') tx.status = 'recovery_required';
        plan.recoveryError = error.message || String(error);
        await persist(); render(); showError(error);
      }
    }).catch(showError));

    function transactionExtras(block) {
      const txs = [].concat(block && block.minerTx ? [block.minerTx] : [], block && Array.isArray(block.txs) ? block.txs : []), out = [];
      for (const tx of txs) {
        if (tx && Array.isArray(tx.extra)) out.push({ extra: new Uint8Array(tx.extra), hash: tx.hash || '' });
        else if (tx && tx.extraHex) out.push({ extra: QmsProtocol.unhex(tx.extraHex), hash: tx.hash || '' });
      }
      return out;
    }
    async function getScanner() {
      assertActive();
      if (!scannerPromise) {
        scannerPromise = withTimeout(options.createScanner(), 'Messenger scanner startup').then(scanner => ({
          getHeight: () => withTimeout(scanner.getHeight(), 'Messenger height request'),
          getBlocksByRange: (start, end) => withTimeout(scanner.getBlocksByRange(start, end), `Messenger block request ${start}-${end}`)
        })).catch(error => { scannerPromise = null; throw error; });
      }
      const scanner = await scannerPromise;
      assertActive();
      return scanner;
    }
    async function scan() {
      if (scanning || recovering || !options.createScanner) return;
      if (Date.now() < nextScanAt) return;
      scanning = true;
      try {
        showStatus('Scanning QWC blocks for encrypted messages…');
        const scanner = await getScanner(); const tip = Number(await scanner.getHeight()); assertActive();
        if (!Number.isSafeInteger(tip) || tip < 0) throw new Error('Daemon returned an invalid height');
        const restoreHeight = Number(state.scan.startHeight || 0);
        let next = Number(state.scan.height || restoreHeight);
        if (next > tip) throw new Error('Daemon height is behind the saved Messenger scan cursor');
        if (next > restoreHeight && state.scan.blockHash) {
          const anchor = await scanner.getBlocksByRange(next - 1, next - 1); assertActive();
          if (!Array.isArray(anchor) || anchor.length !== 1 || Number(anchor[0].height) !== next - 1) throw new Error('Unable to verify the Messenger scan anchor');
          if (anchor[0].hash !== state.scan.blockHash) {
            const checkpoint = await findCommonCheckpoint(scanner, state.scan); assertActive();
            const resumeHeight = checkpoint ? Number(checkpoint.height) + 1 : restoreHeight;
            const snapshot = store.snapshot();
            rollbackForReorg(snapshot.state, resumeHeight, checkpoint ? checkpoint.hash : '');
            state = await store.commit(snapshot.state, snapshot.revision); assertActive();
            next = resumeHeight;
            showStatus(`Chain reorganization detected. Rescanning Messenger from block ${resumeHeight.toLocaleString()}…`);
          }
        }
        let expectedPrevHash = state.scan.blockHash || '';
        if (!expectedPrevHash && next > 0) {
          const predecessor = await scanner.getBlocksByRange(next - 1, next - 1); assertActive();
          if (!Array.isArray(predecessor) || predecessor.length !== 1 || Number(predecessor[0].height) !== next - 1
              || typeof predecessor[0].hash !== 'string' || !/^[0-9a-f]{64}$/i.test(predecessor[0].hash)) {
            throw new Error('Unable to establish the Messenger scan predecessor');
          }
          expectedPrevHash = predecessor[0].hash.toLowerCase();
        }
        while (next < tip) {
          const end = Math.min(tip - 1, next + 19), blocks = await scanner.getBlocksByRange(next, end); assertActive();
          if (!Array.isArray(blocks) || blocks.length !== end - next + 1) throw new Error('Daemon returned an incomplete Messenger block range');
          validateBlockSequence(blocks, next, expectedPrevHash);
          const snapshot = store.snapshot(), candidate = snapshot.state;
          for (let offset = 0; offset < blocks.length; offset++) {
            const block = blocks[offset], expectedHeight = next + offset;
            for (const entry of transactionExtras(block)) {
              markOutgoingConfirmed(candidate, entry.hash, block);
              let segments; try { segments = QmsProtocol.extractSegmentsFromExtra(entry.extra); } catch (_) { continue; }
              if (!segments.length) continue;
              try {
                const fragment = QmsProtocol.decodeSegments(segments);
                acceptFragment(candidate, identity, invitationFromHex(candidate.ownInvitation), fragment, { txHash: entry.hash, blockHeight: block.height, blockHash: block.hash, createdAt: block.timestamp ? new Date(Number(block.timestamp) * 1000).toISOString() : nowIso() });
              } catch (error) {
                if (error && ['QMS_INVALID_FRAGMENT', 'QMS_INVALID_PAYLOAD'].includes(error.code)) continue;
                throw error;
              }
            }
            candidate.scan.height = expectedHeight + 1;
            candidate.scan.blockHash = block.hash.toLowerCase();
          }
          candidate.scan.checkpoints = (candidate.scan.checkpoints || []).concat([{ height: end, hash: candidate.scan.blockHash }]).slice(-64);
          state = await store.commit(candidate, snapshot.revision); assertActive();
          expectedPrevHash = state.scan.blockHash;
          next = end + 1;
        }
        scanFailures = 0;
        nextScanAt = Date.now() + 30000;
        render(); showStatus(state.scan.rescanFrom === undefined
          ? `Messenger scan complete at block ${Math.max(0, tip - 1).toLocaleString()}.`
          : `Messenger scan complete. Stale unmatched carriers were deferred with a bounded rescan anchor at block ${Number(state.scan.rescanFrom).toLocaleString()}. Importing the matching sender invitation retries them.`, 'ok');
      } catch (error) {
        scanFailures += 1;
        const delay = Math.min(5 * 60 * 1000, 30000 * (2 ** Math.min(4, scanFailures - 1)));
        nextScanAt = Date.now() + delay;
        if (error && error.code === 'QMS_CAPACITY') {
          error.message += ' Free local Messenger capacity or import the missing contact, then retry.';
        } else if (error && !error.name) {
          error.message += ` Automatic retry is delayed for ${Math.round(delay / 1000)} seconds.`;
        }
        throw error;
      } finally { scanning = false; }
    }

    restoreDraft();
    render();
    try {
      const stale = state.plans.filter(plan => plan.status === 'building');
      const recoverable = state.plans.filter(plan => ['prepared', 'broadcast_unknown', 'recovery_required'].includes(plan.status));
      const recoveryWallet = stale.length || recoverable.length
        ? await synchronizedWallet('Synchronizing the wallet before restoring the prepared Messenger journal…')
        : null;
      if (stale.length) {
        for (const plan of stale) {
          try { await releasePlanInputs(recoveryWallet, plan); removeDraft(state, plan); }
          catch (error) {
            plan.status = 'recovery_required';
            for (const tx of plan.txs || []) if (tx.status !== 'broadcast' && tx.status !== 'confirmed') tx.status = 'recovery_required';
            plan.recoveryError = error.message || String(error);
          }
        }
      }
      for (const plan of recoverable) {
        const seen = new Set();
        try {
          for (const tx of plan.txs || []) {
            if (tx.status !== 'prepared') continue;
            for (const keyImage of tx.keyImages || []) { if (seen.has(keyImage)) throw new Error('Prepared journal reuses an input'); seen.add(keyImage); await recoveryWallet.freezeOutput(keyImage); }
          }
          delete plan.recoveryError;
        } catch (error) { plan.recoveryError = error.message || String(error); }
      }
      await persist();
    } finally {
      recovering = false; render();
      const plan = activePlan(state);
      if (plan) {
        setTab('messenger');
        if (plan.recoveryError) showStatus(`Prepared draft is blocked: ${plan.recoveryError}`, 'error');
      }
    }

    return {
      async clear() {
        if (uiSaveTimer) {
          clearTimeout(uiSaveTimer);
          uiSaveTimer = null;
          try { await persist(); } catch (_) {}
        }
        closed = true;
        if (signal) signal.removeEventListener('abort', onAbort);
        selectedId = null;
        const messageInput = el('qms-message-input'); if (messageInput) messageInput.value = '';
        const messageList = el('qms-message-list'); if (messageList) messageList.replaceChildren();
        const invitation = el('qms-own-invitation'); if (invitation) invitation.value = '';
        if (options.setWalletSpendBlocked) options.setWalletSpendBlocked(false);
        await closeStore();
      },
      scan,
      resumeScan() { nextScanAt = 0; return scan(); }
    };
  }

  return { mount, testing: { normalizeState, activePlan, acceptFragment, retryCompleteReassemblies, evictStaleInboundState, resetDeferredRescan, rollbackForReorg, validateBlockSequence, findCommonCheckpoint, removeDraft, recomputePlanStatus, releasePlanInputs, createOperationMutex, beginBroadcastAttempt, completeBroadcastAttempt, markBroadcastUnknown, relayPlan, statusLabel } };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsMessenger;
