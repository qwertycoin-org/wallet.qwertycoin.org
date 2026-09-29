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
    'partially confirmed': 'Partially confirmed',
    confirmed: 'Confirmed',
    cancelled: 'Cancelled',
    recovery_required: 'Recovery required'
  });
  const MAX_REASSEMBLIES = 64;
  const MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024;

  function nowIso() { return new Date().toISOString(); }
  function messengerError(code, message) { const error = new Error(message); error.code = code; return error; }
  function short(value) { return value ? value.slice(0, 16) + '…' : ''; }
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
    if (!state.scan || !Number.isSafeInteger(Number(state.scan.height)) || Number(state.scan.height) < 0) state.scan = { height: 0, blockHash: '', startHeight: null, checkpoints: [] };
    if (!Array.isArray(state.scan.checkpoints)) state.scan.checkpoints = [];

    // Early development builds keyed one copy of the same ciphertext by every
    // contact. Merge those copies into one recipient-authenticated reassembly.
    const merged = new Map();
    for (const candidate of state.reassembly) {
      if (!candidate || typeof candidate.messageId !== 'string' || typeof candidate.hash !== 'string' || !candidate.fragments) continue;
      const key = candidate.messageId + ':' + candidate.hash;
      const partial = merged.get(key) || { messageId: candidate.messageId, hash: candidate.hash, count: 0, ciphertextSize: 0, fragments: {}, bytes: 0 };
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
  function addFragmentRecord(state, fragment, source) {
    const messageId = QmsProtocol.hex(fragment.messageId);
    const hash = QmsProtocol.hex(fragment.ciphertextHash);
    let partial = state.reassembly.find(item => item.messageId === messageId && item.hash === hash);
    if (!partial) {
      if (state.reassembly.length >= MAX_REASSEMBLIES) throw messengerError('QMS_CAPACITY', 'Messenger reassembly limit reached; scan cursor was not advanced');
      partial = { messageId, hash, count: fragment.count, ciphertextSize: fragment.ciphertextSize, fragments: {}, bytes: 0 };
      state.reassembly.push(partial);
    }
    if (partial.count !== fragment.count || partial.ciphertextSize !== fragment.ciphertextSize) throw messengerError('QMS_INVALID_FRAGMENT', 'Conflicting Messenger fragment metadata');

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
    for (const senderContact of state.contacts) {
      try {
        const opened = QmsProtocol.openText(identity, invitationFromHex(senderContact.invitationHex), ownInvitation, fragments[0].messageId, ciphertext);
        const newest = records.slice().sort((a, b) => Number(a.blockHeight || 0) - Number(b.blockHeight || 0)).pop();
        return {
          id: partial.messageId,
          contactId: senderContact.id,
          direction: 'in',
          text: opened.text,
          createdAt: newest.createdAt || nowIso(),
          status: 'confirmed',
          txHash: newest.txHash || '',
          sourceFragments: records
        };
      } catch (_) { /* Recipient MACs deliberately do not identify the pinned sender. */ }
    }
    return null;
  }

  function acceptFragment(state, identity, ownInvitation, fragment, source) {
    if (!QmsProtocol.verifyFragment(ownInvitation, fragment)) return null;
    const messageId = QmsProtocol.hex(fragment.messageId);
    if (state.messages.some(message => message.id === messageId && message.direction === 'in')) return null;
    const partial = addFragmentRecord(state, fragment, source);
    const message = openCompletePartial(state, partial, identity, ownInvitation);
    if (message) {
      state.messages.push(message);
      state.reassembly = state.reassembly.filter(item => item !== partial);
    }
    return message;
  }

  function retryCompleteReassemblies(state, identity, ownInvitation) {
    const opened = [];
    for (const partial of state.reassembly.slice()) {
      const message = openCompletePartial(state, partial, identity, ownInvitation);
      if (!message || state.messages.some(item => item.id === message.id && item.direction === 'in')) continue;
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
    if (statuses.some(status => status === 'confirmed')) return 'partially confirmed';
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
    normalizeState(state);
    for (const plan of state.plans) {
      for (const tx of plan.txs || []) {
        if (tx.status === 'confirmed' && Number(tx.blockHeight || 0) >= restoreHeight) { tx.status = 'broadcast'; delete tx.blockHeight; delete tx.blockHash; }
      }
      if (plan.status === 'confirmed' || plan.status === 'partially confirmed') plan.status = recomputePlanStatus(plan);
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

    let selectedId = activePlan(state) ? activePlan(state).contactId : (state.contacts[0] ? state.contacts[0].id : null);
    let scanning = false;
    let recovering = true;
    let scannerPromise = null;
    const operations = createOperationMutex();
    const el = id => document.getElementById(id);
    const section = el('qms-section'), overviewTab = el('wallet-tab-overview'), messengerTab = el('wallet-tab-messenger');
    const dashboard = el('dashboard');
    const overviewNodes = Array.from(dashboard.children).filter(node => node !== section && node.id !== 'wallet-tabs' && !node.classList.contains('wallet-header'));
    const originalHidden = new Map(overviewNodes.map(node => [node, node.hidden]));

    function showStatus(message, type) { if (closed) return; const node = el('qms-status'); node.textContent = message || ''; node.className = 'qms-status' + (type ? ' ' + type : ''); }
    function showError(error) { if (closed || (error && error.name === 'AbortError')) return; showStatus(error && error.message ? error.message : String(error), 'error'); }
    function emptyNotice(message) { const node = document.createElement('div'); node.className = 'qms-empty'; node.textContent = message; return node; }
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
    function contact() { return state.contacts.find(item => item.id === selectedId) || null; }
    function preparedForSelected() { return state.plans.find(plan => plan.contactId === selectedId && ACTIVE_PLAN_STATUSES.has(plan.status) && plan.status !== 'building') || null; }
    function formatDate(value) { try { return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)); } catch (_) { return value; } }
    function messageByteCount() { return new TextEncoder().encode(el('qms-message-input').value).length; }

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
      if (!state.contacts.length) { list.appendChild(emptyNotice('No contacts yet')); return; }
      for (const item of state.contacts) {
        const button = document.createElement('button'); button.className = 'qms-contact' + (item.id === selectedId ? ' active' : ''); button.type = 'button';
        button.setAttribute('aria-pressed', String(item.id === selectedId));
        button.disabled = recovering;
        const name = document.createElement('strong'); name.textContent = item.name;
        const fingerprint = document.createElement('span'); fingerprint.textContent = short(item.fingerprint);
        button.append(name, fingerprint);
        button.addEventListener('click', () => {
          selectedId = item.id; render();
        });
        list.appendChild(button);
      }
    }

    function updateComposer() {
      const item = contact(), lockedPlan = activePlan(state), size = messageByteCount();
      el('qms-byte-count').textContent = `${size.toLocaleString()} / 4,096 UTF-8 bytes`;
      el('qms-message-input').disabled = recovering || !item || !!lockedPlan;
      el('qms-prepare').disabled = recovering || !item || !!lockedPlan || !size || size > QmsProtocol.C.MAX_TEXT_BYTES;
    }

    function renderMessages() {
      const item = contact();
      const messages = state.messages.filter(message => message.contactId === selectedId).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      el('qms-chat-name').textContent = item ? item.name : 'Select a contact'; el('qms-chat-fingerprint').textContent = item ? item.fingerprint : '';
      const list = el('qms-message-list'); list.replaceChildren();
      if (!messages.length) list.appendChild(emptyNotice(item ? 'No messages in this chat yet.' : 'Import a personal invitation to begin.'));
      for (const message of messages) {
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
      list.scrollTop = list.scrollHeight;
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
      el('qms-own-invitation').value = state.ownInvitation;
      const own = invitationFromHex(state.ownInvitation);
      el('qms-own-fingerprint').textContent = 'Fingerprint: ' + QmsProtocol.hex(QmsProtocol.fingerprint(own.boxPublic, own.signPublic));
      const list = el('qms-manage-list'); list.replaceChildren();
      for (const item of state.contacts) {
        const row = document.createElement('div'); row.className = 'qms-manage-row';
        const input = document.createElement('input'); input.value = item.name; input.maxLength = 80; input.disabled = recovering;
        const rename = document.createElement('button'); rename.className = 'action-btn'; rename.textContent = 'Rename'; rename.disabled = input.disabled;
        rename.addEventListener('click', async () => { assertActive(); const value = input.value.trim(); if (!value) return; item.name = value; await persist(); render(); showStatus('Contact renamed.', 'ok'); });
        const remove = document.createElement('button'); remove.className = 'action-btn'; remove.textContent = 'Remove'; remove.disabled = input.disabled;
        remove.addEventListener('click', async () => {
          if ((state.plans || []).some(plan => plan.contactId === item.id && ACTIVE_PLAN_STATUSES.has(plan.status))) {
            showStatus('Resolve this contact’s prepared Messenger transaction before removing the contact.', 'error');
            return;
          }
          if (!confirm(`Remove ${item.name}? Existing local chat history will be retained and will reappear if this invitation is imported again.`)) return;
          state.contacts = state.contacts.filter(candidate => candidate.id !== item.id);
          if (selectedId === item.id) selectedId = state.contacts[0] ? state.contacts[0].id : null;
          await persist(); render(); showStatus('Contact removed. Existing local message history was retained.', 'ok');
        });
        row.append(input, rename, remove); list.appendChild(row);
      }
    }
    function render() { if (closed) return; renderContacts(); renderMessages(); renderManage(); }

    el('qms-manage-toggle').addEventListener('click', () => {
      el('qms-chat-view').hidden = true; el('qms-manage-view').hidden = false;
    });
    el('qms-manage-back').addEventListener('click', () => { el('qms-manage-view').hidden = true; el('qms-chat-view').hidden = false; render(); });
    el('qms-copy-invitation').addEventListener('click', async () => { await navigator.clipboard.writeText(state.ownInvitation); showStatus('Complete personal invitation copied.', 'ok'); });
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
        if (state.contacts.some(item => item.id === fp)) throw new Error('This contact invitation is already imported');
        state.contacts.push({ id: fp, fingerprint: fp, name, invitationHex, addedAt: nowIso() }); selectedId = fp;
        retryCompleteReassemblies(state, identity, own);
        await persist(); el('qms-contact-name').value = ''; el('qms-contact-invitation').value = ''; render(); showStatus(`Imported ${name}. Confirm fingerprint ${fp}`, 'ok');
      } catch (error) { showError(error); }
    });
    el('qms-message-input').addEventListener('input', updateComposer);

    el('qms-prepare').addEventListener('click', () => operations.run('prepare', async () => {
      const button = el('qms-prepare'); button.disabled = true; button.textContent = 'Encrypting…';
      const frozen = [], reserved = new Set(); let plan = null;
      try {
        const recipientContact = contact(); if (!recipientContact) throw new Error('Select a contact');
        if (activePlan(state)) throw new Error('Send or cancel the existing prepared message first');
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
    async function getScanner() { assertActive(); if (!scannerPromise) scannerPromise = options.createScanner(); const scanner = await scannerPromise; assertActive(); return scanner; }
    async function scan() {
      if (scanning || recovering || !options.createScanner) return;
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
                if (error && error.code === 'QMS_INVALID_FRAGMENT') continue;
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
        render(); showStatus(`Messenger scan complete at block ${Math.max(0, tip - 1).toLocaleString()}.`, 'ok');
      } finally { scanning = false; }
    }

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
        closed = true;
        if (signal) signal.removeEventListener('abort', onAbort);
        selectedId = null;
        const messageInput = el('qms-message-input'); if (messageInput) messageInput.value = '';
        const messageList = el('qms-message-list'); if (messageList) messageList.replaceChildren();
        const invitation = el('qms-own-invitation'); if (invitation) invitation.value = '';
        if (options.setWalletSpendBlocked) options.setWalletSpendBlocked(false);
        await closeStore();
      },
      scan
    };
  }

  return { mount, testing: { normalizeState, activePlan, acceptFragment, retryCompleteReassemblies, rollbackForReorg, validateBlockSequence, findCommonCheckpoint, removeDraft, recomputePlanStatus, releasePlanInputs, createOperationMutex, beginBroadcastAttempt, completeBroadcastAttempt, markBroadcastUnknown, relayPlan, statusLabel } };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsMessenger;
