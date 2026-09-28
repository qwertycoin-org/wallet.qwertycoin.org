// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const QmsMessenger = (() => {
  'use strict';

  const ACTIVE_PLAN_STATUSES = new Set(['building', 'prepared', 'partially broadcast', 'rollback required']);
  const MAX_REASSEMBLIES = 64;
  const MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024;

  function nowIso() { return new Date().toISOString(); }
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
  function activePlan(state) { return state.plans.find(plan => ACTIVE_PLAN_STATUSES.has(plan.status)) || null; }
  function finalFragmentMatches(extraHex, expected) {
    try {
      const segments = QmsProtocol.extractSegmentsFromExtra(QmsProtocol.unhex(extraHex));
      return QmsProtocol.equal(QmsProtocol.encodeFragment(QmsProtocol.decodeSegments(segments)), QmsProtocol.encodeFragment(expected));
    } catch (_) { return false; }
  }

  function normalizeState(state) {
    if (!Array.isArray(state.reassembly)) state.reassembly = [];
    if (!state.scan || !Number.isSafeInteger(Number(state.scan.height)) || Number(state.scan.height) < 0) state.scan = { height: 0, blockHash: '' };

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
    return state;
  }

  function totalReassemblyBytes(state) { return state.reassembly.reduce((sum, partial) => sum + Number(partial.bytes || 0), 0); }
  function addFragmentRecord(state, fragment, source) {
    const messageId = QmsProtocol.hex(fragment.messageId);
    const hash = QmsProtocol.hex(fragment.ciphertextHash);
    let partial = state.reassembly.find(item => item.messageId === messageId && item.hash === hash);
    if (!partial) {
      if (state.reassembly.length >= MAX_REASSEMBLIES) throw new Error('Messenger reassembly limit reached');
      partial = { messageId, hash, count: fragment.count, ciphertextSize: fragment.ciphertextSize, fragments: {}, bytes: 0 };
      state.reassembly.push(partial);
    }
    if (partial.count !== fragment.count || partial.ciphertextSize !== fragment.ciphertextSize) throw new Error('Conflicting Messenger fragment metadata');

    const index = String(fragment.index);
    const encoded = QmsProtocol.hex(QmsProtocol.encodeFragment(fragment));
    if (partial.fragments[index]) {
      if (partial.fragments[index].encoded !== encoded) throw new Error('Conflicting Messenger fragment duplicate');
      return partial;
    }
    if (totalReassemblyBytes(state) + fragment.data.length > MAX_REASSEMBLY_BYTES) throw new Error('Messenger reassembly byte limit reached');
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
    if (statuses.some(status => status === 'prepared')) return statuses.some(status => status !== 'prepared') ? 'partially broadcast' : 'prepared';
    if (statuses.some(status => status === 'confirmed')) return 'partially confirmed';
    return 'broadcast';
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

  function rollbackForReorg(state, restoreHeight) {
    state.messages = state.messages.filter(message => message.direction !== 'in');
    state.reassembly = [];
    for (const plan of state.plans) {
      for (const tx of plan.txs || []) {
        if (tx.status === 'confirmed') { tx.status = 'broadcast'; delete tx.blockHeight; delete tx.blockHash; }
      }
      if (plan.status === 'confirmed' || plan.status === 'partially confirmed') plan.status = recomputePlanStatus(plan);
      updateOutgoingMessageStatus(state, plan);
    }
    state.scan = { height: restoreHeight, blockHash: '' };
  }

  function removeDraft(state, plan) {
    state.plans = state.plans.filter(item => item.id !== plan.id);
    state.messages = state.messages.filter(message => !(message.id === plan.id && message.direction === 'out'));
  }

  async function releasePlanInputs(wallet, plan) {
    const failures = [];
    const seen = new Set();
    for (const tx of plan.txs || []) {
      if (tx.status === 'broadcast' || tx.status === 'confirmed') continue;
      for (const keyImage of tx.keyImages || []) {
        if (seen.has(keyImage)) continue;
        seen.add(keyImage);
        try { await wallet.thawOutput(keyImage); } catch (error) { failures.push(error && error.message ? error.message : String(error)); }
      }
    }
    if (failures.length) throw new Error(`Unable to release ${failures.length} reserved input(s): ${failures[0]}`);
  }

  async function mount(options) {
    await QmsProtocol.ready();
    const walletKeys = options.getWalletKeys();
    if (!walletKeys || !walletKeys.privateSpendKeyHex) throw new Error('Messenger requires an unlocked full wallet');
    const qmsKey = options.getQmsKey && options.getQmsKey();
    if (!(qmsKey instanceof Uint8Array) || qmsKey.length !== 32) throw new Error('Messenger requires a non-empty Session password');
    const qmsKdf = options.getQmsKdf && options.getQmsKdf();
    const store = await QmsStore.open(walletKeys, qmsKey, qmsKdf), state = normalizeState(store.state);
    if (!state.identity) state.identity = identityToJson(QmsProtocol.createIdentity());
    const identity = identityFromJson(state.identity);
    if (!state.ownInvitation) state.ownInvitation = QmsProtocol.hex(QmsProtocol.encodeInvitation(QmsProtocol.createInvitation(identity)));
    await store.save();

    let selectedId = activePlan(state) ? activePlan(state).contactId : (state.contacts[0] ? state.contacts[0].id : null);
    let scanning = false;
    let recovering = true;
    let scannerPromise = null;
    const el = id => document.getElementById(id);
    const section = el('qms-section'), overviewTab = el('wallet-tab-overview'), messengerTab = el('wallet-tab-messenger');
    const dashboard = el('dashboard');
    const overviewNodes = Array.from(dashboard.children).filter(node => node !== section && node.id !== 'wallet-tabs' && !node.classList.contains('wallet-header'));
    const originalHidden = new Map(overviewNodes.map(node => [node, node.hidden]));

    function showStatus(message, type) { const node = el('qms-status'); node.textContent = message || ''; node.className = 'qms-status' + (type ? ' ' + type : ''); }
    function showError(error) { showStatus(error && error.message ? error.message : String(error), 'error'); }
    function emptyNotice(message) { const node = document.createElement('div'); node.className = 'qms-empty'; node.textContent = message; return node; }
    async function synchronizedWallet(statusMessage) {
      if (statusMessage) showStatus(statusMessage);
      const wallet = await options.getWallet();
      if (wallet.reconnectDaemon) await wallet.reconnectDaemon();
      if (wallet.sync) await wallet.sync(Math.max(0, Number(options.getRestoreHeight() || 0)));
      return wallet;
    }
    function contact() { return state.contacts.find(item => item.id === selectedId) || null; }
    function preparedForSelected() { return state.plans.find(plan => plan.contactId === selectedId && (plan.status === 'prepared' || plan.status === 'partially broadcast' || plan.status === 'rollback required')) || null; }
    function formatDate(value) { try { return new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)); } catch (_) { return value; } }
    function messageByteCount() { return new TextEncoder().encode(el('qms-message-input').value).length; }

    function setTab(name) {
      if (name === 'overview' && activePlan(state)) {
        showStatus('Send or cancel the prepared message before returning to the wallet.', 'error');
        return;
      }
      const messenger = name === 'messenger'; section.hidden = !messenger;
      overviewNodes.forEach(node => { node.hidden = messenger ? true : originalHidden.get(node); });
      overviewTab.classList.toggle('active', !messenger); messengerTab.classList.toggle('active', messenger);
      overviewTab.setAttribute('aria-selected', String(!messenger)); messengerTab.setAttribute('aria-selected', String(messenger));
      if (messenger && !recovering) { render(); scan().catch(showError); }
    }
    overviewTab.addEventListener('click', () => setTab('overview'));
    messengerTab.addEventListener('click', () => setTab('messenger'));

    function renderContacts() {
      const lockedPlan = activePlan(state);
      if (lockedPlan && selectedId !== lockedPlan.contactId) selectedId = lockedPlan.contactId;
      const list = el('qms-contact-list'); list.replaceChildren();
      if (!state.contacts.length) { list.appendChild(emptyNotice('No contacts yet')); return; }
      for (const item of state.contacts) {
        const button = document.createElement('button'); button.className = 'qms-contact' + (item.id === selectedId ? ' active' : ''); button.type = 'button';
        button.setAttribute('aria-pressed', String(item.id === selectedId));
        button.disabled = recovering || (!!lockedPlan && item.id !== lockedPlan.contactId);
        const name = document.createElement('strong'); name.textContent = item.name;
        const fingerprint = document.createElement('span'); fingerprint.textContent = short(item.fingerprint);
        button.append(name, fingerprint);
        button.addEventListener('click', () => {
          if (lockedPlan && item.id !== lockedPlan.contactId) { showStatus('Send or cancel the prepared message before changing chats.', 'error'); return; }
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
        const status = document.createElement('span'); status.className = 'qms-message-status' + (message.status === 'failed' ? ' error' : ''); status.textContent = message.status;
        meta.append(who, when, status); bubble.appendChild(meta); row.appendChild(bubble); list.appendChild(row);
      }
      list.scrollTop = list.scrollHeight;
      const plan = preparedForSelected(); el('qms-review').hidden = !plan;
      if (plan) {
        el('qms-review-count').textContent = `${plan.txs.length} transaction${plan.txs.length === 1 ? '' : 's'}`;
        el('qms-review-fee').textContent = `Fee ${atomic(plan.totalFee)} QWC`;
        el('qms-review-note').textContent = plan.recoveryError
          ? `This draft is blocked: ${plan.recoveryError}`
          : 'Review the complete carrier batch. Nothing is broadcast until you select Send encrypted message.';
        el('qms-send').disabled = recovering || !!plan.recoveryError || plan.status === 'rollback required';
        el('qms-cancel').disabled = recovering || plan.txs.some(tx => tx.status === 'broadcast' || tx.status === 'confirmed');
      }
      el('qms-manage-toggle').disabled = recovering || !!activePlan(state);
      overviewTab.disabled = recovering || !!activePlan(state);
      overviewTab.setAttribute('aria-disabled', String(overviewTab.disabled));
      updateComposer();
    }

    function renderManage() {
      el('qms-own-invitation').value = state.ownInvitation;
      const own = invitationFromHex(state.ownInvitation);
      el('qms-own-fingerprint').textContent = 'Fingerprint: ' + QmsProtocol.hex(QmsProtocol.fingerprint(own.boxPublic, own.signPublic));
      const list = el('qms-manage-list'); list.replaceChildren();
      for (const item of state.contacts) {
        const row = document.createElement('div'); row.className = 'qms-manage-row';
        const input = document.createElement('input'); input.value = item.name; input.maxLength = 80; input.disabled = recovering || !!activePlan(state);
        const rename = document.createElement('button'); rename.className = 'action-btn'; rename.textContent = 'Rename'; rename.disabled = input.disabled;
        rename.addEventListener('click', async () => { const value = input.value.trim(); if (!value) return; item.name = value; await store.save(); render(); showStatus('Contact renamed.', 'ok'); });
        const remove = document.createElement('button'); remove.className = 'action-btn'; remove.textContent = 'Remove'; remove.disabled = input.disabled;
        remove.addEventListener('click', async () => {
          if (!confirm(`Remove ${item.name}? Existing local chat history will be retained and will reappear if this invitation is imported again.`)) return;
          state.contacts = state.contacts.filter(candidate => candidate.id !== item.id);
          if (selectedId === item.id) selectedId = state.contacts[0] ? state.contacts[0].id : null;
          await store.save(); render(); showStatus('Contact removed. Existing local message history was retained.', 'ok');
        });
        row.append(input, rename, remove); list.appendChild(row);
      }
    }
    function render() { renderContacts(); renderMessages(); renderManage(); }

    el('qms-manage-toggle').addEventListener('click', () => {
      if (activePlan(state)) { showStatus('Send or cancel the prepared message before managing contacts.', 'error'); return; }
      el('qms-chat-view').hidden = true; el('qms-manage-view').hidden = false;
    });
    el('qms-manage-back').addEventListener('click', () => { el('qms-manage-view').hidden = true; el('qms-chat-view').hidden = false; render(); });
    el('qms-copy-invitation').addEventListener('click', async () => { await navigator.clipboard.writeText(state.ownInvitation); showStatus('Complete personal invitation copied.', 'ok'); });
    el('qms-import-contact').addEventListener('click', async () => {
      try {
        if (activePlan(state)) throw new Error('Send or cancel the prepared message first');
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
        await store.save(); el('qms-contact-name').value = ''; el('qms-contact-invitation').value = ''; render(); showStatus(`Imported ${name}. Confirm fingerprint ${fp}`, 'ok');
      } catch (error) { showError(error); }
    });
    el('qms-message-input').addEventListener('input', updateComposer);

    el('qms-prepare').addEventListener('click', async () => {
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
        state.plans.push(plan); await store.save(); render();
        const wallet = await synchronizedWallet('Synchronizing spendable outputs before preparing the encrypted carrier batch…');
        for (const fragment of fragments) {
          const txSet = await wallet.createTx({ accountIndex: 0, destinations: [{ address: walletKeys.address, amount: '1' }], extraHex: QmsProtocol.hex(QmsProtocol.carrierExtra(fragment)), priority: 1, relay: false, canSplit: false });
          if (!txSet || !Array.isArray(txSet.txs) || txSet.txs.length !== 1) throw new Error('Each Messenger carrier must produce exactly one transaction');
          const tx = txSet.txs[0]; if (!tx.metadata || !tx.extraHex || !finalFragmentMatches(tx.extraHex, fragment)) throw new Error('Wallet construction did not preserve the planned Messenger fragment');
          const keyImages = allKeyImages(tx); if (!keyImages.length) throw new Error('Prepared carrier did not expose reserved inputs');
          for (const keyImage of keyImages) { if (reserved.has(keyImage)) throw new Error('Prepared carrier batch attempted to reuse an input'); reserved.add(keyImage); }
          const txEntry = { hash: tx.hash || '', metadata: tx.metadata, extraHex: tx.extraHex, fee: String(tx.fee || 0), keyImages, status: 'preparing' };
          plan.txs.push(txEntry); await store.save();
          for (const keyImage of keyImages) { await wallet.freezeOutput(keyImage); frozen.push(keyImage); }
          txEntry.status = 'prepared';
          plan.totalFee = (BigInt(plan.totalFee) + BigInt(tx.fee || 0)).toString(); await store.save();
        }
        plan.status = 'prepared'; state.messages.push({ id: plan.id, contactId: recipientContact.id, direction: 'out', text, createdAt: plan.createdAt, status: 'ready to send' });
        await store.save(); el('qms-message-input').value = ''; render(); showStatus(`Prepared ${plan.txs.length} carrier transaction(s). Review the total fee before sending.`, 'ok');
      } catch (error) {
        let rollbackError = null;
        if (plan && frozen.length) {
          try { await releasePlanInputs(await options.getWallet(), plan); } catch (releaseError) { rollbackError = releaseError; }
        }
        if (plan) {
          if (rollbackError) {
            plan.status = 'rollback required';
            plan.recoveryError = rollbackError.message;
          } else {
            removeDraft(state, plan);
          }
        }
        await store.save();
        showError(rollbackError ? `${error.message || error}. ${rollbackError.message}` : error);
      } finally { button.textContent = 'Encrypt & review'; render(); }
    });

    el('qms-send').addEventListener('click', async () => {
      const plan = preparedForSelected(); if (!plan || plan.recoveryError) return;
      const button = el('qms-send'); button.disabled = true; button.textContent = 'Sending…';
      try {
        const wallet = await options.getWallet();
        for (const tx of plan.txs) {
          if (tx.status === 'broadcast' || tx.status === 'confirmed') continue;
          const hashes = await wallet.relayTxs([tx.metadata]); const hash = Array.isArray(hashes) ? hashes[0] : hashes;
          if (typeof hash !== 'string' || !/^[0-9a-f]{64}$/i.test(hash)) throw new Error('Wallet did not return a valid broadcast transaction hash');
          if (tx.hash && tx.hash.toLowerCase() !== hash.toLowerCase()) throw new Error('Broadcast hash does not match the prepared transaction');
          tx.hash = hash.toLowerCase(); tx.status = 'broadcast'; await store.save();
        }
        plan.status = recomputePlanStatus(plan); updateOutgoingMessageStatus(state, plan); await store.save(); render(); showStatus('Encrypted message broadcast. Confirmation status will update during scanning.', 'ok');
      } catch (error) {
        plan.status = recomputePlanStatus(plan); updateOutgoingMessageStatus(state, plan); await store.save(); render(); showError(error);
      } finally { button.disabled = false; button.textContent = 'Send encrypted message'; }
    });
    el('qms-cancel').addEventListener('click', async () => {
      const plan = preparedForSelected(); if (!plan || plan.txs.some(tx => tx.status === 'broadcast' || tx.status === 'confirmed')) return;
      try {
        await releasePlanInputs(await options.getWallet(), plan);
        removeDraft(state, plan); await store.save(); render(); showStatus('Prepared draft deleted and unbroadcast inputs released.', 'ok');
      } catch (error) {
        plan.status = 'rollback required'; plan.recoveryError = error.message || String(error);
        await store.save(); render(); showError(error);
      }
    });

    function transactionExtras(block) {
      const txs = [].concat(block && block.minerTx ? [block.minerTx] : [], block && Array.isArray(block.txs) ? block.txs : []), out = [];
      for (const tx of txs) {
        if (tx && Array.isArray(tx.extra)) out.push({ extra: new Uint8Array(tx.extra), hash: tx.hash || '' });
        else if (tx && tx.extraHex) out.push({ extra: QmsProtocol.unhex(tx.extraHex), hash: tx.hash || '' });
      }
      return out;
    }
    async function getScanner() { if (!scannerPromise) scannerPromise = options.createScanner(); return scannerPromise; }
    async function scan() {
      if (scanning || recovering || activePlan(state) || !state.contacts.length || !options.createScanner) return;
      scanning = true;
      try {
        showStatus('Scanning QWC blocks for encrypted messages…');
        const scanner = await getScanner(); const tip = Number(await scanner.getHeight());
        if (!Number.isSafeInteger(tip) || tip < 0) throw new Error('Daemon returned an invalid height');
        const restoreHeight = Math.max(0, Number(options.getRestoreHeight() || 0));
        let next = Number(state.scan.height || restoreHeight);
        if (next > tip) throw new Error('Daemon height is behind the saved Messenger scan cursor');
        if (next > restoreHeight && state.scan.blockHash) {
          const anchor = await scanner.getBlocksByRange(next - 1, next - 1);
          if (!Array.isArray(anchor) || anchor.length !== 1 || Number(anchor[0].height) !== next - 1) throw new Error('Unable to verify the Messenger scan anchor');
          if (anchor[0].hash !== state.scan.blockHash) { rollbackForReorg(state, restoreHeight); next = restoreHeight; await store.save(); showStatus(`Chain reorganization detected. Rescanning Messenger from block ${restoreHeight.toLocaleString()}…`); }
        }
        while (next < tip) {
          const end = Math.min(tip - 1, next + 19), blocks = await scanner.getBlocksByRange(next, end);
          if (!Array.isArray(blocks) || blocks.length !== end - next + 1) throw new Error('Daemon returned an incomplete Messenger block range');
          for (let offset = 0; offset < blocks.length; offset++) {
            const block = blocks[offset], expectedHeight = next + offset;
            if (Number(block.height) !== expectedHeight || typeof block.hash !== 'string') throw new Error('Daemon returned a non-contiguous Messenger block range');
            for (const entry of transactionExtras(block)) {
              markOutgoingConfirmed(state, entry.hash, block);
              let segments; try { segments = QmsProtocol.extractSegmentsFromExtra(entry.extra); } catch (_) { continue; }
              if (!segments.length) continue;
              try {
                const fragment = QmsProtocol.decodeSegments(segments);
                acceptFragment(state, identity, invitationFromHex(state.ownInvitation), fragment, { txHash: entry.hash, blockHeight: block.height, blockHash: block.hash, createdAt: block.timestamp ? new Date(Number(block.timestamp) * 1000).toISOString() : nowIso() });
              } catch (_) {}
            }
            state.scan = { height: expectedHeight + 1, blockHash: block.hash };
          }
          next = end + 1; await store.save();
        }
        await store.save(); render(); showStatus(`Messenger scan complete at block ${Math.max(0, tip - 1).toLocaleString()}.`, 'ok');
      } finally { scanning = false; }
    }

    render();
    try {
      const stale = state.plans.filter(plan => plan.status === 'building');
      const recoverable = state.plans.filter(plan => plan.status === 'prepared' || plan.status === 'partially broadcast');
      const recoveryWallet = stale.length || recoverable.length
        ? await synchronizedWallet('Synchronizing the wallet before restoring the prepared Messenger journal…')
        : null;
      if (stale.length) {
        for (const plan of stale) {
          try { await releasePlanInputs(recoveryWallet, plan); removeDraft(state, plan); }
          catch (error) { plan.status = 'rollback required'; plan.recoveryError = error.message || String(error); }
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
      await store.save();
    } finally {
      recovering = false; render();
      const plan = activePlan(state);
      if (plan) {
        setTab('messenger');
        if (plan.recoveryError) showStatus(`Prepared draft is blocked: ${plan.recoveryError}`, 'error');
      }
    }

    return {
      clear() {
        selectedId = null;
        try { sodium.memzero(identity.boxSecret); sodium.memzero(identity.signSecret); } catch (_) {}
        store.close();
      },
      scan
    };
  }

  return { mount, testing: { normalizeState, activePlan, acceptFragment, retryCompleteReassemblies, rollbackForReorg, removeDraft, recomputePlanStatus, releasePlanInputs } };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsMessenger;
