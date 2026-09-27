// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** QMS2 Web client. Ordinary browsers remain fail-closed for network transport. */
const QmsMessenger = (() => {
  'use strict';
  const MAX_REASSEMBLIES = 64;
  const MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024;

  function nowSeconds() { return Math.floor(Date.now() / 1000); }
  function nowIso() { return new Date().toISOString(); }
  function clone(value) { return JSON.parse(JSON.stringify(value)); }
  function restore(target, snapshot) { for (const key of Object.keys(target)) delete target[key]; Object.assign(target, snapshot); }

  function makeClient(store) {
    const state = store.state;
    let transientMessages = [];
    let operation = Promise.resolve();
    function serialized(fn) {
      const result = operation.then(fn, fn);
      operation = result.catch(() => {});
      return result;
    }
    async function commit(mutator) {
      const before = clone(state);
      try { await mutator(); await store.save(); }
      catch (error) { restore(state, before); throw error; }
    }
    function requireActive() { if (!state.active) throw new Error('Activate QMS2 before using Messenger'); }
    function cryptoState() { requireActive(); return QmsProtocol.unhex(state.cryptoState); }
    function contactByFingerprint(fingerprint) { return state.contacts.find(item => !item.removed && item.fingerprint === String(fingerprint).toLowerCase()) || null; }
    function totalReassemblyBytes() { return state.reassembly.reduce((sum, item) => sum + Number(item.bytes || 0), 0); }
    function messages() { return state.messages.concat(transientMessages); }

    async function setHistoryEnabled(enabled) {
      return serialized(() => commit(async () => { state.historyEnabled = !!enabled; }));
    }

    async function clearHistory() {
      return serialized(() => commit(async () => {
        state.messages = [];
        transientMessages = [];
      }));
    }

    async function resetState() {
      return serialized(() => commit(async () => {
        const replacement = QmsStore.blank();
        restore(state, replacement);
        transientMessages = [];
      }));
    }

    async function activate() {
      return serialized(async () => {
        if (state.active) return state.ownFingerprint;
        const engine = await QmsProtocol.signal.engineNew();
        const prepared = await QmsProtocol.signal.prepareContactPackage(engine, QmsProtocol.genesis());
        await commit(async () => {
          state.active = true;
          state.cryptoState = QmsProtocol.hex(prepared.nextState);
          state.invitationId = QmsProtocol.hex(prepared.invitationId);
          state.ownPackage = QmsProtocol.hex(prepared.package);
          state.ownFingerprint = QmsProtocol.hex(prepared.fingerprint);
        });
        return state.ownFingerprint;
      });
    }

    async function importContact(label, packageHex, at = nowSeconds()) {
      return serialized(async () => {
        requireActive();
        label = String(label || '').trim();
        if (!label) throw new Error('Enter a contact name');
        const normalized = String(packageHex || '').trim().toLowerCase();
        const packageBytes = QmsProtocol.unhex(normalized);
        const prepared = await QmsProtocol.signal.prepareImportContact(cryptoState(), QmsProtocol.unhex(state.invitationId), packageBytes, at);
        const fingerprint = QmsProtocol.hex(prepared.fingerprint);
        if (fingerprint === state.ownFingerprint) throw new Error("You cannot import this wallet's own QMS2 invitation");
        const existing = state.contacts.find(item => item.fingerprint === fingerprint);
        if (existing && existing.packageHex !== normalized) throw new Error('Contact fingerprint is already bound to different package data');
        await commit(async () => {
          state.cryptoState = QmsProtocol.hex(prepared.nextState);
          if (existing) { existing.removed = false; existing.name = label; }
          else state.contacts.push({ fingerprint, contactId: prepared.contactId, name: label, packageHex: normalized, addedAt: nowIso(), removed: false });
        });
        return fingerprint;
      });
    }

    async function prepareOffline(fingerprint, text, at = nowSeconds()) {
      return serialized(async () => {
        const contact = contactByFingerprint(fingerprint);
        if (!contact) throw new Error('Unknown QMS2 contact');
        if (state.prepared) throw new Error('Cancel or finish the existing QMS2 plan first');
        const current = cryptoState();
        const prepared = await QmsProtocol.signal.prepareSendText(current, contact.contactId, String(text), at);
        const context = await QmsProtocol.signal.transportContext(current, contact.contactId, true);
        const envelope = QmsProtocol.sealOuterEnvelope(context, prepared.messageId, QmsProtocol.concat([prepared.messageType], prepared.ciphertext));
        const fragments = QmsProtocol.fragmentEnvelope(context, prepared.messageId, envelope);
        return {
          messageId: QmsProtocol.hex(prepared.messageId),
          contactFingerprint: contact.fingerprint,
          nextCryptoState: QmsProtocol.hex(prepared.nextState),
          envelopeSize: envelope.length,
          carrierExtras: fragments.map(fragment => QmsProtocol.hex(QmsProtocol.carrierExtra(fragment))),
          encodedFragments: fragments.map(fragment => QmsProtocol.hex(QmsProtocol.encodeFragment(fragment)))
        };
      });
    }

    async function acceptFragment(encodedFragment, source = {}) {
      return serialized(async () => {
        requireActive();
        const fragment = QmsProtocol.decodeFragment(encodedFragment);
        let matched = null;
        for (const contact of state.contacts) {
          if (contact.removed) continue;
          try {
            const contexts = await QmsProtocol.signal.transportContexts(cryptoState(), contact.contactId, false);
            const context = contexts.find(candidate => QmsProtocol.verifyEnvelopeFragment(candidate, fragment));
            if (context) { matched = { contact, context }; break; }
          } catch (_) {}
        }
        if (!matched) return null;
        const messageId = QmsProtocol.hex(fragment.messageId);
        if (messages().some(item => item.id === messageId && item.direction === 'in')) return null;
        const hash = QmsProtocol.hex(fragment.ciphertextHash);
        let partial = state.reassembly.find(item => item.messageId === messageId && item.hash === hash && item.contactFingerprint === matched.contact.fingerprint);
        if (!partial) {
          if (state.reassembly.length >= MAX_REASSEMBLIES) throw new Error('QMS2 reassembly limit reached');
          partial = { messageId, hash, contactFingerprint: matched.contact.fingerprint, count: fragment.count, ciphertextSize: fragment.ciphertextSize, fragments: {}, bytes: 0 };
        }
        const staged = clone(partial);
        const index = String(fragment.index), encoded = QmsProtocol.hex(QmsProtocol.encodeFragment(fragment));
        if (staged.fragments[index]) {
          if (staged.fragments[index].encoded !== encoded) throw new Error('Conflicting QMS2 fragment duplicate');
          return null;
        }
        if (totalReassemblyBytes() + fragment.data.length > MAX_REASSEMBLY_BYTES) throw new Error('QMS2 reassembly byte limit reached');
        staged.fragments[index] = { encoded, txHash: source.txHash || '', blockHeight: Number(source.blockHeight || 0), blockHash: source.blockHash || '', createdAt: source.createdAt || nowIso() };
        staged.bytes += fragment.data.length;

        if (Object.keys(staged.fragments).length !== staged.count) {
          await commit(async () => {
            const position = state.reassembly.findIndex(item => item.messageId === messageId && item.hash === hash && item.contactFingerprint === matched.contact.fingerprint);
            if (position < 0) state.reassembly.push(staged); else state.reassembly[position] = staged;
          });
          return null;
        }

        const fragments = Array.from({ length: staged.count }, (_, part) => {
          if (!staged.fragments[String(part)]) throw new Error('Incomplete QMS2 fragment set');
          return QmsProtocol.decodeFragment(QmsProtocol.unhex(staged.fragments[String(part)].encoded));
        });
        const inner = QmsProtocol.openOuterEnvelope(matched.context, fragment.messageId, QmsProtocol.reassemble(fragments));
        if (inner.length < 2) throw new Error('Empty QMS2 inner ciphertext');
        const received = await QmsProtocol.signal.prepareReceiveText(cryptoState(), matched.contact.contactId, inner[0], inner.slice(1));
        if (!QmsProtocol.equal(received.messageId, fragment.messageId)) throw new Error('QMS2 message identifier mismatch');
        const record = { id: messageId, contactId: matched.contact.fingerprint, direction: 'in', text: received.text, createdAt: source.createdAt || nowIso(), status: 'confirmed', txHash: source.txHash || '', blockHeight: Number(source.blockHeight || 0), blockHash: source.blockHash || '' };
        await commit(async () => {
          state.cryptoState = QmsProtocol.hex(received.nextState);
          state.reassembly = state.reassembly.filter(item => !(item.messageId === messageId && item.hash === hash && item.contactFingerprint === matched.contact.fingerprint));
          if (state.historyEnabled) state.messages.push(record);
          else transientMessages.push(record);
        });
        return record;
      });
    }

    async function markReorg(removedBlockHashes) {
      const removed = new Set(removedBlockHashes || []);
      return serialized(() => commit(async () => {
        for (const message of messages()) if (message.direction === 'in' && removed.has(message.blockHash)) message.status = 'reorged';
        // Ratchet state intentionally never rolls back after authenticated plaintext.
      }));
    }
    function close() { store.close(); }
    return { state, activate, importContact, prepareOffline, acceptFragment, markReorg, messages, setHistoryEnabled, clearHistory, resetState, close };
  }

  async function mount(options) {
    const el = id => document.getElementById(id);
    const section = el('qms-section'), overviewTab = el('wallet-tab-overview'), messengerTab = el('wallet-tab-messenger');
    const dashboard = el('dashboard');
    const overviewNodes = Array.from(dashboard.children).filter(node => node !== section && node.id !== 'wallet-tabs' && !node.classList.contains('wallet-header'));
    const originalHidden = new Map(overviewNodes.map(node => [node, node.hidden]));
    const wallet = options.getWalletKeys();
    const qmsKey = typeof WalletVault !== 'undefined' && WalletVault.qmsKey ? WalletVault.qmsKey() : null;
    if (!qmsKey) {
      messengerTab.hidden = true;
      messengerTab.disabled = true;
      messengerTab.setAttribute('aria-hidden', 'true');
      section.hidden = true;
      return { scan: async () => false, clear: () => {}, client: null };
    }
    messengerTab.hidden = false;
    messengerTab.disabled = false;
    messengerTab.removeAttribute('aria-hidden');
    let renderCurrent = () => {};
    function status(message, kind) { const node = el('qms-status'); node.textContent = message || ''; node.className = 'qms-status' + (kind ? ' ' + kind : ''); }
    function error(value) { status(value && value.message ? value.message : String(value), 'error'); }
    function empty(message) { const node = document.createElement('div'); node.className = 'qms-empty'; node.textContent = message; return node; }
    function setTab(name) {
      const show = name === 'messenger'; section.hidden = !show;
      overviewNodes.forEach(node => { node.hidden = show ? true : originalHidden.get(node); });
      overviewTab.classList.toggle('active', !show); messengerTab.classList.toggle('active', show);
      overviewTab.setAttribute('aria-selected', String(!show)); messengerTab.setAttribute('aria-selected', String(show));
      if (show) renderCurrent();
    }
    overviewTab.addEventListener('click', () => setTab('overview'));
    messengerTab.addEventListener('click', () => setTab('messenger'));

    await QmsProtocol.ready();
    const store = await QmsStore.open(wallet, qmsKey);
    sodium.memzero(qmsKey);
    const client = makeClient(store), state = client.state;
    let selectedId = state.contacts.find(item => !item.removed)?.fingerprint || null;

    function render() {
      const activeContacts = state.contacts.filter(item => !item.removed);
      const activate = el('qms-activate');
      activate.hidden = state.active; activate.disabled = state.active; activate.title = '';
      el('qms-manage-toggle').disabled = false;
      el('qms-own-invitation').value = state.active ? state.ownPackage : '';
      el('qms-own-fingerprint').textContent = state.active ? `Fingerprint: ${state.ownFingerprint}` : 'Activate QMS2 to create an independent Messenger identity.';
      el('qms-copy-invitation').disabled = !state.active;
      el('qms-import-contact').disabled = !state.active;
      const contacts = el('qms-contact-list'); contacts.replaceChildren();
      if (!activeContacts.length) contacts.appendChild(empty(state.active ? 'No contacts yet' : 'Messenger is not activated'));
      for (const item of activeContacts) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'qms-contact' + (item.fingerprint === selectedId ? ' active' : '');
        const name = document.createElement('strong'); name.textContent = item.name;
        const fp = document.createElement('span'); fp.textContent = item.fingerprint.slice(0, 16) + '…';
        button.append(name, fp); button.addEventListener('click', () => { selectedId = item.fingerprint; render(); }); contacts.appendChild(button);
      }
      const selected = activeContacts.find(item => item.fingerprint === selectedId) || null;
      el('qms-chat-name').textContent = selected ? selected.name : 'Select a contact';
      el('qms-chat-fingerprint').textContent = selected ? selected.fingerprint : '';
      const messages = el('qms-message-list'); messages.replaceChildren();
      const rows = client.messages().filter(item => item.contactId === selectedId);
      if (!rows.length) messages.appendChild(empty(selected ? 'No messages in this chat.' : 'Import a personal invitation to begin.'));
      for (const item of rows) {
        const row = document.createElement('div'); row.className = 'qms-message ' + (item.direction === 'out' ? 'me' : 'them');
        const bubble = document.createElement('div'); bubble.className = 'qms-bubble';
        const text = document.createElement('div'); text.textContent = item.text;
        const meta = document.createElement('div'); meta.className = 'qms-bubble-meta'; meta.textContent = `${item.direction === 'out' ? 'Me' : selected.name} · ${item.status}`;
        bubble.append(text, meta); row.appendChild(bubble); messages.appendChild(row);
      }
      const manage = el('qms-manage-list'); manage.replaceChildren();
      for (const item of activeContacts) { const row = document.createElement('div'); row.className = 'qms-manage-row'; const label = document.createElement('span'); label.textContent = `${item.name} · ${item.fingerprint}`; row.append(label); manage.append(row); }
      el('qms-history-enabled').checked = state.historyEnabled;
      el('qms-history-enabled').disabled = false; el('qms-clear-history').disabled = false; el('qms-reset-state').disabled = false;
      const bytes = new TextEncoder().encode(el('qms-message-input').value).length;
      el('qms-byte-count').textContent = `${bytes.toLocaleString()} / 4,096 UTF-8 bytes`;
      el('qms-message-input').disabled = true; el('qms-prepare').disabled = true; el('qms-send').disabled = true; el('qms-cancel').disabled = true;
      el('qms-review').hidden = true;
      status('QMS2 crypto and encrypted contacts are available offline. Sending and chain sync are blocked in a normal browser because it cannot prove Tor-only routing without direct fallback.', 'error');
    }
    renderCurrent = render;
    el('qms-activate').addEventListener('click', async () => { try { el('qms-activate').disabled = true; await client.activate(); render(); } catch (cause) { error(cause); el('qms-activate').disabled = false; } });
    el('qms-copy-invitation').addEventListener('click', async () => { try { await navigator.clipboard.writeText(state.ownPackage); status('Complete QMS2 contact package copied.', 'ok'); } catch (cause) { error(cause); } });
    el('qms-import-contact').addEventListener('click', async () => { try { const fingerprint = await client.importContact(el('qms-contact-name').value, el('qms-contact-invitation').value); selectedId = fingerprint; el('qms-contact-name').value = ''; el('qms-contact-invitation').value = ''; render(); status(`Contact imported. Confirm fingerprint ${fingerprint}`, 'ok'); } catch (cause) { error(cause); } });
    el('qms-history-enabled').addEventListener('change', async event => { try { await client.setHistoryEnabled(event.target.checked); render(); status(event.target.checked ? 'Encrypted local message-history persistence enabled.' : 'Message-history persistence disabled. Existing stored history is retained until deleted.', 'ok'); } catch (cause) { event.target.checked = state.historyEnabled; error(cause); } });
    el('qms-clear-history').addEventListener('click', async () => { try { await client.clearHistory(); render(); status('Local Messenger history deleted. Blockchain carrier data is unchanged.', 'ok'); } catch (cause) { error(cause); } });
    el('qms-reset-state').addEventListener('click', async () => { try { if (!window.confirm('Delete the local Messenger identity, contacts, sessions, history, and prepared plan? Blockchain carrier data is unchanged.')) return; await client.resetState(); selectedId = null; render(); status('Messenger state reset. Activate again and exchange fresh contact packages before sending.', 'ok'); } catch (cause) { error(cause); } });
    el('qms-manage-toggle').addEventListener('click', () => { el('qms-chat-view').hidden = true; el('qms-manage-view').hidden = false; });
    el('qms-manage-back').addEventListener('click', () => { el('qms-manage-view').hidden = true; el('qms-chat-view').hidden = false; });
    el('qms-message-input').addEventListener('input', render);
    render();
    return { scan: async () => false, clear: () => client.close(), client };
  }

  async function commitPreparedStateForTesting(store, plan) {
    if (!store || !store.state || !plan || !/^[0-9a-f]+$/i.test(plan.nextCryptoState || '')) throw new Error('invalid synthetic QMS2 plan');
    store.state.cryptoState = plan.nextCryptoState;
    await store.save();
  }

  return { mount, makeClient, testing: { makeClient, commitPreparedStateForTesting } };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsMessenger;
