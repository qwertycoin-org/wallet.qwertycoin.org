// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Password-wrapped, authenticated QMS1/Fast browser state. */
const QmsStore = (() => {
  'use strict';

  const PREFIX = 'qwc-qms1-fast-store:';
  const LOCK_PREFIX = 'qwc-qms1-fast-writer:';
  const DATABASE_NAME = 'qwc-qms1-fast';
  const DATABASE_VERSION = 1;
  const OBJECT_STORE = 'records';
  const RECORD_SCHEMA = 3;
  const BACKUP_VERSION = 1;
  const BACKUP_MAX_BYTES = 16 * 1024 * 1024;
  const BACKUP_OPSLIMIT = 3;
  const BACKUP_MEMLIMIT = 64 * 1024 * 1024;
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });
  const localLocks = new Set();
  const memoryRecords = new Map();
  let nextMemoryWriteError = null;
  let lastMemoryWriteCount = 0;
  let databasePromise = null;

  function sodiumApi() {
    if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded');
    return sodium;
  }
  function b64(input) { return sodiumApi().to_base64(input, sodiumApi().base64_variants.ORIGINAL); }
  function unb64(value) { return sodiumApi().from_base64(String(value), sodiumApi().base64_variants.ORIGINAL); }
  function associatedData(storageKey, purpose) {
    return te.encode(`QWC-QMS1-FAST-WEB-STORE\u0000${purpose}\u0000${storageKey}`);
  }
  function recordAssociatedData(storageKey, network, type, id) {
    return associatedData(storageKey, `record\u0000${RECORD_SCHEMA}\u0000${network}\u0000${type}\u0000${id}`);
  }
  async function walletId(address) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(String(address))));
    return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function blank() {
    return {
      version: 1,
      identity: null,
      ownInvitation: null,
      contacts: [],
      messages: [],
      plans: [],
      reassembly: [],
      unmatched: [],
      scan: { height: 0, blockHash: '', startHeight: null, checkpoints: [] }
    };
  }
  function validateState(state) {
    if (!state || state.version !== 1 || !Array.isArray(state.contacts)
        || !Array.isArray(state.messages) || !Array.isArray(state.plans)
        || !Array.isArray(state.reassembly) || !Array.isArray(state.unmatched || []) || !state.scan) {
      throw new Error('invalid encrypted QMS1/Fast store');
    }
    return state;
  }
  function cloneState(state) { return JSON.parse(JSON.stringify(validateState(state))); }
  function requireKey(value, label) {
    const key = value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value || []);
    if (key.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
    return key;
  }
  function normalizeKdf(value) {
    if (!value) return null;
    if (value.name !== 'argon2id13'
        || !Number.isInteger(value.opslimit) || value.opslimit < 1 || value.opslimit > 4
        || !Number.isInteger(value.memlimit) || value.memlimit < 8 * 1024 * 1024 || value.memlimit > 128 * 1024 * 1024
        || typeof value.salt !== 'string') throw new Error('Invalid QMS1/Fast KDF metadata');
    let salt;
    try { salt = unb64(value.salt); } catch (_) { throw new Error('Invalid QMS1/Fast KDF salt'); }
    if (salt.length !== 16) throw new Error('Invalid QMS1/Fast KDF salt');
    return { name: 'argon2id13', opslimit: value.opslimit, memlimit: value.memlimit, salt: value.salt };
  }
  function sameKdf(left, right) {
    return !!left === !!right && (!left || (left.name === right.name
      && left.opslimit === right.opslimit && left.memlimit === right.memlimit
      && left.salt === right.salt));
  }
  function encrypt(key, nonce, plaintext, additionalData) {
    return sodiumApi().crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext, additionalData, null, nonce, key);
  }
  function decrypt(key, nonce, ciphertext, additionalData, label) {
    try {
      return sodiumApi().crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ciphertext, additionalData, nonce, key);
    } catch (_) {
      throw new Error(`Unable to decrypt this wallet's ${label}`);
    }
  }
  function hex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
  async function backupIdentityId(state) {
    if (!state.identity || !/^[0-9a-f]{64}$/i.test(state.identity.boxPublic || '')
        || !/^[0-9a-f]{64}$/i.test(state.identity.signPublic || '')) {
      throw new Error('Messenger backup identity is invalid');
    }
    const digest = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', te.encode(`${state.identity.boxPublic.toLowerCase()}:${state.identity.signPublic.toLowerCase()}`)));
    return hex(digest);
  }
  function backupHeaderAad(envelope) {
    return te.encode([
      'QWC-QMS1-FAST-BACKUP', envelope.version, envelope.profile, envelope.network,
      envelope.walletId, envelope.kdf.name, envelope.kdf.opslimit,
      envelope.kdf.memlimit, envelope.kdf.salt
    ].join('\u0000'));
  }
  async function deriveBackupKey(password, kdf) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
      throw new Error('Messenger backup password must contain 12 to 1,024 characters');
    }
    const normalized = normalizeKdf(kdf);
    if (!normalized || normalized.opslimit < 2 || normalized.memlimit < 32 * 1024 * 1024) {
      throw new Error('Messenger backup KDF parameters are too weak');
    }
    if (typeof QmsKdf === 'undefined') throw new Error('Messenger backup KDF is unavailable');
    return requireKey(await QmsKdf.derive(
      password, unb64(normalized.salt), normalized.opslimit, normalized.memlimit, 32),
    'Messenger backup key');
  }
  function validateBackupState(value) {
    const state = cloneState(value);
    if (!state.identity || !/^[0-9a-f]{64}$/i.test(state.identity.boxPublic || '')
        || !/^[0-9a-f]{64}$/i.test(state.identity.boxSecret || '')
        || !/^[0-9a-f]{64}$/i.test(state.identity.signPublic || '')
        || !/^[0-9a-f]{128}$/i.test(state.identity.signSecret || '')
        || typeof state.ownInvitation !== 'string' || state.ownInvitation.length > 2048
        || state.contacts.length > 1000 || state.messages.length > 10000
        || state.plans.length > 128 || state.reassembly.length > 64
        || (state.unmatched || []).length > 32) {
      throw new Error('Messenger backup exceeds supported identity or resource limits');
    }
    return state;
  }
  function lockImportedOutbox(state) {
    const unsafe = new Set(['building', 'prepared', 'broadcasting', 'broadcast_unknown', 'recovery_required']);
    for (const plan of state.plans) {
      if (!unsafe.has(plan.status) && !(plan.txs || []).some(tx => unsafe.has(tx.status))) continue;
      plan.status = 'recovery_required';
      plan.recoveryError = 'Imported transaction journal requires wallet recovery before any relay or input release';
      plan.importedRecovery = true;
      for (const tx of plan.txs || []) {
        if (!['broadcast', 'confirmed'].includes(tx.status)) tx.status = 'recovery_required';
      }
      const message = state.messages.find(item => item.id === plan.id && item.direction === 'out');
      if (message) message.status = 'recovery_required';
    }
    return state;
  }

  function requestResult(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
    });
  }
  function openDatabase() {
    if (databasePromise) return databasePromise;
    if (typeof indexedDB === 'undefined') {
      if (typeof QMS_TEST_MEMORY_STORAGE !== 'undefined' && QMS_TEST_MEMORY_STORAGE === true) return null;
      throw new Error('Encrypted Messenger storage requires IndexedDB');
    }
    databasePromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(OBJECT_STORE)) db.createObjectStore(OBJECT_STORE, { keyPath: 'key' });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('Unable to open encrypted Messenger storage'));
      request.onblocked = () => reject(new Error('Messenger storage upgrade is blocked by another tab'));
    });
    return databasePromise;
  }
  function recordPrefix(storageKey) { return `${storageKey}\u0000`; }
  function idbRange(storageKey) {
    const prefix = recordPrefix(storageKey);
    return IDBKeyRange.bound(prefix, `${prefix}\uffff`);
  }
  async function loadRecords(storageKey) {
    const db = openDatabase();
    if (!db) {
      const prefix = recordPrefix(storageKey);
      return Array.from(memoryRecords.entries())
        .filter(([key]) => key.startsWith(prefix))
        .map(([, record]) => JSON.parse(JSON.stringify(record)));
    }
    const resolved = await db;
    const tx = resolved.transaction(OBJECT_STORE, 'readonly');
    const rows = await requestResult(tx.objectStore(OBJECT_STORE).getAll(idbRange(storageKey)));
    return rows.map(row => row.record);
  }
  async function replaceRecords(storageKey, records) {
    const db = openDatabase();
    if (!db) {
      if (nextMemoryWriteError) {
        const error = nextMemoryWriteError;
        nextMemoryWriteError = null;
        throw error;
      }
      const replacement = new Map(memoryRecords);
      const prefix = recordPrefix(storageKey);
      const desired = new Map(records.map(record => [prefix + record.key, JSON.parse(JSON.stringify(record))]));
      let changed = 0;
      for (const key of replacement.keys()) {
        if (!key.startsWith(prefix)) continue;
        if (!desired.has(key)) { replacement.delete(key); changed += 1; continue; }
        const next = desired.get(key);
        if (JSON.stringify(replacement.get(key)) !== JSON.stringify(next)) {
          replacement.set(key, next);
          changed += 1;
        }
        desired.delete(key);
      }
      desired.forEach((record, key) => { replacement.set(key, record); changed += 1; });
      memoryRecords.clear();
      replacement.forEach((value, key) => memoryRecords.set(key, value));
      lastMemoryWriteCount = changed;
      return changed;
    }
    const resolved = await db;
    await new Promise((resolve, reject) => {
      const tx = resolved.transaction(OBJECT_STORE, 'readwrite');
      const objectStore = tx.objectStore(OBJECT_STORE);
      const prefix = recordPrefix(storageKey);
      const desired = new Map(records.map(record => [prefix + record.key, record]));
      const cursor = objectStore.openCursor(idbRange(storageKey));
      cursor.onerror = () => { try { tx.abort(); } catch (_) {} };
      cursor.onsuccess = () => {
        const current = cursor.result;
        if (current) {
          const next = desired.get(current.key);
          if (!next) current.delete();
          else {
            if (JSON.stringify(current.value.record) !== JSON.stringify(next)) current.update({ key: current.key, record: next });
            desired.delete(current.key);
          }
          current.continue();
          return;
        }
        desired.forEach((record, key) => objectStore.put({ key, record }));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error('Unable to persist encrypted Messenger state'));
      tx.onabort = () => reject(tx.error || new Error('Unable to persist encrypted Messenger state'));
    });
  }

  function locator(kdf) {
    const value = { version: RECORD_SCHEMA, profile: 'qms1-fast', backend: 'indexeddb' };
    if (kdf) value.kdf = kdf;
    return JSON.stringify(value);
  }
  function persistLocator(storageKey, kdf) {
    try { localStorage.setItem(storageKey, locator(kdf)); } catch (_) {
      // IndexedDB remains authoritative if Web Storage is unavailable.
    }
  }

  function decodeLegacyEnvelope(storageKey, envelope, wrappingKey, suppliedKdf) {
    if (envelope.version !== 2 || envelope.profile !== 'qms1-fast'
        || envelope.cipher !== 'xchacha20poly1305-ietf') {
      throw new Error('Unsupported QMS1/Fast store version');
    }
    const persistedKdf = normalizeKdf(envelope.kdf);
    if (persistedKdf && !sameKdf(persistedKdf, suppliedKdf)) {
      throw new Error('QMS1/Fast Session password metadata does not match this wallet store');
    }
    const dataKey = requireKey(decrypt(
      wrappingKey, unb64(envelope.wrapNonce), unb64(envelope.wrappedKey),
      associatedData(storageKey, 'data-key'), 'Messenger key'), 'QMS1/Fast data key');
    const plaintext = decrypt(
      dataKey, unb64(envelope.stateNonce), unb64(envelope.ciphertext),
      associatedData(storageKey, 'state'), 'Messenger store');
    try {
      return { state: cloneState(JSON.parse(td.decode(plaintext))), dataKey, revision: 0 };
    } catch (error) {
      sodiumApi().memzero(dataKey);
      throw error;
    } finally {
      sodiumApi().memzero(plaintext);
    }
  }

  function encryptedRecord(storageKey, network, type, id, order, value, dataKey, recordCache, nextCache) {
    const key = `${type}\u0000${id}`;
    const serialized = JSON.stringify(value);
    const cached = recordCache && recordCache.get(key);
    if (cached && cached.serialized === serialized && cached.record.order === order) {
      nextCache.set(key, cached);
      return cached.record;
    }
    const plaintext = te.encode(serialized);
    const nonce = sodiumApi().randombytes_buf(24);
    try {
      const record = {
        key,
        schema: RECORD_SCHEMA,
        type,
        id,
        order,
        nonce: b64(nonce),
        ciphertext: b64(encrypt(dataKey, nonce, plaintext, recordAssociatedData(storageKey, network, type, id)))
      };
      nextCache.set(key, { serialized, record });
      return record;
    } finally {
      sodiumApi().memzero(plaintext);
    }
  }
  function buildRecordSet(storageKey, network, snapshot, revision, wrappingKey, dataKey, kdf, recordCache = new Map()) {
    const state = cloneState(snapshot);
    const wrapNonce = sodiumApi().randombytes_buf(24);
    const meta = {
      key: 'meta',
      version: RECORD_SCHEMA,
      profile: 'qms1-fast',
      network,
      cipher: 'xchacha20poly1305-ietf',
      revision,
      wrapNonce: b64(wrapNonce),
      wrappedKey: b64(encrypt(wrappingKey, wrapNonce, dataKey, associatedData(storageKey, `data-key\u0000${network}`)))
    };
    if (kdf) meta.kdf = kdf;
    const records = [meta], nextCache = new Map();
    if (state.identity !== null) records.push(encryptedRecord(storageKey, network, 'identity', 'identity', 0, state.identity, dataKey, recordCache, nextCache));
    if (state.ownInvitation !== null) records.push(encryptedRecord(storageKey, network, 'invitation', 'own', 0, state.ownInvitation, dataKey, recordCache, nextCache));
    for (const [type, values] of [
      ['contact', state.contacts], ['message', state.messages], ['plan', state.plans],
      ['reassembly', state.reassembly], ['unmatched', state.unmatched || []]
    ]) values.forEach((value, index) => records.push(encryptedRecord(
      storageKey, network, type, String(index).padStart(10, '0'), index, value, dataKey, recordCache, nextCache)));
    records.push(encryptedRecord(storageKey, network, 'scan', 'scan', 0, state.scan, dataKey, recordCache, nextCache));
    return { records, cache: nextCache };
  }
  function decodeRecordSet(storageKey, network, records, wrappingKey, suppliedKdf) {
    const metaRecords = records.filter(record => record && record.key === 'meta');
    if (metaRecords.length !== 1) throw new Error('Invalid encrypted QMS1/Fast record metadata');
    const meta = metaRecords[0];
    if (meta.version !== RECORD_SCHEMA || meta.profile !== 'qms1-fast'
        || meta.cipher !== 'xchacha20poly1305-ietf' || meta.network !== network
        || !Number.isSafeInteger(meta.revision) || meta.revision < 0) {
      throw new Error('Unsupported QMS1/Fast record store version');
    }
    const persistedKdf = normalizeKdf(meta.kdf);
    const pendingKdf = meta.pendingWrap ? normalizeKdf(meta.pendingWrap.kdf) : null;
    const usePending = !!(meta.pendingWrap && sameKdf(pendingKdf, suppliedKdf));
    if (!usePending && persistedKdf && !sameKdf(persistedKdf, suppliedKdf)) {
      throw new Error('QMS1/Fast Session password metadata does not match this wallet store');
    }
    const wrap = usePending ? meta.pendingWrap : meta;
    const dataKey = requireKey(decrypt(
      wrappingKey, unb64(wrap.wrapNonce), unb64(wrap.wrappedKey),
      associatedData(storageKey, usePending ? `data-key\u0000${network}\u0000pending` : `data-key\u0000${network}`),
      'Messenger key'), 'QMS1/Fast data key');
    const state = blank();
    const arrays = { contact: [], message: [], plan: [], reassembly: [], unmatched: [] };
    const seen = new Set(), recordCache = new Map();
    try {
      for (const record of records) {
        if (record === meta) continue;
        if (!record || record.schema !== RECORD_SCHEMA || typeof record.type !== 'string'
            || typeof record.id !== 'string' || !Number.isSafeInteger(record.order) || record.order < 0) {
          throw new Error('Invalid encrypted QMS1/Fast record');
        }
        const unique = `${record.type}\u0000${record.id}`;
        if (seen.has(unique)) throw new Error('Duplicate encrypted QMS1/Fast record');
        seen.add(unique);
        const plaintext = decrypt(
          dataKey, unb64(record.nonce), unb64(record.ciphertext),
          recordAssociatedData(storageKey, network, record.type, record.id), 'Messenger record');
        let value;
        try { value = JSON.parse(td.decode(plaintext)); } finally { sodiumApi().memzero(plaintext); }
        recordCache.set(unique, { serialized: JSON.stringify(value), record });
        if (record.type === 'identity' && record.id === 'identity') state.identity = value;
        else if (record.type === 'invitation' && record.id === 'own') state.ownInvitation = value;
        else if (record.type === 'scan' && record.id === 'scan') state.scan = value;
        else if (arrays[record.type]) arrays[record.type].push({ order: record.order, value });
        else throw new Error('Unsupported encrypted QMS1/Fast record type');
      }
      for (const [type, property] of [['contact', 'contacts'], ['message', 'messages'], ['plan', 'plans'], ['reassembly', 'reassembly'], ['unmatched', 'unmatched']]) {
        state[property] = arrays[type].sort((left, right) => left.order - right.order).map(entry => entry.value);
      }
      return { state: cloneState(state), dataKey, revision: meta.revision, recordCache, openedPending: usePending };
    } catch (error) {
      sodiumApi().memzero(dataKey);
      throw error;
    }
  }

  async function acquireWriterLock(storageKey) {
    const lockName = LOCK_PREFIX + storageKey.slice(PREFIX.length);
    if (typeof navigator !== 'undefined') {
      if (!navigator.locks || typeof navigator.locks.request !== 'function') {
        throw new Error('This browser cannot safely coordinate Messenger storage across tabs');
      }
      let settleAcquired;
      let releaseLock;
      const acquired = new Promise(resolve => { settleAcquired = resolve; });
      const request = navigator.locks.request(
        lockName,
        { mode: 'exclusive', ifAvailable: true },
        lock => {
          if (!lock) { settleAcquired(false); return undefined; }
          settleAcquired(true);
          return new Promise(resolve => { releaseLock = resolve; });
        }
      ).catch(error => { settleAcquired(error); throw error; });
      const acquisition = await acquired;
      if (acquisition instanceof Error) throw acquisition;
      if (!acquisition) {
        await request;
        throw new Error('Messenger is already open for this wallet in another tab');
      }
      let released = false;
      return {
        release() { if (!released) { released = true; releaseLock(); } },
        done: request.catch(() => {})
      };
    }
    if (localLocks.has(lockName)) throw new Error('Messenger is already open for this wallet in another tab');
    localLocks.add(lockName);
    let released = false;
    return {
      release() { if (!released) { released = true; localLocks.delete(lockName); } },
      done: Promise.resolve()
    };
  }

  async function open(wallet, unlockKey, kdfMetadata) {
    await sodiumApi().ready;
    if (!wallet || !wallet.address || !wallet.privateSpendKeyHex) {
      throw new Error('QMS1/Fast requires an unlocked full wallet');
    }
    let wrappingKey = requireKey(unlockKey, 'QMS1/Fast session key');
    let kdf = normalizeKdf(kdfMetadata);
    const network = String(wallet.network || 'mainnet');
    if (!/^[a-z0-9_-]{1,32}$/i.test(network)) throw new Error('Invalid QMS1/Fast wallet network');
    const storageKey = PREFIX + await walletId(wallet.address);
    const writerLock = await acquireWriterLock(storageKey);
    let dataKey;
    let state = blank();
    let revision = 0;
    let recordCache = new Map();
    let openedPending = false;
    try {
      const records = await loadRecords(storageKey);
      if (records.length) {
        ({ state, dataKey, revision, recordCache, openedPending } = decodeRecordSet(storageKey, network, records, wrappingKey, kdf));
        if (openedPending) {
          const finalized = buildRecordSet(storageKey, network, state, revision + 1, wrappingKey, dataKey, kdf, recordCache);
          await replaceRecords(storageKey, finalized.records);
          recordCache = finalized.cache;
          revision += 1;
          persistLocator(storageKey, kdf);
        }
      } else {
        let envelope = null;
        try { envelope = JSON.parse(localStorage.getItem(storageKey) || 'null'); }
        catch (_) { throw new Error('Invalid QMS1/Fast store envelope'); }
        if (envelope && envelope.version === 2) {
          ({ state, dataKey, revision } = decodeLegacyEnvelope(storageKey, envelope, wrappingKey, kdf));
          const migrated = buildRecordSet(storageKey, network, state, revision + 1, wrappingKey, dataKey, kdf, recordCache);
          await replaceRecords(storageKey, migrated.records);
          recordCache = migrated.cache;
          revision += 1;
          persistLocator(storageKey, kdf);
        } else if (envelope && envelope.version === RECORD_SCHEMA) {
          throw new Error('Encrypted Messenger records are missing from IndexedDB');
        } else if (envelope) {
          throw new Error('Unsupported QMS1/Fast store version');
        } else {
          dataKey = sodiumApi().randombytes_buf(32);
        }
      }
    } catch (error) {
      sodiumApi().memzero(wrappingKey);
      if (dataKey) sodiumApi().memzero(dataKey);
      writerLock.release();
      throw error;
    }

    let saveQueue = Promise.resolve();
    let closed = false;
    let closePromise = null;
    function ensureOpen() { if (closed) throw new Error('QMS1/Fast store is closed'); }
    function prepare(snapshot, nextRevision) {
      return buildRecordSet(storageKey, network, snapshot, nextRevision, wrappingKey, dataKey, kdf, recordCache);
    }
    function save() {
      ensureOpen();
      const candidate = cloneState(state);
      const prepared = prepare(candidate, 0);
      const pending = saveQueue.then(async () => {
        prepared.records[0].revision = revision + 1;
        await replaceRecords(storageKey, prepared.records);
        recordCache = prepared.cache;
        revision += 1;
        persistLocator(storageKey, kdf);
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    function snapshot() {
      ensureOpen();
      return { revision, state: cloneState(state) };
    }
    function commit(nextState, expectedRevision) {
      ensureOpen();
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new Error('Invalid QMS1/Fast store revision');
      const candidate = cloneState(nextState);
      const prepared = prepare(candidate, expectedRevision + 1);
      const pending = saveQueue.then(async () => {
        if (revision !== expectedRevision) throw new Error('QMS1/Fast store changed while the scan batch was in progress');
        await replaceRecords(storageKey, prepared.records);
        state = candidate;
        recordCache = prepared.cache;
        revision += 1;
        persistLocator(storageKey, kdf);
        return state;
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    function close() {
      if (closePromise) return closePromise;
      closed = true;
      closePromise = saveQueue.finally(() => {
        sodiumApi().memzero(dataKey);
        sodiumApi().memzero(wrappingKey);
        writerLock.release();
      });
      return closePromise;
    }
    async function exportBackup(password) {
      ensureOpen();
      const exportedState = validateBackupState(state);
      const salt = sodiumApi().randombytes_buf(16);
      const nonce = sodiumApi().randombytes_buf(24);
      const kdf = {
        name: 'argon2id13',
        opslimit: BACKUP_OPSLIMIT,
        memlimit: BACKUP_MEMLIMIT,
        salt: b64(salt)
      };
      const envelope = {
        type: 'qwc-qms1-fast-backup',
        version: BACKUP_VERSION,
        profile: 'qms1-fast',
        network,
        walletId: storageKey.slice(PREFIX.length),
        kdf,
        nonce: b64(nonce)
      };
      const payload = {
        version: BACKUP_VERSION,
        exportedAt: new Date().toISOString(),
        identityId: await backupIdentityId(exportedState),
        state: exportedState
      };
      const plaintext = te.encode(JSON.stringify(payload));
      if (plaintext.length > BACKUP_MAX_BYTES) throw new Error('Messenger backup exceeds the 16 MiB size limit');
      const backupKey = await deriveBackupKey(password, kdf);
      try {
        envelope.ciphertext = b64(encrypt(backupKey, nonce, plaintext, backupHeaderAad(envelope)));
        return JSON.stringify(envelope);
      } finally {
        sodiumApi().memzero(plaintext);
        sodiumApi().memzero(backupKey);
      }
    }
    async function importBackup(serialized, password) {
      ensureOpen();
      if (typeof serialized !== 'string' || te.encode(serialized).length > BACKUP_MAX_BYTES) {
        throw new Error('Messenger backup is empty or exceeds the 16 MiB size limit');
      }
      let envelope;
      try { envelope = JSON.parse(serialized); }
      catch (_) { throw new Error('Messenger backup is not valid JSON'); }
      if (!envelope || envelope.type !== 'qwc-qms1-fast-backup'
          || envelope.version !== BACKUP_VERSION || envelope.profile !== 'qms1-fast'
          || envelope.network !== network || envelope.walletId !== storageKey.slice(PREFIX.length)
          || typeof envelope.nonce !== 'string' || typeof envelope.ciphertext !== 'string') {
        throw new Error('Messenger backup does not belong to this wallet and network');
      }
      const backupKey = await deriveBackupKey(password, envelope.kdf);
      let plaintext;
      try {
        plaintext = decrypt(
          backupKey, unb64(envelope.nonce), unb64(envelope.ciphertext),
          backupHeaderAad(envelope), 'Messenger backup');
      } finally {
        sodiumApi().memzero(backupKey);
      }
      let payload;
      try { payload = JSON.parse(td.decode(plaintext)); }
      catch (_) { throw new Error('Messenger backup payload is invalid'); }
      finally { sodiumApi().memzero(plaintext); }
      if (!payload || payload.version !== BACKUP_VERSION) throw new Error('Unsupported Messenger backup payload');
      const candidate = lockImportedOutbox(validateBackupState(payload.state));
      if (payload.identityId !== await backupIdentityId(candidate)) throw new Error('Messenger backup identity check failed');
      const currentRevision = revision;
      await commit(candidate, currentRevision);
      return state;
    }
    function changeWrappingKey(nextUnlockKey, nextKdfMetadata, updateVault) {
      ensureOpen();
      if (typeof updateVault !== 'function') throw new Error('Session password update callback is required');
      const nextKey = requireKey(nextUnlockKey, 'new QMS1/Fast session key');
      const nextKdf = normalizeKdf(nextKdfMetadata);
      if (!nextKdf) { sodiumApi().memzero(nextKey); throw new Error('New QMS1/Fast KDF metadata is required'); }
      const candidate = cloneState(state);
      const operation = saveQueue.then(async () => {
        const staged = buildRecordSet(storageKey, network, candidate, revision + 1, wrappingKey, dataKey, kdf, recordCache);
        const pendingNonce = sodiumApi().randombytes_buf(24);
        staged.records[0].pendingWrap = {
          kdf: nextKdf,
          wrapNonce: b64(pendingNonce),
          wrappedKey: b64(encrypt(
            nextKey, pendingNonce, dataKey,
            associatedData(storageKey, `data-key\u0000${network}\u0000pending`)))
        };
        await replaceRecords(storageKey, staged.records);
        recordCache = staged.cache;
        revision += 1;
        try {
          await updateVault();
        } catch (error) {
          const rollback = buildRecordSet(storageKey, network, candidate, revision + 1, wrappingKey, dataKey, kdf, recordCache);
          await replaceRecords(storageKey, rollback.records);
          recordCache = rollback.cache;
          revision += 1;
          persistLocator(storageKey, kdf);
          sodiumApi().memzero(nextKey);
          throw error;
        }

        const oldKey = wrappingKey;
        wrappingKey = nextKey;
        kdf = nextKdf;
        sodiumApi().memzero(oldKey);
        persistLocator(storageKey, kdf);
        const finalized = buildRecordSet(storageKey, network, candidate, revision + 1, wrappingKey, dataKey, kdf, recordCache);
        try {
          await replaceRecords(storageKey, finalized.records);
          recordCache = finalized.cache;
          revision += 1;
          return { cleanupPending: false };
        } catch (_) {
          // The staged record contains both wraps. The new Session can open it
          // and finalizes the pending wrap before exposing Messenger state.
          return { cleanupPending: true };
        }
      });
      const pending = operation.catch(error => {
        if (wrappingKey !== nextKey) sodiumApi().memzero(nextKey);
        throw error;
      });
      saveQueue = pending.catch(() => {});
      return pending;
    }
    return {
      get state() { ensureOpen(); return state; },
      save, snapshot, commit, exportBackup, importBackup, changeWrappingKey, close, storageKey
    };
  }

  const testing = {
    failNextWrite(error) { nextMemoryWriteError = error; },
    lastWriteCount() { return lastMemoryWriteCount; },
    dump(storageKey) {
      const prefix = recordPrefix(storageKey);
      return JSON.stringify(Array.from(memoryRecords.entries()).filter(([key]) => key.startsWith(prefix)));
    },
    clear() { memoryRecords.clear(); nextMemoryWriteError = null; lastMemoryWriteCount = 0; }
  };

  return { open, blank, validateState, testing };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsStore;
