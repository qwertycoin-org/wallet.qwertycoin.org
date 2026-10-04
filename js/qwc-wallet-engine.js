// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const QwcWalletEngine = (() => {
  const MAINNET = 0;
  const WORKER_PATH = "/vendor/qwertycoin-ts/qwertycoin.worker.js?v=d8121227e81fe7d0";
  const REQUEST_TIMEOUT_MS = 180000;
  const DAEMON_CHUNK_BYTES = 3000000;
  const MAX_MEMPOOL_TX_REQUEST = 128;
  let worker;
  let sequence = 0;
  const callbacks = new Map();

  function newId(prefix) {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return `${prefix}-${crypto.randomUUID()}`;
    }
    sequence += 1;
    return `${prefix}-${Date.now()}-${sequence}`;
  }

  function getWorker() {
    if (worker) return worker;
    worker = new Worker(WORKER_PATH);
    worker.onmessage = event => {
      const callbackId = event.data && event.data[1];
      const payload = event.data && event.data[2];
      const callback = callbacks.get(callbackId);
      if (!callback) return;
      callbacks.delete(callbackId);
      clearTimeout(callback.timeout);

      if (payload && payload.error) {
        callback.reject(new Error(`${callback.method}: ${payload.error.message || "QWC wallet worker error"}`));
        return;
      }
      callback.resolve(payload ? payload.result : undefined);
    };
    worker.onerror = event => {
      const error = new Error(event.message || "QWC wallet worker failed");
      for (const callback of callbacks.values()) {
        clearTimeout(callback.timeout);
        callback.reject(error);
      }
      callbacks.clear();
    };
    return worker;
  }

  function invoke(objectId, method, args) {
    const callbackId = newId("callback");
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        callbacks.delete(callbackId);
        reject(new Error(`QWC wallet worker timed out while running ${method}`));
      }, REQUEST_TIMEOUT_MS);

      callbacks.set(callbackId, { resolve, reject, timeout, method });
      try {
        getWorker().postMessage([objectId, method, callbackId].concat(args || []));
      } catch (error) {
        callbacks.delete(callbackId);
        clearTimeout(timeout);
        reject(error);
      }
    });
  }

  async function closeWallet(walletId) {
    try {
      await invoke(walletId, "close", [false]);
    } catch (error) {
      // Closing is best effort for this in-memory beta workbench.
    }
  }

  function getDefaultDaemonUri() {
    if (typeof location !== "undefined" && location.origin) return location.origin;
    return "https://wallet.qwertycoin.org";
  }

  function normalizeTxConfig(config) {
    return Object.assign({
      accountIndex: 0,
      relay: false,
      canSplit: false
    }, config || {});
  }

  function getDefaultServerConfig() {
    return { uri: getDefaultDaemonUri() };
  }

  function parseJonResponse(bytes) {
    const source = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || 0);
    let json = "";
    let inString = false;
    for (let index = 0; index < source.length; index++) {
      const byte = source[index];
      if (!inString) {
        json += String.fromCharCode(byte);
        if (byte === 0x22) inString = true;
        continue;
      }
      if (byte === 0x22) {
        json += '"';
        inString = false;
        continue;
      }
      if (byte === 0x5c) {
        if (++index >= source.length) throw new Error("QWC daemon returned truncated JON data");
        const escaped = source[index];
        json += escaped === 0x76 ? "\\u000b" : `\\${String.fromCharCode(escaped)}`;
        continue;
      }
      json += byte < 0x20
        ? `\\u${byte.toString(16).padStart(4, "0")}`
        : String.fromCharCode(byte);
    }
    if (inString) throw new Error("QWC daemon returned truncated JON data");
    return JSON.parse(json);
  }

  async function postDaemonPath(path, payload, parseBinaryStrings = false) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(`${getDefaultDaemonUri()}/api/proxy?path=${encodeURIComponent(path)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
        signal: controller.signal
      });
      if (!response.ok) throw new Error(`QWC daemon request ${path} failed with HTTP ${response.status}`);
      const body = parseBinaryStrings
        ? parseJonResponse(new Uint8Array(await response.arrayBuffer()))
        : await response.json();
      if (!body || body.status !== "OK") throw new Error(`QWC daemon request ${path} returned an invalid response`);
      return body;
    } finally {
      clearTimeout(timeout);
    }
  }

  function attachBlockHeaderHashes(blocks, headers, start, end) {
    if (!Array.isArray(blocks) || !Array.isArray(headers)) {
      throw new Error("QWC daemon returned an invalid Messenger block range");
    }

    const headersByHeight = new Map();
    for (const header of headers) {
      const height = Number(header && header.height);
      const hash = header && header.hash;
      const prevHash = header && header.prevHash;
      if (!Number.isSafeInteger(height) || height < start || height > end
          || typeof hash !== "string" || !/^[0-9a-f]{64}$/i.test(hash)
          || typeof prevHash !== "string" || !/^[0-9a-f]{64}$/i.test(prevHash)
          || headersByHeight.has(height)) {
        throw new Error("QWC daemon returned invalid Messenger block headers");
      }
      headersByHeight.set(height, Object.assign({}, header, {
        hash: hash.toLowerCase(),
        prevHash: prevHash.toLowerCase()
      }));
    }

    return blocks.map(block => {
      const height = Number(block && block.height);
      const header = headersByHeight.get(height);
      if (!Number.isSafeInteger(height) || !header) {
        throw new Error("QWC daemon returned a Messenger block without its canonical header");
      }
      const blockPrevHash = block && block.prevHash;
      if (typeof blockPrevHash !== "string" || !/^[0-9a-f]{64}$/i.test(blockPrevHash)
          || blockPrevHash.toLowerCase() !== header.prevHash) {
        throw new Error("QWC daemon returned mismatched Messenger block header data");
      }
      for (const field of ["timestamp", "majorVersion", "minorVersion", "nonce"]) {
        if (block[field] !== undefined && header[field] !== undefined
            && Number(block[field]) !== Number(header[field])) {
          throw new Error("QWC daemon returned mismatched Messenger block header data");
        }
      }
      if (typeof block.hash === "string" && block.hash.length
          && block.hash.toLowerCase() !== header.hash) {
        throw new Error("QWC daemon returned mismatched Messenger block and header hashes");
      }
      return Object.assign({}, block, { hash: header.hash });
    });
  }

  function normalizeMempoolHashes(hashes) {
    if (typeof hashes === "string") {
      if (hashes.length % 32 !== 0) throw new Error("QWC daemon returned a truncated transaction-pool hash blob");
      hashes = Array.from({ length: hashes.length / 32 }, (_, index) => hashes.slice(index * 32, (index + 1) * 32));
    }
    if (!Array.isArray(hashes)) throw new Error("QWC daemon returned an invalid transaction-pool hash list");
    const unique = new Set();
    for (const hash of hashes) {
      if (typeof hash !== "string") {
        throw new Error("QWC daemon returned an invalid transaction-pool hash");
      }
      if (/^[0-9a-f]{64}$/i.test(hash)) {
        unique.add(hash.toLowerCase());
        continue;
      }
      if (hash.length !== 32 || Array.from(hash).some(value => value.charCodeAt(0) > 0xff)) {
        throw new Error("QWC daemon returned an invalid transaction-pool hash");
      }
      unique.add(Array.from(hash, value => value.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
    }
    return Array.from(unique);
  }

  function normalizeMempoolTransactions(response, requestedHashes) {
    if (!response) throw new Error("QWC daemon returned invalid transaction-pool data");
    const responseTransactions = response.txs === undefined ? [] : response.txs;
    if (!Array.isArray(responseTransactions)) throw new Error("QWC daemon returned invalid transaction-pool data");
    const requested = new Set(requestedHashes);
    const transactions = [];
    for (const tx of responseTransactions) {
      const hash = tx && tx.tx_hash;
      if (typeof hash !== "string" || !/^[0-9a-f]{64}$/i.test(hash) || tx.in_pool !== true) continue;
      const normalizedHash = hash.toLowerCase();
      if (!requested.has(normalizedHash) || typeof tx.as_json !== "string") continue;
      let decoded;
      try { decoded = JSON.parse(tx.as_json); } catch (_) { continue; }
      if (!decoded || !Array.isArray(decoded.extra)) continue;
      transactions.push({
        hash: normalizedHash,
        extra: decoded.extra,
        receivedTimestamp: Number(tx.received_timestamp || 0)
      });
    }
    return transactions;
  }

  async function createWallet(config, method, canSign = true) {
    const walletId = newId("wallet");
    await invoke(walletId, method, [config]);
    return {
      id: walletId,
      getSeed: () => invoke(walletId, "getSeed", []),
      getPrivateSpendKey: () => invoke(walletId, "getPrivateSpendKey", []),
      getPrivateViewKey: () => invoke(walletId, "getPrivateViewKey", []),
      getPublicSpendKey: () => invoke(walletId, "getPublicSpendKey", []),
      getPublicViewKey: () => invoke(walletId, "getPublicViewKey", []),
      getAddress: (accountIdx, subaddressIdx) => invoke(walletId, "getAddress", [accountIdx, subaddressIdx]),
      decodeIntegratedAddress: address => invoke(walletId, "decodeIntegratedAddress", [address]),
      isConnectedToDaemon: () => invoke(walletId, "isConnectedToDaemon", []),
      reconnectDaemon: () => invoke(walletId, "setDaemonConnection", [getDefaultServerConfig(), true]),
      getHeight: () => invoke(walletId, "getHeight", []),
      getDaemonHeight: () => invoke(walletId, "getDaemonHeight", []),
      getBalance: () => invoke(walletId, "getBalance", []),
      getUnlockedBalance: () => invoke(walletId, "getUnlockedBalance", []),
      getTxs: () => invoke(walletId, "getTxs", [{ txs: [{}] }]),
      getOutputs: () => invoke(walletId, "getOutputs", [{ txs: [{}] }]),
      freezeOutput: keyImage => invoke(walletId, "freezeOutput", [keyImage]),
      thawOutput: keyImage => invoke(walletId, "thawOutput", [keyImage]),
      createTx: config => invoke(walletId, "createTxs", [normalizeTxConfig(config)]),
      describeTxSet: txSet => invoke(walletId, "describeTxSet", [txSet]),
      relayTxs: txMetadatas => invoke(walletId, "relayTxs", [txMetadatas]),
      submitTxs: signedTxHex => invoke(walletId, "submitTxs", [signedTxHex]),
      signMessage: (message, signatureType = 0, accountIdx = 0, subaddressIdx = 0) =>
        canSign
          ? invoke(walletId, "signMessage", [message, signatureType, accountIdx, subaddressIdx])
          : Promise.reject(new Error("Watch-only wallets cannot create signatures.")),
      verifyMessage: (message, address, signature) =>
        invoke(walletId, "verifyMessage", [message, address, signature]),
      sync: startHeight => invoke(walletId, "sync", [
        Number.isSafeInteger(startHeight) && startHeight > 0 ? startHeight : undefined,
        false
      ]),
      close: () => closeWallet(walletId)
    };
  }

  return {
    MAINNET,
    createDaemonScanner: async () => {
      const daemonId = newId("daemon");
      await invoke(daemonId, "connectDaemonRpc", [{
        server: getDefaultServerConfig(),
        proxyToWorker: false
      }]);
      return {
        getHeight: () => invoke(daemonId, "daemonGetHeight", []),
        getTxPoolHashes: async () => {
          const response = await postDaemonPath("/get_transaction_pool_hashes.bin", {}, true);
          return normalizeMempoolHashes(response.tx_hashes === undefined ? [] : response.tx_hashes);
        },
        getMempoolTransactions: async hashes => {
          const normalized = normalizeMempoolHashes(hashes);
          if (normalized.length > MAX_MEMPOOL_TX_REQUEST) {
            throw new Error(`Messenger transaction-pool request exceeds ${MAX_MEMPOOL_TX_REQUEST} hashes`);
          }
          if (!normalized.length) return [];
          return normalizeMempoolTransactions(
            await postDaemonPath("/get_transactions", {
              txs_hashes: normalized,
              decode_as_json: true,
              prune: true,
              split: false
            }),
            normalized
          );
        },
        getBlocksByRange: async (start, end) => {
          const [blocks, headers] = await Promise.all([
            invoke(daemonId, "daemonGetBlocksByRangeChunked", [start, end, DAEMON_CHUNK_BYTES]),
            invoke(daemonId, "daemonGetBlockHeadersByRange", [start, end])
          ]);
          return attachBlockHeaderHashes(blocks, headers, start, end);
        }
      };
    },
    createFromKeys: config => {
      const keyConfig = {
        networkType: MAINNET,
        primaryAddress: config.primaryAddress,
        privateViewKey: config.privateViewKey,
        restoreHeight: 0,
        language: "English"
      };
      if (config.privateSpendKey) keyConfig.privateSpendKey = config.privateSpendKey;
      // Keys-only wallets deliberately do not implement message signing or
      // verification in qwertycoin-cpp. A full in-memory wallet uses the
      // existing Core wallet2 implementation and remains offline because this
      // configuration contains no daemon server.
      return createWallet(keyConfig, "createWalletFull", !!config.privateSpendKey);
    },
    createRandomWallet: language => createWallet({
      networkType: MAINNET,
      language: language || "English",
      server: getDefaultServerConfig()
    }, "createWalletFull"),
    restoreFromSeed: (seed, restoreHeight) => createWallet({
      networkType: MAINNET,
      seed: seed.trim(),
      restoreHeight: Number.isSafeInteger(restoreHeight) && restoreHeight > 0 ? restoreHeight : 0,
      server: getDefaultServerConfig()
    }, "createWalletFull")
  };
})();

if (typeof module !== "undefined" && module.exports) module.exports = QwcWalletEngine;
