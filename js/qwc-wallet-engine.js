// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const QwcWalletEngine = (() => {
  const MAINNET = 0;
  const WORKER_PATH = "/vendor/qwertycoin-ts/monero.worker.js?v=20260901-5";
  const REQUEST_TIMEOUT_MS = 180000;
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
        callback.reject(new Error(payload.error.message || "QWC wallet worker error"));
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

      callbacks.set(callbackId, { resolve, reject, timeout });
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

  async function createWallet(config, method) {
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
      createTx: config => invoke(walletId, "createTxs", [normalizeTxConfig(config)]),
      describeTxSet: txSet => invoke(walletId, "describeTxSet", [txSet]),
      relayTxs: txMetadatas => invoke(walletId, "relayTxs", [txMetadatas]),
      submitTxs: signedTxHex => invoke(walletId, "submitTxs", [signedTxHex]),
      sync: startHeight => invoke(walletId, "sync", [
        Number.isSafeInteger(startHeight) && startHeight > 0 ? startHeight : undefined,
        false
      ]),
      close: () => closeWallet(walletId)
    };
  }

  return {
    MAINNET,
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
