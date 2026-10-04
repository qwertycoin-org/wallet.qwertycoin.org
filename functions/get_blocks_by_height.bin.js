// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

import { json, proxyQwcRpc } from "./_qwcRpcProxy.js";

// qwertycoin-ts requests this exact daemon path while scanning blocks.
// Keep the underscore after "get"; /getblocks_by_height.bin is not the
// canonical binary RPC route.
export async function onRequest(context) {
  return proxyQwcRpc(context, "/get_blocks_by_height.bin").catch(error => {
    return json(context.request, 500, { error: error.message || "Proxy failed" });
  });
}
