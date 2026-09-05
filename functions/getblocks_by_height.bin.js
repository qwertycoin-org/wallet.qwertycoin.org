// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

import { json, proxyQwcRpc } from "./_qwcRpcProxy.js";

export async function onRequest(context) {
  return proxyQwcRpc(context, "/getblocks_by_height.bin").catch(error => {
    return json(context.request, 500, { error: error.message || "Proxy failed" });
  });
}
