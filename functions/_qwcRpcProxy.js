// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const DEFAULT_NODES = [
  "https://explorer.qwertycoin.org/qwc-rpc"
];

const JSON_RPC_METHODS = new Set([
  "get_info",
  "get_version",
  "get_block_count",
  "get_fee_estimate",
  "get_last_block_header",
  "get_block_header_by_height",
  "getblockheaderbyheight",
  "get_block_headers_range",
  "getblockheadersrange",
  "hard_fork_info",
  "get_output_histogram",
  "get_transactions"
]);

const ROOT_RPC_PATHS = new Set([
  "/json_rpc",
  "/getblocks.bin",
  "/getblocks_by_height.bin",
  "/gethashes.bin",
  "/get_o_indexes.bin",
  "/get_output_distribution.bin",
  "/get_outs.bin",
  "/get_transactions",
  "/gettransactions",
  "/get_transaction_pool_hashes.bin",
  "/is_key_image_spent",
  "/send_raw_transaction",
  "/submit_raw_tx",
  "/sendrawtransaction"
]);

const MAX_JSON_REQUEST_BYTES = 256 * 1024;
const MAX_BINARY_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 12 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 20_000;

const ALLOWED_ORIGINS = new Set([
  "https://wallet.qwertycoin.org"
]);

const BASE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Expose-Headers": "Content-Type",
  "Vary": "Origin"
};

function getAllowedOrigin(request) {
  const origin = request.headers.get("origin") || "";
  if (ALLOWED_ORIGINS.has(origin) || /^https:\/\/(?:[a-z0-9-]+\.)+pages\.dev$/i.test(origin)) return origin;
  return "https://wallet.qwertycoin.org";
}

export function corsHeaders(request, contentType = "application/json") {
  return {
    ...BASE_CORS_HEADERS,
    "Access-Control-Allow-Origin": getAllowedOrigin(request),
    "Content-Type": contentType
  };
}

export function json(request, status, body) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(request) });
}

async function readBodyWithLimit(request, maxBytes) {
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (contentLength > maxBytes) throw new Error("Request too large");

  const body = await request.arrayBuffer();
  if (body.byteLength > maxBytes) throw new Error("Request too large");
  return body;
}

function normalizeContentType(contentType) {
  if (contentType && contentType.includes("application/octet-stream")) return "application/octet-stream";
  return "application/json";
}

async function readResponseWithLimit(response) {
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (contentLength > MAX_RESPONSE_BYTES) throw new Error("Response too large");

  const body = await response.arrayBuffer();
  if (body.byteLength > MAX_RESPONSE_BYTES) throw new Error("Response too large");
  return body;
}

export function isAllowedRootRpcPath(path) {
  return ROOT_RPC_PATHS.has(path);
}

export async function proxyQwcRpc(context, path) {
  const { request } = context;
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }
  if (request.method !== "POST") {
    return json(request, 405, { error: "Method not allowed" });
  }
  if (!ROOT_RPC_PATHS.has(path)) {
    return json(request, 403, { error: "Path not allowed" });
  }

  const isJson = path === "/json_rpc" || !path.endsWith(".bin");
  const body = await readBodyWithLimit(request, isJson ? MAX_JSON_REQUEST_BYTES : MAX_BINARY_REQUEST_BYTES)
    .catch(error => ({ error }));
  if (body && body.error) {
    return json(request, 400, { error: body.error.message === "Request too large" ? body.error.message : "Invalid request body" });
  }

  if (path === "/json_rpc") {
    let payload;
    try {
      payload = JSON.parse(new TextDecoder().decode(body));
    } catch (error) {
      return json(request, 400, { error: "Invalid JSON" });
    }
    if (!payload || typeof payload.method !== "string" || !JSON_RPC_METHODS.has(payload.method)) {
      return json(request, 403, { error: "JSON-RPC method not allowed" });
    }
  }

  const requestContentType = isJson
    ? request.headers.get("content-type") || "application/json"
    : "application/octet-stream";

  for (const node of DEFAULT_NODES) {
    try {
      const upstream = await fetch(node + path, {
        method: "POST",
        headers: { "Content-Type": requestContentType },
        body: path.endsWith(".bin") ? new Uint8Array(body) : body,
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS)
      });

      if (!upstream.ok) continue;

      const responseBody = await readResponseWithLimit(upstream);
      const contentType = normalizeContentType(upstream.headers.get("content-type") || requestContentType);
      return new Response(responseBody, { status: 200, headers: corsHeaders(request, contentType) });
    } catch (error) {
      // Never log wallet request or response bodies.
    }
  }

  return json(request, 502, { error: "All upstream QWC nodes unreachable" });
}
