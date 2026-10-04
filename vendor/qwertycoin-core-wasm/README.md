# Qwertycoin Core WASM (vendored upstream implementation)

This directory contains a pinned vendor copy of
[`mymonero-core-js`](https://github.com/mymonero/mymonero-core-js) — the
WebAssembly-based Monero transaction-construction library originally
written by the MyMonero team and used in production by their wallet for
years before MyMonero shut down in January 2026.

Qwertycoin Web Wallet uses this code to build, sign, and prepare-for-broadcast
RingCT/CLSAG/Bulletproofs transactions **entirely inside the user's
browser tab**, so the spend key never leaves the device. The light-wallet
server (monero-lws) only sees the view key (for incoming output scanning)
and the signed transaction hex (for broadcast); transaction construction
is fully client-side.

## License

[BSD 3-Clause](./LICENSE.txt) — see the original `LICENSE.txt` checked
into this folder. The copyright is held by MyMonero.com (2014–2019).
This file is intentionally left unmodified to satisfy the license's
attribution requirement.

The BSD 3-Clause license is permissive and compatible with Qwertycoin Web Wallet's
overall MIT license.

## Files

| File | Size | Purpose |
|---|---|---|
| `qwertycoin-core-wasm.wasm` | ~2.1 MB | The Qwertycoin-compatible WebAssembly binary compiled from the upstream C++ implementation |
| `qwertycoin-core-wasm.js`   | ~250 KB | Emscripten-generated loader with a locally branded factory and asset filename |
| `QwertycoinCoreBridge.js`             | ~3 KB | Top-level CommonJS factory (wraps the bridge in a Promise) |
| `QwertycoinCoreBridgeClass.js`        | ~12 KB | High-level API wrapping raw WASM calls into nicer methods |
| `QwertycoinCoreBridgeEssentialsClass.js` | ~8 KB | Same idea, lighter-weight subset |
| `LICENSE.txt`                       | ~1 KB | The BSD 3-Clause license, kept for attribution |

## Status

**Vendored and active.** The dashboard loads the branded Emscripten artifact
and uses it for client-side transaction construction and signing.

## Provenance

```
source:    https://github.com/mymonero/mymonero-core-js
commit:    master branch as of 2026-04-09
fetched:   raw.githubusercontent.com/mymonero/mymonero-core-js/master/monero_utils/
```

The binary and bridge sources originate from the upstream repository's
`monero_utils/` directory. The loaded Emscripten JavaScript has only its
factory and asset filename adapted to the Qwertycoin runtime namespace;
the upstream license and provenance remain unchanged. SHA-256 hashes of
all shipped artifacts are recorded in `MANIFEST.txt`.

## Notes for whoever wires this up next

The bridge files (`QwertycoinCoreBridge.js`, `QwertycoinCoreBridgeClass.js`,
`QwertycoinCoreBridgeEssentialsClass.js`) are written as Node.js CommonJS
modules with `require()` calls, which don't work directly in browsers.
The original MyMonero codebase used webpack to bundle them — we don't
have a build step.

The simplest browser-compat path is one of:

1. **Skip the bridge** and call the Emscripten-generated
   `QwertycoinCoreWasmFactory` global directly. The
   `qwertycoin-core-wasm.js` file exposes that factory when loaded via a script tag, with
   no require() needed. The downside is you call low-level WASM exports
   instead of nice wrapper methods.
2. **Re-export the bridge classes as browser globals** by patching their
   `require()` calls to read from a small dictionary set up in advance.
   ~30 lines of glue code. Lets us keep the nice high-level methods.
3. **Bundle them via a one-shot script** that runs at commit time and
   produces a `qwertycoin-core.bundle.js`. Most invasive but cleanest.

The send flow needs roughly these methods from the bridge:
- `decode_address(address, network_type)` — validate a recipient
- `generate_key_image(key_image_inputs)` — for spent-output detection
- `send_funds(...)` — the big one: takes outputs, recipient, amount,
  view+spend keys, builds and signs a transaction, returns hex
- `compute_tx_id(tx_hex)` — for receipt tracking

Reference implementation calling these methods:
https://github.com/mymonero/mymonero-app-js/blob/master/local_modules/Wallets/Models/SecretPersistingHostedWallet.js

That's the original MyMonero web wallet's send-flow code, which is the
exact same library we vendored here, called from a vanilla-JS context.
It's the model to follow when wiring this up.
