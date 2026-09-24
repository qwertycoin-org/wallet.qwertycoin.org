# QMS2 Messenger in the Web Wallet

QMS2 is the experimental Qwertycoin Messenger profile shared with the native
wallet. It uses ordinary QWC transactions as carrier records. It does not
change consensus, block production, relay limits, or service-node rewards.

The browser build currently exposes only the offline cryptographic and local
state-management surface. A normal browser cannot prove that every wallet RPC
request used a Tor-only route with no direct fallback. Chain synchronization,
transaction preparation, and broadcast are therefore disabled for QMS2 in the
web wallet. Use the native wallet for transport testing.

## Offline browser flow

1. Unlock a password-protected full wallet and choose **Activate QMS2**.
2. Exchange the complete QMS2 contact packages over a confidential channel.
3. Compare the 64-character fingerprints over an independent authenticated
   channel before accepting a contact.
4. Keep plaintext-history persistence off unless it is explicitly required.
5. Use **Reset Messenger identity and sessions** after restoring an old browser
   backup or if local state rollback is suspected, then exchange fresh contact
   packages.

Passwordless browser sessions cannot activate QMS2 because they cannot provide
the independent password-derived wrapping key required for durable ratchet
state. Watch-only wallets cannot activate it either.

## Protocol profile

- Wire version/profile: `2/2` (`QMS2`)
- QWC v2 mainnet genesis:
  `4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39`
- Existing `TX_EXTRA_NONCE` outer field with QMS subtype `0x72`
- Pinned libsignal PQXDH handshake and ongoing Triple Ratchet/SPQR session
- XChaCha20-Poly1305 metadata envelope with HKDF-separated envelope,
  discovery, and fragment-MAC keys
- Deterministic padding classes up to 9,600 bytes
- 600-byte fragment payloads, at most 16 fragments, and at most 4,096 UTF-8
  plaintext bytes
- A full carrier remains exactly 726 bytes of `tx_extra`

The 4,096-byte PQXDH first-message vector serializes to 5,953 bytes before the
outer envelope and occupies the 7,200-byte padding class (12 carriers). The
same vector is pinned in Core and the browser tests.

## Ratchet and outer-secret rotation

Each contact owns independent libsignal session state. The PQXDH pre-key
message establishes the initial session; every subsequent message advances the
ongoing Triple Ratchet. QMS2 also rotates the outer discovery/envelope secret:

- rotation is offered after 16 committed sends;
- an unacknowledged offer is repeated;
- the receiver switches to the offered context and acknowledges it;
- the sender retains one retiring context for a bounded grace period;
- obsolete secret material is deleted after confirmation and grace handling.

State transitions are prepared first and committed only with the corresponding
local operation checkpoint. Authentication failures, incomplete fragments, or
storage failures do not advance ratchet state.

## Local storage

The QMS2 state is encrypted with a random 32-byte data key using
XChaCha20-Poly1305. That data key is wrapped by a separate 32-byte QMS unlock
key derived from the wallet password with Argon2id. Associated data binds both
layers to the hashed wallet-address storage key and their purpose. Password
changes rewrap the data key rather than re-encrypting or resetting sessions.

The encrypted state contains identity, contact packages, ratchet state,
prepared checkpoints, and authenticated incomplete fragments. Incomplete
reassembly is capped at 64 messages and 8 MiB. Plaintext message history is off
by default, can be enabled explicitly, and can be deleted without rolling back
ratchet state.

This protects records from casual browser-storage inspection. It does not
protect an unlocked session from hostile same-origin code, a compromised
browser extension, or a compromised operating system.

## Restore and deletion limits

Authenticated state prevents undetected byte-level tampering, but a complete
rollback of all browser storage to an older valid snapshot cannot be detected
locally. After restoring an old backup, reset QMS2 and exchange fresh contact
packages. Deleting local history or QMS2 state does not remove immutable
blockchain carrier data.

## Transport boundary

Native QMS2 requires a validated SOCKS proxy and a Tor v3 onion endpoint, with
no direct fallback, before wallet refresh, preparation, or commit. The browser
cannot attest that policy itself. Consequently this repository's QMS2 browser
controller contains no wallet-RPC, transaction-construction, broadcast, or
scanner path. Enabling such a path requires a separately reviewable,
attestable Tor-only browser transport design.

## Security and release status

- QMS2 has not received an independent security audit.
- Transaction hashes, timing, fees, sizes, and fragment relationships remain
  public blockchain metadata even though message content and inner metadata
  are encrypted.
- Contact packages are confidential capabilities; fingerprints must be
  verified independently.
- libsignal is pinned and redistributed under AGPL-3.0-only terms. Signal does
  not support third-party use of the library. See the vendored license and
  third-party notice shipped with the QMS2 WebAssembly artifact.
- The current work is an offline security candidate. No live node, Tor, or
  transaction test is represented by the browser test suite.

## Artifact provenance

The QMS2 browser module is built from immutable TypeScript, C++ adapter, Core,
libsignal, Rust-toolchain, wasm-bindgen, and Emscripten revisions in CI. The
authoritative artifact and its `QMS2-SHA256SUMS`, license, and third-party
notice are copied into `vendor/qwertycoin-ts/qms2/` only after an independent
post-CI hash verification. Exact pins are recorded in
[`vendor/qwertycoin-ts/BUILDINFO.txt`](../vendor/qwertycoin-ts/BUILDINFO.txt)
and the repository-wide manifest.
