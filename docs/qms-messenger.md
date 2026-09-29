# QMS1/Fast Messenger in the Web Wallet

The experimental **Messenger** tab implements QMS1/Fast over normal QWC
transactions. It does not change consensus, mining, EPoSe or relay rules and it
does not use a central chat server. The tab is created only for an unlocked full
wallet opened with a non-empty Session password, as required by the product
profile.

The browser sender supports the canonical 25-word QWC wallet flow, including a
wallet restored from its spend key. Messenger is unavailable for watch-only,
hardware, multisig, BIP-39/polyseed, integrated-address and payment-ID message
flows in this profile.

## What QMS1/Fast protects

- Message content is end-to-end encrypted with libsodium sealed boxes.
- Every plaintext envelope is signed with the sender's separate Ed25519
  Messenger identity and bound to the recipient invitation, message ID,
  fingerprint, network genesis and profile.
- Discovery hints and fragment MACs are derived from the confidential
  invitation secret. The wallet spend and view keys are not Messenger keys.
- Local records use XChaCha20-Poly1305 under a random data key. Argon2id derives
  the Session wrapping key in an origin-local Web Worker without weakening its
  parameters.

QMS1/Fast has **no forward secrecy, post-compromise recovery or post-quantum
protection**. A later compromise of the long-term recipient key can expose
historical ciphertext that was retained from the chain. Transaction hashes,
timing, fees, sizes and fragment relationships remain public metadata. These
limits must not be described as Signal-like security.

## Starting a chat

1. Both people open full wallets with non-empty Session passwords.
2. In **Messenger → Manage contacts**, exchange the complete invitation through
   a confidential channel. A versioned JSON file and an entirely local QR code
   are available; no invitation is placed in a URL, shortlink or analytics
   service. Hex remains available for expert use.
3. Importing and verifying are separate operations. Compare the complete
   grouped fingerprint over an independently authenticated channel, then mark
   it verified. A valid self-signature alone does not identify a person.
4. The browser creates a dedicated invitation/discovery secret for that
   contact. The bootstrap invitation remains for backward compatibility.
5. Enter at most 4,096 UTF-8 bytes. The composer shows byte and carrier counts.
   Select **Encrypt & review**, inspect the binding fee total, then explicitly
   select **Send encrypted message**.

Removing a contact archives its local key material and history; it cannot
cryptographically revoke an invitation already shared with that person.

## Wire and transport profile

- Wire version/profile: `1/1` (`QMS1`)
- Mainnet genesis:
  `4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39`
- Existing `TX_EXTRA_NONCE` field with subtype `0x72`
- 214-byte signed invitations and 96-byte fragment headers
- 600-byte fragment payloads, no more than 16 fragments
- Existing 1,060-byte `tx_extra` relay limit
- `ciphertext bytes = UTF-8 text bytes + 272`
- `carriers = ceil(ciphertext bytes / 600)`

| Text bytes | Ciphertext bytes | Carrier transactions |
|---:|---:|---:|
| 5 (`Hello`) | 277 | 1 |
| 328 | 600 | 1 |
| 329 | 601 | 2 |
| 1,024 | 1,296 | 3 |
| 4,096 | 4,368 | 8 |

The 393 bytes reported for `Hello` are its QMS carrier `tx_extra`, not the full
RingCT transaction. Fees are calculated from each prepared signed transaction;
the historic `0.023568 QWC` live-test fee is not a fixed Messenger price.

The browser verifies that the vendored wallet/WASM builder preserved every
planned fragment byte. Each prepared carrier journals its signed payload,
transaction ID, fee and reserved key images before relay.

## Outbox and recovery

The durable outbox uses these internal states:

`building → prepared → broadcasting → broadcast/broadcast_unknown → partially_confirmed → confirmed`

`cancelled` and `recovery_required` are terminal review states. Send, cancel,
prepare and recovery share one operation mutex. A network timeout after relay
is **broadcast outcome unknown**, never proof that the transaction was not
sent. Retry submits the identical signed payload and transaction ID; it does
not create a new carrier or charge a second newly built transaction. A running
or ambiguous broadcast cannot be cancelled or thawed.

On restart, open journals are reconciled and inputs are refrozen before normal
wallet spending. Imported backups always place open journals in
`recovery_required`; importing a backup never broadcasts automatically.

## Receiving and chain consistency

The scanner reads public confirmed blocks through the same-origin, restricted
Production Explorer gateway. It does not send wallet addresses, view keys,
contacts or discovery secrets to the gateway. Binary block ranges are joined
by height with canonical headers, then checked for height, hash and continuous
`prevHash → hash` linkage within and across every 20-block batch.

Cursor, messages, fragments, outbox confirmations and checkpoints are committed
atomically. Invalid foreign payloads are discarded; local capacity, storage and
infrastructure errors stop the cursor visibly. Checkpoints roll shallow reorgs
back to a common ancestor. A deeper mismatch rescans from the persistent
Messenger start height while retaining contacts and chain-independent outbox
data.

Incomplete ciphertext is capped at 64 messages/8 MiB. Complete unknown-sender
ciphertext has a separate 32-message/4 MiB queue. An incomplete/unknown item
that is more than 2,048 scanned blocks behind the current fragment can leave
the active buffer; its earliest height is retained as an encrypted bounded
rescan anchor. Importing a contact retries the queue and activates that rescan.
This block-distance rule is independent of how long the wallet was offline,
because historical blocks are processed in ascending order.

Polling never overlaps, uses a 20-second request timeout and backs off from 30
seconds to at most five minutes after failures. Browser background throttling
means this is not guaranteed background or instant delivery. Confirmation time
remains the fundamental latency floor.

## Encrypted local persistence

QMS records live as separate encrypted IndexedDB rows: identity, invitations,
contacts, messages, fragments, unknown senders, scan state and outbox. AAD binds
every row to the wallet, network, record type, ID and schema. Only a public
version/KDF locator remains in `localStorage`; private keys, invitations,
plaintext and transaction journals do not.

An origin-wide Web Lock permits one active writer per network/wallet. A second
tab fails closed instead of overwriting another snapshot. Cursor and received
records share one IndexedDB transaction. Migration from the legacy encrypted
`localStorage` envelope is authenticated and committed before its source is
removed. Quota/write errors preserve the prior good state and block new sends
when their journal cannot be made durable.

The limits are 1,000 contacts, 10,000 messages and 128 outbox plans. Only
changed encrypted records are rewritten. Chats render 100 messages at a time,
load older pages on demand and preserve scroll position. Drafts are encrypted
per contact; the contact list shows unread count and last message and can filter
locally without a server query.

JavaScript can zero reachable typed key arrays at lock/close, but it cannot
promise physical erasure of immutable strings or browser/runtime copies.

## Backup and password change

The wallet seed does not reconstruct the random Messenger identity. Export a
versioned encrypted Messenger backup and protect it with a separate password.
The backup authenticates wallet/network/identity, applies KDF and size limits,
and includes identity, per-contact invitations, contacts, history, scan state
and recovery journals. A wrong password or invalid/foreign file changes
nothing.

Changing the Session password atomically rewraps the Messenger data key and
updates the Wallet Session. An interrupted final cleanup remains recoverable by
the new password; failure before commit leaves the old password functional.
Copying one backup into multiple simultaneously active browsers is not
multi-device synchronization.

## Network and browser boundaries

Normal web operation uses HTTPS through Cloudflare Pages and the Production
Explorer's restricted wallet RPC. `proxyToWorker: false` means the daemon client
runs inside the existing wallet Worker; it is not a Tor or IP-anonymity mode.
JavaScript cannot impose browser-wide SOCKS5 routing. Onion/Tor use requires a
separately proven browser/network deployment and must not be inferred from the
GUI wallet's Tor architecture.

At-rest encryption does not protect an unlocked session from hostile code on
the wallet origin, a compromised extension, browser or operating system. The
CSP still contains an Emscripten `unsafe-eval` exception; `script-src 'self'`
does not make that exception harmless.

## Provenance and verification

- Web baseline reviewed for this hardening: `670cf48d377e6f6c8b31bd8ddb8b24f759c4d3df`
- QMS1/Fast Core used by the cross-language test:
  `a62ac68bc43a1e0ea55049da52be7eca6c5b9f68`
- Desktop GUI compatibility reference:
  `184a9c9ffbb9bc8a47d5a725e2879234f57ab09c`
- `qwertycoin-ts`: `42050b20f13089251d1aa7d117a1eea515da0444`
- `qwertycoin-cpp`: `d4a8cc78ac80e96a2e362ac0ad2630bf99a0759c`

Run the standard and browser gates:

```bash
npm test
PLAYWRIGHT_CORE_PATH=/app/node_modules/playwright-core \
CHROMIUM_PATH=/ms-playwright/chromium-1243/chrome-linux64/chrome \
npm run test:browser-qms-store
PLAYWRIGHT_CORE_PATH=/app/node_modules/playwright-core \
CHROMIUM_PATH=/ms-playwright/chromium-1243/chrome-linux64/chrome \
npm run test:browser-qms-ui
```

The optional Core interoperability gate compiles a temporary probe against the
pinned Core build and proves complete carriers in both directions without a
network broadcast:

```bash
QMS_CORE_SOURCE=/path/to/qwertycoin \
QMS_CORE_BUILD=/path/to/qwertycoin-build \
npm run test:interop-qms-core
```

See [the hardening test report](qms-messenger-test-report.md) for F01–F12,
performance data and remaining release gates.
