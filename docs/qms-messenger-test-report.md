# QMS1/Fast hardening report

Date: 2026-09-29  
Scope: Web Wallet PR #14, based on
`670cf48d377e6f6c8b31bd8ddb8b24f759c4d3df`  
Live-tested hardened code SHA: `4dab9a3734c6c35060fe7d9c7fd8b2fb457e80d5`
Implementation/evidence commits: 18 reviewable commits from `c628e06` through `4dab9a3`

This report distinguishes automated evidence from remaining release work. A
green source-string assertion is not treated as browser or fault-injection
evidence.

## F01–F12 disposition

| ID | Result | Evidence |
|---|---|---|
| F01 | Fixed | Save/close lifecycle rejects new writes, drains accepted writes before key destruction, and has close-before/between-write regressions (`c628e06`). |
| F02 | Fixed | One origin-wide Web Lock per network/wallet; the real Chromium test opens a second tab/store and verifies fail-closed behavior (`c628e06`). |
| F03 | Fixed | Durable outbox state machine, operation mutex, journal-before-relay, `broadcast_unknown`, identical-payload retry and no ambiguous thaw (`a2b4a47`). |
| F04 | Fixed | Capacity/storage errors stop the cursor; unknown senders use a separate bounded queue; stale pressure records a bounded rescan anchor; authenticated but undecryptable foreign payloads are classified and discarded (`839b0be`, `3d0c46f`, `5db2b35`). |
| F05 | Fixed | `tx_extra` tag `0x04` parses a varint count × 32-byte keys; valid/truncated Core-shaped fixtures are covered (`839b0be`). |
| F06 | Fixed | Scanning and contact management continue while a plan exists; only spend/prepare paths affected by reserved inputs remain blocked (`a2b4a47`, `839b0be`). |
| F07 | Fixed | Encrypted IndexedDB records, changed-row persistence, explicit quotas and bounded contacts/messages/plans (`4aaa4e1`, `84c730f`). |
| F08 | Fixed | Ciphertext opens once before fingerprint lookup/authentication; 100-message pages, incremental unchanged-poll behavior and stable scroll (`231ecc1`, `6073e8a`). |
| F09 | Fixed | Authenticated encrypted backup/import and atomic Session-password/data-key rewrap (`ea1073f`, `92a7789`). |
| F10 | Fixed | Import and verification are separate; `verifiedAt`, grouped fingerprints and per-contact discovery invitations are persisted (`231ecc1`, `72a8d07`). |
| F11 | Fixed | Persistent start height, cross-batch hash chain, checkpoints, atomic cursor/data commit and controlled rollback/rescan (`839b0be`). |
| F12 | Partly proven | Real Chromium IndexedDB/Web Locks/UI/mobile/performance tests, bidirectional Web↔Core byte interoperability and a final-SHA Web→chain→Web QMS receive are present. Firefox, WebKit/Safari and an installed Desktop-GUI network round-trip remain release gates. |

No P0 item remains open in this source tree. F12's remaining browser/Desktop
matrix must be completed before a regular release; it is not closed by naming
the Core protocol test “Desktop”.

## Automated evidence

- 44 wallet/compatibility tests
- 15 presentation-contract tests
- message-signing and actual bundled worker/WASM custom-`tx_extra` bridge
- 33 QMS1 protocol/store/scanner/outbox tests
- real Chromium IndexedDB, Web Locks, password rotation and KDF-worker test
- real Chromium chat, pagination, drafts, unread/filter, invitation QR/file,
  verification gate and 390 px navigation test
- Core `a62ac68…` focused suite: 9/9
- temporary cross-language probe: Web carrier opened by Core; Core reply carrier
  opened by Web
- repository manifest/vendor provenance check

Available locally for this report: Chromium `153.0.8010.12`. Firefox and
WebKit were not installed, so no claim is made for those engines. Safari-style
behavior is not inferred from Chromium viewport emulation.

## Performance

Reference host: 4 vCPU AMD EPYC-Genoa, 7.7 GiB RAM, headless Chromium
`153.0.8010.12`, 1280×900, local HTTP, no network RPC in interaction samples.
Each sample waits for the next animation frame. Cold setup/persistence/mount
are reported separately from unlocked interaction long tasks.

The actual Session KDF parameters (`Argon2id`, opslimit 2, 64 MiB) took
262.6–322.7 ms in two dedicated-Worker runs on this host and produced no
observed main-thread long task. These are reference measurements, not a reason
to weaken the parameters.

### Identical 100-contact / 1,000-message dataset

| Revision | Chat switch p50/p95 | Input p50/p95 | Messages in DOM | Max interaction long task |
|---|---:|---:|---:|---:|
| Reviewed head `670cf48d…` | 28.8 / 185.0 ms | 16.7 / 28.9 ms | 901 | 238 ms |
| Hardened tree after `3d0c46f` | 20.2 / 33.7 ms | 16.7 / 16.8 ms | 100 | 0 ms |

### Required 100-contact / 10,000-message dataset

- Reviewed head: Chromium renderer crashed while mounting the full 9,901-entry
  heavy conversation; no misleading percentile is reported.
- Hardened tree: setup 2,302.2 ms, encrypted-record persistence 1,188.4 ms,
  Messenger mount 1,044.9 ms, chat p50/p95 15.7/26.7 ms, input p50/p95
  16.7/17.0 ms, 100 messages in the DOM, no interaction long task over 50 ms.

Numbers are a recorded run, not a universal device guarantee. Reproduce with:

```bash
PLAYWRIGHT_CORE_PATH=/app/node_modules/playwright-core \
CHROMIUM_PATH=/ms-playwright/chromium-1243/chrome-linux64/chrome \
QMS_BENCH_ENFORCE=1 npm run test:benchmark-qms-ui
```

## Current network evidence and remaining acceptance

Final hardened-preview Web→chain→Web carrier:
[`770f8d1430c5f9b8c7ec4542e15e6cb33dfef35c6d218e8e2e5795631c6933bf`](https://explorer.qwertycoin.org/tx/770f8d1430c5f9b8c7ec4542e15e6cb33dfef35c6d218e8e2e5795631c6933bf)
in block 11205. The expressly supplied limited-budget test wallets were both
restored from their seeds, checked against their expected addresses and
synchronized through the final Cloudflare preview using the Production
Explorer gateway. A short signed message produced one 435-byte carrier,
paid `0.023496 QWC`, relayed in 115.3 ms and was confirmed after 168.8 s. The
recipient scanner fetched the confirmed block through the Production Explorer,
verified the fragment MAC, recipient binding and sender signature, and recovered
the exact UTF-8 plaintext. Measured wallet syncs were 11.6 s and 10.7 s; signed
carrier construction took 3.47 s. The receiver path itself performed no spend.

The broadcast was performed once. A preceding dry-run verified the same
one-carrier invariant, final signed `tx_extra` bytes and fee before relay. No
production seed or primary wallet was used, and no ambiguous response was
retried with a newly built transaction.

The encrypted IndexedDB reimport path is proven separately by the real Chromium
test: the same wallet plus Session password reopens its history, while a wrong
password cannot replace it. The final network test intentionally did not expose
or copy the wallet seeds into logs, source files or commits.

Earlier Web transport evidence remains useful as a historical regression:

Historical Web test carrier:
`83b4636857b9dcb94a76eaae16d7305de1ca3f52bd53287f688410b60d2fbe54`
in block 10645. It used one 440-byte `tx_extra`, paid `0.023568 QWC`, and was
found and decrypted by the recipient scanner. The Production Explorer scan
also re-read the earlier carrier
`b24727104f05efbdfc825061dbbca9daa03b6bb2ffd7b4c0e78a2b69e34ee024`.
These older transactions prove the earlier live transport path; the block-11205
transaction above covers the final hardened preview SHA.

Before a regular release, complete and attach:

1. installed Desktop GUI Web→Desktop and Desktop→Web chain tests with exact
   GUI/Core SHAs;
2. Firefox and WebKit/Safari desktop plus 360/390 px runs;
3. screenshots for chat, fingerprint verification, fee review, capacity/error
   state and mobile list→conversation navigation.

No production seed or primary wallet is used by the automated suites. Network
tests must use the expressly supplied limited-budget test wallets. No merge or
production rollout is authorized by this report.
