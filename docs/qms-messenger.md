# QMS1 Messenger in the Web Wallet

The web wallet's **Messenger** tab is compatible with the experimental QMS1
implementation in Qwertycoin GUI `v2.0.3-rc2`. It uses normal QWC
transactions as carriers; nodes, miners and consensus rules are unchanged.

## Test flow

1. Open **Messenger → Manage contacts** in each full wallet.
2. Give the complete 428-character personal invitation to the other person
   over a confidential channel. The invitation contains a discovery secret and
   must not be posted publicly.
3. Compare the shorter fingerprint over an authenticated channel, then import
   and confirm the invitation in both directions.
4. Select the contact, enter at most 4,096 UTF-8 bytes, and choose
   **Encrypt & review**.
5. Review the number of carrier transactions and total fee. No transaction is
   broadcast until **Send encrypted message** is selected.
6. The recipient sees the message after all fragments are confirmed and the
   web wallet has scanned those blocks.

QMS identities, invitations, contacts and history are local to each app or
browser profile. Opening the same QWC spend wallet in the desktop and web apps
does not copy that Messenger state. For desktop-to-web testing, exchange and
import the desktop invitation and the web invitation in opposite directions.

**Cancel & delete draft** removes an unbroadcast local message and releases its
reserved inputs. A partially broadcast batch cannot be cancelled; retrying
send only relays its remaining prepared transactions. Removing a contact keeps
the encrypted local chat history, which reappears if the same invitation is
imported again.

## Protocol compatibility

- Wire version/profile: `1/1` (`QMS1`)
- QWC v2 mainnet genesis:
  `4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39`
- Existing `TX_EXTRA_NONCE` outer field with QMS subtype `0x72`
- libsodium sealed boxes, Ed25519 sender signatures, HKDF/HMAC-SHA-256
- 214-byte signed invitations and 96-byte fragment headers
- 600-byte fragment payloads, up to 16 fragments and 4,096 UTF-8 text bytes
- Existing 1,060-byte `tx_extra` relay limit; no protocol-limit changes

The browser assembles and validates the exact `tx_extra` bytes before asking
the vendored Qwertycoin WebAssembly wallet to build each non-relayed carrier.
It then verifies that the signed transaction preserved the planned fragment.
Different wallet inputs are frozen across the complete prepared batch and are
released only on a successful unbroadcast cancellation.

## Receiving and reorgs

The scanner reads confirmed blocks through the existing restricted same-origin
QWC RPC gateway. A message is shown only after canonical segment parsing,
recipient discovery/MAC checks, full ciphertext hashing, decryption and pinned
sender-signature verification. Incomplete reassembly is capped at 64 messages
and 8 MiB. The saved scan anchor is checked on restart; a mismatch discards
derived incoming state and rescans from the wallet restore height.

## Local storage

QMS identity keys, invitations, contacts, messages, reassembly state and the
prepared-transaction journal are serialized into one AES-256-GCM envelope in
`localStorage`. Its non-extractable key is derived with HKDF-SHA-256 from the
wallet private spend key and a random per-wallet salt. The wallet address is
hashed for the storage key. Plaintext QMS private material is not written to
browser storage.

This protects at-rest records from casual storage inspection, not from hostile
code executing in the unlocked wallet origin, a compromised browser extension
or a compromised operating system.

## Security limitations

- QMS1 has no forward secrecy, double ratchet, post-compromise recovery or
  post-quantum protection.
- Transaction hashes, timing, fees, sizes and carrier relationships are public
  blockchain metadata even though message content is encrypted.
- Personal invitations are confidential capabilities. Use a separate channel
  to verify fingerprints.
- Messenger is disabled for watch-only wallets. The current browser sender
  supports standard 25-word QWC wallets (including a standard wallet restored
  from its spend key), not BIP-39 or polyseed imports. Hardware, multisig,
  integrated-address and payment-ID message flows are not supported.
- The feature is experimental. Use a test wallet with limited funds and do not
  send sensitive production messages.

## Vendored worker provenance

The custom-extra bridge used by the browser is built from immutable revisions:

- `qwertycoin-ts`: `3756ee66aacc81b64cf5589e8ffe441cb22e442e`
- `qwertycoin-cpp`: `bd63c9e3320396964cc7be0d48a88efa532dc060`
- Qwertycoin Core snapshot: `e6e0b46b6603bc5c1402df63696b514ba735f8ee`

Exact artifact digests are recorded in
[`vendor/qwertycoin-ts/BUILDINFO.txt`](../vendor/qwertycoin-ts/BUILDINFO.txt) and
the repository-wide `MANIFEST.txt`. The byte-exact npm package provenance and
digests for the vendored browser cryptography are recorded in
[`vendor/libsodium/BUILDINFO.txt`](../vendor/libsodium/BUILDINFO.txt).
