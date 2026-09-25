# Qwertycoin Web Wallet

![Qwertycoin Web Wallet](assets/social-card.2f2114c74813.png)

The official open-source, non-custodial Qwertycoin web wallet. Private keys are derived and used inside the browser.

Live at [wallet.qwertycoin.org](https://wallet.qwertycoin.org/).

## Supported wallet access

- **Restore from seed:** exactly 25 Qwertycoin words (24 data words plus checksum)
- **Create new wallet:** a fresh 25-word QWC seed from the browser CSPRNG
- **Private spend key:** 64-character hexadecimal import
- **Watch-only:** QWC address plus private view key

Legacy 12-, 13- and 16-word seed formats from other projects are not exposed or accepted by the Qwertycoin wallet UI.

## Architecture

```text
Browser
├── Qwertycoin key derivation and address generation
├── qwertycoin-ts WebAssembly scanner
├── local spend-key message signing and signature verification
├── QMS2 offline cryptography and encrypted local Messenger state
├── local transaction construction and signing
├── encrypted in-tab WalletVault session
└── local QR generation and scanning

Cloudflare Pages
├── immutable static wallet assets
├── restricted same-origin QWC RPC gateway
├── binary scanner endpoint
└── abuse controls for transaction submission

Qwertycoin infrastructure
└── Integration Explorer's restricted, allowlisted wallet RPC gateway
```

The seed, private spend key and private view key remain in the browser. The RPC
gateway receives restricted blockchain queries and, when the user sends QWC,
the completed signed transaction. Message signing and verification do not use
the gateway. The dedicated pool-challenge view validates the exact address,
threshold, nonce, expiration and domain locally before creating a spend-key
signature.

## Message signing

Open **Sign / Verify** in a loaded wallet to create or verify a Qwertycoin
message signature. Messages are signed as their exact UTF-8 bytes: whitespace,
line endings and Unicode normalization are not changed. Watch-only wallets can
verify signatures but cannot create them.

Pool operators integrating payout-threshold authorization must use the strict
challenge format and server-side replay controls described in
[`docs/message-signing.md`](docs/message-signing.md).

## Messenger

The **Messenger** tab exposes the offline part of the experimental QMS2
profile: pinned libsignal PQXDH plus ongoing Triple Ratchet/SPQR, QMS2 contact
packages, encrypted password-bound state, outer-secret rotation, explicit
history opt-in/deletion, and restore reset.

A normal browser cannot attest that all wallet RPC traffic used Tor with no
direct fallback. QMS2 chain synchronization, transaction construction, and
broadcast are therefore fail-closed in the web wallet. The native client is
required for transport testing. See
[`docs/qms-messenger.md`](docs/qms-messenger.md) for the exact protocol,
storage, restore, metadata, licensing, and audit limitations.

## Self-hosting

The maintained guide is available at [wallet.qwertycoin.org/self-host](https://wallet.qwertycoin.org/self-host) and in [`self-host.html`](self-host.html).

```bash
git clone https://github.com/qwertycoin-org/wallet.qwertycoin.org.git
cd wallet.qwertycoin.org
python3 -m http.server 8000
```

For full wallet operation, configure the Pages functions or an equivalent same-origin gateway against a restricted `qwertycoind` RPC endpoint. Do not expose unrestricted administrative RPC publicly.

QMS2 does not use this gateway in the browser build. Its network operations
remain disabled until a separately reviewable browser design can attest
Tor-only routing without direct fallback.

## Verification

```bash
npm test
./tools/build-manifest.sh
sha256sum -c MANIFEST.sha256
```

The manifest covers every shipped HTML, JavaScript, CSS, font, image, WebAssembly and serverless-function asset.

## Security model

The wallet protects the seed and private keys from the hosting and RPC infrastructure by keeping derivation and signing in the browser. It does not protect against a compromised browser extension, operating system, fake domain, hostile code served from the canonical origin, or a user exposing their seed.

For substantial funds, use a dedicated wallet environment and independently verify the application source and domain. Report security issues through [GitHub private vulnerability reporting](https://github.com/qwertycoin-org/wallet.qwertycoin.org/security/advisories/new).

## Third-party provenance and copyright

Qwertycoin inherits CryptoNote-compatible algorithms and includes compatibility modules whose historical filenames or public JavaScript symbols contain `monero` or `mymonero`. Those technical names are intentionally retained where renaming could break interoperability or obscure provenance.

Upstream copyright, license texts and notices are preserved in:

- [`LICENSE`](LICENSE)
- [`fonts/LICENSES.md`](fonts/LICENSES.md)
- [`js/mymonero-core/LICENSE.txt`](js/mymonero-core/LICENSE.txt)
- [`vendor/qwertycoin-ts/qwertycoin.worker.js.LICENSE.txt`](vendor/qwertycoin-ts/qwertycoin.worker.js.LICENSE.txt)
- `vendor/qwertycoin-ts/qms2/LICENSE.qwc-qms-crypto`
- `vendor/qwertycoin-ts/qms2/THIRD_PARTY.qwc-qms-crypto.md`
- [`vendor/libsodium/LICENSE.libsodium-wrappers-sumo`](vendor/libsodium/LICENSE.libsodium-wrappers-sumo)
- [`vendor/libsodium/BUILDINFO.txt`](vendor/libsodium/BUILDINFO.txt)
- SPDX headers in source files

Do not remove or rewrite third-party attribution when modifying the wallet.

## Contributing

Pull requests should preserve funds safety, QWC v2 genesis binding, restricted-RPC policy, local key handling, deterministic manifests and responsive accessibility.

## License

The project-authored code is MIT licensed. Bundled third-party components remain under their respective licenses and copyright notices.
