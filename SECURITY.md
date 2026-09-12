# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting:

<https://github.com/qwertycoin-org/wallet.qwertycoin.org/security/advisories/new>

Include the affected files or functions, reproduction steps, expected impact and any suggested mitigation. Never place real wallet seeds, private keys or spendable transaction material in a report.

## Scope

In scope:

- the production wallet at `wallet.qwertycoin.org`
- the 25-word QWC seed import and wallet-creation paths
- private-spend-key and watch-only imports
- browser-side Qwertycoin scanning and transaction signing
- `WalletVault` encrypted session storage and idle locking
- the restricted QWC RPC and binary scanner gateways
- transaction-broadcast abuse controls
- content-security policy, cache policy and asset manifest integrity
- QWC v2 genesis and vendored `qwertycoin-ts` artifact binding

Out of scope:

- compromised operating systems, browsers or browser extensions
- phishing domains that do not serve the canonical repository code
- denial of service against third-party network or hosting infrastructure
- reports that require exposing real wallet credentials

## Areas of particular interest

- any path that transmits a seed, private spend key or private view key
- transaction or address substitution
- failures in 25-word QWC key derivation or checksum validation
- signing, output selection, key-image or change-output errors
- QWC v2 genesis mismatches between JavaScript, WebAssembly and RPC
- CSP bypasses, DOM injection, clipboard hijacking or unsafe external assets
- bypasses of restricted-RPC or transaction-submission policy
- encrypted-session or auto-lock failures

## Third-party components

Some compatibility filenames and JavaScript symbols retain inherited `monero` or `mymonero` names. They are technical provenance, not user-facing product support. Their copyright and license notices must remain intact, including `js/mymonero-core/LICENSE.txt`, `vendor/qwertycoin-ts/monero.worker.js.LICENSE.txt`, `fonts/LICENSES.md`, the root `LICENSE`, and SPDX headers.

## Disclosure

Confirmed issues are handled privately until a mitigation is available. Where appropriate, the project will publish a GitHub security advisory and credit the reporter unless anonymity is requested.
