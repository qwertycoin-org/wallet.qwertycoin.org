# Qwertycoin Web Wallet visual-alignment evidence

Date: 2026-09-12

Wallet baseline: `69eb5e13d36b51bcd0e5ef69a88ce15becd023e0`

Design reference: `qwertycoin-org/qwertycoin-org.github.io@cad291f45602e44c94f756c5592167771dee7681`

## Scope and invariants

This change is presentation-only. It adds the approved Qwertycoin mark, local
Archivo/Inter fonts, the cream/black/gold/violet visual system, responsive
layout rules, and a complete favicon matrix. Wallet creation/restoration,
session storage, encryption, RPC, scanning, amounts, fees, transaction
construction/signing/relay, and all functional event handlers are unchanged.

The 44-file JavaScript/Worker/server baseline and the post-change set have the
same aggregate SHA-256 manifest:

`31cfa01b7bdb03f9de244af3d54ea1586af2e9e768e76d4ab39544563890fa95`

The redesign intentionally preserves functional IDs/classes and inline
`display`/`hidden` state ownership. The shared stylesheet is loaded after the
legacy page styles and overrides presentation only.

## Visual coverage

The browser matrix exercised:

- seed, private-spend-key, watch-only, and create tabs;
- newly generated throwaway wallet and dashboard;
- balance/loading/network/error states;
- send form, receive QR, unlock, rate-limit, and QR-scanner dialogs;
- keys (still blurred), mnemonic, subaddresses, custom node, export, and disconnect;
- privacy and self-host documents;
- 360, 390, 768, 1024, and 1440 px widths plus a 1440 px viewport at 200% zoom equivalence.

No real seed, private wallet data, or Mainnet transfer was used. Screenshots
contain only an isolated generated throwaway wallet; private values remain
visually obscured.

## Before / after

### Wallet access — desktop

| Before | After |
| --- | --- |
| ![Previous wallet access](screenshots/before/verify-desktop.webp) | ![Redesigned wallet access](screenshots/after/verify-desktop.webp) |

### Wallet access — 390 px

| Before | After |
| --- | --- |
| ![Previous wallet access mobile](screenshots/before/verify-mobile.webp) | ![Redesigned wallet access mobile](screenshots/after/verify-mobile.webp) |

### Dashboard — desktop

| Before | After |
| --- | --- |
| ![Previous dashboard](screenshots/before/dashboard-desktop.webp) | ![Redesigned dashboard](screenshots/after/dashboard-desktop.webp) |

### Send and receive

| Send | Receive |
| --- | --- |
| ![Redesigned send dialog](screenshots/after/send-desktop.webp) | ![Redesigned receive dialog](screenshots/after/receive-desktop.webp) |

Additional evidence is in [`screenshots/after`](screenshots/after), including
mobile dialogs, create/watch-only states, unlock, rate-limit, QR scanner,
privacy, and self-host pages.

## Verification

| Check | Result |
| --- | --- |
| Existing wallet tests | 44/44 PASS |
| Presentation-contract tests | 7/7 PASS |
| Manifest build and `--check` | 66/66 files PASS |
| Protected logic hash comparison | byte-identical PASS |
| Responsive overflow matrix | 24/24 page/viewport combinations PASS |
| Browser interaction/state checks | PASS |
| Unexpected failed asset requests | 0 |
| HTML structural validation | no structural errors |

The Python static preview cannot execute Cloudflare Functions, so its controlled
dashboard run intentionally receives HTTP 501 for `/api/proxy` and exercises
the existing node-error state. The deployed PR preview is checked separately
against the real same-origin proxy before approval.

## Lighthouse (local, commit under review)

Chrome headless, Lighthouse defaults for mobile and `--preset=desktop` for
desktop, served from the local static preview. Scores are
Performance / Accessibility / Best Practices / SEO.

| Page/profile | Scores | LCP | CLS | TBT |
| --- | --- | ---: | ---: | ---: |
| Verify / mobile | 87 / 100 / 100 / 100 | 3,990 ms | 0.0037 | 23 ms |
| Verify / desktop | 99 / 100 / 100 / 100 | 847 ms | 0.0013 | 0 ms |
| Privacy / mobile | 100 / 100 / 100 / 100 | 1,656 ms | 0.0146 | 0 ms |
| Privacy / desktop | 100 / 100 / 100 / 100 | 363 ms | 0.0107 | 0 ms |

The local mobile Verify result is dominated by the existing synchronous wallet
and wordlist payload on Lighthouse's throttled profile, served without edge
compression. Script order and wallet loading semantics were intentionally not
changed in a presentation-only PR. The compressed deployment preview is the
release-facing measurement.

## Asset delivery

- Original Q mark is copied byte-for-byte from the approved website source.
- Archivo 900 and Inter 400/600 are local, content-addressed WOFF2 files.
- Font licensing is shipped in `fonts/LICENSES.md`.
- SVG, 16 px PNG, 32 px PNG, multi-size ICO, 180 px Apple touch, and 192 px
  icons all use the approved Q mark.
- New CSS, icons, fonts, and license data are included in `MANIFEST.txt`.
- Presentation assets remain same-origin; no font CDN, analytics, or new
  runtime dependency is introduced.

## Known limitations outside this visual scope

The existing `privacy.html` and `self-host.html` prose still contains inherited
Monero-era wording and URLs. The brief explicitly requires their factual
content/instructions to remain unchanged in this presentation-only change, so
the issue is documented instead of silently mixing editorial and visual work.
No new theme switch was added because the wallet has no existing theme control.
