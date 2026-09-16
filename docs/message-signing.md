# Message signing and pool challenges

The Web Wallet creates and verifies Qwertycoin-compatible message signatures
inside the bundled `qwertycoin-ts` worker/WASM. Signing uses the wallet spend
key and does not send the message, signature or private key to the RPC gateway.
Verification is also local and is available to watch-only wallets.

## Sign or verify a message

1. Load the wallet that controls the address and open **Sign / Verify**.
2. To sign, paste or type the message in **Sign message**, then create and copy
   the spend-key signature.
3. To verify, enter the signing address, the exact message and the complete
   signature in **Verify signature**.

The message is encoded as UTF-8 exactly as entered, up to 16,384 bytes. The
wallet does not trim whitespace, rewrite line endings or normalize Unicode.
Browser text fields represent entered line breaks as `LF`; pasted or dropped
text containing `CR` or `CRLF` is therefore rejected before insertion instead
of being silently normalized. Use a Core wallet interface that preserves those
bytes if an existing signature covers `CR` or `CRLF`. A trailing space and
composed versus decomposed Unicode are also different signed messages. The
address and signature fields may have surrounding whitespace removed during
verification; the message field never does.

New signatures are spend-key `SigV2` signatures compatible with the existing
Qwertycoin Core wallet verifier. A valid signature proves control of the
address spend key for those exact message bytes; it does not move funds or
prove that a statement is true. Read and independently confirm any message
before signing it.

## Pool payout challenge format

The **Pool challenge** tab only accepts this exact six-line format, with `LF`
line endings and no trailing newline:

```text
Qwertycoin pool payout threshold
Address: QWC...
Threshold: 2500.125 QWC
Nonce: 0123456789abcdef0123456789abcdef0123456789abcdef
Expires: 2026-09-16T13:05:00.000Z
Domain: pool.qwertycoin.org
```

Rules:

- `Address` must exactly equal the address of the loaded wallet.
- `Threshold` must be canonical QWC decimal text from 1,000 through 10,000,000
  QWC, with at most eight decimal places and no redundant leading or trailing
  zeros. `1000` and `2500.125` are valid; `01000`, `1000.0` and signed values
  are not.
- `Nonce` is 24 cryptographically random bytes encoded as 48 lowercase
  hexadecimal characters.
- `Expires` is canonical UTC ISO 8601 with milliseconds. The challenge must be
  unexpired and have a lifetime of no more than ten minutes. The signer allows
  up to one additional minute for clock skew; issuers should not rely on it.
- `Domain` is exactly `pool.qwertycoin.org`.
- Field names, order, spaces, case and bytes are fixed. Do not reconstruct,
  trim, normalize or convert line endings.

The generic signing tab refuses text that starts like a pool challenge. This
ensures that the address, threshold, expiry and domain are shown for explicit
confirmation before the spend-key signature is created.

## Pool integration requirements

The browser checks protect the signer, but they are not pool-side
authorization. A pool accepting these signatures must:

1. Generate the nonce with a CSPRNG and store an issued record containing the
   nonce, account, address, threshold, expiry, exact challenge bytes and an
   unused state.
2. Deliver those exact `LF` bytes to the user. Avoid transports or widgets
   that silently convert line endings or Unicode.
3. On submission, locate the issued record and compare the submitted message
   byte-for-byte with the stored challenge. Never rebuild the message from
   submitted fields.
4. Recheck the account, address, threshold, domain and expiry against trusted
   server state and the server clock.
5. Verify the signature through a Qwertycoin Core/wallet-RPC-compatible
   message verifier and require a successful **spend-key** signature. Reject
   view-key, unknown-type and malformed signatures.
6. Atomically change the nonce from unused to consumed as part of accepting
   the threshold change. Concurrent or later submissions of the same nonce
   must fail.
7. Rate-limit challenge creation and verification. Log only non-secret audit
   metadata; never log wallet seeds, private keys or other credentials.

Reject unknown, expired, consumed or mismatched challenges even when a
signature is otherwise valid. A signature over an arbitrary message is not a
substitute for an issued challenge, and client-side validation is not a
substitute for server-side replay protection.

## Security notes

- Use a trusted wallet origin and a browser environment without hostile
  extensions. Local signing cannot protect a compromised browser or served
  application.
- Treat signatures as public proof. Clipboard contents and any submitted
  signature can be retained by another party.
- Message signing is independent of wallet balance and does not require a
  transaction or network connection after the worker assets are loaded.
- For high-impact authorization, compare the exact message through a separate
  trusted channel before signing.
