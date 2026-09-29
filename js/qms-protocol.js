// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/** Byte-for-byte browser implementation of QMS1 (Core src/qms/protocol.cpp). */
const QmsProtocol = (() => {
  'use strict';

  const C = Object.freeze({
    WIRE_VERSION: 1, PROFILE: 1, NONCE_SUBTYPE: 0x72, TX_EXTRA_NONCE: 0x02,
    MAX_TEXT_BYTES: 4096, MAX_CIPHERTEXT_BYTES: 9600,
    MAX_FRAGMENT_DATA_BYTES: 600, MAX_FRAGMENTS: 16,
    FRAGMENT_HEADER_BYTES: 96, MAX_SEGMENT_DATA_BYTES: 248,
    MAX_SEGMENTS_PER_FRAGMENT: 3, MAX_TX_EXTRA_SIZE: 1060,
    GENESIS_HEX: '4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39'
  });
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });
  const MAGIC = te.encode('QMS1');
  const domains = Object.freeze({
    signed: te.encode('QWC-QMS-SIGNED-MESSAGE-V1'),
    invite: te.encode('QWC-QMS-INVITATION-V1'),
    hint: te.encode('QWC-QMS-DISCOVERY-HINT-V1'),
    extract: te.encode('QWC-QMS-HKDF-EXTRACT-V1'),
    discovery: te.encode('QWC-QMS-DISCOVERY-KEY-V1'),
    fragmentKey: te.encode('QWC-QMS-FRAGMENT-MAC-KEY-V1'),
    fragment: te.encode('QWC-QMS-FRAGMENT-V1'),
    fingerprint: te.encode('QWC-QMS-FINGERPRINT-V1')
  });

  function sodiumApi() {
    if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded');
    return sodium;
  }
  async function ready() { await sodiumApi().ready; return sodiumApi(); }
  function bytes(value) { return value instanceof Uint8Array ? value : new Uint8Array(value); }
  function concat(...parts) {
    const size = parts.reduce((n, p) => n + bytes(p).length, 0);
    const out = new Uint8Array(size); let pos = 0;
    for (const part of parts) { const b = bytes(part); out.set(b, pos); pos += b.length; }
    return out;
  }
  function equal(a, b) {
    a = bytes(a); b = bytes(b); if (a.length !== b.length) return false;
    return sodiumApi().memcmp(a, b);
  }
  function u16(value) { return new Uint8Array([value & 255, (value >>> 8) & 255]); }
  function u32(value) { return new Uint8Array([value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255]); }
  function readU16(input, pos) { if (pos + 2 > input.length) throw new Error('truncated uint16'); return input[pos] | (input[pos + 1] << 8); }
  function readU32(input, pos) { if (pos + 4 > input.length) throw new Error('truncated uint32'); return (input[pos] | (input[pos + 1] << 8) | (input[pos + 2] << 16) | (input[pos + 3] << 24)) >>> 0; }
  function hex(input) { return Array.from(bytes(input), b => b.toString(16).padStart(2, '0')).join(''); }
  function unhex(value) {
    if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]*$/i.test(value)) throw new Error('invalid hex');
    const out = new Uint8Array(value.length / 2); for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16); return out;
  }
  function random(size) { const out = new Uint8Array(size); crypto.getRandomValues(out); return out; }
  function sha256(value) { return sodiumApi().crypto_hash_sha256(bytes(value)); }
  function hmac(key, value) { return sodiumApi().crypto_auth_hmacsha256(bytes(value), bytes(key)); }
  function genesis() { return unhex(C.GENESIS_HEX); }
  function requireLength(value, size, label) { value = bytes(value); if (value.length !== size) throw new Error(`invalid ${label}`); return value; }
  function utf8(text) {
    text = String(text);
    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (++i >= text.length) throw new Error('message must be valid UTF-8');
        const low = text.charCodeAt(i);
        if (low < 0xdc00 || low > 0xdfff) throw new Error('message must be valid UTF-8');
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new Error('message must be valid UTF-8');
      }
    }
    return te.encode(text);
  }

  function fingerprint(boxPublic, signPublic) {
    return sha256(concat(domains.fingerprint, requireLength(boxPublic, 32, 'box public key'), requireLength(signPublic, 32, 'sign public key')));
  }
  function invitationUnsigned(inv) {
    return concat(domains.invite, [inv.version, inv.profile], inv.genesis, inv.invitationId, inv.boxPublic, inv.signPublic, inv.discoverySecret);
  }
  function verifyInvitation(inv) {
    try {
      requireLength(inv.genesis, 32, 'invitation genesis');
      requireLength(inv.invitationId, 16, 'invitation id');
      requireLength(inv.boxPublic, 32, 'box public key');
      requireLength(inv.signPublic, 32, 'sign public key');
      requireLength(inv.discoverySecret, 32, 'discovery secret');
      requireLength(inv.signature, 64, 'invitation signature');
      return inv.version === C.WIRE_VERSION && inv.profile === C.PROFILE &&
        sodiumApi().crypto_sign_verify_detached(inv.signature, invitationUnsigned(inv), inv.signPublic);
    } catch (_) { return false; }
  }
  function createIdentity() {
    const box = sodiumApi().crypto_box_keypair(); const sign = sodiumApi().crypto_sign_keypair();
    return { boxPublic: box.publicKey, boxSecret: box.privateKey, signPublic: sign.publicKey, signSecret: sign.privateKey };
  }
  function createInvitation(identity, networkGenesis = genesis()) {
    const inv = { version: C.WIRE_VERSION, profile: C.PROFILE, genesis: requireLength(networkGenesis, 32, 'genesis'), invitationId: random(16), boxPublic: identity.boxPublic, signPublic: identity.signPublic, discoverySecret: random(32) };
    inv.signature = sodiumApi().crypto_sign_detached(invitationUnsigned(inv), identity.signSecret); return inv;
  }
  function encodeInvitation(inv) {
    if (!verifyInvitation(inv)) throw new Error('invalid QMS invitation');
    return concat(MAGIC, [inv.version, inv.profile], inv.genesis, inv.invitationId, inv.boxPublic, inv.signPublic, inv.discoverySecret, inv.signature);
  }
  function decodeInvitation(encoded) {
    const b = bytes(encoded); if (b.length !== 214 || !equal(b.slice(0, 4), MAGIC)) throw new Error('invalid QMS invitation encoding');
    const inv = { version: b[4], profile: b[5], genesis: b.slice(6, 38), invitationId: b.slice(38, 54), boxPublic: b.slice(54, 86), signPublic: b.slice(86, 118), discoverySecret: b.slice(118, 150), signature: b.slice(150, 214) };
    if (!verifyInvitation(inv)) throw new Error('invalid QMS invitation signature or profile'); return inv;
  }

  function sealText(identity, recipient, messageId, text) {
    if (!verifyInvitation(recipient) || !equal(recipient.genesis, genesis())) throw new Error('recipient invitation mismatch');
    const textBytes = utf8(text); if (textBytes.length > C.MAX_TEXT_BYTES) throw new Error('message exceeds 4,096 UTF-8 bytes');
    const body = concat(domains.signed, [C.WIRE_VERSION, C.PROFILE], genesis(), requireLength(messageId, 16, 'message id'), recipient.invitationId,
      fingerprint(identity.boxPublic, identity.signPublic), fingerprint(recipient.boxPublic, recipient.signPublic), [1], u32(textBytes.length), textBytes);
    const signature = sodiumApi().crypto_sign_detached(body, identity.signSecret);
    const ciphertext = sodiumApi().crypto_box_seal(concat(body, signature), recipient.boxPublic);
    if (ciphertext.length > C.MAX_CIPHERTEXT_BYTES) throw new Error('QMS ciphertext exceeds transport limit'); return ciphertext;
  }
  function openTextEnvelope(identity, ownInvitation, expectedMessageId, ciphertext) {
    ciphertext = bytes(ciphertext);
    if (!verifyInvitation(ownInvitation)) throw new Error('untrusted QMS invitation');
    if (!equal(ownInvitation.genesis, genesis())) throw new Error('QMS genesis mismatch');
    if (ciphertext.length < 48 || ciphertext.length > C.MAX_CIPHERTEXT_BYTES) throw new Error('invalid QMS ciphertext size');
    const plain = sodiumApi().crypto_box_seal_open(ciphertext, identity.boxPublic, identity.boxSecret);
    if (!plain || plain.length < 64) throw new Error('QMS decryption failed');
    const body = plain.slice(0, -64), signature = plain.slice(-64);
    let p = 0; const take = n => { if (p + n > body.length) throw new Error('truncated QMS signed message'); const out = body.slice(p, p + n); p += n; return out; };
    if (!equal(take(domains.signed.length), domains.signed) || take(1)[0] !== C.WIRE_VERSION || take(1)[0] !== C.PROFILE) throw new Error('QMS signed profile mismatch');
    if (!equal(take(32), genesis())) throw new Error('QMS signed genesis mismatch');
    const messageId = take(16); if (!equal(messageId, expectedMessageId)) throw new Error('QMS signed message id mismatch');
    if (!equal(take(16), ownInvitation.invitationId)) throw new Error('QMS invitation id mismatch');
    const senderFingerprint = take(32);
    if (!equal(take(32), fingerprint(identity.boxPublic, identity.signPublic))) throw new Error('QMS recipient fingerprint mismatch');
    if (take(1)[0] !== 1) throw new Error('unsupported QMS content type');
    const textSize = readU32(body, p); p += 4; if (textSize > C.MAX_TEXT_BYTES || p + textSize !== body.length) throw new Error('invalid QMS text size');
    return { body, signature, messageId, invitationId: ownInvitation.invitationId, senderFingerprint, textBytes: take(textSize) };
  }
  function authenticateTextEnvelope(opened, sender) {
    if (!opened || !verifyInvitation(sender) || !equal(sender.genesis, genesis())) throw new Error('untrusted QMS sender invitation');
    if (!equal(opened.senderFingerprint, fingerprint(sender.boxPublic, sender.signPublic))) throw new Error('QMS pinned sender fingerprint mismatch');
    if (!sodiumApi().crypto_sign_verify_detached(opened.signature, opened.body, sender.signPublic)) throw new Error('QMS sender signature verification failed');
    return { messageId: opened.messageId, invitationId: opened.invitationId, text: td.decode(opened.textBytes) };
  }
  function openText(identity, sender, ownInvitation, expectedMessageId, ciphertext) {
    return authenticateTextEnvelope(openTextEnvelope(identity, ownInvitation, expectedMessageId, ciphertext), sender);
  }

  function hkdfKey(secret, info, inv) {
    const saltHash = sha256(concat(domains.extract, genesis())); const prk = hmac(saltHash, secret);
    return hmac(prk, concat(info, [C.WIRE_VERSION, C.PROFILE], genesis(), inv.invitationId, fingerprint(inv.boxPublic, inv.signPublic), [1]));
  }
  function fragmentWithoutMac(f) { return concat(MAGIC, [f.version, f.profile], u16(f.flags), f.messageId, u16(f.index), u16(f.count), u32(f.ciphertextSize), f.discoveryHint, f.ciphertextHash); }
  function validateFragment(f) {
    if (f.version !== 1 || f.profile !== 1 || f.flags !== 0 || !f.count || f.count > 16 || f.index >= f.count) throw new Error('invalid QMS fragment header');
    requireLength(f.messageId, 16, 'fragment message id');
    requireLength(f.discoveryHint, 16, 'fragment discovery hint');
    requireLength(f.ciphertextHash, 32, 'fragment ciphertext hash');
    if (!f.data || !f.ciphertextSize || f.ciphertextSize > C.MAX_CIPHERTEXT_BYTES || f.data.length > 600) throw new Error('invalid QMS fragment size');
    const count = Math.ceil(f.ciphertextSize / 600), size = f.index + 1 === f.count ? f.ciphertextSize - f.index * 600 : 600;
    if (f.count !== count || f.data.length !== size) throw new Error('non-canonical QMS fragment');
  }
  function fragmentCiphertext(recipient, messageId, ciphertext) {
    ciphertext = bytes(ciphertext);
    messageId = requireLength(messageId, 16, 'message id');
    if (!verifyInvitation(recipient) || !equal(recipient.genesis, genesis()) || !ciphertext.length || ciphertext.length > C.MAX_CIPHERTEXT_BYTES) throw new Error('invalid QMS fragmentation input');
    const count = Math.ceil(ciphertext.length / 600); if (!count || count > 16) throw new Error('too many QMS fragments');
    const hintKey = hkdfKey(recipient.discoverySecret, domains.discovery, recipient), macKey = hkdfKey(recipient.discoverySecret, domains.fragmentKey, recipient);
    const hint = hmac(hintKey, concat(domains.hint, genesis(), messageId)).slice(0, 16), hash = sha256(ciphertext), result = [];
    for (let index = 0; index < count; index++) {
      const f = { version: 1, profile: 1, flags: 0, messageId, index, count, ciphertextSize: ciphertext.length, discoveryHint: hint, ciphertextHash: hash, data: ciphertext.slice(index * 600, Math.min((index + 1) * 600, ciphertext.length)) };
      f.mac = hmac(macKey, concat(domains.fragment, fragmentWithoutMac(f), f.data)).slice(0, 16); result.push(f);
    } return result;
  }
  function encodeFragment(f) { validateFragment(f); return concat(fragmentWithoutMac(f), requireLength(f.mac, 16, 'fragment MAC'), f.data); }
  function decodeFragment(input) {
    const b = bytes(input); if (b.length < 96 || !equal(b.slice(0, 4), MAGIC)) throw new Error('invalid QMS fragment encoding');
    const f = { version: b[4], profile: b[5], flags: readU16(b, 6), messageId: b.slice(8, 24), index: readU16(b, 24), count: readU16(b, 26), ciphertextSize: readU32(b, 28), discoveryHint: b.slice(32, 48), ciphertextHash: b.slice(48, 80), mac: b.slice(80, 96), data: b.slice(96) }; validateFragment(f); return f;
  }
  function verifyFragment(inv, f) {
    try { validateFragment(f); if (!verifyInvitation(inv) || !equal(inv.genesis, genesis())) return false; const hintKey = hkdfKey(inv.discoverySecret, domains.discovery, inv), macKey = hkdfKey(inv.discoverySecret, domains.fragmentKey, inv);
      return equal(f.discoveryHint, hmac(hintKey, concat(domains.hint, genesis(), f.messageId)).slice(0, 16)) && equal(f.mac, hmac(macKey, concat(domains.fragment, fragmentWithoutMac(f), f.data)).slice(0, 16));
    } catch (_) { return false; }
  }
  function reassemble(fragments) {
    if (!fragments.length || fragments.length > 16) throw new Error('invalid QMS fragment set'); const map = new Map();
    for (const f of fragments) { validateFragment(f); const key = f.index; if (map.has(key) && !equal(encodeFragment(map.get(key)), encodeFragment(f))) throw new Error('conflicting QMS duplicate'); map.set(key, f); }
    const first = map.get(0); if (!first || map.size !== first.count) throw new Error('incomplete QMS fragment set'); const parts = [];
    for (let i = 0; i < first.count; i++) { const f = map.get(i); if (!f || !equal(f.messageId, first.messageId) || !equal(f.ciphertextHash, first.ciphertextHash) || f.ciphertextSize !== first.ciphertextSize) throw new Error('inconsistent QMS fragments'); parts.push(f.data); }
    const result = concat(...parts); if (result.length !== first.ciphertextSize || !equal(sha256(result), first.ciphertextHash)) throw new Error('QMS ciphertext hash mismatch'); return result;
  }
  function encodeSegments(f) {
    const record = encodeFragment(f), count = Math.ceil(record.length / 248); if (!count || count > 3) throw new Error('QMS fragment exceeds nonce budget'); const out = [];
    for (let i = 0; i < count; i++) out.push(concat([C.NONCE_SUBTYPE], MAGIC, [i, count], record.slice(i * 248, Math.min((i + 1) * 248, record.length)))); return out;
  }
  function decodeSegments(nonces) {
    if (!nonces.length || nonces.length > 3) throw new Error('invalid QMS segment count'); const map = new Map(); let count = 0;
    for (const raw of nonces) { const n = bytes(raw); if (n.length < 7 || n.length > 255 || n[0] !== 0x72 || !equal(n.slice(1, 5), MAGIC)) throw new Error('invalid QMS nonce segment'); if (!count) count = n[6]; if (n[6] !== count || !count || count > 3 || n[5] >= count || map.has(n[5])) throw new Error('invalid QMS segment set'); map.set(n[5], n.slice(7)); }
    if (map.size !== count) throw new Error('missing QMS segment'); return decodeFragment(concat(...Array.from({ length: count }, (_, i) => map.get(i))));
  }
  function varint(value) { const out = []; do { let b = value & 0x7f; value >>>= 7; if (value) b |= 0x80; out.push(b); } while (value); return new Uint8Array(out); }
  function carrierExtra(f) {
    const fields = encodeSegments(f).map(n => concat([C.TX_EXTRA_NONCE], varint(n.length), n)); const out = concat(...fields);
    if (out.length > C.MAX_TX_EXTRA_SIZE) throw new Error('QMS tx_extra exceeds relay limit'); return out;
  }
  function extractSegmentsFromExtra(input) {
    const b = bytes(input), result = []; let p = 0;
    const readVarint = () => {
      let value = 0, shift = 0, octet, count = 0;
      do {
        if (p >= b.length || shift > 28) throw new Error('invalid tx_extra varint');
        octet = b[p++]; value |= (octet & 0x7f) << shift; shift += 7; count += 1;
      } while (octet & 0x80);
      if (count > 1 && (octet & 0x7f) === 0) throw new Error('non-canonical tx_extra varint');
      return value >>> 0;
    };
    const skipBytes = (length, label) => {
      if (!Number.isSafeInteger(length) || length < 0 || length > b.length - p) throw new Error(`truncated ${label}`);
      const start = p;
      p += length;
      return b.slice(start, p);
    };
    while (p < b.length) {
      const tag = readVarint();
      if (tag === 0x00) {
        let padding = 1;
        while (p < b.length) {
          if (b[p++] !== 0) throw new Error('tx_extra padding must be terminal');
          if (++padding > 255) throw new Error('tx_extra padding exceeds limit');
        }
        break;
      }
      if (tag === 0x01) { skipBytes(32, 'tx public key'); continue; }
      if (tag === 0x04) {
        const count = readVarint();
        if (count > Math.floor((b.length - p) / 32)) throw new Error('truncated additional tx public keys');
        skipBytes(count * 32, 'additional tx public keys');
        continue;
      }
      if (![C.TX_EXTRA_NONCE, 0x03, 0x05, 0xde].includes(tag)) throw new Error('unsupported tx_extra field');
      const field = skipBytes(readVarint(), 'length-delimited tx_extra field');
      if (tag === C.TX_EXTRA_NONCE && field[0] === C.NONCE_SUBTYPE) result.push(field);
    } return result;
  }

  return { C, ready, hex, unhex, equal, random, genesis, fingerprint, createIdentity, createInvitation, encodeInvitation, decodeInvitation, verifyInvitation, sealText, openTextEnvelope, authenticateTextEnvelope, openText, fragmentCiphertext, encodeFragment, decodeFragment, verifyFragment, reassemble, encodeSegments, decodeSegments, carrierExtra, extractSegmentsFromExtra };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsProtocol;
