// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

/**
 * Browser QMS2 adapter.
 *
 * Session cryptography is provided only by the pinned libsignal Rust/WASM
 * backend. This file contains the deterministic QMS2 outer envelope and
 * unchanged tx_extra framing glue shared with Core src/qms/protocol.cpp.
 */
const QmsProtocol = (() => {
  'use strict';

  const C = Object.freeze({
    WIRE_VERSION: 2, PROFILE: 2, ABI_VERSION: 3,
    NONCE_SUBTYPE: 0x72, TX_EXTRA_NONCE: 0x02,
    MAX_TEXT_BYTES: 4096, MAX_CIPHERTEXT_BYTES: 9600,
    MAX_FRAGMENT_DATA_BYTES: 600, MAX_FRAGMENTS: 16,
    FRAGMENT_HEADER_BYTES: 96, MAX_SEGMENT_DATA_BYTES: 248,
    MAX_SEGMENTS_PER_FRAGMENT: 3, MAX_TX_EXTRA_SIZE: 1060,
    ENVELOPE_CLASSES: Object.freeze([1200, 2400, 4800, 7200, 9600]),
    GENESIS_HEX: '4f95857586e2c66063c277370eda99cd75897d773af09f0c3cd1e22f7e87db39',
    WASM_MODULE_URL: '/vendor/qwertycoin-ts/qms2/qwc_qms_crypto.js',
    WASM_BINARY_URL: '/vendor/qwertycoin-ts/qms2/qwc_qms_crypto_bg.wasm'
  });
  const te = new TextEncoder();
  const td = new TextDecoder('utf-8', { fatal: true });
  const MAGIC = te.encode('QMS1');
  const domains = Object.freeze({
    extract: te.encode('QWC-QMS2-HKDF-EXTRACT'),
    envelope: te.encode('QWC-QMS2-ENVELOPE-KEY'),
    discovery: te.encode('QWC-QMS2-DISCOVERY-KEY'),
    fragmentKey: te.encode('QWC-QMS2-FRAGMENT-MAC-KEY'),
    outerAd: te.encode('QWC-QMS2-OUTER-AD'),
    hint: te.encode('QWC-QMS2-DISCOVERY-HINT'),
    fragment: te.encode('QWC-QMS2-FRAGMENT')
  });
  let injectedSignal = null;
  let signalPromise = null;

  function sodiumApi() {
    if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded');
    return sodium;
  }
  async function ready() {
    await sodiumApi().ready;
    await signalApi();
    return QmsProtocol;
  }
  function bytes(value) { return value instanceof Uint8Array ? value : new Uint8Array(value); }
  function concat(...parts) {
    const normalized = parts.map(bytes);
    const out = new Uint8Array(normalized.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of normalized) { out.set(part, offset); offset += part.length; }
    return out;
  }
  function equal(a, b) {
    a = bytes(a); b = bytes(b);
    return a.length === b.length && sodiumApi().memcmp(a, b);
  }
  function hex(input) { return Array.from(bytes(input), value => value.toString(16).padStart(2, '0')).join(''); }
  function unhex(value) {
    if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]*$/i.test(value)) throw new Error('invalid hex');
    const out = new Uint8Array(value.length / 2);
    for (let index = 0; index < out.length; index++) out[index] = parseInt(value.slice(index * 2, index * 2 + 2), 16);
    return out;
  }
  function random(size) { const out = new Uint8Array(size); crypto.getRandomValues(out); return out; }
  function u16(value) { return new Uint8Array([value & 255, (value >>> 8) & 255]); }
  function u32(value) { return new Uint8Array([value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255]); }
  function readU16(input, position) { if (position + 2 > input.length) throw new Error('truncated uint16'); return input[position] | (input[position + 1] << 8); }
  function readU32(input, position) { if (position + 4 > input.length) throw new Error('truncated uint32'); return (input[position] | (input[position + 1] << 8) | (input[position + 2] << 16) | (input[position + 3] << 24)) >>> 0; }
  function requireLength(value, length, label) { value = bytes(value); if (value.length !== length) throw new Error(`invalid ${label}`); return value; }
  function sha256(value) { return sodiumApi().crypto_hash_sha256(bytes(value)); }
  function hmac(key, value) { return sodiumApi().crypto_auth_hmacsha256(bytes(value), bytes(key)); }
  function genesis() { return unhex(C.GENESIS_HEX); }
  function utf8(text) {
    text = String(text);
    for (let index = 0; index < text.length; index++) {
      const unit = text.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (++index >= text.length || text.charCodeAt(index) < 0xdc00 || text.charCodeAt(index) > 0xdfff) throw new Error('message must be valid UTF-8');
      } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('message must be valid UTF-8');
    }
    const result = te.encode(text);
    if (result.length > C.MAX_TEXT_BYTES) throw new Error('message exceeds 4,096 UTF-8 bytes');
    return result;
  }

  function setSignalModuleForTesting(module) { injectedSignal = module; signalPromise = null; }
  function validateSignal(module) {
    const required = ['qwc_qms_wasm_abi_version', 'qwc_qms_wasm_engine_new', 'qwc_qms_wasm_prepare_contact_package', 'qwc_qms_wasm_prepare_import_contact', 'qwc_qms_wasm_prepare_send_text', 'qwc_qms_wasm_prepare_receive_text', 'qwc_qms_wasm_transport_context'];
    for (const name of required) if (!module || typeof module[name] !== 'function') throw new Error(`QMS2 WASM is missing ${name}`);
    if (module.qwc_qms_wasm_abi_version() !== C.ABI_VERSION) throw new Error('QMS2 WASM ABI mismatch');
    return module;
  }
  async function signalApi() {
    if (injectedSignal) return validateSignal(injectedSignal);
    if (!signalPromise) signalPromise = (async () => {
      const module = await import(C.WASM_MODULE_URL);
      if (typeof module.default === 'function') await module.default({ module_or_path: C.WASM_BINARY_URL });
      return validateSignal(module);
    })();
    return signalPromise;
  }
  function parseContactPackage(value) {
    value = bytes(value);
    if (value.length < 52) throw new Error('truncated QMS2 contact package result');
    const packageLength = readU32(value, 48);
    if (!packageLength || 52 + packageLength >= value.length) throw new Error('invalid QMS2 contact package result');
    return { invitationId: value.slice(0, 16), fingerprint: value.slice(16, 48), package: value.slice(52, 52 + packageLength), nextState: value.slice(52 + packageLength) };
  }
  function parseImport(value) {
    value = bytes(value);
    if (value.length <= 32) throw new Error('truncated QMS2 contact import result');
    return { fingerprint: value.slice(0, 32), contactId: hex(value.slice(0, 32)), nextState: value.slice(32) };
  }
  function parseSend(value) {
    value = bytes(value);
    if (value.length < 21) throw new Error('truncated QMS2 send result');
    const ciphertextLength = readU32(value, 17);
    if (!ciphertextLength || 21 + ciphertextLength >= value.length) throw new Error('invalid QMS2 send result');
    return { messageType: value[0], messageId: value.slice(1, 17), ciphertext: value.slice(21, 21 + ciphertextLength), nextState: value.slice(21 + ciphertextLength) };
  }
  function parseReceive(value) {
    value = bytes(value);
    if (value.length < 20) throw new Error('truncated QMS2 receive result');
    const textLength = readU32(value, 16);
    if (textLength > C.MAX_TEXT_BYTES || 20 + textLength >= value.length) throw new Error('invalid QMS2 receive result');
    return { messageId: value.slice(0, 16), text: td.decode(value.slice(20, 20 + textLength)), nextState: value.slice(20 + textLength) };
  }
  function parseContexts(value) {
    value = bytes(value);
    if (value.length < 4) throw new Error('truncated QMS2 transport contexts');
    const count = readU32(value, 0);
    if (!count || value.length !== 4 + count * 97) throw new Error('invalid QMS2 transport context count');
    const result = [];
    for (let index = 0; index < count; index++) {
      const offset = 4 + index * 97;
      if (value[offset + 96] > 1) throw new Error('invalid QMS2 transport direction');
      result.push({ genesis: value.slice(offset, offset + 32), invitationId: value.slice(offset + 32, offset + 48), sessionId: value.slice(offset + 48, offset + 64), rootSecret: value.slice(offset + 64, offset + 96), direction: value[offset + 96] });
    }
    return result;
  }
  const signal = Object.freeze({
    async engineNew() { return bytes((await signalApi()).qwc_qms_wasm_engine_new()); },
    async prepareContactPackage(state, networkGenesis = genesis()) { return parseContactPackage((await signalApi()).qwc_qms_wasm_prepare_contact_package(bytes(state), requireLength(networkGenesis, 32, 'genesis'))); },
    async prepareImportContact(state, invitationId, remotePackage, nowSeconds) { return parseImport((await signalApi()).qwc_qms_wasm_prepare_import_contact(bytes(state), requireLength(invitationId, 16, 'invitation id'), bytes(remotePackage), Number(nowSeconds) >>> 0)); },
    async prepareSendText(state, contactId, text, nowSeconds) { utf8(text); return parseSend((await signalApi()).qwc_qms_wasm_prepare_send_text(bytes(state), String(contactId), String(text), Number(nowSeconds) >>> 0)); },
    async prepareReceiveText(state, contactId, messageType, ciphertext) { return parseReceive((await signalApi()).qwc_qms_wasm_prepare_receive_text(bytes(state), String(contactId), Number(messageType) & 255, bytes(ciphertext))); },
    async transportContexts(state, contactId, outgoing) { return parseContexts((await signalApi()).qwc_qms_wasm_transport_context(bytes(state), String(contactId), !!outgoing)); },
    async transportContext(state, contactId, outgoing) { return (await this.transportContexts(state, contactId, outgoing))[0]; }
  });

  function contextKey(context, info) {
    const saltHash = sha256(concat(domains.extract, requireLength(context.genesis, 32, 'context genesis'), [C.WIRE_VERSION, C.PROFILE]));
    const prk = hmac(saltHash, requireLength(context.rootSecret, 32, 'context root secret'));
    return hmac(prk, concat(info, [C.WIRE_VERSION, C.PROFILE], context.genesis, requireLength(context.invitationId, 16, 'context invitation id'), requireLength(context.sessionId, 16, 'context session id'), [context.direction, 1]));
  }
  function envelopeClass(innerSize) {
    const required = 24 + 16 + 4 + Number(innerSize);
    const result = C.ENVELOPE_CLASSES.find(size => size >= required);
    if (!result) throw new Error('QMS2 inner ciphertext exceeds 9,600-byte envelope');
    return result;
  }
  function envelopeAd(context, messageId, paddedSize) {
    if (context.direction > 1 || !C.ENVELOPE_CLASSES.includes(paddedSize)) throw new Error('invalid QMS2 envelope context');
    return concat(domains.outerAd, context.genesis, [C.WIRE_VERSION, C.PROFILE], requireLength(messageId, 16, 'message id'), [context.direction], u32(paddedSize));
  }
  function sealOuterEnvelope(context, messageId, inner) {
    inner = bytes(inner);
    if (!inner.length || context.direction > 1) throw new Error('invalid QMS2 envelope input');
    const paddedSize = envelopeClass(inner.length);
    const plain = random(paddedSize - 24 - 16);
    plain.set(u32(inner.length)); plain.set(inner, 4);
    const nonce = random(24);
    const ciphertext = sodiumApi().crypto_aead_xchacha20poly1305_ietf_encrypt(plain, envelopeAd(context, messageId, paddedSize), null, nonce, contextKey(context, domains.envelope));
    sodiumApi().memzero(plain);
    if (ciphertext.length !== paddedSize - 24) throw new Error('QMS2 envelope encryption failed');
    return concat(nonce, ciphertext);
  }
  function openOuterEnvelope(context, messageId, envelope) {
    envelope = bytes(envelope);
    if (context.direction > 1 || !C.ENVELOPE_CLASSES.includes(envelope.length)) throw new Error('invalid QMS2 envelope size or direction');
    let plain;
    try { plain = sodiumApi().crypto_aead_xchacha20poly1305_ietf_decrypt(null, envelope.slice(24), envelopeAd(context, messageId, envelope.length), envelope.slice(0, 24), contextKey(context, domains.envelope)); }
    catch (_) { throw new Error('QMS2 envelope authentication failed'); }
    const innerSize = readU32(plain, 0);
    if (!innerSize || innerSize > plain.length - 4 || envelopeClass(innerSize) !== envelope.length) { sodiumApi().memzero(plain); throw new Error('non-canonical QMS2 envelope payload'); }
    const result = plain.slice(4, 4 + innerSize); sodiumApi().memzero(plain); return result;
  }

  function fragmentWithoutMac(fragment) { return concat(MAGIC, [fragment.version, fragment.profile], u16(fragment.flags), fragment.messageId, u16(fragment.index), u16(fragment.count), u32(fragment.ciphertextSize), fragment.discoveryHint, fragment.ciphertextHash); }
  function validateFragment(fragment) {
    if (fragment.version !== C.WIRE_VERSION || fragment.profile !== C.PROFILE || fragment.flags !== 0 || !fragment.count || fragment.count > C.MAX_FRAGMENTS || fragment.index >= fragment.count) throw new Error('invalid QMS2 fragment header');
    requireLength(fragment.messageId, 16, 'fragment message id'); requireLength(fragment.discoveryHint, 16, 'fragment discovery hint'); requireLength(fragment.ciphertextHash, 32, 'fragment ciphertext hash'); requireLength(fragment.mac, 16, 'fragment MAC');
    if (!fragment.data || !fragment.ciphertextSize || fragment.ciphertextSize > C.MAX_CIPHERTEXT_BYTES || fragment.data.length > C.MAX_FRAGMENT_DATA_BYTES) throw new Error('invalid QMS2 fragment size');
    const count = Math.ceil(fragment.ciphertextSize / C.MAX_FRAGMENT_DATA_BYTES);
    const size = fragment.index + 1 === fragment.count ? fragment.ciphertextSize - fragment.index * C.MAX_FRAGMENT_DATA_BYTES : C.MAX_FRAGMENT_DATA_BYTES;
    if (fragment.count !== count || fragment.data.length !== size) throw new Error('non-canonical QMS2 fragment');
  }
  function fragmentInput(fragment) { return concat(domains.fragment, fragmentWithoutMac(fragment), fragment.data); }
  function hintInput(context, messageId) { return concat(domains.hint, context.genesis, [C.WIRE_VERSION, C.PROFILE, context.direction], messageId); }
  function fragmentEnvelope(context, messageId, envelope) {
    envelope = bytes(envelope); messageId = requireLength(messageId, 16, 'message id');
    if (context.direction > 1 || !C.ENVELOPE_CLASSES.includes(envelope.length)) throw new Error('invalid QMS2 fragmentation input');
    const count = Math.ceil(envelope.length / C.MAX_FRAGMENT_DATA_BYTES);
    const hint = hmac(contextKey(context, domains.discovery), hintInput(context, messageId)).slice(0, 16);
    const hash = sha256(envelope), macKey = contextKey(context, domains.fragmentKey), result = [];
    for (let index = 0; index < count; index++) {
      const fragment = { version: C.WIRE_VERSION, profile: C.PROFILE, flags: 0, messageId, index, count, ciphertextSize: envelope.length, discoveryHint: hint, ciphertextHash: hash, mac: new Uint8Array(16), data: envelope.slice(index * 600, Math.min((index + 1) * 600, envelope.length)) };
      fragment.mac = hmac(macKey, fragmentInput(fragment)).slice(0, 16); result.push(fragment);
    }
    return result;
  }
  function verifyEnvelopeFragment(context, fragment) {
    try {
      validateFragment(fragment);
      const hint = hmac(contextKey(context, domains.discovery), hintInput(context, fragment.messageId)).slice(0, 16);
      const mac = hmac(contextKey(context, domains.fragmentKey), fragmentInput(fragment)).slice(0, 16);
      return equal(fragment.discoveryHint, hint) && equal(fragment.mac, mac);
    } catch (_) { return false; }
  }
  function encodeFragment(fragment) { validateFragment(fragment); return concat(fragmentWithoutMac(fragment), fragment.mac, fragment.data); }
  function decodeFragment(input) {
    const value = bytes(input);
    if (value.length < C.FRAGMENT_HEADER_BYTES || !equal(value.slice(0, 4), MAGIC)) throw new Error('invalid QMS2 fragment encoding');
    const fragment = { version: value[4], profile: value[5], flags: readU16(value, 6), messageId: value.slice(8, 24), index: readU16(value, 24), count: readU16(value, 26), ciphertextSize: readU32(value, 28), discoveryHint: value.slice(32, 48), ciphertextHash: value.slice(48, 80), mac: value.slice(80, 96), data: value.slice(96) };
    validateFragment(fragment); return fragment;
  }
  function reassemble(fragments) {
    if (!fragments.length || fragments.length > C.MAX_FRAGMENTS) throw new Error('invalid QMS2 fragment set');
    const map = new Map();
    for (const fragment of fragments) { validateFragment(fragment); if (map.has(fragment.index) && !equal(encodeFragment(map.get(fragment.index)), encodeFragment(fragment))) throw new Error('conflicting QMS2 duplicate'); map.set(fragment.index, fragment); }
    const first = map.get(0); if (!first || map.size !== first.count) throw new Error('incomplete QMS2 fragment set');
    const parts = [];
    for (let index = 0; index < first.count; index++) { const fragment = map.get(index); if (!fragment || !equal(fragment.messageId, first.messageId) || !equal(fragment.ciphertextHash, first.ciphertextHash) || fragment.ciphertextSize !== first.ciphertextSize) throw new Error('inconsistent QMS2 fragments'); parts.push(fragment.data); }
    const result = concat(...parts); if (result.length !== first.ciphertextSize || !equal(sha256(result), first.ciphertextHash)) throw new Error('QMS2 ciphertext hash mismatch'); return result;
  }
  function encodeSegments(fragment) {
    const record = encodeFragment(fragment), count = Math.ceil(record.length / C.MAX_SEGMENT_DATA_BYTES);
    if (!count || count > C.MAX_SEGMENTS_PER_FRAGMENT) throw new Error('QMS2 fragment exceeds nonce budget');
    return Array.from({ length: count }, (_, index) => concat([C.NONCE_SUBTYPE], MAGIC, [index, count], record.slice(index * 248, Math.min((index + 1) * 248, record.length))));
  }
  function decodeSegments(nonces) {
    if (!nonces.length || nonces.length > C.MAX_SEGMENTS_PER_FRAGMENT) throw new Error('invalid QMS2 segment count');
    const map = new Map(); let count = 0;
    for (const raw of nonces) { const value = bytes(raw); if (value.length < 7 || value.length > 255 || value[0] !== C.NONCE_SUBTYPE || !equal(value.slice(1, 5), MAGIC)) throw new Error('invalid QMS2 nonce segment'); if (!count) count = value[6]; if (value[6] !== count || !count || count > 3 || value[5] >= count || map.has(value[5])) throw new Error('invalid QMS2 segment set'); map.set(value[5], value.slice(7)); }
    if (map.size !== count) throw new Error('missing QMS2 segment'); return decodeFragment(concat(...Array.from({ length: count }, (_, index) => map.get(index))));
  }
  function varint(value) { const out = []; do { let part = value & 0x7f; value >>>= 7; if (value) part |= 0x80; out.push(part); } while (value); return new Uint8Array(out); }
  function carrierExtra(fragment) {
    const out = concat(...encodeSegments(fragment).map(nonce => concat([C.TX_EXTRA_NONCE], varint(nonce.length), nonce)));
    if (out.length > C.MAX_TX_EXTRA_SIZE) throw new Error('QMS2 tx_extra exceeds relay limit'); return out;
  }
  function extractSegmentsFromExtra(input) {
    const value = bytes(input), result = []; let position = 0;
    function readVarint() { let parsed = 0, shift = 0, octet, count = 0; do { if (position >= value.length || shift > 28) throw new Error('invalid tx_extra varint'); octet = value[position++]; parsed |= (octet & 0x7f) << shift; shift += 7; count++; } while (octet & 0x80); if (count > 1 && (octet & 0x7f) === 0) throw new Error('non-canonical tx_extra varint'); return parsed >>> 0; }
    while (position < value.length) {
      const tag = readVarint();
      if (tag === 0) { while (position < value.length) if (value[position++] !== 0) throw new Error('tx_extra padding must be terminal'); break; }
      if (tag === 1) { if (position + 32 > value.length) throw new Error('truncated tx public key'); position += 32; continue; }
      if (![C.TX_EXTRA_NONCE, 3, 4, 5, 0xde].includes(tag)) throw new Error('unsupported tx_extra field');
      const length = readVarint(); if (position + length > value.length) throw new Error('truncated length-delimited tx_extra field');
      const field = value.slice(position, position + length); position += length;
      if (tag === C.TX_EXTRA_NONCE && field[0] === C.NONCE_SUBTYPE) result.push(field);
    }
    return result;
  }

  return { C, ready, bytes, concat, equal, hex, unhex, random, genesis, utf8, signal, setSignalModuleForTesting, contextKey, sealOuterEnvelope, openOuterEnvelope, fragmentEnvelope, verifyEnvelopeFragment, encodeFragment, decodeFragment, reassemble, encodeSegments, decodeSegments, carrierExtra, extractSegmentsFromExtra };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QmsProtocol;
