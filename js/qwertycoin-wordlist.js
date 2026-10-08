// SPDX-License-Identifier: MIT
/**
 * qwertycoin-wordlist.js
 * Qwertycoin mnemonic word-list handler
 *
 * The actual word list (1626 words) is inherited from the canonical upstream
 * CryptoNote implementation and registered via QwertycoinWordList.register().
 * 
 * Download the English list from:
 *   https://raw.githubusercontent.com/monero-project/monero/master/src/mnemonics/english.h
 *
 * This module provides:
 *   - Word list registration and lookup
 *   - Checksum verification  
 *   - 3-word-group → bytes decoding
 */

const QwertycoinWordList = (function () {
  'use strict';

  const lists = {};

  function prefixByCodePoint(word, length) {
    return Array.from(word).slice(0, length).join('');
  }

  function foldWord(word) {
    return word.trim().toLowerCase();
  }

  function register(lang, words, prefixLen, flags) {
    flags = flags || 0;
    const ALLOW_DUPLICATE_PREFIXES = 1;
    if (words.length !== 1626) {
      throw new Error(`Word list must have exactly 1626 entries, got ${words.length}`);
    }
    const map = {};       // prefix → Core-compatible index for abbreviated input
    const fullMap = {};   // full lowercased word → index (exact lookup)
    for (let i = 0; i < words.length; i++) {
      const w = foldWord(words[i]);
      const key = prefixByCodePoint(w, prefixLen);
      if (map[key] !== undefined && !(flags & ALLOW_DUPLICATE_PREFIXES)) {
        throw new Error(`Duplicate prefix "${key}" at index ${i}`);
      }
      // Core's trimmed-word map overwrites duplicate prefixes. Exact full-word
      // lookup still runs first, so this only affects explicitly abbreviated
      // legacy-English input and keeps that fallback aligned with Core.
      map[key] = i;
      fullMap[w] = i;
    }
    lists[lang] = { words, prefixLen, map, fullMap, flags };
  }

  function lookup(lang, word) {
    const list = lists[lang];
    if (!list) throw new Error(`Word list not loaded: ${lang}`);
    const w = foldWord(word);
    // Always try full-word match first — this is the only correct lookup
    // when the wordlist has duplicate prefixes (legacy English).
    if (list.fullMap[w] !== undefined) return list.fullMap[w];
    // Fall back to prefix-truncated lookup for users who entered the
    // shortened prefix form of a word (allowed by the Qwertycoin CLI).
    const prefix = prefixByCodePoint(w, list.prefixLen);
    const idx = list.map[prefix];
    return idx !== undefined ? idx : -1;
  }

  function wordAt(lang, index) {
    const list = lists[lang];
    if (!list) throw new Error(`Word list not loaded: ${lang}`);
    return list.words[index];
  }

  function verifyChecksum(lang, words) {
    const list = lists[lang];
    if (!list) throw new Error(`Word list not loaded: ${lang}`);
    if (!Array.isArray(words) || words.length < 2) return false;
    const dataWords = words.slice(0, words.length - 1);
    const checksumWord = words[words.length - 1];
    let prefixStr;
    try {
      prefixStr = canonicalPrefixes(lang, dataWords);
    } catch (_) {
      return false;
    }
    const crc = crc32(prefixStr);
    const expectedIdx = ((crc >>> 0) % dataWords.length);
    const expectedWordIndex = lookup(lang, dataWords[expectedIdx]);
    const expectedPrefix = prefixByCodePoint(
      foldWord(list.words[expectedWordIndex]),
      list.prefixLen
    );
    const actualPrefix = prefixByCodePoint(foldWord(checksumWord), list.prefixLen);
    return lookup(lang, checksumWord) >= 0 && expectedPrefix === actualPrefix;
  }

  // Compatibility for phrases created by older Web Wallet releases. Those
  // releases lowercased every prefix and fed JavaScript UTF-16 code units into
  // CRC-32. This verifier is intentionally separate from the canonical path so
  // callers can migrate an exact legacy-browser phrase instead of weakening
  // normal Core-compatible checksum validation.
  function verifyLegacyBrowserChecksum(lang, words) {
    const list = lists[lang];
    if (!list || !Array.isArray(words) || words.length < 2) return false;

    for (const word of words) {
      if (lookup(lang, word) < 0) return false;
    }

    const dataWords = words.slice(0, words.length - 1);
    const checksumWord = words[words.length - 1];
    const prefixStr = dataWords.map(word =>
      foldWord(word).substring(0, list.prefixLen)
    ).join('');
    const expectedIdx = legacyBrowserCrc32(prefixStr) % dataWords.length;
    return foldWord(dataWords[expectedIdx]) === foldWord(checksumWord);
  }

  function decodeWords(lang, dataWords) {
    const N = 1626;
    const indices = dataWords.map(w => {
      const idx = lookup(lang, w);
      if (idx < 0) throw new Error(`Unknown word: "${w}"`);
      return idx;
    });
    if (indices.length % 3 !== 0) {
      throw new Error(`Data word count must be divisible by 3, got ${indices.length}`);
    }
    const seed = new Uint8Array((indices.length / 3) * 4);
    for (let i = 0; i < indices.length; i += 3) {
      const w1 = indices[i], w2 = indices[i + 1], w3 = indices[i + 2];
      let val = w1 + N * ((w2 - w1 + N * 2) % N) + N * N * ((w3 - w2 + N * 2) % N);
      const off = (i / 3) * 4;
      seed[off] = val & 0xff;
      seed[off + 1] = (val >>> 8) & 0xff;
      seed[off + 2] = (val >>> 16) & 0xff;
      seed[off + 3] = (val >>> 24) & 0xff;
    }
    return seed;
  }

  function encodeBytes(lang, seedBytes) {
    const list = lists[lang];
    if (!list) throw new Error(`Word list not loaded: ${lang}`);
    const N = 1626;
    if (seedBytes.length % 4 !== 0) {
      throw new Error(`Seed byte length must be divisible by 4, got ${seedBytes.length}`);
    }
    const words = [];
    for (let i = 0; i < seedBytes.length; i += 4) {
      const val = (seedBytes[i] | (seedBytes[i+1] << 8) | (seedBytes[i+2] << 16) | ((seedBytes[i+3] << 24) >>> 0)) >>> 0;
      const w1 = val % N;
      const w2 = ((Math.floor(val / N) % N) + w1) % N;
      const w3 = ((Math.floor(val / (N * N)) % N) + w2) % N;
      words.push(list.words[w1], list.words[w2], list.words[w3]);
    }
    return words;
  }

  function appendChecksum(lang, dataWords) {
    const list = lists[lang];
    if (!list) throw new Error(`Word list not loaded: ${lang}`);
    if (!Array.isArray(dataWords) || !dataWords.length) {
      throw new Error('Cannot append a checksum to an empty word list');
    }
    const prefixStr = canonicalPrefixes(lang, dataWords);
    const checksumIdx = crc32(prefixStr) % dataWords.length;
    return [...dataWords, dataWords[checksumIdx]];
  }

  function isLoaded(lang) { return lang in lists; }

  // Qwertycoin Core inherits Monero's checksum algorithm: concatenate the
  // canonically-cased word-list prefixes, encode that string as UTF-8 bytes,
  // then run CRC-32. Lowercasing the prefixes or hashing UTF-16 code units is
  // self-consistent in JavaScript but incompatible with Core for German and
  // non-ASCII word lists.
  function canonicalPrefixes(lang, words) {
    const list = lists[lang];
    return words.map(word => {
      const index = lookup(lang, word);
      if (index < 0) throw new Error(`Unknown word: "${word}"`);
      return prefixByCodePoint(list.words[index], list.prefixLen);
    }).join('');
  }

  function utf8Bytes(str) {
    const bytes = [];
    for (const char of str) {
      const codePoint = char.codePointAt(0);
      if (codePoint <= 0x7f) {
        bytes.push(codePoint);
      } else if (codePoint <= 0x7ff) {
        bytes.push(0xc0 | (codePoint >>> 6), 0x80 | (codePoint & 0x3f));
      } else if (codePoint <= 0xffff) {
        bytes.push(
          0xe0 | (codePoint >>> 12),
          0x80 | ((codePoint >>> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      } else {
        bytes.push(
          0xf0 | (codePoint >>> 18),
          0x80 | ((codePoint >>> 12) & 0x3f),
          0x80 | ((codePoint >>> 6) & 0x3f),
          0x80 | (codePoint & 0x3f)
        );
      }
    }
    return bytes;
  }

  function crc32(str) {
    let crc = 0xFFFFFFFF;
    for (const byte of utf8Bytes(str)) {
      crc ^= byte;
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (0xEDB88320 & (-(crc & 1)));
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function legacyBrowserCrc32(str) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < str.length; i++) {
      crc ^= str.charCodeAt(i);
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (0xEDB88320 & (-(crc & 1)));
      }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  return {
    register,
    lookup,
    wordAt,
    verifyChecksum,
    verifyLegacyBrowserChecksum,
    decodeWords,
    encodeBytes,
    appendChecksum,
    isLoaded,
    crc32
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QwertycoinWordList;
