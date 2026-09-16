// Copyright (c) 2026 The Qwertycoin Project
// SPDX-License-Identifier: MIT

const QwcMessageSigning = (() => {
  const MAX_MESSAGE_LENGTH = 16384;
  const MAX_ADDRESS_LENGTH = 256;
  const MAX_SIGNATURE_LENGTH = 4096;
  const POOL_CHALLENGE_TITLE = 'Qwertycoin pool payout threshold';
  const POOL_CHALLENGE_LIFETIME_MS = 10 * 60 * 1000;
  const POOL_CLOCK_SKEW_MS = 60 * 1000;
  const POOL_MIN_THRESHOLD_ATOMIC = 1000n * 100000000n;
  const POOL_MAX_THRESHOLD_ATOMIC = 10000000n * 100000000n;

  function utf8Length(value) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(value).length;
    if (typeof Buffer !== 'undefined') return Buffer.byteLength(value, 'utf8');
    return unescape(encodeURIComponent(value)).length;
  }

  function containsUnpairedSurrogate(value) {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return true;
      }
    }
    return false;
  }

  function requireMessage(value) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('Enter a message.');
    }
    if (containsUnpairedSurrogate(value)) {
      throw new Error('The message contains invalid Unicode and cannot be encoded exactly.');
    }
    if (utf8Length(value) > MAX_MESSAGE_LENGTH) {
      throw new Error(`Messages are limited to ${MAX_MESSAGE_LENGTH.toLocaleString()} UTF-8 bytes.`);
    }
    return value;
  }

  function thresholdToAtomic(value) {
    const match = /^(0|[1-9][0-9]{0,7})(?:\.([0-9]{0,7}[1-9]))?$/.exec(value);
    if (!match) throw new Error('The pool threshold is not in canonical QWC format.');
    const fraction = (match[2] || '').padEnd(8, '0');
    const atomic = BigInt(match[1]) * 100000000n + BigInt(fraction || '0');
    if (atomic < POOL_MIN_THRESHOLD_ATOMIC || atomic > POOL_MAX_THRESHOLD_ATOMIC) {
      throw new Error('The pool threshold must be from 1,000 to 10,000,000 QWC.');
    }
    return atomic;
  }

  function requireAddress(value) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('Enter the signing address.');
    }
    if (value.length > MAX_ADDRESS_LENGTH) {
      throw new Error('The signing address is too long.');
    }
    return value;
  }

  function requireSignature(value) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('Enter the complete signature.');
    }
    if (value.length > MAX_SIGNATURE_LENGTH) {
      throw new Error('The signature is too long.');
    }
    return value;
  }

  function isPoolChallengeCandidate(value) {
    return typeof value === 'string' &&
      (value === POOL_CHALLENGE_TITLE ||
       value.startsWith(`${POOL_CHALLENGE_TITLE}\n`) ||
       value.startsWith(`${POOL_CHALLENGE_TITLE}\r`));
  }

  function parsePoolChallenge(message, expectedAddress, nowMs = Date.now()) {
    requireMessage(message);
    if (message.includes('\r')) {
      throw new Error('The pool challenge must retain its original line endings.');
    }
    if (typeof expectedAddress !== 'string' || expectedAddress.length === 0) {
      throw new Error('A loaded wallet address is required.');
    }

    const lines = message.split('\n');
    if (lines.length !== 6 || lines[0] !== POOL_CHALLENGE_TITLE) {
      throw new Error('This is not an exact Qwertycoin pool payout challenge.');
    }

    const addressMatch = /^Address: (QWC[1-9A-HJ-NP-Za-km-z]+)$/.exec(lines[1]);
    const thresholdMatch = /^Threshold: ([0-9]+(?:\.[0-9]+)?) QWC$/.exec(lines[2]);
    const nonceMatch = /^Nonce: ([a-f0-9]{48})$/.exec(lines[3]);
    const expiresMatch = /^Expires: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)$/.exec(lines[4]);
    if (!addressMatch || !thresholdMatch || !nonceMatch || !expiresMatch || lines[5] !== 'Domain: pool.qwertycoin.org') {
      throw new Error('The pool challenge fields are malformed or the domain is not pool.qwertycoin.org.');
    }
    if (addressMatch[1] !== expectedAddress) {
      throw new Error('The pool challenge address does not match this wallet.');
    }

    const thresholdAtomic = thresholdToAtomic(thresholdMatch[1]);
    const expiresAt = Date.parse(expiresMatch[1]);
    if (!Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== expiresMatch[1]) {
      throw new Error('The pool challenge expiration is invalid.');
    }
    if (!Number.isFinite(nowMs) || expiresAt <= nowMs) {
      throw new Error('The pool challenge has expired. Create a new request on pool.qwertycoin.org.');
    }
    if (expiresAt - nowMs > POOL_CHALLENGE_LIFETIME_MS + POOL_CLOCK_SKEW_MS) {
      throw new Error('The pool challenge lifetime is longer than the allowed ten minutes.');
    }

    return {
      address: addressMatch[1],
      thresholdQwc: thresholdMatch[1],
      thresholdAtomic: thresholdAtomic.toString(),
      nonce: nonceMatch[1],
      expiresAt: expiresMatch[1],
      domain: 'pool.qwertycoin.org'
    };
  }

  function signatureTypeLabel(value) {
    if (value === 0 || value === 'spend' || value === 'SIGN_WITH_SPEND_KEY') return 'spend';
    if (value === 1 || value === 'view' || value === 'SIGN_WITH_VIEW_KEY') return 'view';
    return 'unknown';
  }

  function describeVerification(result) {
    if (!result || result.isGood !== true) {
      return { good: false, signatureType: 'unknown', message: 'Signature does not match this message and address.' };
    }
    const signatureType = signatureTypeLabel(result.signatureType);
    if (signatureType === 'unknown') {
      return { good: false, signatureType, message: 'Signature uses an unsupported key type.' };
    }
    const version = Number.isSafeInteger(result.version) ? `, version ${result.version}` : '';
    const legacy = result.isOld === true ? ', legacy format' : '';
    return {
      good: true,
      signatureType,
      message: `Valid ${signatureType}-key signature${version}${legacy}.`
    };
  }

  function requireSpendVerification(result) {
    if (!result || result.isGood !== true) {
      throw new Error('The locally created signature did not verify.');
    }
    if (signatureTypeLabel(result.signatureType) !== 'spend') {
      throw new Error('The locally created signature is not a spend-key signature.');
    }
    return result;
  }

  return {
    MAX_ADDRESS_LENGTH,
    MAX_MESSAGE_LENGTH,
    MAX_SIGNATURE_LENGTH,
    utf8Length,
    isPoolChallengeCandidate,
    parsePoolChallenge,
    requireAddress,
    requireMessage,
    requireSignature,
    requireSpendVerification,
    describeVerification
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = QwcMessageSigning;
