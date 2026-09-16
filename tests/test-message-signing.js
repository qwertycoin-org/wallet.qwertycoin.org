'use strict';

const assert = require('assert');
const QwcMessageSigning = require('../js/message-signing.js');

const ADDRESS = 'QWC1' + 'A'.repeat(94);
const OTHER_ADDRESS = 'QWC1' + 'B'.repeat(94);
const NOW = Date.parse('2026-09-15T20:00:00.000Z');
const EXPIRES = '2026-09-15T20:10:00.000Z';
const NONCE = 'ab'.repeat(24);

function challenge(overrides = {}) {
  return [
    'Qwertycoin pool payout threshold',
    `Address: ${overrides.address || ADDRESS}`,
    `Threshold: ${overrides.threshold || '2500.125'} QWC`,
    `Nonce: ${overrides.nonce || NONCE}`,
    `Expires: ${overrides.expires || EXPIRES}`,
    `Domain: ${overrides.domain || 'pool.qwertycoin.org'}`
  ].join('\n');
}

const parsed = QwcMessageSigning.parsePoolChallenge(challenge(), ADDRESS, NOW);
assert.deepStrictEqual(parsed, {
  address: ADDRESS,
  thresholdQwc: '2500.125',
  thresholdAtomic: '250012500000',
  nonce: NONCE,
  expiresAt: EXPIRES,
  domain: 'pool.qwertycoin.org'
});

assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge(), OTHER_ADDRESS, NOW), /does not match/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ domain: 'example.org' }), ADDRESS, NOW), /malformed|domain/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replaceAll('\n', '\r'), ADDRESS, NOW), /line endings/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replaceAll('\n', '\r\n'), ADDRESS, NOW), /line endings/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '999.99999999' }), ADDRESS, NOW), /1,000/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '10000000.00000001' }), ADDRESS, NOW), /10,000,000/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '1000.0' }), ADDRESS, NOW), /canonical/);
assert.strictEqual(QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '1000' }), ADDRESS, NOW).thresholdAtomic, '100000000000');
assert.strictEqual(QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '10000000' }), ADDRESS, NOW).thresholdAtomic, '1000000000000000');
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ nonce: NONCE.toUpperCase() }), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ nonce: NONCE.slice(2) }), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ expires: '2026-09-15T19:59:59.999Z' }), ADDRESS, NOW), /expired/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ expires: '2026-09-15T20:00:00.000Z' }), ADDRESS, NOW), /expired/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ expires: '2026-09-15T20:11:00.001Z' }), ADDRESS, NOW), /longer/);
assert.doesNotThrow(() => QwcMessageSigning.parsePoolChallenge(challenge({ expires: '2026-09-15T20:11:00.000Z' }), ADDRESS, NOW));
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge() + '\n', ADDRESS, NOW), /not an exact/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replace('Threshold:', 'Threshold :'), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replace('Address:', 'address:'), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replace('Address:', 'Address:  '), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replace('Threshold:', 'Threshold: 00'), ADDRESS, NOW), /malformed|canonical/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '1000.00000000' }), ADDRESS, NOW), /canonical/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '1000.000000001' }), ADDRESS, NOW), /canonical/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge({ threshold: '+1000' }), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge().replace('Nonce:', 'Expires:'), ADDRESS, NOW), /malformed/);
assert.throws(() => QwcMessageSigning.parsePoolChallenge(challenge(), ADDRESS, Number.NaN), /expired/);

assert.strictEqual(QwcMessageSigning.requireMessage(' exact\nmessage '), ' exact\nmessage ');
assert.strictEqual(QwcMessageSigning.requireMessage('e\u0301'), 'e\u0301');
assert.notStrictEqual(QwcMessageSigning.requireMessage('e\u0301'), QwcMessageSigning.requireMessage('\u00e9'));
assert.strictEqual(QwcMessageSigning.requireMessage('x'.repeat(QwcMessageSigning.MAX_MESSAGE_LENGTH)).length, QwcMessageSigning.MAX_MESSAGE_LENGTH);
assert.throws(() => QwcMessageSigning.requireMessage(''), /Enter a message/);
assert.throws(() => QwcMessageSigning.requireMessage('x'.repeat(QwcMessageSigning.MAX_MESSAGE_LENGTH + 1)), /limited/);
assert.strictEqual(QwcMessageSigning.utf8Length('Grüße ☃'), 11);
assert.throws(() => QwcMessageSigning.requireMessage('☃'.repeat(6000)), /UTF-8 bytes/);
assert.doesNotThrow(() => QwcMessageSigning.requireMessage('☃'.repeat(5461) + 'x'));
assert.throws(() => QwcMessageSigning.requireMessage('☃'.repeat(5461) + 'xx'), /UTF-8 bytes/);
assert.throws(() => QwcMessageSigning.requireMessage('\ud800'), /invalid Unicode/);
assert.strictEqual(QwcMessageSigning.isPoolChallengeCandidate(challenge()), true);
assert.strictEqual(QwcMessageSigning.isPoolChallengeCandidate(challenge().replaceAll('\n', '\r\n')), true);
assert.strictEqual(QwcMessageSigning.isPoolChallengeCandidate('ordinary message'), false);
assert.strictEqual(QwcMessageSigning.requireAddress(' exact-address '), ' exact-address ');
assert.throws(() => QwcMessageSigning.requireAddress(''), /Enter the signing address/);
assert.throws(() => QwcMessageSigning.requireAddress('x'.repeat(QwcMessageSigning.MAX_ADDRESS_LENGTH + 1)), /too long/);
assert.strictEqual(QwcMessageSigning.requireSignature('SigV2exact'), 'SigV2exact');
assert.throws(() => QwcMessageSigning.requireSignature(''), /complete signature/);
assert.throws(() => QwcMessageSigning.requireSignature('x'.repeat(QwcMessageSigning.MAX_SIGNATURE_LENGTH + 1)), /too long/);

assert.deepStrictEqual(QwcMessageSigning.describeVerification({ isGood: false }), {
  good: false,
  signatureType: 'unknown',
  message: 'Signature does not match this message and address.'
});
assert.deepStrictEqual(
  QwcMessageSigning.describeVerification({ isGood: true, signatureType: 0, isOld: false, version: 2 }),
  { good: true, signatureType: 'spend', message: 'Valid spend-key signature, version 2.' }
);
assert.deepStrictEqual(
  QwcMessageSigning.describeVerification({ isGood: true, signatureType: 1, isOld: true, version: 1 }),
  { good: true, signatureType: 'view', message: 'Valid view-key signature, version 1, legacy format.' }
);
assert.deepStrictEqual(
  QwcMessageSigning.describeVerification({ isGood: true, signatureType: 99, version: 2 }),
  { good: false, signatureType: 'unknown', message: 'Signature uses an unsupported key type.' }
);
assert.strictEqual(QwcMessageSigning.requireSpendVerification({ isGood: true, signatureType: 0 }).isGood, true);
assert.strictEqual(QwcMessageSigning.requireSpendVerification({ isGood: true, signatureType: 'SIGN_WITH_SPEND_KEY' }).isGood, true);
assert.throws(() => QwcMessageSigning.requireSpendVerification({ isGood: false, signatureType: 0 }), /did not verify/);
assert.throws(() => QwcMessageSigning.requireSpendVerification({ isGood: true, signatureType: 1 }), /not a spend-key/);
assert.throws(() => QwcMessageSigning.requireSpendVerification({ isGood: true, signatureType: 99 }), /not a spend-key/);

console.log('  focused message-signing contract checks passed');
