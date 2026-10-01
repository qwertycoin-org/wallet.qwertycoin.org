#!/usr/bin/env node
'use strict';

const assert = require('assert');
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..');
const coreSource = process.env.QMS_CORE_SOURCE;
const coreBuild = process.env.QMS_CORE_BUILD;
if (!coreSource || !coreBuild) throw new Error('QMS_CORE_SOURCE and QMS_CORE_BUILD are required');

function loadProtocol() {
  const context = vm.createContext({ console, crypto: crypto.webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, setTimeout, clearTimeout });
  context.globalThis = context; context.self = context; context.window = context;
  for (const file of ['vendor/libsodium/libsodium-sumo.js', 'vendor/libsodium/libsodium-wrappers.js', 'js/qms-protocol.js']) {
    vm.runInContext(fs.readFileSync(path.join(root, file), 'utf8'), context, { filename: file });
  }
  return vm.runInContext('QmsProtocol', context);
}

function compileProbe(targetDir) {
  const object = path.join(targetDir, 'qms-core-interop-probe.o');
  const executable = path.join(targetDir, 'qms-core-interop-probe');
  childProcess.execFileSync('c++', ['-std=c++14', `-I${path.join(coreSource, 'src')}`, '-c', path.join(__dirname, 'qms-core-interop-probe.cpp'), '-o', object], { stdio: 'inherit' });
  const commands = childProcess.execFileSync('ninja', ['-C', coreBuild, '-t', 'commands', 'qms_unit_tests'], { encoding: 'utf8' }).trim().split('\n');
  let link = commands[commands.length - 1];
  link = link.replace('tests/unit_tests/CMakeFiles/qms_unit_tests.dir/qms.cpp.o', JSON.stringify(object));
  link = link.replace('-o tests/unit_tests/qms_unit_tests', `-o ${JSON.stringify(executable)}`);
  childProcess.execFileSync('bash', ['-lc', link], { cwd: coreBuild, stdio: 'inherit' });
  return executable;
}

(async function () {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'qms-core-interop-'));
  try {
    const qms = loadProtocol();
    await qms.ready();
    const alice = qms.createIdentity(), bob = qms.createIdentity();
    const aliceInvitation = qms.createInvitation(alice), bobInvitation = qms.createInvitation(bob);
    const webMessageId = qms.random(16), replyMessageId = qms.random(16);
    const webCiphertext = qms.sealText(alice, bobInvitation, webMessageId, 'Web to Core QMS1');
    const webFragments = qms.fragmentCiphertext(bobInvitation, webMessageId, webCiphertext);
    assert.strictEqual(webFragments.length, 1);
    const fixture = [
      qms.hex(bob.boxPublic), qms.hex(bob.boxSecret), qms.hex(bob.signPublic), qms.hex(bob.signSecret),
      qms.hex(qms.encodeInvitation(aliceInvitation)), qms.hex(qms.encodeInvitation(bobInvitation)),
      qms.hex(qms.genesis()), qms.hex(webMessageId), qms.hex(qms.carrierExtra(webFragments[0])), qms.hex(replyMessageId)
    ].join('\n') + '\n';
    const fixturePath = path.join(temporary, 'fixture');
    const resultPath = path.join(temporary, 'result');
    fs.writeFileSync(fixturePath, fixture, { mode: 0o600 });
    const probe = compileProbe(temporary);
    childProcess.execFileSync(probe, [fixturePath, resultPath], { stdio: ['ignore', 'ignore', 'inherit'] });
    const replyExtra = qms.unhex(fs.readFileSync(resultPath, 'utf8').trim());
    const replySegments = qms.extractSegmentsFromExtra(replyExtra);
    const replyFragment = qms.decodeSegments(replySegments);
    assert(qms.verifyFragment(aliceInvitation, replyFragment));
    const opened = qms.openText(alice, bobInvitation, aliceInvitation, replyMessageId, qms.reassemble([replyFragment]));
    assert.strictEqual(opened.text, 'Core to Web QMS1');
    console.log(JSON.stringify({ webToCore: true, coreToWeb: true, compactCarriers: true }));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error && error.stack ? error.stack : error); process.exitCode = 1; });
