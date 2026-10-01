'use strict';

const { parentPort, workerData } = require('worker_threads');

global.self = globalThis;
if (workerData.browserLike) {
  global.importScripts = function () {};
  global.location = new URL(workerData.origin);
}
global.postMessage = function (data) {
  parentPort.postMessage(data);
};

require(workerData.script);

parentPort.on('message', function (data) {
  if (typeof global.onmessage !== 'function') {
    throw new Error('qwertycoin-ts worker did not register onmessage');
  }
  Promise.resolve(global.onmessage({ data })).catch(function (error) {
    setImmediate(function () { throw error; });
  });
});
