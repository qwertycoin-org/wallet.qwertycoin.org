'use strict';

const { parentPort, workerData } = require('worker_threads');

global.self = globalThis;
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
