'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.uint8ArrayToBase64 = exports.uint8ArrayToHex = exports.rawHEX = void 0;
const rawHEX = (input) => {
  input = input.trim();
  if (input.toLowerCase().startsWith('0x')) {
    input = input.substring(2);
  }
  if (input.length % 2 !== 0) {
    input = '0' + input;
  }
  return input;
};
exports.rawHEX = rawHEX;
const uint8ArrayToHex = (bytes) => {
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] < 16) {
      output += '0';
    }
    output += bytes[i].toString(16);
  }
  return output;
};
exports.uint8ArrayToHex = uint8ArrayToHex;
const uint8ArrayToBase64 = (bytes) => {
  return btoa(String.fromCharCode.apply(null, [].slice.call(bytes)));
};
exports.uint8ArrayToBase64 = uint8ArrayToBase64;
//# sourceMappingURL=utils.js.map
