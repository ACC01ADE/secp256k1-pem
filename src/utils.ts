const rawHEX = (input: string): string => {
  input = input.trim();
  if (input.toLowerCase().startsWith('0x')) {
    input = input.substring(2);
  }
  if (input.length % 2 !== 0) {
    input = '0' + input;
  }
  return input;
};

const uint8ArrayToHex = (bytes: Uint8Array): string => {
  let output: string = '';
  for (let i: number = 0; i < bytes.length; i++) {
    if (bytes[i] < 16) {
      output += '0';
    }
    output += bytes[i].toString(16);
  }
  return output;
};

const uint8ArrayToBase64 = (bytes: Uint8Array): string => {
  return btoa(String.fromCharCode.apply(null, [].slice.call(bytes)));
};

export { rawHEX, uint8ArrayToHex, uint8ArrayToBase64 };
