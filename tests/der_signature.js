const secp = require('@noble/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

// using samples from https://github.com/holographxyz/holograph-protocol/blob/testnet/sample.env

const privateKey = 'ff22437ccbedfffafa93a9f1da2e8c19c1711052799acf3b58ae5bebb5c6bd7b';
const publicKey = Buffer.from(secp.Point.fromPrivateKey(secp.utils.hexToBytes(privateKey)).toRawBytes(false)).toString(
  'hex'
);
const walletAddress = Buffer.from(keccak_256(Buffer.from(publicKey, 'hex').slice(1)))
  .slice(-20)
  .toString('hex');

console.log({ privateKey: '0x' + privateKey, publicKey: '0x' + publicKey, walletAddress: '0x' + walletAddress });

// keccak256('Hello World!')
const msg = '3ea2f1d0abf3fc66cf29eebb70cbd4e7fe762ef8a09bcc06c8edf641230afec0';

// DER encoded signature
const sig =
  '3044' +
  '0220' +
  '0c3c58db0e29f24cd1e4dc4cac4043c11d7d1a8ea17d3d2691264e02ee31c6b6' +
  '0220' +
  '5b5a81fa29df0bbfc68bdeebcaea21ac7ac0a31271ef6f94c8883d0d7964d859';

const signature = secp.Signature.fromDER(sig);

// to find the proper recovery value, we try both options
const ecdsaPoint = [secp.Point.fromSignature(msg, sig, 0), secp.Point.fromSignature(msg, sig, 1)];

const address = [
  Buffer.from(keccak_256(ecdsaPoint[0].toRawBytes(false).slice(1)))
    .slice(-20)
    .toString('hex'),
  Buffer.from(keccak_256(ecdsaPoint[1].toRawBytes(false).slice(1)))
    .slice(-20)
    .toString('hex'),
];

let recoveryValue = 0;
if (address[1] == walletAddress) {
  recoveryValue = 1;
}

const signatureHash = signature.toCompactHex() + (recoveryValue + 27).toString(16).padStart(2, '0');

console.log({ signature: '0x' + signatureHash });

console.log({
  r: '0x' + signatureHash.substr(0, 64),
  s: '0x' + signatureHash.substr(64, 128),
  v: '0x' + signatureHash.substr(128, 130),
});
