'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (!desc || ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Secp256k1PEM = void 0;
const secp256k1 = __importStar(require('@noble/secp256k1'));
const bip39 = __importStar(require('@scure/bip39'));
const bip32_1 = require('@scure/bip32');
const utils_1 = require('./utils');
/*
  @dev Read this for more info -> http://websites.umich.edu/~x509/ssleay/layman.html

  // HEADER

  0x30 - ASN.1
  0x74 - Length of all following bytes (116 bytes)


  // PRIVATE KEY PARAMS

  0x02 - Type (integer)
  0x01 - Length of integer (1 byte)
  0x01 - Value of integer (1)

  0x04 - Type (octet string)
  0x20 - Length of string (32 bytes)

    // PRIVATE KEY

    - 32 byte private key goes here
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00


  // CURVE PARAMS

  0xA0 - Tag 0
  0x07 - Length of tag (7 bytes)
  0x06 - Type (Object ID)
  0x05 - Length of the Object ID (5 bytes)

    // CURVE

    - The object ID of the curve secp256k1
    0x2B 0x81 0x04 0x00 0x0A


  // PUBLIC KEY PARAMS

  0xA1 - Tag 1
  0x44 - Length of tag (68 bytes)
  0x03 - Type – Bit string
  0x42 - Length of the bit string (66 bytes)
  0x00 - Length of unused padding bits in the bit string
  0x04 - Uncompressed Public Key

    // PUBLIC KEY

    - 64 byte public key goes here
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
    0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00

*/
const ASN_HEADER = secp256k1.utils.hexToBytes((0, utils_1.rawHEX)('0x30740201010420'));
const CURVE_HEADER = secp256k1.utils.hexToBytes((0, utils_1.rawHEX)('0xA00706052B8104000AA14403420004'));
const PEM_KEY_HEADER = '-----BEGIN EC PRIVATE KEY-----\n';
const PEM_KEY_FOOTER = '\n-----END EC PRIVATE KEY-----';
// limit line width to 64 characters with this regex
const PEM_LINE_WIDTH_REGEX = /([-a-z0-9+\/=]{64})/gi;
const DEFAULT_HD_PATH = "m/44'/60'/0'/0/";
class Secp256k1PEM {
  constructor() {
    this._isHdKey = false;
  }
  static fromPrivateKey(privateKeyHex) {
    let secpPEM = new Secp256k1PEM();
    let _privateKey = secp256k1.utils.hexToBytes((0, utils_1.rawHEX)(privateKeyHex));
    let _publicKey = secp256k1.Point.fromPrivateKey(_privateKey).toRawBytes(false).slice(1);
    secpPEM._rawPEM = secp256k1.utils.concatBytes(ASN_HEADER, _privateKey, CURVE_HEADER, _publicKey);
    _privateKey.fill(0);
    _privateKey = undefined;
    return secpPEM;
  }
  static fromMnemonic(mnemonic, passphrase) {
    let seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
    const secpPEM = Secp256k1PEM.fromSeed((0, utils_1.uint8ArrayToHex)(seed));
    seed.fill(0);
    seed = undefined;
    return secpPEM;
  }
  static fromSeed(seed) {
    let secpPEM = new Secp256k1PEM();
    secpPEM._isHdKey = true;
    secpPEM._hdKey = bip32_1.HDKey.fromMasterSeed(secp256k1.utils.hexToBytes((0, utils_1.rawHEX)(seed)));
    secpPEM.setDefaultPEM();
    return secpPEM;
  }
  static fromExtendedKey(base58key) {
    let secpPEM = new Secp256k1PEM();
    secpPEM._isHdKey = true;
    secpPEM._hdKey = bip32_1.HDKey.fromExtendedKey(base58key);
    secpPEM.setDefaultPEM();
    return secpPEM;
  }
  setDefaultPEM() {
    const defaultKey = this._hdKey.derive(DEFAULT_HD_PATH + '0');
    this._rawPEM = secp256k1.utils.concatBytes(
      ASN_HEADER,
      defaultKey.privateKey,
      CURVE_HEADER,
      secp256k1.Point.fromPrivateKey(defaultKey.privateKey).toRawBytes(false).slice(1)
    );
    defaultKey.wipePrivateData();
  }
  getRawPAM() {
    return this._rawPEM;
  }
  getPAM(path) {
    let PEM = new Uint8Array(this._rawPEM);
    if (typeof path !== 'undefined') {
      if (this._isHdKey) {
        if (typeof path === 'number') {
          path = DEFAULT_HD_PATH + Number(path).toString(10);
        }
        // we need a new rawPEM
        const defaultKey = this._hdKey.derive(path);
        PEM = secp256k1.utils.concatBytes(
          ASN_HEADER,
          defaultKey.privateKey,
          CURVE_HEADER,
          secp256k1.Point.fromPrivateKey(defaultKey.privateKey).toRawBytes(false).slice(1)
        );
        defaultKey.wipePrivateData();
      } else {
        throw new Error('The path attribute does not apply to classes constructed via fromPrivateKey function.');
      }
    }
    const hex = (0, utils_1.uint8ArrayToHex)(PEM);
    const b64 = (0, utils_1.uint8ArrayToBase64)(secp256k1.utils.hexToBytes(hex));
    return PEM_KEY_HEADER + b64.replace(PEM_LINE_WIDTH_REGEX, '$1\n') + PEM_KEY_FOOTER;
  }
}
exports.Secp256k1PEM = Secp256k1PEM;
//# sourceMappingURL=secp256k1-pem.js.map
