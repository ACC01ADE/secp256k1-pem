import * as secp256k1 from '@noble/secp256k1';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

import { rawHEX, uint8ArrayToHex, uint8ArrayToBase64 } from './utils';

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
const ASN_HEADER: Uint8Array = secp256k1.utils.hexToBytes(rawHEX('0x30740201010420'));
const CURVE_HEADER: Uint8Array = secp256k1.utils.hexToBytes(rawHEX('0xA00706052B8104000AA14403420004'));

const PEM_KEY_HEADER: string = '-----BEGIN EC PRIVATE KEY-----\n';
const PEM_KEY_FOOTER: string = '\n-----END EC PRIVATE KEY-----';

// limit line width to 64 characters with this regex
const PEM_LINE_WIDTH_REGEX: RegExp = /([-a-z0-9+\/=]{64})/gi;

const DEFAULT_HD_PATH: string = "m/44'/60'/0'/0/";

export class Secp256k1PEM {
  private _rawPEM!: Uint8Array | undefined;
  private _isHdKey: boolean = false;
  private _hdKey?: HDKey;

  static fromPrivateKey(privateKeyHex: string): Secp256k1PEM {
    let secpPEM = new Secp256k1PEM();
    let _privateKey: Uint8Array | undefined = secp256k1.utils.hexToBytes(rawHEX(privateKeyHex));
    let _publicKey: Uint8Array = secp256k1.Point.fromPrivateKey(_privateKey as Uint8Array)
      .toRawBytes(false)
      .slice(1);
    secpPEM._rawPEM = secp256k1.utils.concatBytes(ASN_HEADER, _privateKey as Uint8Array, CURVE_HEADER, _publicKey);
    _privateKey.fill(0);
    _privateKey = undefined;
    return secpPEM;
  }

  static fromMnemonic(mnemonic: string, passphrase?: string): Secp256k1PEM {
    let seed: Uint8Array | undefined = bip39.mnemonicToSeedSync(mnemonic, passphrase);
    const secpPEM: Secp256k1PEM = Secp256k1PEM.fromSeed(uint8ArrayToHex(seed as Uint8Array));
    seed.fill(0);
    seed = undefined;
    return secpPEM;
  }

  static fromSeed(seed: string): Secp256k1PEM {
    let secpPEM = new Secp256k1PEM();
    secpPEM._isHdKey = true;
    secpPEM._hdKey = HDKey.fromMasterSeed(secp256k1.utils.hexToBytes(rawHEX(seed)));
    secpPEM.setDefaultPEM();
    return secpPEM;
  }

  static fromExtendedKey(base58key: string): Secp256k1PEM {
    let secpPEM = new Secp256k1PEM();
    secpPEM._isHdKey = true;
    secpPEM._hdKey = HDKey.fromExtendedKey(base58key);
    secpPEM.setDefaultPEM();
    return secpPEM;
  }

  setDefaultPEM(): void {
    const defaultKey: HDKey = this._hdKey!.derive(DEFAULT_HD_PATH + '0');
    this._rawPEM = secp256k1.utils.concatBytes(
      ASN_HEADER,
      defaultKey.privateKey as Uint8Array,
      CURVE_HEADER,
      secp256k1.Point.fromPrivateKey(defaultKey.privateKey as Uint8Array)
        .toRawBytes(false)
        .slice(1)
    );
    defaultKey.wipePrivateData();
  }

  getRawPAM(): Uint8Array | undefined {
    return this._rawPEM;
  }

  getPAM(path?: string | number): string {
    let PEM: Uint8Array = new Uint8Array(this._rawPEM!);
    if (typeof path !== 'undefined') {
      if (this._isHdKey) {
        if (typeof path === 'number') {
          path = (DEFAULT_HD_PATH + Number(path as number).toString(10)) as string;
        }
        // we need a new rawPEM
        const defaultKey: HDKey = this._hdKey!.derive(path as string);
        PEM = secp256k1.utils.concatBytes(
          ASN_HEADER,
          defaultKey.privateKey as Uint8Array,
          CURVE_HEADER,
          secp256k1.Point.fromPrivateKey(defaultKey.privateKey as Uint8Array)
            .toRawBytes(false)
            .slice(1)
        );
        defaultKey.wipePrivateData();
      } else {
        throw new Error('The path attribute does not apply to classes constructed via fromPrivateKey function.');
      }
    }
    const hex: string = uint8ArrayToHex(PEM);
    const b64: string = uint8ArrayToBase64(secp256k1.utils.hexToBytes(hex));
    return PEM_KEY_HEADER + b64.replace(PEM_LINE_WIDTH_REGEX, '$1\n') + PEM_KEY_FOOTER;
  }
}
