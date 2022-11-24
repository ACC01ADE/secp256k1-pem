import * as secp256k1 from '@noble/secp256k1';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

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

const PEM_STATIC_1: Uint8Array = secp256k1.utils.hexToBytes(rawHEX('0x30740201010420'));
const PEM_STATIC_2: Uint8Array = secp256k1.utils.hexToBytes(rawHEX('0xa00706052b8104000aa144034200'));
const PEM_HEADER: string = '-----BEGIN EC PRIVATE KEY-----\n';
const PEM_FOOTER: string = '\n-----END EC PRIVATE KEY-----';
const PEM_FORMAT_REGEX: RegExp = /([-a-z0-9+\/=]{64})/gi;

const DEFAULT_HD_PATH: string = "m/44'/60'/0'/0/";

export class Secp256k1PEM {
  private _rawPEM!: Uint8Array | undefined;
  private _isHdKey: boolean = false;
  private _hdKey?: HDKey;

  static fromPrivateKey(privateKeyHex: string): Secp256k1PEM {
    let secpPEM = new Secp256k1PEM();
    let _privateKey: Uint8Array | undefined = secp256k1.utils.hexToBytes(rawHEX(privateKeyHex));
    let _publicKey: Uint8Array = secp256k1.Point.fromPrivateKey(_privateKey as Uint8Array).toRawBytes(false);
    secpPEM._rawPEM = secp256k1.utils.concatBytes(PEM_STATIC_1, _privateKey as Uint8Array, PEM_STATIC_2, _publicKey);
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
      PEM_STATIC_1,
      defaultKey.privateKey as Uint8Array,
      PEM_STATIC_2,
      secp256k1.Point.fromPrivateKey(defaultKey.privateKey as Uint8Array).toRawBytes(false)
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
          PEM_STATIC_1,
          defaultKey.privateKey as Uint8Array,
          PEM_STATIC_2,
          secp256k1.Point.fromPrivateKey(defaultKey.privateKey as Uint8Array).toRawBytes(false)
        );
        defaultKey.wipePrivateData();
      } else {
        throw new Error('The path attribute does not apply to classes constructed via fromPrivateKey function.');
      }
    }
    const hex: string = uint8ArrayToHex(PEM);
    const b64: string = uint8ArrayToBase64(secp256k1.utils.hexToBytes(hex));
    return PEM_HEADER + b64.replace(PEM_FORMAT_REGEX, '$1\n') + PEM_FOOTER;
  }
}
