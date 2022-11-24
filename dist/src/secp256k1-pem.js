"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Secp256k1PEM = void 0;
const secp256k1 = __importStar(require("@noble/secp256k1"));
const bip39 = __importStar(require("@scure/bip39"));
const bip32_1 = require("@scure/bip32");
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
const uint8ArrayToBase64 = (bytes) => {
    return btoa(String.fromCharCode.apply(null, [].slice.call(bytes)));
};
const PEM_STATIC_1 = secp256k1.utils.hexToBytes(rawHEX('0x30740201010420'));
const PEM_STATIC_2 = secp256k1.utils.hexToBytes(rawHEX('0xa00706052b8104000aa144034200'));
const PEM_HEADER = '-----BEGIN EC PRIVATE KEY-----\n';
const PEM_FOOTER = '\n-----END EC PRIVATE KEY-----';
const PEM_FORMAT_REGEX = /([-a-z0-9+\/=]{64})/gi;
const DEFAULT_HD_PATH = "m/44'/60'/0'/0/";
class Secp256k1PEM {
    constructor() {
        this._isHdKey = false;
    }
    static fromPrivateKey(privateKeyHex) {
        let secpPEM = new Secp256k1PEM();
        let _privateKey = secp256k1.utils.hexToBytes(rawHEX(privateKeyHex));
        let _publicKey = secp256k1.Point.fromPrivateKey(_privateKey).toRawBytes(false);
        secpPEM._rawPEM = secp256k1.utils.concatBytes(PEM_STATIC_1, _privateKey, PEM_STATIC_2, _publicKey);
        _privateKey.fill(0);
        _privateKey = undefined;
        return secpPEM;
    }
    static fromMnemonic(mnemonic, passphrase) {
        let seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
        const secpPEM = Secp256k1PEM.fromSeed(uint8ArrayToHex(seed));
        seed.fill(0);
        seed = undefined;
        return secpPEM;
    }
    static fromSeed(seed) {
        let secpPEM = new Secp256k1PEM();
        secpPEM._isHdKey = true;
        secpPEM._hdKey = bip32_1.HDKey.fromMasterSeed(secp256k1.utils.hexToBytes(rawHEX(seed)));
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
        this._rawPEM = secp256k1.utils.concatBytes(PEM_STATIC_1, defaultKey.privateKey, PEM_STATIC_2, secp256k1.Point.fromPrivateKey(defaultKey.privateKey).toRawBytes(false));
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
                    path = (DEFAULT_HD_PATH + Number(path).toString(10));
                }
                // we need a new rawPEM
                const defaultKey = this._hdKey.derive(path);
                PEM = secp256k1.utils.concatBytes(PEM_STATIC_1, defaultKey.privateKey, PEM_STATIC_2, secp256k1.Point.fromPrivateKey(defaultKey.privateKey).toRawBytes(false));
                defaultKey.wipePrivateData();
            }
            else {
                throw new Error('The path attribute does not apply to classes constructed via fromPrivateKey function.');
            }
        }
        const hex = uint8ArrayToHex(PEM);
        const b64 = uint8ArrayToBase64(secp256k1.utils.hexToBytes(hex));
        return PEM_HEADER + b64.replace(PEM_FORMAT_REGEX, '$1\n') + PEM_FOOTER;
    }
}
exports.Secp256k1PEM = Secp256k1PEM;
//# sourceMappingURL=secp256k1-pem.js.map