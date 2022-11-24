export declare class Secp256k1PEM {
  private _rawPEM;
  private _isHdKey;
  private _hdKey?;
  static fromPrivateKey(privateKeyHex: string): Secp256k1PEM;
  static fromMnemonic(mnemonic: string, passphrase?: string): Secp256k1PEM;
  static fromSeed(seed: string): Secp256k1PEM;
  static fromExtendedKey(base58key: string): Secp256k1PEM;
  setDefaultPEM(): void;
  getRawPAM(): Uint8Array | undefined;
  getPAM(path?: string | number): string;
}
//# sourceMappingURL=secp256k1-pem.d.ts.map
