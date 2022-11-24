## Secp256k1 to PEM format

A simple library for converting EVM wallet keys to PEM format.
The goal of this project is to convert the ECDSA (EC K256 - secp256k1) private keys into a PAM format that YubiHSM can import.
The library works with private keys, extended keys, seeds, and mnemonic phrases.

Install:

- `npm -i secp256k1-pem`.

Import into your project:

- **Typescript**: `import { Secp256k1PEM } from 'secp256k1-pem';`
- **JavaScript**: `const { Secp256k1PEM } = require('secp256k1-pem');`

Use:

- **Private Key**: `Secp256k1PEM.fromPrivateKey(PRIVATE_KEY).getPAM()`
  - _Sample Input_: `0xff22437ccbedfffafa93a9f1da2e8c19c1711052799acf3b58ae5bebb5c6bd7b`
- **BIP32 Root Key**: `Secp256k1PEM.fromExtendedKey(EXTENDED_KEY).getPAM()`
  - _Sample Input_: `xprv9s21ZrQH143K416LEFgxfdhXevstXQ4vxnjV9vuXuC7NWnDZshZN9qUEext3SMBUcfd8w7H9Jrjk7Vi3eqgNbFy5tyMmzETqKqxJUB2Sr9R`
- **BIP39 Seed**: `Secp256k1PEM.fromSeed(SEED_HEX).getPAM()`
  - _Sample Input_: `1d3604de517910bc57e3801fdb61b81580cd8bfd33dc437ddc83fd474eb8696638f56de46bbba77e72e492c4d8a0d2ad1e3fb69173a0b2b117233b4d69e49243`
- **BIP39 Mnemonic**: `Secp256k1PEM.fromMnemonic(MNEMONIC_ENGLISH).getPAM()`
  - _Sample Input_: `deputy annual debris outer baby prefer mammal scene insect obtain parrot length zero detail average nation address depart stem tuition fork rocket topple kidney`

### Notes

The function `getPAM` accepts an optional attribute `path`. This does not work with `fromPrivateKey` since it is a single account. For all other types, you can specify path as full path string or account index integer.
The default deviration path is `m/44'/60'/0'/0/0` to conform with the standard **BIP32 Derivation Path**.

Examples:

- **Account Index**: `.getPAM(1)` == (`"m/44'/60'/0'/0/" + 1`)
- **Full Path**: `.getPAM("m/44'/60'/0'/0/1")`
