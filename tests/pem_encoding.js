const { Secp256k1PEM } = require('../dist/src/index');

// using samples from https://github.com/holographxyz/holograph-protocol/blob/testnet/sample.env

console.log(Secp256k1PEM.fromPrivateKey('0xff22437ccbedfffafa93a9f1da2e8c19c1711052799acf3b58ae5bebb5c6bd7b').getPAM());

console.log(
  Secp256k1PEM.fromMnemonic(
    'deputy annual debris outer baby prefer mammal scene insect obtain parrot length zero detail average nation address depart stem tuition fork rocket topple kidney'
  ).getPAM(0)
);

console.log(
  Secp256k1PEM.fromMnemonic(
    'deputy annual debris outer baby prefer mammal scene insect obtain parrot length zero detail average nation address depart stem tuition fork rocket topple kidney'
  ).getPAM()
);

console.log(
  Secp256k1PEM.fromExtendedKey(
    'xprv9s21ZrQH143K416LEFgxfdhXevstXQ4vxnjV9vuXuC7NWnDZshZN9qUEext3SMBUcfd8w7H9Jrjk7Vi3eqgNbFy5tyMmzETqKqxJUB2Sr9R'
  ).getPAM(0)
);

console.log(
  Secp256k1PEM.fromExtendedKey(
    'xprv9s21ZrQH143K416LEFgxfdhXevstXQ4vxnjV9vuXuC7NWnDZshZN9qUEext3SMBUcfd8w7H9Jrjk7Vi3eqgNbFy5tyMmzETqKqxJUB2Sr9R'
  ).getPAM()
);

console.log(
  Secp256k1PEM.fromSeed(
    '1d3604de517910bc57e3801fdb61b81580cd8bfd33dc437ddc83fd474eb8696638f56de46bbba77e72e492c4d8a0d2ad1e3fb69173a0b2b117233b4d69e49243'
  ).getPAM(0)
);

console.log(
  Secp256k1PEM.fromSeed(
    '1d3604de517910bc57e3801fdb61b81580cd8bfd33dc437ddc83fd474eb8696638f56de46bbba77e72e492c4d8a0d2ad1e3fb69173a0b2b117233b4d69e49243'
  ).getPAM()
);
