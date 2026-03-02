import {secp256k1} from '@noble/curves/secp256k1.js';

// Shim adapted from https://github.com/soatok/elliptic-to-noble
// https://github.com/indutny/elliptic/issues/343
// elliptic seems to be getting no maintenance, but we don't want to
// introduce unmonitored packages into the code

export class KeyPairSecp256k1 {
  constructor(opts) {
    this.ec = {...secp256k1};
    if(opts.priv != null) {
      this.priv = opts.priv;
    }
    if(opts.pub != null) {
      this.pub = opts.pub;
    }
  }

  static hexToBytes(hex) {
    if(typeof hex !== 'string') {
      throw new Error('hex string expected');
    }
    if(hex.length % 2) {
      throw new Error('hex string must have even length');
    }
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for(let i = 0; i < len; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  static bytesToHex(bytes) {
    return Array.from(bytes || [])
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  static keyFromPublic(pub, enc = 'hex') {
    const bytes = enc === 'hex' ? KeyPairSecp256k1.hexToBytes(pub) : pub;
    return new KeyPairSecp256k1({pub: bytes});
  }

  getPublic(compressed = true, enc = 'hex') {
    if(!this.pub) {
      this.pub = this.ec.getPublicKey(this.priv, false);
    }
    let pubBytes = this.pub;
    const point = this.ec.Point.fromHex(KeyPairSecp256k1.bytesToHex(pubBytes));
    const hex = point.toHex(compressed);
    pubBytes = KeyPairSecp256k1.hexToBytes(hex);

    if(enc === 'hex') {
      return KeyPairSecp256k1.bytesToHex(pubBytes);
    }
    return pubBytes;
  }
}
