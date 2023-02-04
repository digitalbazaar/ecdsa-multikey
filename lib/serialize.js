/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as base64url from 'base64url-universal';
import {EXTRACTABLE} from './constants.js';
import {webcrypto} from './ecdsa.js';
import {
  getNamedCurve,
  getPrivateKeySize,
  setPrivateKeyHeader,
  setPublicKeyHeader
} from './helpers.js';

// FIXME: may need to move any leading zeros for bitstring compression; needs
// testing with various browsers
const PKCS8_PREFIXES = new Map([
  ['P-256', {
    private: new Uint8Array([
      48, 103, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72,
      206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
      1, 7, 4, 77, 48, 75, 2, 1, 1, 4, 32
    ]),
    public: new Uint8Array([161, 36, 3, 34, 0])
  }],
  ['P-384', {
    private: new Uint8Array([
      48, 129, 132, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
      4, 109, 48, 107, 2, 1, 1, 4, 48
    ]),
    public: new Uint8Array([161, 52, 3, 50, 0])
  }],
  ['P-521', {
    private: new Uint8Array([
      48, 129, 170, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35,
      4, 129, 146, 48, 129, 143, 2, 1, 1, 4, 66
    ]),
    public: new Uint8Array([161, 70, 3, 68, 0])
  }]
]);

const SPKI_PREFIXES = new Map([
  ['P-256', new Uint8Array([
    48, 57, 48, 19, 6, 7, 42, 134, 72, 206,
    61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
    3, 1, 7, 3, 34, 0
  ])],
  ['P-384', new Uint8Array([
    48, 70, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 34, 3, 50, 0
  ])],
  ['P-521', new Uint8Array([
    48, 88, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 35, 3, 68, 0
  ])]
]);

export async function exportKeyPair({
  keyPair, privateKey, publicKey, includeContext
} = {}) {
  const privateKeySize = getPrivateKeySize({keyPair});

  // get JWK
  const cryptoKey = privateKey ? keyPair.privateKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = 'https://w3id.org/security/suites/multikey/v1';
  }
  exported.id = keyPair.id;

  if(publicKey) {
    // convert `x` coordinate to compressed public key
    const x = base64url.decode(jwk.x);
    const y = base64url.decode(jwk.y);
    // public key size is always private key size + 1
    const publicKeySize = privateKeySize + 1;
    // leave room for multicodec header (2 bytes)
    const multikey = new Uint8Array(2 + publicKeySize);
    setPublicKeyHeader({keyPair, buffer: multikey});
    // use even / odd status of `y` coordinate for compressed header
    const even = y[y.length - 1] % 2 === 0;
    multikey[2] = even ? 2 : 3;
    // write `x` coordinate at end of multikey buffer to zero-fill it
    multikey.set(x, multikey.length - x.length);
    exported.publicKeyMultibase = 'z' + base58.encode(multikey);
  }

  if(privateKey) {
    const d = base64url.decode(jwk.d);
    // leave room for multicodec header (2 bytes)
    const multikey = new Uint8Array(2 + privateKeySize);
    setPrivateKeyHeader({keyPair, buffer: multikey});
    // write `d` at end of multikey buffer to zero-fill it
    multikey.set(d, multikey.length - d.length);
    exported.secretKeyMultibase = 'z' + base58.encode(multikey);
  }

  return exported;
}

export async function importKeyPair({
  id, secretKeyMultibase, publicKeyMultibase
}) {
  const keyPair = {id};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === 'z')) {
    throw new Error(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));

  // set named curved based on multikey header
  const algorithm = {
    name: 'ECDSA',
    namedCurve: getNamedCurve({publicMultikey})
  };

  // import public key; convert to `spki` format because `jwk` doesn't handle
  // compressed public keys
  const spki = _toSpki({publicMultikey});
  keyPair.publicKey = await webcrypto.subtle.importKey(
    'spki', spki, algorithm, EXTRACTABLE, ['verify']);

  // import private key if given
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
    secretKeyMultibase[0] === 'z')) {
      throw new Error(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.');
    }
    const privateMultikey = base58.decode(secretKeyMultibase.slice(1));

    // FIXME: ensure private key multikey header appropriately matches the
    // public key multikey header

    // convert to `pkcs8` format for import because `jwk` doesn't support
    // compressed keys
    const pkcs8 = _toPkcs8({privateMultikey, publicMultikey});
    keyPair.privateKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, ['sign']);
  }

  return keyPair;
}

function _toPkcs8({privateMultikey, publicMultikey}) {
  /* Format:
  SEQUENCE (3 elem)
    INTEGER 0
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey
      // curve-specific, e.g. P-256:
      OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1
    OCTET STRING
      SEQUENCE (3 elem)
        INTEGER 1
        OCTET STRING (32 byte) (RAW PRIVATE KEY BYTES)
        [1] (1 elem)
          BIT STRING (COMPRESSED/UNCOMPRESSED PUBLIC KEY BYTES)

  This translates to:

  PKCS #8 DER PRIVATE KEY HEADER (w/algorithm OID for specific key type)
  RAW PRIVATE KEY BYTES
  PKCS #8 DER PUBLIC KEY HEADER
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const headers = PKCS8_PREFIXES.get(getNamedCurve({publicMultikey}));
  const pkcs8 = new Uint8Array(
    headers.private.length +
    // do not include multikey 2-byte header
    privateMultikey.length - 2 +
    headers.public.length +
    // do not include multikey 2-byte header
    publicMultikey.length - 2);
  let offset = 0;
  pkcs8.set(headers.private, offset);
  offset += headers.private.length;
  pkcs8.set(privateMultikey.subarray(2), offset);
  offset += privateMultikey.length - 2;
  pkcs8.set(headers.public, offset);
  offset += headers.public.length;
  pkcs8.set(publicMultikey.subarray(2), offset);
  return pkcs8;
}

function _toSpki({publicMultikey}) {
  /* Format:
  SPKI DER PUBLIC KEY HEADER (w/algorithm OID for specific key type)
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const header = SPKI_PREFIXES.get(getNamedCurve({publicMultikey}));
  const spki = new Uint8Array(
    header.length +
    // do not include multikey 2-byte header
    publicMultikey.length - 2);
  let offset = 0;
  spki.set(header, offset);
  offset += header.length;
  spki.set(publicMultikey.subarray(2), offset);
  return spki;
}
