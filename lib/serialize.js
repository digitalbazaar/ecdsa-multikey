/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as base64url from 'base64url-universal';
import {
  ALGORITHM,
  ECDSA_CURVE,
  EXTRACTABLE,
  MULTIBASE_BASE58_HEADER,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {webcrypto} from './crypto.js';
import {
  getNamedCurveFromPublicMultikey,
  getNamedCurveFromSecretMultikey,
  getSecretKeySize,
  setPublicKeyHeader,
  setSecretKeyHeader
} from './helpers.js';
import elliptic from 'elliptic';

// FIXME: may need to move any leading zeros for bitstring compression; needs
// testing with various browsers
const PKCS8_PREFIXES = new Map([
  [ECDSA_CURVE.P256, {
    secret: new Uint8Array([
      48, 103, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72,
      206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
      1, 7, 4, 77, 48, 75, 2, 1, 1, 4, 32
    ]),
    public: new Uint8Array([161, 36, 3, 34, 0])
  }],
  [ECDSA_CURVE.P384, {
    secret: new Uint8Array([
      48, 129, 132, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34,
      4, 109, 48, 107, 2, 1, 1, 4, 48
    ]),
    public: new Uint8Array([161, 52, 3, 50, 0])
  }],
  [ECDSA_CURVE.P521, {
    secret: new Uint8Array([
      48, 129, 170, 2, 1, 0, 48, 16, 6, 7, 42, 134,
      72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35,
      4, 129, 146, 48, 129, 143, 2, 1, 1, 4, 66
    ]),
    public: new Uint8Array([161, 70, 3, 68, 0])
  }],
  [ECDSA_CURVE.secp256k1, {
    secret: new Uint8Array([
      // deal with compressed/uncompressed prefix?
      // uncompressed index 2 value 132 / compressed 103
      48, 129, 132, 2, 1, 0, 48, 16, 6,
      7, 42, 134, 72, 206, 61, 2, 1, 6,
      5, 43, 129, 4, 0, 10, 4, 109, 48,
      107, 2, 1, 1, 4, 32
    ]),
    public: new Uint8Array([161, 68, 3, 66, 0])
  }]
]);

const SPKI_PREFIXES = new Map([
  [ECDSA_CURVE.P256, new Uint8Array([
    48, 57, 48, 19, 6, 7, 42, 134, 72, 206,
    61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
    3, 1, 7, 3, 34, 0
  ])],
  [ECDSA_CURVE.P384, new Uint8Array([
    48, 70, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 34, 3, 50, 0
  ])],
  [ECDSA_CURVE.P521, new Uint8Array([
    48, 88, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
    1, 6, 5, 43, 129, 4, 0, 35, 3, 68, 0
  ])],
  [ECDSA_CURVE.secp256k1, new Uint8Array([
    48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1,
    6, 5, 43, 129, 4, 0, 10, 3, 66, 0
  ])]
]);

// converts key pair to PKCS #8 format
export async function cryptoKeyfromRaw({
  curve, secretKey, publicKey, keyAgreement
} = {}) {
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: curve
  };

  let cryptoKey;
  if(secretKey) {
    const pkcs8 = _rawToPkcs8({curve, secretKey, publicKey});
    const secretUsage = keyAgreement ? ['deriveBits'] : ['sign'];
    cryptoKey = await webcrypto.subtle.importKey(
      'pkcs8', pkcs8, algorithm, EXTRACTABLE, secretUsage);
  } else {
    const spki = _rawToSpki({curve, publicKey});
    // must be empty usage for importing a public key
    const publicUsage = keyAgreement ? [] : ['verify'];
    cryptoKey = await webcrypto.subtle.importKey(
      'spki', spki, algorithm, EXTRACTABLE, publicUsage);
  }
  return cryptoKey;
}

// exports key pair
export async function exportKeyPair({
  keyPair, secretKey, publicKey, includeContext
} = {}) {
  if(!(publicKey || secretKey)) {
    throw new TypeError(
      'Export requires specifying either "publicKey" or "secretKey".');
  }

  // get JWK
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);

  // export as Multikey
  const exported = {};
  if(includeContext) {
    exported['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  exported.id = keyPair.id;
  exported.type = 'Multikey';
  exported.controller = keyPair.controller;

  if(publicKey) {
    exported.publicKeyMultibase = toPublicKeyMultibase({jwk});
  }

  if(useSecretKey) {
    exported.secretKeyMultibase = toSecretKeyMultibase({jwk});
  }

  return exported;
}

function decompressKey(pubkey) { // pubkey should be 33 bytes
  const secp256k1 = new elliptic.ec('secp256k1');
  return Uint8Array.from(
    secp256k1.keyFromPublic(pubkey).getPublic(false, 'array')
  );
}

// imports key pair
export async function importKeyPair({
  id, controller, secretKeyMultibase, publicKeyMultibase, keyAgreement = false
}) {
  if(!publicKeyMultibase) {
    throw new TypeError('The "publicKeyMultibase" property is required.');
  }

  const keyPair = {id, controller};

  // import public key
  if(!(publicKeyMultibase && typeof publicKeyMultibase === 'string' &&
    publicKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
    throw new TypeError(
      '"publicKeyMultibase" must be a multibase, base58-encoded string.');
  }
  const publicMultikey = base58.decode(publicKeyMultibase.slice(1));

  // set named curved based on multikey header
  const algorithm = {
    name: keyAgreement ? 'ECDH' : ALGORITHM,
    namedCurve: getNamedCurveFromPublicMultikey({publicMultikey})
  };

  // import public key; convert to `spki` format because `jwk` doesn't handle
  // compressed public keys
  console.log('publicMultikey', publicMultikey);
  const spki = _multikeyToSpki({publicMultikey});
  console.log('spki', spki, algorithm);
  // must be empty usage for importing a public key
  const publicUsage = keyAgreement ? [] : ['verify'];
  if(algorithm.namedCurve === ECDSA_CURVE.secp256k1) {
    const {Crypto} = await import('@peculiar/webcrypto');
    const cryptoPolyfill = new Crypto();

    keyPair.publicKey = await cryptoPolyfill.subtle.importKey(
      'spki', spki, algorithm, EXTRACTABLE, publicUsage);

  } else {
    keyPair.publicKey = await webcrypto.subtle.importKey(
      'spki', spki, algorithm, EXTRACTABLE, publicUsage);
  }
  // import secret key if given
  if(secretKeyMultibase) {
    if(!(typeof secretKeyMultibase === 'string' &&
    secretKeyMultibase[0] === MULTIBASE_BASE58_HEADER)) {
      throw new TypeError(
        '"secretKeyMultibase" must be a multibase, base58-encoded string.');
    }
    const secretMultikey = base58.decode(secretKeyMultibase.slice(1));

    console.log('secretMultikey', secretMultikey);

    // ensure secret key multikey header appropriately matches the
    // public key multikey header
    _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey});

    // convert to `pkcs8` format for import because `jwk` doesn't support
    // compressed keys
    const pkcs8 = _multikeyToPkcs8({secretMultikey, publicMultikey});

    console.log('pkcs8', pkcs8);

    const secretUsage = keyAgreement ? ['deriveBits'] : ['sign'];

    if(algorithm.namedCurve === ECDSA_CURVE.secp256k1) {
      const {Crypto} = await import('@peculiar/webcrypto');
      const cryptoPolyfill = new Crypto();

      keyPair.secretKey = await cryptoPolyfill.subtle.importKey(
        'pkcs8', pkcs8, algorithm, EXTRACTABLE, secretUsage);

    } else {
      keyPair.secretKey = await webcrypto.subtle.importKey(
        'pkcs8', pkcs8, algorithm, EXTRACTABLE, secretUsage);
    }
  }

  return keyPair;
}

export function toPublicKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  // public key size is always secret key size + 1
  const publicKeySize = secretKeySize + 1;
  const publicKey = new Uint8Array(publicKeySize);
  // use even / odd status of `y` coordinate for compressed header
  const even = y[y.length - 1] % 2 === 0;
  publicKey[0] = even ? 2 : 3;
  // write `x` coordinate at end of multikey buffer to zero-fill it
  publicKey.set(x, publicKey.length - x.length);
  return publicKey;
}

export function toPublicKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  // convert `x` coordinate to compressed public key
  const x = base64url.decode(jwk.x);
  const y = base64url.decode(jwk.y);
  // public key size is always secret key size + 1
  const publicKeySize = secretKeySize + 1;
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + publicKeySize);
  setPublicKeyHeader({curve, buffer: multikey});
  // use even / odd status of `y` coordinate for compressed header
  const even = y[y.length - 1] % 2 === 0;
  multikey[2] = even ? 2 : 3;
  // write `x` coordinate at end of multikey buffer to zero-fill it
  multikey.set(x, multikey.length - x.length);
  const publicKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return publicKeyMultibase;
}

export function toSecretKeyBytes({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  const d = base64url.decode(jwk.d);
  const secretKey = new Uint8Array(secretKeySize);
  // write `d` at end of multikey buffer to zero-fill it
  secretKey.set(d, secretKey.length - d.length);
  return secretKey;
}

export function toSecretKeyMultibase({jwk} = {}) {
  if(jwk?.kty !== 'EC') {
    throw new TypeError('"jwk.kty" must be "EC".');
  }
  const {crv: curve} = jwk;
  const secretKeySize = getSecretKeySize({curve});
  const d = base64url.decode(jwk.d);
  // leave room for multicodec header (2 bytes)
  const multikey = new Uint8Array(2 + secretKeySize);
  setSecretKeyHeader({curve: jwk.crv, buffer: multikey});
  // write `d` at end of multikey buffer to zero-fill it
  multikey.set(d, multikey.length - d.length);
  const secretKeyMultibase = MULTIBASE_BASE58_HEADER + base58.encode(multikey);
  return secretKeyMultibase;
}

// ensures that public key header matches secret key header
function _ensureMultikeyHeadersMatch({secretMultikey, publicMultikey}) {
  const publicCurve = getNamedCurveFromPublicMultikey({publicMultikey});
  const secretCurve = getNamedCurveFromSecretMultikey({secretMultikey});
  if(publicCurve !== secretCurve) {
    throw new Error(
      `Public key curve ('${publicCurve}') does not match ` +
      `secret key curve ('${secretCurve}').`);
  }
}

// converts key pair to PKCS #8 format
function _multikeyToPkcs8({secretMultikey, publicMultikey}) {
  const curve = getNamedCurveFromSecretMultikey({secretMultikey});
  // omit multikey headers
  const secretKey = secretMultikey.subarray(2);
  const publicKey = publicMultikey.subarray(2);
  return _rawToPkcs8({curve, secretKey, publicKey});
}

function _multikeyToSpki({publicMultikey}) {
  const curve = getNamedCurveFromPublicMultikey({publicMultikey});
  // omit multikey header
  let publicKey = publicMultikey.subarray(2);
  console.log('public key before decompression', publicKey);
  if(curve === ECDSA_CURVE.secp256k1) {
    publicKey = decompressKey(publicKey);
    console.log('decompressed public key', publicKey);
  }
  return _rawToSpki({curve, publicKey});
}

// converts key pair to PKCS #8 format
export function _rawToPkcs8({curve, secretKey, publicKey}) {
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
        OCTET STRING (32 byte) (RAW SECRET KEY BYTES)
        [1] (1 elem)
          BIT STRING (COMPRESSED/UNCOMPRESSED PUBLIC KEY BYTES)

  This translates to:

  PKCS #8 DER SECRET KEY HEADER (w/algorithm OID for specific key type)
  RAW SECRET KEY BYTES
  PKCS #8 DER PUBLIC KEY HEADER
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const headers = PKCS8_PREFIXES.get(curve);
  if(!headers) {
    throw new Error(`Unsupported curve "${curve}".`);
  }
  if(curve === ECDSA_CURVE.secp256k1) {
    publicKey = decompressKey(publicKey);
    console.log('decompressed public key', publicKey);
  }
  console.log(headers.secret.length, secretKey.length,
    headers.public.length, 'pubkey length', publicKey.length, 'total', headers.secret.length + secretKey.length + headers.public.length + publicKey.length);
  const pkcs8 = new Uint8Array(
    headers.secret.length + secretKey.length +
    headers.public.length + publicKey.length);
  let offset = 0;
  pkcs8.set(headers.secret, offset);
  offset += headers.secret.length;
  pkcs8.set(secretKey, offset);
  offset += secretKey.length;
  pkcs8.set(headers.public, offset);
  offset += headers.public.length;
  pkcs8.set(publicKey, offset);
  return pkcs8;
}

// converts public key to SubjectPublicKeyInfo format
function _rawToSpki({curve, publicKey}) {
  /* Format:
  SPKI DER PUBLIC KEY HEADER (w/algorithm OID for specific key type)
  COMPRESSED / UNCOMPRESSED PUBLIC KEY BYTES */
  const header = SPKI_PREFIXES.get(curve);
  const spki = new Uint8Array(header.length + publicKey.length);
  let offset = 0;
  spki.set(header, offset);
  offset += header.length;
  spki.set(publicKey, offset);
  return spki;
}
