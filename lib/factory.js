/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM, ECDSA_CURVE, ECDSA_HASH} from './constants.js';
import {webcrypto} from './crypto.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const {namedCurve: curve} = secretKey.algorithm;
  const algorithm = {name: ALGORITHM, hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: curve,
    id,
    async sign({data} = {}) {
      if(curve === ECDSA_CURVE.secp256k1) {
        const {Crypto} = await import('@peculiar/webcrypto');
        const cryptoPolyfill = new Crypto();
        return new Uint8Array(await cryptoPolyfill.subtle.sign(
          algorithm, secretKey, data));
      } else {
        return new Uint8Array(await webcrypto.subtle.sign(
          algorithm, secretKey, data));
      }
    }
  };
}

// exposes verify method
export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('"publicKey" is required for verifying.');
  }
  const {namedCurve: curve} = publicKey.algorithm;
  const algorithm = {name: ALGORITHM, hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: curve,
    id,
    async verify({data, signature} = {}) {
      if(curve === ECDSA_CURVE.secp256k1) {
        const {Crypto} = await import('@peculiar/webcrypto');
        const cryptoPolyfill = new Crypto();
        return cryptoPolyfill.subtle
          .verify(algorithm, publicKey, signature, data);
      }
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ECDSA hash function
function _getEcdsaHash({curve}) {
  if(curve === ECDSA_CURVE.P256 || curve === ECDSA_CURVE.secp256k1) {
    return ECDSA_HASH.SHA256;
  }
  if(curve === ECDSA_CURVE.P384) {
    return ECDSA_HASH.SHA384;
  }
  if(curve === ECDSA_CURVE.P521) {
    return ECDSA_HASH.SHA512;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}
