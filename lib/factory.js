/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM, ECDSA_CURVE, ECDSA_HASH} from './constants.js';
import {webcrypto} from './ecdsa.js';

// exposes sign method
export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('"secretKey" is required for signing.');
  }
  const {namedCurve: curve} = secretKey.algorithm;
  const algorithm = {name: ALGORITHM, hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: ALGORITHM,
    id,
    async sign({data} = {}) {
      return webcrypto.subtle.sign(algorithm, secretKey, data);
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
    algorithm: ALGORITHM,
    id,
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ECDSA hash function
function _getEcdsaHash({curve}) {
  if(curve === ECDSA_CURVE.P256) {
    return ECDSA_HASH.Sha256;
  }
  if(curve === ECDSA_CURVE.P384) {
    return ECDSA_HASH.Sha384;
  }
  if(curve === ECDSA_CURVE.P521) {
    return ECDSA_HASH.Sha512;
  }
  throw new TypeError(`Unsupported curve "${curve}".`);
}
