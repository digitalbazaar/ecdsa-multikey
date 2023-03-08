/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import arrayBufferToBuffer from 'arraybuffer-to-buffer';
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
      const dataArrayBuffer = await webcrypto.subtle.sign(
        algorithm,
        secretKey,
        data
      );
      return arrayBufferToBuffer(dataArrayBuffer);
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
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

// retrieves name of appropriate ECDSA hash function
function _getEcdsaHash({curve}) {
  if(curve === ECDSA_CURVE.P256) {
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
