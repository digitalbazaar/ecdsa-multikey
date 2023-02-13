/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {ALGORITHM} from './constants.js';
import {webcrypto, EcdsaCurve, EcdsaHash} from './ecdsa.js';

export function createSigner({id, secretKey}) {
  if(!secretKey) {
    throw new Error('A secret key is not available for signing.');
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

export function createVerifier({id, publicKey}) {
  if(!publicKey) {
    throw new Error('A public key is not available for verifying.');
  }
  const {namedCurve: curve} = publicKey.algorithm;
  const algorithm = {name: 'ECDSA', hash: {name: _getEcdsaHash({curve})}};
  return {
    algorithm: ALGORITHM,
    id,
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

function _getEcdsaHash({curve}) {
  if(curve === EcdsaCurve.P256) {
    return EcdsaHash.Sha256;
  }
  if(curve === EcdsaCurve.P384) {
    return EcdsaHash.Sha384;
  }
  if(curve === EcdsaCurve.P521) {
    return EcdsaHash.Sha512;
  }
  throw Error(`Unsupported curve "${curve}".`);
}
