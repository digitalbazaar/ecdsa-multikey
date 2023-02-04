/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {webcrypto} from './ecdsa.js';

export function createSigner({privateKey}) {
  const {namedCurve: curve} = privateKey.algorithm;
  const algorithm = {name: 'ECDSA', hash: {name: _getEcdsaHash({curve})}};
  return {
    async sign({data} = {}) {
      return webcrypto.subtle.sign(algorithm, privateKey, data);
    }
  };
}

export function createVerifier({publicKey}) {
  const {namedCurve: curve} = publicKey.algorithm;
  const algorithm = {name: 'ECDSA', hash: {name: _getEcdsaHash({curve})}};
  return {
    async verify({data, signature} = {}) {
      return webcrypto.subtle.verify(algorithm, publicKey, signature, data);
    }
  };
}

function _getEcdsaHash({curve}) {
  if(curve === 'P-256') {
    return 'SHA-256';
  }
  if(curve === 'P-384') {
    return 'SHA-384';
  }
  if(curve === 'P-521') {
    return 'SHA-512';
  }
  throw Error(`Unsupported curve "${curve}".`);
}
