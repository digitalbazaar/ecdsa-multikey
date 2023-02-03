/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {MULTIKEY_CONTEXT_V1_URL} from './constants.js';

export async function generate({id, controller} = {}) {

}

// import key pair from JSON Multikey
export async function from(key) {

}

async function _createKeyPairInterface({keyPair}) {
  return keyPair;
}

function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new Error('"key" must be a Multikey with type "Multikey".');
  }
  if(key['@context'] !== MULTIKEY_CONTEXT_V1_URL) {
    throw new Error('"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}
