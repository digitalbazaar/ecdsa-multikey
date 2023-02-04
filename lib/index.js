/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {EXTRACTABLE, MULTIKEY_CONTEXT_V1_URL} from './constants.js';
import {CryptoKey, webcrypto} from './ecdsa.js';
import {createSigner, createVerifier} from './factory.js';
import {exportKeyPair, importKeyPair} from './serialize.js';

// FIXME: support `P-256K` via `@noble/secp256k1`
export async function generate({id, curve} = {}) {
  const algorithm = {name: 'ECDSA', namedCurve: curve};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign']);
  keyPair.id = id;
  return _createKeyPairInterface({keyPair});
}

// import key pair from JSON Multikey
export async function from(key) {
  _assertMultikey(key);
  return _createKeyPairInterface({keyPair: key});
}

async function _createKeyPairInterface({keyPair}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  return {
    _keyPair: keyPair,
    async export({
      publicKey = true, privateKey = false, includeContext = true
    } = {}) {
      return exportKeyPair({keyPair, publicKey, privateKey, includeContext});
    },
    signer() {
      const {privateKey} = keyPair;
      return createSigner({privateKey});
    },
    verifier() {
      const {publicKey} = keyPair;
      return createVerifier({publicKey});
    }
  };
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
