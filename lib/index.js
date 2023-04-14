/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ALGORITHM,
  ECDSA_CURVE,
  EXTRACTABLE,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {CryptoKey, webcrypto} from './crypto.js';
import {createSigner, createVerifier} from './factory.js';
import {exportKeyPair, importKeyPair} from './serialize.js';
import {toMultikey} from './translators.js';

// FIXME: support `P-256K` via `@noble/secp256k1`
// generates ECDSA key pair
export async function generate({id, controller, curve} = {}) {
  if(!curve) {
    throw new TypeError(
      '"curve" must be one of the following values: ' +
      `${Object.values(ECDSA_CURVE).map(v => `'${v}'`).join(', ')}.`
    );
  }
  const algorithm = {name: ALGORITHM, namedCurve: curve};
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, ['sign', 'verify']
  );
  keyPair.secretKey = keyPair.privateKey;
  delete keyPair.privateKey;
  const keyPairInterface = await _createKeyPairInterface({keyPair});
  const exportedKeyPair = await keyPairInterface.export({publicKey: true});
  const {publicKeyMultibase} = exportedKeyPair;
  if(controller && !id) {
    id = `${controller}#${publicKeyMultibase}`;
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  return keyPairInterface;
}

// imports ECDSA key pair from JSON Multikey
export async function from(key) {
  let multikey = {...key};
  if(multikey.type && multikey.type !== 'Multikey') {
    multikey = await toMultikey({keyPair: multikey});
    return _createKeyPairInterface({keyPair: multikey});
  }
  if(!multikey.type) {
    multikey.type = 'Multikey';
  }
  if(!multikey['@context']) {
    multikey['@context'] = MULTIKEY_CONTEXT_V1_URL;
  }
  if(multikey.controller && !multikey.id) {
    multikey.id = `${key.controller}#${key.publicKeyMultibase}`;
  }

  _assertMultikey(multikey);
  return _createKeyPairInterface({keyPair: multikey});
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true
  } = {}) => {
    return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
  };
  const {publicKeyMultibase, secretKeyMultibase} = await exportFn({
    publicKey: true, secretKey: true, includeContext: true
  });
  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
    }
  };

  return keyPair;
}

// checks if key pair is in Multikey format
function _assertMultikey(key) {
  if(!(key && typeof key === 'object')) {
    throw new TypeError('"key" must be an object.');
  }
  if(key.type !== 'Multikey') {
    throw new TypeError('"key" must be a Multikey with type "Multikey".');
  }
  if(key['@context'] !== MULTIKEY_CONTEXT_V1_URL) {
    throw new TypeError(
      '"key" must be a Multikey with context ' +
      `"${MULTIKEY_CONTEXT_V1_URL}".`
    );
  }
}
