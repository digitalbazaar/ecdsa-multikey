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
import {
  exportKeyPair, importKeyPair,
  toPublicKeyBytes, toSecretKeyBytes,
  toPublicKeyMultibase, toSecretKeyMultibase
} from './serialize.js';
import {getSecretKeySize} from './helpers.js';
import {toMultikey} from './translators.js';

// FIXME: support `P-256K` via `@noble/secp256k1`
// generates ECDSA key pair
export async function generate({
  id, controller, curve, keyAgreement = false
} = {}) {
  if(!curve) {
    throw new TypeError(
      '"curve" must be one of the following values: ' +
      `${Object.values(ECDSA_CURVE).map(v => `'${v}'`).join(', ')}.`);
  }
  const algorithm = keyAgreement ?
    {name: 'ECDH', namedCurve: curve} : {name: ALGORITHM, namedCurve: curve};
  const usage = keyAgreement ? ['deriveBits'] : ['sign', 'verify'];
  const keyPair = await webcrypto.subtle.generateKey(
    algorithm, EXTRACTABLE, usage);
  keyPair.secretKey = keyPair.privateKey;
  delete keyPair.privateKey;
  const keyPairInterface = await _createKeyPairInterface(
    {keyPair, keyAgreement});
  const exportedKeyPair = await keyPairInterface.export({publicKey: true});
  const {publicKeyMultibase} = exportedKeyPair;
  if(controller && !id) {
    id = `${controller}#${publicKeyMultibase}`;
  }
  keyPairInterface.id = id;
  keyPairInterface.controller = controller;
  return keyPairInterface;
}

// imports P-256 key pair from JSON Multikey
export async function from(key, keyAgreement = false) {
  let multikey = {...key};
  if(multikey.type && multikey.type !== 'Multikey') {
    multikey = await toMultikey({keyPair: multikey});
    return _createKeyPairInterface({keyPair: multikey, keyAgreement});
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
  return _createKeyPairInterface({keyPair: multikey, keyAgreement});
}

// imports key pair from JWK
export async function fromJwk({jwk, secretKey = false} = {}) {
  const multikey = {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    type: 'Multikey',
    publicKeyMultibase: toPublicKeyMultibase({jwk})
  };
  if(secretKey && jwk.d) {
    multikey.secretKeyMultibase = toSecretKeyMultibase({jwk});
  }
  const keyAgreement = !jwk.key_ops || jwk.key_ops.includes('deriveBits');
  return from(multikey, keyAgreement);
}

// converts key pair to JWK
export async function toJwk({keyPair, secretKey = false} = {}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const useSecretKey = secretKey && !!keyPair.secretKey;
  const cryptoKey = useSecretKey ? keyPair.secretKey : keyPair.publicKey;
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
  return jwk;
}

// augments key pair with useful metadata and utilities
async function _createKeyPairInterface({keyPair, keyAgreement = false}) {
  if(!(keyPair?.publicKey instanceof CryptoKey)) {
    keyPair = await importKeyPair(keyPair);
  }
  const exportFn = async ({
    publicKey = true, secretKey = false, includeContext = true, raw = false
  } = {}) => {
    if(raw) {
      const jwk = await toJwk({keyPair, secretKey});
      const result = {};
      if(publicKey) {
        result.publicKey = toPublicKeyBytes({jwk});
      }
      if(secretKey) {
        result.secretKey = toSecretKeyBytes({jwk});
      }
      return result;
    }
    return exportKeyPair({keyPair, publicKey, secretKey, includeContext});
  };
  const {publicKeyMultibase, secretKeyMultibase} = await exportFn({
    publicKey: true, secretKey: true, includeContext: true
  });
  keyPair = {
    ...keyPair,
    publicKeyMultibase,
    secretKeyMultibase,
    keyAgreement,
    export: exportFn,
    signer() {
      const {id, secretKey} = keyPair;
      return createSigner({id, secretKey});
    },
    verifier() {
      const {id, publicKey} = keyPair;
      return createVerifier({id, publicKey});
    },
    // pass `publicKey`, as `remotePublicKey` is just a backwards compatible
    // alias
    async deriveSecret({publicKey, remotePublicKey} = {}) {
      if(remotePublicKey && publicKey) {
        throw new Error(
          'Only one of "remotePublicKey" and "publicKey" must be given.');
      }
      if(!keyPair.keyAgreement) {
        const error = Error('"keyAgreement" is not supported by this keypair.');
        error.name = 'NotSupportedError';
        throw error;
      }
      return _deriveSecret(
        {localKeyPair: this, remoteKeyPair: remotePublicKey || publicKey});
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
      `"${MULTIKEY_CONTEXT_V1_URL}".`);
  }
}

async function _deriveSecret({localKeyPair, remoteKeyPair}) {
  if(!localKeyPair.secretKey) {
    const error = Error('"secretKey" required to derive secret.');
    error.name = 'NotSupportedError';
    throw error;
  }

  // import keys with `keyAgreement` key usage
  localKeyPair = await importKeyPair({...localKeyPair, keyAgreement: true});
  remoteKeyPair = await importKeyPair({...remoteKeyPair, keyAgreement: true});

  // produce shared secret that is the same size as a secret key, the
  // shared secret should be used as just one input to a KDF
  const {namedCurve: curve} = localKeyPair.secretKey.algorithm;
  const secretSize = getSecretKeySize({curve});
  const arrayBuffer = await webcrypto.subtle.deriveBits({
    name: 'ECDH',
    namedCurve: curve,
    public: remoteKeyPair.publicKey,
  }, localKeyPair.secretKey, secretSize * 8);
  return new Uint8Array(arrayBuffer, 0, secretSize);
}
