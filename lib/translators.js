/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {
  ECDSA_2019_SECP_256_KEY_TYPE,
  ECDSA_2019_SECP_384_KEY_TYPE,
  ECDSA_2019_SECP_521_KEY_TYPE,
  ECDSA_2019_SUITE_CONTEXT_V1_URL,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';
import {mbEncodeKeyPair} from './helpers.js';

export async function toMultikey({keyPair}) {
  const validEcdsaTypes = [
    ECDSA_2019_SECP_256_KEY_TYPE,
    ECDSA_2019_SECP_384_KEY_TYPE,
    ECDSA_2019_SECP_521_KEY_TYPE
  ];
  if (!validEcdsaTypes.includes(keyPair.type)) {
    throw new Error(`Unsupported key type "${keyPair.type}".`);
  }

  if(!keyPair['@context']) {
    keyPair['@context'] = ECDSA_2019_SUITE_CONTEXT_V1_URL;
  }
  if(!_includesContext({document: keyPair, contextUrl: ECDSA_2019_SUITE_CONTEXT_V1_URL})) {
    throw new Error(`Context not supported "${keyPair['@context']}".`);
  }

  return _translateEcdsa2019VerificationKey({keyPair});
}

async function _translateEcdsa2019VerificationKey({keyPair}) {
  const key = {
    publicKey: base58.decode(keyPair.publicKeyBase58),
    secretKey: undefined
  };

  if(keyPair.privateKeyBase58) {
    key.secretKey = base58.decode(keyPair.privateKeyBase58);
  }

  const {publicKeyMultibase, secretKeyMultibase} = mbEncodeKeyPair({
    keyPair: key
  });

  return {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    id: keyPair.id,
    type: 'Multikey',
    controller: keyPair.controller,
    publicKeyMultibase,
    secretKeyMultibase
  };
}

function _includesContext({document, contextUrl}) {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}
