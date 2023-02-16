/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  ECDSA_2019_SECP_256_KEY_TYPE,
  ECDSA_2019_SECP_384_KEY_TYPE,
  ECDSA_2019_SECP_521_KEY_TYPE,
  ECDSA_2019_SUITE_CONTEXT_V1_URL,
  MULTIKEY_CONTEXT_V1_URL
} from './constants.js';

// converts key pair to Multikey format
export async function toMultikey({keyPair}) {
  const validEcdsaTypes = [
    ECDSA_2019_SECP_256_KEY_TYPE,
    ECDSA_2019_SECP_384_KEY_TYPE,
    ECDSA_2019_SECP_521_KEY_TYPE
  ];
  if(!validEcdsaTypes.includes(keyPair.type)) {
    throw new Error(`Unsupported key type "${keyPair.type}".`);
  }

  if(!keyPair['@context']) {
    keyPair['@context'] = ECDSA_2019_SUITE_CONTEXT_V1_URL;
  }
  if(!_includesContext({
    document: keyPair,
    contextUrl: ECDSA_2019_SUITE_CONTEXT_V1_URL
  })) {
    throw new Error(`Context not supported "${keyPair['@context']}".`);
  }

  return {
    '@context': MULTIKEY_CONTEXT_V1_URL,
    id: keyPair.id,
    type: 'Multikey',
    controller: keyPair.controller,
    publicKeyMultibase: keyPair.publicKeyMultibase,
    secretKeyMultibase: keyPair.secretKeyMultibase
  };
}

// checks if context was properly included in document
function _includesContext({document, contextUrl}) {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}
