/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {
  MULTIBASE_BASE58_HEADER,
  MULTICODEC_ECDSA_PUB_HEADER_BYTE_1,
  MULTICODEC_P256_PUB_HEADER_BYTE_2,
  MULTICODEC_P384_PUB_HEADER_BYTE_2,
  MULTICODEC_P521_PUB_HEADER_BYTE_2,
  MULTICODEC_ECDSA_PRIV_HEADER_BYTE_1,
  MULTICODEC_P256_PRIV_HEADER_BYTE_2,
  MULTICODEC_P384_PRIV_HEADER_BYTE_2,
  MULTICODEC_P521_PRIV_HEADER_BYTE_2,
} from './constants.js';
import {EcdsaCurve} from './ecdsa.js';

export function getNamedCurve({publicMultikey}) {
  if(publicMultikey[0] === MULTICODEC_ECDSA_PUB_HEADER_BYTE_1) {
    if(publicMultikey[1] === MULTICODEC_P256_PUB_HEADER_BYTE_2) {
      return EcdsaCurve.P256;
    }
    if(publicMultikey[1] === MULTICODEC_P384_PUB_HEADER_BYTE_2) {
      return EcdsaCurve.P384;
    }
    if(publicMultikey[1] === MULTICODEC_P521_PUB_HEADER_BYTE_2) {
      return EcdsaCurve.P521;
    }
  }

  // FIXME; also support P-256K/secp256k1
  const err = new Error('Unsupported multikey header.');
  err.name = 'UnsupportedError';
  throw err;
}

export function getPrivateKeySize({keyPair}) {
  const key = keyPair.privateKey || keyPair.publicKey;
  const {namedCurve: curve} = key.algorithm;
  if(curve === EcdsaCurve.P256) {
    return 32;
  }
  if(curve === EcdsaCurve.P384) {
    return 48;
  }
  if(curve === EcdsaCurve.P521) {
    return 66;
  }
  throw new Error(`Unsupported curve "${curve}".`);
}

export function setPrivateKeyHeader({keyPair, buffer}) {
  const key = keyPair.privateKey || keyPair.publicKey;
  const {namedCurve: curve} = key.algorithm;
  // FIXME: these must be added to the multicodec table
  if(curve === EcdsaCurve.P256) {
    buffer[0] = MULTICODEC_ECDSA_PRIV_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P256_PRIV_HEADER_BYTE_2;
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = MULTICODEC_ECDSA_PRIV_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P384_PRIV_HEADER_BYTE_2;
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = MULTICODEC_ECDSA_PRIV_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P521_PRIV_HEADER_BYTE_2;
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

export function setPublicKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.publicKey.algorithm;
  if(curve === EcdsaCurve.P256) {
    buffer[0] = MULTICODEC_ECDSA_PUB_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P256_PUB_HEADER_BYTE_2;
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = MULTICODEC_ECDSA_PUB_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P384_PUB_HEADER_BYTE_2;
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = MULTICODEC_ECDSA_PUB_HEADER_BYTE_1;
    buffer[1] = MULTICODEC_P521_PUB_HEADER_BYTE_2;
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

export function mbEncodeKeyPair({keyPair}) {
  const publicKeyMultibase =
    _encodeMbKey(MULTICODEC_PUB_HEADER, keyPair.publicKey);
  const secretKeyMultibase =
    _encodeMbKey(MULTICODEC_PRIV_HEADER, keyPair.secretKey);

  return {
    publicKeyMultibase,
    secretKeyMultibase
  };
}

// encode a multibase base58 multicodec key
function _encodeMbKey(header, key) {
  const mbKey = new Uint8Array(header.length + key.length);

  mbKey.set(header);
  mbKey.set(key, header.length);

  return MULTIBASE_BASE58_HEADER + base58.encode(mbKey);
}
