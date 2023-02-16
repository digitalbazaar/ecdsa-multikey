/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  MULTICODEC_P256_PUBLIC_KEY_HEADER,
  MULTICODEC_P256_SECRET_KEY_HEADER,
  MULTICODEC_P384_PUBLIC_KEY_HEADER,
  MULTICODEC_P384_SECRET_KEY_HEADER,
  MULTICODEC_P521_PUBLIC_KEY_HEADER,
  MULTICODEC_P521_SECRET_KEY_HEADER
} from './constants.js';
import {EcdsaCurve} from './ecdsa.js';

// retrieves name of appropriate ECDSA curve
export function getNamedCurve({publicMultikey}) {
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P256_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getLastByte(MULTICODEC_P256_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P256;
    }
  }
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P384_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getLastByte(MULTICODEC_P384_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P384;
    }
  }
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P521_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getLastByte(MULTICODEC_P521_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P521;
    }
  }

  // FIXME; also support P-256K/secp256k1
  const err = new Error('Unsupported multikey header.');
  err.name = 'UnsupportedError';
  throw err;
}

// retrieves size of secret key
export function getSecretKeySize({keyPair}) {
  const key = keyPair.secretKey || keyPair.publicKey;
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

// sets secret key header bytes on key pair
export function setSecretKeyHeader({keyPair, buffer}) {
  const key = keyPair.secretKey || keyPair.publicKey;
  const {namedCurve: curve} = key.algorithm;
  // FIXME: these must be added to the multicodec table
  if(curve === EcdsaCurve.P256) {
    buffer[0] = _getFirstByte(MULTICODEC_P256_SECRET_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P256_SECRET_KEY_HEADER);
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = _getFirstByte(MULTICODEC_P384_SECRET_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P384_SECRET_KEY_HEADER);
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = _getFirstByte(MULTICODEC_P521_SECRET_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P521_SECRET_KEY_HEADER);
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

// sets public key header bytes on key pair
export function setPublicKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.publicKey.algorithm;
  if(curve === EcdsaCurve.P256) {
    buffer[0] = _getFirstByte(MULTICODEC_P256_PUBLIC_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P256_PUBLIC_KEY_HEADER);
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = _getFirstByte(MULTICODEC_P384_PUBLIC_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P384_PUBLIC_KEY_HEADER);
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = _getFirstByte(MULTICODEC_P521_PUBLIC_KEY_HEADER);
    buffer[1] = _getLastByte(MULTICODEC_P521_PUBLIC_KEY_HEADER);
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

// get first byte of data
function _getFirstByte(data) {
  return data >> 8;
}

// get last byte of data
function _getLastByte(data) {
  return data & 0x00ff;
}
