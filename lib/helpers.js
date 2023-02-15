/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {
  MULTIBASE_BASE58_HEADER,
  MULTICODEC_P256_PUBLIC_KEY_HEADER,
  MULTICODEC_P256_SECRET_KEY_HEADER,
  MULTICODEC_P384_PUBLIC_KEY_HEADER,
  MULTICODEC_P384_SECRET_KEY_HEADER,
  MULTICODEC_P521_PUBLIC_KEY_HEADER,
  MULTICODEC_P521_SECRET_KEY_HEADER
} from './constants.js';
import {EcdsaCurve} from './ecdsa.js';

export function getNamedCurve({publicMultikey}) {
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P256_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getSecondByte(MULTICODEC_P256_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P256;
    }
  }
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P384_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getSecondByte(MULTICODEC_P384_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P384;
    }
  }
  if(publicMultikey[0] === _getFirstByte(MULTICODEC_P521_PUBLIC_KEY_HEADER)) {
    if(publicMultikey[1] === _getSecondByte(MULTICODEC_P521_PUBLIC_KEY_HEADER)) {
      return EcdsaCurve.P521;
    }
  }

  // FIXME; also support P-256K/secp256k1
  const err = new Error('Unsupported multikey header.');
  err.name = 'UnsupportedError';
  throw err;
}

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

export function setSecretKeyHeader({keyPair, buffer}) {
  const key = keyPair.secretKey || keyPair.publicKey;
  const {namedCurve: curve} = key.algorithm;
  // FIXME: these must be added to the multicodec table
  if(curve === EcdsaCurve.P256) {
    buffer[0] = _getFirstByte(MULTICODEC_P256_SECRET_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P256_SECRET_KEY_HEADER);
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = _getFirstByte(MULTICODEC_P384_SECRET_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P384_SECRET_KEY_HEADER);
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = _getFirstByte(MULTICODEC_P521_SECRET_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P521_SECRET_KEY_HEADER);
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

export function setPublicKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.publicKey.algorithm;
  if(curve === EcdsaCurve.P256) {
    buffer[0] = _getFirstByte(MULTICODEC_P256_PUBLIC_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P256_PUBLIC_KEY_HEADER);
  } else if(curve === EcdsaCurve.P384) {
    buffer[0] = _getFirstByte(MULTICODEC_P384_PUBLIC_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P384_PUBLIC_KEY_HEADER);
  } else if(curve === EcdsaCurve.P521) {
    buffer[0] = _getFirstByte(MULTICODEC_P521_PUBLIC_KEY_HEADER);
    buffer[1] = _getSecondByte(MULTICODEC_P521_PUBLIC_KEY_HEADER);
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

function _getFirstByte(data) {
  return data >> 8;
}

function _getSecondByte(data) {
  return data & 0x00ff;
}
