/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
export function getNamedCurve({publicMultikey}) {
  if(publicMultikey[0] === 0x12) {
    if(publicMultikey[1] === 0x00) {
      return 'P-256';
    }
    if(publicMultikey[1] === 0x01) {
      return 'P-384';
    }
    if(publicMultikey[1] === 0x02) {
      return 'P-521';
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
  if(curve === 'P-256') {
    return 32;
  }
  if(curve === 'P-384') {
    return 48;
  }
  if(curve === 'P-521') {
    return 66;
  }
  throw new Error(`Unsupported curve "${curve}".`);
}

export function setPrivateKeyHeader({keyPair, buffer}) {
  const key = keyPair.privateKey || keyPair.publicKey;
  const {namedCurve: curve} = key.algorithm;
  // FIXME: these must be added to the multicodec table
  if(curve === 'P-256') {
    buffer[0] = 0x13;
    buffer[1] = 0x03;
  } else if(curve === 'P-384') {
    buffer[0] = 0x13;
    buffer[1] = 0x04;
  } else if(curve === 'P-521') {
    buffer[0] = 0x13;
    buffer[1] = 0x05;
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}

export function setPublicKeyHeader({keyPair, buffer}) {
  const {namedCurve: curve} = keyPair.publicKey.algorithm;
  if(curve === 'P-256') {
    buffer[0] = 0x12;
    buffer[1] = 0x00;
  } else if(curve === 'P-384') {
    buffer[0] = 0x12;
    buffer[1] = 0x01;
  } else if(curve === 'P-521') {
    buffer[0] = 0x12;
    buffer[1] = 0x02;
  } else {
    throw new Error(`Unsupported curve "${curve}".`);
  }
}
