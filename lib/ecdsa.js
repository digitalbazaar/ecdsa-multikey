/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {webcrypto} from 'node:crypto';
const {CryptoKey} = webcrypto;
export {CryptoKey, webcrypto};

// ECDSA curves
export const EcdsaCurve = {
  P256: 'P-256',
  P384: 'P-384',
  P521: 'P-521'
};

// ECDSA hash functions
export const EcdsaHash = {
  Sha256: 'SHA-256',
  Sha384: 'SHA-384',
  Sha512: 'SHA-512'
};
