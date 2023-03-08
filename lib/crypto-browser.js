/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
// eslint-disable-next-line unicorn/prefer-node-protocol
import {Buffer} from 'buffer';
// eslint-disable-next-line no-undef
window.Buffer = Buffer;

// eslint-disable-next-line no-undef
export const webcrypto = globalThis.crypto;
// eslint-disable-next-line no-undef
export const CryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
