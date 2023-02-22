/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
// eslint-disable-next-line no-undef
export const webcrypto = globalThis.crypto;
// eslint-disable-next-line no-undef
export const CryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
