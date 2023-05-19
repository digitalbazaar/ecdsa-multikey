/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {webcrypto} from 'node:crypto';
const CryptoKey = globalThis.CryptoKey ?? webcrypto.CryptoKey;
export {CryptoKey, webcrypto};
