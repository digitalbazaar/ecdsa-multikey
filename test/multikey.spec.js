/*!
 * Copyright (c) 2024 Digital Bazaar, Inc.
 */

import {multikeys} from './mock-data.js';
import {
  testAlgorithm,
  testExport,
  testFrom,
  testGenerate,
  testJWK,
  testRaw,
  testSignVerify
} from './assertions.js';

describe('ecdsa-multikey', function() {
  for(const [keyType, options] of multikeys) {
    const {
      id,
      serializedKeyPair,
      props
    } = options;
    describe(keyType, function() {
      describe('algorithm', function() {
        testAlgorithm({keyType, serializedKeyPair});
      });
      describe('generate', function() {
        testGenerate({curve: keyType, ...props});
      });
      describe('export', () => {
        testExport({curve: keyType});
      });
      describe('sign and verify', function() {
        testSignVerify({id, serializedKeyPair, keyType});
      });
      describe('from', function() {
        testFrom({keyType, id, serializedKeyPair});
      });
      describe('fromJwk/toJwk', () => {
        testJWK({curve: keyType});
      });
      describe('fromRaw', () => {
        testRaw({curve: keyType});
      });
    });
  }
});
