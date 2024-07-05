/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import {keyTypes} from './mock-data.js';
import {testSignVerify} from './assertions.js';

describe('sign and verify', function() {
  for(const [keyType, {serializedKeyPair, id}] of keyTypes) {
    describe(keyType, function() {
      testSignVerify({id, serializedKeyPair, keyType});
    });
  }
});
