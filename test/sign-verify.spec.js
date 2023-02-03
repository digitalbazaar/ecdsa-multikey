/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();

import * as EcdsaMultikey from '../lib/index.js';
import {mockKey, suites} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
import * as base58btc from 'base58-universal';

const keyPair = await EcdsaMultikey.from({
  controller: 'did:example:1234',
  ...mockKey
});
const signer = keyPair.signer();
const verifier = keyPair.verifier();

describe('sign and verify', () => {
  it('works properly', async () => {
  });

  it('fails if signing data is changed', async () => {
  });
  // these tests simulate what happens when a key & signature
  // created in either the browser or the node is verified
  // in a different enviroment
  for(const suite of suites) {
    it(suite.title, async () => {
    });
  }
});
