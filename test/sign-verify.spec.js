/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {mockKey, suites} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
chai.should();

const keyPair = await EcdsaMultikey.from({
  controller: 'did:example:1234',
  ...mockKey
});
const signer = keyPair.signer();
const verifier = keyPair.verifier();

describe('sign and verify', () => {
  it('works properly', async () => {
    signer.should.have.property('id',
      'did:example:1234#zynkLvFajqEANBYZ7BbjYfjZWEKxC2o1cFWbvsK4XzSDyjJ6Unze3XNAvBNKkfCPRHAEQY');
    verifier.should.have.property('id',
      'did:example:1234#zynkLvFajqEANBYZ7BbjYfjZWEKxC2o1cFWbvsK4XzSDyjJ6Unze3XNAvBNKkfCPRHAEQY');
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('fails if signing data is changed', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
  // these tests simulate what happens when a key & signature
  // created in either the browser or the node is verified
  // in a different enviroment
  for(const suite of suites) {
    it(suite.title, async () => {
      const _keyPair = await EcdsaMultikey.from({
        controller: 'did:example:1234',
        ...suite.key
      });

      const data = stringToUint8Array(suite.data);
      const signature = base58.decode(suite.signature);
      const result = await _keyPair.verifier().verify({data, signature});
      result.should.be.true;
    });
  }
});
