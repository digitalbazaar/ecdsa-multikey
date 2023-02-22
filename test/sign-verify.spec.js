/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {mockKey} from './mock-data.js';
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
    signer.should.have.property(
      'id',
      'did:example:1234#zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw'
    );
    verifier.should.have.property(
      'id',
      'did:example:1234#zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw'
    );
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
});
