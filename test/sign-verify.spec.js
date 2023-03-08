/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {mockKey} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
chai.should();
const {expect} = chai;

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

  it('has proper signature format', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});

    // check some expected properties of a Buffer object
    expect(signature).to.have.property('buffer');
    expect(signature).to.have.property('byteLength');
    expect(signature).to.have.property('byteOffset');
    expect(signature).to.have.property('compare');
    expect(signature).to.have.property('copy');
    expect(signature).to.have.property('entries');
    expect(signature).to.have.property('equals');
    expect(signature).to.have.property('fill');
    expect(signature).to.have.property('includes');
    expect(signature).to.have.property('slice');
    expect(signature).to.have.property('write');
  });

  it('fails if signing data is changed', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
});
