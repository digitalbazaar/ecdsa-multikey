/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {mockKeyEcdsaSecp256k1} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';
chai.should();
const {expect} = chai;

const keyPair = await EcdsaMultikey.from({
  controller: 'did:example:1234',
  ...mockKeyEcdsaSecp256k1
});
const signer = keyPair.signer();
const verifier = keyPair.verifier();

describe('sign and verify', () => {
  it('works properly', async () => {
    signer.should.have.property(
      'id',
      'did:example:1234#zQ3shwLBJHiP3Z3g9j4AsiFYNXApgBsb8FG6mXvzukxTzwS3R'
    );
    verifier.should.have.property(
      'id',
      'did:example:1234#zQ3shwLBJHiP3Z3g9j4AsiFYNXApgBsb8FG6mXvzukxTzwS3R'
    );
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('has proper signature format', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    expect(signature).to.be.instanceof(Uint8Array);
  });

  it('fails if signing data is changed', async () => {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
});
