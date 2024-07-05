/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {keyTypes} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';

chai.should();
const {expect} = chai;

describe('sign and verify', function() {
  for(const [keyType, exportedKey] of keyTypes) {
    describe(keyType, function() {
      const id = `${exportedKey.controller}#${exportedKey.publicKeyMultibase}`;
      _testKeyType({id, exportedKey, keyType});
    });
  }
});

function _testKeyType({id, exportedKey, keyType}) {
  let signer;
  let verifier;
  before(async function() {
    const keyPair = await EcdsaMultikey.from({
      id,
      ...exportedKey
    });
    signer = keyPair.signer();
    verifier = keyPair.verifier();
  });
  it('should have correct id', function() {
    signer.should.have.property('id', id);
    verifier.should.have.property('id', id);
  });
  it(`should have algorithm ${keyType}`, function() {
    signer.should.have.property('algorithm', keyType);
    verifier.should.have.property('algorithm', keyType);
  });
  it('should sign & verify', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const result = await verifier.verify({data, signature});
    result.should.be.true;
  });

  it('has proper signature format', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    expect(signature).to.be.instanceof(Uint8Array);
  });

  it('fails if signing data is changed', async function() {
    const data = stringToUint8Array('test 1234');
    const signature = await signer.sign({data});
    const changedData = stringToUint8Array('test 4321');
    const result = await verifier.verify({data: changedData, signature});
    result.should.be.false;
  });
}
