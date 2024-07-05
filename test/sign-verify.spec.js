/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {keyTypes} from './mock-data.js';
import {stringToUint8Array} from './text-encoder.js';

chai.should();
const {expect} = chai;

for(const [keyType, exportedKey] of keyTypes) {
  _testKeyType({keyType, exportedKey});
}

function _testKeyType({keyType, exportedKey}) {
  describe(keyType, function() {
    describe(`sign and verify`, async function() {
      const id = `${exportedKey.controller}#${exportedKey.publicMultibase}`;
      const keyPair = await EcdsaMultikey.from({
        id,
        ...exportedKey
      });
      const signer = keyPair.signer();
      const verifier = keyPair.verifier();

      it('works properly', async () => {
        signer.should.have.property('id', id);
        verifier.should.have.property('id', id);
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
  });
}
