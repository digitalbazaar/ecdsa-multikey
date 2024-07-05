/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as EcdsaMultikey from '../lib/index.js';
import chai from 'chai';
import {
  mockKeyEcdsaSecp256,
  mockKeyEcdsaSecp384,
  mockKeyEcdsaSecp521,
} from './mock-data.js';

const should = chai.should();
const {expect} = chai;

describe('EcdsaMultikey', () => {
  describe('module', () => {
    it('should have proper exports', async () => {
      expect(EcdsaMultikey).to.have.property('generate');
      expect(EcdsaMultikey).to.have.property('from');
      expect(EcdsaMultikey).to.have.property('fromJwk');
      expect(EcdsaMultikey).to.have.property('toJwk');
    });
  });

  describe('algorithm', () => {
    it('deriveSecret() should not be supported by default', async () => {
      const keyPair = await EcdsaMultikey.generate({curve: 'P-256'});

      let err;
      try {
        await keyPair.deriveSecret({publicKey: keyPair});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotSupportedError');
    });

    it('deriveSecret() should produce a shared secret', async () => {
      const keyPair1 = await EcdsaMultikey.generate(
        {curve: 'P-256', keyAgreement: true});
      const keyPair2 = await EcdsaMultikey.generate(
        {curve: 'P-256', keyAgreement: true});

      const secret1 = await keyPair1.deriveSecret({publicKey: keyPair2});
      const secret2 = await keyPair2.deriveSecret({publicKey: keyPair1});

      expect(secret1).to.deep.eql(secret2);
    });
  });

  describe('from', () => {
    it('should error if publicKeyMultibase property is missing', async () => {
      let error;
      try {
        await EcdsaMultikey.from({});
      } catch(e) {
        error = e;
      }
      expect(error).to.be.an.instanceof(TypeError);
      expect(error.message)
        .to.equal('The "publicKeyMultibase" property is required.');
    });
  });

  describe('Backwards compat with EcdsaSecp256r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256);
      const data = (new TextEncoder()).encode('test data goes here');
      const signature = await keyPair.signer().sign({data});

      expect(
        await keyPair.verifier()
          .verify({data, signature})
      ).to.be.true;
    });
  });

  describe('Backwards compat with EcdsaSecp384r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp384);
      const data = (new TextEncoder()).encode('test data goes here');
      const signature = await keyPair.signer().sign({data});

      expect(
        await keyPair.verifier()
          .verify({data, signature})
      ).to.be.true;
    });
  });

  describe('Backwards compat with EcdsaSecp521r1VerificationKey2019', () => {
    it('Multikey should import properly', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp521);
      const data = (new TextEncoder()).encode('test data goes here');
      const signature = await keyPair.signer().sign({data});

      expect(
        await keyPair.verifier()
          .verify({data, signature})
      ).to.be.true;
    });
  });
});
