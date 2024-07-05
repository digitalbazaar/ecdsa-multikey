/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as EcdsaMultikey from '../lib/index.js';
import chai from 'chai';
import {getNamedCurveFromPublicMultikey} from '../lib/helpers.js';
import {
  mockKey,
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
    it('should auto-set key.id based on controller', async () => {
      const {publicKeyMultibase} = mockKey;

      const keyPair = await EcdsaMultikey.from(mockKey);

      _ensurePublicKeyEncoding({keyPair, publicKeyMultibase});
      expect(keyPair.id).to.equal(
        'did:example:1234#zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw'
      );
    });

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

    it('should round-trip load exported keys', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: 'P-256'
      });
      const keyPairExported = await keyPair.export({
        publicKey: true, secretKey: true
      });
      const keyPairImported = await EcdsaMultikey.from(keyPairExported);

      expect(await keyPairImported.export({publicKey: true, secretKey: true}))
        .to.eql(keyPairExported);
    });

    it('should import with `@context` array', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: 'P-256'
      });
      const keyPairExported = await keyPair.export({
        publicKey: true, secretKey: true
      });
      const keyPairImported = await EcdsaMultikey.from({
        ...keyPairExported,
        '@context': [{}, keyPairExported['@context']]
      });

      expect(await keyPairImported.export({publicKey: true, secretKey: true}))
        .to.eql(keyPairExported);
    });

    it('should load `publicKeyJwk`', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: 'P-256'
      });
      const jwk1 = await EcdsaMultikey.toJwk({keyPair});
      should.not.exist(jwk1.d);
      const keyPairImported1 = await EcdsaMultikey.from({publicKeyJwk: jwk1});
      const keyPairImported2 = await EcdsaMultikey.from({
        type: 'JsonWebKey',
        publicKeyJwk: jwk1
      });
      const jwk2 = await EcdsaMultikey.toJwk({keyPair: keyPairImported1});
      const jwk3 = await EcdsaMultikey.toJwk({keyPair: keyPairImported2});
      expect(jwk1).to.eql(jwk2);
      expect(jwk1).to.eql(jwk3);
    });
  });

  describe('fromJwk/toJwk', () => {
    it('should round-trip secret JWKs', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: 'P-256'
      });
      const jwk1 = await EcdsaMultikey.toJwk({keyPair, secretKey: true});
      should.exist(jwk1.d);
      const keyPairImported = await EcdsaMultikey.fromJwk(
        {jwk: jwk1, secretKey: true});
      const jwk2 = await EcdsaMultikey.toJwk(
        {keyPair: keyPairImported, secretKey: true});
      expect(jwk1).to.eql(jwk2);
    });

    it('should round-trip public JWKs', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: 'P-256'
      });
      const jwk1 = await EcdsaMultikey.toJwk({keyPair});
      should.not.exist(jwk1.d);
      const keyPairImported = await EcdsaMultikey.fromJwk({jwk: jwk1});
      const jwk2 = await EcdsaMultikey.toJwk({keyPair: keyPairImported});
      expect(jwk1).to.eql(jwk2);
    });
  });

  describe('fromRaw', () => {
    it('should import raw public key', async () => {
      const curve = 'P-256';
      const keyPair = await EcdsaMultikey.generate({curve});

      // first export
      const expectedPublicKey = base58.decode(
        keyPair.publicKeyMultibase.slice(1)).slice(2);
      const {publicKey} = await keyPair.export({publicKey: true, raw: true});
      expect(expectedPublicKey).to.deep.equal(publicKey);

      // then import
      const imported = await EcdsaMultikey.fromRaw({curve, publicKey});

      // then re-export to confirm
      const {publicKey: publicKey2} = await imported.export(
        {publicKey: true, raw: true});
      expect(expectedPublicKey).to.deep.equal(publicKey2);
    });

    it('should import raw secret key', async () => {
      const curve = 'P-256';
      const keyPair = await EcdsaMultikey.generate({curve});

      // first export
      const expectedSecretKey = base58.decode(
        keyPair.secretKeyMultibase.slice(1)).slice(2);
      const {secretKey, publicKey} = await keyPair.export(
        {secretKey: true, raw: true});
      expect(expectedSecretKey).to.deep.equal(secretKey);

      // then import
      const imported = await EcdsaMultikey.fromRaw(
        {curve, secretKey, publicKey});

      // then re-export to confirm
      const {secretKey: secretKey2} = await imported.export(
        {secretKey: true, raw: true});
      expect(expectedSecretKey).to.deep.equal(secretKey2);
    });

    it('should import raw secret key for key agreement', async () => {
      const curve = 'P-256';
      const keyPair = await EcdsaMultikey.generate({curve, keyAgreement: true});

      // first export
      const expectedSecretKey = base58.decode(
        keyPair.secretKeyMultibase.slice(1)).slice(2);
      const {secretKey, publicKey} = await keyPair.export(
        {secretKey: true, raw: true});
      expect(expectedSecretKey).to.deep.equal(secretKey);

      // then import
      const imported = await EcdsaMultikey.fromRaw(
        {curve, secretKey, publicKey, keyAgreement: true});
      expect(imported.keyAgreement).to.equal(true);

      // then re-export to confirm
      const {secretKey: secretKey2} = await imported.export(
        {secretKey: true, raw: true});
      expect(expectedSecretKey).to.deep.equal(secretKey2);
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

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  keyPair.publicKeyMultibase.startsWith('z').should.be.true;
  publicKeyMultibase.startsWith('z').should.be.true;
  const decodedPubkey = base58.decode(publicKeyMultibase.slice(1));
  const ecdsaCurve = getNamedCurveFromPublicMultikey({
    publicMultikey: decodedPubkey
  });
  ecdsaCurve.should.equal('P-256');
  const encodedPubkey = 'z' + base58.encode(decodedPubkey);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
