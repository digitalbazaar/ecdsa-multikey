/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as EcdsaMultikey from '../lib/index.js';
import chai from 'chai';
import {Crypto} from '@peculiar/webcrypto';
import {getNamedCurveFromPublicMultikey} from '../lib/helpers.js';
import {exportKeyPair} from '../lib/serialize.js';
import {
  mockKeyEcdsaSecp256k1
} from './mock-data.js';
const should = chai.should();
const {expect} = chai;

const cryptoPolyfill = new Crypto();
const SECP256K1_CURVE_IDENTIFIER = 'K-256';

describe('EcdsaMultikey secp256k1 support', () => {

  describe('algorithm', () => {
    it('signer() instance should export proper algorithm', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256k1);
      const signer = keyPair.signer();
      signer.algorithm.should.equal(SECP256K1_CURVE_IDENTIFIER);
    });

    it('verifier() instance should export proper algorithm', async () => {
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256k1);
      const verifier = keyPair.verifier();
      verifier.algorithm.should.equal(SECP256K1_CURVE_IDENTIFIER);
    });

    it('deriveSecret() should produce a shared secret', async () => {
      const keyPair1 = await EcdsaMultikey.generate(
        {curve: SECP256K1_CURVE_IDENTIFIER, keyAgreement: true});
      const keyPair2 = await EcdsaMultikey.generate(
        {curve: SECP256K1_CURVE_IDENTIFIER, keyAgreement: true});

      const secret1 = await keyPair1.deriveSecret({publicKey: keyPair2});
      const secret2 = await keyPair2.deriveSecret({publicKey: keyPair1});

      expect(secret1).to.deep.eql(secret2);
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let keyPair;
      let error;
      try {
        keyPair = await EcdsaMultikey.generate({curve: SECP256K1_CURVE_IDENTIFIER});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);

      expect(keyPair).to.have.property('publicKeyMultibase');
      expect(keyPair).to.have.property('secretKeyMultibase');
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('secretKey');
      expect(keyPair).to.have.property('export');
      expect(keyPair).to.have.property('signer');
      expect(keyPair).to.have.property('verifier');
      const secretKeyBytes = base58
        .decode(keyPair.secretKeyMultibase.slice(1));
      const publicKeyBytes = base58
        .decode(keyPair.publicKeyMultibase.slice(1));
      secretKeyBytes.length.should.equal(34);
      publicKeyBytes.length.should.equal(35);
    });
  });

  describe('export', () => {
    it('should export id, type and key material', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        controller: 'did:example:1234',
        curve: SECP256K1_CURVE_IDENTIFIER
      });
      const keyPairExported = await keyPair.export({
        publicKey: true, secretKey: true
      });

      const expectedProperties = [
        'id', 'type', 'controller', 'publicKeyMultibase', 'secretKeyMultibase'
      ];
      for(const property of expectedProperties) {
        expect(keyPairExported).to.have.property(property);
        expect(keyPairExported[property]).to.exist;
      }

      expect(keyPairExported.controller).to.equal('did:example:1234');
      expect(keyPairExported.type).to.equal('Multikey');
      expect(keyPairExported.id).to.equal('4e0db4260c87cc200df3');
    });

    it('should only export public key if specified', async () => {
      const keyPair = await EcdsaMultikey.generate({
        id: '4e0db4260c87cc200df3',
        curve: SECP256K1_CURVE_IDENTIFIER
      });
      const keyPairExported = await keyPair.export({publicKey: true});

      expect(keyPairExported).not.to.have.property('secretKeyMultibase');
      expect(keyPairExported).to.have.property('publicKeyMultibase');
      expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
      expect(keyPairExported).to.have.property('type', 'Multikey');
    });

    it('should only export secret key if available', async () => {
      const algorithm = {name: 'ECDSA', namedCurve: SECP256K1_CURVE_IDENTIFIER};
      const keyPair = await cryptoPolyfill.subtle.generateKey(
        algorithm, true, ['sign', 'verify']);
      delete keyPair.privateKey;

      const keyPairExported = await exportKeyPair({
        keyPair,
        publicKey: true,
        secretKey: true,
        includeContext: true
      });

      expect(keyPairExported).not.to.have.property('secretKeyMultibase');
    });

    it('should export raw public key', async () => {
      const keyPair = await EcdsaMultikey.generate({curve: SECP256K1_CURVE_IDENTIFIER});
      const expectedPublicKey = base58.decode(
        keyPair.publicKeyMultibase.slice(1)).slice(2);
      const {publicKey} = await keyPair.export({publicKey: true, raw: true});
      expect(expectedPublicKey).to.deep.equal(publicKey);
    });

    it('should export raw secret key', async () => {
      const keyPair = await EcdsaMultikey.generate({curve: SECP256K1_CURVE_IDENTIFIER});
      const expectedSecretKey = base58.decode(
        keyPair.secretKeyMultibase.slice(1)).slice(2);
      const {secretKey} = await keyPair.export({secretKey: true, raw: true});
      expect(expectedSecretKey).to.deep.equal(secretKey);
    });
  });

  describe('from', () => {
    it('should auto-set key.id based on controller', async () => {
      const {publicKeyMultibase} = mockKeyEcdsaSecp256k1;

      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256k1);

      _ensurePublicKeyEncoding({keyPair, publicKeyMultibase});
      expect(keyPair.id).to.equal(
        'did:example:1234#zQ3shwLBJHiP3Z3g9j4AsiFYNXApgBsb8FG6mXvzukxTzwS3R'
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
        curve: SECP256K1_CURVE_IDENTIFIER
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
        curve: SECP256K1_CURVE_IDENTIFIER
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
        curve: SECP256K1_CURVE_IDENTIFIER
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
        curve: SECP256K1_CURVE_IDENTIFIER
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
        curve: SECP256K1_CURVE_IDENTIFIER
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
      const curve = SECP256K1_CURVE_IDENTIFIER;
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
      const curve = SECP256K1_CURVE_IDENTIFIER;
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
      const curve = SECP256K1_CURVE_IDENTIFIER;
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
      const keyPair = await EcdsaMultikey.from(mockKeyEcdsaSecp256k1);
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
  ecdsaCurve.should.equal(SECP256K1_CURVE_IDENTIFIER);
  const encodedPubkey = 'z' + base58.encode(decodedPubkey);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
