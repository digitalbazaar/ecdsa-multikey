/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import chai from 'chai';
import {CryptoKey, webcrypto} from '../lib/crypto.js';
import {getNamedCurveFromPublicMultikey} from '../lib/helpers.js';
import * as EcdsaMultikey from '../lib/index.js';
import {exportKeyPair} from '../lib/serialize.js';
import {
  mockKey,
  mockKeyEcdsaSecp256,
  mockKeyEcdsaSecp384,
  mockKeyEcdsaSecp521
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
    it('signer() instance should export proper algorithm', async () => {
      const keyPair = await EcdsaMultikey.from(mockKey);
      const signer = keyPair.signer();
      signer.algorithm.should.equal('P-256');
    });

    it('verifier() instance should export proper algorithm', async () => {
      const keyPair = await EcdsaMultikey.from(mockKey);
      const verifier = keyPair.verifier();
      verifier.algorithm.should.equal('P-256');
    });

    it('deriveSecret() should not be supported by default', async () => {
      const keyPair = await EcdsaMultikey.generate({curve: 'P-256'});

      let err;
      try {
        await keyPair.deriveSecret({remotePublicKey: keyPair});
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

      const secret1 = await keyPair1.deriveSecret({remotePublicKey: keyPair2});
      const secret2 = await keyPair2.deriveSecret({remotePublicKey: keyPair1});

      expect(secret1).to.deep.eql(secret2);
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let keyPair;
      let error;
      try {
        keyPair = await EcdsaMultikey.generate({curve: 'P-256'});
      } catch(e) {
        error = e;
      }
      should.not.exist(error);

      expect(keyPair).to.have.property('publicKeyMultibase');
      expect(keyPair).to.have.property('secretKeyMultibase');
      expect(keyPair).to.have.property('publicKey');
      expect(keyPair?.publicKey instanceof CryptoKey).to.be.true;
      expect(keyPair).to.have.property('secretKey');
      expect(keyPair?.secretKey instanceof CryptoKey).to.be.true;
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
        curve: 'P-256'
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
        curve: 'P-256'
      });
      const keyPairExported = await keyPair.export({publicKey: true});

      expect(keyPairExported).not.to.have.property('secretKeyMultibase');
      expect(keyPairExported).to.have.property('publicKeyMultibase');
      expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
      expect(keyPairExported).to.have.property('type', 'Multikey');
    });

    it('should only export secret key if available', async () => {
      const algorithm = {name: 'ECDSA', namedCurve: 'P-256'};
      const keyPair = await webcrypto.subtle.generateKey(
        algorithm, true, ['sign', 'verify']
      );
      delete keyPair.privateKey;

      const keyPairExported = await exportKeyPair({
        keyPair,
        publicKey: true,
        secretKey: true,
        includeContext: true
      });

      expect(keyPairExported).not.to.have.property('secretKeyMultibase');
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
