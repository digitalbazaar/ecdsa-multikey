/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import chai from 'chai';
import multibase from 'multibase';
import multicodec from 'multicodec';
import {ECDSA_CURVE, MULTIBASE_BASE58_HEADER} from '../lib/constants.js';
import {CryptoKey} from '../lib/crypto.js';
import * as EcdsaMultikey from '../lib/index.js';
import {mockKey} from './mock-data.js';
const should = chai.should();
const {expect} = chai;

describe('EcdsaMultikey', () => {
  describe('module', () => {
    it('should have "generate" and "from" properties', async () => {
      expect(EcdsaMultikey).to.have.property('generate');
      expect(EcdsaMultikey).to.have.property('from');
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
      let keyPair;
      let error;
      try {
        keyPair = await EcdsaMultikey.generate({curve: ECDSA_CURVE.P256});
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
        curve: ECDSA_CURVE.P256
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
        curve: ECDSA_CURVE.P256
      });
      const keyPairExported = await keyPair.export({publicKey: true});

      expect(keyPairExported).not.to.have.property('secretKeyMultibase');
      expect(keyPairExported).to.have.property('publicKeyMultibase');
      expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
      expect(keyPairExported).to.have.property('type', 'Multikey');
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
        curve: ECDSA_CURVE.P256
      });
      const keyPairExported = await keyPair.export({
        publicKey: true, secretKey: true
      });
      const keyPairImported = await EcdsaMultikey.from(keyPairExported);

      expect(await keyPairImported.export({publicKey: true, secretKey: true}))
        .to.eql(keyPairExported);
    });
  });
});

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  keyPair.publicKeyMultibase.startsWith(MULTIBASE_BASE58_HEADER).should.be.true;
  const mcPubkeyBytes = multibase.decode(publicKeyMultibase);
  const mcType = multicodec.getNameFromData(mcPubkeyBytes);
  mcType.should.equal('p256-pub');
  const pubkeyBytes =
    multicodec.addPrefix('p256-pub', multicodec.rmPrefix(mcPubkeyBytes));
  const encodedPubkey = MULTIBASE_BASE58_HEADER +
    base58.encode(pubkeyBytes);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
