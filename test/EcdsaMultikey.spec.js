/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import * as base58btc from 'base58-universal';
import {mockKey, seed} from './mock-data.js';
import multibase from 'multibase';
import multicodec from 'multicodec';
const should = chai.should();
const {expect} = chai;

import * as EcdsaMultikey from '../lib/index.js';


// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z';

describe('EcdsaMultikey', () => {
  describe('module', () => {
    it('should have "generate" and "from" properties', async () => {
      expect(EcdsaMultikey).to.have.property('generate');
      expect(EcdsaMultikey).to.have.property('from');
    });
  });

  describe('generate', () => {
    it('should generate a key pair', async () => {
    });

    it('should generate the same key from the same seed', async () => {
    });
  });

  describe('export', () => {
    it('should export id, type and key material', async () => {
    });

    it('should only export public key if specified', async () => {
    });
  });

  describe('from', () => {
    it('should auto-set key.id based on controller', async () => {
    });

    it('should error if publicKeyMultibase property is missing', async () => {
    });
    it('should round-trip load exported keys', async () => {
    });
  });
});

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase}) {
  keyPair.publicKeyMultibase.startsWith('z').should.be.true;
  const mcPubkeyBytes = multibase.decode(publicKeyMultibase);
  const mcType = multicodec.getCodec(mcPubkeyBytes);
  mcType.should.equal('p256-pub');
  const pubkeyBytes =
    multicodec.addPrefix('p256-pub', multicodec.rmPrefix(mcPubkeyBytes));
  const encodedPubkey = MULTIBASE_BASE58BTC_HEADER +
    base58btc.encode(pubkeyBytes);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
