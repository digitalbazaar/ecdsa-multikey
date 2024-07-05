/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import * as base58 from 'base58-universal';
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {stringToUint8Array} from './text-encoder.js';
import {CryptoKey} from '../lib/crypto.js';

chai.should();
const {expect} = chai;

export function testSignVerify({id, serializedKeyPair}) {
  let signer;
  let verifier;
  before(async function() {
    const keyPair = await EcdsaMultikey.from({
      id,
      ...serializedKeyPair
    });
    signer = keyPair.signer();
    verifier = keyPair.verifier();
  });
  it('should have correct id', function() {
    signer.should.have.property('id', id);
    verifier.should.have.property('id', id);
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

export function testAlgorithm({serializedKeyPair, keyType}) {
  it('signer() instance should export proper algorithm', async () => {
    const keyPair = await EcdsaMultikey.from(serializedKeyPair);
    const signer = keyPair.signer();
    signer.algorithm.should.equal(keyType);
  });
  it('verifier() instance should export proper algorithm', async () => {
    const keyPair = await EcdsaMultikey.from(serializedKeyPair);
    const verifier = keyPair.verifier();
    verifier.algorithm.should.equal(keyType);
  });
}

export function testGenerate({
  curve,
  decoder = base58,
  secretKeyByteLength = 34,
  publicKeyByteLength = 35
}) {
  it('should generate a key pair', async function() {
    let keyPair;
    let err;
    try {
      keyPair = await EcdsaMultikey.generate({curve});
    } catch(e) {
      err = e;
    }
    expect(err).to.not.exist;

    expect(keyPair).to.have.property('publicKeyMultibase');
    expect(keyPair).to.have.property('secretKeyMultibase');
    expect(keyPair).to.have.property('publicKey');
    expect(keyPair?.publicKey instanceof CryptoKey).to.be.true;
    expect(keyPair).to.have.property('secretKey');
    expect(keyPair?.secretKey instanceof CryptoKey).to.be.true;
    expect(keyPair).to.have.property('export');
    expect(keyPair).to.have.property('signer');
    expect(keyPair).to.have.property('verifier');
    const secretKeyBytes = decoder
      .decode(keyPair.secretKeyMultibase.slice(1));
    const publicKeyBytes = decoder
      .decode(keyPair.publicKeyMultibase.slice(1));
    secretKeyBytes.length.should.equal(
      secretKeyByteLength,
      `Expected secretKey byte length to be ${secretKeyByteLength}.`);
    publicKeyBytes.length.should.equal(
      publicKeyByteLength,
      `Expected publicKey byte length to be ${publicKeyByteLength}.`);
  });
}

