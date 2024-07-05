/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc.
 */
import * as base58 from 'base58-universal';
import chai from 'chai';
import * as EcdsaMultikey from '../lib/index.js';
import {stringToUint8Array} from './text-encoder.js';
import {CryptoKey} from '../lib/crypto.js';
import {webcrypto} from '../lib/crypto.js';
import {exportKeyPair} from '../lib/serialize.js';
import {getNamedCurveFromPublicMultikey} from '../lib/helpers.js';

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

export function testExport({curve}) {
  it('should export id, type and key material', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      controller: 'did:example:1234',
      curve
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
      curve
    });
    const keyPairExported = await keyPair.export({publicKey: true});

    expect(keyPairExported).not.to.have.property('secretKeyMultibase');
    expect(keyPairExported).to.have.property('publicKeyMultibase');
    expect(keyPairExported).to.have.property('id', '4e0db4260c87cc200df3');
    expect(keyPairExported).to.have.property('type', 'Multikey');
  });

  it('should only export secret key if available', async () => {
    const algorithm = {name: 'ECDSA', namedCurve: curve};
    const keyPair = await webcrypto.subtle.generateKey(
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
    const keyPair = await EcdsaMultikey.generate({curve});
    const expectedPublicKey = base58.decode(
      keyPair.publicKeyMultibase.slice(1)).slice(2);
    const {publicKey} = await keyPair.export({publicKey: true, raw: true});
    expect(expectedPublicKey).to.deep.equal(publicKey);
  });

  it('should export raw secret key', async () => {
    const keyPair = await EcdsaMultikey.generate({curve});
    const expectedSecretKey = base58.decode(
      keyPair.secretKeyMultibase.slice(1)).slice(2);
    const {secretKey} = await keyPair.export({secretKey: true, raw: true});
    expect(expectedSecretKey).to.deep.equal(secretKey);
  });
}

export function testFrom({serializedKeyPair, id, keyType}) {
  it('should auto-set key.id based on controller', async () => {
    const {publicKeyMultibase} = serializedKeyPair;
    const keyPair = await EcdsaMultikey.from(serializedKeyPair);
    _ensurePublicKeyEncoding({keyPair, keyType, publicKeyMultibase});
    expect(keyPair.id).to.equal(id);
  });
  it('should round-trip load exported keys', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve: keyType
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
      curve: keyType
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
      curve: keyType
    });
    const jwk1 = await EcdsaMultikey.toJwk({keyPair});
    expect(jwk1.d).to.not.exist;
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
}

export function testJWK({curve}) {
  it('should round-trip secret JWKs', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve
    });
    const jwk1 = await EcdsaMultikey.toJwk({keyPair, secretKey: true});
    expect(jwk1.d).to.exist;
    const keyPairImported = await EcdsaMultikey.fromJwk(
      {jwk: jwk1, secretKey: true});
    const jwk2 = await EcdsaMultikey.toJwk(
      {keyPair: keyPairImported, secretKey: true});
    expect(jwk1).to.eql(jwk2);
  });

  it('should round-trip public JWKs', async () => {
    const keyPair = await EcdsaMultikey.generate({
      id: '4e0db4260c87cc200df3',
      curve
    });
    const jwk1 = await EcdsaMultikey.toJwk({keyPair});
    expect(jwk1.d).to.not.exist
    const keyPairImported = await EcdsaMultikey.fromJwk({jwk: jwk1});
    const jwk2 = await EcdsaMultikey.toJwk({keyPair: keyPairImported});
    expect(jwk1).to.eql(jwk2);
  });
}

export function testRaw({curve}) {
  it('should import raw public key', async () => {
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

}

function _ensurePublicKeyEncoding({keyPair, publicKeyMultibase, keyType}) {
  keyPair.publicKeyMultibase.startsWith('z').should.be.true;
  publicKeyMultibase.startsWith('z').should.be.true;
  const decodedPubkey = base58.decode(publicKeyMultibase.slice(1));
  const ecdsaCurve = getNamedCurveFromPublicMultikey({
    publicMultikey: decodedPubkey
  });
  ecdsaCurve.should.equal(keyType);
  const encodedPubkey = 'z' + base58.encode(decodedPubkey);
  encodedPubkey.should.equal(keyPair.publicKeyMultibase);
}
