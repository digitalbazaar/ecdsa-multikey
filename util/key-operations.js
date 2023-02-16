/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {ECDSA_CURVE} from '../lib/constants.js';
import * as EcdsaMultikey from '../lib/index.js';
import {stringToUint8Array} from '../test/text-encoder.js';

// generates ECDSA key pair
async function generateKeyPair(options = {}) {
  if(!options.curve) {
    options.curve = ECDSA_CURVE.P256;
  }
  if(!options.controller) {
    options.controller = 'did:example:1234';
  }
  return EcdsaMultikey.generate(options);
}

// executes common key operations
async function main() {
  const keyPair = await generateKeyPair();
  console.log('raw key pair:', keyPair);
  const exportedKeyPair = await keyPair.export({
    publicKey: true,
    secretKey: true,
    includeContext: true
  });
  console.log('exported key pair:', exportedKeyPair);
  const signer = keyPair.signer();
  const verifier = keyPair.verifier();
  const rawData = 'key operations test';
  const data = stringToUint8Array(rawData);
  const signature = await signer.sign({data});
  console.log('signature:', base58.encode(new Uint8Array(signature)));
  const result = await verifier.verify({data, signature});
  console.log('result:', result);
}

main();
