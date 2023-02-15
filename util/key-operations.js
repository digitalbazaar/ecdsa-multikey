import * as base58 from 'base58-universal';
import * as EcdsaMultikey from '../lib/index.js';
import {stringToUint8Array} from '../test/text-encoder.js';

async function main() {
  const keyPair = await EcdsaMultikey.generate({curve: 'P-256'});
  console.log('raw key pair:', keyPair);
  const exportedKeyPair = await keyPair.export({ publicKey: true, secretKey: true, includeContext: true });
  console.log('exported key pair:', exportedKeyPair);
  const signer = keyPair.signer();
  const verifier = keyPair.verifier();
  const rawData = 'key pair operations test';
  const data = stringToUint8Array(rawData);
  const signature = await signer.sign({data});
  console.log('signature:', base58.encode(new Uint8Array(signature)));
  const result = await verifier.verify({data, signature});
  console.log('result:', result);
}

main();
