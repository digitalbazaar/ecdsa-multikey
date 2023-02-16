/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import varint from 'varint';

// converts varint to hex
function vintToHex(data) {
  if(typeof data !== 'number') {
    throw new TypeError('"data" must be a number.');
  }
  return varint.encode(data);
}

// converts ECDSA key headers from varint to hex
function main() {
  console.log('varint -> hex:');
  console.log(`0x1200 -> 0x${Buffer.from(vintToHex(0x1200)).toString('hex')}`);
  console.log(`0x1201 -> 0x${Buffer.from(vintToHex(0x1201)).toString('hex')}`);
  console.log(`0x1202 -> 0x${Buffer.from(vintToHex(0x1202)).toString('hex')}`);
  console.log(`0x1306 -> 0x${Buffer.from(vintToHex(0x1306)).toString('hex')}`);
  console.log(`0x1307 -> 0x${Buffer.from(vintToHex(0x1307)).toString('hex')}`);
  console.log(`0x1308 -> 0x${Buffer.from(vintToHex(0x1308)).toString('hex')}`);
}

main();
