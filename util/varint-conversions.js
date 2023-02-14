import varint from 'varint';

function varintToHex(data) {
  if (typeof data !== 'number') {
    throw new TypeError('"data" must be a number.');
  }
  return varint.encode(data);
}

function main() {
  console.log(varintToHex(0x1200));
  console.log(varintToHex(0x1201));
  console.log(varintToHex(0x1202));
  console.log(varintToHex(0x1303));
  console.log(varintToHex(0x1304));
  console.log(varintToHex(0x1305));
}

main();
