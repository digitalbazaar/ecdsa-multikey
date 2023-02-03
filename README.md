# EcdsaMultikey Key Pair Library for Linked Data _(@digitalbazaar/ecdsa-multikey)_

[![Node.js CI](https://github.com/digitalbazaar/ecdsa-multikey/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/ecdsa-multikey/actions?query=workflow%3A%22Node.js+CI%22)
[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/ecdsa-multikey.svg)](https://npm.im/@digitalbazaar/ecdsa-multikey)

> Javascript library for generating and working with EcdsaMultikey key pairs.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

For use with:

* [`@digitalbazaar/ecdsa-2019-cryptosuite`](https://github.com/digitalbazaar/ecdsa-2019-cryptosuite) `^1.0.0`
  crypto suite (with [`jsonld-signatures`](https://github.com/digitalbazaar/jsonld-signatures) `^11.0.0`)
* [`@digitalbazaar/data-integrity`](https://github.com/digitalbazaar/data-integrity) `^1.0.0`

See also (related specs):

* [Verifiable Credential Data Integrity](https://w3c.github.io/vc-data-integrity/)

## Security

As with most security- and cryptography-related tools, the overall security of
your system will largely depend on your design decisions.

## Install

- Node.js 16+ is required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/ecdsa-multikey.git
cd ecdsa-multikey
npm install
```

## Usage

### Generating a new public/secret key pair

To generate a new public/secret key pair:

* `{string} [id]` Optional id for the generated key.
* `{string} [controller]` Optional controller URI or DID to initialize the
  generated key. (This will also init the key id.)
* `{string} [seed]` Optional deterministic seed value from which to generate the
  key.

```js
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

const edKeyPair = await EcdsaMultikey.generate();
```

### Importing a key pair from storage

To create an instance of a public/secret key pair from data imported from
storage, use `.from()`:

```js
const serializedKeyPair = { ... };

const keyPair = await EcdsaMultikey.from(serializedKeyPair);
````

### Exporting the public key only

To export just the public key of a pair:

```js
await keyPair.export({publicKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX'
}
```

### Exporting the full public-secret key pair

To export the full key pair, including secret key (warning: this should be a
carefully considered operation, best left to dedicated Key Management Systems):

```js
await keyPair.export({publicKey: true, secretKey: true});
// ->
{
  type: 'Multikey',
  id: 'did:example:1234#z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  secretKeyMultibase: 'zruzf4Y29hDp7vLoV3NWzuymGMTtJcQfttAWzESod4wV2fbPvEp4XtzGp2VWwQSQAXMxDyqrnVurYg2sBiqiu1FHDDM'
}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = EcdsaMultikey.generate();

const {sign} = keyPair.signer();

// data is a Uint8Array of bytes
const data = (new TextEncoder()).encode('test data goes here');
// Signing also outputs a Uint8Array, which you can serialize to text etc.
const signatureValueBytes = await sign({data});
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = EcdsaMultikey.generate();

const {verify} = keyPair.verifier();

const valid = await verify({data, signature});
// true
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © 2020 Digital Bazaar
