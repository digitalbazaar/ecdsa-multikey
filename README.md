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

* `{string} [curve]` \[Required\] ECDSA curve used to generate the key:
  \['P-256', 'P-384', 'P-521'\].
* `{string} [id]` \[Optional\] ID for the generated key.
* `{string} [controller]` \[Optional\] Controller URI or DID to initialize the
  generated key. (This will be used to generate `id` if it is not explicitly defined.)

```js
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

const keyPair = await EcdsaMultikey.generate({curve: 'P-384'});
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
  id: 'did:example:1234#zynkWQ2LUf58H4VwLGjscwb9KJwGUmqBFXdJKnCXxDMciFXioY7Hq7MvEdVfsBiQSVa9k9',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zynkWQ2LUf58H4VwLGjscwb9KJwGUmqBFXdJKnCXxDMciFXioY7Hq7MvEdVfsBiQSVa9k9'
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
  id: 'did:example:1234#zynkWQ2LUf58H4VwLGjscwb9KJwGUmqBFXdJKnCXxDMciFXioY7Hq7MvEdVfsBiQSVa9k9',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zynkWQ2LUf58H4VwLGjscwb9KJwGUmqBFXdJKnCXxDMciFXioY7Hq7MvEdVfsBiQSVa9k9',
  secretKeyMultibase: 'zEbCcd62anxNxioGCdP818UobJn1oEmgL5PHUvQ5AvdyVeLJxeJ4Kr73RqqvG5DN7Zq48'
}
```

### Creating a signer function

In order to perform a cryptographic signature, you need to create a `sign`
function, and then invoke it.

```js
const keyPair = EcdsaMultikey.generate({curve: 'P-256'});

const {sign} = keyPair.signer();

// data is a Uint8Array of bytes
const data = (new TextEncoder()).encode('test data goes here');
// Signing also outputs a Uint8Array, which you can serialize to text etc.
const signature = await sign({data});
```

### Creating a verifier function

In order to verify a cryptographic signature, you need to create a `verify`
function, and then invoke it (passing it the data to verify, and the signature).

```js
const keyPair = EcdsaMultikey.generate({curve: 'P-521'});

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

[New BSD License (3-clause)](LICENSE) © 2023 Digital Bazaar
