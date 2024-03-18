# @digitalbazaar/ecdsa-multikey ChangeLog

## 1.7.0 - 2024-mm-dd

### Added
- Add conversion from `publicKeyJwk` feature via `from()`.

### Fixed
- Allow `@context` array values in multikeys.

## 1.6.0 - 2023-11-07

### Added
- Add `fromRaw()` to import a key pair from a named `curve`, `secretKey`,
  and `publicKey`.
- Reformat `keyAgreement` param in `from()` to `options` to enable named
  usage (`{keyAgreement: true|false}`) for better API.

## 1.5.0 - 2023-11-05

### Added
- Rename `remotePublicKey` param to `publicKey` for `deriveSecret()` to get
  better compatibility with WebKMS Client KeyAgreementKey interface. The
  param can still be passed as `remotePublicKey` but this is considered
  deprecated.

## 1.4.0 - 2023-11-05

### Added
- Add `raw` option to key pair `export()`. Based on the requested public/secret
  key, the output will include the raw bytes for the public/secret key using
  the properties `publicKey` and/or `secretKey`, respectively. The public key
  will be output using the compressed format.

## 1.3.0 - 2023-10-31

### Added
- Add `keyAgreement` option to `generate()` to generate ECDH keys instead of
  ECDSA keys. This module needs a better name than `ecdsa-multikey` as it also
  supports key agreement keys, but only for keys based on curves that are also
  compatible with ECDSA. Note that a key should only be used for ECDSA or ECDH
  (key agreement), not both, so calling this module `ecdsa-multikey` is a bit
  misleading as you can also generate a key that is to only be used for key
  agreement.
- Add `deriveSecret()` API for `keyAgreement` enabled keys.

## 1.2.1 - 2023-10-30

### Fixed
- Do not include `ext` or `key_ops` in output JWK.

## 1.2.0 - 2023-10-30

### Added
- Add `fromJwk()` and `toJwk()` for importing / exporting key pairs using JWK.

## 1.1.3 - 2023-05-19

### Fixed
- Support Node.js 20.x.

## 1.1.2 - 2023-04-14

### Fixed
- Update `.from()` method to not modify key input.

## 1.1.1 - 2023-03-11

### Fixed
- Fix data format alignment issues with ecdsa-2019-cryptosuite.
- Use constant strings in tests.

## 1.1.0 - 2023-03-06

### Changed
- Ensure public and secret multikey headers match.
- Change exported algorithm from "ECDSA" to curve name.

## 1.0.0 - 2023-02-27

### Added
- Initial version.
