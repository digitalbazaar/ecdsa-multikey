# @digitalbazaar/ecdsa-multikey ChangeLog

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
