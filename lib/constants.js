/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */

// Name of algorithm
export const ALGORITHM = 'ECDSA';
// Determines whether key pair is extractable
export const EXTRACTABLE = true;
// ECDSA curve P-256 type
export const ECDSA_2019_SECP_256_KEY_TYPE = 'EcdsaSecp256r1VerificationKey2019';
// ECDSA curve P-384 type
export const ECDSA_2019_SECP_384_KEY_TYPE = 'EcdsaSecp384r1VerificationKey2019';
// ECDSA curve P-521 type
export const ECDSA_2019_SECP_521_KEY_TYPE = 'EcdsaSecp521r1VerificationKey2019';
// ECDSA 2019 suite context v1 URL
export const ECDSA_2019_SUITE_CONTEXT_V1_URL = 'https://w3id.org/security/suites/ecdsa-2019/v1';
// Multikey context v1 URL
export const MULTIKEY_CONTEXT_V1_URL = 'https://w3id.org/security/multikey/v1';
export const MULTIBASE_BASE58_HEADER = 'z';

// Multicodec ECDSA public header byte 1
export const MULTICODEC_ECDSA_PUB_HEADER_BYTE_1 = 0x12;
// Multicodec p256-pub header byte 2
export const MULTICODEC_P256_PUB_HEADER_BYTE_2 = 0x00;
// Multicodec p384-pub header byte 2
export const MULTICODEC_P384_PUB_HEADER_BYTE_2 = 0x01;
// Multicodec p521-pub header byte 2
export const MULTICODEC_P521_PUB_HEADER_BYTE_2 = 0x02;

// Multicodec ECDSA private header byte 1
export const MULTICODEC_ECDSA_PRIV_HEADER_BYTE_1 = 0x13;
// Multicodec p256-priv header byte 2
export const MULTICODEC_P256_PRIV_HEADER_BYTE_2 = 0x03;
// Multicodec p384-priv header byte 2
export const MULTICODEC_P384_PRIV_HEADER_BYTE_2 = 0x04;
// Multicodec p521-priv header byte 2
export const MULTICODEC_P521_PRIV_HEADER_BYTE_2 = 0x05;
