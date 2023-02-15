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

// Multicodec p256-pub header (0x1200 varint -> 0x8024 hex)
export const MULTICODEC_P256_PUBLIC_KEY_HEADER = 0x8024;
// Multicodec p384-pub header (0x1201 varint -> 0x8124 hex)
export const MULTICODEC_P384_PUBLIC_KEY_HEADER = 0x8124;
// Multicodec p521-pub header (0x1202 varint -> 0x8224 hex)
export const MULTICODEC_P521_PUBLIC_KEY_HEADER = 0x8224;

// Multicodec p256-priv header (0x1306 varint -> 0x8626 hex)
export const MULTICODEC_P256_SECRET_KEY_HEADER = 0x8626;
// Multicodec p384-priv header (0x1307 varint -> 0x8726 hex)
export const MULTICODEC_P384_SECRET_KEY_HEADER = 0x8726;
// Multicodec p521-priv header (0x1308 varint -> 0x8826 hex)
export const MULTICODEC_P521_SECRET_KEY_HEADER = 0x8826;
