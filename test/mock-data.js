/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
export const mockKey = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
};

export const mockKeyEcdsaSecp256 = {
  type: 'EcdsaSecp256r1VerificationKey2019',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
};

export const mockKeyEcdsaSecp384 = {
  type: 'EcdsaSecp384r1VerificationKey2019',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
};

export const mockKeyEcdsaSecp521 = {
  type: 'EcdsaSecp521r1VerificationKey2019',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
};

export const keyTypes = new Map([
  ['P-256', mockKeyEcdsaSecp256],
  ['P-384', mockKeyEcdsaSecp384],
  ['P-521', mockKeyEcdsaSecp521]
])
