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
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: 'zDnaeSMnptAKpH4AD41vTkwzjznW7yNetdRh9FJn8bJsbsdbw',
  secretKeyMultibase: 'z42twirSb1PULt5Sg6gjgNMsdiLycu6fbA83aX1vVb8e3ncP'
};

export const mockKeyEcdsaSecp384 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4L' +
    'utoYWhvQCnGjdVn14kujQ',
  secretKeyMultibase: 'z2fanyY7zgwNpZGxX5fXXibvScNaUWNprHU9dKx7qpVj7mws9J' +
    '8LLt4mDB5TyH2GLHWkUc'
};

export const mockKeyEcdsaSecp521 = {
  type: 'Multikey',
  controller: 'did:example:1234',
  publicKeyMultibase: 'z2J9gaYgHvgaEEg2hB8EQMhwh4XxgRwUQdwMwnpa7P9qehd763' +
    'sEVaD9pHGqxCtKpt2xKQWX1d5XGT3GtdrwrAVxg8m9ke9R',
  secretKeyMultibase: 'zJp6tCshdToy3U7P24S5YnDRyjCS13mKeRMevYmqVqJpraXAWT' +
    'K6vuzCXSp1hwwvgGGEnQS82ZeKaPcFDrvhWhaq4767Am'
};

const getKeyId = ({controller, publicKeyMultibase}) =>
  `${controller}#${publicKeyMultibase}`;

export const multikeys = new Map([
  ['P-256', {
    id: getKeyId(mockKeyEcdsaSecp256),
    serializedKeyPair: mockKeyEcdsaSecp256,
    props: {

    }
  }],
  ['P-384', {
    id: getKeyId(mockKeyEcdsaSecp384),
    serializedKeyPair: mockKeyEcdsaSecp384,
    props: {
      secretKeyByteLength: 50,
      publicKeyByteLength: 51
    }
  }],
  ['P-521', {
    id: getKeyId(mockKeyEcdsaSecp521),
    serializedKeyPair: mockKeyEcdsaSecp521,
    props: {
      secretKeyByteLength: 68,
      publicKeyByteLength: 69
    }
  }]
]);
