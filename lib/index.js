'use strict';

const bs58 = require('bs58');
const sodium = require('sodium-native');
const {veres} = require('did-client/lib/index');

async function cipherKeysForDid (options) {
  let doc = await getLocalDidDoc(options);

  if (!doc) {
    return null;
  }

  return cipherKeysFor(doc);
}

/**
 * @param doc {Document} DID Document
 *
 * @returns {{publicKey: Buffer, secretKey: Buffer}} KeyPair (curve25519 encryption keys)
 */
function cipherKeysFor(doc) {
  const {publicKey: signKeyPublic, secretKey: signKeySecret} = authKeysFor(doc);

  // Convert DID ed25519 signing authentication keys to curve25519 keys
  const cipherKeyPublic = new Buffer(sodium.crypto_box_PUBLICKEYBYTES);
  sodium.crypto_sign_ed25519_pk_to_curve25519(cipherKeyPublic, signKeyPublic);

  const cipherKeySecret = new Buffer(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_sign_ed25519_sk_to_curve25519(cipherKeySecret, signKeySecret);

  return {
    publicKey: cipherKeyPublic,
    secretKey: cipherKeySecret
  }
}

/**
 * @param doc {Document} DID Document
 *
 * @returns {{publicKey: Buffer, secretKey: Buffer}} KeyPair (ed25519 signing keys)
 */
function authKeysFor (doc) {
  const authKey = doc.authentication[0].publicKey[0];  // ed25519 signing key

  return {
    publicKey: bs58.decode(authKey.publicKeyBase58),
    secretKey: bs58.decode(authKey.privateKey.privateKeyBase58)
  }
}

/**
 * Resolves with a locally stored DID Document fetch result.
 *
 * @param options {object} Options hashmap
 * @param options.did {string}
 *
 * @throws {Error}
 *
 * @returns {Promise<Document|null>}
 */
function getLocalDidDoc(options) {
  return getDidDoc({location: 'local', mode: 'test', ...options});
}

/**
 * Resolves with a DID Document fetch result or null if not found.
 *
 * @param options {object} Options hashmap
 * @param options.did {string}
 * @param options.mode {string}
 * @param options.location {string}
 * @param [options.client]
 *
 * @returns {Promise<Document|null>}
 */
function getDidDoc(options) {
  const client = options.client || veres;

  return new Promise((resolve, reject) => {
    client.info({
      ...options,
      callback: (error, result) => {
        if(error) {
          return reject(error);
        }

        if (!result || !result.found) {
          return resolve(null);
        }

        resolve(result.doc);
      }
    });
  });
}

module.exports = {
  authKeysFor,
  cipherKeysForDid,
  cipherKeysFor,
  getLocalDidDoc,
  getDidDoc
};
