'use strict';

const axios = require('axios');
const bs58 = require('bs58');
const sodium = require('sodium-native');
const {veres} = require('did-client/lib/index');

const tls = require('tls');
tls.DEFAULT_ECDH_CURVE = 'auto';

/**
 * @param options
 * @param options.did {string} DID of recipient
 * @param options.message {string} Plaintext message to be encrypted
 * @param options.expiration {string} Expiration ('5m', '1h', '1d' or '1w')
 *
 * @returns {Promise<object>} Encrypted message object with keyId, expiration
 *   in seconds, and a base58 encoded cipher text.
 */
async function encryptForDid({did, message, expiration}) {
  const didOptions = {did, location: 'ledger', mode: 'test'};
  const cipherKeys = await cipherKeysForDid(didOptions);

  const cipher = bs58.encode(encryptMessage(message, cipherKeys));

  return {
    cipher,
    expiration: parseExpiration(expiration), // convert to seconds
    keyId: cipherKeys.keyId
  };
}

/**
 * @param message {string} Plaintext message
 * @param keys {KeyPair} curve25519 key pair
 *
 * @returns {Buffer} Message encrypted via libsodium's crypto_box_seal
 */
function encryptMessage(message, keys) {
  message = new Buffer(message);
  const cipher = new Buffer(message.length + sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal(cipher, message, keys.publicKey);

  return cipher;
}

/**
 * @param message {string}
 * @param storeUrl {string}
 * @returns {Promise<string>}
 */
async function saveMessage(message, storeUrl) {
  const url = storeUrl.endsWith('/whisper') ? storeUrl : storeUrl + '/whisper';

  const response = await axios.post(url, message, {responseType: 'text'});

  return response.data;
}

/**
 * @param url {string} URL of stored message, or DID of recipient
 * @param [cipher] {string} Encrypted message, base58-encoded
 *
 * @returns {Promise<string>} Resolves with decrypted message
 */
function decrypt(url, cipher) {
  if(cipher) {
    const did = url;
    return decryptForDid(did, cipher);
  }
  // Common case, fetch cipher from a did-whisper-server instance
  return decryptStored(url);
}

/**
 * @param url {string} URL of stored message
 *
 * @returns {Promise<string>} Resolves with decrypted message
 */
async function decryptStored(url) {
  const storedMessage = await fetchMessage(url);

  const {cipher, keyId} = storedMessage;
  const did = keyId && keyId.split('#')[0]; // Drop hash fragment

  return decryptForDid(did, cipher, keyId);
}

/**
 * @param did {string} DID of recipient
 * @param cipher {string} Encrypted cipher text, base58-encoded
 * @param [keyId] {string}
 *
 * @returns {Promise<string>} Decrypted plaintext message (using authentication
 *   private and public keys in the DID Document)
 */
async function decryptForDid(did, cipher, keyId) {
  const didOptions = {did, location: 'local', mode: 'test'};
  const recipientKeys = await cipherKeysForDid(didOptions);

  if(!(recipientKeys.secretKey && recipientKeys.publicKey)) {
    throw new Error('Could not find private decryption key in DID Document');
  }

  cipher = bs58.decode(cipher);

  return decryptMessage(cipher, recipientKeys).toString();
}

/**
 * @param cipher {string}
 * @param recipientKeys {{publicKey: Buffer, secretKey: Buffer}} KeyPair
 *   (curve25519 encryption keys)
 *
 * @returns {Buffer}
 */
function decryptMessage(cipher, recipientKeys) {
  const message = new Buffer(cipher.length - sodium.crypto_box_SEALBYTES);
  sodium.crypto_box_seal_open(message, cipher, recipientKeys.publicKey,
    recipientKeys.secretKey);

  return message;
}

/**
 * @param url {string}
 *
 * @throws {Error} Encountered while fetching or parsing stored message
 *
 * @returns {Promise<object>} Resolves with stored message
 */
async function fetchMessage(url) {
  const headers = {accept: 'application/json'};
  const response = await axios.get(url, {headers, responseType: 'json'});
  return response.data;
}

/**
 * @param options {object} Options hashmap (see docstring for `getDidDoc()`)
 * @param options.did {string}
 * @param options.location {string} Typically 'local' (when decrypting)
 *   or 'all' (when encrypting).
 *
 * @param [keyId] {string} Optional key id, if known
 *
 * @throws {Error} If unable to fetch a local DID Document
 *
 * @returns {{publicKey: Buffer, secretKey: Buffer}} KeyPair (curve25519
 *   encryption keys)
 */
async function cipherKeysForDid(options, keyId) {
  const doc = await getDidDoc(options);

  if(!doc) {
    throw new Error(`Could not fetch DID Document for ${options.did}`);
  }

  return cipherKeysFor(doc, keyId);
}

/**
 * @param doc {Document} DID Document
 * @param [keyId] {string} Optional key id, if known
 *
 * @returns {{publicKey: Buffer, secretKey: Buffer}} KeyPair (curve25519
 *   encryption keys)
 */
function cipherKeysFor(doc, keyId = null) {
  const keys = authKeysFor(doc, keyId);

  const {publicKey: signKeyPublic, secretKey: signKeySecret} = keys;
  keyId = keyId || keys.keyId;

  // Convert DID ed25519 signing authentication keys to curve25519 keys
  const cipherKeyPublic = new Buffer(sodium.crypto_box_PUBLICKEYBYTES);
  sodium.crypto_sign_ed25519_pk_to_curve25519(cipherKeyPublic, signKeyPublic);

  let cipherKeySecret;
  if(signKeySecret) {
    cipherKeySecret = new Buffer(sodium.crypto_box_SECRETKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_curve25519(cipherKeySecret, signKeySecret);
  }

  return {keyId, publicKey: cipherKeyPublic, secretKey: cipherKeySecret};
}

/**
 * @param doc {Document} DID Document
 * @param [keyId] {string} Optional key id, if known
 *
 * @returns {{publicKey: Buffer, secretKey: Buffer}} KeyPair (ed25519)
 */
function authKeysFor(doc, keyId) {
  const authKey = doc.authentication[0].publicKey[0]; // ed25519 signing key

  const publicKey = bs58.decode(authKey.publicKeyBase58);
  let secretKey;

  if(authKey.privateKey) {
    secretKey = bs58.decode(authKey.privateKey.privateKeyBase58);
  }

  return {
    publicKey,
    secretKey,
    keyId: authKey.id
  };
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

        if(!result || !result.found) {
          return resolve(null);
        }

        resolve(result.doc);
      }
    });
  });
}

/**
 * @param expiration {string} Expiration ('5m', '1h', '1d' or '1w')
 *
 * @returns {number} In seconds
 */
function parseExpiration(expiration) {
  const ONE_WEEK = 604800;

  const validExpirations = {
    '5m': 300,
    '1h': 3600,
    '1d': 86400,
    '1w': ONE_WEEK
  };

  return validExpirations[expiration] || ONE_WEEK;
}

module.exports = {
  authKeysFor,
  cipherKeysForDid,
  cipherKeysFor,
  decrypt,
  decryptForDid,
  decryptMessage,
  encryptForDid,
  encryptMessage,
  getDidDoc,
  saveMessage
};
