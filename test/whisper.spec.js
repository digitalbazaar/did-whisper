const chai = require('chai');
chai.use(require('dirty-chai'));
chai.should();

const {expect} = chai;

const bs58 = require('bs58');
const sodium = require('sodium-native');

const testLocalDoc = require('./dids/did1.json');
const authKey = testLocalDoc.authentication[0].publicKey[0];
const signKeyPublic = bs58.decode(authKey.publicKeyBase58);
const signKeySecret = bs58.decode(authKey.privateKey.privateKeyBase58);

const plainText = new Buffer('Hello world!');

describe('did-whisper', () => {
  it('should encrypt with DID public key and decrypt with private', () => {
    // console.log(authKey);
    // console.log('Decoded public:', signKeyPublic.toString('hex'));
    // console.log('Decoded private:', signKeySecret.toString('hex'));

    // Convert DID ed25519 signing authentication keys to curve25519 keys
    const cipherKeyPublic = new Buffer(sodium.crypto_box_PUBLICKEYBYTES);
    sodium.crypto_sign_ed25519_pk_to_curve25519(cipherKeyPublic, signKeyPublic);

    const cipherKeySecret = new Buffer(sodium.crypto_box_SECRETKEYBYTES);
    sodium.crypto_sign_ed25519_sk_to_curve25519(cipherKeySecret, signKeySecret);

    // Encrypt the message
    const cipher = new Buffer(plainText.length + sodium.crypto_box_SEALBYTES);
    sodium.crypto_box_seal(cipher, plainText, cipherKeyPublic);

    // Decrypt the message
    const decrypted = new Buffer(cipher.length - sodium.crypto_box_SEALBYTES);
    sodium.crypto_box_seal_open(decrypted, cipher, cipherKeyPublic,
      cipherKeySecret);

    expect(plainText.toString()).to.equal(decrypted.toString());
  });
});

