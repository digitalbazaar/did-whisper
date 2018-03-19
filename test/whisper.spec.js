const chai = require('chai');
chai.use(require('dirty-chai'));
chai.should();

const bs58 = require('bs58');
const chloride = require('chloride');

const testLocalDoc = require('./dids/did1.json');
const authKey = testLocalDoc.authentication[0].publicKey[0];
const signKeyPublic = bs58.decode(authKey.publicKeyBase58);
const signKeySecret = bs58.decode(authKey.privateKey.privateKeyBase58);

const plainText = 'Hello world!';

describe('did-whisper', () => {
  it('should encrypt with DID public key', () => {
    console.log(authKey);

    console.log('Decoded public:', signKeyPublic.toString('hex'));
    console.log('Decoded private:', signKeySecret.toString('hex'));

    const cipherKeyPublic =
      chloride.crypto_sign_ed25519_pk_to_curve25519(signKeyPublic);

    console.log('cipher key public:', cipherKeyPublic);
  });
});

