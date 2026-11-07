import assert from 'node:assert/strict';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
const nativePqc = await webcrypto.subtle.generateKey({name:'ML-DSA-65'}, true, ['sign','verify']).then(() => typeof webcrypto.subtle.encapsulateBits === 'function', () => false);
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  generatePqcHybridKeyPair,
  pqcEncapsulate,
  pqcDecapsulate,
  generateMlDsaKeyPair,
  mlDsaSign,
  mlDsaVerify,
  generateMnemonic,
  mnemonicToSeed,
  shamirSplit,
  shamirCombine,
  totp,
  verifyTotp,
  argon2Verify,
  argon2id,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  balloonHash,
  poseidonHash,
} = require('../dist/lib/index.js');

test('1. PQC Hybrid KEM: encapsulates and decapsulates identical shared secret', { skip: !nativePqc }, async () => {
  const aliceKeyPair = await generatePqcHybridKeyPair();
  assert.equal(aliceKeyPair.publicKey.length, 1248);
  assert.equal(aliceKeyPair.algorithm, 'X25519-ML-KEM-768');

  // Bob encapsulates to Alice
  const { sharedSecret: bobSecret, ciphertext } = await pqcEncapsulate(aliceKeyPair.publicKey);
  assert.equal(bobSecret.length, 32);
  assert.equal(ciphertext.length, 1130);

  // Alice decapsulates using her private key
  const aliceSecret = await pqcDecapsulate(ciphertext, aliceKeyPair.privateKey);
  assert.deepEqual(aliceSecret, bobSecret);

  // Eve with different key cannot obtain the same secret
  const eveKeyPair = await generatePqcHybridKeyPair();
  const eveSecret = await pqcDecapsulate(ciphertext, eveKeyPair.privateKey);
  assert.notDeepEqual(eveSecret, bobSecret);
});

test('2. ML-DSA-65 Signature: verifies authentic signatures and rejects tampering', { skip: !nativePqc }, async () => {
  const keyPair = await generateMlDsaKeyPair();
  assert.equal(keyPair.publicKey.length, 1974);

  const message = 'Antigravity Cryptographic Payload v1.0.0';
  const signature = await mlDsaSign(message, keyPair.privateKey);
  assert.equal(signature.length, 3309);

  // Authentic signature must verify
  const valid = await mlDsaVerify(message, signature, keyPair.publicKey);
  assert.equal(valid, true);

  // Tampered message must fail
  const tamperedMsgValid = await mlDsaVerify(message + '!', signature, keyPair.publicKey);
  assert.equal(tamperedMsgValid, false);

  // Tampered signature must fail
  const tamperedSig = new Uint8Array(signature);
  tamperedSig[0] ^= 0xff;
  const tamperedSigValid = await mlDsaVerify(message, tamperedSig, keyPair.publicKey);
  assert.equal(tamperedSigValid, false);

  // Wrong public key must fail
  const otherKeyPair = await generateMlDsaKeyPair();
  const wrongKeyValid = await mlDsaVerify(message, signature, otherKeyPair.publicKey);
  assert.equal(wrongKeyValid, false);
});

test('3. BIP-39 Mnemonic: generates CSPRNG entropy and derives 64-byte master seed', async () => {
  const mnemonic12 = await generateMnemonic(128);
  const words12 = mnemonic12.split(' ');
  assert.equal(words12.length, 12);

  const mnemonic24 = await generateMnemonic(256);
  const words24 = mnemonic24.split(' ');
  assert.equal(words24.length, 24);

  const seed = await mnemonicToSeed(mnemonic12, 'passphrase123');
  assert.equal(seed.length, 64);
});

test('4. Shamir Secret Sharing: restores secret from threshold shares, fails under threshold', async () => {
  const secret = 'TOP_SECRET_AIR_GAP_KEY_2026';
  const shares = shamirSplit(secret, 5, 3);
  assert.equal(shares.length, 5);

  // Restore with 3 shares (shares 1, 3, 5)
  const subset = [shares[0], shares[2], shares[4]];
  const recovered = shamirCombine(subset);
  assert.equal(new TextDecoder().decode(recovered), secret);

  // Attempt restore with under threshold (2 shares) yields incorrect recovered bytes
  const underThreshold = shamirCombine([shares[0], shares[1]]);
  assert.notEqual(new TextDecoder().decode(underThreshold), secret);
});

test('5. TOTP / HOTP: generates 6-digit OTP and verifies with timing safety', async () => {
  const key = new TextEncoder().encode('JBSWY3DPEHPK3PXP');
  const code = await totp(key);
  assert.equal(code.length, 6);
  assert.equal(/^\d{6}$/.test(code), true);

  const ok = await verifyTotp(code, key);
  assert.equal(ok, true);

  const bad = await verifyTotp('000000', key, { window: 0 });
  assert.equal(bad, false);
});

test('5b. Base32: decodes padded, unpadded, whitespace, case-insensitively with zero ReDoS', () => {
  const { decodeBase32 } = require('../dist/lib/totp.js');
  assert.equal(new TextDecoder().decode(decodeBase32('MZXW6===')), 'foo');
  assert.equal(new TextDecoder().decode(decodeBase32('mzxw6')), 'foo');
  assert.equal(new TextDecoder().decode(decodeBase32('M Z X W 6 = = =')), 'foo');
  assert.throws(() => decodeBase32('invalid189!'), /Invalid Base32 character/);
});

test('6. ChaCha20-Poly1305 AEAD: encrypts and fails on tampered ciphertext', async () => {
  const key = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(12).fill(3);
  const plaintext = new TextEncoder().encode('Zero-dependency AEAD packet');

  const { ciphertext, tag } = await chacha20Poly1305Encrypt(plaintext, key, nonce);
  assert.equal(tag.length, 16);

  const decrypted = await chacha20Poly1305Decrypt(ciphertext, key, nonce, tag);
  assert.equal(new TextDecoder().decode(decrypted), 'Zero-dependency AEAD packet');

  // Tamper ciphertext
  const badCipher = new Uint8Array(ciphertext);
  badCipher[0] ^= 1;
  await assert.rejects(
    async () => await chacha20Poly1305Decrypt(badCipher, key, nonce, tag),
    /Authenticated tag verification failed/,
  );
});

test('7. Argon2id: verifies password with timing-safe comparison', async () => {
  const password = 'CorrectHorseBatteryStaple';
  const salt = 'sodium-chloride-salt';
  const phcHash = await argon2id({
    password,
    salt,
    iterations: 2,
    memorySize: 512,
    parallelism: 1,
    hashLength: 32,
    outputType: 'encoded',
  });

  const valid = await argon2Verify({ password, hash: phcHash });
  assert.equal(valid, true);

  const invalid = await argon2Verify({ password: 'WrongPassword', hash: phcHash });
  assert.equal(invalid, false);
});

test('8. Poseidon & Balloon: computes deterministic ZK & memory-hard digests', async () => {
  const poseidonDigest = poseidonHash([100n, 200n]);
  assert.equal(typeof poseidonDigest, 'string');
  assert.equal(poseidonDigest.length, 64);

  const balloonDigest = await balloonHash('user-password', 'random-salt', 2, 8);
  assert.equal(balloonDigest.length, 64);
});
