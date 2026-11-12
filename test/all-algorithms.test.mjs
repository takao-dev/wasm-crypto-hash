import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import {
  adler32, createAdler32,
  crc32, createCRC32,
  crc64, createCRC64,
  md4, createMD4,
  md5, createMD5,
  ripemd160, createRIPEMD160,
  sha1, createSHA1,
  sha224, createSHA224,
  sha256, createSHA256,
  sha384, createSHA384,
  sha512, createSHA512,
  sm3, createSM3,
  xxhash32, createXXHash32,
  xxhash64, createXXHash64,
  xxhash3, createXXHash3,
  xxhash128, createXXHash128,
  kmac256,
  sipHash24,
  murmurHash3_32, murmurHash3_128,
  xchacha20Poly1305Encrypt, xchacha20Poly1305Decrypt,
  bcrypt, bcryptVerify,
  scrypt,
  pbkdf2,
  argon2i, argon2d, argon2Verify,
  hotp, totp, verifyTotp,
  blake2b, createBLAKE2b,
  blake2s, createBLAKE2s,
  blake3, createBLAKE3,
  keccak, createKeccak,
  sha3, createSHA3,
  shake256, createSHAKE256,
} from '../dist/lib/index.js';

test('Classical and checksum hashes: Adler32, CRC32, CRC64, MD4, MD5, RIPEMD160, SM3', async () => {
  const data = 'The quick brown fox jumps over the lazy dog';

  // Adler32 (call twice to test cache hit)
  const a32 = await adler32(data);
  const a32Second = await adler32(data);
  assert.equal(a32, a32Second);
  assert.match(a32, /^[0-9a-f]{8}$/i);
  const a32H = await createAdler32();
  a32H.init().update(data);
  assert.equal(a32H.digest('hex'), a32);

  // CRC32
  const c32 = await crc32(data);
  const c32Second = await crc32(data);
  assert.equal(c32, c32Second);
  assert.match(c32, /^[0-9a-f]{8}$/i);
  const c32H = await createCRC32();
  c32H.init().update(data);
  assert.equal(c32H.digest('hex'), c32);

  // CRC64
  const c64 = await crc64(data);
  const c64Second = await crc64(data);
  assert.equal(c64, c64Second);
  assert.match(c64, /^[0-9a-f]{16}$/i);
  const c64H = await createCRC64();
  c64H.init().update(data);
  assert.equal(c64H.digest('hex'), c64);

  // MD4
  const m4 = await md4(data);
  const m4Second = await md4(data);
  assert.equal(m4, m4Second);
  assert.match(m4, /^[0-9a-f]{32}$/i);
  const m4H = await createMD4();
  m4H.init().update(data);
  assert.equal(m4H.digest('hex'), m4);

  // MD5
  const m5 = await md5(data);
  const m5Second = await md5(data);
  assert.equal(m5, m5Second);
  assert.match(m5, /^[0-9a-f]{32}$/i);
  const m5H = await createMD5();
  m5H.init().update(data);
  assert.equal(m5H.digest('hex'), m5);

  // RIPEMD160
  const r160 = await ripemd160(data);
  const r160Second = await ripemd160(data);
  assert.equal(r160, r160Second);
  assert.match(r160, /^[0-9a-f]{40}$/i);
  const r160H = await createRIPEMD160();
  r160H.init().update(data);
  assert.equal(r160H.digest('hex'), r160);

  // SM3
  const sm3Res = await sm3(data);
  const sm3Second = await sm3(data);
  assert.equal(sm3Res, sm3Second);
  assert.match(sm3Res, /^[0-9a-f]{64}$/i);
  const sm3H = await createSM3();
  sm3H.init().update(data);
  assert.equal(sm3H.digest('hex'), sm3Res);
});

test('SHA-2 and SHA-3 family: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3, Keccak, SHAKE', async () => {
  const data = 'Cryptographic test message';

  // SHA-1
  const s1 = await sha1(data);
  const s1Second = await sha1(data);
  assert.equal(s1, s1Second);
  assert.match(s1, /^[0-9a-f]{40}$/i);
  const s1H = await createSHA1();
  s1H.init().update(data);
  assert.equal(s1H.digest('hex'), s1);

  // SHA-224 (call twice for cache hit)
  const s224 = await sha224(data);
  const s224Second = await sha224(data);
  assert.equal(s224, s224Second);
  assert.match(s224, /^[0-9a-f]{56}$/i);
  const s224H = await createSHA224();
  s224H.init().update(data);
  assert.equal(s224H.digest('hex'), s224);

  // SHA-256
  const s256 = await sha256(data);
  const s256Second = await sha256(data);
  assert.equal(s256, s256Second);
  assert.match(s256, /^[0-9a-f]{64}$/i);
  const s256H = await createSHA256();
  s256H.init().update(data);
  assert.equal(s256H.digest('hex'), s256);

  // SHA-384
  const s384 = await sha384(data);
  const s384Second = await sha384(data);
  assert.equal(s384, s384Second);
  assert.match(s384, /^[0-9a-f]{96}$/i);
  const s384H = await createSHA384();
  s384H.init().update(data);
  assert.equal(s384H.digest('hex'), s384);

  // SHA-512
  const s512 = await sha512(data);
  const s512Second = await sha512(data);
  assert.equal(s512, s512Second);
  assert.match(s512, /^[0-9a-f]{128}$/i);
  const s512H = await createSHA512();
  s512H.init().update(data);
  assert.equal(s512H.digest('hex'), s512);

  // SHA-3 (512 default, plus 256 variant)
  const s3 = await sha3(data);
  const s3Second = await sha3(data);
  assert.equal(s3, s3Second);
  assert.match(s3, /^[0-9a-f]{128}$/i);
  const s3H = await createSHA3(512);
  s3H.init().update(data);
  assert.equal(s3H.digest('hex'), s3);

  const s3_256 = await sha3(data, 256);
  assert.match(s3_256, /^[0-9a-f]{64}$/i);

  // Keccak (512 default, plus 256 variant)
  const kec = await keccak(data);
  const kecSecond = await keccak(data);
  assert.equal(kec, kecSecond);
  assert.match(kec, /^[0-9a-f]{128}$/i);
  const kecH = await createKeccak(512);
  kecH.init().update(data);
  assert.equal(kecH.digest('hex'), kec);

  const kec_256 = await keccak(data, 256);
  assert.match(kec_256, /^[0-9a-f]{64}$/i);

  // SHAKE-256 (call twice for cache hit)
  const shk256 = await shake256(data, 512);
  const shk256Second = await shake256(data, 512);
  assert.equal(shk256, shk256Second);
  assert.match(shk256, /^[0-9a-f]{128}$/i);
  const shk256H = await createSHAKE256(512);
  shk256H.init().update(data);
  assert.equal(shk256H.digest('hex'), shk256);
});

test('xxHash family: xxHash32, xxHash64, xxHash3, xxHash128', async () => {
  const data = 'High throughput hashing with xxHash';

  const x32 = await xxhash32(data);
  const x32Second = await xxhash32(data);
  assert.equal(x32, x32Second);
  assert.match(x32, /^[0-9a-f]{8}$/i);
  const x32H = await createXXHash32();
  x32H.init().update(data);
  assert.equal(x32H.digest('hex'), x32);

  const x64 = await xxhash64(data);
  const x64Second = await xxhash64(data);
  assert.equal(x64, x64Second);
  assert.match(x64, /^[0-9a-f]{16}$/i);
  const x64H = await createXXHash64();
  x64H.init().update(data);
  assert.equal(x64H.digest('hex'), x64);

  const x3 = await xxhash3(data);
  const x3Second = await xxhash3(data);
  assert.equal(x3, x3Second);
  assert.match(x3, /^[0-9a-f]{16}$/i);
  const x3H = await createXXHash3();
  x3H.init().update(data);
  assert.equal(x3H.digest('hex'), x3);

  const x128 = await xxhash128(data);
  const x128Second = await xxhash128(data);
  assert.equal(x128, x128Second);
  assert.match(x128, /^[0-9a-f]{32}$/i);
  const x128H = await createXXHash128();
  x128H.init().update(data);
  assert.equal(x128H.digest('hex'), x128);
});

test('BLAKE family: BLAKE2b, BLAKE2s, BLAKE3', async () => {
  const data = 'BLAKE cryptographic hash testing';
  const key = new Uint8Array(32).fill(9);

  // BLAKE2b with and without key, twice for cache hit
  const b2b = await blake2b(data);
  const b2bSecond = await blake2b(data);
  assert.equal(b2b, b2bSecond);
  assert.match(b2b, /^[0-9a-f]{128}$/i);
  const b2bKeyed = await blake2b(data, 512, key);
  assert.notEqual(b2b, b2bKeyed);

  const b2bH = await createBLAKE2b();
  b2bH.init().update(data);
  assert.equal(b2bH.digest('hex'), b2b);

  // BLAKE2s with and without key
  const b2s = await blake2s(data);
  const b2sSecond = await blake2s(data);
  assert.equal(b2s, b2sSecond);
  assert.match(b2s, /^[0-9a-f]{64}$/i);
  const b2sKeyed = await blake2s(data, 256, key);
  assert.notEqual(b2s, b2sKeyed);

  const b2sH = await createBLAKE2s();
  b2sH.init().update(data);
  assert.equal(b2sH.digest('hex'), b2s);

  // BLAKE3 with and without key
  const b3 = await blake3(data);
  const b3Second = await blake3(data);
  assert.equal(b3, b3Second);
  assert.match(b3, /^[0-9a-f]{64}$/i);
  const b3Keyed = await blake3(data, 256, key);
  assert.notEqual(b3, b3Keyed);

  const b3H = await createBLAKE3();
  b3H.init().update(data);
  assert.equal(b3H.digest('hex'), b3);
});

test('Specialized MACs & non-crypto hashes: KMAC256, SipHash-2-4, MurmurHash3', async () => {
  const key16 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const key32 = new Uint8Array(32).fill(7);

  // KMAC256
  const kmac = await kmac256(key32, 'Message to authenticate', 256, 'MyCustomDomain');
  assert.match(kmac, /^[0-9a-f]{64}$/i);

  // SipHash-2-4
  const sip = sipHash24(key16, 'SipHash data input');
  assert.match(sip, /^[0-9a-f]{16}$/i);

  // MurmurHash3: test remainder lengths 0, 1, 2, 3 and all 1..15 byte tails for 128-bit
  for (let len = 1; len <= 16; len++) {
    const input = new Uint8Array(len).fill(0xab);
    const m32 = murmurHash3_32(input, 123);
    assert.ok(typeof m32 === 'number');
    const m128 = murmurHash3_128(input, 123);
    assert.match(m128, /^[0-9a-f]{32}$/i);
  }
});

test('XChaCha20-Poly1305 extended nonce AEAD encrypt and decrypt', async () => {
  const key = randomBytes(32);
  const nonce24 = randomBytes(24);
  const plaintext = 'Confidential payload with 192-bit nonce';
  const aad = new Uint8Array([1, 2, 3, 4]);

  const { ciphertext, tag } = await xchacha20Poly1305Encrypt(plaintext, key, nonce24, aad);
  assert.ok(ciphertext.length > 0);
  assert.equal(tag.length, 16);

  const decryptedBytes = await xchacha20Poly1305Decrypt(ciphertext, key, nonce24, tag, aad);
  const decrypted = new TextDecoder().decode(decryptedBytes);
  assert.equal(decrypted, plaintext);

  // Fails on tampered tag
  const badTag = new Uint8Array(tag);
  badTag[0] ^= 0xff;
  await assert.rejects(
    () => xchacha20Poly1305Decrypt(ciphertext, key, nonce24, badTag, aad),
    /tag verification failed/i
  );
});

test('Password KDFs: bcrypt and scrypt', async () => {
  // bcrypt
  const salt16 = randomBytes(16);
  const hashed = await bcrypt({
    password: 'super-secure-password',
    salt: salt16,
    costFactor: 4,
    outputType: 'encoded',
  });
  assert.ok(typeof hashed === 'string');
  assert.ok(hashed.startsWith('$2'));

  const valid = await bcryptVerify({
    password: 'super-secure-password',
    hash: hashed,
  });
  assert.equal(valid, true);

  const invalid = await bcryptVerify({
    password: 'wrong-password',
    hash: hashed,
  });
  assert.equal(invalid, false);

  // bcrypt binary and hex output types
  const hexHash = await bcrypt({
    password: 'super-secure-password',
    salt: salt16,
    costFactor: 4,
    outputType: 'hex',
  });
  assert.match(hexHash, /^[0-9a-f]{48}$/i);

  const binHash = await bcrypt({
    password: 'super-secure-password',
    salt: salt16,
    costFactor: 4,
    outputType: 'binary',
  });
  assert.equal(binHash.length, 24);

  // scrypt hex and binary output types
  const scryptHash = await scrypt({
    password: 'scrypt-password',
    salt: salt16,
    costFactor: 1024,
    blockSize: 8,
    parallelism: 1,
    hashLength: 32,
    outputType: 'hex',
  });
  assert.match(scryptHash, /^[0-9a-f]{64}$/i);

  const scryptBin = await scrypt({
    password: 'scrypt-password',
    salt: salt16,
    costFactor: 1024,
    blockSize: 8,
    parallelism: 1,
    hashLength: 32,
    outputType: 'binary',
  });
  assert.equal(scryptBin.length, 32);

  // bcrypt validation errors
  await assert.rejects(
    () => bcrypt({ password: 'pwd', salt: new Uint8Array(10), costFactor: 4 }),
    /Salt should be 16 bytes/i
  );
  await assert.rejects(
    () => bcrypt({ password: '', salt: salt16, costFactor: 4 }),
    /Password should be at least 1 byte long/i
  );
});

test('Argon2 variants: argon2i, argon2d, and verification', async () => {
  const salt = randomBytes(16);
  const pwd = 'argon2-test-password';

  // argon2i
  const hashI = await argon2i({
    password: pwd,
    salt,
    iterations: 1,
    parallelism: 1,
    memorySize: 256,
    hashLength: 32,
    outputType: 'encoded',
  });
  assert.ok(hashI.startsWith('$argon2i$'));
  assert.equal(await argon2Verify({ password: pwd, hash: hashI }), true);
  assert.equal(await argon2Verify({ password: 'wrong', hash: hashI }), false);

  // argon2d
  const hashD = await argon2d({
    password: pwd,
    salt,
    iterations: 1,
    parallelism: 1,
    memorySize: 256,
    hashLength: 32,
    outputType: 'hex',
  });
  assert.match(hashD, /^[0-9a-f]{64}$/i);
});

test('TOTP and HOTP with SHA256 and custom digits', async () => {
  const key = 'JBSWY3DPEHPK3PXP'; // Base32 test secret

  const hotp256 = await hotp(key, 1234, 8, 'sha256');
  assert.equal(hotp256.length, 8);
  assert.match(hotp256, /^[0-9]{8}$/);

  const totpCode = await totp(key, { algorithm: 'sha256', digits: 8, step: 60 });
  assert.equal(totpCode.length, 8);

  const verified = await verifyTotp(totpCode, key, { algorithm: 'sha256', digits: 8, step: 60 });
  assert.equal(verified, true);

  const wrong = await verifyTotp('00000000', key, { algorithm: 'sha256', digits: 8, step: 60 });
  assert.equal(wrong, false);
});

test('PBKDF2 derivations and validation errors', async () => {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  // Hex output
  const hex = await pbkdf2({
    password: 'password',
    salt,
    iterations: 10,
    hashLength: 32,
    hashFunction: createSHA256(),
    outputType: 'hex',
  });
  assert.match(hex, /^[0-9a-f]{64}$/i);

  // Binary output
  const bin = await pbkdf2({
    password: 'password',
    salt,
    iterations: 10,
    hashLength: 16,
    hashFunction: createSHA256(),
    outputType: 'binary',
  });
  assert.equal(bin.length, 16);

  // Validation errors
  await assert.rejects(
    () => pbkdf2({ password: 'p', salt, iterations: 0, hashLength: 16, hashFunction: createSHA256() }),
    /Iterations should be a positive number/i
  );
  await assert.rejects(
    () => pbkdf2({ password: 'p', salt, iterations: 10, hashLength: 0, hashFunction: createSHA256() }),
    /Hash length should be a positive number/i
  );
});

test('BLAKE invalid bits parameter errors', async () => {
  await assert.rejects(
    () => blake2b('data', 7),
    /Invalid variant/i
  );
  await assert.rejects(
    () => blake2s('data', 520),
    /Invalid variant/i
  );
  await assert.rejects(
    () => blake3('data', 7),
    /Invalid variant/i
  );
});
