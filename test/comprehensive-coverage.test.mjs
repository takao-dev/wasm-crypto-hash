import assert from 'node:assert/strict';
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
  bcrypt, bcryptVerify,
  scrypt,
  pbkdf2,
  argon2i, argon2d, argon2id, argon2Verify,
  blake2b, createBLAKE2b,
  blake2s, createBLAKE2s,
  blake3, createBLAKE3,
  keccak, createKeccak,
  sha3, createSHA3,
  shake256, createSHAKE256,
  createHMAC,
  entropyToMnemonic, generateMnemonic,
  aesKeyWrap, aesKeyUnwrap,
  poseidonHash,
  shamirSplit,
} from '../dist/lib/index.js';

import {
  getUInt8Buffer,
  encodeBase64,
  decodeBase64,
  hexStringEqualsUInt8,
  writeHexToUInt8,
  timingSafeEqualString,
  verifyRsaSignatureBase64,
} from '../dist/lib/util.js';

test('Hasher state save and load for all streaming hash algorithms', async () => {
  const hashFactories = [
    { name: 'adler32', create: createAdler32, oneShot: adler32 },
    { name: 'crc32', create: createCRC32, oneShot: crc32 },
    { name: 'crc64', create: createCRC64, oneShot: crc64 },
    { name: 'md4', create: createMD4, oneShot: md4 },
    { name: 'md5', create: createMD5, oneShot: md5 },
    { name: 'ripemd160', create: createRIPEMD160, oneShot: ripemd160 },
    { name: 'sha1', create: createSHA1, oneShot: sha1 },
    { name: 'sha224', create: createSHA224, oneShot: sha224 },
    { name: 'sha256', create: createSHA256, oneShot: sha256 },
    { name: 'sha384', create: createSHA384, oneShot: sha384 },
    { name: 'sha512', create: createSHA512, oneShot: sha512 },
    { name: 'sm3', create: createSM3, oneShot: sm3 },
    { name: 'xxhash32', create: createXXHash32, oneShot: xxhash32 },
    { name: 'xxhash64', create: createXXHash64, oneShot: xxhash64 },
    { name: 'xxhash3', create: createXXHash3, oneShot: xxhash3 },
    { name: 'xxhash128', create: createXXHash128, oneShot: xxhash128 },
    { name: 'blake2b', create: () => createBLAKE2b(256), oneShot: (d) => blake2b(d, 256) },
    { name: 'blake2s', create: () => createBLAKE2s(256), oneShot: (d) => blake2s(d, 256) },
    { name: 'blake3', create: createBLAKE3, oneShot: blake3 },
    { name: 'keccak', create: () => createKeccak(256), oneShot: (d) => keccak(d, 256) },
    { name: 'sha3', create: () => createSHA3(256), oneShot: (d) => sha3(d, 256) },
    { name: 'shake256', create: () => createSHAKE256(256), oneShot: (d) => shake256(d, 256) },
  ];

  for (const item of hashFactories) {
    // 1. Test save and load state
    const h1 = await item.create();
    h1.init().update('part_one_');
    const state = h1.save();
    assert.ok(state instanceof Uint8Array);

    const h2 = await item.create();
    h2.load(state);
    h2.update('part_two');
    const digestRestored = h2.digest('hex');

    const expected = await item.oneShot('part_one_part_two');
    assert.equal(digestRestored, expected, `${item.name} save/load state failed`);

    // 2. Test cached calculation error catch path by passing invalid input
    await assert.rejects(async () => {
      await item.oneShot(null);
    });
  }
});

test('WASMInterface state and boundary validations', async () => {
  const h = await createSHA256();
  // Call digest first to set initialized = false
  h.digest('hex');

  // update before init
  assert.throws(() => h.update('test'), /update\(\) called before init\(\)/);

  // digest before init
  assert.throws(() => h.digest('hex'), /digest\(\) called before init\(\)/);

  // save before init
  assert.throws(() => h.save(), /save\(\) can only be called after init\(\)/);

  // load invalid inputs
  assert.throws(() => h.load(null), /load\(\) expects an Uint8Array/);
  assert.throws(() => h.load(new Uint8Array(4)), /Bad state length/);

  // load tampered state prefix
  h.init().update('abc');
  const validState = h.save();
  const corrupted = new Uint8Array(validState);
  corrupted[0] ^= 0xff;
  assert.throws(() => h.load(corrupted), /incompatible hash implementation/);

  // Large input streaming (> 16KB)
  const largeData = new Uint8Array(40000).fill(0x42);
  const largeHex = await sha256(largeData);
  assert.match(largeHex, /^[0-9a-f]{64}$/);
});

test('Argon2 options validations and output formats', async () => {
  const validOpts = {
    password: 'password123',
    salt: 'salt12345678',
    iterations: 1,
    parallelism: 1,
    memorySize: 64,
    hashLength: 32,
  };

  // Invalid options
  await assert.rejects(() => argon2i(null), /Invalid options parameter/);
  await assert.rejects(() => argon2i({ ...validOpts, password: '' }), /Password must be specified/);
  await assert.rejects(() => argon2i({ ...validOpts, salt: '' }), /Salt must be specified/);
  await assert.rejects(() => argon2i({ ...validOpts, salt: 'short' }), /Salt should be at least 8 bytes/);
  await assert.rejects(() => argon2i({ ...validOpts, iterations: 0 }), /Iterations should be a positive number/);
  await assert.rejects(() => argon2i({ ...validOpts, parallelism: 0 }), /Parallelism should be a positive number/);
  await assert.rejects(() => argon2i({ ...validOpts, hashLength: 2 }), /Hash length should be at least 4 bytes/);
  await assert.rejects(() => argon2i({ ...validOpts, memorySize: null }), /Memory size should be specified/);
  await assert.rejects(() => argon2i({ ...validOpts, memorySize: 4, parallelism: 2 }), /Memory size should be at least 8 \* parallelism/);
  await assert.rejects(() => argon2i({ ...validOpts, outputType: 'unsupported' }), /Insupported output type/);

  // Binary and encoded output
  const bin = await argon2i({ ...validOpts, outputType: 'binary' });
  assert.ok(bin instanceof Uint8Array);
  assert.equal(bin.length, 32);

  const enc = await argon2i({ ...validOpts, outputType: 'encoded', secret: 'my-secret' });
  assert.ok(typeof enc === 'string');
  assert.ok(enc.startsWith('$argon2i$'));

  // argon2d binary and encoded
  const binD = await argon2d({ ...validOpts, outputType: 'binary' });
  assert.ok(binD instanceof Uint8Array);

  const encD = await argon2d({ ...validOpts, outputType: 'encoded' });
  assert.ok(encD.startsWith('$argon2d$'));

  // argon2Verify with invalid inputs
  await assert.rejects(() => argon2Verify(null), /Invalid options parameter/);
  await assert.rejects(() => argon2Verify({ hash: 123, password: 'pw' }), /Hash should be specified/);
  await assert.rejects(() => argon2Verify({ hash: 'invalid_hash', password: 'pw' }), /Invalid hash/);
});

test('Bcrypt options validations and output formats', async () => {
  const validOpts = {
    password: 'password123',
    salt: new Uint8Array(16).fill(1),
    costFactor: 4,
  };

  await assert.rejects(() => bcrypt(null), /Invalid options parameter/);
  await assert.rejects(() => bcrypt({ ...validOpts, costFactor: 2 }), /Cost factor should be a number between 4 and 31/);
  await assert.rejects(() => bcrypt({ ...validOpts, password: '' }), /Password should be at least 1 byte long/);
  await assert.rejects(() => bcrypt({ ...validOpts, password: 'a'.repeat(80) }), /Password should be at most 72 bytes long/);
  await assert.rejects(() => bcrypt({ ...validOpts, salt: new Uint8Array(10) }), /Salt should be 16 bytes long/);
  await assert.rejects(() => bcrypt({ ...validOpts, outputType: 'invalid' }), /Insupported output type/);

  // Hex and binary output
  const hex = await bcrypt({ ...validOpts, outputType: 'hex' });
  assert.equal(typeof hex, 'string');
  assert.equal(hex.length, 48);

  const bin = await bcrypt({ ...validOpts, outputType: 'binary' });
  assert.ok(bin instanceof Uint8Array);
  assert.equal(bin.length, 24);

  // bcryptVerify validation branches
  await assert.rejects(() => bcryptVerify(null), /Invalid options parameter/);
  await assert.rejects(() => bcryptVerify({ hash: null, password: 'pw' }), /Hash should be specified/);
  await assert.rejects(() => bcryptVerify({ hash: 'short', password: 'pw' }), /Hash should be 60 bytes long/);
  await assert.rejects(() => bcryptVerify({ hash: 'x'.repeat(60), password: 'pw' }), /Invalid hash/);
  await assert.rejects(() => bcryptVerify({ hash: '$2a$02$' + 'a'.repeat(53), password: 'pw' }), /Invalid hash/);
  await assert.rejects(() => bcryptVerify({ hash: '$2a$35$' + 'a'.repeat(53), password: 'pw' }), /Invalid hash/);
  const validFormatHash = '$2b$04$' + 'a'.repeat(53);
  await assert.rejects(() => bcryptVerify({ hash: validFormatHash, password: '' }), /Password should be at least 1 byte long/);
  await assert.rejects(() => bcryptVerify({ hash: validFormatHash, password: 'p'.repeat(80) }), /Password should be at most 72 bytes long/);
});

test('Scrypt options validations and output formats', async () => {
  const validOpts = {
    password: 'password123',
    salt: 'salt1234',
    costFactor: 16,
    blockSize: 8,
    parallelism: 1,
    hashLength: 32,
  };

  await assert.rejects(() => scrypt(null), /Invalid options parameter/);
  await assert.rejects(() => scrypt({ ...validOpts, blockSize: 0 }), /Block size should be a positive number/);
  await assert.rejects(() => scrypt({ ...validOpts, costFactor: 3 }), /Cost factor should be a power of 2/);
  await assert.rejects(() => scrypt({ ...validOpts, parallelism: 0 }), /Parallelism should be a positive number/);
  await assert.rejects(() => scrypt({ ...validOpts, hashLength: 0 }), /Hash length should be a positive number/);
  await assert.rejects(() => scrypt({ ...validOpts, outputType: 'bad' }), /Insupported output type/);

  // Binary output
  const bin = await scrypt({ ...validOpts, outputType: 'binary' });
  assert.ok(bin instanceof Uint8Array);
  assert.equal(bin.length, 32);
});

test('PBKDF2 options validations and multi-block derivations', async () => {
  await assert.rejects(() => pbkdf2(null), /Invalid options parameter/);
  await assert.rejects(() => pbkdf2({ hashFunction: null }), /Invalid hash function is provided/);
  await assert.rejects(() => pbkdf2({ hashFunction: createSHA256(), iterations: 0, hashLength: 32 }), /Iterations should be a positive number/);
  await assert.rejects(() => pbkdf2({ hashFunction: createSHA256(), iterations: 1, hashLength: 0 }), /Hash length should be a positive number/);
  await assert.rejects(() => pbkdf2({ hashFunction: createSHA256(), iterations: 1, hashLength: 32, outputType: 'bad' }), /Insupported output type/);

  // Multi-block derivation (hashLength 64 with SHA-256 (32 bytes) requires 2 blocks)
  const derivedHex = await pbkdf2({
    password: 'password',
    salt: 'salt',
    iterations: 2,
    hashLength: 64,
    hashFunction: createSHA256(),
    outputType: 'hex',
  });
  assert.equal(derivedHex.length, 128);

  const derivedBin = await pbkdf2({
    password: 'password',
    salt: new Uint8Array([1, 2, 3, 4]),
    iterations: 2,
    hashLength: 64,
    hashFunction: createSHA256(),
    outputType: 'binary',
  });
  assert.ok(derivedBin instanceof Uint8Array);
  assert.equal(derivedBin.length, 64);
});

test('HMAC long keys, save/load rejection and validations', async () => {
  assert.throws(() => createHMAC(null, 'key'), /Invalid hash function is provided/);

  await assert.rejects(async () => {
    await createHMAC(createMD4(), 'key');
  }, /HMAC-MD4 is not supported/);

  // Key longer than blockSize (SHA-256 block size is 64 bytes)
  const longKey = new Uint8Array(100).fill(0x5a);
  const hmacLong = await createHMAC(createSHA256(), longKey);
  hmacLong.update('hello');
  const dHex = hmacLong.digest('hex');
  assert.match(dHex, /^[0-9a-f]{64}$/);

  // Digest binary
  const hmacBin = await createHMAC(createSHA256(), 'shortKey');
  hmacBin.update('world');
  const dBin = hmacBin.digest('binary');
  assert.ok(dBin instanceof Uint8Array);
  assert.equal(dBin.length, 32);

  // Unsupported save and load
  assert.throws(() => hmacBin.save(), /save\(\) not supported/);
  assert.throws(() => hmacBin.load(), /load\(\) not supported/);
});

test('BIP-39 parameter error checking', async () => {
  await assert.rejects(() => entropyToMnemonic(new Uint8Array(10)), /Entropy length must be between 16 and 32/);
  await assert.rejects(() => entropyToMnemonic(new Uint8Array(16), ['only_one_word']), /BIP-39 requires exactly 2048 unique/);
  await assert.rejects(() => generateMnemonic(100), /Mnemonic strength must be 128 or 256/);
});

test('AES-KW parameter error checking', async () => {
  const kek16 = new Uint8Array(16);
  await assert.rejects(() => aesKeyWrap(new Uint8Array(10), new Uint8Array(16)), /AES-KW KEK must contain 16, 24 or 32 bytes/);
  await assert.rejects(() => aesKeyWrap(kek16, new Uint8Array(10)), /Plaintext key length must be a multiple of 8/);
  await assert.rejects(() => aesKeyUnwrap(new Uint8Array(10), new Uint8Array(24)), /AES-KW KEK must contain 16, 24 or 32 bytes/);
  await assert.rejects(() => aesKeyUnwrap(kek16, new Uint8Array(10)), /Wrapped key length must be a multiple of 8/);
});

test('Poseidon input validations and plain string inputs', () => {
  assert.throws(() => poseidonHash([]), /Poseidon requires at least one input element/);
  assert.throws(() => poseidonHash(null), /Poseidon requires at least one input element/);
  assert.throws(() => poseidonHash([true]), /Invalid Poseidon input type/);

  // Plain string input without 0x prefix
  const h = poseidonHash(['hello', 'world', 12345, 67890n]);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test('Shamir secret sharing bounds checking', () => {
  assert.throws(() => shamirSplit('secret', 1, 2), /Parts must be >= threshold/);
  assert.throws(() => shamirSplit('secret', 5, 1), /Threshold must be >= 2/);
  assert.throws(() => shamirSplit('secret', 300, 3), /Maximum 255 parts/);
});

test('Util functions edge cases', () => {
  // getUInt8Buffer invalid type
  assert.throws(() => getUInt8Buffer(12345), /Invalid data type/);

  // hexStringEqualsUInt8 mismatch length
  assert.equal(hexStringEqualsUInt8('123', new Uint8Array(2)), false);

  // Base64 encoding pad variations
  const b1 = encodeBase64(new Uint8Array([1]));
  assert.ok(b1.endsWith('=='));
  const b1NoPad = encodeBase64(new Uint8Array([1]), false);
  assert.ok(!b1NoPad.endsWith('='));

  const b2 = encodeBase64(new Uint8Array([1, 2]));
  assert.ok(b2.endsWith('='));
  const b2NoPad = encodeBase64(new Uint8Array([1, 2]), false);
  assert.ok(!b2NoPad.endsWith('='));

  // Base64 decoding
  assert.deepEqual(decodeBase64(b1), new Uint8Array([1]));
  assert.deepEqual(decodeBase64(b2), new Uint8Array([1, 2]));

  // timingSafeEqualString
  assert.equal(timingSafeEqualString('abc', 'abc'), true);
  assert.equal(timingSafeEqualString('abc', 'abd'), false);
  assert.equal(timingSafeEqualString('abc', 'abcd'), false);

  // writeHexToUInt8
  const target = new Uint8Array(2);
  writeHexToUInt8(target, '0102');
  assert.deepEqual(target, new Uint8Array([1, 2]));
});

test('Algorithm parameter validation error branches', async () => {
  // CRC-32
  await assert.rejects(() => crc32('test', -1), /Polynomial must be a valid 32-bit/);
  await assert.rejects(() => createCRC32(-1), /Polynomial must be a valid 32-bit/);

  // CRC-64
  await assert.rejects(() => crc64('test', 'short'), /Polynomial must be provided as a 16 char/);
  await assert.rejects(() => crc64('test', 'zzzzzzzzzzzzzzzz'), /Polynomial must be provided as a 16 char/);
  await assert.rejects(() => createCRC64('short'), /Polynomial must be provided as a 16 char/);

  // Keccak & SHA-3
  await assert.rejects(() => keccak('test', 123), /Invalid variant/);
  await assert.rejects(() => createKeccak(123), /Invalid variant/);
  await assert.rejects(() => sha3('test', 123), /Invalid variant/);
  await assert.rejects(() => createSHA3(123), /Invalid variant/);

  // xxHash32
  await assert.rejects(() => xxhash32('test', -1), /Seed must be a valid 32-bit/);
  await assert.rejects(() => createXXHash32(-1), /Seed must be a valid 32-bit/);

  // xxHash64, xxHash3, xxHash128
  await assert.rejects(() => xxhash64('test', -1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => xxhash64('test', 0, -1), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash64(-1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash64(0, -1), /Seed must be given as two valid 32-bit/);

  await assert.rejects(() => xxhash3('test', -1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => xxhash3('test', 0, -1), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash3(-1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash3(0, -1), /Seed must be given as two valid 32-bit/);

  await assert.rejects(() => xxhash128('test', -1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => xxhash128('test', 0, -1), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash128(-1, 0), /Seed must be given as two valid 32-bit/);
  await assert.rejects(() => createXXHash128(0, -1), /Seed must be given as two valid 32-bit/);

  // BLAKE family with keyed hashing and invalid parameters
  await assert.rejects(() => blake2b('test', 512, new Uint8Array(100)), /Max key length is 64 bytes/);
  await assert.rejects(() => createBLAKE2b(999), /Invalid variant/);
  await assert.rejects(() => createBLAKE2b(512, new Uint8Array(100)), /Max key length is 64 bytes/);
  const b2bKeyed = await blake2b('test', 512, 'my-key');
  assert.match(b2bKeyed, /^[0-9a-f]{128}$/);
  const b2bHasher = await createBLAKE2b(512, 'my-key');
  b2bHasher.init().update('test');
  assert.equal(b2bHasher.digest('hex'), b2bKeyed);

  await assert.rejects(() => blake2s('test', 256, new Uint8Array(50)), /Max key length is 32 bytes/);
  await assert.rejects(() => createBLAKE2s(999), /Invalid variant/);
  await assert.rejects(() => createBLAKE2s(256, new Uint8Array(50)), /Max key length is 32 bytes/);
  const b2sKeyed = await blake2s('test', 256, 'my-key');
  assert.match(b2sKeyed, /^[0-9a-f]{64}$/);
  // Re-run with different output size to trigger lockedCreate with key
  const b2sKeyed128 = await blake2s('test', 128, 'my-key');
  assert.match(b2sKeyed128, /^[0-9a-f]{32}$/);
  const b2sHasher = await createBLAKE2s(256, 'my-key');
  b2sHasher.init().update('test');
  assert.equal(b2sHasher.digest('hex'), b2sKeyed);

  await assert.rejects(() => blake3('test', 256, 'bad_key'), /Key length must be exactly 32 bytes/);
  await assert.rejects(() => createBLAKE3(256, 'bad_key'), /Key length must be exactly 32 bytes/);
  await assert.rejects(() => blake3('test', 999), /Invalid variant/);
  await assert.rejects(() => createBLAKE3(999), /Invalid variant/);
  const b3Key = new Uint8Array(32).fill(0x33);
  const b3Keyed = await blake3('test', 256, b3Key);
  assert.match(b3Keyed, /^[0-9a-f]{64}$/);
  // Re-run with different output size to trigger lockedCreate with key
  const b3Keyed128 = await blake3('test', 128, b3Key);
  assert.match(b3Keyed128, /^[0-9a-f]{32}$/);
  const b3Hasher = await createBLAKE3(256, b3Key);
  b3Hasher.init().update('test');
  assert.equal(b3Hasher.digest('hex'), b3Keyed);
});

test('Argon2 partialBytesNeeded, default outputType, and unsupported version', async () => {
  // hashLength 100 exercises partialBytesNeeded branch (len > 64 and len % 32 !== 0)
  const nonAligned = await argon2i({
    password: 'password',
    salt: 'salt12345678',
    iterations: 1,
    parallelism: 1,
    memorySize: 64,
    hashLength: 100,
  });
  assert.equal(nonAligned.length, 200);

  // Default outputType is hex
  const defaultOut = await argon2i({
    password: 'password',
    salt: 'salt12345678',
    iterations: 1,
    parallelism: 1,
    memorySize: 64,
    hashLength: 32,
    outputType: undefined,
  });
  assert.match(defaultOut, /^[0-9a-f]{64}$/);

  // Empty Uint8Array password
  await assert.rejects(() => argon2i({
    password: new Uint8Array(0),
    salt: 'salt12345678',
    iterations: 1,
    parallelism: 1,
    memorySize: 64,
    hashLength: 32,
  }), /Password must be specified/);

  // Unsupported version in argon2Verify
  await assert.rejects(() => argon2Verify({
    hash: '$argon2id$v=18$m=64,t=1,p=1$c2FsdDEyMzQ1Njc4$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    password: 'password',
  }), /Unsupported version: 18/);
});

test('Bcrypt, Scrypt, PBKDF2 default outputType', async () => {
  const bc = await bcrypt({
    password: 'pw',
    salt: new Uint8Array(16).fill(1),
    costFactor: 4,
    outputType: undefined,
  });
  assert.ok(typeof bc === 'string');
  assert.ok(bc.startsWith('$2'));

  const sc = await scrypt({
    password: 'pw',
    salt: 'salt1234',
    costFactor: 16,
    blockSize: 8,
    parallelism: 1,
    hashLength: 32,
    outputType: undefined,
  });
  assert.match(sc, /^[0-9a-f]{64}$/);

  const pb = await pbkdf2({
    password: 'pw',
    salt: 'salt',
    iterations: 1,
    hashLength: 32,
    hashFunction: createSHA256(),
    outputType: undefined,
  });
  assert.match(pb, /^[0-9a-f]{64}$/);
});

test('Poseidon 0x hex string and environment fallbacks', async () => {
  // Poseidon with 0x prefix
  const hHex = poseidonHash(['0x42', 100, 200n]);
  assert.match(hHex, /^[0-9a-f]{64}$/);

  // Missing getRandomValues error path
  const origGetRandomValues = globalThis.crypto.getRandomValues;
  try {
    Object.defineProperty(globalThis.crypto, 'getRandomValues', { value: undefined, configurable: true });
    await assert.rejects(() => generateMnemonic(128), /Cryptographically secure random number generator/);
    assert.throws(() => shamirSplit('secret', 3, 2), /Cryptographically secure random number generator/);
  } finally {
    Object.defineProperty(globalThis.crypto, 'getRandomValues', { value: origGetRandomValues, configurable: true });
  }

  // WebAssembly missing error path
  const origWA = globalThis.WebAssembly;
  try {
    Object.defineProperty(globalThis, 'WebAssembly', { value: undefined, configurable: true });
    const { WASMInterface } = await import('../dist/lib/WASMInterface.js');
    await assert.rejects(() => WASMInterface({}, 32), /WebAssembly is not supported/);
  } finally {
    Object.defineProperty(globalThis, 'WebAssembly', { value: origWA, configurable: true });
  }

  // Object.create null fallback during CommonJS module binding
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const resolved = require.resolve('../dist/lib/index.js');
  delete require.cache[resolved];
  const origCreate = Object.create;
  try {
    Object.create = null;
    require('../dist/lib/index.js');
  } finally {
    Object.create = origCreate;
  }

  // RSASSA-PSS and RSASSA-PKCS1 verification in verifyRsaSignatureBase64
  const nodeCrypto = (await import('node:crypto')).default;
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  const sampleData = new Uint8Array([1, 2, 3, 4]);
  // PSS
  const sigPss = nodeCrypto.sign('sha256', Buffer.from(sampleData), {
    key: privateKey,
    padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString('base64');
  assert.equal(await verifyRsaSignatureBase64(sampleData, sigPss, publicKey, 'pss'), true);
  // PKCS1
  const sigPkcs1 = nodeCrypto.sign('sha256', Buffer.from(sampleData), privateKey).toString('base64');
  assert.equal(await verifyRsaSignatureBase64(sampleData, sigPkcs1, publicKey, 'pkcs1'), true);
});

