# wasm-crypto-hash

[![npm package](https://img.shields.io/npm/v/wasm-crypto-hash.svg)](http://npmjs.org/package/wasm-crypto-hash)
[![Bundle size](https://badgen.net/bundlephobia/minzip/wasm-crypto-hash)](https://bundlephobia.com/result?p=wasm-crypto-hash)
[![codecov](https://codecov.io/gh/takaodev/wasm-crypto-hash/branch/master/graph/badge.svg)](https://codecov.io/gh/takaodev/wasm-crypto-hash)
[![Build status](https://github.com/takaodev/wasm-crypto-hash/workflows/Build%20%26%20publish/badge.svg?branch=master)](https://github.com/takaodev/wasm-crypto-hash/actions)
[![JSDelivr downloads](https://data.jsdelivr.com/v1/package/npm/wasm-crypto-hash/badge)](https://www.jsdelivr.com/package/npm/wasm-crypto-hash)

Wasm Crypto Hash is a standalone WebAssembly-based cryptographic hash and checksum utility package for browsers and Node.js.
It uses hand-tuned WebAssembly binaries to calculate cryptographic digests quickly.
Inspired by [hash-wasm](https://github.com/Daninet/hash-wasm) and the same practical, small-bundle philosophy.

# Supported algorithms

| Name                                           | Bundle size (gzipped) |
| ---------------------------------------------- | --------------------- |
| Adler-32                                       | 3 kB                  |
| Argon2: Argon2d, Argon2i, Argon2id (v1.3)      | 11 kB                 |
| bcrypt                                         | 11 kB                 |
| BLAKE2b                                        | 6 kB                  |
| BLAKE2s                                        | 5 kB                  |
| BLAKE3                                         | 9 kB                  |
| CRC32                                          | 3 kB                  |
| CRC64                                          | 4 kB                  |
| HMAC                                           | -                     |
| MD4                                            | 4 kB                  |
| MD5 (legacy / insecure)                        | 4 kB                  |
| PBKDF2                                         | -                     |
| RIPEMD-160 (legacy / compatibility)            | 5 kB                  |
| scrypt                                         | 10 kB                 |
| SHA-1 (legacy / insecure)                      | 5 kB                  |
| SHA-2: SHA-224, SHA-256                        | 7 kB                  |
| SHA-2: SHA-384, SHA-512                        | 8 kB                  |
| SHA-3: SHA3-224, SHA3-256, SHA3-384, SHA3-512  | 4 kB                  |
| Keccak-224, Keccak-256, Keccak-384, Keccak-512 | 4 kB                  |
| SM3                                            | 4 kB                  |
| xxHash32                                       | 3 kB                  |
| xxHash64                                       | 4 kB                  |
| xxHash3                                        | 7 kB                  |
| xxHash128                                      | 8 kB                  |

# Features

- A lot faster than other JS / WASM implementations (see [benchmarks](#benchmark) below)
- It's lightweight. See the table above
- Compiled from heavily optimized algorithms written in C
- Supports all modern browsers, Node.js and Deno
- Supports large data streams
- Supports UTF-8 strings and typed arrays
- Supports chunked input streams
- Modular architecture (the algorithms are compiled into individual WASM binaries)
- WASM modules are bundled as base64 strings (no problems with linking)
- Supports tree shaking (Webpack only bundles the hash algorithms you use)
- Works without Webpack or other bundlers
- Includes TypeScript type definitions
- Works in Web Workers
- Zero dependencies
- Supports concurrent hash calculations with multiple states
- Supports saving and loading the internal state of the hash (segmented hashing and rewinding)
- [Unit tests](https://github.com/takaodev/wasm-crypto-hash/tree/master/test) for all algorithms
- 100% open source & transparent [build process](https://github.com/takaodev/wasm-crypto-hash/actions)
- Easy to use, Promise-based API

## Algorithm guidance

For new designs, prefer the modern primitives that are already available in this library:

- HMAC-SHA256 or HMAC-SHA512 for message authentication
- PBKDF2 with SHA-256 or SHA-512 for key derivation

Legacy or compatibility-only algorithms should stay available, but be treated as insecure or niche:

- MD4, MD5, and SHA-1 are kept for compatibility and checksum-style use cases, not for new security-sensitive designs
- RIPEMD-160 is kept for ecosystem compatibility, including legacy constructions such as PBKDF2-RIPEMD-160
- HMAC-MD5 and PBKDF2-RIPEMD-160 are compatibility-only combinations and should not be used for new applications
- HMAC-MD4 is rejected at runtime and should not be used for new or compatibility-sensitive code
_\* See [String encoding pitfalls](#string-encoding-pitfalls)_
import { createHMAC, createSHA3 } from "wasm-crypto-hash";
### Advanced usage with streaming input

The recommended process for choosing the parameters can be found here: https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4

# Installation

```
npm i wasm-crypto-hash
```

It can also be used directly from HTML via jsDelivr:

```html
<!-- load all algorithms into the global `wasmCryptoHash` variable -->
<script src="https://cdn.jsdelivr.net/npm/wasm-crypto-hash@4"></script>

<!-- load individual algorithms into the global `wasmCryptoHash` variable -->
<script src="https://cdn.jsdelivr.net/npm/wasm-crypto-hash@4/dist/md5.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/wasm-crypto-hash@4/dist/hmac.umd.min.js"></script>
```

# Examples

### Usage with the shorthand form

It is the easiest and the fastest way to calculate hashes. Use it when the input buffer is already in memory.

```javascript
import { md5, sha1, sha512, sha3 } from "wasm-crypto-hash";

async function run() {
  console.log("MD5:", await md5("demo"));

  const int8Buffer = new Uint8Array([0, 1, 2, 3]);
  console.log("SHA1:", await sha1(int8Buffer));
  console.log("SHA512:", await sha512(int8Buffer));

  const int32Buffer = new Uint32Array([1056, 641]);
Wasm Digest is a standalone WebAssembly-based digest and checksum utility package for browsers and Node.js.
It ships optimized WebAssembly binaries for fast hashing without relying on the previous package naming.

run();
```

_


_
async function run() {
  const salt = new Uint8Array(16);

### Advanced usage with streaming input

createXXXX() functions create new WASM instances with separate states, which can be used to calculate multiple hashes in parallel. They are slower compared to shorthand functions like md5(), which reuse the same WASM instance and state to do multiple calculations. For this reason, the shorthand form is always preferred when the input is already in memory.

For the best performance, avoid calling createXXXX() functions in loops. When calculating multiple hashes sequentially, the init() function can be used to reset the internal state between runs. It is faster than creating new instances with createXXXX().

```javascript
import { createSHA1 } from "wasm-crypto-hash";

async function run() {
  const sha1 = await createSHA1();
  sha1.init();

  while (hasMoreData()) {
    const chunk = readChunk();
    sha1.update(chunk);
  }

  const hash = sha1.digest("binary");
  console.log("SHA1:", hash);
}

run();
```

_
  window.crypto.getRandomValues(salt);

_

  const key = await argon2id({

### Hashing passwords with Argon2
    password: "pass",
    iterations: 256,
    memorySize: 512, // use 512KB memory
    hashLength: 32, // output size = 32 bytes
    outputType: "encoded", // return standard encoded string containing parameters needed to verify the key
  });

  console.log("Derived key:", key);

  const isValid = await argon2Verify({
    password: "pass",
    hash: key,
  });

  console.log(isValid ? "Valid password" : "Invalid password");
}

run();
```

_\* See [String encoding pitfalls](#string-encoding-pitfalls)_

_\*\* See [API reference](#api)_

### Hashing passwords with bcrypt

```javascript
import { bcrypt, bcryptVerify } from "wasm-crypto-hash";

async function run() {
  const salt = new Uint8Array(16);
  window.crypto.getRandomValues(salt);

  const key = await bcrypt({
    password: "pass",
    salt, // salt is a buffer containing 16 random bytes
    costFactor: 11,
    outputType: "encoded", // return standard encoded string containing parameters needed to verify the key
  });

  console.log("Derived key:", key);

  const isValid = await bcryptVerify({
    password: "pass",
    hash: key,
  });

  console.log(isValid ? "Valid password" : "Invalid password");
}

run();
```

_\* See [String encoding pitfalls](#string-encoding-pitfalls)_

_\*\* See [API reference](#api)_

### Calculating HMAC

All supported hash functions can be used to calculate HMAC. For the best performance, avoid calling createXXXX() in loops (see `Advanced usage with streaming input` section above)

HMAC-MD4 is not supported in this library and will throw at runtime.

```javascript
import { createHMAC, createSHA3 } from "wasm-crypto-hash";

async function run() {
  const hashFunc = createSHA3(224); // SHA3-224
  const hmac = await createHMAC(hashFunc, "key");

  const fruits = ["apple", "raspberry", "watermelon"];
  console.log("Input:", fruits);

  const codes = fruits.map((data) => {
    hmac.init();
    hmac.update(data);
    return hmac.digest();
  });

  console.log("HMAC:", codes);
}

run();
```

_\* See [String encoding pitfalls](#string-encoding-pitfalls)_

_\*\* See [API reference](#api)_

### Calculating PBKDF2

All supported hash functions can be used to calculate PBKDF2. For the best performance, avoid calling createXXXX() in loops (see `Advanced usage with streaming input` section above)

Prefer PBKDF2 with SHA-256 or SHA-512 for new applications. PBKDF2-RIPEMD-160 is legacy-only and should be reserved for compatibility with existing systems.

```javascript
import { pbkdf2, createSHA1 } from "wasm-crypto-hash";

async function run() {
  const salt = new Uint8Array(16);
  window.crypto.getRandomValues(salt);

  const key = await pbkdf2({
    password: "password",
    salt,
    iterations: 1000,
    hashLength: 32,
    hashFunction: createSHA1(),
    outputType: "hex",
  });

  console.log("Derived key:", key);
}

run();
```

_\* See [String encoding pitfalls](#string-encoding-pitfalls)_

_\*\* See [API reference](#api)_

### String encoding pitfalls

You should be aware that there may be multiple UTF-8 representations of a given string:

```js
npm i wasm-crypto-hash
"u\u0308"; // also encodes the ü character

"\u00fc" === "u\u0308"; // false
"ü" === "ü"; // false
```

All algorithms defined in this library depend on the binary representation of the input string. Thus, it's highly recommended to normalize your strings before passing it to hash-wasm. You can use the `normalize()` built-in String function to archive this:

```js
"\u00fc".normalize() === "u\u0308".normalize(); // true

const te = new TextEncoder();
te.encode("u\u0308"); // Uint8Array(3) [117, 204, 136]
te.encode("\u00fc"); // Uint8Array(2) [195, 188]

te.encode("u\u0308".normalize("NFKC")); // Uint8Array(2) [195, 188]
te.encode("\u00fc".normalize("NFKC")); // Uint8Array(2) [195, 188]
```

You can read more about this issue here: https://en.wikipedia.org/wiki/Unicode_equivalence

### Resumable hashing

You can save the current internal state of the hash using the `.save()` function. This state may be written to disk or stored elsewhere in memory.
You can then use the `.load(state)` function to reload that state into a new instance of the hash, or back into the same instance.

This allows you to span the work of hashing a file across multiple processes (e.g. in environments with limited execution times like AWS Lambda, where large jobs need to be split across multiple invocations), or rewind the hash to an earlier point in the stream. For example, the first process could:

```js
// first process starts hashing
const md5 = await createMD5();
md5.init();
md5.update("Hello, ");
const state = md5.save(); // save this state

// second process resumes hashing from the stored state
const md5 = await createMD5();
md5.load(state);
md5.update("world!");
console.log(md5.digest()); // Prints 6cd3556deb0da54bca060b4c39479839 = md5("Hello, world!")
```

_Note that both the saving and loading processes must be running compatible versions of the hash function (i.e. the hash function hasn't changed between the versions of hash-wasm used in the saving and loading processes). If the saved state is incompatible, `load()` will throw an exception._

_The saved state can contain information about the input, including plaintext input bytes, so from a security perspective it must be treated with the same care as the input data itself._

<br/>

# Browser support

<br/>

| Chrome | Safari | Firefox | Edge | IE            | Node.js | Deno |
| ------ | ------ | ------- | ---- | ------------- | ------- | ---- |
| 57+    | 11+    | 53+     | 16+  | Not supported | 8+      | 1+   |

<br/>

# Benchmark

You can make your own measurements here: [link](https://daninet.github.io/hash-wasm-benchmark/)

Two scenarios were measured:

- throughput with the short form (input size = 32 bytes)
- throughput with the short form (input size = 1MB)

Results:

| MD5                         | throughput (32 bytes) | throughput (1MB) |
| --------------------------- | --------------------- | ---------------- |
| **hash-wasm 4.10.0**        | **110.52 MB/s**       | **850.31 MB/s**  |
| spark-md5 3.0.2 (from npm)  | 38.87 MB/s            | 171.73 MB/s      |
| md5-wasm 2.0.0 (from npm)   | 37.36 MB/s            | 131.77 MB/s      |
| crypto-js 4.1.1 (from npm)  | 9.30 MB/s             | 46.71 MB/s       |
| node-forge 1.3.1 (from npm) | 18.23 MB/s            | 28.94 MB/s       |
| md5 2.3.0 (from npm)        | 14.50 MB/s            | 21.65 MB/s       |

#

| SHA1                        | throughput (32 bytes) | throughput (1MB) |
| --------------------------- | --------------------- | ---------------- |
| **hash-wasm 4.10.0**        | **83.80 MB/s**        | **798.19 MB/s**  |
| jsSHA 3.3.1 (from npm)      | 34.93 MB/s            | 78.12 MB/s       |
| crypto-js 4.1.1 (from npm)  | 9.50 MB/s             | 69.02 MB/s       |
| node-forge 1.3.1 (from npm) | 17.02 MB/s            | 32.00 MB/s       |
| sha1 1.1.1 (from npm)       | 14.68 MB/s            | 24.24 MB/s       |

#

| SHA256                        | throughput (32 bytes) | throughput (1MB) |
| ----------------------------- | --------------------- | ---------------- |
| **hash-wasm 4.10.0**          | **63.99 MB/s**        | **426.16 MB/s**  |
| sha256-wasm 2.2.2 (from npm)  | 20.37 MB/s            | 308.39 MB/s      |
| noble-hashes 1.3.2 (from npm) | 24.73 MB/s            | 110.02 MB/s      |
| crypto-js 4.1.1 (from npm)    | 8.99 MB/s             | 65.17 MB/s       |
| jsSHA 3.3.1 (from npm)        | 25.64 MB/s            | 57.98 MB/s       |
| node-forge 1.3.1 (from npm)   | 13.93 MB/s            | 28.19 MB/s       |

#

## CI: Signing and Secrets

## Signing artifact encoding and canonicalization

When producing signed `.wasm.json` artifacts for distribution, follow these encoding and canonicalization rules to ensure cross-environment interoperability:

- Canonical signing object key order: `name`, `data`, `hash`, `hmac`, `sig_algo`. The signing and verification code expects these fields to be present and treated as literal UTF-8 values when canonicalizing bytes for signature.
- Use standard Base64 (RFC 4648 "base64" with `=` padding) for all Base64-encoded fields such as `hmac` and `sig`. Do NOT use URL-safe Base64 or omit padding for artifacts that will be signed/verified by the tools in this repository.
- If you must accept URL-safe Base64 input, normalize it before decoding: replace `-` with `+`, `_` with `/`, then restore padding to make the length a multiple of 4 by appending `=` characters.
- `hash` MUST be the lowercase hex-encoded SHA-256 digest (64 hex characters) of the raw WASM bytes.
- `data` (if present) is a UTF-8 string identifier (e.g., filename) and must be included verbatim when canonicalizing.

Example canonical JSON used for signing:

```
{
  "name": "example.wasm",
  "data": "static/example.wasm",
  "hash": "<lowercase-sha256-hex>",
  "hmac": "<base64-with-padding>",
  "sig_algo": "pss"
}
```

Verification notes:

- `sig` is the signature encoded as standard Base64 of the raw RSA signature bytes. Verification code expects the public key as a PEM-format string (SPKI/PKCS#8 compatible). For `pss` verification with WebCrypto, set `saltLength` equal to the hash output length (32 for SHA-256).
- HMACs are HMAC-SHA256 and encoded as standard Base64 with padding. Implementations must compare HMAC strings in constant time (for example using `timingSafeEqualString`).

日本語（簡潔）:

- 署名・検証に使う `.wasm.json` のフィールドは次のキー順で正規化してください: `name`, `data`, `hash`, `hmac`, `sig_algo`。
- `hmac` / `sig` は標準 Base64（RFC 4648、`=` パディングあり）を使用してください。URL セーフ Base64 を受け入れる場合は、`-`→`+`、`_`→`/`、およびパディング復元を行ってください。
- `hash` は生の WASM バイト列の SHA-256 を小文字 hex（64 文字）で表記します。
- `pss`（RSASSA-PSS）を既定とすることを推奨します。WebCrypto で検証する場合は `saltLength` をハッシュ長（SHA-256 なら 32）に設定してください。

This repository includes a CI job that builds the WASM artifacts and optionally signs them. The CI expects the following GitHub Secrets to be configured for full end-to-end signing and verification:

- `WASM_HMAC_KEY` — base64 encoded HMAC key used by `make_json.js` when generating `.wasm.json` (optional depending on your pipeline).
- `WASM_SIG_PRIV_PEM` — RSA private key (PEM, single-line newlines allowed) used by `scripts/sign_wasm.js` to sign artifacts in CI.
- `WASM_SIG_PUBKEY` — RSA public key (PEM) used by test runners and Workers to verify signatures.

By default the CI workflow sets `WASM_SIG_ALGO=pss` and will produce RSASSA-PSS signatures. If you must use legacy PKCS#1 v1.5, set `WASM_SIG_ALGO=pkcs1` in your workflow or Secrets.

Example OpenSSL commands to generate a 2048-bit RSA keypair suitable for RSASSA-PSS:

```bash
# generate private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out wasm-sign-priv.pem

# extract public key (SPKI PEM)
openssl pkey -in wasm-sign-priv.pem -pubout -out wasm-sign-pub.pem

# optional: convert public key to a single-line base64-free PEM for storing in some secret UIs
cat wasm-sign-pub.pem
```

Add the contents of `wasm-sign-priv.pem` to the `WASM_SIG_PRIV_PEM` secret, and `wasm-sign-pub.pem` to `WASM_SIG_PUBKEY`.

CI workflow notes:
- The workflow `.github/workflows/e2e-selfsign.yml` provides a secrets-free end-to-end signature verification job. You can also run `scripts/sign_wasm_kms_sdk.js` in CI when KMS credentials are available.
- The `scripts/sign_wasm.js` script now emits a `sig_algo` field into the generated `.wasm.json` so clients know which verification algorithm to use.


| SHA3-512                      | throughput (32 bytes) | throughput (1MB) |
| ----------------------------- | --------------------- | ---------------- |
| **hash-wasm 4.10.0**          | **38.06 MB/s**        | **234.40 MB/s**  |
| sha3-wasm 1.0.0 (from npm)    | 15.44 MB/s            | 101.51 MB/s      |
| noble-hashes 1.3.2 (from npm) | 5.74 MB/s             | 14.19 MB/s       |
| sha3 2.1.4 (from npm)         | 3.80 MB/s             | 10.73 MB/s       |
| jsSHA 3.2.0 (from npm)        | 2.08 MB/s             | 3.82 MB/s        |

#

| XXHash64                     | throughput (32 bytes) | throughput (1MB)   |
| ---------------------------- | --------------------- | ------------------ |
| **hash-wasm 4.10.0**         | **101.66 MB/s**       | **15 989 MB/s** |
| xxhash-wasm 1.0.2 (from npm) | 47.58 MB/s            | 15 929 MB/s     |
| xxhashjs 0.2.2 (from npm)    | 0.92 MB/s             | 42.26 MB/s         |

#

| PBKDF2-SHA512 - 1000 iterations | operations per second (16 bytes) |
| ------------------------------- | -------------------------------- |
| **hash-wasm 4.10.0**            | **588 ops**                      |
| noble-hashes 1.3.2 (from npm)   | 395 ops                          |
| pbkdf2 3.1.2 (from npm)         | 83 ops                           |
| crypto-js 4.1.1 (from npm)      | 29 ops                           |

#

| Argon2id (m=512, t=8, p=1)       | operations per second (16 bytes) |
| -------------------------------- | -------------------------------- |
| **hash-wasm 4.10.0**             | **438 ops**                      |
| argon2-browser 1.18.0 (from npm) | 213 ops                          |
| argon2-wasm-pro 1.1.0 (from npm) | 203 ops                          |
| argon2-wasm 0.9.0 (from npm)     | 195 ops                          |

<br/>

\* These measurements were made with `Chrome v131` on a Ryzen 9 7900X desktop CPU.

# API

```ts
type IDataType = string | Buffer | Uint8Array | Uint16Array | Uint32Array;

// all functions return hash in hex format
adler32(data: IDataType): Promise<string>
blake2b(data: IDataType, bits?: number, key?: IDataType): Promise<string> // default is 512 bits
blake2s(data: IDataType, bits?: number, key?: IDataType): Promise<string> // default is 256 bits
blake3(data: IDataType, bits?: number, key?: IDataType): Promise<string> // default is 256 bits
crc32(data: IDataType, polynomial?: number): Promise<string> // default polynomial is 0xedb88320, for CRC32C use 0x82f63b78
crc64(data: IDataType, polynomial?: string): Promise<string> // default polynomial is 'c96c5795d7870f42' (ECMA)
keccak(data: IDataType, bits?: 224 | 256 | 384 | 512): Promise<string> // default is 512 bits
md4(data: IDataType): Promise<string>
md5(data: IDataType): Promise<string>
ripemd160(data: IDataType): Promise<string>
sha1(data: IDataType): Promise<string>
sha224(data: IDataType): Promise<string>
sha256(data: IDataType): Promise<string>
sha3(data: IDataType, bits?: 224 | 256 | 384 | 512): Promise<string> // default is 512 bits
sha384(data: IDataType): Promise<string>
sha512(data: IDataType): Promise<string>
sm3(data: IDataType): Promise<string>
xxhash32(data: IDataType, seed?: number): Promise<string>
xxhash64(data: IDataType, seedLow?: number, seedHigh?: number): Promise<string>
xxhash3(data: IDataType, seedLow?: number, seedHigh?: number): Promise<string>
xxhash128(data: IDataType, seedLow?: number, seedHigh?: number): Promise<string>

interface IHasher {
  init: () => IHasher;
  update: (data: IDataType) => IHasher;
  digest: (outputType: 'hex' | 'binary') => string | Uint8Array; // by default returns hex string
  save: () => Uint8Array; // returns the internal state for later resumption
  load: (state: Uint8Array) => IHasher; // loads a previously saved internal state
  blockSize: number; // in bytes
  digestSize: number; // in bytes
}

createAdler32(): Promise<IHasher>
createBLAKE2b(bits?: number, key?: IDataType): Promise<IHasher> // default is 512 bits
createBLAKE2s(bits?: number, key?: IDataType): Promise<IHasher> // default is 256 bits
createBLAKE3(bits?: number, key?: IDataType): Promise<IHasher> // default is 256 bits
createCRC32(polynomial?: number): Promise<IHasher> // default polynomial is 0xedb88320, for CRC32C use 0x82f63b78
createCRC64(polynomial?: number): Promise<IHasher> // default polynomial is 'c96c5795d7870f42' (ECMA)
createKeccak(bits?: 224 | 256 | 384 | 512): Promise<IHasher> // default is 512 bits
createMD4(): Promise<IHasher>
createMD5(): Promise<IHasher>
createRIPEMD160(): Promise<IHasher>
createSHA1(): Promise<IHasher>
createSHA224(): Promise<IHasher>
createSHA256(): Promise<IHasher>
createSHA3(bits?: 224 | 256 | 384 | 512): Promise<IHasher> // default is 512 bits
createSHA384(): Promise<IHasher>
createSHA512(): Promise<IHasher>
createSM3(): Promise<IHasher>
createXXHash32(seed: number): Promise<IHasher>
createXXHash64(seedLow: number, seedHigh: number): Promise<IHasher>
createXXHash3(seedLow: number, seedHigh: number): Promise<IHasher>
createXXHash128(seedLow: number, seedHigh: number): Promise<IHasher>

createHMAC(hashFunction: Promise<IHasher>, key: IDataType): Promise<IHasher>

pbkdf2({
  password: IDataType, // password (or message) to be hashed
  salt: IDataType, // salt (usually containing random bytes)
  iterations: number, // number of iterations to perform
  hashLength: number, // output size in bytes
  hashFunction: Promise<IHasher>, // the return value of a function like createSHA1()
  outputType?: 'hex' | 'binary', // by default returns hex string
}): Promise<string | Uint8Array>

scrypt({
  password: IDataType, // password (or message) to be hashed
  salt: IDataType, // salt (usually containing random bytes)
  costFactor: number, // CPU/memory cost - must be a power of 2 (e.g. 1024)
  blockSize: number, // block size parameter (8 is commonly used)
  parallelism: number, // degree of parallelism
  hashLength: number, // output size in bytes
  outputType?: 'hex' | 'binary', // by default returns hex string
}): Promise<string | Uint8Array>

interface IArgon2Options {
  password: IDataType; // password (or message) to be hashed
  salt: IDataType; // salt (usually containing random bytes)
  secret?: IDataType; // secret for keyed hashing
  iterations: number; // number of iterations to perform
  parallelism: number; // degree of parallelism
  memorySize: number; // amount of memory to be used in kibibytes (1024 bytes)
  hashLength: number; // output size in bytes
  outputType?: 'hex' | 'binary' | 'encoded'; // by default returns hex string
}

argon2i(options: IArgon2Options): Promise<string | Uint8Array>
argon2d(options: IArgon2Options): Promise<string | Uint8Array>
argon2id(options: IArgon2Options): Promise<string | Uint8Array>

argon2Verify({
  password: IDataType, // password
  secret?: IDataType, // secret used on hash creation
  hash: string, // encoded hash
}): Promise<boolean>

bcrypt({
  password: IDataType, // password
  salt: IDataType, // salt (16 bytes long - usually containing random bytes)
  costFactor: number, // number of iterations to perform (4 - 31)
  outputType?: 'hex' | 'binary' | 'encoded', // by default returns encoded string
}): Promise<string | Uint8Array>

bcryptVerify({
  password: IDataType, // password
  hash: string, // encoded hash
}): Promise<boolean>

```

# Future plans

- Add more well-known algorithms
- Write a polyfill which keeps bundle sizes low and enables running binaries containing newer WASM instructions
- Use WebAssembly Bulk Memory Operations
- Use WebAssembly SIMD instructions (expecting a 10-20% performance increase)
- Enable multithreading where it's possible (like at Argon2)
