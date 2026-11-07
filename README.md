# wasm-crypto-hash

## Security compatibility and migration

- Hash APIs still support the declared base runtimes. **ML-KEM-768 and ML-DSA-65 additionally require native Web Crypto support** (for example Node.js 26). Unsupported Node/browser/Workers runtimes reject; no classical substitution occurs. Native algorithm support does not imply certification or independent review of this package.
- Hybrid keys/ciphertexts use versioned package-specific envelopes combining actual X25519 and ML-KEM-768 secrets through HKDF-SHA256 with a hashed ciphertext transcript. They are not TLS/IETF wire formats. ML-DSA public keys are DER SPKI, private keys DER PKCS#8, and signatures 3309 bytes. Previous classical-only keys/ciphertexts are incompatible: generate new keys and migrate deliberately; do not relabel old material.
- AES-KW requires native Web Crypto and rejects authentication/capability failures. Prior fallback-produced records may expose plaintext keys. Re-wrap only known-trusted original keys and rotate affected keys; untrusted old records cannot be safely auto-recovered.
- BIP39 defaults to the complete official English 2048-word list. Custom dictionaries must have exactly 2048 unique NFKD words. Existing recovery phrases remain inputs to mnemonicToSeed; do not regenerate a phrase to recover existing data. Replace old sample-list phrases through an explicit key/wallet migration.
- The remote WASM loader requires a caller-trusted SHA-256 pin, HMAC/signature, or public key. Pins always cover decoded WASM bytes, including JSON containers. A configured public key requires a signature; requested verification without its key rejects. Detached signatures cover raw bytes; container signatures cover canonical metadata. Embedded module validation runs before cache lookup and cache identity is the content digest.
- Signature keys/pins must come from a trusted channel independent of downloaded metadata. Packaged metadata hashes detect corruption, not a malicious publisher replacing both code and metadata. Signing/KMS configuration is optional and must be configured by the distributor; this repository's artifacts are not all signed by default.


[![npm package](https://img.shields.io/npm/v/wasm-crypto-hash.svg)](https://www.npmjs.com/package/wasm-crypto-hash)
[![CI](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/wasm-crypto-hash/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/wasm-crypto-hash)
[![CodeQL](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Ultra-fast WebAssembly Cryptographic Suite**: 31+ cryptographic hashes, AEAD ciphers, Post-Quantum (PQC) primitives, KDFs, 2FA, and threshold secret sharing for Browsers, Node.js, and Cloudflare Workers (workerd).

`wasm-crypto-hash` combines hand-tuned C WebAssembly binaries and pure TypeScript to deliver industry-leading cryptographic throughput with enterprise-grade supply-chain tamper resistance (AWS/GCP KMS signing).

# Supported algorithms

| Name                                           | Category | Bundle size (gzipped) | Description / Standard |
| ---------------------------------------------- | -------- | --------------------- | ---------------------- |
| Adler-32                                       | Checksum | 2 kB                  | RFC 1950 (WASM)        |
| AES-KW (Key Wrap)                              | Key Wrap | 1 kB                  | RFC 3394 / NIST SP 800-38F |
| Argon2: Argon2d, Argon2i, Argon2id (v1.3)      | KDF / Pwd| 6 kB                  | RFC 9106 (WASM)        |
| Balloon Hashing                                | KDF / Pwd| 1 kB                  | Stanford memory-hard KDF (Boneh et al.) |
| bcrypt                                         | KDF / Pwd| 9 kB                  | OpenBSD Blowfish cipher (WASM) |
| BIP-39 (Mnemonic & Seed)                       | Seed KDF | 2 kB                  | Bitcoin / Web3 standard |
| BLAKE2b / BLAKE2s                              | Hash     | 5 kB / 5 kB           | RFC 7693 (WASM)        |
| BLAKE3                                         | Hash     | 8 kB                  | Tree hash / BA-Tree (WASM) |
| ChaCha20-Poly1305                              | AEAD     | 2 kB                  | RFC 8439 Authenticated Encryption |
| CRC32 / CRC64                                  | Checksum | 2 kB / 2 kB           | ISO 3309 / ECMA 182 (WASM) |
| HMAC                                           | MAC      | 1 kB                  | RFC 2104               |
| Keccak-224 / 256 / 384 / 512                   | Hash     | 3 kB                  | Original Keccak sponge (WASM) |
| KMAC128 / KMAC256                              | MAC      | 1 kB                  | NIST SP 800-185        |
| MD4 / MD5                                      | Legacy   | 3 kB / 3 kB           | RFC 1320 / RFC 1321 (WASM) |
| ML-DSA-65 (Dilithium)                          | PQC Sig  | native runtime                  | NIST FIPS 204 Post-Quantum Signatures |
| ML-KEM-768 + X25519 (Hybrid)                   | PQC KEM  | native runtime                  | Native ML-KEM-768 + X25519; package-specific HKDF envelope |
| MurmurHash3 (32-bit / 128-bit)                 | Fast Hash| 1 kB                  | Austin Appleby Bloom filter suite |
| PBKDF2                                         | KDF      | 1 kB                  | RFC 2898               |
| Poseidon                                       | ZK Hash  | 1 kB                  | BN254 algebraic ZK-SNARK hash |
| RIPEMD-160                                     | Legacy   | 4 kB                  | ISO/IEC 10118-3 (WASM) |
| scrypt                                         | KDF / Pwd| 4 kB                  | RFC 7914 (WASM)        |
| SHA-1                                          | Legacy   | 4 kB                  | RFC 3174 (WASM)        |
| SHA-2: SHA-224, SHA-256, SHA-384, SHA-512      | Hash     | 5 kB - 7 kB           | FIPS PUB 180-4 (WASM)  |
| SHA-3: SHA3-224, SHA3-256, SHA3-384, SHA3-512  | Hash     | 3 kB                  | FIPS PUB 202 (WASM)    |
| SHAKE128 / SHAKE256                            | XOF      | 3 kB                  | FIPS PUB 202 Extendable-Output (WASM) |
| Shamir's Secret Sharing (SSS)                  | Threshold| 2 kB                  | GF(2^8) (k, n) Threshold Secret Sharing |
| SipHash-2-4                                    | PRF Hash | 1 kB                  | RFC 7693 HashDoS-resistant PRF |
| SM3                                            | Hash     | 3 kB                  | GM/T 0004-2012 (WASM)  |
| TOTP / HOTP                                    | 2FA / OTP| 1 kB                  | RFC 6238 / RFC 4226 One-Time Passwords |
| XChaCha20-Poly1305                             | AEAD     | 1 kB                  | Extended 192-bit Nonce AEAD |
| xxHash: xxHash32, xxHash64, xxHash3, xxHash128 | Fast Hash| 2 kB - 7 kB           | Yann Collet xxHash suite (WASM) |

# Advantages over conventional WebAssembly crypto libraries

`wasm-crypto-hash` is an enterprise-grade evolution designed for modern Edge runtimes, supply-chain tamper resistance, and next-generation cryptographic primitives:

1. **Hardware Cryptographic Signing & Tamper Verification (Supply-Chain Defense)**:
   - Conventional WASM libraries run raw WebAssembly bytecode without integrity checks, exposing users to malicious tampering if npm accounts or CDNs are breached.
   - Distributors can configure AWS/GCP KMS signing and supply trusted verification keys. The loader enforces configured SHA-256, RSA signatures and HMAC requirements before instantiation; signing is not enabled for every artifact by default.
2. **Native Cloudflare Workers (workerd) & Edge Integration**:
   - Traditional WebAssembly packages often trigger runtime errors or unhandled promise rejections on Cloudflare Workers due to dynamic code generation restrictions.
   - `wasm-crypto-hash` provides unified `exports` with dedicated `"workerd"` conditional targets, enabling plug-and-play operation across Cloudflare Workers, Pages Functions, Node.js, and modern browsers without configuration.
3. **Remote WASM Verification Loader (`remoteWasmLoader.ts`)**:
   - Built-in support for loading remote WASM modules from CDNs (unpkg, jsdelivr) or cloud storage (Cloudflare R2, AWS S3) with on-the-fly digest and cryptographic signature verification.
4. **Verification comparison behavior**:
   - MAC comparison helpers utilize `timingSafeEqualString` bitwise constant-time comparisons, mathematically neutralizing side-channel timing attacks.
5. **Next-Generation Cryptographic Protocol Suite**:
   - Extends far beyond classical hashes to include **NIST FIPS 203 Post-Quantum Cryptography (ML-KEM-768 Hybrid)**, **RFC 8439 ChaCha20-Poly1305 AEAD**, **NIST SP 800-185 KMAC**, **SHAKE256 XOF**, **Poseidon ZK-SNARK Hash**, **Balloon Hashing**, and **Shamir's Secret Sharing**.
6. **Leak-Free Memory Safety & Zero Audit Vulnerabilities**:
   - Verified with `--expose-gc` heap monitoring to prevent WebAssembly linear memory leaks during high-throughput streaming. Maintained with 0 npm audit security vulnerabilities.

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
- [Unit tests](https://github.com/takao-dev/wasm-crypto-hash/tree/main/test) for all algorithms
- 100% open source & transparent [build process](https://github.com/takao-dev/wasm-crypto-hash/actions)
- Easy to use, Promise-based API

## Algorithm guidance

For new designs, prefer the modern primitives that are already available in this library:

- HMAC-SHA256 or HMAC-SHA512 for message authentication
- PBKDF2 with SHA-256 or SHA-512 for key derivation
- ChaCha20-Poly1305 or XChaCha20-Poly1305 for authenticated encryption (AEAD)
- Argon2id for password hashing
- ML-KEM-768 and ML-DSA-65 for Post-Quantum cryptographic resistance

Legacy or compatibility-only algorithms should stay available, but be treated as insecure or niche:

- MD4, MD5, and SHA-1 are kept for compatibility and checksum-style use cases, not for new security-sensitive designs
- RIPEMD-160 is kept for ecosystem compatibility, including legacy constructions such as PBKDF2-RIPEMD-160
- HMAC-MD5 and PBKDF2-RIPEMD-160 are compatibility-only combinations and should not be used for new applications
- HMAC-MD4 is rejected at runtime and should not be used for new or compatibility-sensitive code

# Installation

```bash
npm install wasm-crypto-hash
```

It can also be used directly from modern browsers (ESM) via CDN:

```html
<script type="module">
  import { sha256, blake3, chacha20Poly1305Encrypt } from "https://esm.sh/wasm-crypto-hash@1";

  console.log("SHA-256:", await sha256("Hello Edge!"));
</script>
```

# Examples

### Usage with the shorthand form

It is the easiest and the fastest way to calculate hashes. Use it when the input buffer is already in memory.

```javascript
import { md5, sha1, sha512, sha3, shake256, kmac256 } from "wasm-crypto-hash";

async function run() {
  console.log("MD5:", await md5("demo"));

  const int8Buffer = new Uint8Array([0, 1, 2, 3]);
  console.log("SHA1:", await sha1(int8Buffer));
  console.log("SHA512:", await sha512(int8Buffer));
  console.log("SHAKE256:", await shake256("Hello Edge", 256));
  console.log("KMAC256:", await kmac256("auth-key", "payload", 256));
}

run();
```

### Usage in Cloudflare Workers (workerd)

`wasm-crypto-hash` has first-class native support for Cloudflare Workers, Pages Functions, and edge runtimes via `"workerd"` conditional exports. No extra bundler plugins or `.wasm` file loaders are required!

```typescript
// worker.ts (Cloudflare Workers with Wrangler)
import { sha256, kmac256, chacha20Poly1305Encrypt } from 'wasm-crypto-hash';

export interface Env {
  API_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const payload = await request.text();

    // 1. Compute cryptographic hash in WASM at the edge
    const digest = await sha256(payload || 'default-input');

    // 2. Compute KMAC256 message authentication with worker secret
    const mac = await kmac256(env.API_SECRET || 'edge-secret-key', payload, 256, 'my-worker');

    return new Response(JSON.stringify({ digest, mac, runtime: 'Cloudflare Workers (workerd)' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
```

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
"u\u0308"; // also encodes the ü character

"\u00fc" === "u\u0308"; // false
"ü" === "ü"; // false
```

All algorithms defined in this library depend on the binary representation of the input string. Thus, it's highly recommended to normalize your strings before passing it to wasm-crypto-hash. You can use the `normalize()` built-in String function to achieve this:

```js
"\u00fc".normalize() === "u\u0308".normalize(); // true

const te = new TextEncoder();
te.encode("u\u0308"); // Uint8Array(3) [117, 204, 136]
te.encode("\u00fc"); // Uint8Array(2) [195, 188]

te.encode("u\u0308".normalize("NFKC")); // Uint8Array(2) [195, 188]
te.encode("\u00fc".normalize("NFKC")); // Uint8Array(2) [195, 188]
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

_Note that both the saving and loading processes must be running compatible versions of the hash function (i.e. the hash function hasn't changed between the versions of wasm-crypto-hash used in the saving and loading processes). If the saved state is incompatible, `load()` will throw an exception._

_The saved state can contain information about the input, including plaintext input bytes, so from a security perspective it must be treated with the same care as the input data itself._

<br/>

# Browser support

<br/>

| Chrome | Safari | Firefox | Edge | IE            | Node.js | Deno |
| ------ | ------ | ------- | ---- | ------------- | ------- | ---- |
| 57+    | 11+    | 53+     | 16+  | Not supported | 18+     | 1+   |

<br/>

# Benchmark

You can reproduce these benchmarks locally using `npm run bench:prod`.

Two scenarios were measured:
- throughput with the short form (input size = 32 bytes)
- throughput with the short form (input size = 1MB)

Results:

| MD5                         | throughput (32 bytes) | throughput (1MB) |
| --------------------------- | --------------------- | ---------------- |
| **wasm-crypto-hash 1.0.0**  | **110.52 MB/s**       | **850.31 MB/s**  |
| spark-md5 3.0.2 (from npm)  | 38.87 MB/s            | 171.73 MB/s      |
| md5-wasm 2.0.0 (from npm)   | 37.36 MB/s            | 131.77 MB/s      |
| crypto-js 4.1.1 (from npm)  | 9.30 MB/s             | 46.71 MB/s       |
| node-forge 1.3.1 (from npm) | 18.23 MB/s            | 28.94 MB/s       |
| md5 2.3.0 (from npm)        | 14.50 MB/s            | 21.65 MB/s       |

#

| SHA1                        | throughput (32 bytes) | throughput (1MB) |
| --------------------------- | --------------------- | ---------------- |
| **wasm-crypto-hash 1.0.0**  | **83.80 MB/s**        | **798.19 MB/s**  |
| jsSHA 3.3.1 (from npm)      | 34.93 MB/s            | 78.12 MB/s       |
| crypto-js 4.1.1 (from npm)  | 9.50 MB/s             | 69.02 MB/s       |
| node-forge 1.3.1 (from npm) | 17.02 MB/s            | 32.00 MB/s       |
| sha1 1.1.1 (from npm)       | 14.68 MB/s            | 24.24 MB/s       |

#

| SHA256                        | throughput (32 bytes) | throughput (1MB) |
| ----------------------------- | --------------------- | ---------------- |
| **wasm-crypto-hash 1.0.0**    | **63.99 MB/s**        | **426.16 MB/s**  |
| sha256-wasm 2.2.2 (from npm)  | 20.37 MB/s            | 308.39 MB/s      |
| noble-hashes 1.3.2 (from npm) | 24.73 MB/s            | 110.02 MB/s      |
| crypto-js 4.1.1 (from npm)    | 8.99 MB/s             | 65.17 MB/s       |
| jsSHA 3.3.1 (from npm)        | 25.64 MB/s            | 57.98 MB/s       |
| node-forge 1.3.1 (from npm)   | 13.93 MB/s            | 28.19 MB/s       |

#

| SHA3-512                      | throughput (32 bytes) | throughput (1MB) |
| ----------------------------- | --------------------- | ---------------- |
| **wasm-crypto-hash 1.0.0**    | **38.06 MB/s**        | **234.40 MB/s**  |
| sha3-wasm 1.0.0 (from npm)    | 15.44 MB/s            | 101.51 MB/s      |
| noble-hashes 1.3.2 (from npm) | 5.74 MB/s             | 14.19 MB/s       |
| sha3 2.1.4 (from npm)         | 3.80 MB/s             | 10.73 MB/s       |
| jsSHA 3.2.0 (from npm)        | 2.08 MB/s             | 3.82 MB/s        |

#

| XXHash64                     | throughput (32 bytes) | throughput (1MB)   |
| ---------------------------- | --------------------- | ------------------ |
| **wasm-crypto-hash 1.0.0**   | **101.66 MB/s**       | **15 989 MB/s**    |
| xxhash-wasm 1.0.2 (from npm) | 47.58 MB/s            | 15 929 MB/s        |
| xxhashjs 0.2.2 (from npm)    | 0.92 MB/s             | 42.26 MB/s         |

#

| PBKDF2-SHA512 - 1000 iterations | operations per second (16 bytes) |
| ------------------------------- | -------------------------------- |
| **wasm-crypto-hash 1.0.0**      | **588 ops**                      |
| noble-hashes 1.3.2 (from npm)   | 395 ops                          |
| pbkdf2 3.1.2 (from npm)         | 83 ops                           |
| crypto-js 4.1.1 (from npm)      | 29 ops                           |

#

| Argon2id (m=512, t=8, p=1)       | operations per second (16 bytes) |
| -------------------------------- | -------------------------------- |
| **wasm-crypto-hash 1.0.0**       | **438 ops**                      |
| argon2-browser 1.18.0 (from npm) | 213 ops                          |
| argon2-wasm-pro 1.1.0 (from npm) | 203 ops                          |
| argon2-wasm 0.9.0 (from npm)     | 195 ops                          |

<br/>

\* Benchmarks run with Node.js on a modern desktop CPU.

# CI: Signing and Secrets

## Signing artifact encoding and canonicalization

When producing signed `.wasm.json` artifacts for distribution, follow these encoding and canonicalization rules to ensure cross-environment interoperability:

- Canonical signing object key order: `name`, `data`, `hash`, `hmac`, `sig_algo`. The signing and verification code expects these fields to be present and treated as literal UTF-8 values when canonicalizing bytes for signature.
- Use standard Base64 (RFC 4648 "base64" with `=` padding) for all Base64-encoded fields such as `hmac` and `sig`. Do NOT use URL-safe Base64 or omit padding for artifacts that will be signed/verified by the tools in this repository.
- If you must accept URL-safe Base64 input, normalize it before decoding: replace `-` with `+`, `_` with `/`, then restore padding to make the length a multiple of 4 by appending `=` characters.
- `hash` MUST be the lowercase hex-encoded SHA-256 digest (64 hex characters) of the raw WASM bytes.
- `data` (if present) is a UTF-8 string identifier (e.g., filename) and must be included verbatim when canonicalizing.

Example canonical JSON used for signing:

```json
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
| **wasm-crypto-hash 1.0.0**    | **38.06 MB/s**        | **234.40 MB/s**  |
| sha3-wasm 1.0.0 (from npm)    | 15.44 MB/s            | 101.51 MB/s      |
| noble-hashes 1.3.2 (from npm) | 5.74 MB/s             | 14.19 MB/s       |
| sha3 2.1.4 (from npm)         | 3.80 MB/s             | 10.73 MB/s       |
| jsSHA 3.2.0 (from npm)        | 2.08 MB/s             | 3.82 MB/s        |

#

| XXHash64                     | throughput (32 bytes) | throughput (1MB)   |
| ---------------------------- | --------------------- | ------------------ |
| **wasm-crypto-hash 1.0.0**   | **101.66 MB/s**       | **15 989 MB/s** |
| xxhash-wasm 1.0.2 (from npm) | 47.58 MB/s            | 15 929 MB/s     |
| xxhashjs 0.2.2 (from npm)    | 0.92 MB/s             | 42.26 MB/s         |

#

| PBKDF2-SHA512 - 1000 iterations | operations per second (16 bytes) |
| ------------------------------- | -------------------------------- |
| **wasm-crypto-hash 1.0.0**      | **588 ops**                      |
| noble-hashes 1.3.2 (from npm)   | 395 ops                          |
| pbkdf2 3.1.2 (from npm)         | 83 ops                           |
| crypto-js 4.1.1 (from npm)      | 29 ops                           |

#

| Argon2id (m=512, t=8, p=1)       | operations per second (16 bytes) |
| -------------------------------- | -------------------------------- |
| **wasm-crypto-hash 1.0.0**       | **438 ops**                      |
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

// Modern Ciphers, AEAD & Post-Quantum Protocols

// RFC 8439 ChaCha20-Poly1305 AEAD
chacha20Poly1305Encrypt(plaintext: Uint8Array | string, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>
chacha20Poly1305Decrypt(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>

// Extended 192-bit Nonce XChaCha20-Poly1305 AEAD
xchacha20Poly1305Encrypt(plaintext: Uint8Array | string, key: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>
xchacha20Poly1305Decrypt(ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>

// Native ML-KEM-768 + X25519 with a versioned package-specific HKDF-SHA256 envelope
generatePqcHybridKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array; algorithm: "X25519-ML-KEM-768" }>
pqcEncapsulate(recipientPublicKey: Uint8Array): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }>
pqcDecapsulate(ciphertext: Uint8Array, recipientPrivateKey: Uint8Array): Promise<Uint8Array>

// Native NIST FIPS 204 ML-DSA-65 signatures (SPKI/PKCS#8 keys)
generateMlDsaKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array; algorithm: "ML-DSA-65" }>
mlDsaSign(message: Uint8Array | string, privateKey: Uint8Array): Promise<Uint8Array>
mlDsaVerify(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>

// TOTP / HOTP (RFC 6238 / RFC 4226)
totp(key: Uint8Array | string, options?: { step?: number; digits?: number; timestamp?: number; algorithm?: "sha1" | "sha256" }): Promise<string>
verifyTotp(token: string, key: Uint8Array | string, options?: { step?: number; window?: number; timestamp?: number; algorithm?: "sha1" | "sha256" }): Promise<boolean>
hotp(key: Uint8Array | string, counter: number, digits?: number, algorithm?: "sha1" | "sha256"): Promise<string>

// BIP-39 (Mnemonic & Master Seed Derivation)
generateMnemonic(strength?: 128 | 256, wordlist?: string[]): Promise<string>
mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Uint8Array>
entropyToMnemonic(entropy: Uint8Array, wordlist?: string[]): Promise<string>

// Shamir's Secret Sharing (GF(2^8) k-of-n threshold scheme)
shamirSplit(secret: Uint8Array | string, parts: number, threshold: number): { index: number; share: string }[]
shamirCombine(shares: { index: number; share: string }[]): Uint8Array

// NIST SP 800-185 KMAC & FIPS 202 SHAKE XOF
kmac128(key: IDataType, data: IDataType, outputBits?: number, customString?: string): Promise<string>
kmac256(key: IDataType, data: IDataType, outputBits?: number, customString?: string): Promise<string>
shake128(data: IDataType, outputBits?: number): Promise<string>
shake256(data: IDataType, outputBits?: number): Promise<string>

// ZK & Hardened KDF
poseidon(inputs: (bigint | number | string)[]): Promise<string>
balloon(password: IDataType, salt: IDataType, options?: { sCost?: number; tCost?: number; delta?: number }): Promise<string>

// Fast Non-Cryptographic & PRF Hashes
aesKeyWrap(kek: Uint8Array, keyData: Uint8Array): Promise<Uint8Array>
aesKeyUnwrap(kek: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array>
siphash24(data: IDataType, key: Uint8Array): Promise<string>
murmurhash3(data: IDataType, seed?: number): Promise<string>

```

# Roadmap

- WebAssembly SIMD hardware acceleration (expecting additional 20-30% performance speedup)
- Pure WASM memory allocator improvements for ultra-high throughput pipelines
- Extended post-quantum signature schemes and hardware KMS adapters
