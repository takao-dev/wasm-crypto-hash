# Changelog

All notable changes to `wasm-crypto-hash` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-11

### Fixed
- **Security**: Eliminate polynomial regular expression denial-of-service (ReDoS) vulnerability in RFC 6238 TOTP Base32 decoder.
- **Security**: Prevent insecure temporary file creation in WASM KMS signer by using cryptographically isolated temporary directories (`fs.mkdtempSync`) with guaranteed teardown.
- **Security**: Sanitize HTTP 500 error responses in Cloudflare Worker examples to prevent leaking internal stack traces.
- **Code Quality**: Remove unused variables, redundant assignments, and obsolete mock artifacts detected by CodeQL SAST.

## [1.0.0] - 2026-11-08

### Added
- **Full-Stack Next-Generation Cryptographic Suite**:
  - **AEAD Ciphers**: RFC 8439 ChaCha20-Poly1305 and extended 192-bit nonce XChaCha20-Poly1305 authenticated encryption.
  - **Post-Quantum Cryptography (PQC)**:
    - NIST FIPS 203 Post-Quantum Hybrid Key Encapsulation (X25519 + ML-KEM-768 / Kyber).
    - NIST FIPS 204 Post-Quantum Digital Signatures (Ed25519 + ML-DSA-65 / Dilithium).
  - **Authentication & 2FA**: RFC 6238 TOTP (Time-based One-Time Password) and RFC 4226 HOTP generator & constant-time verifier.
  - **Key Management & Threshold Cryptography**:
    - BIP-39 mnemonic phrase generation and 512-bit master seed derivation (2048 iterations PBKDF2-HMAC-SHA512).
    - Shamir's Secret Sharing Scheme (k-of-n threshold secret splitting and reconstruction over Galois Field GF(2^8)).
    - NIST SP 800-38F AES Key Wrap (AES-KW) and Key Unwrap.
  - **Next-Gen Hashes & KDFs**:
    - NIST SP 800-185 KMAC128 and KMAC256.
    - FIPS 202 SHAKE128 and SHAKE256 Extendable-Output Functions (XOF).
    - BN254 algebraic Poseidon hash for Zero-Knowledge (ZK-SNARK) proofs.
    - Stanford memory-hard Balloon Hashing algorithm.
    - SipHash-2-4 HashDoS-resistant PRF.
    - MurmurHash3 32-bit and 128-bit high-speed non-cryptographic hashes.
- **Enterprise Edge & Cloudflare Workers Integration**:
  - Native `workerd` conditional export in `package.json` for plug-and-play Cloudflare Workers and Pages Functions operation without build configuration.
- **Supply-Chain Integrity & Hardware KMS Verification**:
  - Automatic RSASSA-PSS and HMAC-SHA256 digital signature verification for WebAssembly modules with fail-closed behavior against tampering.
  - Remote WASM streaming verification loader (`remoteWasmLoader.ts`) for CDN and Cloudflare R2 / S3 module hydration.
- **Timing Attack Immunity**:
  - `timingSafeEqualString` bitwise constant-time comparisons applied across all MAC, hash, and signature verification routines.
- **Universal Multi-Runtime Compatibility**:
  - `getCrypto()` helper ensuring seamless operation across Node.js 18, 20, 22, 24+, modern web browsers, Deno, and Edge environments.
- **Comprehensive Matrix CI & CodeQL**:
  - Cross-platform CI matrix covering Ubuntu, Windows, and macOS on Node.js 18.x through 24.x.
  - GitHub CodeQL automated static application security testing (SAST).
