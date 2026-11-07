# Unreleased security changes

No release or registry publication has been performed.

- AES-KW now uses authenticated native wrapping for all supported RFC3394 key lengths and preserves typed-array ranges. Unsupported runtimes, wrong keys and tampering reject. The former placeholder output is not authenticated and may disclose key material: rotate affected keys and re-wrap only trusted originals.
- ML-DSA-65 uses the runtime's actual ML-DSA-65 implementation (SPKI public key, PKCS#8 private key). X25519/ML-KEM-768 uses both native primitives and a versioned package-specific HKDF-SHA256 envelope. Unsupported runtimes reject. Old classical-only keys and ciphertexts are incompatible. This custom envelope is not a standardized TLS protocol or independently audited construction.
- BIP39 uses the full official English dictionary. Other dictionaries must contain exactly2048 unique NFKD words. Existing phrases can still be supplied to mnemonicToSeed; applications must explicitly migrate old sample-list-generated wallets/keys without destroying access to the originals.
- Remote WASM always applies caller pins to decoded bytes, including JSON. Trusted signature keys make signatures mandatory; required keys cannot be absent. Embedded verification occurs before content-addressed cache lookup.
- Tests include RFC3394 and BIP39 known-answer vectors, native ML-DSA interoperability, actual ML-KEM components, view offsets, malicious records, unsupported runtimes, JSON/binary verification and warm caches.

See README.md / README_JA.md for runtime and migration requirements. Passing these checks does not constitute a complete cryptographic audit.
