# Cloudflare Worker PoC for wasm-crypto-hash

This example demonstrates a minimal Cloudflare Worker that:

- fetches a `*.wasm.json` artifact (contains `name`, `data` base64, `hash`, `sig`, `sig_algo`)
- canonicalizes the metadata and verifies the `sig` using RSASSA-PSS and WebCrypto
- compiles and instantiates the WASM module if verification succeeds

Usage:
- Set `__WASM_MANIFEST_URL` and `__WASM_SIG_PUBKEY` as Worker environment bindings (or local development variables). The manifest URL must be a trusted HTTPS URL.
- Deploy the worker or run it with `wrangler dev`.
- The worker loads only that configured manifest. Request query parameters cannot select an artifact or disable verification.
- The artifact must include a valid `sig` generated with RSASSA-PSS and the matching trusted public key. Unsigned metadata is rejected.

Notes:
- Manifest fetches reject redirects, time out after 10 seconds, and stop reading above 24 MiB. Decoded WASM is limited to 16 MiB.
- This is still a PoC. Keep the signing private key outside the Worker, distribute the public key through trusted Worker configuration, and review runtime-specific execution limits before production use.
