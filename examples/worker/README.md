# Cloudflare Worker PoC for hash-wasm

This example demonstrates a minimal Cloudflare Worker that:

- fetches a `*.wasm.json` artifact (contains `name`, `data` base64, `hash`, `sig`, `sig_algo`)
- canonicalizes the metadata and verifies the `sig` using RSASSA-PSS and WebCrypto
- compiles and instantiates the WASM module if verification succeeds

Usage:
- Deploy the worker or run with `wrangler` in a dev environment.
- Ensure the Worker runtime has the public key available in `globalThis.__WASM_SIG_PUBKEY`.
- Query the worker with `?wasm=https://cdn.example.com/example.wasm.json`.

Notes:
- This is a PoC. For production, ensure streaming instantiate (`instantiateStreaming`) is used when serving raw `.wasm` from CDN, and trust root distribution is secure.
- Add timeouts and size checks to avoid DoS from large WASM binaries.

Bundle size (gzipped):

- `worker.dev.js` (gzipped): 858 bytes (~0.84 KB)
