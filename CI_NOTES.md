CI signing and verification notes

- Required secrets:
  - `WASM_SIG_PRIV_PEM` : RSA private key PEM (for CI signing)
  - `WASM_SIG_PUBKEY`  : RSA public key PEM (for runtime verification, e.g., injected into Workers)
  - Optional: `WASM_SIG_ALGO` : signing algorithm, set to `pss` (recommended) or `pkcs1`

- Local build signing (example):
  - Generate signed artifacts locally: `node ./scripts/sign_wasm.js` (requires `WASM_SIG_PRIV_PEM` env var)
  - Or generate an example signed file for testing: `node ./scripts/generate_signed_wasm_local.js`

- Worker runtime verification:
  - Inject the public key into Worker runtime (example global variable `__WASM_SIG_PUBKEY`) or use KV/Secrets.
  - The runtime loader uses `verifyRsaSignatureBase64(..., algo='pss')` by default.

Recommended secret injection for Cloudflare Workers:

- Prefer using Cloudflare Worker Secrets (or KV) rather than embedding the public key in source code or globals.
- Example (Workers `wrangler.toml` / secrets): store the PEM in `WASM_SIG_PUBKEY` and load it at startup, e.g. `globalThis.__WASM_SIG_PUBKEY = WASM_SIG_PUBKEY`.
- When deploying via CI, set the repository secret `WASM_SIG_PRIV_PEM` for signing and set the runtime secret `WASM_SIG_PUBKEY` in the Worker environment.

Encoding and canonicalization (recommended rules)

- Canonical signing object keys order: `name`, `data`, `hash`, `hmac`, `sig_algo` (this ordering is used by the signing scripts and verification code).
- Use standard Base64 (RFC 4648 "base64" with `=` padding) for all Base64-encoded fields: `hmac` and `sig` fields MUST use standard Base64 with padding. Do NOT use URL-safe Base64 or omit padding when producing artifacts for signing/verification.
- When verifying artifacts in environments that may produce URL-safe Base64 (e.g., some JS libraries), normalize by converting `-`→`+`, `_`→`/` and restoring padding to a multiple of 4 characters before decoding.
- Binary hashes: `hash` field should be hex-encoded lowercase SHA-256 (64 hex chars) of the raw wasm bytes.
- `data` field (if present in `.wasm.json`) is the filename or identifier and must be treated as literal UTF-8 string when canonicalizing.

Example canonical JSON used for signing (spacing/indentation does not matter; keys and values must match exactly):

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

- `sig` is the signature encoded as standard Base64 of the raw RSA signature bytes. Verification code expects the PEM-format public key (PKCS#8 / SPKI) string.
- HMACs are computed using HMAC-SHA256 and encoded as standard Base64 with padding. Use constant-time comparison (`timingSafeEqualString`) when comparing HMAC strings.
- When implementing verification with WebCrypto, ensure you import the public key with the correct algorithm parameters for `RSASSA-PSS` and set `saltLength` to the hash length (for SHA-256, `saltLength: 32`).

KMS signing in CI

- This repository includes `scripts/sign_wasm_kms_sdk.js` which can sign `.wasm.json` artifacts using AWS KMS or GCP KMS.
- Set `WASM_KMS_PROVIDER=aws` or `WASM_KMS_PROVIDER=gcp` in CI, and provide the provider-specific secret below.

AWS KMS:

- Required secrets / env in CI:
  - `WASM_KMS_PROVIDER=aws`
  - `AWS_KMS_KEY_ID` or `WASM_AWS_KMS_KEY_ID` — KMS KeyId or ARN with Sign permission
  - AWS credentials (e.g., `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`) configured in the runner environment via repository secrets or OIDC

GCP KMS:

- Required secrets / env in CI:
  - `WASM_KMS_PROVIDER=gcp`
  - `WASM_GCP_KMS_RESOURCE` — full resource name of the CryptoKeyVersion, e.g. `projects/PROJECT/locations/global/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/1`
  - GCP service account JSON provided to the runner (configure `GOOGLE_APPLICATION_CREDENTIALS` or use the `google-github-actions/auth` action)

The `sign_wasm_kms_sdk.js` script will set `sig` and `sig_algo` (`pss`) fields in the `.wasm.json` files under `wasm/`.

- Notes:
  - Default recommended algorithm is `pss` (RSASSA-PSS) with SHA-256 and saltLength = digest length.
  - HMAC checks use constant-time comparison via `timingSafeEqualString`.
  - CI should produce both `.wasm` and `.wasm.json` signed metadata for distribution.
