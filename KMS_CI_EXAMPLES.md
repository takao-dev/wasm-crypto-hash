KMS signing examples for CI (AWS & GCP)

This file contains example GitHub Actions snippets to run KMS-based signing of `.wasm.json` artifacts in CI.

AWS KMS example (GitHub Actions):

```yaml
name: Sign WASM with AWS KMS
on:
  workflow_dispatch:

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Node
        uses: actions/setup-node@v4
        with:
          node-version: 18
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_TO_ASSUME }} # or set access keys
          aws-region: ${{ secrets.AWS_REGION }}
      - name: Install deps
        run: |
          cd package/hash-wasm
          npm ci
      - name: Sign with AWS KMS
        env:
          WASM_KMS_PROVIDER: aws
          AWS_KMS_KEY_ID: ${{ secrets.AWS_KMS_KEY_ID }}
        run: |
          cd package/hash-wasm
          node ./scripts/sign_wasm_kms_sdk.js
      - name: Upload signed artifacts
        uses: actions/upload-artifact@v4
        with:
          name: signed-wasm
          path: package/hash-wasm/wasm/*.wasm.json
```

GCP KMS example (GitHub Actions):

```yaml
name: Sign WASM with GCP KMS
on:
  workflow_dispatch:

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Node
        uses: actions/setup-node@v4
        with:
          node-version: 18
      - name: Authenticate to GCP
        uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY_JSON }}
      - name: Install deps
        run: |
          cd package/hash-wasm
          npm ci
      - name: Sign with GCP KMS
        env:
          WASM_KMS_PROVIDER: gcp
          WASM_GCP_KMS_RESOURCE: ${{ secrets.WASM_GCP_KMS_RESOURCE }}
        run: |
          cd package/hash-wasm
          node ./scripts/sign_wasm_kms_sdk.js
      - name: Upload signed artifacts
        uses: actions/upload-artifact@v4
        with:
          name: signed-wasm
          path: package/hash-wasm/wasm/*.wasm.json
```

Notes and recommendations:

- Use short-lived credentials where possible (OIDC or roles) rather than long-lived static keys.
- Ensure the KMS key has an asymmetric signing key (RSA) compatible with RSASSA-PSS + SHA-256.
- After signing, run verification (e.g., using `node ./scripts/verify_local_signed.js` or a custom verification step) in CI to catch misconfiguration early.
- The `sign_wasm_kms_sdk.js` script sets `sig_algo` to `pss` and writes `sig` field as Base64.
