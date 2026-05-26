Dev instructions: place public key here

For local testing with `dev_worker.mjs`, place the PEM public key you want to use in:

`package/hash-wasm/examples/worker/pubkey.pem`

You can extract the public key from the generated example signed JSON:

```bash
jq -r .pubkey package/hash-wasm/examples/static/example.signed.wasm.json > package/hash-wasm/examples/worker/pubkey.pem
```

Run dev with Miniflare:

```bash
cd package/hash-wasm
npm install -g miniflare
miniflare --modules ../../package/hash-wasm/examples/worker/dev_worker.mjs
```
