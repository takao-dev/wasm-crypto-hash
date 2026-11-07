Dev instructions: place public key here

For local testing with `dev_worker.mjs`, place the PEM public key you want to use in:

`examples/worker/pubkey.pem`

You can extract the public key from the generated example signed JSON:

```bash
jq -r .pubkey examples/static/example.signed.wasm.json > examples/worker/pubkey.pem
```

Run dev with Miniflare:

```bash
miniflare --modules examples/worker/dev_worker.mjs
```
