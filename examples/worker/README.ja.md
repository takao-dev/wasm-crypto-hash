Cloudflare Worker サンプル（署名検証）

このディレクトリには、署名済みの `.wasm.json` を検証する簡単な Cloudflare Worker の例があります。

使い方（概要）:

- Worker をデプロイする際に、公開鍵（PEM）を `WASM_SIG_PUBKEY` として Worker Secret に登録してください。
- `worker.mjs` は埋め込みの `example.signed.wasm.json` を読み取り、`lib/util` の `canonicalizeWasmForSigning` と `verifyRsaSignatureBase64` を使って検証します。

wrangler.toml の例:

```
name = "hash-wasm-verify-example"
main = "./worker.mjs"

[vars]
# 代替: Secret を使う場合は wrangler secret に設定してここでは参照しない
# WASM_SIG_PUBKEY = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

Secret 登録例:

```bash
wrangler secret put WASM_SIG_PUBKEY < public.pem
```

注意:

- 実行環境では `fetch(meta.data)` が利用可能で、`meta.data` は署名付き JSON の `data` フィールドに設定された URL/パスを指します。
- このサンプルは概念実証（PoC）用途です。本番ではエラーハンドリング、ログ、rate-limit、公開鍵のローテーションなどを強化してください。
