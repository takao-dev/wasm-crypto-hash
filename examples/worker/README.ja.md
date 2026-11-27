# wasm-crypto-hash Cloudflare Worker サンプル

`worker.dev.js` と `worker.js` は `worker.core.mjs` を使うモジュール形式のWorkerです。`wrangler.toml` から起動し、ローカルでは `.dev.vars`、デプロイ時はWorkerの環境バインディングに次を設定します。

- `__WASM_MANIFEST_URL`: 信頼する署名済み `.wasm.json` のHTTPS URL。
- `__WASM_SIG_PUBKEY`: 署名の確認に使うPEM公開鍵。秘密鍵はWorkerに設定しないでください。

リクエストのクエリから取得先を選ぶ機能や署名検証を無効にする機能はありません。リダイレクトを拒否し、取得を10秒・24 MiB、展開後のWASMを16 MiBに制限します。署名なし、または不正な署名のデータは実行しません。

このコードは概念実証です。本番利用前に、署名鍵の管理・公開鍵の更新手順・Workerの実行制限を確認してください。
