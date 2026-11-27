# wasm-crypto-hash (日本語ドキュメント)

## セキュリティ修正と移行上の注意

- ハッシュAPIの基本対応環境とは別に、**ML-KEM-768／ML-DSA-65にはネイティブWeb Crypto対応が必要**です（例：Node.js 26）。未対応のNode・ブラウザー・Workersではエラーとなり、古典暗号へ代替しません。ネイティブAPIの使用は、このパッケージの認証・第三者監査を意味しません。
- ハイブリッド方式は実際のX25519とML-KEM-768の共有秘密を、暗号文のハッシュを文脈に含めたHKDF-SHA256で結合する独自の版付き形式です。TLS/IETF形式ではありません。ML-DSA公開鍵はDER SPKI、秘密鍵はDER PKCS#8、署名は3309バイトです。以前の古典暗号だけの鍵・暗号文とは互換性がないため、新しい鍵を生成して明示的に移行してください。
- AES-KWはネイティブWeb Cryptoを使用し、認証失敗・未対応時に拒否します。旧フォールバックの出力は鍵の平文を含む可能性があります。信頼できる元の鍵から再ラップし、影響する鍵はローテーションしてください。不明な旧データを自動復旧しません。
- `poseidon` と `balloon` のエクスポートはAPI互換性のため残していますが、実装が規格に適合しないため呼び出すとエラーになります。使用せず、別途レビュー済みの実装へ移行してください。
- BIP39の既定値は公式英語2048語です。独自辞書も重複のない2048語のNFKD形式が必要です。既存フレーズは引き続きmnemonicToSeedへの入力に使用できます。復旧目的でフレーズを再生成せず、旧サンプル辞書からの移行は鍵・ウォレットの移行として実施してください。
- リモートWASMには、呼び出し側が信頼するSHA-256・HMAC・署名または公開鍵が必要です。JSON形式もデコード後のバイト列に同じ検証を適用します。公開鍵を設定した場合は署名必須、検証に必要な鍵がない場合も拒否します。分離署名は生バイト、コンテナー署名は正規化メタデータを対象とします。埋め込みモジュールもキャッシュ参照前に検証し、キャッシュは内容のハッシュで識別します。
- リモートローダーはダウンロードした内容を検証する前に、呼び出し側が渡したURLへ `fetch()` します。応答を既定16 MiB（上限64 MiB）、取得・読み込み時間を既定30秒（上限120秒）に制限し、リダイレクトを拒否します。接続先を検証せず、SSRFは防ぎません。サーバー側ではリクエスト等の未信頼値をURLとして渡さず、信頼済みの固定HTTPS URLを使用してください。
- WASMのリソース依存暗号入力にも上限があり、Argon2はメモリ64 MiB・反復10回・並列度16、bcryptコスト16、scrypt/PBKDF2は総作業量、HOTP/TOTPは1〜10桁・TOTP窓10、Keccak出力は1 MiBまでです。未信頼入力から呼び出すアプリでは、別途レート制限も行ってください。
- 検証鍵やハッシュは配布メタデータと独立した信頼経路で設定してください。同梱ハッシュだけでは、コードとハッシュを両方置換する配布元への攻撃を防げません。KMS署名は配布者による設定が必要で、全成果物への既定署名を保証しません。


[![npm package](https://img.shields.io/npm/v/wasm-crypto-hash.svg)](https://www.npmjs.com/package/wasm-crypto-hash)
[![CI](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/wasm-crypto-hash/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/wasm-crypto-hash)
[![CodeQL](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **WebAssembly 暗号ユーティリティ**: 多数のハッシュ、AEAD共通鍵暗号、耐量子暗号（PQC）、2要素認証（2FA/TOTP）、BIP-39ニーモニック、閾値秘密分散を提供します。ブラウザ、Node.js、および Cloudflare Workers（workerd）向けです。

**wasm-crypto-hash** は、ブラウザ、Node.js、および Cloudflare Workers（Edge）向けに高度に最適化された WebAssembly (WASM) ベースの高速暗号ハッシュ・チェックサム・次世代暗号プロトコルユーティリティパッケージです。

WebAssembly バイナリと TypeScript を組み合わせた暗号ユーティリティです。WASM整合性検証や署名検証は任意設定であり、既定で全成果物が署名済みであること、または第三者監査・認証済みであることを意味しません。性能は実行環境により異なります。

---

## 従来の WebAssembly 暗号ライブラリに対する本パッケージの優位点

一般的な WebAssembly 暗号ライブラリと比較し、本パッケージは以下の決定的な優位点・技術的差別化を備えています：

1. **サプライチェーン改ざん防御 & KMS ハードウェア暗号署名検証**:
   - 従来の WASM 暗号ライブラリは raw WASM バイナリを直接実行するため、万一の npm や CDN 侵害時に改ざんバイトコードを検知できません。
   - 配布者がAWS/GCP KMS署名と信頼する検証鍵を設定できます。設定されたハッシュ・署名・HMACをインスタンス化前に検証します。全成果物への既定署名は保証しません。
2. **Cloudflare Workers (workerd) & Edge ランタイムへのネイティブ統合**:
   - 従来のライブラリで問題になりやすかった Workers の動的 WASM ロード制約を解消。
   - `package.json` の `exports` に `"workerd"` 条件分岐を整備し、Cloudflare Workers や Pages Functions 上でも設定ゼロで直接動作します（Cloudflare Workers 向け専用エクスポートを本パッケージに標準統合）。
3. **リモート WASM 検証付き読み込み検証ローダー (`remoteWasmLoader.ts`)**:
   - CDN（unpkg, jsdelivr）やオブジェクトストレージ（Cloudflare R2, AWS S3）から WASM を動的フェッチする際にも、リアルタイムにダイジェストおよびデジタル署名を検証可能。
4. **MAC比較時のタイミング差の低減**:
   - MAC照合には比較用ヘルパーを使用します。JavaScript実行環境全体の定時間性やタイミング攻撃への完全耐性を保証するものではありません。
5. **次世代暗号プロトコルスイートの拡充**:
   - **NIST FIPS 203 ML-KEM-768 ハイブリッド鍵カプセル化**、**RFC 8439 ChaCha20-Poly1305 AEAD**、**NIST SP 800-185 KMAC256**、**FIPS 202 SHAKE256**、**シャミアの秘密分散法（SSS）** を含みます。`poseidon` と `balloon` は現在呼び出すとエラーになります。上記の互換性注記を参照してください。
6. **セキュリティ回帰テスト**:
   - 暗号処理と入力検証に関する一部の回帰を自動テストします。テストや依存監査の成功は、脆弱性が存在しないことを保証しません。

---

## サポートアルゴリズム一覧 (Supported Algorithms)

| アルゴリズム名 | 分類 | バンドルサイズ (gzip) | 準拠規格 / 概要 |
| :--- | :--- | :---: | :--- |
| **Adler-32** | チェックサム | 2 kB | RFC 1950 (WASM) |
| **AES-KW (Key Wrap)** | 鍵ラッピング | 1 kB | RFC 3394 / NIST SP 800-38F |
| **Argon2: 2d, 2i, 2id (v1.3)** | パスワードKDF | 6 kB | RFC 9106（WASM） |
| **bcrypt** | パスワードKDF | 9 kB | OpenBSD Blowfish 暗号 (WASM) |
| **BIP-39 (Mnemonic & Seed)** | ニーモニックKDF | 2 kB | Bitcoin / Web3 標準決定性シード生成 |
| **BLAKE2b / BLAKE2s** | 暗号学的ハッシュ | 5 kB / 5 kB | RFC 7693 (WASM) |
| **BLAKE3** | 暗号学的ハッシュ | 8 kB | ツリーハッシュ並列処理 (WASM) |
| **ChaCha20-Poly1305** | 認証付き暗号 (AEAD) | 2 kB | RFC 8439 |
| **CRC32 / CRC64** | チェックサム | 2 kB / 2 kB | ISO 3309 / ECMA 182 (WASM) |
| **HMAC** | メッセージ認証 | 1 kB | RFC 2104 |
| **Keccak-224 / 256 / 384 / 512** | 暗号学的ハッシュ | 3 kB | オリジナル Keccak スポンジ関数 (WASM) |
| **KMAC128 / KMAC256** | メッセージ認証 | 1 kB | NIST SP 800-185（伸長攻撃耐性） |
| **MD4 / MD5** | レガシー | 3 kB / 3 kB | RFC 1320 / RFC 1321 (WASM) |
| **ML-DSA-65 (Dilithium)** | 耐量子電子署名 (PQC) | 実行環境依存 | NIST FIPS 204 耐量子電子署名標準 |
| **ML-KEM-768 + X25519 (Hybrid)** | 耐量子鍵共有 (PQC) | 実行環境依存 | ネイティブ ML-KEM-768 + X25519、独自HKDF形式 |
| **MurmurHash3 (32 / 128)** | 非暗号超高速ハッシュ | 1 kB | Austin Appleby ブルームフィルター標準 |
| **PBKDF2** | 鍵導出関数 | 1 kB | RFC 2898 |
| **RIPEMD-160** | レガシー | 4 kB | ISO/IEC 10118-3 (WASM) |
| **scrypt** | パスワードKDF | 4 kB | RFC 7914 (WASM) |
| **SHA-1** | レガシー | 4 kB | RFC 3174 (WASM) |
| **SHA-2: SHA-224 / 256 / 384 / 512** | 暗号学的ハッシュ | 5 kB - 7 kB | FIPS PUB 180-4 (WASM) |
| **SHA-3: SHA3-224 / 256 / 384 / 512** | 暗号学的ハッシュ | 3 kB | FIPS PUB 202 (WASM) |
| **SHAKE128 / SHAKE256** | 拡張可能出力関数 (XOF)| 3 kB | FIPS PUB 202（WASM） |
| **Shamir's Secret Sharing (SSS)** | 閾値暗号 | 2 kB | GF(2^8) (k, n) 秘密分散法 |
| **SipHash-2-4** | 耐DoS PRFハッシュ | 1 kB | RFC 7693 HashDoS攻撃耐性PRF |
| **SM3** | 暗号学的ハッシュ | 3 kB | 中国国家規格 GM/T 0004-2012 (WASM) |
| **TOTP / HOTP** | 2要素認証 (2FA/OTP) | 1 kB | RFC 6238 / RFC 4226 ワンタイムコード |
| **XChaCha20-Poly1305** | 拡張ノンス AEAD | 1 kB | 192-bit 拡張ノンス認証付き暗号 |
| **xxHash: 32, 64, 3, 128** | 非暗号超高速ハッシュ | 2 kB - 7 kB | Yann Collet 高速スイート (WASM) |

---

## クイックスタート

```bash
npm install wasm-crypto-hash
```

### 1. SHA-256 / SHA-3 / SHAKE256 の計算
```typescript
import { sha256, sha3, shake256 } from 'wasm-crypto-hash';

// SHA-256
const digest = await sha256('Hello World');
console.log(digest);

// SHA-3 (512-bit)
const sha3Hash = await sha3('Hello World', 512);

// SHAKE256 (任意長 XOF)
const shakeHash = await shake256('Hello World', 256);
```

### 2. KMAC256 メッセージ認証 (NIST SP 800-185)
```typescript
import { kmac256 } from 'wasm-crypto-hash';

const mac = await kmac256('secret-key', 'message-body', 256, 'my-application');
console.log('KMAC:', mac);
```

### 3. ChaCha20-Poly1305 認証付き暗号化 (RFC 8439)
```typescript
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from 'wasm-crypto-hash';

const key = crypto.getRandomValues(new Uint8Array(32));
const nonce = crypto.getRandomValues(new Uint8Array(12));

const { ciphertext, tag } = await chacha20Poly1305Encrypt('極秘データ', key, nonce);
const decrypted = await chacha20Poly1305Decrypt(ciphertext, key, nonce, tag);
console.log(new TextDecoder().decode(decrypted)); // '極秘データ'
```

### 4. シャミアの秘密分散法 (3-of-5 閾値秘密分割)
```typescript
import { shamirSplit, shamirCombine } from 'wasm-crypto-hash';

// 秘密情報を5つのシェアに分割（3つあれば復元可能）
const shares = shamirSplit('Master-Recovery-Key', 5, 3);

// 任意の3つのシェアから復元
const recovered = shamirCombine([shares[0], shares[2], shares[4]]);
console.log(new TextDecoder().decode(recovered)); // 'Master-Recovery-Key'
```

### 5. 耐量子暗号ハイブリッド鍵共有 (ML-KEM-768 + X25519)
```typescript
import { generatePqcHybridKeyPair, pqcEncapsulate, pqcDecapsulate } from 'wasm-crypto-hash';

// 受信者の耐量子鍵ペア生成
const recipient = await generatePqcHybridKeyPair();

// 送信者側：カプセル化（共有秘密鍵と暗号文を生成）
const { sharedSecret, ciphertext } = await pqcEncapsulate(recipient.publicKey);

// 受信者側：秘密鍵でデカプセル化（同一の共有秘密鍵を復元）
const recoveredSecret = await pqcDecapsulate(ciphertext, recipient.privateKey);
```

### 6. Cloudflare Workers / Wrangler での利用例 (workerd)

`wasm-crypto-hash` は `package.json` の `"workerd"` 条件分岐エクスポートに対応しているため、Wrangler や Cloudflare Pages 上で設定不要（プラグ＆プレイ）で動作します。

`API_SECRET` には `wrangler secret put API_SECRET` などで登録した、暗号学的乱数による32バイト以上の秘密値を設定してください。共有秘密を保持できる信頼されたバックエンドからのみ呼び出し、ブラウザーのコードには含めないでください。この例はクライアントから受け取ったMACを検証し、任意の入力に対するMACを返しません。状態変更を伴うリクエストでは認証対象に時刻またはnonceを含め、リプレイを拒否してください。

```typescript
// worker.ts (Cloudflare Workers)
import { sha256, kmac256 } from 'wasm-crypto-hash';
import { timingSafeEqualString } from 'wasm-crypto-hash/util';

export interface Env {
  API_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const secret = env.API_SECRET;
    if (!secret || new TextEncoder().encode(secret).length < 32) {
      return new Response('API_SECRET は32バイト以上の秘密値として設定してください', { status: 500 });
    }
    const payload = await request.text();
    const suppliedMac = request.headers.get('x-signature') ?? '';
    const expectedMac = await kmac256(secret, payload, 256, 'edge-api');
    if (!timingSafeEqualString(suppliedMac, expectedMac)) {
      return new Response('Unauthorized', { status: 401 });
    }

    // 1. Edge 上で WebAssembly による超高速 SHA-256 計算
    const digest = await sha256(payload);

    return new Response(JSON.stringify({ digest, runtime: 'Cloudflare Workers' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
```

---

## 関連エッジセキュリティパッケージ群

- [edge-rate-limiter](https://github.com/takao-dev/edge-rate-limiter): 外部依存ゼロの固定/スライド窓型レートリミッター（ソルト付き匿名化対応）
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): タイミング攻撃耐性を持つ WebCrypto ベースの JWT & クレーム暗号化スイート
- [edge-session-crypto](https://github.com/takao-dev/edge-session-crypto): AES-GCM と鍵ローテーションを備えたステートレス暗号化クッキーセッション管理
- [zero-pii-redactor](https://github.com/takao-dev/zero-pii-redactor): ログ・AIプロンプト向けの超高速・ReDoSフリー PII マスキング＆匿名化ツール
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): AES-GCM & HMAC による改ざん検知機能付きセキュアKVストレージ
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): 暗号論的ハッシュチェーンによる改ざん耐性監査ログ記録

---

## ライセンス
MIT License
