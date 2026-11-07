# wasm-crypto-hash (日本語ドキュメント)

[![npm package](https://img.shields.io/npm/v/wasm-crypto-hash.svg)](https://www.npmjs.com/package/wasm-crypto-hash)
[![CI](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/wasm-crypto-hash/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/wasm-crypto-hash)
[![CodeQL](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/wasm-crypto-hash/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **超高速 WebAssembly 暗号スイート**: 31種類以上の暗号ハッシュ、AEAD共通鍵暗号、耐量子暗号（PQC）、2要素認証（2FA/TOTP）、BIP-39ニーモニック、閾値秘密分散を網羅。ブラウザ、Node.js、および Cloudflare Workers（workerd）に完全対応。

**wasm-crypto-hash** は、ブラウザ、Node.js、および Cloudflare Workers（Edge）向けに高度に最適化された WebAssembly (WASM) ベースの高速暗号ハッシュ・チェックサム・次世代暗号プロトコルユーティリティパッケージです。

ハンドチューニングされた WebAssembly バイナリと純粋な TypeScript により、業界最高水準の計算速度とエンタープライズ級の改ざん耐性を提供します。

---

## 従来の WebAssembly 暗号ライブラリに対する本パッケージの優位点

一般的な WebAssembly 暗号ライブラリと比較し、本パッケージは以下の決定的な優位点・技術的差別化を備えています：

1. **サプライチェーン改ざん防御 & KMS ハードウェア暗号署名検証**:
   - 従来の WASM 暗号ライブラリは raw WASM バイナリを直接実行するため、万一の npm や CDN 侵害時に改ざんバイトコードを検知できません。
   - `wasm-crypto-hash` は CI ビルド時に **AWS KMS または GCP KMS（クラウド HSM）** による暗号署名を各 `.wasm.json` に付与。実行時に WebCrypto / Node crypto で **RSASSA-PSS および HMAC-SHA256 署名を自動検証** してからインスタンス化し、1バイトでも改ざんがあれば即座に拒絶（フェイルクローズ）します。
2. **Cloudflare Workers (workerd) & Edge ランタイムへのネイティブ統合**:
   - 従来のライブラリで問題になりやすかった Workers の動的 WASM ロード制約を解消。
   - `package.json` の `exports` に `"workerd"` 条件分岐を整備し、Cloudflare Workers や Pages Functions 上でも設定ゼロで直接動作します（Cloudflare Workers 向け専用エクスポートを本パッケージに標準統合）。
3. **リモート WASM ストリーミング検証ローダー (`remoteWasmLoader.ts`)**:
   - CDN（unpkg, jsdelivr）やオブジェクトストレージ（Cloudflare R2, AWS S3）から WASM を動的フェッチする際にも、リアルタイムにダイジェストおよびデジタル署名をストリーミング検証可能。
4. **定時間比較によるタイミング攻撃（Side-Channel Attack）の排除**:
   - すべての署名・MAC・ダイジェスト照合に `timingSafeEqualString` による定時間比較を採用し、応答時間のミリ秒単位の差異を突く攻撃を数学的に遮断。
5. **次世代暗号プロトコルスイートの拡充**:
   - 古典ハッシュにとどまらず、**NIST FIPS 203 耐量子暗号（ML-KEM-768 ハイブリッド）**、**RFC 8439 ChaCha20-Poly1305 AEAD**、**NIST SP 800-185 KMAC256**、**FIPS 202 SHAKE256**、**ゼロ知識証明向け Poseidon ハッシュ**、**Stanford Balloon Hashing**、**シャミアの秘密分散法（SSS）** を標準搭載。
6. **厳格なメモリリーク検査（Leak-Free）＆ 脆弱性ゼロ**:
   - `--expose-gc` による GC 強制実行とヒープモニタリングテストを実施。大容量ストリーミング時も線形メモリを安全に管理し、npm audit 脆弱性ゼロ（0 vulnerabilities）を維持。

---

## サポートアルゴリズム一覧 (Supported Algorithms)

| アルゴリズム名 | 分類 | バンドルサイズ (gzip) | 準拠規格 / 概要 |
| :--- | :--- | :---: | :--- |
| **Adler-32** | チェックサム | 2 kB | RFC 1950 (WASM) |
| **AES-KW (Key Wrap)** | 鍵ラッピング | 1 kB | RFC 3394 / NIST SP 800-38F |
| **Argon2: 2d, 2i, 2id (v1.3)** | パスワードKDF | 6 kB | RFC 9106（WASM） |
| **Balloon Hashing** | パスワードKDF | 1 kB | スタンフォード大学設計（Boneh et al.） |
| **bcrypt** | パスワードKDF | 9 kB | OpenBSD Blowfish 暗号 (WASM) |
| **BIP-39 (Mnemonic & Seed)** | ニーモニックKDF | 2 kB | Bitcoin / Web3 標準決定性シード生成 |
| **BLAKE2b / BLAKE2s** | 暗号学的ハッシュ | 5 kB / 5 kB | RFC 7693 (WASM) |
| **BLAKE3** | 暗号学的ハッシュ | 8 kB | ツリーハッシュ並列処理 (WASM) |
| **ChaCha20-Poly1305** | 認証付き暗号 (AEAD) | 2 kB | RFC 8439 高速定時間暗号 |
| **CRC32 / CRC64** | チェックサム | 2 kB / 2 kB | ISO 3309 / ECMA 182 (WASM) |
| **HMAC** | メッセージ認証 | 1 kB | RFC 2104 |
| **Keccak-224 / 256 / 384 / 512** | 暗号学的ハッシュ | 3 kB | オリジナル Keccak スポンジ関数 (WASM) |
| **KMAC128 / KMAC256** | メッセージ認証 | 1 kB | NIST SP 800-185（伸長攻撃耐性） |
| **MD4 / MD5** | レガシー | 3 kB / 3 kB | RFC 1320 / RFC 1321 (WASM) |
| **ML-DSA-65 (Dilithium)** | 耐量子電子署名 (PQC) | 1 kB | NIST FIPS 204 耐量子電子署名標準 |
| **ML-KEM-768 + X25519 (Hybrid)** | 耐量子鍵共有 (PQC) | 1 kB | NIST FIPS 203 耐量子暗号標準 |
| **MurmurHash3 (32 / 128)** | 非暗号超高速ハッシュ | 1 kB | Austin Appleby ブルームフィルター標準 |
| **PBKDF2** | 鍵導出関数 | 1 kB | RFC 2898 |
| **Poseidon** | ゼロ知識ハッシュ | 1 kB | BN254 楕円曲線 ZK-SNARK 最適化 |
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

```typescript
// worker.ts (Cloudflare Workers)
import { sha256, kmac256, chacha20Poly1305Encrypt } from 'wasm-crypto-hash';

export interface Env {
  API_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const payload = await request.text();

    // 1. Edge 上で WebAssembly による超高速 SHA-256 計算
    const digest = await sha256(payload || 'default-input');

    // 2. Workers 環境変数（シークレット）を用いた KMAC256 メッセージ認証
    const mac = await kmac256(env.API_SECRET || 'edge-secret-key', payload, 256, 'edge-api');

    return new Response(JSON.stringify({ digest, mac, runtime: 'Cloudflare Workers' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
```

---

## ライセンス
MIT License
