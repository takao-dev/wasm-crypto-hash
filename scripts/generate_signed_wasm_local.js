#!/usr/bin/env node
const fs = require('fs');
const crypto = require('node:crypto');
const path = require('path');
// Inline canonicalization to avoid build dependency on lib
function canonicalizeWasmForSigning(obj) {
  const keys = ['name','data','hash','hmac','sig_algo'];
  const canonical = {};
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) canonical[k]=obj[k];
  canonical.sig_algo = obj.sig_algo || 'pss';
  return JSON.stringify(canonical);
}

// Generate RSA keypair and sign canonicalized metadata
const outDir = path.join(__dirname, '..', 'examples', 'static');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
});

const wasmDataBase64 = 'AGFzbQEAAAA='; // minimal wasm
const meta = {
  name: 'example-prod-wasm',
  data: wasmDataBase64,
  hash: '',
  sig_algo: 'pss'
};

const canonical = canonicalizeWasmForSigning(meta);
const sigBuf = crypto.sign('sha256', Buffer.from(canonical), {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
});

meta.sig = sigBuf.toString('base64');
meta.pubkey = publicKey;

const outPath = path.join(outDir, 'example.signed.wasm.json');
fs.writeFileSync(outPath, JSON.stringify(meta, null, 2));
console.log('Wrote signed wasm json to', outPath);
console.log('Public key (PEM) written into json as "pubkey" field.');
