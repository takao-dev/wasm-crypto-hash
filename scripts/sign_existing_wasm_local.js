#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('node:crypto');

// Usage: node sign_existing_wasm_local.js <name> [algo]
// algo: pss (default) | pss-hash | ed25519-hash
const name = process.argv[2] || process.env.WASM_NAME || 'argon2';
const algo = process.argv[3] || process.env.SIGN_ALGO || 'pss';
const wasmDir = path.join(__dirname, '..', 'wasm');
const srcPath = path.join(wasmDir, `${name}.wasm.json`);
if (!fs.existsSync(srcPath)) {
  console.error('Source wasm json not found:', srcPath);
  process.exit(1);
}
const meta = JSON.parse(fs.readFileSync(srcPath, 'utf8'));

function canonicalize(obj) {
  const keys = ['name','data','hash','hmac','sig_algo'];
  const canonical = {};
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) canonical[k]=obj[k];
  canonical.sig_algo = obj.sig_algo || 'pss';
  return JSON.stringify(canonical);
}

function canonicalizeNameHash(obj) {
  return JSON.stringify({ name: obj.name, hash: obj.hash, sig_algo: obj.sig_algo });
}

function sha256HexFromBase64(b64) {
  return crypto.createHash('sha256').update(Buffer.from(b64,'base64')).digest('hex');
}

let publicKey, privateKey;
if (algo === 'ed25519-hash') {
  const kp = crypto.generateKeyPairSync('ed25519');
  publicKey = kp.publicKey.export({ type: 'spki', format: 'pem' });
  privateKey = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
  // compute hash and sign name+hash
  meta.hash = sha256HexFromBase64(meta.data);
  meta.sig_algo = 'ed25519-hash';
  const canonical = canonicalizeNameHash(meta);
  const sig = crypto.sign(null, Buffer.from(canonical), { key: privateKey });
  meta.sig = sig.toString('base64');
  meta.pubkey = publicKey;
} else if (algo === 'pss-hash') {
  const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });
  publicKey = kp.publicKey; privateKey = kp.privateKey;
  meta.hash = sha256HexFromBase64(meta.data);
  meta.sig_algo = 'pss-hash';
  const canonical = canonicalizeNameHash(meta);
  const sig = crypto.sign('sha256', Buffer.from(canonical), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
  meta.sig = sig.toString('base64');
  meta.pubkey = publicKey;
} else {
  const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });
  publicKey = kp.publicKey; privateKey = kp.privateKey;
  meta.sig_algo = 'pss';
  const canonical = canonicalize(meta);
  const sig = crypto.sign('sha256', Buffer.from(canonical), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
  meta.sig = sig.toString('base64');
  meta.pubkey = publicKey;
}

// Security checks: ensure canonical used for signing does not include sig or pubkey
if (meta.sig && meta.pubkey) {
  // basic sanity: remove sig/pubkey before canonicalizing for verification
}

const outDir = path.join(__dirname, '..', 'examples', 'static');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, 'example.signed.wasm.json');
fs.writeFileSync(outPath, JSON.stringify(meta, null, 2));
console.log('Wrote signed wasm json to', outPath);
console.log('Signed', name, 'size (bytes):', Buffer.from(meta.data,'base64').length);
