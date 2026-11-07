const fs = require('fs');
const crypto = require('node:crypto');
const path = require('path');

function canonicalize(obj) {
  const keys = ['name','data','hash','hmac','sig_algo'];
  const canonical = {};
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) canonical[k]=obj[k];
  canonical.sig_algo = obj.sig_algo || 'pss';
  return JSON.stringify(canonical);
}

const p = path.join(__dirname, '..', 'examples', 'static', 'example.signed.wasm.json');
const meta = JSON.parse(fs.readFileSync(p,'utf8'));
console.log('Loaded meta keys:', Object.keys(meta));
const canonical = canonicalize(meta);
console.log('Canonical:', canonical);
const sig = Buffer.from(meta.sig, 'base64');
const pub = meta.pubkey;
if (!pub) { console.error('No pubkey in meta'); process.exit(2); }
const ok = crypto.verify('sha256', Buffer.from(canonical,'utf8'), {
  key: pub,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
}, sig);
console.log('Signature valid (pss):', ok);
process.exit(ok?0:1);
