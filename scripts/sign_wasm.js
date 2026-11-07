const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const dir = path.resolve(__dirname, '..', 'wasm');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.wasm.json'));

const privPem = process.env.WASM_SIG_PRIV_PEM;
if (!privPem) {
  console.error('WASM_SIG_PRIV_PEM not set; skipping signing');
  process.exit(0);
}

// allow selecting signing algorithm via env: 'pss' (recommended default) or 'pkcs1'
const algo = (process.env.WASM_SIG_ALGO || 'pss').toLowerCase();

for (const file of files) {
  const full = path.join(dir, file);
  const json = JSON.parse(fs.readFileSync(full, 'utf8'));
  // Build canonical object for signing: include keys in deterministic order
  const canonicalKeys = ['name', 'data', 'hash', 'hmac', 'sig_algo'];
  const canonicalObj = {};
  for (const k of canonicalKeys) {
    if (Object.prototype.hasOwnProperty.call(json, k)) {
      canonicalObj[k] = json[k];
    }
  }
  // Ensure sig_algo reflects selected algo
  canonicalObj.sig_algo = algo;

  const canonicalString = JSON.stringify(canonicalObj);
  const canonicalBytes = Buffer.from(canonicalString, 'utf8');

  let sig;
  if (algo === 'pss') {
    const sigBuf = crypto.sign('sha256', canonicalBytes, {
      key: privPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });
    sig = sigBuf.toString('base64');
  } else {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(canonicalBytes);
    sig = sign.sign(privPem, 'base64');
  }

  json.sig = sig;
  json.sig_algo = algo;
  fs.writeFileSync(full, JSON.stringify(json));
  console.log('signed', file, 'algo=' + algo);
}

console.log('done');
