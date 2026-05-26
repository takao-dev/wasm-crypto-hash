const fs = require('node:fs');
const path = require('node:path');
const child = require('node:child_process');

const dir = path.resolve(__dirname, '..', 'wasm');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.wasm.json'));

const provider = (process.env.WASM_KMS_PROVIDER || '').toLowerCase();
if (!provider) {
  console.error('WASM_KMS_PROVIDER not set; skipping KMS signing');
  process.exit(0);
}

function canonicalize(json, algo) {
  const canonicalKeys = ['name', 'data', 'hash', 'hmac', 'sig_algo'];
  const canonicalObj = {};
  for (const k of canonicalKeys) {
    if (Object.prototype.hasOwnProperty.call(json, k)) {
      canonicalObj[k] = json[k];
    }
  }
  canonicalObj.sig_algo = algo;
  return JSON.stringify(canonicalObj);
}

for (const file of files) {
  const full = path.join(dir, file);
  const json = JSON.parse(fs.readFileSync(full, 'utf8'));
  const algo = (process.env.WASM_SIG_ALGO || 'pss').toLowerCase();

  if (provider === 'aws') {
    const keyId = process.env.AWS_KMS_KEY_ID || process.env.WASM_AWS_KMS_KEY_ID;
    if (!keyId) {
      console.error('AWS_KMS_KEY_ID or WASM_AWS_KMS_KEY_ID not set; cannot sign');
      process.exit(1);
    }

    const canonical = canonicalize(json, algo);

    // Use aws cli via stdin; require aws CLI v2 available in CI
    try {
      const args = [
        'kms',
        'sign',
        '--key-id',
        keyId,
        '--signing-algorithm',
        'RSASSA_PSS_SHA_256',
        '--message',
        'fileb://-',
        '--message-type',
        'RAW',
        '--output',
        'text',
        '--query',
        'Signature',
      ];
      const out = child.execFileSync('aws', args, { input: Buffer.from(canonical, 'utf8') });
      const sig = out.toString('utf8').trim();
      json.sig = sig;
      json.sig_algo = 'pss';
      fs.writeFileSync(full, JSON.stringify(json));
      console.log('signed', file, 'via AWS KMS');
    } catch (e) {
      console.error('AWS KMS sign failed for', file, e.message || e);
      process.exit(1);
    }

  } else if (provider === 'gcp') {
    // For GCP, require gcloud CLI and KMS resource in WASM_GCP_KMS_RESOURCE
    const resource = process.env.WASM_GCP_KMS_RESOURCE || process.env.GCP_KMS_RESOURCE;
    if (!resource) {
      console.error('WASM_GCP_KMS_RESOURCE or GCP_KMS_RESOURCE not set; cannot sign');
      process.exit(1);
    }

    const canonical = canonicalize(json, algo);
    // Use gcloud CLI asymmetric-sign. The exact flags differ; use --location/--keyring/--key if resource is split.
    try {
      // If resource looks like projects/.../locations/.../keyRings/.../cryptoKeys/.../cryptoKeyVersions/...
      // gcloud accepts: gcloud kms keys versions asymmetric-sign --location=... --keyring=... --key=... --version=... --digest-file=-
      // Fallback to using the generic `gcloud kms keys versions asymmetric-sign --key` with message file via stdin
      const tmp = require('os').tmpdir();
      const tmpfile = path.join(tmp, `canon-${Date.now()}.json`);
      fs.writeFileSync(tmpfile, canonical);
      // Try the high-level command; users must adapt resource parsing if needed
      const args = ['kms', 'keys', 'versions', 'asymmetric-sign', '--key', resource, '--location', process.env.WASM_GCP_KMS_LOCATION || 'global', '--keyring', process.env.WASM_GCP_KMS_KEYRING || '', '--quiet', '--format', 'get(signature)', '--message-file', tmpfile];
      // If keyring is empty remove those args
      let finalArgs = args;
      if (!process.env.WASM_GCP_KMS_KEYRING) {
        finalArgs = ['kms', 'keys', 'versions', 'asymmetric-sign', '--key', resource, '--location', process.env.WASM_GCP_KMS_LOCATION || 'global', '--quiet', '--format', 'get(signature)', '--message-file', tmpfile];
      }
      const out = child.execFileSync('gcloud', finalArgs, { env: process.env });
      const sig = out.toString('utf8').trim();
      fs.unlinkSync(tmpfile);
      json.sig = sig;
      json.sig_algo = 'pss';
      fs.writeFileSync(full, JSON.stringify(json));
      console.log('signed', file, 'via GCP KMS (gcloud)');
    } catch (e) {
      console.error('GCP KMS sign failed for', file, e.message || e);
      process.exit(1);
    }

  } else {
    console.error('Unsupported WASM_KMS_PROVIDER:', provider);
    process.exit(1);
  }
}

console.log('done');
