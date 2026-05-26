#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const dir = path.resolve(__dirname, '..', 'wasm');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.wasm.json'));

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

async function signWithAws(keyId, message) {
  const { KMSClient, SignCommand } = require('@aws-sdk/client-kms');
  const client = new KMSClient({});
  const params = {
    KeyId: keyId,
    Message: Buffer.from(message, 'utf8'),
    SigningAlgorithm: 'RSASSA_PSS_SHA_256',
    MessageType: 'RAW'
  };
  const cmd = new SignCommand(params);
  const resp = await client.send(cmd);
  return Buffer.from(resp.Signature).toString('base64');
}

async function signWithGcp(resourceName, message) {
  const { KeyManagementServiceClient } = require('@google-cloud/kms');
  const client = new KeyManagementServiceClient();
  // For GCP, asymmetricSign expects a digest; compute SHA-256 of message
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update(Buffer.from(message, 'utf8')).digest();
  const request = {
    name: resourceName,
    digest: { sha256: hash }
  };
  const [result] = await client.asymmetricSign(request);
  return result.signature.toString('base64');
}

async function main() {
  const provider = (process.env.WASM_KMS_PROVIDER || '').toLowerCase();
  if (!provider) {
    console.error('WASM_KMS_PROVIDER not set; skipping KMS signing');
    process.exit(0);
  }

  for (const file of files) {
    const full = path.join(dir, file);
    const json = JSON.parse(fs.readFileSync(full, 'utf8'));
    const algo = (process.env.WASM_SIG_ALGO || 'pss').toLowerCase();
    const canonical = canonicalize(json, algo);

    try {
      let sig;
      if (provider === 'aws') {
        const keyId = process.env.AWS_KMS_KEY_ID || process.env.WASM_AWS_KMS_KEY_ID;
        if (!keyId) throw new Error('AWS_KMS_KEY_ID not set');
        sig = await signWithAws(keyId, canonical);
      } else if (provider === 'gcp') {
        const resource = process.env.WASM_GCP_KMS_RESOURCE || process.env.GCP_KMS_RESOURCE;
        if (!resource) throw new Error('WASM_GCP_KMS_RESOURCE not set');
        sig = await signWithGcp(resource, canonical);
      } else {
        throw new Error('Unsupported provider: ' + provider);
      }

      json.sig = sig;
      json.sig_algo = 'pss';
      fs.writeFileSync(full, JSON.stringify(json));
      console.log('signed', file, 'via', provider);
    } catch (e) {
      console.error('signing failed for', file, e.message || e);
      process.exit(1);
    }
  }

  console.log('done');
}

main().catch((e) => { console.error(e); process.exit(1); });
