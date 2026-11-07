#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const crypto = require('node:crypto');

function canonicalizeWasmForSigning(obj) {
  const keys = ['name','data','hash','hmac','sig_algo'];
  const canonical = {};
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) canonical[k]=obj[k];
  canonical.sig_algo = obj.sig_algo || 'pss';
  return JSON.stringify(canonical);
}

function canonicalizeNameHashForSigning(name, hash, sig_algo) {
  const canonical = { name, hash, sig_algo: sig_algo || 'pss-hash' };
  return JSON.stringify(canonical);
}

function sha256HexFromBase64(b64) {
  const buf = Buffer.from(b64, 'base64');
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function verifyRsaSignatureBase64(canonicalStr, sigBase64, pubKeyPem, algo='pss'){
  const sig = Buffer.from(sigBase64, 'base64');
  if (algo === 'pss'){
    return crypto.verify('sha256', Buffer.from(canonicalStr), {
      key: pubKeyPem,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, sig);
  }
  // fallback pkcs1
  return crypto.verify('sha256', Buffer.from(canonicalStr), {
    key: pubKeyPem,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  }, sig);
}

async function runBench() {
  const metaPath = path.join(__dirname, '..', 'static', 'example.signed.wasm.json');
  if (!fs.existsSync(metaPath)) {
    console.error('Signed wasm metadata not found:', metaPath);
    process.exitCode = 2;
    return;
  }
  const raw = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const pubkey = raw.pubkey;
  if (!pubkey || !raw.sig) {
    console.error('Missing pubkey or sig in metadata');
    process.exitCode = 3;
    return;
  }

  const runs = parseInt(process.env.BENCH_RUNS || '20', 10);
  const times = [];
  const mode = process.env.BENCH_MODE || 'default';
  const detail = process.env.BENCH_DETAIL === '1';
  if (mode === 'cached') {
    // verify and compile once, then instantiate repeatedly (simulate cached module)
    // verify once
    const t0 = performance.now();
    // for cached mode, compute hash if needed
    let verifyOk = false;
    let verifyMs = 0;
    if ((raw.sig_algo||'').includes('hash')) {
      const tHash0 = performance.now();
      const computedHash = sha256HexFromBase64(raw.data);
      const hashMs = performance.now() - tHash0;
      if (computedHash !== raw.hash) {
        console.error('Hash mismatch: metadata.hash != computed');
        process.exitCode = 4; return;
      }
      const canonicalSmall = canonicalizeNameHashForSigning(raw.name, raw.hash, raw.sig_algo);
      const tVerify0 = performance.now();
      if ((raw.sig_algo||'').startsWith('ed25519')) {
        verifyOk = crypto.verify(null, Buffer.from(canonicalSmall), pubkey, Buffer.from(raw.sig,'base64'));
      } else {
        verifyOk = crypto.verify('sha256', Buffer.from(canonicalSmall), { key: pubkey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, Buffer.from(raw.sig,'base64'));
      }
      verifyMs = performance.now() - tVerify0 + hashMs;
      if (!verifyOk) { console.error('Signature verification failed'); process.exitCode=4; return; }
    } else {
      const tVerify0 = performance.now();
      verifyOk = await verifyRsaSignatureBase64(canonicalizeWasmForSigning(raw), raw.sig, pubkey, raw.sig_algo || 'pss');
      verifyMs = performance.now() - tVerify0;
      if (!verifyOk) { console.error('Signature verification failed'); process.exitCode=4; return; }
    }
    // verified
    const wasmBytes = Buffer.from(raw.data, 'base64');
    const tCompile0 = performance.now();
    const module = await WebAssembly.compile(wasmBytes);
    const compileMs = performance.now() - tCompile0;

    for (let i=0;i<runs;i++) {
      const tInst0 = performance.now();
      const inst = await WebAssembly.instantiate(module, {});
      const instantiateMs = performance.now() - tInst0;
      const totalMs = compileMs + instantiateMs; // verify once
      times.push({ verifyMs: 0, compileMs, instantiateMs, totalMs });
      process.stdout.write(`run ${i+1}/${runs}: ${Math.round(totalMs)} ms\n`);
    }
  } else {
    for (let i=0;i<runs;i++) {
      const tStart = performance.now();
      // 1) compute hash if needed
      let hashMs = 0; let computedHash = null;
      if ((raw.sig_algo||'').includes('hash')) {
        const th0 = performance.now();
        computedHash = sha256HexFromBase64(raw.data);
        hashMs = performance.now() - th0;
        if (computedHash !== raw.hash) { console.error('Hash mismatch'); process.exitCode=4; return; }
      }
      // 2) canonicalize (small)
      const tCanon0 = performance.now();
      const canonStr = ( (raw.sig_algo||'').includes('hash') ) ? canonicalizeNameHashForSigning(raw.name, raw.hash, raw.sig_algo) : canonicalizeWasmForSigning(raw);
      const canonMs = performance.now() - tCanon0;
      // 3) verify
      const tVerify0 = performance.now();
      let ok;
      if ((raw.sig_algo||'').startsWith('ed25519')) {
        ok = crypto.verify(null, Buffer.from(canonStr), pubkey, Buffer.from(raw.sig,'base64'));
      } else if ((raw.sig_algo||'').includes('hash')) {
        ok = crypto.verify('sha256', Buffer.from(canonStr), { key: pubkey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }, Buffer.from(raw.sig,'base64'));
      } else {
        ok = await verifyRsaSignatureBase64(canonStr, raw.sig, pubkey, raw.sig_algo || 'pss');
      }
      const verifyMs = performance.now() - tVerify0 + hashMs + canonMs;
      if (!ok) { console.error('Signature verification failed'); process.exitCode=4; return; }

      // 4) decode base64
      const tDecode0 = performance.now();
      const wasmBytes = Buffer.from(raw.data, 'base64');
      const decodeMs = performance.now() - tDecode0;

      // 5) compile
      const tCompile0 = performance.now();
      const module = await WebAssembly.compile(wasmBytes);
      const compileMs = performance.now() - tCompile0;

      // 6) instantiate
      const tInst0 = performance.now();
      const inst = await WebAssembly.instantiate(module, {});
      const instantiateMs = performance.now() - tInst0;

      const totalMs = verifyMs + decodeMs + compileMs + instantiateMs;
      times.push({ verifyMs, decodeMs, compileMs, instantiateMs, totalMs });
      process.stdout.write(`run ${i+1}/${runs}: ${Math.round(totalMs)} ms\n`);
    }
  }
  const sums = times.reduce((acc,cur)=>{
    acc.verify+=cur.verifyMs; acc.compile+=cur.compileMs; acc.instantiate+=cur.instantiateMs; acc.total+=cur.totalMs; return acc;
  }, {verify:0,compile:0,instantiate:0,total:0});
  const avg = { verify: sums.verify/runs, compile: sums.compile/runs, instantiate: sums.instantiate/runs, total: sums.total/runs };
  const result = { runs, avg, times };
  fs.writeFileSync(path.join(__dirname,'..','static','bench_results.json'), JSON.stringify(result, null, 2));
  console.log('\nSummary avg (ms):', avg);
}

runBench().catch(err=>{console.error(err); process.exitCode=10});
