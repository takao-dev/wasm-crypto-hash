// Dev worker with simple caching: compiled modules and imported public keys are cached
addEventListener('fetch', event => {
  event.respondWith(handle(event.request));
});

// caches to reduce repeated work
const moduleCache = new Map(); // key -> WebAssembly.Module
const cryptoKeyCache = new Map(); // pubPem -> CryptoKey
const canonicalCache = new Map(); // key -> Uint8Array canonical bytes

async function handle(req) {
  const url = new URL(req.url);
  const wasmJsonUrl = url.searchParams.get('wasm');
  const skipSig = url.searchParams.get('skipSig') === '1';

  // fetch metadata or use embedded minimal wasm
  let meta;
  if (!wasmJsonUrl) {
    meta = {
      name: 'embedded-min-wasm',
      data: 'AGFzbQEAAAA=',
      hash: '',
      sig: null,
      sig_algo: 'pss'
    };
  } else {
    const res = await fetch(wasmJsonUrl);
    if (!res.ok) return new Response('Failed to fetch wasm json', { status: 502 });
    meta = await res.json();
  }

  const cacheKey = wasmJsonUrl || meta.name || 'embedded';

  // signature verification (cache importKey and canonical bytes)
  if (!skipSig && meta.sig) {
    let canonical = canonicalCache.get(cacheKey);
    if (!canonical) {
      canonical = canonicalizeForSigning(meta);
      canonicalCache.set(cacheKey, canonical);
    }

    // Use only injected trusted public key in dev as well to mirror production policy
    const pubPem = globalThis.__WASM_SIG_PUBKEY || null;
    if (!pubPem) return new Response('No public key configured', { status: 500 });

    let cryptoKey = cryptoKeyCache.get(pubPem);
    if (!cryptoKey) {
      try {
        cryptoKey = await importSpkiKey(pubPem);
        cryptoKeyCache.set(pubPem, cryptoKey);
      } catch (e) {
        return new Response('Failed to import public key: '+e.message, { status: 500 });
      }
    }

    const sig = base64ToUint8(meta.sig);
    const ok = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, cryptoKey, sig.buffer, canonical);
    if (!ok) return new Response('Signature verification failed', { status: 403 });
  }

  const wasmBytes = base64ToUint8(meta.data);

  const t0 = Date.now();
  try {
    let module = moduleCache.get(cacheKey);
    let compileMs = 0;
    if (!module) {
      const tCompile0 = Date.now();
      module = await WebAssembly.compile(wasmBytes);
      compileMs = Date.now() - tCompile0;
      moduleCache.set(cacheKey, module);
    }
    const tInst0 = Date.now();
    const inst = await WebAssembly.instantiate(module, {});
    const instantiateMs = Date.now() - tInst0;
    const body = {
      ok: true,
      compileMs,
      instantiateMs,
      totalMs: Date.now() - t0
    };
    return new Response(JSON.stringify(body), { status: 200 });
  } catch (e) {
    return new Response('WASM instantiate failed: ' + e.message, { status: 500 });
  }
}

function canonicalizeForSigning(obj) {
  const keys = ['name','data','hash','hmac','sig_algo'];
  const canonical = {};
  for (const k of keys) if (Object.prototype.hasOwnProperty.call(obj, k)) canonical[k]=obj[k];
  canonical.sig_algo = obj.sig_algo || 'pss';
  return new TextEncoder().encode(JSON.stringify(canonical));
}

function base64ToUint8(b64) {
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

async function importSpkiKey(pem) {
  const pemBody = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
  const der = base64ToUint8(pemBody);
  return await crypto.subtle.importKey('spki', der.buffer, { name: 'RSA-PSS', hash: { name: 'SHA-256' } }, false, ['verify']);
}
