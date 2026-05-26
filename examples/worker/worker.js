// Cloudflare Worker PoC: fetch signed .wasm.json, verify PSS signature using WebCrypto, then instantiate

addEventListener('fetch', event => {
  event.respondWith(handle(event.request));
});

// caches to improve performance: compiled modules and imported public keys
const moduleCache = new Map();
const cryptoKeyCache = new Map();
const canonicalCache = new Map();

async function handle(req) {
  const url = new URL(req.url);
  const wasmJsonUrl = url.searchParams.get('wasm') || 'https://example.com/example.wasm.json';

  const res = await fetch(wasmJsonUrl);
  if (!res.ok) return new Response('Failed to fetch wasm json', { status: 502 });
  const meta = await res.json();
  if (!meta.sig) return new Response('No signature in metadata', { status: 400 });

  const cacheKey = wasmJsonUrl || meta.name || 'remote';

  // canonical bytes cache
  let canonical = canonicalCache.get(cacheKey);
  if (!canonical) {
    canonical = canonicalizeForSigning(meta);
    canonicalCache.set(cacheKey, canonical);
  }

  // Use only an injected trusted public key; do NOT accept pubkey from metadata in production
  const pubPem = (globalThis.__WASM_SIG_PUBKEY) || null;
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

  // decode wasm
  const wasmBytes = base64ToUint8(meta.data);
  try {
    let module = moduleCache.get(cacheKey);
    if (!module) {
      module = await WebAssembly.compile(wasmBytes);
      moduleCache.set(cacheKey, module);
    }
    const inst = await WebAssembly.instantiate(module, {});
    return new Response('WASM loaded and instantiated', { status: 200 });
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
