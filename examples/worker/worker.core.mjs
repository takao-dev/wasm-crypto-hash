// Shared Cloudflare Worker handler: fetch one configured artifact and require a valid PSS signature.

const MAX_MANIFEST_BYTES = 24 * 1024 * 1024;
const MAX_WASM_BYTES = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES = 8192;
const FETCH_TIMEOUT_MS = 10_000;

// Keep only the current artifact and key in each isolate.
let cachedModule = null;
let cachedPublicKeyPem = null;
let cachedPublicKey = null;

async function handle(req, env, fetcher = fetch, setTimer = setTimeout, clearTimer = clearTimeout) {
  if (req.method !== 'GET') return new Response('Method not allowed', { status: 405 });

  const manifestUrl = env?.__WASM_MANIFEST_URL;
  const publicKeyPem = env?.__WASM_SIG_PUBKEY;
  if (typeof manifestUrl !== 'string' || typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    return new Response('Worker artifact URL and verification key must be configured', { status: 500 });
  }

  let trustedManifestUrl;
  try {
    trustedManifestUrl = new URL(manifestUrl);
    if (trustedManifestUrl.protocol !== 'https:' || trustedManifestUrl.username || trustedManifestUrl.password) {
      throw new Error('Invalid artifact URL');
    }
  } catch {
    return new Response('Configured artifact URL must be an HTTPS URL', { status: 500 });
  }

  let meta;
  try {
    const response = await fetchBounded(trustedManifestUrl.href, MAX_MANIFEST_BYTES, FETCH_TIMEOUT_MS, fetcher, setTimer, clearTimer);
    if (!response.ok) return new Response('Failed to fetch configured artifact', { status: 502 });
    meta = JSON.parse(new TextDecoder().decode(response.bytes));
  } catch {
    return new Response('Configured artifact request failed or exceeded its size limit', { status: 502 });
  }

  if (!meta || typeof meta !== 'object' || Array.isArray(meta) ||
      typeof meta.name !== 'string' || meta.name.length < 1 || meta.name.length > 256 ||
      typeof meta.data !== 'string' || typeof meta.sig !== 'string' || meta.sig_algo !== 'pss' ||
      meta.data.length > Math.ceil(MAX_WASM_BYTES / 3) * 4 + 4 ||
      meta.sig.length > Math.ceil(MAX_SIGNATURE_BYTES / 3) * 4 + 4) {
    return new Response('Artifact metadata is invalid or exceeds size limits', { status: 400 });
  }

  let cryptoKey;
  try {
    if (cachedPublicKeyPem !== publicKeyPem || !cachedPublicKey) {
      cachedPublicKey = await importSpkiKey(publicKeyPem);
      cachedPublicKeyPem = publicKeyPem;
    }
    cryptoKey = cachedPublicKey;
    const signature = base64ToUint8(meta.sig, MAX_SIGNATURE_BYTES);
    const canonical = canonicalizeForSigning(meta);
    const valid = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 }, cryptoKey, signature, canonical
    );
    if (!valid) return new Response('Signature verification failed', { status: 403 });
  } catch {
    return new Response('Artifact signature could not be verified', { status: 403 });
  }

  let wasmBytes;
  try {
    wasmBytes = base64ToUint8(meta.data, MAX_WASM_BYTES);
    if (wasmBytes.byteLength === 0) throw new Error('Empty artifact');
  } catch {
    return new Response('Artifact data is invalid or exceeds size limits', { status: 400 });
  }

  const startedAt = Date.now();
  try {
    const signatureKey = `${trustedManifestUrl.href}:${meta.sig}`;
    let module = cachedModule?.key === signatureKey ? cachedModule.module : null;
    let compileMs = 0;
    if (!module) {
      const compileStartedAt = Date.now();
      module = await WebAssembly.compile(wasmBytes);
      compileMs = Date.now() - compileStartedAt;
      cachedModule = { key: signatureKey, module };
    }
    const instantiateStartedAt = Date.now();
    await WebAssembly.instantiate(module, {});
    return new Response(JSON.stringify({
      ok: true,
      compileMs,
      instantiateMs: Date.now() - instantiateStartedAt,
      totalMs: Date.now() - startedAt
    }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
  } catch {
    return new Response('WASM compile or instantiate failed', { status: 400 });
  }
}

async function fetchBounded(url, maxBytes, timeoutMs, fetcher, setTimer, clearTimer) {
  const controller = new AbortController();
  const timeout = setTimer(() => controller.abort(), timeoutMs);
  try {
    const response = await fetcher(url, { signal: controller.signal, redirect: 'error' });
    if (!response.ok) {
      await response.body?.cancel();
      return { ok: false, bytes: new Uint8Array() };
    }

    const declaredLength = response.headers.get('content-length');
    if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maxBytes)) {
      await response.body?.cancel();
      throw new RangeError('Response exceeds size limit');
    }

    const reader = response.body?.getReader();
    if (!reader) {
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > maxBytes) throw new RangeError('Response exceeds size limit');
      return { ok: true, bytes };
    }

    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RangeError('Response exceeds size limit');
      }
      chunks.push(value);
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { ok: true, bytes };
  } finally {
    clearTimer(timeout);
  }
}

function canonicalizeForSigning(obj) {
  const keys = ['name', 'data', 'hash', 'hmac', 'sig_algo'];
  const canonical = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) canonical[key] = obj[key];
  }
  return new TextEncoder().encode(JSON.stringify(canonical));
}

function base64ToUint8(value, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes / 3) * 4 + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError('Invalid base64 data');
  }
  const raw = atob(value);
  if (raw.length > maxBytes) throw new RangeError('Decoded data exceeds size limit');
  const bytes = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index++) bytes[index] = raw.charCodeAt(index);
  return bytes;
}

async function importSpkiKey(pem) {
  if (typeof pem !== 'string' || pem.length > 16_384) throw new TypeError('Invalid public key');
  const pemBody = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
  const der = base64ToUint8(pemBody, 8192);
  return crypto.subtle.importKey('spki', der, { name: 'RSA-PSS', hash: { name: 'SHA-256' } }, false, ['verify']);
}

export { handle as handleWorkerRequest };
export default {
  fetch(request, env) {
    return handle(request, env);
  }
};
