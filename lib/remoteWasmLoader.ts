import { computeSHA256Hex, computeHmacBase64, verifyRsaSignatureBase64, decodeBase64, canonicalizeWasmForSigning, timingSafeEqualString } from './util';

export type WasmMeta = {
  sha256?: string;
  hmac?: string;
  /** Detached signature over the decoded WASM bytes, not the JSON envelope. */
  sig?: string;
  sig_algo?: 'pkcs1' | 'pss';
};

/** Apply caller-owned trust requirements to decoded bytes in every response format. */
export async function fetchAndInstantiateWasm(url: string, meta: WasmMeta = {}, importObject: any = {}, opts: { pubKey?: string } = {}): Promise<WebAssembly.Instance> {
  meta = { ...meta };
  const globals: any = typeof globalThis !== 'undefined' ? globalThis : {};
  const pub = opts.pubKey || globals.__WASM_SIG_PUBKEY;
  const hmacKey = globals.__WASM_HMAC_KEY;
  if (!meta.sha256 && !meta.hmac && !meta.sig && !pub) throw new Error('Trusted WASM integrity metadata or a signature public key is required');
  if (meta.sha256 !== undefined && !/^[0-9a-f]{64}$/i.test(meta.sha256)) throw new Error('Invalid WASM SHA-256 pin');
  if (meta.hmac !== undefined && !meta.hmac) throw new Error('Invalid WASM HMAC');
  if (meta.sig !== undefined && !meta.sig) throw new Error('Invalid WASM signature');
  if (meta.hmac && !hmacKey) throw new Error('WASM HMAC key is required');
  if (meta.sig && !pub) throw new Error('WASM signature public key is required');
  if (meta.sig_algo && !['pkcs1', 'pss'].includes(meta.sig_algo)) throw new Error('Unsupported WASM signature algorithm');
  if (typeof fetch === 'undefined') throw new Error('fetch is not available in this environment');
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch WASM from ${url}: ${res.status}`);

  const contentType = (res.headers.get('content-type') || '').toLowerCase();
  const isJson = new URL(url, 'https://localhost/').pathname.endsWith('.wasm.json') || contentType.includes('application/json');
  let container: any;
  let bytes: Uint8Array;
  if (isJson) {
    container = await res.json();
    if (!container || typeof container !== 'object' || typeof container.data !== 'string') throw new Error('Invalid WASM JSON container');
    bytes = decodeBase64(container.data);
  } else {
    bytes = new Uint8Array(await res.arrayBuffer());
  }

  if (meta.sha256 && (await computeSHA256Hex(bytes)) !== meta.sha256.toLowerCase()) throw new Error('WASM binary SHA-256 mismatch');
  if (meta.hmac && !timingSafeEqualString(await computeHmacBase64(bytes, hmacKey), meta.hmac)) throw new Error('WASM HMAC verification failed');
  if (meta.sig && !await verifyRsaSignatureBase64(bytes, meta.sig, pub, meta.sig_algo || 'pss')) throw new Error('WASM RSA signature verification failed');
  // A configured public key means signatures are mandatory, including JSON with a stripped sig.
  if (pub && !meta.sig) {
    if (!container || typeof container.sig !== 'string' || !container.sig) throw new Error('WASM signature is required');
    const algorithm = container.sig_algo || 'pss';
    if (!['pkcs1', 'pss'].includes(algorithm)) throw new Error('Unsupported WASM signature algorithm');
    if (!await verifyRsaSignatureBase64(canonicalizeWasmForSigning(container), container.sig, pub, algorithm)) throw new Error('WASM RSA signature verification failed');
  }
  const module = await WebAssembly.compile(new Uint8Array(bytes).buffer);
  return WebAssembly.instantiate(module, importObject);
}
