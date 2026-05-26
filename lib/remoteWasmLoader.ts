import { computeSHA256Hex, computeHmacBase64, verifyRsaSignatureBase64, decodeBase64, canonicalizeWasmForSigning, timingSafeEqualString } from './util';

export type WasmMeta = {
  sha256?: string;
  hmac?: string;
  sig?: string;
};

export async function fetchAndInstantiateWasm(url: string, meta: WasmMeta = {}, importObject: any = {}, opts: { pubKey?: string } = {}): Promise<WebAssembly.Instance> {
  if (typeof fetch === 'undefined') throw new Error('fetch is not available in this environment');

  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch WASM from ${url}: ${res.status}`);

  // attempt streaming compile if available
    if ((WebAssembly as any).compileStreaming && res.body) {
    // but we still need to verify before instantiation if metadata present
    if (!meta.sha256 && !meta.hmac && !meta.sig) {
      const module = await (WebAssembly as any).compileStreaming(res) as WebAssembly.Module;
      const instance = await WebAssembly.instantiate(module as WebAssembly.Module, importObject) as unknown as WebAssembly.Instance;
      return instance;
    }
  }

  // If the URL looks like a .wasm.json or the response is JSON, treat it as metadata container
  const contentType = res.headers.get('content-type') || '';
  if (url.endsWith('.wasm.json') || contentType.indexOf('application/json') !== -1) {
    const fullMeta = await res.json();
    // fullMeta should contain 'data' (base64), 'name', 'hash', optional 'sig', 'sig_algo', 'hmac'
    if (fullMeta.sig) {
      const pub = opts && opts.pubKey ? opts.pubKey : (typeof globalThis !== 'undefined' ? (globalThis as any).__WASM_SIG_PUBKEY : null);
      if (pub) {
        const canonical = canonicalizeWasmForSigning(fullMeta as any);
        const sigAlgo = (fullMeta as any).sig_algo ? (fullMeta as any).sig_algo : 'pss';
        const ok = await verifyRsaSignatureBase64(canonical, fullMeta.sig as string, pub, sigAlgo as any);
        if (!ok) throw new Error('WASM RSA signature verification failed');
      }
    }

    // decode base64 data
    const bytes = decodeBase64(fullMeta.data as string);
    const module = await WebAssembly.compile(bytes.buffer as ArrayBuffer);
    const instance = await WebAssembly.instantiate(module as WebAssembly.Module, importObject) as unknown as WebAssembly.Instance;
    return instance;
  }

  const buf = await res.arrayBuffer();
  const bytes = new Uint8Array(buf);

  // verify sha256 if present
  if (meta.sha256) {
    const calc = await computeSHA256Hex(bytes);
    if (calc !== meta.sha256) throw new Error('WASM binary SHA-256 mismatch');
  }

  // verify hmac if present and runtime key available
  if (meta.hmac) {
    const g: any = typeof globalThis !== 'undefined' ? globalThis : (typeof global !== 'undefined' ? global : window);
    const runtimeKey = g && g.__WASM_HMAC_KEY ? g.__WASM_HMAC_KEY : null;
    if (runtimeKey) {
      const calc = await computeHmacBase64(bytes, runtimeKey);
      if (!timingSafeEqualString(calc, meta.hmac)) throw new Error('WASM HMAC verification failed');
    }
  }

  // verify signature if present and pubkey available
  if (meta.sig) {
    const g: any = typeof globalThis !== 'undefined' ? globalThis : (typeof global !== 'undefined' ? global : window);
    const pub = g && g.__WASM_SIG_PUBKEY ? g.__WASM_SIG_PUBKEY : null;
      if (pub) {
        const sigAlgo = (meta as any).sig_algo ? (meta as any).sig_algo : 'pss';
        const ok = await verifyRsaSignatureBase64(bytes, meta.sig as string, pub, sigAlgo as any);
      if (!ok) throw new Error('WASM RSA signature verification failed');
    }
  }

  const module = await WebAssembly.compile(bytes.buffer as ArrayBuffer);
  const instance = await WebAssembly.instantiate(module as WebAssembly.Module, importObject) as unknown as WebAssembly.Instance;
  return instance;
}
