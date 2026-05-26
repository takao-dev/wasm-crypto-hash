// Cloudflare Worker example: verifies a signed .wasm.json and returns status
// Usage: deploy as Worker with a secret `WASM_SIG_PUBKEY` containing PEM public key

import wasmJson from "../../wasm/example.signed.wasm.json";
import { canonicalizeWasmForSigning, verifyRsaSignatureBase64, computeHmacBase64 } from "../../lib/util";

export default {
  async fetch(request) {
    try {
      const pubKeyPem = globalThis.__WASM_SIG_PUBKEY || WASM_SIG_PUBKEY; // inject via wrangler or secrets
      if (!pubKeyPem) {
        return new Response('WASM_SIG_PUBKEY not set', { status: 500 });
      }

      // In this example, we use the embedded example JSON imported above.
      const meta = wasmJson;

      // Recompute HMAC if WASM_HMAC_KEY present (optional)
      if (meta.hmac && globalThis.__WASM_HMAC_KEY) {
        const hmacBase64 = await computeHmacBase64(globalThis.__WASM_HMAC_KEY, await fetch(meta.data).then(r=>r.arrayBuffer()));
        if (hmacBase64 !== meta.hmac) {
          return new Response('HMAC mismatch', { status: 400 });
        }
      }

      // Canonicalize and verify signature
      const canonical = canonicalizeWasmForSigning(meta);
      const valid = await verifyRsaSignatureBase64(canonical, meta.sig, pubKeyPem, meta.sig_algo || 'pss');

      return new Response(JSON.stringify({ valid }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (err) {
      return new Response(String(err), { status: 500 });
    }
  }
};
