// Local dev Worker: read public key from file and verify embedded example
import { canonicalizeWasmForSigning, verifyRsaSignatureBase64 } from '../../lib/util.js';
import fs from 'fs';
import path from 'path';

export default {
  async fetch() {
    try {
      const metaPath = path.join(new URL('.', import.meta.url).pathname, '../../examples/static/example.signed.wasm.json');
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));

      const pubPath = path.join(process.cwd(), 'package/hash-wasm/examples/worker/pubkey.pem');
      if (!fs.existsSync(pubPath)) return new Response('pubkey.pem missing', { status: 500 });
      const pub = fs.readFileSync(pubPath, 'utf8');

      const canonical = canonicalizeWasmForSigning(meta);
      const ok = await verifyRsaSignatureBase64(canonical, meta.sig, pub, meta.sig_algo || 'pss');
      return new Response(JSON.stringify({ valid: ok }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(String(e), { status: 500 });
    }
  }
};
