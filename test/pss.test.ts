import { canonicalizeWasmForSigning, verifyRsaSignatureBase64 } from '../lib/util';
const crypto = require('node:crypto');

test('RSASSA-PSS sign and verify (Node path)', async () => {
  // generate ephemeral keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });

  const sample = {
    name: 'test-wasm',
    data: Buffer.from([0x00, 0x61, 0x62, 0x63]).toString('base64'),
    hash: 'deadbeef',
  };

  const canonical = canonicalizeWasmForSigning(sample as any);
  // sign with PSS
  const sigBuf = crypto.sign('sha256', Buffer.from(canonical), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  });
  const sigBase64 = sigBuf.toString('base64');

  const ok = await verifyRsaSignatureBase64(canonical, sigBase64, publicKey, 'pss');
  expect(ok).toBe(true);
});
