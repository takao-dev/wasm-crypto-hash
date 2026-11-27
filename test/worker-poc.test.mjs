import assert from 'node:assert/strict';
import { test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { handleWorkerRequest } from '../examples/worker/worker.core.mjs';

const manifestUrl = 'https://cdn.example.test/example.wasm.json';

async function createKeys() {
  const pair = await webcrypto.subtle.generateKey({
    name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'
  }, true, ['sign', 'verify']);
  const der = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey)).toString('base64');
  const pem = `-----BEGIN PUBLIC KEY-----\n${der}\n-----END PUBLIC KEY-----`;
  return { ...pair, pem };
}

async function signedManifest(privateKey) {
  const meta = { name: 'minimal', data: 'AGFzbQEAAAA=', hash: 'test-hash', sig_algo: 'pss' };
  const canonical = {};
  for (const key of ['name', 'data', 'hash', 'hmac', 'sig_algo']) {
    if (Object.hasOwn(meta, key)) canonical[key] = meta[key];
  }
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const signature = await webcrypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, bytes);
  return { ...meta, sig: Buffer.from(signature).toString('base64') };
}

const environment = publicKeyPem => ({ __WASM_MANIFEST_URL: manifestUrl, __WASM_SIG_PUBKEY: publicKeyPem });
const request = url => ({ method: 'GET', url });

test('worker ignores request-selected URLs and instantiates only a signed configured artifact', async () => {
  const keys = await createKeys();
  const meta = await signedManifest(keys.privateKey);
  const fetched = [];
  const response = await handleWorkerRequest(
    request('https://worker.example/?wasm=https%3A%2F%2Fevil.example%2Funsigned.json&skipSig=1'),
    environment(keys.pem),
    async (input, options) => {
      fetched.push([String(input), options.redirect]);
      return new Response(JSON.stringify(meta), { status: 200 });
    }
  );

  assert.equal(response.status, 200);
  assert.equal((await response.json()).ok, true);
  assert.deepEqual(fetched, [[manifestUrl, 'error']]);
});

test('worker rejects unsigned and forged metadata before compiling WASM', async () => {
  const keys = await createKeys();
  const unsigned = await handleWorkerRequest(
    request('https://worker.example/?skipSig=1'), environment(keys.pem),
    async () => new Response(JSON.stringify({ name: 'unsigned', data: 'AGFzbQEAAAA=', sig_algo: 'pss' }))
  );
  assert.equal(unsigned.status, 400);

  const forged = await signedManifest(keys.privateKey);
  forged.name = 'forged';
  const invalidSignature = await handleWorkerRequest(
    request('https://worker.example/'), environment(keys.pem),
    async () => new Response(JSON.stringify(forged))
  );
  assert.equal(invalidSignature.status, 403);
});

test('worker rejects non-HTTPS artifact configuration and oversized manifest responses', async () => {
  const keys = await createKeys();
  let fetchCalls = 0;
  const fetchImpl = async () => {
    fetchCalls++;
    return new Response('{}', { status: 200, headers: { 'content-length': '999999999' } });
  };

  const invalidUrl = await handleWorkerRequest(request('https://worker.example/'), {
    ...environment(keys.pem), __WASM_MANIFEST_URL: 'http://cdn.example.test/example.wasm.json'
  }, fetchImpl);
  assert.equal(invalidUrl.status, 500);
  assert.equal(fetchCalls, 0);

  const oversized = await handleWorkerRequest(request('https://worker.example/'), environment(keys.pem), fetchImpl);
  assert.equal(oversized.status, 502);
  assert.equal(fetchCalls, 1);
});

test('worker aborts a manifest fetch when its deadline expires', async () => {
  let sawAbortedSignal = false;
  const response = await handleWorkerRequest(request('https://worker.example/'), environment('key'), async (_url, options) => {
    sawAbortedSignal = options.signal.aborted;
    throw new Error('aborted');
  }, callback => {
    callback();
    return 1;
  }, () => {});

  assert.equal(sawAbortedSignal, true);
  assert.equal(response.status, 502);
});
