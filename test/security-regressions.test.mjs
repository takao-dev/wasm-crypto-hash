import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { webcrypto, createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
const require = createRequire(import.meta.url);
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', {configurable:true,value:webcrypto});
const api = require('../dist/lib/index.js');
const {fetchAndInstantiateWasm} = require('../dist/lib/remoteWasmLoader.js');
const {canonicalizeWasmForSigning} = require('../dist/lib/util.js');
const {WASMInterface} = require('../dist/lib/WASMInterface.js');
const embedded = require('../dist/wasm/sha256.wasm.json');
const nativePqc = await webcrypto.subtle.generateKey('ML-DSA-65',true,['sign','verify']).then(()=>typeof webcrypto.subtle.encapsulateBits === 'function',()=>false);
const hex = s => new Uint8Array(Buffer.from(s,'hex'));
const view = bytes => { const out = new Uint8Array(bytes.length+8); out.set(bytes,3); return out.subarray(3,3+bytes.length); };

test('AES-KW RFC3394 vector, arbitrary key sizes and offset views', async()=>{
 const kek=hex('000102030405060708090a0b0c0d0e0f'), key=hex('00112233445566778899aabbccddeeff');
 const expected=hex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5');
 assert.deepEqual(await api.aesKeyWrap(view(kek),view(key)),expected);
 assert.deepEqual(await api.aesKeyUnwrap(view(kek),view(expected)),key);
 const wide=new Uint8Array(40).fill(42), wrapped=await api.aesKeyWrap(kek,wide);
 assert.notDeepEqual(wrapped.subarray(8),wide);
 assert.deepEqual(await api.aesKeyUnwrap(kek,wrapped),wide);
 await assert.rejects(()=>api.aesKeyUnwrap(kek,new Uint8Array(24).fill(23)));
 await assert.rejects(()=>api.aesKeyUnwrap(new Uint8Array(16).fill(9),expected));
 const tampered=new Uint8Array(expected); tampered[10]^=1;
 await assert.rejects(()=>api.aesKeyUnwrap(kek,tampered));
 await assert.rejects(()=>api.aesKeyWrap(new Uint8Array(15),key));
});

test('crypto capability failures never produce fallback keys or classical PQC', async()=>{
 const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto');
 Object.defineProperty(globalThis,'crypto',{configurable:true,value:{subtle:{
  importKey:async()=>{throw new Error('unsupported');},
  generateKey:async()=>{throw new Error('unsupported');}
 }}});
 try {
  await assert.rejects(()=>api.aesKeyWrap(new Uint8Array(16),new Uint8Array(16)),/unsupported/);
  await assert.rejects(()=>api.aesKeyUnwrap(new Uint8Array(16),new Uint8Array(24)),/unsupported/);
  await assert.rejects(()=>api.generateMlDsaKeyPair(),/unsupported/);
  await assert.rejects(()=>api.generatePqcHybridKeyPair(),/ML-KEM/);
 } finally {Object.defineProperty(globalThis,'crypto',descriptor);}
});

test('BIP39 official English entropy/seed vectors and strict dictionary validation',async()=>{
 const phrase='abandon '.repeat(11)+'about';
 assert.equal(api.BIP39_ENGLISH.length,2048);
 assert.equal(await api.entropyToMnemonic(new Uint8Array(16)),phrase);
 assert.equal(await api.entropyToMnemonic(new Uint8Array(16).fill(255)),'zoo '.repeat(11)+'wrong');
 assert.equal(await api.entropyToMnemonic(new Uint8Array(32)),'abandon '.repeat(23)+'art');
 assert.equal(Buffer.from(await api.mnemonicToSeed(phrase,'TREZOR')).toString('hex'),
 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');
 await assert.rejects(()=>api.entropyToMnemonic(new Uint8Array(16),api.BIP39_ENGLISH.slice(0,128)),/2048/);
 await assert.rejects(()=>api.entropyToMnemonic(new Uint8Array(16),Array(2048).fill('same')),/2048/);
 await assert.rejects(()=>api.generateMnemonic(160),/strength/);
});

test('real native ML-DSA interoperates and authenticates only each supplied view',{skip:!nativePqc},async()=>{
 const pair=await api.generateMlDsaKeyPair(), full=new TextEncoder().encode('admin=true');
 const sig=await api.mlDsaSign(view(full),view(pair.privateKey));
 const nativeKey=await webcrypto.subtle.importKey('spki',pair.publicKey,'ML-DSA-65',false,['verify']);
 assert.equal(await webcrypto.subtle.verify('ML-DSA-65',nativeKey,sig,full),true);
 assert.equal(await api.mlDsaVerify(view(full),view(sig),view(pair.publicKey)),true);
 assert.equal(await api.mlDsaVerify(full.subarray(0,5),sig,pair.publicKey),false);
 const short=full.subarray(2,5), shortSig=await api.mlDsaSign(short,pair.privateKey);
 assert.equal(await api.mlDsaVerify(new Uint8Array(short),shortSig,pair.publicKey),true);
 assert.equal(await api.mlDsaVerify(full,shortSig,pair.publicKey),false);
 const legacy=await webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const legacyPublic=new Uint8Array(await webcrypto.subtle.exportKey('spki',legacy.publicKey));
 await assert.rejects(()=>api.mlDsaVerify(full,new Uint8Array(64),legacyPublic));
});

test('hybrid KEM contains actual native ML-KEM material and binds both components',{skip:!nativePqc},async()=>{
 const pair=await api.generatePqcHybridKeyPair();
 const encapsulated=await api.pqcEncapsulate(view(pair.publicKey));
 assert.deepEqual(await api.pqcDecapsulate(view(encapsulated.ciphertext),view(pair.privateKey)),encapsulated.sharedSecret);
 const split=bytes=>{const n=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(6);return [bytes.slice(10,10+n),bytes.slice(10+n)];};
 const [,pqPrivate]=split(pair.privateKey), [xPublic,pqCiphertext]=split(encapsulated.ciphertext);
 assert.equal(xPublic.length,32); assert.equal(pqCiphertext.length,1088);
 const nativePrivate=await webcrypto.subtle.importKey('pkcs8',pqPrivate,'ML-KEM-768',false,['decapsulateBits']);
 assert.equal((await webcrypto.subtle.decapsulateBits('ML-KEM-768',nativePrivate,pqCiphertext)).byteLength,32);
 const tampered=new Uint8Array(encapsulated.ciphertext);tampered[tampered.length-1]^=1;
 assert.notDeepEqual(await api.pqcDecapsulate(tampered,pair.privateKey),encapsulated.sharedSecret);
 const other=await api.generatePqcHybridKeyPair();
 assert.notDeepEqual(await api.pqcDecapsulate(encapsulated.ciphertext,other.privateKey),encapsulated.sharedSecret);
 await assert.rejects(()=>api.pqcEncapsulate(new Uint8Array(32)),/envelope/);
 await assert.rejects(()=>api.pqcDecapsulate(encapsulated.ciphertext.subarray(0,50),pair.privateKey));
});

test('remote WASM pins apply to JSON and binary, signatures and HMAC fail closed',async()=>{
 const wasm=new Uint8Array([0,97,115,109,1,0,0,0]);
 const pin=createHash('sha256').update(wasm).digest('hex');
 const originalFetch=globalThis.fetch, oldHmac=globalThis.__WASM_HMAC_KEY, oldPub=globalThis.__WASM_SIG_PUBKEY;
 delete globalThis.__WASM_HMAC_KEY;delete globalThis.__WASM_SIG_PUBKEY;
 let json=true, container={data:Buffer.from(wasm).toString('base64')};
 globalThis.fetch=async()=>new Response(json?JSON.stringify(container):wasm,{headers:{'Content-Type':json?'application/json':'application/wasm'}});
 try {
  for (const format of [true,false]) {
   json=format;
   assert.ok(await fetchAndInstantiateWasm('https://example.invalid/a.wasm',{sha256:pin}) instanceof WebAssembly.Instance);
   await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{sha256:'0'.repeat(64)}),/mismatch/);
   await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{hmac:'bad'}),/key is required/);
   await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{sig:'bad'}),/key is required/);
   await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm'),/Trusted/);
  }
  globalThis.__WASM_HMAC_KEY=Buffer.from('synthetic-hmac-test-key').toString('base64');
  const hmac=createHmac('sha256',Buffer.from(globalThis.__WASM_HMAC_KEY,'base64')).update(wasm).digest('base64');
  json=true;
  assert.ok(await fetchAndInstantiateWasm('https://example.invalid/a.wasm',{hmac}) instanceof WebAssembly.Instance);
  await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{hmac:'bad'}),/HMAC verification/);
  const keys=generateKeyPairSync('rsa',{modulusLength:2048});
  const pubKey=keys.publicKey.export({type:'spki',format:'pem'});
  await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{sha256:pin},{},{pubKey}),/signature is required/);
  container={...container,name:'test',sig_algo:'pkcs1'};
  container.sig=sign('sha256',canonicalizeWasmForSigning(container),keys.privateKey).toString('base64');
  assert.ok(await fetchAndInstantiateWasm('https://example.invalid/a.wasm',{}, {},{pubKey}) instanceof WebAssembly.Instance);
  container.name='tampered';
  await assert.rejects(()=>fetchAndInstantiateWasm('https://example.invalid/a.wasm',{}, {},{pubKey}),/verification failed/);
  json=false;
  const signature=sign('sha256',wasm,keys.privateKey).toString('base64');
  assert.ok(await fetchAndInstantiateWasm('https://example.invalid/a.wasm',{sig:signature,sig_algo:'pkcs1'},{},{pubKey}) instanceof WebAssembly.Instance);
 } finally {
  globalThis.fetch=originalFetch;
  if(oldHmac===undefined)delete globalThis.__WASM_HMAC_KEY;else globalThis.__WASM_HMAC_KEY=oldHmac;
  if(oldPub===undefined)delete globalThis.__WASM_SIG_PUBKEY;else globalThis.__WASM_SIG_PUBKEY=oldPub;
 }
});

test('embedded WASM validates each policy and content even after cache warmup',async()=>{
 await WASMInterface({...embedded},32);
 await assert.rejects(()=>WASMInterface({...embedded,sha256:'0'.repeat(64)},32),/mismatch/);
 await assert.rejects(()=>WASMInterface({...embedded,hmac:'bad'},32),/HMAC key/);
 await assert.rejects(()=>WASMInterface({...embedded,sig:'bad'},32),/public key/);
 const keys=generateKeyPairSync('rsa',{modulusLength:2048});
 const pubKey=keys.publicKey.export({type:'spki',format:'pem'});
 await assert.rejects(()=>WASMInterface({...embedded},32,{pubKey}),/signature is required/);
 const signed={...embedded,sig_algo:'pkcs1'};
 signed.sig=sign('sha256',canonicalizeWasmForSigning(signed),keys.privateKey).toString('base64');
 await WASMInterface(signed,32,{pubKey,allowSigAlgos:['pkcs1']});
 await assert.rejects(()=>WASMInterface(signed,32,{pubKey,allowSigAlgos:['pss']}),/algorithm/);
 const changed={...embedded,data:Buffer.from([0,97,115,109,1,0,0,0]).toString('base64')};
 await assert.rejects(()=>WASMInterface(changed,32),/mismatch/);
});
