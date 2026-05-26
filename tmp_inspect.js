const m = require('./dist/index.umd.js');
console.log(Object.keys(m));
// expose some functions
console.log('has canonicalizeWasmForSigning:', typeof m.canonicalizeWasmForSigning);
console.log('has verifyRsaSignatureBase64:', typeof m.verifyRsaSignatureBase64);
