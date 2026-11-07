#!/usr/bin/env node
const fs = require('fs');

function pemToOneLine(pem) {
  return pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\r?\n/g, '').trim();
}

function oneLineToPem(one, header='PUBLIC KEY'){
  const chunks = one.match(/.{1,64}/g) || [];
  return `-----BEGIN ${header}-----\n${chunks.join('\n')}\n-----END ${header}-----\n`;
}

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === 'to-one') {
    const inPath = process.argv[3];
    const outPath = process.argv[4];
    const pem = fs.readFileSync(inPath,'utf8');
    fs.writeFileSync(outPath || (inPath + '.oneline'), pemToOneLine(pem));
    console.log('wrote', outPath || (inPath + '.oneline'));
  } else if (cmd === 'from-one') {
    const inPath = process.argv[3];
    const outPath = process.argv[4];
    const one = fs.readFileSync(inPath,'utf8').trim();
    fs.writeFileSync(outPath || (inPath + '.pem'), oneLineToPem(one));
    console.log('wrote', outPath || (inPath + '.pem'));
  } else {
    console.log('Usage: pem_env_helpers.js to-one <in.pem> [out.oneline]');
    console.log('       pem_env_helpers.js from-one <in.oneline> [out.pem]');
  }
}

module.exports = { pemToOneLine, oneLineToPem };
