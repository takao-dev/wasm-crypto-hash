const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'lib');
let creates = [];
for (const f of fs.readdirSync(dir)) {
  if (!f.endsWith('.ts')) continue;
  const txt = fs.readFileSync(path.join(dir, f), 'utf8');
  const re = /export function (create[A-Za-z0-9_]+)/g;
  let m;
  while ((m = re.exec(txt)) !== null) {
    creates.push(m[1]);
  }
}
creates.sort();
console.log('lib create functions', creates.length, creates);
