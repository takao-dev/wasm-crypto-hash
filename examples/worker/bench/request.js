const http = require('http');
const { performance } = require('perf_hooks');

const url = 'http://127.0.0.1:8787/?skipSig=1';
const N = 20;

function requestOnce() {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    http.get(url, res => {
      res.on('data', ()=>{});
      res.on('end', ()=>{
        const t1 = performance.now();
        resolve(t1 - t0);
      });
    }).on('error', reject);
  });
}

(async () => {
  const times = [];
  for (let i=0;i<N;i++) {
    try {
      const ms = await requestOnce();
      times.push(ms);
      process.stdout.write(`${i+1}/${N}: ${ms.toFixed(2)} ms\n`);
    } catch (e) {
      console.error('request error', e);
      break;
    }
  }
  const sum = times.reduce((a,b)=>a+b,0);
  const avg = sum / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);
  console.log(`\nResults (N=${times.length}): avg=${avg.toFixed(2)}ms min=${min.toFixed(2)}ms max=${max.toFixed(2)}ms`);
})();
