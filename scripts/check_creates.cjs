const api = require('../dist/index.umd.js');
const keys = Object.keys(api).filter(k => k.startsWith('create')).sort();
console.log('dist keys', keys.length, keys);
(async () => {
  for (const key of keys) {
    try {
      console.log('calling', key);
      const result = api[key]();
      if (result && typeof result.then === 'function') {
        const resolved = await result;
        console.log('-> resolved', key, !!resolved);
      } else {
        console.log('-> returned sync', key, !!result);
      }
    } catch (e) {
      console.error('ERROR calling', key, e && e.stack ? e.stack : e);
    }
  }
})();
