import { decodeBase64, timingSafeEqualString, canonicalizeWasmForSigning } from '../lib/util';

describe('util extra tests', () => {
  test('decodeBase64 normalizes URL-safe input after manual normalization', () => {
    // URL-safe base64 for 'foo' -> 'Zm9v' (same) but with '-' and '_' variants
    const urlSafe = 'YWJjLWRf'; // 'abc-d_'
    // normalize: '-'->'+', '_'->'/' and pad
    const normalized = urlSafe.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice((urlSafe.length + 3) % 4);
    const decoded = decodeBase64(normalized);
    expect(Buffer.from(decoded).toString('ascii').startsWith('abc')).toBe(true);
  });

  test('timingSafeEqualString compares correctly', () => {
    expect(timingSafeEqualString('abc', 'abc')).toBe(true);
    expect(timingSafeEqualString('abc', 'abd')).toBe(false);
    expect(timingSafeEqualString('', '')).toBe(true);
    expect(timingSafeEqualString('a', '')).toBe(false);
  });

  test('canonicalization preserves key order and fields', () => {
    const meta = { sig_algo: 'pss', name: 'n', data: 'd', hmac: 'h', hash: 'x', extra: 'skip' } as any;
    const out = canonicalizeWasmForSigning(meta);
    const s = Buffer.from(out).toString('utf8');
    // keys should appear in the canonical order
    expect(s.indexOf('"name"') < s.indexOf('"data"')).toBe(true);
    expect(s.indexOf('"data"') < s.indexOf('"hash"')).toBe(true);
    expect(s.indexOf('"hash"') < s.indexOf('"hmac"')).toBe(true);
    expect(s).not.toContain('"extra"');
  });
});
