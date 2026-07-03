/**
 * NTT correctness: the negacyclic NTT product MUST equal the schoolbook
 * product bit-for-bit. This is the "no compromise" guarantee — the optimization
 * is only sound if it computes exactly the same ring element.
 */
import { describe, it, expect } from '@jest/globals';
import { NegacyclicNTT, getNTT } from '../utils/lattice/ntt';
import * as sampling from '../utils/entropy/sampling';

const Q = 12289;

/** Reference schoolbook negacyclic multiply mod (X^n + 1) mod q. */
function schoolbook(a: number[], b: number[], n: number, q: number): number[] {
  const r = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const idx = i + j;
      if (idx < n) r[idx] = (r[idx] + a[i] * b[j]) % q;
      else r[idx - n] = (((r[idx - n] - a[i] * b[j]) % q) + q) % q;
    }
  }
  return r;
}

function randomPoly(n: number, q: number): number[] {
  return Array.from({ length: n }, () => sampling.randomModInt(q));
}

describe('NegacyclicNTT', () => {
  for (const n of [32, 64, 128, 256]) {
    it(`n=${n}: NTT product equals schoolbook product (random inputs)`, () => {
      const ntt = getNTT(n, Q);
      expect(ntt.usable).toBe(true);
      for (let trial = 0; trial < 20; trial++) {
        const a = randomPoly(n, Q);
        const b = randomPoly(n, Q);
        expect(ntt.multiply(a, b)).toEqual(schoolbook(a, b, n, Q));
      }
    });
  }

  it('respects the negacyclic relation X^n = -1', () => {
    const n = 64;
    const ntt = getNTT(n, Q);
    // a = X^{n-1}, b = X  ->  X^n = -1  ->  coeffs = [-1, 0, ...] = [q-1, 0, ...]
    const a = new Array(n).fill(0);
    a[n - 1] = 1;
    const b = new Array(n).fill(0);
    b[1] = 1;
    const prod = ntt.multiply(a, b);
    expect(prod[0]).toBe(Q - 1);
    for (let i = 1; i < n; i++) expect(prod[i]).toBe(0);
  });

  it('multiplicative identity: a * 1 = a', () => {
    const n = 128;
    const ntt = getNTT(n, Q);
    const a = randomPoly(n, Q);
    const one = new Array(n).fill(0);
    one[0] = 1;
    expect(ntt.multiply(a, one)).toEqual(a);
  });

  it('reports unusable for non-NTT-friendly parameters', () => {
    expect(new NegacyclicNTT(48, Q).usable).toBe(false); // not a power of two
    expect(new NegacyclicNTT(32, 7919).usable).toBe(false); // 2n ∤ (q-1)
  });

  it('is substantially faster than schoolbook at n=256 (informational)', () => {
    const n = 256;
    const ntt = getNTT(n, Q);
    const a = randomPoly(n, Q);
    const b = randomPoly(n, Q);
    const iters = 200;

    let t0 = process.hrtime.bigint();
    for (let i = 0; i < iters; i++) schoolbook(a, b, n, Q);
    const schoolNs = Number(process.hrtime.bigint() - t0);

    t0 = process.hrtime.bigint();
    for (let i = 0; i < iters; i++) ntt.multiply(a, b);
    const nttNs = Number(process.hrtime.bigint() - t0);

    // eslint-disable-next-line no-console
    console.log(`n=256 x${iters}: schoolbook=${(schoolNs / 1e6).toFixed(1)}ms ntt=${(nttNs / 1e6).toFixed(1)}ms speedup=${(schoolNs / nttNs).toFixed(1)}x`);
    expect(nttNs).toBeLessThan(schoolNs); // NTT must win at this size
  });
});
