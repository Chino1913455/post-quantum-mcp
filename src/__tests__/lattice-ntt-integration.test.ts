/**
 * Verifies the NTT fast path integrated into the lattice modules
 * (homomorphic-voting RingPoly, lattice-zkp PolynomialRing, IBE PolyRing)
 * produces the EXACT same ring product as the canonical schoolbook convolution.
 *
 * These modules previously had no tests; this is the correctness guarantee that
 * the optimization changed speed only, not results.
 */
import { describe, it, expect } from '@jest/globals';
import { RingPoly } from '../utils/pq-homomorphic-voting';
import { PolynomialRing } from '../algorithms/lattice-zkp';
import { PolyRing } from '../algorithms/identity-based-encryption';
import { getNTT } from '../utils/lattice/ntt';
import * as sampling from '../utils/entropy/sampling';

const Q = 12289;
const N = 256; // NTT-friendly with q=12289

function schoolbook(a: number[], b: number[], n: number, q: number): number[] {
  const c = new Array(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const idx = i + j;
      if (idx < n) c[idx] = (c[idx] + a[i] * b[j]) % q;
      else c[idx - n] = (((c[idx - n] - a[i] * b[j]) % q) + q) % q;
    }
  }
  return c;
}

const rand = (n: number, q: number) => Array.from({ length: n }, () => sampling.randomModInt(q));

describe('NTT integration in lattice modules', () => {
  it('the NTT path is actually engaged for these params', () => {
    expect(getNTT(N, Q).usable).toBe(true);
  });

  it('homomorphic-voting RingPoly.mul matches schoolbook', () => {
    const ring = new RingPoly(N, Q);
    for (let t = 0; t < 12; t++) {
      const a = rand(N, Q);
      const b = rand(N, Q);
      expect(ring.mul(a, b)).toEqual(schoolbook(a, b, N, Q));
    }
  });

  it('lattice-zkp PolynomialRing.mul matches schoolbook', () => {
    const ring = new PolynomialRing(N, Q);
    for (let t = 0; t < 12; t++) {
      const a = rand(N, Q);
      const b = rand(N, Q);
      expect(ring.mul(a, b)).toEqual(schoolbook(a, b, N, Q));
    }
  });

  it('IBE PolyRing.mul matches schoolbook', () => {
    for (let t = 0; t < 12; t++) {
      const a = rand(N, Q);
      const b = rand(N, Q);
      const pa = new PolyRing(a, N, Q);
      const pb = new PolyRing(b, N, Q);
      expect(pa.mul(pb).coeffs).toEqual(schoolbook(a, b, N, Q));
    }
  });
});
