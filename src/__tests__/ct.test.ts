/**
 * Constant-time primitives + constant-time discrete Gaussian.
 *
 * These tests verify functional correctness (the constant-time routines compute
 * the same values as the obvious branching ones). The constant-time *property*
 * itself is a design guarantee — branchless, no secret-dependent control flow or
 * table indexing — not something a unit test times directly.
 */
import { describe, it, expect } from '@jest/globals';
import { ctMask, ctSelect, ctEqMask, ctIsZeroMask, ctGE, timingSafeEqual } from '../utils/ct';
import { ConstantTimeGaussian } from '../utils/entropy/sampling';

describe('constant-time primitives', () => {
  it('ctMask / ctSelect behave like branching equivalents', () => {
    expect(ctMask(1)).toBe(-1);
    expect(ctMask(0)).toBe(0);
    for (const [m, a, b] of [[1, 0xaa, 0x55], [0, 0xaa, 0x55]] as const) {
      const mask = ctMask(m);
      expect(ctSelect(mask, a, b) >>> 0).toBe((m ? a : b) >>> 0);
    }
  });

  it('ctEqMask / ctIsZeroMask', () => {
    expect(ctEqMask(123, 123)).toBe(-1);
    expect(ctEqMask(123, 124)).toBe(0);
    expect(ctIsZeroMask(0)).toBe(-1);
    expect(ctIsZeroMask(7)).toBe(0);
  });

  it('ctGE matches >=', () => {
    for (const [a, b] of [[5, 3], [3, 5], [4, 4], [0, 0], [1000, 999]] as const) {
      expect(ctGE(a, b)).toBe(a >= b ? 1 : 0);
    }
  });

  it('timingSafeEqual compares correctly', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    expect(timingSafeEqual(a, new Uint8Array([1, 2, 3, 4]))).toBe(true);
    expect(timingSafeEqual(a, new Uint8Array([1, 2, 3, 5]))).toBe(false);
    expect(timingSafeEqual(a, new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe('ConstantTimeGaussian', () => {
  it('produces a centered distribution with ~correct standard deviation', () => {
    const sigma = 8;
    const g = new ConstantTimeGaussian(sigma);
    const n = 8000;
    let sum = 0;
    let sumsq = 0;
    let maxAbs = 0;
    for (let i = 0; i < n; i++) {
      const x = g.sample();
      sum += x;
      sumsq += x * x;
      maxAbs = Math.max(maxAbs, Math.abs(x));
    }
    const mean = sum / n;
    const std = Math.sqrt(sumsq / n - mean * mean);
    expect(Math.abs(mean)).toBeLessThan(1.5); // ~0
    expect(std).toBeGreaterThan(sigma * 0.8);
    expect(std).toBeLessThan(sigma * 1.2);
    expect(maxAbs).toBeLessThanOrEqual(12 * sigma); // within the tau bound
  });
});
