/**
 * Entropy & secure-randomness toolkit tests.
 *
 * Asserts real properties: sampling is unbiased and in-range, the extractor
 * respects the Leftover Hash Lemma, the SP 800-90B health tests CATCH a stuck
 * or biased source (not just pass good data), and the NIST SP 800-22 suite
 * passes CSPRNG output while FAILING a structured (non-random) sequence.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';

import * as sampling from '../utils/entropy/sampling';
import { ToeplitzExtractor, bytesToBits } from '../utils/entropy/extractor';
import { runHealthTests, repetitionCountTest, adaptiveProportionTest } from '../utils/entropy/health';
import { runAllTests, frequencyMonobit } from '../utils/entropy/nist-sp800-22';
import { erfc, igamc, normalCdf } from '../utils/entropy/mathfns';
import { EntropyService, OsCsprngSource } from '../utils/entropy/sources';
import { SecureRandomHandler, QuantumRandomHandler } from '../utils/quantum-random';

const mockLogger = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);

describe('secure sampling', () => {
  it('randomUniformInt stays in range and covers the space', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 5000; i++) {
      const v = sampling.randomUniformInt(10);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(10);
      seen.add(v);
    }
    expect(seen.size).toBe(10); // all residues appear
  });

  it('randomUniformInt is approximately unbiased (chi-squared)', () => {
    const q = 16;
    const N = 16000;
    const counts = new Array(q).fill(0);
    for (let i = 0; i < N; i++) counts[sampling.randomUniformInt(q)]++;
    const exp = N / q;
    let chi = 0;
    for (const c of counts) chi += ((c - exp) * (c - exp)) / exp;
    // 15 DOF: P(chi^2 > 37.7) ~ 0.001 — generous bound, effectively never flakes.
    expect(chi).toBeLessThan(37.7);
  });

  it('randomBigIntBelow stays in [0, max)', () => {
    const max = (1n << 200n) + 12345n;
    for (let i = 0; i < 500; i++) {
      const v = sampling.randomBigIntBelow(max);
      expect(v >= 0n && v < max).toBe(true);
    }
  });

  it('randomUnitFloat in [0,1); centeredBinomial in [-eta,eta]', () => {
    for (let i = 0; i < 2000; i++) {
      const f = sampling.randomUnitFloat();
      expect(f).toBeGreaterThanOrEqual(0);
      expect(f).toBeLessThan(1);
      const cb = sampling.centeredBinomial(3);
      expect(cb).toBeGreaterThanOrEqual(-3);
      expect(cb).toBeLessThanOrEqual(3);
    }
  });

  it('discreteGaussian has ~correct standard deviation', () => {
    const sigma = 8;
    const n = 8000;
    let sum = 0;
    let sumsq = 0;
    for (let i = 0; i < n; i++) {
      const x = sampling.discreteGaussian(sigma);
      sum += x;
      sumsq += x * x;
    }
    const std = Math.sqrt(sumsq / n - (sum / n) ** 2);
    expect(std).toBeGreaterThan(sigma * 0.8);
    expect(std).toBeLessThan(sigma * 1.2);
  });

  it('randomPermutation is a true permutation', () => {
    const p = sampling.randomPermutation(50);
    expect(new Set(p).size).toBe(50);
    expect(Math.min(...p)).toBe(0);
    expect(Math.max(...p)).toBe(49);
  });
});

describe('special functions', () => {
  it('erfc / normalCdf / igamc behave at known points', () => {
    expect(erfc(0)).toBeCloseTo(1, 6);
    expect(erfc(10)).toBeCloseTo(0, 6);
    expect(normalCdf(0)).toBeCloseTo(0.5, 6);
    expect(normalCdf(1.96)).toBeCloseTo(0.975, 3);
    expect(igamc(1, 0)).toBeCloseTo(1, 6);
    expect(igamc(1, 50)).toBeCloseTo(0, 6);
  });
});

describe('Toeplitz extractor', () => {
  it('Leftover Hash Lemma gate: accepts safe params, rejects over-extraction', () => {
    const safe = new ToeplitzExtractor({ inputBits: 2048, outputBits: 256, minEntropyRate: 0.5 });
    expect(safe.leftoverHashLemmaCheck().satisfiesLHL).toBe(true);

    const greedy = new ToeplitzExtractor({ inputBits: 512, outputBits: 256, minEntropyRate: 0.5 });
    // 512*0.5 = 256 min-entropy, minus 2*32 margin -> max ~192 < 256 requested.
    expect(greedy.leftoverHashLemmaCheck().satisfiesLHL).toBe(false);
  });

  it('conditioned output has the requested length and passes monobit', () => {
    const raw = new Uint8Array(256);
    for (let i = 0; i < raw.length; i++) raw[i] = sampling.randomUniformInt(256);
    const ex = new ToeplitzExtractor({ inputBits: raw.length * 8, outputBits: 128 * 8, minEntropyRate: 0.9 });
    const out = ex.extractBytes(raw);
    expect(out.length).toBe(128);
    expect(frequencyMonobit(bytesToBits(out)).pValue).toBeGreaterThan(0.001);
  });
});

describe('SP 800-90B health tests', () => {
  it('pass on CSPRNG bytes', () => {
    const buf = new Uint8Array(4096);
    for (let i = 0; i < buf.length; i++) buf[i] = sampling.randomUniformInt(256);
    expect(runHealthTests(buf).passed).toBe(true);
  });

  it('Repetition Count Test catches a stuck source', () => {
    const stuck = new Uint8Array(1024); // all zeros = stuck
    expect(repetitionCountTest(stuck, 8, 2 ** -20).passed).toBe(false);
  });

  it('Adaptive Proportion Test catches a heavily biased source', () => {
    const biased = new Uint8Array(2048);
    for (let i = 0; i < biased.length; i++) biased[i] = sampling.randomUnitFloat() < 0.9 ? 7 : sampling.randomUniformInt(256);
    expect(adaptiveProportionTest(biased, 8, 2 ** -20, 512).passed).toBe(false);
  });
});

describe('NIST SP 800-22 suite', () => {
  it('CSPRNG output passes (allowing at most one statistical fluke)', () => {
    const buf = new Uint8Array(20000);
    for (let i = 0; i < buf.length; i++) buf[i] = sampling.randomUniformInt(256);
    const results = runAllTests(bytesToBits(buf));
    for (const r of results) {
      expect(r.pValue).toBeGreaterThanOrEqual(0);
      expect(r.pValue).toBeLessThanOrEqual(1);
    }
    const passed = results.filter((r) => r.passed).length;
    expect(passed).toBeGreaterThanOrEqual(results.length - 1);
  });

  it('a structured (non-random) sequence fails', () => {
    const bits: number[] = [];
    for (let i = 0; i < 20000; i++) bits.push(i % 2); // 0101...
    const results = runAllTests(bits);
    expect(results.some((r) => !r.passed)).toBe(true);
  });
});

describe('EntropyService + handler', () => {
  let logger: Logger;
  let cache: NodeCache;
  beforeEach(() => { logger = mockLogger(); cache = new NodeCache(); });

  it('service reports a real source and correct length', () => {
    const svc = new EntropyService([new OsCsprngSource()]);
    const r = svc.generate(48);
    expect(r.bytes.length).toBe(48);
    expect(r.source).toBe('os-csprng');
    expect(r.health?.passed).toBe(true);
  });

  it('handler generate() returns honest metadata', async () => {
    const h = new SecureRandomHandler(logger, cache);
    const res = await h.generate({ bytes: 32, format: 'hex' });
    const data = JSON.parse(res.content[0].text);
    expect(data.random).toMatch(/^[0-9a-f]{64}$/);
    expect(['os-csprng', 'os-hwrng']).toContain(data.source);
    expect(data.note).toMatch(/Not quantum/i);
  });

  it('handler validate() passes CSPRNG and fails all-zeros', async () => {
    const h = new SecureRandomHandler(logger, cache);
    const good = JSON.parse((await h.validate({ bytes: 8192 })).content[0].text);
    expect(good.testsPassed).toBeGreaterThanOrEqual(good.testsRun - 1);

    const zeros = Buffer.alloc(2048).toString('hex');
    const bad = JSON.parse((await h.validate({ data: zeros, format: 'hex' })).content[0].text);
    expect(bad.overallPass).toBe(false);
  });

  it('back-compat: QuantumRandomHandler is the same handler', () => {
    expect(QuantumRandomHandler).toBe(SecureRandomHandler);
  });
});
