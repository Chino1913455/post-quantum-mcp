/**
 * NIST SP 800-22 statistical test suite (practical subset).
 *
 * Ported from the VerisSuite `true-rng` design's NISTValidator. These are
 * batch tests for evaluating the quality of an RNG over a large sample (as
 * opposed to the online SP 800-90B health tests in health.ts). A p-value below
 * the 0.01 significance level indicates the sequence is unlikely to be random.
 *
 * Implemented: Frequency (Monobit), Block Frequency, Runs, Longest Run of Ones,
 * Cumulative Sums, Approximate Entropy, Serial. These cover the failure modes a
 * conditioned-CSPRNG or hardware source is most likely to exhibit and have
 * unambiguous, well-conditioned p-value formulas. Tests requiring very long
 * streams (Linear Complexity, Random Excursions, Maurer's Universal) are
 * intentionally omitted to keep results meaningful on modest samples.
 */
import { erfc, igamc, normalCdf } from './mathfns.js';

export interface NistTestResult {
  name: string;
  pValue: number;
  passed: boolean;
  note?: string;
}

const ALPHA = 0.01;
const pass = (p: number) => p >= ALPHA;

/** Test 1 — Frequency (Monobit). */
export function frequencyMonobit(bits: number[]): NistTestResult {
  const n = bits.length;
  let s = 0;
  for (const b of bits) s += 2 * b - 1;
  const sObs = Math.abs(s) / Math.sqrt(n);
  const p = erfc(sObs / Math.SQRT2);
  return { name: 'Frequency (Monobit)', pValue: p, passed: pass(p) };
}

/** Test 2 — Block Frequency. */
export function blockFrequency(bits: number[], M = 128): NistTestResult {
  const n = bits.length;
  const N = Math.floor(n / M);
  if (N === 0) return { name: 'Block Frequency', pValue: 0, passed: false, note: 'insufficient data' };
  let sum = 0;
  for (let i = 0; i < N; i++) {
    let ones = 0;
    for (let j = 0; j < M; j++) ones += bits[i * M + j];
    const pi = ones / M;
    sum += (pi - 0.5) * (pi - 0.5);
  }
  const chiSq = 4 * M * sum;
  const p = igamc(N / 2, chiSq / 2);
  return { name: 'Block Frequency', pValue: p, passed: pass(p) };
}

/** Test 3 — Runs. */
export function runs(bits: number[]): NistTestResult {
  const n = bits.length;
  let ones = 0;
  for (const b of bits) ones += b;
  const pi = ones / n;
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return { name: 'Runs', pValue: 0, passed: false, note: 'failed monobit prerequisite' };
  }
  let v = 1;
  for (let i = 1; i < n; i++) if (bits[i] !== bits[i - 1]) v++;
  const num = Math.abs(v - 2 * n * pi * (1 - pi));
  const den = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const p = erfc(num / den);
  return { name: 'Runs', pValue: p, passed: pass(p) };
}

/** Test 4 — Longest Run of Ones in a Block (M=8 variant, requires n>=128). */
export function longestRunOfOnes(bits: number[]): NistTestResult {
  const n = bits.length;
  if (n < 128) return { name: 'Longest Run of Ones', pValue: 0, passed: false, note: 'requires n>=128' };
  const M = 8;
  const N = 16;
  const K = 3;
  const piProb = [0.2148, 0.3672, 0.2305, 0.1875];
  const v = [0, 0, 0, 0];
  for (let i = 0; i < N; i++) {
    let longest = 0;
    let cur = 0;
    for (let j = 0; j < M; j++) {
      if (bits[i * M + j] === 1) {
        cur++;
        if (cur > longest) longest = cur;
      } else cur = 0;
    }
    // Buckets: <=1, 2, 3, >=4
    if (longest <= 1) v[0]++;
    else if (longest === 2) v[1]++;
    else if (longest === 3) v[2]++;
    else v[3]++;
  }
  let chiSq = 0;
  for (let i = 0; i <= K; i++) {
    const exp = N * piProb[i];
    chiSq += ((v[i] - exp) * (v[i] - exp)) / exp;
  }
  const p = igamc(K / 2, chiSq / 2);
  return { name: 'Longest Run of Ones', pValue: p, passed: pass(p) };
}

/** Test 5 — Cumulative Sums (forward mode). */
export function cumulativeSums(bits: number[]): NistTestResult {
  const n = bits.length;
  let s = 0;
  let z = 0;
  for (const b of bits) {
    s += 2 * b - 1;
    if (Math.abs(s) > z) z = Math.abs(s);
  }
  if (z === 0) return { name: 'Cumulative Sums', pValue: 1, passed: true };
  const sqrtN = Math.sqrt(n);
  let sum1 = 0;
  for (let k = Math.floor((-n / z + 1) / 4); k <= Math.floor((n / z - 1) / 4); k++) {
    sum1 += normalCdf(((4 * k + 1) * z) / sqrtN) - normalCdf(((4 * k - 1) * z) / sqrtN);
  }
  let sum2 = 0;
  for (let k = Math.floor((-n / z - 3) / 4); k <= Math.floor((n / z - 1) / 4); k++) {
    sum2 += normalCdf(((4 * k + 3) * z) / sqrtN) - normalCdf(((4 * k + 1) * z) / sqrtN);
  }
  const p = 1 - sum1 + sum2;
  return { name: 'Cumulative Sums', pValue: p, passed: pass(p) };
}

/** Count overlapping m-bit pattern frequencies with wraparound. */
function patternCounts(bits: number[], m: number): number[] {
  if (m === 0) return [bits.length];
  const n = bits.length;
  const counts = new Array(1 << m).fill(0);
  for (let i = 0; i < n; i++) {
    let idx = 0;
    for (let j = 0; j < m; j++) idx = (idx << 1) | bits[(i + j) % n];
    counts[idx]++;
  }
  return counts;
}

function psiSquared(bits: number[], m: number): number {
  if (m <= 0) return 0;
  const n = bits.length;
  const counts = patternCounts(bits, m);
  let sum = 0;
  for (const c of counts) sum += c * c;
  return (Math.pow(2, m) / n) * sum - n;
}

/** Test 6 — Approximate Entropy (block length m). */
export function approximateEntropy(bits: number[], m = 2): NistTestResult {
  const n = bits.length;
  const phi = (mm: number): number => {
    if (mm === 0) return 0;
    const counts = patternCounts(bits, mm);
    let sum = 0;
    for (const c of counts) {
      if (c > 0) {
        const p = c / n;
        sum += p * Math.log(p);
      }
    }
    return sum;
  };
  const apEn = phi(m) - phi(m + 1);
  const chiSq = 2 * n * (Math.log(2) - apEn);
  const p = igamc(Math.pow(2, m - 1), chiSq / 2);
  return { name: 'Approximate Entropy', pValue: p, passed: pass(p) };
}

/** Test 7 — Serial (block length m); reports the lower of the two p-values. */
export function serial(bits: number[], m = 3): NistTestResult {
  const psiM = psiSquared(bits, m);
  const psiM1 = psiSquared(bits, m - 1);
  const psiM2 = psiSquared(bits, m - 2);
  const del1 = psiM - psiM1;
  const del2 = psiM - 2 * psiM1 + psiM2;
  const p1 = igamc(Math.pow(2, m - 2), del1 / 2);
  const p2 = igamc(Math.pow(2, m - 3), del2 / 2);
  const p = Math.min(p1, p2);
  return { name: 'Serial', pValue: p, passed: pass(p), note: `p1=${p1.toFixed(4)} p2=${p2.toFixed(4)}` };
}

/** Run the full implemented subset over a bit sequence. */
export function runAllTests(bits: number[]): NistTestResult[] {
  const results: NistTestResult[] = [frequencyMonobit(bits)];
  if (bits.length >= 128) {
    results.push(blockFrequency(bits, Math.min(128, Math.floor(bits.length / 20) || 1)));
    results.push(longestRunOfOnes(bits));
  }
  results.push(runs(bits));
  results.push(cumulativeSums(bits));
  if (bits.length >= 100) {
    results.push(approximateEntropy(bits, 2));
    results.push(serial(bits, 3));
  }
  return results;
}
