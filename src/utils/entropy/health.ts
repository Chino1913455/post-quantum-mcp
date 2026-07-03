/**
 * Continuous entropy-source health tests.
 *
 * Two NIST SP 800-90B online tests, which are the correct tools for monitoring
 * a *raw entropy source* in real time (catch a stuck/biased/failing source):
 *   - Repetition Count Test (RCT, SP 800-90B 4.4.1)
 *   - Adaptive Proportion Test (APT, SP 800-90B 4.4.2)
 *
 * Plus the lightweight panel from the VerisSuite `true-rng` design
 * (chi-squared byte frequency, max repetition, bit proportion) for parity with
 * that project's `EntropyPool.health_check`.
 *
 * These run on RAW samples. Conditioned CSPRNG output will pass trivially;
 * the point is to validate hardware entropy BEFORE it is trusted.
 */
import { critBinom } from './mathfns.js';

export interface HealthTest {
  name: string;
  passed: boolean;
  detail: Record<string, number | boolean>;
}

export interface HealthReport {
  passed: boolean;
  sampleCount: number;
  tests: HealthTest[];
}

export interface HealthOptions {
  /** Assessed min-entropy per 8-bit sample (bits). Full-entropy bytes ≈ 8. */
  minEntropyPerSample?: number;
  /** Per-test false-positive rate. SP 800-90B recommends ~2^-20. */
  alpha?: number;
  /** APT window size (SP 800-90B uses 512 for non-binary sources). */
  aptWindow?: number;
}

/**
 * Repetition Count Test: fail if any byte value repeats C or more times in a
 * row, where C = 1 + ceil(-log2(alpha) / H).
 */
export function repetitionCountTest(samples: Uint8Array, H: number, alpha: number): HealthTest {
  const cutoff = 1 + Math.ceil(-Math.log2(alpha) / H);
  let maxRun = samples.length > 0 ? 1 : 0;
  let run = 1;
  for (let i = 1; i < samples.length; i++) {
    run = samples[i] === samples[i - 1] ? run + 1 : 1;
    if (run > maxRun) maxRun = run;
  }
  return {
    name: 'SP800-90B Repetition Count',
    passed: maxRun < cutoff,
    detail: { maxRun, cutoff, minEntropyPerSample: H },
  };
}

/**
 * Adaptive Proportion Test: in each window of W samples, count how often the
 * window's first sample recurs; fail if it reaches the binomial cutoff for the
 * assumed min-entropy (most-likely-symbol probability 2^-H).
 */
export function adaptiveProportionTest(
  samples: Uint8Array,
  H: number,
  alpha: number,
  windowSize: number,
): HealthTest {
  const p = Math.pow(2, -H);
  const cutoff = critBinom(windowSize, p, 1 - alpha) + 1;
  let worstCount = 0;
  let failed = false;
  for (let start = 0; start + windowSize <= samples.length; start += windowSize) {
    const a = samples[start];
    let count = 0;
    for (let i = start; i < start + windowSize; i++) if (samples[i] === a) count++;
    if (count > worstCount) worstCount = count;
    if (count >= cutoff) failed = true;
  }
  return {
    name: 'SP800-90B Adaptive Proportion',
    passed: !failed,
    detail: { worstCount, cutoff, windowSize, minEntropyPerSample: H },
  };
}

/**
 * true-rng parity panel: chi-squared byte frequency (≈255 DOF), max repetition,
 * and overall bit proportion. Mirrors EntropyPool.health_check.
 */
export function quickHealthPanel(samples: Uint8Array): HealthTest[] {
  const n = samples.length;

  // Chi-squared over byte frequencies.
  const freq = new Array(256).fill(0);
  for (const b of samples) freq[b]++;
  const expected = n / 256;
  let chiSq = 0;
  for (const f of freq) chiSq += ((f - expected) * (f - expected)) / expected;
  // Rough acceptance band for 255 DOF (matches true-rng's 200<χ²<320).
  const chiPass = chiSq > 200 && chiSq < 320;

  // Max consecutive repetition.
  let maxRepeat = n > 0 ? 1 : 0;
  let cur = 1;
  for (let i = 1; i < n; i++) {
    cur = samples[i] === samples[i - 1] ? cur + 1 : 1;
    if (cur > maxRepeat) maxRepeat = cur;
  }

  // Bit proportion of ones.
  let ones = 0;
  for (const b of samples) ones += popcount(b);
  const proportion = ones / (n * 8);

  return [
    { name: 'Byte frequency (chi-squared)', passed: chiPass, detail: { chiSquared: round(chiSq, 1) } },
    { name: 'Repetition', passed: maxRepeat < 10, detail: { maxRepeat } },
    { name: 'Bit proportion', passed: proportion > 0.45 && proportion < 0.55, detail: { proportion: round(proportion, 4) } },
  ];
}

/** Run the full health panel on a sample of raw entropy bytes. */
export function runHealthTests(samples: Uint8Array, opts: HealthOptions = {}): HealthReport {
  const H = opts.minEntropyPerSample ?? 8;
  const alpha = opts.alpha ?? Math.pow(2, -20);
  const aptWindow = opts.aptWindow ?? 512;

  const tests: HealthTest[] = [repetitionCountTest(samples, H, alpha)];
  if (samples.length >= aptWindow) {
    tests.push(adaptiveProportionTest(samples, H, alpha, aptWindow));
  }
  if (samples.length >= 64) tests.push(...quickHealthPanel(samples));

  return {
    passed: tests.every((t) => t.passed),
    sampleCount: samples.length,
    tests,
  };
}

function popcount(b: number): number {
  let c = 0;
  while (b) {
    b &= b - 1;
    c++;
  }
  return c;
}

function round(x: number, dp: number): number {
  const f = Math.pow(10, dp);
  return Math.round(x * f) / f;
}
