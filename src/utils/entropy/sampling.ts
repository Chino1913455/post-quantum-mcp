/**
 * Cryptographically secure sampling primitives.
 *
 * EVERY source of randomness in this package MUST route through here.
 * `Math.random()` is a non-cryptographic PRNG (xorshift128+) whose output is
 * predictable from a few samples — using it anywhere in a key, nonce, secret,
 * commitment, or rejection-sampling decision is a critical vulnerability.
 *
 * Performance: lattice routines sample hundreds of thousands of coefficients in
 * tight rejection loops. Calling `crypto.randomBytes`/`randomInt` per draw is
 * ~100x slower than Math.random and makes those routines time out. So draws are
 * served from a buffered CSPRNG pool: a 64 KiB block is filled in bulk from the
 * OS CSPRNG and consumed byte-wise. This is exactly as secure as per-call
 * crypto.randomBytes (it is the same CSPRNG stream) but ~100x faster.
 *
 * Hardening notes (tracked, not yet done):
 *   - `discreteGaussian` uses CSPRNG-backed Box–Muller. This removes the
 *     predictable-PRNG flaw, but a side-channel-resistant constant-time
 *     discrete Gaussian (CDT / Knuth–Yao) is a separate item for any signing
 *     path exposed to timing adversaries.
 */
import * as crypto from 'crypto';

// ── Buffered CSPRNG pool ────────────────────────────────────────────────────

const POOL_SIZE = 1 << 16; // 64 KiB
let pool: Buffer = crypto.randomBytes(POOL_SIZE);
let poolOffset = 0;

/** Ensure at least `need` bytes remain in the pool, refilling from the OS CSPRNG. */
function ensure(need: number): void {
  if (poolOffset + need > POOL_SIZE) {
    crypto.randomFillSync(pool);
    poolOffset = 0;
  }
}

/** Take `n` bytes from the pool (or directly from the CSPRNG for large reads). */
function take(n: number): Buffer {
  if (n >= POOL_SIZE) return crypto.randomBytes(n);
  ensure(n);
  const out = pool.subarray(poolOffset, poolOffset + n);
  poolOffset += n;
  return out;
}

// ── Public API ──────────────────────────────────────────────────────────────

/** Raw CSPRNG bytes (always a fresh independent draw). */
export function randomBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new Error(`randomBytes: invalid length ${n}`);
  return new Uint8Array(crypto.randomBytes(n));
}

/**
 * Unbiased uniform integer in [0, maxExclusive) via rejection sampling over the
 * smallest sufficient number of pooled bytes. maxExclusive must be a positive
 * integer < 2^48.
 */
export function randomUniformInt(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error(`randomUniformInt: maxExclusive must be a positive integer, got ${maxExclusive}`);
  }
  if (maxExclusive === 1) return 0;
  if (maxExclusive > 0x1_0000_0000_0000) {
    throw new Error('randomUniformInt: maxExclusive must be < 2^48');
  }
  const bytesNeeded = Math.ceil(Math.log2(maxExclusive) / 8);
  const domain = Math.pow(2, bytesNeeded * 8);
  const maxUnbiased = Math.floor(domain / maxExclusive) * maxExclusive;
  for (;;) {
    const b = take(bytesNeeded);
    let v = 0;
    for (let i = 0; i < bytesNeeded; i++) v = v * 256 + b[i];
    if (v < maxUnbiased) return v % maxExclusive;
  }
}

/** Unbiased uniform integer in [min, max] (inclusive both ends). */
export function randomIntInclusive(min: number, max: number): number {
  if (!Number.isInteger(min) || !Number.isInteger(max) || max < min) {
    throw new Error(`randomIntInclusive: bad range [${min}, ${max}]`);
  }
  return min + randomUniformInt(max - min + 1);
}

/** Alias: unbiased uniform residue in [0, q) for a numeric modulus q < 2^48. */
export function randomModInt(q: number): number {
  return randomUniformInt(q);
}

/**
 * Unbiased uniform bigint in [0, maxExclusive) via rejection sampling.
 * Used for finite-field elements over large primes (e.g. 256-bit Shamir field).
 */
export function randomBigIntBelow(maxExclusive: bigint): bigint {
  if (maxExclusive <= 0n) throw new Error('randomBigIntBelow: maxExclusive must be > 0');
  if (maxExclusive === 1n) return 0n;
  const bits = maxExclusive.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    const buf = take(bytes);
    let v = 0n;
    for (let i = 0; i < bytes; i++) v = (v << 8n) | BigInt(buf[i]);
    v &= mask;
    if (v < maxExclusive) return v;
  }
}

/** Uniform field element in [1, prime) (nonzero), for polynomial coefficients. */
export function randomNonzeroFieldElement(prime: bigint): bigint {
  if (prime <= 1n) throw new Error('randomNonzeroFieldElement: prime must be > 1');
  return randomBigIntBelow(prime - 1n) + 1n;
}

/**
 * Uniform float in [0, 1) with 53 bits of CSPRNG precision.
 * Use for accept/reject probability comparisons (replaces `Math.random() < p`).
 */
export function randomUnitFloat(): number {
  const b = take(8);
  const hi = b.readUInt32BE(0) >>> 5; // 27 bits
  const lo = b.readUInt32BE(4) >>> 6; // 26 bits
  return (hi * 67108864 + lo) / 9007199254740992; // (hi*2^26 + lo) / 2^53
}

/** Continuous Gaussian sample N(0, sigma^2) via CSPRNG-backed Box–Muller. */
export function gaussianFloat(sigma: number): number {
  const u1 = 1 - randomUnitFloat(); // (0,1]
  const u2 = randomUnitFloat();
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2) * sigma;
}

/** Rounded (discrete) Gaussian sample, CSPRNG-backed. See file header caveat. */
export function discreteGaussian(sigma: number): number {
  return Math.round(gaussianFloat(sigma));
}

/**
 * Centered Binomial Distribution sample (Kyber/ML-KEM noise), CSPRNG-backed.
 * Returns a value in [-eta, eta].
 */
export function centeredBinomial(eta: number): number {
  const bits = randomBits(2 * eta);
  let a = 0;
  let b = 0;
  for (let i = 0; i < eta; i++) a += bits[i];
  for (let i = 0; i < eta; i++) b += bits[eta + i];
  return a - b;
}

/** Array of `n` fair random bits (0/1) from the pooled CSPRNG. */
export function randomBits(n: number): number[] {
  const bytes = take(Math.ceil(n / 8));
  const out: number[] = new Array(n);
  for (let i = 0; i < n; i++) out[i] = (bytes[i >> 3] >> (i & 7)) & 1;
  return out;
}

/** In-place Fisher–Yates shuffle using unbiased CSPRNG indices. */
export function fisherYatesShuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomUniformInt(i + 1);
    const t = arr[i];
    arr[i] = arr[j];
    arr[j] = t;
  }
  return arr;
}

/** A uniformly random permutation of {0, 1, ..., n-1}. */
export function randomPermutation(n: number): number[] {
  const a = Array.from({ length: n }, (_, i) => i);
  return fisherYatesShuffle(a);
}

/**
 * Constant-time discrete Gaussian sampler (CDT — Cumulative Distribution Table).
 *
 * `discreteGaussian` (Box–Muller) runs in value-dependent time (Math.log/cos and
 * data flow), a timing side-channel if the sample feeds a secret. This builds a
 * CDF table once, then for each draw scans the WHOLE table with branchless
 * comparisons — so the time is independent of the value produced. Use this in
 * secret-dependent lattice sampling where timing leakage matters.
 */
export class ConstantTimeGaussian {
  private readonly cdt: number[];
  private readonly center: number;
  private static readonly SCALE = 1 << 30;

  constructor(sigma: number, tau = 12) {
    const bound = Math.max(1, Math.ceil(tau * sigma));
    this.center = bound;
    const weights: number[] = [];
    let total = 0;
    for (let x = -bound; x <= bound; x++) {
      const p = Math.exp(-(x * x) / (2 * sigma * sigma));
      weights.push(p);
      total += p;
    }
    this.cdt = [];
    let acc = 0;
    for (const w of weights) {
      acc += w / total;
      this.cdt.push(Math.min(ConstantTimeGaussian.SCALE, Math.round(acc * ConstantTimeGaussian.SCALE)));
    }
  }

  /** One constant-time sample from the centered discrete Gaussian. */
  sample(): number {
    const b = randomBytes(4);
    const v = (((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0) >>> 2; // 30-bit uniform
    let idx = 0;
    for (let i = 0; i < this.cdt.length; i++) {
      // idx += (v >= cdt[i]) ? 1 : 0, branchless
      idx += ((this.cdt[i] - v - 1) >> 31) & 1;
    }
    return idx - this.center;
  }
}
