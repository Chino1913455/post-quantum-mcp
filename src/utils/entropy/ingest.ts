/**
 * External-entropy ingest gate + DRBG seeding.
 *
 * This is the `prove.py` proving logic (from the VerisSuite true-rng project)
 * realized as a pipeline stage: take RAW bytes from an external entropy device
 * (the TrueEntropy SPAD/avalanche capture), MEASURE their min-entropy, GATE on
 * the SP 800-90B health tests + a min-entropy floor, CONDITION the survivors via
 * the Toeplitz extractor, and use the result to seed an SP 800-90A HMAC_DRBG
 * that yields unlimited output.
 *
 * Why this exists: the EntropyService pipeline trusts a source's *declared*
 * min-entropy. A real hardware source must be *measured* and *refused* if it is
 * stuck/biased/degraded. This module is the missing measurement + gate, so a
 * validated device — not its datasheet claim — is what feeds the DRBG.
 *
 *   raw device bytes ──► measure (MCV min-entropy) ──► gate (RCT/APT + floor)
 *      ──► condition (Toeplitz) ──► 512-bit seed ──► HmacDrbg ──► unlimited bytes
 */
import * as crypto from 'crypto';
import { ToeplitzExtractor } from './extractor.js';
import {
  repetitionCountTest,
  adaptiveProportionTest,
  runHealthTests,
  type HealthReport,
} from './health.js';
import { EntropyService, type EntropySource } from './sources.js';

const ALPHA = Math.pow(2, -20); // SP 800-90B health-test false-positive budget

/**
 * SP 800-90B 6.3.1 Most-Common-Value min-entropy estimate (bits per byte).
 * The single number that determines how much you may safely extract/seed.
 */
export function minEntropyMCV(samples: Uint8Array): { hMin: number; pMax: number } {
  const n = samples.length;
  if (n < 2) return { hMin: 0, pMax: 1 };
  const counts = new Uint32Array(256);
  for (const b of samples) counts[b]++;
  let cMax = 0;
  for (const c of counts) if (c > cMax) cMax = c;
  const pHat = cMax / n;
  // 99% upper confidence bound, then H = -log2(pU).
  const pU = Math.min(1, pHat + 2.576 * Math.sqrt((pHat * (1 - pHat)) / (n - 1)));
  return { hMin: -Math.log2(pU), pMax: pHat };
}

/**
 * Statistical distance of the conditioned output from a PERFECTLY uniform
 * (full-entropy) distribution. Smaller = closer to full entropy. The default is
 * BEST; "standard" is the common 2^-32. Tightening this only costs a little
 * extra raw min-entropy surplus — so we default to the best.
 */
export const STANDARD_EPSILON = Math.pow(2, -32);
export const BEST_EPSILON = Math.pow(2, -64);

export interface IngestOptions {
  /** Reject if measured min-entropy/byte is below this floor (default 5.0). */
  minEntropyFloor?: number;
  /** Conditioned seed length in bits (default 512). */
  seedBits?: number;
  /** Distance-from-uniform target. Overrides `quality` if set. */
  epsilon?: number;
  /** 'best' (default) = 2^-64 from uniform; 'standard' = 2^-32. */
  quality?: 'standard' | 'best';
  /** Name to register the validated source under. */
  sourceName?: string;
}

/**
 * Proof that the seed is FULL ENTROPY: by the Leftover Hash Lemma the output is
 * within `distanceFromUniform` of a perfectly uniform distribution. This — not a
 * frequency measurement of the tiny seed — is what certifies full entropy.
 */
export interface FullEntropyCertificate {
  fullEntropy: boolean; // LHL satisfied -> output is (near-)uniform
  distanceFromUniform: number; // epsilon: how close to perfect full entropy
  inputMinEntropyBits: number; // certified min-entropy consumed
  outputBits: number; // full-entropy bits produced
  securityMarginBits: number; // surplus headroom
}

export interface IngestResult {
  accepted: boolean;
  reason: string;
  measuredMinEntropyPerByte: number;
  pMax: number;
  rawBytes: number;
  /** Full health report (informational; gate uses RCT/APT + floor). */
  health: HealthReport;
  /** Conditioned FULL-ENTROPY seed (near-uniform) — only present when accepted. */
  seed: Uint8Array | null;
  /** Full-entropy proof for the seed (null when rejected). */
  certificate: FullEntropyCertificate | null;
}

function round(x: number, dp = 4): number {
  const f = Math.pow(10, dp);
  return Math.round(x * f) / f;
}

/**
 * Measure → gate → condition. Returns a 512-bit seed iff the source passes the
 * SP 800-90B continuous tests AND clears the min-entropy floor. The gate is the
 * RCT/APT + floor (each with negligible false-reject for a healthy source); the
 * looser parity panel is reported but not used to reject.
 */
export function ingestExternalEntropy(raw: Uint8Array, opts: IngestOptions = {}): IngestResult {
  const floor = opts.minEntropyFloor ?? 5.0;
  const seedBits = opts.seedBits ?? 512;
  const epsilon = opts.epsilon ?? (opts.quality === 'standard' ? STANDARD_EPSILON : BEST_EPSILON);

  const { hMin, pMax } = minEntropyMCV(raw);
  const H = Math.max(0.1, Math.min(8, hMin)); // clamp for the test cutoffs
  const health = runHealthTests(raw, { minEntropyPerSample: H });

  const rct = repetitionCountTest(raw, H, ALPHA);
  const apt =
    raw.length >= 512
      ? adaptiveProportionTest(raw, H, ALPHA, 512)
      : { name: 'SP800-90B Adaptive Proportion', passed: true, detail: {} };

  const base = {
    measuredMinEntropyPerByte: round(hMin),
    pMax: round(pMax, 6),
    rawBytes: raw.length,
    health,
    certificate: null,
  };
  const reject = (reason: string): IngestResult => ({ accepted: false, reason, seed: null, ...base });

  if (!rct.passed) return reject('RCT failed — source is stuck or repeating');
  if (!apt.passed) return reject('APT failed — source is biased toward a value');
  if (hMin < floor) return reject(`min-entropy ${round(hMin, 2)}/byte below floor ${floor}`);

  // Consume enough raw to justify a FULL-ENTROPY seed: the Leftover Hash Lemma
  // needs the input min-entropy to exceed the output by 2*log2(1/epsilon); the
  // extra 64-bit slack makes the certificate carry positive margin.
  const lhlMargin = 2 * Math.log2(1 / epsilon);
  const needBytes = Math.ceil((seedBits + lhlMargin + 64) / hMin);
  if (needBytes > raw.length) {
    return reject(`need ${needBytes} bytes for a ${seedBits}-bit full-entropy seed at this entropy, have ${raw.length}`);
  }
  const extractor = new ToeplitzExtractor({
    inputBits: needBytes * 8,
    outputBits: seedBits,
    minEntropyRate: hMin / 8,
    epsilon,
  });
  const seed = extractor.extractBytes(raw.subarray(0, needBytes)).subarray(0, seedBits / 8);
  const lhl = extractor.leftoverHashLemmaCheck();
  const certificate: FullEntropyCertificate = {
    fullEntropy: lhl.satisfiesLHL,
    distanceFromUniform: epsilon,
    inputMinEntropyBits: lhl.minEntropyBits,
    outputBits: seedBits,
    securityMarginBits: lhl.securityMarginBits,
  };
  return { accepted: true, reason: 'ok (full-entropy seed)', seed, ...base, certificate };
}

/**
 * Verify a block of output IS full entropy: measure its min-entropy + Shannon
 * entropy and confirm it is essentially uniform. Use on a LARGE block
 * (>= ~100 KB) — a 512-bit seed is too small to measure, so its full-entropy
 * guarantee comes from the LHL certificate, not from measurement. (The MCV
 * min-entropy estimate is conservative for finite n, so "near uniform" keys on
 * Shannon ~8 with min-entropy comfortably high.)
 */
export function verifyFullEntropy(bytes: Uint8Array): {
  minEntropyPerByte: number;
  shannonPerByte: number;
  nearUniform: boolean;
} {
  const n = bytes.length;
  const counts = new Uint32Array(256);
  for (const b of bytes) counts[b]++;
  let shannon = 0;
  for (const c of counts) {
    if (c) {
      const p = c / n;
      shannon -= p * Math.log2(p);
    }
  }
  const { hMin } = minEntropyMCV(bytes);
  return {
    minEntropyPerByte: round(hMin),
    shannonPerByte: round(shannon),
    nearUniform: shannon >= 7.99 && hMin >= 7.4,
  };
}

/**
 * SP 800-90A HMAC_DRBG (SHA-256). Seeded by a validated external seed, it
 * produces unlimited near-uniform output and can be reseeded as more device
 * entropy is captured. This is the DRBG the validated source feeds.
 */
export class HmacDrbg {
  private K: Buffer;
  private V: Buffer;
  private reseedCounter = 1;

  constructor(seed: Uint8Array) {
    if (seed.length < 16) throw new Error('HmacDrbg: seed too short');
    this.K = Buffer.alloc(32, 0x00);
    this.V = Buffer.alloc(32, 0x01);
    this.update(Buffer.from(seed));
  }

  private hmac(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha256', key).update(data).digest();
  }

  private update(provided: Buffer | null): void {
    const p = provided ?? Buffer.alloc(0);
    this.K = this.hmac(this.K, Buffer.concat([this.V, Buffer.from([0x00]), p]));
    this.V = this.hmac(this.K, this.V);
    if (p.length > 0) {
      this.K = this.hmac(this.K, Buffer.concat([this.V, Buffer.from([0x01]), p]));
      this.V = this.hmac(this.K, this.V);
    }
  }

  reseed(seed: Uint8Array): void {
    this.update(Buffer.from(seed));
    this.reseedCounter = 1;
  }

  generate(n: number): Uint8Array {
    if (!Number.isInteger(n) || n <= 0) throw new Error(`generate: invalid length ${n}`);
    const out = Buffer.alloc(n);
    let pos = 0;
    while (pos < n) {
      this.V = this.hmac(this.K, this.V);
      const take = Math.min(32, n - pos);
      this.V.copy(out, pos, 0, take);
      pos += take;
    }
    this.update(null);
    this.reseedCounter++;
    return new Uint8Array(out);
  }
}

/** An EntropySource backed by captured raw bytes from a TrueEntropy device. */
export class BufferEntropySource implements EntropySource {
  readonly raw = true;
  private off = 0;
  constructor(
    private readonly buf: Uint8Array,
    readonly name = 'true-entropy-device',
    readonly minEntropyPerByte = 6,
  ) {}
  available(): boolean {
    return this.off < this.buf.length;
  }
  read(n: number): Uint8Array {
    if (this.off + n > this.buf.length) throw new Error('true-entropy buffer exhausted; capture more');
    const out = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }
}

/**
 * Validate a device capture and, if it passes, register it as the preferred
 * (raw) source on an EntropyService — so the existing generate() pipeline now
 * draws from the proven device. Returns the ingest verdict.
 */
export function registerValidatedSource(
  service: EntropyService,
  raw: Uint8Array,
  opts: IngestOptions = {},
): IngestResult {
  const res = ingestExternalEntropy(raw, opts);
  if (res.accepted) {
    const credited = Math.max(1, Math.min(8, Math.floor(res.measuredMinEntropyPerByte)));
    service.register(new BufferEntropySource(raw, opts.sourceName ?? 'true-entropy-device', credited));
  }
  return res;
}
