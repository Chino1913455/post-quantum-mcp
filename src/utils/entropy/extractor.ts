/**
 * Toeplitz-hashing randomness extractor (universal hash family).
 *
 * Ported from the VerisSuite `true-rng` design (quantum_rng_design.py,
 * RandomnessExtractor), with one correctness fix: the original seeded the
 * Toeplitz matrix from Python's `random.randint` (a non-crypto PRNG). A
 * randomness extractor's seed must be independent and unpredictable, so here
 * the seed is drawn from the OS CSPRNG.
 *
 * Purpose: condition raw, biased hardware entropy into near-uniform output.
 * The Leftover Hash Lemma guarantees the output is within statistical distance
 * epsilon of uniform, provided the input has at least
 *   m + 2*log2(1/epsilon)
 * bits of min-entropy, where m is the output length.
 */
import * as crypto from 'crypto';

export interface LHLResult {
  inputBits: number;
  outputBits: number;
  minEntropyBits: number;
  maxSecureOutputBits: number;
  epsilon: number;
  satisfiesLHL: boolean;
  securityMarginBits: number;
}

export interface ExtractorParams {
  /** Raw input length in bits. */
  inputBits: number;
  /** Desired extracted output length in bits. */
  outputBits: number;
  /** Assessed min-entropy rate of the source, H_min / n in [0, 1]. */
  minEntropyRate: number;
  /** Target statistical distance from uniform (default 2^-32). */
  epsilon?: number;
}

function bytesToBits(bytes: Uint8Array): number[] {
  const bits: number[] = new Array(bytes.length * 8);
  for (let i = 0; i < bytes.length; i++) {
    for (let j = 0; j < 8; j++) bits[i * 8 + j] = (bytes[i] >> j) & 1;
  }
  return bits;
}

function bitsToBytes(bits: number[]): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) out[i >> 3] |= 1 << (i & 7);
  }
  return out;
}

export class ToeplitzExtractor {
  readonly inputBits: number;
  readonly outputBits: number;
  readonly minEntropyRate: number;
  readonly epsilon: number;

  constructor(params: ExtractorParams) {
    this.inputBits = params.inputBits;
    this.outputBits = params.outputBits;
    this.minEntropyRate = params.minEntropyRate;
    this.epsilon = params.epsilon ?? 2 ** -32;
    if (this.outputBits <= 0 || this.inputBits <= 0) {
      throw new Error('ToeplitzExtractor: input/output bit lengths must be positive');
    }
    if (this.outputBits > this.inputBits) {
      throw new Error('ToeplitzExtractor: cannot expand (output > input)');
    }
  }

  get compressionRatio(): number {
    return this.outputBits / this.inputBits;
  }

  /**
   * Leftover Hash Lemma check: is it safe to extract `outputBits` from a
   * source with this min-entropy rate at the target epsilon?
   */
  leftoverHashLemmaCheck(): LHLResult {
    const k = this.inputBits * this.minEntropyRate; // min-entropy in bits
    const maxOutput = k - 2 * Math.log2(1 / this.epsilon);
    return {
      inputBits: this.inputBits,
      outputBits: this.outputBits,
      minEntropyBits: Math.round(k * 10) / 10,
      maxSecureOutputBits: Math.round(maxOutput * 10) / 10,
      epsilon: this.epsilon,
      satisfiesLHL: this.outputBits <= maxOutput,
      securityMarginBits: Math.round((maxOutput - this.outputBits) * 10) / 10,
    };
  }

  /**
   * Extract `outputBits` near-uniform bits from `rawBits` (length >= inputBits)
   * using a fresh CSPRNG-seeded Toeplitz matrix.
   */
  extractBits(rawBits: number[]): number[] {
    const n = Math.min(rawBits.length, this.inputBits);
    const m = this.outputBits;

    // Toeplitz matrix is defined by its first row+column: n + m - 1 seed bits,
    // drawn from the OS CSPRNG (independent of the source — required by LHL).
    const seedLen = n + m - 1;
    const seedBytes = crypto.randomBytes(Math.ceil(seedLen / 8));
    const seed = (i: number) => (seedBytes[i >> 3] >> (i & 7)) & 1;

    const out: number[] = new Array(m).fill(0);
    for (let i = 0; i < m; i++) {
      let bit = 0;
      for (let j = 0; j < n; j++) bit ^= seed(i + j) & rawBits[j];
      out[i] = bit;
    }
    return out;
  }

  /** Convenience: condition raw entropy bytes into `outputBits/8` output bytes. */
  extractBytes(rawBytes: Uint8Array): Uint8Array {
    return bitsToBytes(this.extractBits(bytesToBits(rawBytes)));
  }
}

export { bytesToBits, bitsToBytes };
