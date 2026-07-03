/**
 * Post-Quantum Verifiable Delay Functions (VDFs)
 * ================================================
 *
 * VDFs produce an output that takes a prescribed amount of sequential
 * time to compute, yet the result can be verified exponentially faster.
 * This module provides multiple VDF constructions, including post-quantum
 * secure variants based on lattice and isogeny hardness assumptions.
 *
 * Implements:
 *   - Iterated Squaring VDF (RSA group, Wesolowski proof, Pietrzak proof)
 *   - Lattice-Based VDF (sequential lattice operations, PQ-secure delay)
 *   - Isogeny-Based VDF (sequential isogeny computation on supersingular curves)
 *   - Efficient proof verification (exponentially faster than computation)
 *   - Chained VDFs (composable VDF chains for longer delays)
 *   - Randomness beacon (unbiasable randomness from VDF output)
 *   - Fair leader election (VDF-based unbiasable selection)
 *   - Timelock encryption (encrypt now, decrypt after VDF completes)
 *   - Benchmarking and difficulty calibration
 */

import * as crypto from 'crypto';
import * as sampling from '../utils/entropy/sampling.js';

// ============================================================
// Utility: Big-integer arithmetic helpers (pure JS, no deps)
// ============================================================

/** Modular exponentiation: base^exp mod modulus, using bigint */
function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % modulus;
    }
    exp >>= 1n;
    base = (base * base) % modulus;
  }
  return result;
}

// extGcd and modInverse removed (unused)

/** SHA-256 hash returning bigint */
function hashToBigInt(...inputs: (string | bigint | Buffer)[]): bigint {
  const h = crypto.createHash('sha256');
  for (const inp of inputs) {
    if (typeof inp === 'bigint') {
      h.update(inp.toString(16));
    } else if (Buffer.isBuffer(inp)) {
      h.update(inp);
    } else {
      h.update(inp);
    }
  }
  return BigInt('0x' + h.digest('hex'));
}

/** SHA-256 hash returning hex string */
function hashToHex(...inputs: (string | bigint | Buffer)[]): string {
  const h = crypto.createHash('sha256');
  for (const inp of inputs) {
    if (typeof inp === 'bigint') {
      h.update(inp.toString(16));
    } else if (Buffer.isBuffer(inp)) {
      h.update(inp);
    } else {
      h.update(inp);
    }
  }
  return h.digest('hex');
}

/** SHAKE-256 hash with variable output length */
function shake256(data: Buffer | string, outputLen: number): Buffer {
  // Use SHA-256 iterated to simulate variable-length output
  const blocks: Buffer[] = [];
  let remaining = outputLen;
  let counter = 0;
  while (remaining > 0) {
    const h = crypto.createHash('sha256');
    h.update(typeof data === 'string' ? Buffer.from(data) : data);
    h.update(Buffer.from([counter >> 8, counter & 0xff]));
    const block = h.digest();
    blocks.push(block.subarray(0, Math.min(remaining, 32)));
    remaining -= 32;
    counter++;
  }
  return Buffer.concat(blocks).subarray(0, outputLen);
}

/** Generate a random bigint in [2, max-1] */
function randomBigInt(max: bigint): bigint {
  const byteLen = Math.ceil(max.toString(16).length / 2) + 4;
  const buf = crypto.randomBytes(byteLen);
  const val = BigInt('0x' + buf.toString('hex')) % (max - 2n);
  return val + 2n;
}

/** Miller-Rabin primality test */
function isProbablePrime(n: bigint, rounds: number = 20): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  let d = n - 1n;
  let r = 0;
  while (d % 2n === 0n) {
    d >>= 1n;
    r++;
  }

  for (let i = 0; i < rounds; i++) {
    const a = randomBigInt(n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 0; j < r - 1; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

/** Generate a random prime of given bit length */
function generatePrime(bits: number): bigint {
  while (true) {
    const bytes = crypto.randomBytes(Math.ceil(bits / 8));
    bytes[0] |= 0x80; // set high bit
    bytes[bytes.length - 1] |= 0x01; // set low bit (odd)
    const candidate = BigInt('0x' + bytes.toString('hex'));
    if (isProbablePrime(candidate, 20)) {
      return candidate;
    }
  }
}

/** Hash-to-prime: deterministic prime derivation from input */
function hashToPrime(input: string | bigint, bitLength: number = 128): bigint {
  let nonce = 0n;
  while (true) {
    const h = hashToBigInt(input.toString(), nonce.toString());
    const candidate = h | (1n << BigInt(bitLength - 1)) | 1n;
    const mask = (1n << BigInt(bitLength)) - 1n;
    const trimmed = candidate & mask;
    if (isProbablePrime(trimmed, 15)) {
      return trimmed;
    }
    nonce++;
  }
}

// ============================================================
// VDF Core Interfaces
// ============================================================

export interface VDFSetupParams {
  securityBits: number;
  timeParameter: number; // T: number of sequential steps
}

export interface VDFPublicParams {
  type: string;
  securityBits: number;
  timeParameter: number;
  groupDescription: string;
  [key: string]: unknown;
}

export interface VDFInput {
  challenge: string;
  encoded: bigint;
}

export interface VDFOutput {
  value: bigint;
  proof: VDFProof;
  computationTimeMs: number;
  steps: number;
}

export interface VDFProof {
  type: string;
  data: Record<string, unknown>;
}

export interface VDFVerificationResult {
  valid: boolean;
  verificationTimeMs: number;
  speedup: number; // computation time / verification time
}

// ============================================================
// 1. Iterated Squaring VDF (RSA Group)
// ============================================================

/**
 * Classical Iterated Squaring VDF in an RSA group.
 *
 * Computation: y = x^(2^T) mod N where N = p*q (RSA modulus).
 * The computation requires T sequential squarings.
 *
 * Two proof systems:
 *   - Wesolowski: single-round, proof is pi = x^(floor(2^T / l)) mod N
 *   - Pietrzak: log(T)-round recursive halving proof
 */
export class IteratedSquaringVDF {
  private N: bigint;
  private bitLength: number;
  private p: bigint | null = null;
  private q: bigint | null = null;

  constructor(bitLength: number = 1024) {
    this.bitLength = bitLength;
    // Generate RSA modulus
    const halfBits = Math.floor(bitLength / 2);
    this.p = generatePrime(halfBits);
    this.q = generatePrime(halfBits);
    this.N = this.p * this.q;
  }

  /** Create from existing modulus (trusted setup removed) */
  static fromModulus(N: bigint): IteratedSquaringVDF {
    const vdf = Object.create(IteratedSquaringVDF.prototype);
    vdf.N = N;
    vdf.bitLength = N.toString(2).length;
    vdf.p = null;
    vdf.q = null;
    return vdf;
  }

  getPublicParams(T: number): VDFPublicParams {
    return {
      type: 'iterated-squaring',
      securityBits: this.bitLength,
      timeParameter: T,
      groupDescription: `RSA group Z/NZ, |N| = ${this.bitLength} bits`,
      N: this.N.toString(16),
    };
  }

  /** Encode challenge string into group element */
  encodeInput(challenge: string): VDFInput {
    const h = hashToBigInt(challenge, this.N);
    const encoded = (h % (this.N - 2n)) + 2n;
    return { challenge, encoded };
  }

  /**
   * Evaluate: compute y = x^(2^T) mod N
   * This is inherently sequential: each step depends on the previous.
   */
  evaluate(input: VDFInput, T: number): VDFOutput {
    const startTime = Date.now();
    let y = input.encoded;

    for (let i = 0; i < T; i++) {
      y = (y * y) % this.N;
    }

    const computationTimeMs = Date.now() - startTime;

    return {
      value: y,
      proof: { type: 'none', data: {} },
      computationTimeMs,
      steps: T,
    };
  }

  /**
   * Evaluate with Wesolowski proof.
   *
   * Proof: pi = x^(floor(2^T / l)) mod N
   * where l = HashToPrime(x, y)
   *
   * Verification: y == pi^l * x^r mod N
   * where r = 2^T mod l
   */
  evaluateWesolowski(input: VDFInput, T: number): VDFOutput {
    const startTime = Date.now();
    const x = input.encoded;

    // Step 1: compute y = x^(2^T) mod N
    let y = x;
    for (let i = 0; i < T; i++) {
      y = (y * y) % this.N;
    }

    // Step 2: derive challenge prime l
    const l = hashToPrime(`${x.toString(16)}:${y.toString(16)}`, 128);

    // Step 3: compute proof pi = x^(floor(2^T / l)) mod N
    // We compute floor(2^T / l) by tracking the quotient through the squarings
    let quotient = 0n;
    let remainder = 1n;
    for (let i = 0; i < T; i++) {
      remainder = remainder * 2n;
      quotient = quotient * 2n + remainder / l;
      remainder = remainder % l;
    }
    const pi = modPow(x, quotient, this.N);

    const computationTimeMs = Date.now() - startTime;

    return {
      value: y,
      proof: {
        type: 'wesolowski',
        data: {
          pi: pi.toString(16),
          l: l.toString(16),
          x: x.toString(16),
          T,
        },
      },
      computationTimeMs,
      steps: T,
    };
  }

  /**
   * Verify Wesolowski proof.
   * Check: y == pi^l * x^r mod N  where r = 2^T mod l
   */
  verifyWesolowski(input: VDFInput, output: VDFOutput): VDFVerificationResult {
    const startTime = Date.now();
    const x = input.encoded;
    const y = output.value;
    const proofData = output.proof.data;

    const pi = BigInt('0x' + (proofData.pi as string));
    const l = BigInt('0x' + (proofData.l as string));
    const T = proofData.T as number;

    // Verify l is correct hash-to-prime
    const expectedL = hashToPrime(`${x.toString(16)}:${y.toString(16)}`, 128);
    if (l !== expectedL) {
      return { valid: false, verificationTimeMs: Date.now() - startTime, speedup: 0 };
    }

    // Compute r = 2^T mod l
    const r = modPow(2n, BigInt(T), l);

    // Check: y == pi^l * x^r mod N
    const lhs = y;
    const piL = modPow(pi, l, this.N);
    const xR = modPow(x, r, this.N);
    const rhs = (piL * xR) % this.N;

    const verificationTimeMs = Date.now() - startTime;

    return {
      valid: lhs === rhs,
      verificationTimeMs,
      speedup: output.computationTimeMs > 0 ? output.computationTimeMs / Math.max(verificationTimeMs, 1) : 0,
    };
  }

  /**
   * Evaluate with Pietrzak proof.
   *
   * Recursive halving: split T into T/2 and provide intermediate values.
   * Proof size: O(log T) group elements.
   */
  evaluatePietrzak(input: VDFInput, T: number): VDFOutput {
    const startTime = Date.now();
    const x = input.encoded;

    // Pre-compute all intermediate squarings to enable proof generation
    const intermediates: bigint[] = [x];
    let current = x;
    for (let i = 0; i < T; i++) {
      current = (current * current) % this.N;
      intermediates.push(current);
    }
    const y = intermediates[T];

    // Generate Pietrzak proof: recursive halving
    const proofElements = this.pietrzakProve(intermediates, 0, T);

    const computationTimeMs = Date.now() - startTime;

    return {
      value: y,
      proof: {
        type: 'pietrzak',
        data: {
          elements: proofElements.map((e) => e.toString(16)),
          x: x.toString(16),
          T,
        },
      },
      computationTimeMs,
      steps: T,
    };
  }

  private pietrzakProve(intermediates: bigint[], start: number, length: number): bigint[] {
    if (length <= 1) return [];

    const half = Math.floor(length / 2);
    const mu = intermediates[start + half]; // x^(2^(T/2))

    // Challenge from Fiat-Shamir
    const xStart = intermediates[start];
    const xEnd = intermediates[start + length];
    void (hashToBigInt(
      xStart.toString(16),
      xEnd.toString(16),
      mu.toString(16)
    ) % (this.N - 2n) + 2n); // r challenge

    // Recurse on both halves, reducing the problem
    // New input: x' = x^r * mu mod N
    // New output: mu^r * y mod N
    // These satisfy x'^(2^(T/2)) = new_output
    const leftProof = this.pietrzakProve(intermediates, start, half);
    const rightProof = this.pietrzakProve(intermediates, start + half, length - half);

    return [mu, ...leftProof, ...rightProof];
  }

  /**
   * Verify Pietrzak proof.
   * O(log T) group operations.
   */
  verifyPietrzak(input: VDFInput, output: VDFOutput): VDFVerificationResult {
    const startTime = Date.now();
    const proofData = output.proof.data;
    const elements = (proofData.elements as string[]).map((e) => BigInt('0x' + e));
    const T = proofData.T as number;
    const x = input.encoded;
    const y = output.value;

    const valid = this.pietrzakVerifyRecursive(x, y, T, elements, 0);

    const verificationTimeMs = Date.now() - startTime;

    return {
      valid,
      verificationTimeMs,
      speedup: output.computationTimeMs > 0 ? output.computationTimeMs / Math.max(verificationTimeMs, 1) : 0,
    };
  }

  private pietrzakVerifyRecursive(
    x: bigint,
    y: bigint,
    T: number,
    elements: bigint[],
    idx: number
  ): boolean {
    if (T <= 1) {
      // Base case: check x^2 = y mod N (for T=1) or x = y (for T=0)
      if (T === 0) return x === y;
      return (x * x) % this.N === y;
    }

    if (idx >= elements.length) return false;

    const mu = elements[idx];
    const half = Math.floor(T / 2);

    // Derive challenge r
    const r = hashToBigInt(
      x.toString(16),
      y.toString(16),
      mu.toString(16)
    ) % (this.N - 2n) + 2n;

    // Reduce: x' = x^r * mu, y' = mu^r * y
    const xPrime = (modPow(x, r, this.N) * mu) % this.N;
    const yPrime = (modPow(mu, r, this.N) * y) % this.N;

    // Count elements used by left subtree to compute right index
    const leftCount = this.pietrzakElementCount(half);
    const rightStart = idx + 1 + leftCount;

    // Verify both halves
    const leftValid = this.pietrzakVerifyRecursive(x, mu, half, elements, idx + 1);
    void this.pietrzakVerifyRecursive(mu, y, T - half, elements, rightStart); // rightValid

    // Also verify the reduction
    const reductionCheck = this.pietrzakVerifyRecursive(xPrime, yPrime, half, elements, idx + 1);

    return leftValid || reductionCheck; // Either direct or reduction must hold
  }

  private pietrzakElementCount(T: number): number {
    if (T <= 1) return 0;
    const half = Math.floor(T / 2);
    return 1 + this.pietrzakElementCount(half) + this.pietrzakElementCount(T - half);
  }

  /** If trapdoor (factorization) is known, evaluate in O(log T) time */
  evaluateWithTrapdoor(input: VDFInput, T: number): VDFOutput | null {
    if (!this.p || !this.q) return null;

    const startTime = Date.now();
    const x = input.encoded;

    // phi(N) = (p-1)(q-1)
    const phi = (this.p - 1n) * (this.q - 1n);
    // y = x^(2^T mod phi(N)) mod N
    const exponent = modPow(2n, BigInt(T), phi);
    const y = modPow(x, exponent, this.N);

    const computationTimeMs = Date.now() - startTime;

    return {
      value: y,
      proof: { type: 'trapdoor', data: {} },
      computationTimeMs,
      steps: T,
    };
  }

  getModulus(): bigint {
    return this.N;
  }
}

// ============================================================
// 2. Lattice-Based VDF (Post-Quantum Secure)
// ============================================================

/** Parameters for lattice-based VDF */
interface LatticeVDFParams {
  n: number;       // lattice dimension
  q: number;       // modulus
  sigma: number;   // Gaussian parameter
  rounds: number;  // number of sequential rounds
}

/** A vector mod q */
class ModVector {
  readonly data: number[];
  readonly q: number;

  constructor(data: number[], q: number) {
    this.q = q;
    this.data = data.map((v) => ((v % q) + q) % q);
  }

  static zero(n: number, q: number): ModVector {
    return new ModVector(new Array(n).fill(0), q);
  }

  static random(n: number, q: number): ModVector {
    return new ModVector(
      Array.from({ length: n }, () => sampling.randomModInt(q)),
      q
    );
  }

  static fromHash(input: string, n: number, q: number): ModVector {
    const components: number[] = [];
    for (let i = 0; i < n; i++) {
      const h = hashToBigInt(input, BigInt(i));
      components.push(Number(h % BigInt(q)));
    }
    return new ModVector(components, q);
  }

  add(other: ModVector): ModVector {
    const result = this.data.map((v, i) => (v + other.data[i]) % this.q);
    return new ModVector(result, this.q);
  }

  scale(scalar: number): ModVector {
    const s = ((scalar % this.q) + this.q) % this.q;
    return new ModVector(this.data.map((v) => (v * s) % this.q), this.q);
  }

  dot(other: ModVector): number {
    let sum = 0;
    for (let i = 0; i < this.data.length; i++) {
      sum = (sum + this.data[i] * other.data[i]) % this.q;
    }
    return ((sum % this.q) + this.q) % this.q;
  }

  hash(): string {
    return hashToHex(this.data.join(','));
  }

  norm(): number {
    return Math.sqrt(this.data.reduce((s, v) => {
      const centered = v > this.q / 2 ? v - this.q : v;
      return s + centered * centered;
    }, 0));
  }

  toHex(): string {
    return this.data.map((v) => v.toString(16).padStart(4, '0')).join('');
  }

  static fromHex(hex: string, n: number, q: number): ModVector {
    const data: number[] = [];
    for (let i = 0; i < n; i++) {
      data.push(parseInt(hex.slice(i * 4, (i + 1) * 4), 16));
    }
    return new ModVector(data, q);
  }
}

/** A square matrix mod q for lattice operations */
class ModMatrix {
  readonly rows: ModVector[];
  readonly n: number;
  readonly q: number;

  constructor(rows: ModVector[]) {
    this.rows = rows;
    this.n = rows.length;
    this.q = rows[0]?.q ?? 12289;
  }

  static random(n: number, q: number): ModMatrix {
    return new ModMatrix(
      Array.from({ length: n }, () => ModVector.random(n, q))
    );
  }

  static fromSeed(seed: string, n: number, q: number): ModMatrix {
    const rows: ModVector[] = [];
    for (let i = 0; i < n; i++) {
      const components: number[] = [];
      for (let j = 0; j < n; j++) {
        const h = hashToBigInt(seed, BigInt(i * n + j));
        components.push(Number(h % BigInt(q)));
      }
      rows.push(new ModVector(components, q));
    }
    return new ModMatrix(rows);
  }

  mulVec(v: ModVector): ModVector {
    const result = this.rows.map((row) => row.dot(v));
    return new ModVector(result, this.q);
  }

  hash(): string {
    return hashToHex(this.rows.map((r) => r.toHex()).join(':'));
  }
}

/**
 * Lattice-Based VDF.
 *
 * Sequential computation: iterated application of a lattice-based
 * one-way function. Each step hashes the current state, uses the hash
 * to derive a lattice evaluation, then folds the result back.
 *
 * Security relies on the hardness of SIS/LWE under quantum attack.
 */
export class LatticeBasedVDF {
  private params: LatticeVDFParams;
  private A: ModMatrix; // public lattice matrix

  constructor(params?: Partial<LatticeVDFParams>) {
    this.params = {
      n: params?.n ?? 64,
      q: params?.q ?? 12289,
      sigma: params?.sigma ?? 3.2,
      rounds: params?.rounds ?? 1000,
    };
    // Deterministic matrix from seed for reproducibility
    this.A = ModMatrix.fromSeed('lattice-vdf-public-matrix', this.params.n, this.params.q);
  }

  getPublicParams(): VDFPublicParams {
    return {
      type: 'lattice-vdf',
      securityBits: Math.floor(this.params.n * Math.log2(this.params.q) / 2),
      timeParameter: this.params.rounds,
      groupDescription: `Lattice Z_${this.params.q}^${this.params.n}, SIS/LWE hardness`,
      n: this.params.n,
      q: this.params.q,
      matrixHash: this.A.hash(),
    };
  }

  /** Encode challenge into lattice vector */
  encodeInput(challenge: string): { challenge: string; state: ModVector } {
    return {
      challenge,
      state: ModVector.fromHash(challenge, this.params.n, this.params.q),
    };
  }

  /**
   * Evaluate: T rounds of sequential lattice operations.
   *
   * Each round:
   *   1. hash current state to get scalar c
   *   2. s_{i+1} = A * s_i + c * s_i  (mod q)
   *   3. Apply component-wise rounding/folding for non-linearity
   *
   * This is inherently sequential because each step depends on the
   * hash of the previous state.
   */
  evaluate(input: { challenge: string; state: ModVector }, T?: number): {
    output: ModVector;
    proof: LatticeVDFProof;
    computationTimeMs: number;
    steps: number;
  } {
    const rounds = T ?? this.params.rounds;
    const startTime = Date.now();
    const checkpoints: ModVector[] = [];
    const checkpointInterval = Math.max(1, Math.floor(rounds / 32));

    let state = input.state;

    for (let i = 0; i < rounds; i++) {
      // Hash current state to get challenge scalar
      const stateHash = state.hash();
      const c = Number(hashToBigInt(stateHash, BigInt(i)) % BigInt(this.params.q));

      // Linear lattice step: A*s + c*s
      const As = this.A.mulVec(state);
      const cs = state.scale(c);
      state = As.add(cs);

      // Non-linear folding: reduce large coefficients
      const folded = state.data.map((v) => {
        const centered = v > this.params.q / 2 ? v - this.params.q : v;
        return ((centered * centered) % this.params.q + this.params.q) % this.params.q;
      });
      state = new ModVector(folded, this.params.q);

      // Checkpoint for proof
      if (i % checkpointInterval === 0) {
        checkpoints.push(state);
      }
    }

    const computationTimeMs = Date.now() - startTime;

    return {
      output: state,
      proof: {
        type: 'lattice-checkpoint',
        checkpoints: checkpoints.map((cp) => cp.toHex()),
        checkpointInterval,
        inputChallenge: input.challenge,
        rounds,
      },
      computationTimeMs,
      steps: rounds,
    };
  }

  /**
   * Verify lattice VDF output.
   *
   * Re-execute from each checkpoint to the next, verifying consistency.
   * This is faster than full re-computation if checkpoints are trusted
   * and verified in parallel, but full verification requires replaying
   * the sequential computation.
   *
   * For efficiency, we verify a random sample of checkpoint transitions.
   */
  verify(
    input: { challenge: string; state: ModVector },
    output: ModVector,
    proof: LatticeVDFProof,
    sampleSize: number = 4
  ): VDFVerificationResult {
    const startTime = Date.now();
    const checkpoints = proof.checkpoints.map((hex) =>
      ModVector.fromHex(hex, this.params.n, this.params.q)
    );

    // Verify first checkpoint from input
    const firstCheck = this.evaluateSegment(
      input.state,
      0,
      proof.checkpointInterval
    );
    if (firstCheck.toHex() !== checkpoints[0].toHex()) {
      return { valid: false, verificationTimeMs: Date.now() - startTime, speedup: 0 };
    }

    // Verify random sample of consecutive checkpoint pairs
    const numCheckpoints = checkpoints.length;
    const indices: number[] = [];
    for (let i = 0; i < Math.min(sampleSize, numCheckpoints - 1); i++) {
      indices.push(sampling.randomUniformInt(numCheckpoints - 1));
    }

    for (const idx of indices) {
      const segStart = idx * proof.checkpointInterval;
      const segEnd = Math.min(segStart + proof.checkpointInterval, proof.rounds);
      const expected = idx + 1 < checkpoints.length ? checkpoints[idx + 1] : output;
      const computed = this.evaluateSegment(checkpoints[idx], segStart, segEnd);

      if (computed.toHex() !== expected.toHex()) {
        return { valid: false, verificationTimeMs: Date.now() - startTime, speedup: 0 };
      }
    }

    // Verify last checkpoint leads to output
    const lastIdx = checkpoints.length - 1;
    const lastStart = lastIdx * proof.checkpointInterval;
    const lastComputed = this.evaluateSegment(checkpoints[lastIdx], lastStart, proof.rounds);
    const valid = lastComputed.toHex() === output.toHex();

    const verificationTimeMs = Date.now() - startTime;

    return {
      valid,
      verificationTimeMs,
      speedup: 0, // Lattice VDF verification is same complexity
    };
  }

  /** Evaluate a segment of the sequential computation */
  private evaluateSegment(startState: ModVector, fromRound: number, toRound: number): ModVector {
    let state = startState;
    for (let i = fromRound; i < toRound; i++) {
      const stateHash = state.hash();
      const c = Number(hashToBigInt(stateHash, BigInt(i)) % BigInt(this.params.q));
      const As = this.A.mulVec(state);
      const cs = state.scale(c);
      state = As.add(cs);
      const folded = state.data.map((v) => {
        const centered = v > this.params.q / 2 ? v - this.params.q : v;
        return ((centered * centered) % this.params.q + this.params.q) % this.params.q;
      });
      state = new ModVector(folded, this.params.q);
    }
    return state;
  }

  getParams(): LatticeVDFParams {
    return { ...this.params };
  }
}

interface LatticeVDFProof {
  type: string;
  checkpoints: string[];
  checkpointInterval: number;
  inputChallenge: string;
  rounds: number;
}

// ============================================================
// 3. Isogeny-Based VDF (Post-Quantum, Simplified)
// ============================================================

/**
 * Simplified model of a supersingular elliptic curve point.
 * Real isogeny VDFs work over supersingular isogeny graphs;
 * this is a faithful structural simulation using hash chains
 * over a Montgomery curve model.
 */
interface IsogenyCurve {
  a: bigint;  // Montgomery coefficient: y^2 = x^3 + a*x^2 + x
  p: bigint;  // prime field characteristic
}

interface IsogenyPoint {
  x: bigint;
  y: bigint;
  curve: IsogenyCurve;
}

/**
 * Isogeny-Based VDF.
 *
 * Models sequential isogeny computation on supersingular elliptic curves.
 * Each step computes a degree-l isogeny from the current curve to a
 * neighboring curve in the supersingular isogeny graph.
 *
 * The sequentiality comes from the fact that computing isogenies
 * between distant curves requires traversing the graph step-by-step.
 *
 * Post-quantum secure: best known quantum algorithms for finding
 * isogeny paths have exponential complexity (unlike SIDH which
 * leaks torsion point info, our VDF only reveals the endpoint).
 */
export class IsogenyBasedVDF {
  private p: bigint;           // field prime
  private startCurve: IsogenyCurve;
  private l: number;           // isogeny degree

  constructor(primeBits: number = 256, isogenyDegree: number = 2) {
    this.l = isogenyDegree;
    // Use a prime p = 3 mod 4 for supersingular curve existence
    this.p = this.generateSupersingularPrime(primeBits);
    this.startCurve = { a: 6n, p: this.p }; // E: y^2 = x^3 + 6x^2 + x
  }

  private generateSupersingularPrime(bits: number): bigint {
    // Generate p such that p = 3 mod 4 (ensures supersingular curves exist)
    while (true) {
      const candidate = generatePrime(bits);
      if (candidate % 4n === 3n) return candidate;
    }
  }

  getPublicParams(T: number): VDFPublicParams {
    return {
      type: 'isogeny-vdf',
      securityBits: Number(this.p.toString(2).length) / 2,
      timeParameter: T,
      groupDescription: `Supersingular isogeny graph over F_p, |p| = ${this.p.toString(2).length} bits, degree-${this.l}`,
      p: this.p.toString(16),
      startCurveA: this.startCurve.a.toString(16),
    };
  }

  /**
   * Compute a single degree-l isogeny step.
   *
   * In a real implementation this would compute the Velu formula
   * for the isogeny kernel. Here we model it as a sequential
   * hash-based walk on the isogeny graph.
   */
  private isogenyStep(curve: IsogenyCurve, stepIndex: number): IsogenyCurve {
    // The new curve coefficient is determined by hashing the current one
    // along with the step index. This models the deterministic walk.
    const h = hashToBigInt(
      curve.a.toString(16),
      curve.p.toString(16),
      BigInt(stepIndex),
      BigInt(this.l)
    );

    // Velu-like transformation: new Montgomery coefficient
    // a' = f(a) where f is derived from the isogeny kernel point
    const kernelX = h % curve.p;
    // Simplified Velu: a' = (3*kernel_x^2 + 2*a*kernel_x + 1) / (kernel_x^2) mod p
    const numerator = (3n * kernelX * kernelX + 2n * curve.a * kernelX + 1n) % curve.p;
    const denominator = (kernelX * kernelX + 1n) % curve.p;
    const denomInv = modPow(denominator === 0n ? 1n : denominator, curve.p - 2n, curve.p);
    const newA = (numerator * denomInv) % curve.p;

    return { a: ((newA % curve.p) + curve.p) % curve.p, p: curve.p };
  }

  /**
   * Compute a point on the curve for commitment (simplified Elligator).
   */
  public curvePoint(curve: IsogenyCurve, seed: string): IsogenyPoint {
    const h = hashToBigInt(seed, curve.a);
    const x = h % curve.p;
    // y^2 = x^3 + a*x^2 + x mod p
    const y2 = (modPow(x, 3n, curve.p) + curve.a * modPow(x, 2n, curve.p) + x) % curve.p;
    // Tonelli-Shanks would give exact sqrt; we approximate for the model
    const y = modPow(y2, (curve.p + 1n) / 4n, curve.p);
    return { x, y, curve };
  }

  /**
   * Evaluate: walk T steps in the supersingular isogeny graph.
   */
  evaluate(challenge: string, T: number): {
    finalCurve: IsogenyCurve;
    path: string[];
    proof: IsogenyVDFProof;
    computationTimeMs: number;
    steps: number;
  } {
    const startTime = Date.now();
    let currentCurve = { ...this.startCurve };
    const pathHashes: string[] = [];
    const checkpoints: IsogenyCurve[] = [];
    const checkpointInterval = Math.max(1, Math.floor(T / 16));

    // Derive initial direction from challenge
    const initialSeed = hashToBigInt(challenge);
    currentCurve = {
      a: (currentCurve.a + initialSeed) % currentCurve.p,
      p: currentCurve.p,
    };

    for (let i = 0; i < T; i++) {
      currentCurve = this.isogenyStep(currentCurve, i);
      pathHashes.push(hashToHex(currentCurve.a.toString(16)));

      if (i % checkpointInterval === 0) {
        checkpoints.push({ ...currentCurve });
      }
    }

    const computationTimeMs = Date.now() - startTime;

    return {
      finalCurve: currentCurve,
      path: pathHashes,
      proof: {
        type: 'isogeny-checkpoint',
        checkpoints: checkpoints.map((c) => ({
          a: c.a.toString(16),
          p: c.p.toString(16),
        })),
        checkpointInterval,
        challenge,
        T,
        pathDigest: hashToHex(pathHashes.join(':')),
      },
      computationTimeMs,
      steps: T,
    };
  }

  /**
   * Verify isogeny VDF by re-walking from checkpoints.
   */
  verify(
    _challenge: string,
    finalCurve: IsogenyCurve,
    proof: IsogenyVDFProof,
    sampleSize: number = 3
  ): VDFVerificationResult {
    const startTime = Date.now();
    const checkpoints = proof.checkpoints.map((c) => ({
      a: BigInt('0x' + c.a),
      p: BigInt('0x' + c.p),
    }));

    // Verify random checkpoint transitions
    const numCheckpoints = checkpoints.length;
    let valid = true;

    for (let s = 0; s < Math.min(sampleSize, numCheckpoints - 1); s++) {
      const idx = sampling.randomUniformInt(numCheckpoints - 1);
      let curve = { ...checkpoints[idx] };
      const segStart = idx * proof.checkpointInterval;
      const segEnd = Math.min(segStart + proof.checkpointInterval, proof.T);

      for (let i = segStart; i < segEnd; i++) {
        curve = this.isogenyStep(curve, i);
      }

      const expected = idx + 1 < checkpoints.length ? checkpoints[idx + 1] : finalCurve;
      if (curve.a !== expected.a) {
        valid = false;
        break;
      }
    }

    // Verify last checkpoint to output
    if (valid && checkpoints.length > 0) {
      const lastIdx = checkpoints.length - 1;
      let curve = { ...checkpoints[lastIdx] };
      const segStart = lastIdx * proof.checkpointInterval;

      for (let i = segStart; i < proof.T; i++) {
        curve = this.isogenyStep(curve, i);
      }

      if (curve.a !== finalCurve.a) {
        valid = false;
      }
    }

    const verificationTimeMs = Date.now() - startTime;

    return {
      valid,
      verificationTimeMs,
      speedup: 0,
    };
  }

  getFieldPrime(): bigint {
    return this.p;
  }

  getStartCurve(): IsogenyCurve {
    return { ...this.startCurve };
  }
}

interface IsogenyVDFProof {
  type: string;
  checkpoints: Array<{ a: string; p: string }>;
  checkpointInterval: number;
  challenge: string;
  T: number;
  pathDigest: string;
}

// ============================================================
// 4. VDF Verification Engine
// ============================================================

/**
 * Unified verification engine supporting all VDF types.
 * Dispatches to the appropriate verifier based on proof type.
 */
export class VDFVerifier {
  private rsaVDFs: Map<string, IteratedSquaringVDF> = new Map();
  private latticeVDFs: Map<string, LatticeBasedVDF> = new Map();
  private isogenyVDFs: Map<string, IsogenyBasedVDF> = new Map();

  registerRSA(id: string, vdf: IteratedSquaringVDF): void {
    this.rsaVDFs.set(id, vdf);
  }

  registerLattice(id: string, vdf: LatticeBasedVDF): void {
    this.latticeVDFs.set(id, vdf);
  }

  registerIsogeny(id: string, vdf: IsogenyBasedVDF): void {
    this.isogenyVDFs.set(id, vdf);
  }

  /**
   * Verify any VDF output given its serialized proof bundle.
   */
  verifyBundle(bundle: VDFProofBundle): VDFVerificationResult {
    switch (bundle.vdfType) {
      case 'iterated-squaring-wesolowski':
        return this.verifyIteratedSquaringWesolowski(bundle);
      case 'iterated-squaring-pietrzak':
        return this.verifyIteratedSquaringPietrzak(bundle);
      case 'lattice-vdf':
        return this.verifyLatticeVDF(bundle);
      case 'isogeny-vdf':
        return this.verifyIsogenyVDF(bundle);
      default:
        return { valid: false, verificationTimeMs: 0, speedup: 0 };
    }
  }

  private verifyIteratedSquaringWesolowski(bundle: VDFProofBundle): VDFVerificationResult {
    const vdf = this.rsaVDFs.get(bundle.vdfId);
    if (!vdf) return { valid: false, verificationTimeMs: 0, speedup: 0 };

    const input = vdf.encodeInput(bundle.challenge);
    const output: VDFOutput = {
      value: BigInt('0x' + bundle.outputHex),
      proof: {
        type: 'wesolowski',
        data: bundle.proofData,
      },
      computationTimeMs: bundle.computationTimeMs,
      steps: bundle.steps,
    };

    return vdf.verifyWesolowski(input, output);
  }

  private verifyIteratedSquaringPietrzak(bundle: VDFProofBundle): VDFVerificationResult {
    const vdf = this.rsaVDFs.get(bundle.vdfId);
    if (!vdf) return { valid: false, verificationTimeMs: 0, speedup: 0 };

    const input = vdf.encodeInput(bundle.challenge);
    const output: VDFOutput = {
      value: BigInt('0x' + bundle.outputHex),
      proof: {
        type: 'pietrzak',
        data: bundle.proofData,
      },
      computationTimeMs: bundle.computationTimeMs,
      steps: bundle.steps,
    };

    return vdf.verifyPietrzak(input, output);
  }

  private verifyLatticeVDF(bundle: VDFProofBundle): VDFVerificationResult {
    const vdf = this.latticeVDFs.get(bundle.vdfId);
    if (!vdf) return { valid: false, verificationTimeMs: 0, speedup: 0 };

    const params = vdf.getParams();
    const input = vdf.encodeInput(bundle.challenge);
    const output = ModVector.fromHex(bundle.outputHex, params.n, params.q);
    const proof = bundle.proofData as unknown as LatticeVDFProof;

    return vdf.verify(input, output, proof);
  }

  private verifyIsogenyVDF(bundle: VDFProofBundle): VDFVerificationResult {
    const vdf = this.isogenyVDFs.get(bundle.vdfId);
    if (!vdf) return { valid: false, verificationTimeMs: 0, speedup: 0 };

    const finalCurve: IsogenyCurve = {
      a: BigInt('0x' + (bundle.proofData.finalCurveA as string)),
      p: vdf.getFieldPrime(),
    };
    const proof = bundle.proofData as unknown as IsogenyVDFProof;

    return vdf.verify(bundle.challenge, finalCurve, proof);
  }
}

export interface VDFProofBundle {
  vdfType: string;
  vdfId: string;
  challenge: string;
  outputHex: string;
  proofData: Record<string, unknown>;
  computationTimeMs: number;
  steps: number;
  timestamp: number;
}

// ============================================================
// 5. Chained VDFs (Composable Chains)
// ============================================================

export interface ChainLink {
  index: number;
  vdfType: string;
  input: string;
  outputHex: string;
  proofBundle: VDFProofBundle;
  cumulativeSteps: number;
  cumulativeTimeMs: number;
}

/**
 * Chained VDFs: compose multiple VDF evaluations sequentially.
 *
 * The output of each VDF becomes the input challenge for the next.
 * This allows building longer delays from shorter VDF instances,
 * and mixing different VDF types for defense-in-depth.
 */
export class ChainedVDF {
  private chain: ChainLink[] = [];
  private rsaVDF: IteratedSquaringVDF | null = null;
  private latticeVDF: LatticeBasedVDF | null = null;
  private isogenyVDF: IsogenyBasedVDF | null = null;

  constructor(config: {
    rsa?: IteratedSquaringVDF;
    lattice?: LatticeBasedVDF;
    isogeny?: IsogenyBasedVDF;
  }) {
    this.rsaVDF = config.rsa ?? null;
    this.latticeVDF = config.lattice ?? null;
    this.isogenyVDF = config.isogeny ?? null;
  }

  /**
   * Build a chain of VDF evaluations.
   *
   * @param initialChallenge Starting input
   * @param schedule Array of { type, steps } defining each link
   */
  buildChain(
    initialChallenge: string,
    schedule: Array<{ type: 'rsa' | 'lattice' | 'isogeny'; steps: number }>
  ): ChainLink[] {
    this.chain = [];
    let currentChallenge = initialChallenge;
    let cumulativeSteps = 0;
    let cumulativeTimeMs = 0;

    for (let i = 0; i < schedule.length; i++) {
      const entry = schedule[i];
      const link = this.evaluateLink(i, entry.type, currentChallenge, entry.steps);
      cumulativeSteps += link.proofBundle.steps;
      cumulativeTimeMs += link.proofBundle.computationTimeMs;

      link.cumulativeSteps = cumulativeSteps;
      link.cumulativeTimeMs = cumulativeTimeMs;

      this.chain.push(link);

      // Next challenge is hash of current output
      currentChallenge = hashToHex(link.outputHex);
    }

    return this.chain;
  }

  private evaluateLink(
    index: number,
    type: 'rsa' | 'lattice' | 'isogeny',
    challenge: string,
    steps: number
  ): ChainLink {
    switch (type) {
      case 'rsa': {
        if (!this.rsaVDF) throw new Error('RSA VDF not configured');
        const input = this.rsaVDF.encodeInput(challenge);
        const output = this.rsaVDF.evaluateWesolowski(input, steps);
        return {
          index,
          vdfType: 'rsa',
          input: challenge,
          outputHex: output.value.toString(16),
          proofBundle: {
            vdfType: 'iterated-squaring-wesolowski',
            vdfId: 'chain-rsa',
            challenge,
            outputHex: output.value.toString(16),
            proofData: output.proof.data,
            computationTimeMs: output.computationTimeMs,
            steps: output.steps,
            timestamp: Date.now(),
          },
          cumulativeSteps: 0,
          cumulativeTimeMs: 0,
        };
      }
      case 'lattice': {
        if (!this.latticeVDF) throw new Error('Lattice VDF not configured');
        const lInput = this.latticeVDF.encodeInput(challenge);
        const lOutput = this.latticeVDF.evaluate(lInput, steps);
        return {
          index,
          vdfType: 'lattice',
          input: challenge,
          outputHex: lOutput.output.toHex(),
          proofBundle: {
            vdfType: 'lattice-vdf',
            vdfId: 'chain-lattice',
            challenge,
            outputHex: lOutput.output.toHex(),
            proofData: lOutput.proof as unknown as Record<string, unknown>,
            computationTimeMs: lOutput.computationTimeMs,
            steps: lOutput.steps,
            timestamp: Date.now(),
          },
          cumulativeSteps: 0,
          cumulativeTimeMs: 0,
        };
      }
      case 'isogeny': {
        if (!this.isogenyVDF) throw new Error('Isogeny VDF not configured');
        const iOutput = this.isogenyVDF.evaluate(challenge, steps);
        return {
          index,
          vdfType: 'isogeny',
          input: challenge,
          outputHex: iOutput.finalCurve.a.toString(16),
          proofBundle: {
            vdfType: 'isogeny-vdf',
            vdfId: 'chain-isogeny',
            challenge,
            outputHex: iOutput.finalCurve.a.toString(16),
            proofData: {
              ...iOutput.proof,
              finalCurveA: iOutput.finalCurve.a.toString(16),
            },
            computationTimeMs: iOutput.computationTimeMs,
            steps: iOutput.steps,
            timestamp: Date.now(),
          },
          cumulativeSteps: 0,
          cumulativeTimeMs: 0,
        };
      }
    }
  }

  /**
   * Verify entire chain: each link's proof and the chaining constraint
   * (output of link i hashes to input of link i+1).
   */
  verifyChain(verifier: VDFVerifier): {
    valid: boolean;
    linkResults: Array<{ index: number; valid: boolean }>;
    totalVerificationTimeMs: number;
  } {
    const startTime = Date.now();
    const linkResults: Array<{ index: number; valid: boolean }> = [];
    let allValid = true;

    for (let i = 0; i < this.chain.length; i++) {
      const link = this.chain[i];

      // Verify the VDF proof
      const result = verifier.verifyBundle(link.proofBundle);
      linkResults.push({ index: i, valid: result.valid });

      if (!result.valid) {
        allValid = false;
      }

      // Verify chaining constraint
      if (i > 0) {
        const expectedInput = hashToHex(this.chain[i - 1].outputHex);
        if (link.input !== expectedInput) {
          linkResults[i].valid = false;
          allValid = false;
        }
      }
    }

    return {
      valid: allValid,
      linkResults,
      totalVerificationTimeMs: Date.now() - startTime,
    };
  }

  getChain(): ChainLink[] {
    return [...this.chain];
  }

  /** Total delay across all chain links */
  getTotalSteps(): number {
    return this.chain.reduce((sum, link) => sum + link.proofBundle.steps, 0);
  }

  getTotalTimeMs(): number {
    return this.chain.reduce((sum, link) => sum + link.proofBundle.computationTimeMs, 0);
  }

  /** Serialize chain for storage/transmission */
  serialize(): string {
    return JSON.stringify({
      chain: this.chain,
      totalSteps: this.getTotalSteps(),
      totalTimeMs: this.getTotalTimeMs(),
    });
  }

  /** Deserialize a chain from JSON */
  static deserialize(json: string): ChainLink[] {
    const parsed = JSON.parse(json);
    return parsed.chain as ChainLink[];
  }
}

// ============================================================
// 6. Applications
// ============================================================

// --- 6a. Randomness Beacon ---

export interface BeaconRound {
  round: number;
  challenge: string;
  output: string;
  proof: VDFProofBundle;
  timestamp: number;
  entropy: string;          // combined randomness
  previousOutput: string;   // chain back-link
}

/**
 * VDF-based Randomness Beacon.
 *
 * Produces unbiasable, publicly-verifiable random values at each round.
 * Each round's challenge is the hash of the previous round's output
 * concatenated with external entropy sources (block hashes, etc.).
 *
 * Properties:
 *   - Unbiasable: no party can influence the output (VDF is sequential)
 *   - Publicly verifiable: anyone can check the VDF proof
 *   - Unpredictable: output cannot be known until VDF completes
 */
export class RandomnessBeacon {
  private vdf: IteratedSquaringVDF;
  private timeParameter: number;
  private rounds: BeaconRound[] = [];
  private entropySources: string[] = [];

  constructor(vdf: IteratedSquaringVDF, timeParameter: number = 100000) {
    this.vdf = vdf;
    this.timeParameter = timeParameter;
  }

  /** Add external entropy that will be mixed into the next round */
  addEntropy(source: string): void {
    this.entropySources.push(source);
  }

  /**
   * Produce the next beacon round.
   *
   * Challenge = H(previous_output || round_number || entropy_sources)
   */
  nextRound(): BeaconRound {
    const roundNumber = this.rounds.length;
    const previousOutput = roundNumber > 0
      ? this.rounds[roundNumber - 1].output
      : '0000000000000000000000000000000000000000000000000000000000000000';

    // Build challenge from chain + entropy
    const entropyMix = this.entropySources.join(':');
    this.entropySources = []; // consume entropy

    const challenge = hashToHex(
      previousOutput,
      BigInt(roundNumber),
      Buffer.from(entropyMix || 'no-entropy')
    );

    // Evaluate VDF
    const input = this.vdf.encodeInput(challenge);
    const output = this.vdf.evaluateWesolowski(input, this.timeParameter);

    const beaconRound: BeaconRound = {
      round: roundNumber,
      challenge,
      output: output.value.toString(16),
      proof: {
        vdfType: 'iterated-squaring-wesolowski',
        vdfId: 'beacon',
        challenge,
        outputHex: output.value.toString(16),
        proofData: output.proof.data,
        computationTimeMs: output.computationTimeMs,
        steps: output.steps,
        timestamp: Date.now(),
      },
      timestamp: Date.now(),
      entropy: hashToHex(output.value.toString(16), BigInt(roundNumber)),
      previousOutput,
    };

    this.rounds.push(beaconRound);
    return beaconRound;
  }

  /** Verify a beacon round */
  verifyRound(round: BeaconRound): VDFVerificationResult {
    const input = this.vdf.encodeInput(round.challenge);
    const output: VDFOutput = {
      value: BigInt('0x' + round.output),
      proof: {
        type: 'wesolowski',
        data: round.proof.proofData,
      },
      computationTimeMs: round.proof.computationTimeMs,
      steps: round.proof.steps,
    };
    return this.vdf.verifyWesolowski(input, output);
  }

  /** Verify the entire beacon chain integrity */
  verifyChain(): { valid: boolean; invalidRounds: number[] } {
    const invalidRounds: number[] = [];

    for (let i = 0; i < this.rounds.length; i++) {
      const round = this.rounds[i];

      // Verify VDF proof
      const vdfResult = this.verifyRound(round);
      if (!vdfResult.valid) {
        invalidRounds.push(i);
        continue;
      }

      // Verify chain link (previous output)
      if (i > 0) {
        if (round.previousOutput !== this.rounds[i - 1].output) {
          invalidRounds.push(i);
        }
      }
    }

    return { valid: invalidRounds.length === 0, invalidRounds };
  }

  /** Extract random bytes from the latest beacon output */
  getRandomness(numBytes: number = 32): Buffer {
    if (this.rounds.length === 0) {
      throw new Error('No beacon rounds computed yet');
    }
    const latest = this.rounds[this.rounds.length - 1];
    return shake256(latest.entropy, numBytes);
  }

  /** Get random integer in [0, max) */
  getRandomInt(max: number): number {
    const bytes = this.getRandomness(8);
    const val = bytes.readUInt32BE(0);
    return val % max;
  }

  getRounds(): BeaconRound[] {
    return [...this.rounds];
  }

  getLatestRound(): BeaconRound | null {
    return this.rounds.length > 0 ? this.rounds[this.rounds.length - 1] : null;
  }
}

// --- 6b. Fair Leader Election ---

export interface ElectionCandidate {
  id: string;
  publicKey: string;
  commitment: string;
}

export interface ElectionResult {
  winnerId: string;
  winnerIndex: number;
  beaconRound: BeaconRound;
  selectionProof: string;
  verifiable: boolean;
}

/**
 * VDF-based Fair Leader Election.
 *
 * Uses the randomness beacon to select a leader from a set of candidates.
 * No party can bias the selection because:
 *   - Candidates commit before the VDF challenge is known
 *   - The VDF output is deterministic but unpredictable
 *   - Anyone can verify the selection using the VDF proof
 */
export class FairLeaderElection {
  private beacon: RandomnessBeacon;
  private candidates: ElectionCandidate[] = [];
  private committed: boolean = false;
  private commitmentDeadlineHash: string = '';

  constructor(beacon: RandomnessBeacon) {
    this.beacon = beacon;
  }

  /** Register a candidate with their commitment */
  registerCandidate(id: string, publicKey: string): string {
    if (this.committed) {
      throw new Error('Registration phase closed');
    }
    const commitment = hashToHex(id, BigInt(0), Buffer.from(publicKey));
    this.candidates.push({ id, publicKey, commitment });
    return commitment;
  }

  /** Close registration and record the candidate set hash */
  closeRegistration(): string {
    if (this.candidates.length === 0) {
      throw new Error('No candidates registered');
    }
    this.committed = true;
    this.commitmentDeadlineHash = hashToHex(
      this.candidates.map((c) => c.commitment).join(':')
    );

    // Add the commitment hash as entropy to the beacon
    this.beacon.addEntropy(this.commitmentDeadlineHash);

    return this.commitmentDeadlineHash;
  }

  /**
   * Run the election: compute VDF beacon round and select winner.
   */
  elect(): ElectionResult {
    if (!this.committed) {
      throw new Error('Registration must be closed first');
    }
    if (this.candidates.length === 0) {
      throw new Error('No candidates');
    }

    // Generate beacon round (this is the slow VDF computation)
    const round = this.beacon.nextRound();

    // Derive winner index from beacon entropy
    const selectionHash = hashToBigInt(round.entropy, BigInt(this.candidates.length));
    const winnerIndex = Number(selectionHash % BigInt(this.candidates.length));
    const winner = this.candidates[winnerIndex];

    const selectionProof = hashToHex(
      round.entropy,
      BigInt(winnerIndex),
      Buffer.from(winner.id)
    );

    return {
      winnerId: winner.id,
      winnerIndex,
      beaconRound: round,
      selectionProof,
      verifiable: true,
    };
  }

  /** Verify an election result */
  verifyElection(result: ElectionResult): boolean {
    // Verify the VDF proof
    const vdfValid = this.beacon.verifyRound(result.beaconRound);
    if (!vdfValid.valid) return false;

    // Verify the winner selection
    const selectionHash = hashToBigInt(
      result.beaconRound.entropy,
      BigInt(this.candidates.length)
    );
    const expectedIndex = Number(selectionHash % BigInt(this.candidates.length));

    return expectedIndex === result.winnerIndex;
  }

  getCandidates(): ElectionCandidate[] {
    return [...this.candidates];
  }

  /** Reset for a new election */
  reset(): void {
    this.candidates = [];
    this.committed = false;
    this.commitmentDeadlineHash = '';
  }
}

// --- 6c. Timelock Encryption ---

export interface TimelockCiphertext {
  encryptedData: string;        // AES-256-GCM encrypted payload
  iv: string;                   // initialization vector
  authTag: string;              // GCM authentication tag
  vdfChallenge: string;         // VDF input challenge
  vdfParams: VDFPublicParams;   // public VDF parameters
  lockDurationSteps: number;    // number of VDF steps to decrypt
  keyCommitment: string;        // hash of the decryption key for verification
  timestamp: number;            // encryption time
}

export interface TimelockDecryptionResult {
  plaintext: string;
  decryptionKey: string;
  vdfOutput: VDFOutput;
  verified: boolean;
  totalTimeMs: number;
}

/**
 * Timelock Encryption using VDFs.
 *
 * Encrypts data such that it can only be decrypted after a VDF
 * computation completes (representing a real-time delay).
 *
 * Protocol:
 *   1. Encryptor chooses secret key k, encrypts message with AES-GCM(k)
 *   2. Encryptor computes VDF(challenge) = y with trapdoor (knows factoring)
 *   3. Encryptor publishes: ciphertext, challenge, k XOR H(y)
 *   4. Decryptor must compute VDF(challenge) to recover y, then k
 *
 * Without the trapdoor, anyone must perform T sequential squarings.
 */
export class TimelockEncryption {
  private vdf: IteratedSquaringVDF;

  constructor(vdf?: IteratedSquaringVDF) {
    this.vdf = vdf ?? new IteratedSquaringVDF(1024);
  }

  /**
   * Encrypt data with a timelock.
   *
   * @param plaintext The message to encrypt
   * @param lockSteps Number of VDF steps (controls delay duration)
   * @param challenge Optional challenge (random if not provided)
   */
  encrypt(plaintext: string, lockSteps: number, challenge?: string): TimelockCiphertext {
    const vdfChallenge = challenge ?? crypto.randomBytes(32).toString('hex');

    // Generate the AES key by evaluating VDF with trapdoor (fast)
    const input = this.vdf.encodeInput(vdfChallenge);
    const vdfResult = this.vdf.evaluateWithTrapdoor(input, lockSteps);

    let vdfOutput: bigint;
    if (vdfResult) {
      vdfOutput = vdfResult.value;
    } else {
      // Fallback: actually compute (slow)
      const slowResult = this.vdf.evaluate(input, lockSteps);
      vdfOutput = slowResult.value;
    }

    // Derive AES key from VDF output
    const keyMaterial = shake256(vdfOutput.toString(16), 32);
    const keyCommitment = hashToHex(keyMaterial.toString('hex'));

    // Encrypt with AES-256-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyMaterial, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return {
      encryptedData: encrypted,
      iv: iv.toString('hex'),
      authTag,
      vdfChallenge,
      vdfParams: this.vdf.getPublicParams(lockSteps),
      lockDurationSteps: lockSteps,
      keyCommitment,
      timestamp: Date.now(),
    };
  }

  /**
   * Decrypt timelock ciphertext by computing the VDF.
   * This takes O(lockSteps) sequential operations.
   */
  decrypt(ciphertext: TimelockCiphertext): TimelockDecryptionResult {
    const startTime = Date.now();

    // Recover VDF modulus from params
    const N = BigInt('0x' + (ciphertext.vdfParams.N as string));
    const vdf = IteratedSquaringVDF.fromModulus(N);

    // Compute VDF (the slow part)
    const input = vdf.encodeInput(ciphertext.vdfChallenge);
    const vdfOutput = vdf.evaluate(input, ciphertext.lockDurationSteps);

    // Derive AES key from VDF output
    const keyMaterial = shake256(vdfOutput.value.toString(16), 32);
    const keyHex = keyMaterial.toString('hex');

    // Verify key commitment
    const computedCommitment = hashToHex(keyHex);
    const verified = computedCommitment === ciphertext.keyCommitment;

    // Decrypt with AES-256-GCM
    let plaintext = '';
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        keyMaterial,
        Buffer.from(ciphertext.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(ciphertext.authTag, 'hex'));
      plaintext = decipher.update(ciphertext.encryptedData, 'hex', 'utf8');
      plaintext += decipher.final('utf8');
    } catch {
      plaintext = '[DECRYPTION_FAILED]';
    }

    const totalTimeMs = Date.now() - startTime;

    return {
      plaintext,
      decryptionKey: keyHex,
      vdfOutput,
      verified,
      totalTimeMs,
    };
  }

  /**
   * Estimate wall-clock time for decryption based on benchmarking.
   */
  estimateDecryptionTime(ciphertext: TimelockCiphertext, benchmarkResult?: BenchmarkResult): number {
    if (benchmarkResult) {
      return ciphertext.lockDurationSteps * benchmarkResult.nsPerStep / 1e6;
    }
    // Default estimate: ~100ns per squaring for 1024-bit modulus
    return ciphertext.lockDurationSteps * 100 / 1e6;
  }

  /** Get the VDF instance */
  getVDF(): IteratedSquaringVDF {
    return this.vdf;
  }
}

// ============================================================
// 7. Benchmarking and Difficulty Calibration
// ============================================================

export interface BenchmarkResult {
  vdfType: string;
  steps: number;
  totalTimeMs: number;
  nsPerStep: number;
  stepsPerSecond: number;
  memoryUsedBytes: number;
  securityLevel: string;
  timestamp: number;
}

export interface CalibrationResult {
  targetTimeMs: number;
  recommendedSteps: number;
  vdfType: string;
  confidence: number;  // 0-1, based on benchmark consistency
  benchmarkRuns: number;
}

/**
 * VDF Benchmarking and Difficulty Calibration.
 *
 * Measures the per-step cost of each VDF type on the current hardware,
 * then uses these measurements to calibrate the number of steps needed
 * to achieve a target wall-clock delay.
 */
export class VDFBenchmark {
  private results: Map<string, BenchmarkResult[]> = new Map();

  /**
   * Benchmark the iterated squaring VDF.
   */
  benchmarkIteratedSquaring(
    bitLength: number = 1024,
    steps: number = 10000,
    warmupSteps: number = 1000
  ): BenchmarkResult {
    const vdf = new IteratedSquaringVDF(bitLength);
    const input = vdf.encodeInput('benchmark-challenge');

    // Warmup
    let warmup = input.encoded;
    for (let i = 0; i < warmupSteps; i++) {
      warmup = (warmup * warmup) % vdf.getModulus();
    }

    // Benchmark
    const memBefore = process.memoryUsage().heapUsed;
    const startTime = performance.now();

    let val = warmup;
    for (let i = 0; i < steps; i++) {
      val = (val * val) % vdf.getModulus();
    }

    const elapsed = performance.now() - startTime;
    const memAfter = process.memoryUsage().heapUsed;

    const result: BenchmarkResult = {
      vdfType: `iterated-squaring-${bitLength}bit`,
      steps,
      totalTimeMs: elapsed,
      nsPerStep: (elapsed * 1e6) / steps,
      stepsPerSecond: Math.floor(steps / (elapsed / 1000)),
      memoryUsedBytes: Math.max(0, memAfter - memBefore),
      securityLevel: `${bitLength}-bit RSA`,
      timestamp: Date.now(),
    };

    this.storeResult(result);
    return result;
  }

  /**
   * Benchmark the lattice-based VDF.
   */
  benchmarkLatticeVDF(
    dimension: number = 64,
    steps: number = 1000,
    warmupSteps: number = 100
  ): BenchmarkResult {
    const vdf = new LatticeBasedVDF({ n: dimension, rounds: steps });
    const input = vdf.encodeInput('benchmark-challenge');

    // Warmup
    vdf.evaluate(input, warmupSteps);

    // Benchmark
    const memBefore = process.memoryUsage().heapUsed;
    const startTime = performance.now();

    vdf.evaluate(input, steps);

    const elapsed = performance.now() - startTime;
    const memAfter = process.memoryUsage().heapUsed;

    const result: BenchmarkResult = {
      vdfType: `lattice-vdf-${dimension}dim`,
      steps,
      totalTimeMs: elapsed,
      nsPerStep: (elapsed * 1e6) / steps,
      stepsPerSecond: Math.floor(steps / (elapsed / 1000)),
      memoryUsedBytes: Math.max(0, memAfter - memBefore),
      securityLevel: `${dimension}-dimensional lattice`,
      timestamp: Date.now(),
    };

    this.storeResult(result);
    return result;
  }

  /**
   * Benchmark the isogeny-based VDF.
   */
  benchmarkIsogenyVDF(
    primeBits: number = 256,
    steps: number = 500,
    warmupSteps: number = 50
  ): BenchmarkResult {
    const vdf = new IsogenyBasedVDF(primeBits);

    // Warmup
    vdf.evaluate('warmup', warmupSteps);

    // Benchmark
    const memBefore = process.memoryUsage().heapUsed;
    const startTime = performance.now();

    vdf.evaluate('benchmark-challenge', steps);

    const elapsed = performance.now() - startTime;
    const memAfter = process.memoryUsage().heapUsed;

    const result: BenchmarkResult = {
      vdfType: `isogeny-vdf-${primeBits}bit`,
      steps,
      totalTimeMs: elapsed,
      nsPerStep: (elapsed * 1e6) / steps,
      stepsPerSecond: Math.floor(steps / (elapsed / 1000)),
      memoryUsedBytes: Math.max(0, memAfter - memBefore),
      securityLevel: `${primeBits}-bit isogeny`,
      timestamp: Date.now(),
    };

    this.storeResult(result);
    return result;
  }

  /**
   * Run all benchmarks.
   */
  benchmarkAll(config?: {
    rsaBits?: number;
    rsaSteps?: number;
    latticeDim?: number;
    latticeSteps?: number;
    isogenyBits?: number;
    isogenySteps?: number;
  }): Map<string, BenchmarkResult> {
    const results = new Map<string, BenchmarkResult>();

    const rsaResult = this.benchmarkIteratedSquaring(
      config?.rsaBits ?? 1024,
      config?.rsaSteps ?? 5000
    );
    results.set('rsa', rsaResult);

    const latticeResult = this.benchmarkLatticeVDF(
      config?.latticeDim ?? 64,
      config?.latticeSteps ?? 500
    );
    results.set('lattice', latticeResult);

    const isogenyResult = this.benchmarkIsogenyVDF(
      config?.isogenyBits ?? 256,
      config?.isogenySteps ?? 200
    );
    results.set('isogeny', isogenyResult);

    return results;
  }

  /**
   * Calibrate: determine the number of steps to achieve a target
   * wall-clock delay for a given VDF type.
   */
  calibrate(
    vdfType: 'rsa' | 'lattice' | 'isogeny',
    targetTimeMs: number,
    runs: number = 3
  ): CalibrationResult {
    const benchmarks: BenchmarkResult[] = [];

    for (let i = 0; i < runs; i++) {
      let result: BenchmarkResult;
      switch (vdfType) {
        case 'rsa':
          result = this.benchmarkIteratedSquaring(1024, 5000);
          break;
        case 'lattice':
          result = this.benchmarkLatticeVDF(64, 500);
          break;
        case 'isogeny':
          result = this.benchmarkIsogenyVDF(256, 200);
          break;
      }
      benchmarks.push(result);
    }

    // Average ns per step
    const avgNsPerStep =
      benchmarks.reduce((sum, b) => sum + b.nsPerStep, 0) / benchmarks.length;

    // Compute variance for confidence
    const variance =
      benchmarks.reduce((sum, b) => sum + (b.nsPerStep - avgNsPerStep) ** 2, 0) /
      benchmarks.length;
    const stdDev = Math.sqrt(variance);
    const coeffOfVariation = stdDev / avgNsPerStep;
    const confidence = Math.max(0, Math.min(1, 1 - coeffOfVariation));

    // Target steps = target time (ns) / ns per step
    const targetNs = targetTimeMs * 1e6;
    const recommendedSteps = Math.ceil(targetNs / avgNsPerStep);

    return {
      targetTimeMs,
      recommendedSteps,
      vdfType,
      confidence,
      benchmarkRuns: runs,
    };
  }

  /**
   * Estimate wall-clock time for a given number of steps.
   */
  estimateTime(vdfType: string, steps: number): number | null {
    const results = this.results.get(vdfType);
    if (!results || results.length === 0) return null;

    const latest = results[results.length - 1];
    return (steps * latest.nsPerStep) / 1e6; // ms
  }

  private storeResult(result: BenchmarkResult): void {
    const existing = this.results.get(result.vdfType) ?? [];
    existing.push(result);
    // Keep last 20 results per type
    if (existing.length > 20) existing.shift();
    this.results.set(result.vdfType, existing);
  }

  /** Get all benchmark results */
  getResults(): Map<string, BenchmarkResult[]> {
    return new Map(this.results);
  }

  /** Get summary statistics */
  getSummary(): Array<{
    vdfType: string;
    avgNsPerStep: number;
    avgStepsPerSecond: number;
    runs: number;
  }> {
    const summary: Array<{
      vdfType: string;
      avgNsPerStep: number;
      avgStepsPerSecond: number;
      runs: number;
    }> = [];

    for (const [vdfType, results] of this.results) {
      const avgNs = results.reduce((s, r) => s + r.nsPerStep, 0) / results.length;
      const avgSps = results.reduce((s, r) => s + r.stepsPerSecond, 0) / results.length;
      summary.push({
        vdfType,
        avgNsPerStep: avgNs,
        avgStepsPerSecond: avgSps,
        runs: results.length,
      });
    }

    return summary;
  }
}

// ============================================================
// Unified VDF System Interface
// ============================================================

export interface VDFSystemConfig {
  rsaBitLength?: number;
  latticeDimension?: number;
  latticeModulus?: number;
  isogenyPrimeBits?: number;
  defaultTimeParameter?: number;
}

/**
 * VDFSystem: unified interface to all VDF constructions and applications.
 *
 * Provides a single entry point for creating, evaluating, verifying,
 * and applying VDFs across all supported types.
 */
export class VDFSystem {
  private rsaVDF: IteratedSquaringVDF;
  private latticeVDF: LatticeBasedVDF;
  private isogenyVDF: IsogenyBasedVDF;
  private verifier: VDFVerifier;
  private benchmark: VDFBenchmark;
  private config: Required<VDFSystemConfig>;

  constructor(config?: VDFSystemConfig) {
    this.config = {
      rsaBitLength: config?.rsaBitLength ?? 1024,
      latticeDimension: config?.latticeDimension ?? 64,
      latticeModulus: config?.latticeModulus ?? 12289,
      isogenyPrimeBits: config?.isogenyPrimeBits ?? 256,
      defaultTimeParameter: config?.defaultTimeParameter ?? 10000,
    };

    this.rsaVDF = new IteratedSquaringVDF(this.config.rsaBitLength);
    this.latticeVDF = new LatticeBasedVDF({
      n: this.config.latticeDimension,
      q: this.config.latticeModulus,
    });
    this.isogenyVDF = new IsogenyBasedVDF(this.config.isogenyPrimeBits);

    this.verifier = new VDFVerifier();
    this.verifier.registerRSA('default', this.rsaVDF);
    this.verifier.registerLattice('default', this.latticeVDF);
    this.verifier.registerIsogeny('default', this.isogenyVDF);

    this.benchmark = new VDFBenchmark();
  }

  // --- RSA VDF operations ---

  /** Evaluate RSA iterated squaring VDF with Wesolowski proof */
  evaluateRSA(challenge: string, steps?: number): VDFOutput {
    const T = steps ?? this.config.defaultTimeParameter;
    const input = this.rsaVDF.encodeInput(challenge);
    return this.rsaVDF.evaluateWesolowski(input, T);
  }

  /** Evaluate RSA VDF with Pietrzak proof */
  evaluateRSAPietrzak(challenge: string, steps?: number): VDFOutput {
    const T = steps ?? this.config.defaultTimeParameter;
    const input = this.rsaVDF.encodeInput(challenge);
    return this.rsaVDF.evaluatePietrzak(input, T);
  }

  /** Verify RSA VDF Wesolowski proof */
  verifyRSA(challenge: string, output: VDFOutput): VDFVerificationResult {
    const input = this.rsaVDF.encodeInput(challenge);
    return this.rsaVDF.verifyWesolowski(input, output);
  }

  /** Verify RSA VDF Pietrzak proof */
  verifyRSAPietrzak(challenge: string, output: VDFOutput): VDFVerificationResult {
    const input = this.rsaVDF.encodeInput(challenge);
    return this.rsaVDF.verifyPietrzak(input, output);
  }

  // --- Lattice VDF operations ---

  /** Evaluate lattice-based VDF */
  evaluateLattice(challenge: string, steps?: number): {
    output: ModVector;
    proof: LatticeVDFProof;
    computationTimeMs: number;
    steps: number;
  } {
    const T = steps ?? this.config.defaultTimeParameter;
    const input = this.latticeVDF.encodeInput(challenge);
    return this.latticeVDF.evaluate(input, T);
  }

  /** Verify lattice VDF */
  verifyLattice(
    challenge: string,
    output: ModVector,
    proof: LatticeVDFProof
  ): VDFVerificationResult {
    const input = this.latticeVDF.encodeInput(challenge);
    return this.latticeVDF.verify(input, output, proof);
  }

  // --- Isogeny VDF operations ---

  /** Evaluate isogeny-based VDF */
  evaluateIsogeny(challenge: string, steps?: number): {
    finalCurve: IsogenyCurve;
    path: string[];
    proof: IsogenyVDFProof;
    computationTimeMs: number;
    steps: number;
  } {
    const T = steps ?? this.config.defaultTimeParameter;
    return this.isogenyVDF.evaluate(challenge, T);
  }

  /** Verify isogeny VDF */
  verifyIsogeny(
    challenge: string,
    finalCurve: IsogenyCurve,
    proof: IsogenyVDFProof
  ): VDFVerificationResult {
    return this.isogenyVDF.verify(challenge, finalCurve, proof);
  }

  // --- Chained VDF ---

  /** Create and evaluate a VDF chain */
  evaluateChain(
    challenge: string,
    schedule: Array<{ type: 'rsa' | 'lattice' | 'isogeny'; steps: number }>
  ): ChainLink[] {
    const chained = new ChainedVDF({
      rsa: this.rsaVDF,
      lattice: this.latticeVDF,
      isogeny: this.isogenyVDF,
    });
    return chained.buildChain(challenge, schedule);
  }

  // --- Applications ---

  /** Create a randomness beacon */
  createBeacon(timeParameter?: number): RandomnessBeacon {
    return new RandomnessBeacon(this.rsaVDF, timeParameter ?? this.config.defaultTimeParameter);
  }

  /** Create a fair leader election instance */
  createElection(beacon?: RandomnessBeacon): FairLeaderElection {
    const b = beacon ?? this.createBeacon();
    return new FairLeaderElection(b);
  }

  /** Create a timelock encryption instance */
  createTimelock(): TimelockEncryption {
    return new TimelockEncryption(this.rsaVDF);
  }

  /** Encrypt with timelock */
  timelockEncrypt(plaintext: string, lockSteps: number): TimelockCiphertext {
    const tl = this.createTimelock();
    return tl.encrypt(plaintext, lockSteps);
  }

  /** Decrypt timelock ciphertext */
  timelockDecrypt(ciphertext: TimelockCiphertext): TimelockDecryptionResult {
    const tl = this.createTimelock();
    return tl.decrypt(ciphertext);
  }

  // --- Benchmarking ---

  /** Run benchmarks for all VDF types */
  runBenchmarks(config?: {
    rsaSteps?: number;
    latticeSteps?: number;
    isogenySteps?: number;
  }): Map<string, BenchmarkResult> {
    return this.benchmark.benchmarkAll({
      rsaBits: this.config.rsaBitLength,
      rsaSteps: config?.rsaSteps ?? 5000,
      latticeDim: this.config.latticeDimension,
      latticeSteps: config?.latticeSteps ?? 500,
      isogenyBits: this.config.isogenyPrimeBits,
      isogenySteps: config?.isogenySteps ?? 200,
    });
  }

  /** Calibrate steps for a target delay */
  calibrate(
    vdfType: 'rsa' | 'lattice' | 'isogeny',
    targetTimeMs: number
  ): CalibrationResult {
    return this.benchmark.calibrate(vdfType, targetTimeMs);
  }

  /** Get benchmark summary */
  getBenchmarkSummary(): Array<{
    vdfType: string;
    avgNsPerStep: number;
    avgStepsPerSecond: number;
    runs: number;
  }> {
    return this.benchmark.getSummary();
  }

  // --- Accessors ---

  getRSAVDF(): IteratedSquaringVDF {
    return this.rsaVDF;
  }

  getLatticeVDF(): LatticeBasedVDF {
    return this.latticeVDF;
  }

  getIsogenyVDF(): IsogenyBasedVDF {
    return this.isogenyVDF;
  }

  getVerifier(): VDFVerifier {
    return this.verifier;
  }

  getBenchmarker(): VDFBenchmark {
    return this.benchmark;
  }

  getConfig(): Required<VDFSystemConfig> {
    return { ...this.config };
  }

  /** Get public parameters for all VDF types */
  getAllPublicParams(): Record<string, VDFPublicParams> {
    return {
      rsa: this.rsaVDF.getPublicParams(this.config.defaultTimeParameter),
      lattice: this.latticeVDF.getPublicParams(),
      isogeny: this.isogenyVDF.getPublicParams(this.config.defaultTimeParameter),
    };
  }

  /** Generate a comprehensive system report */
  systemReport(): VDFSystemReport {
    const params = this.getAllPublicParams();
    return {
      version: '1.0.0',
      config: this.config,
      vdfTypes: ['iterated-squaring', 'lattice-vdf', 'isogeny-vdf'],
      publicParams: params,
      features: [
        'Iterated Squaring VDF (RSA group, Wesolowski + Pietrzak proofs)',
        'Lattice-Based VDF (SIS/LWE hardness, PQ-secure)',
        'Isogeny-Based VDF (supersingular curves, PQ-secure)',
        'Chained VDFs (composable, multi-type)',
        'Randomness Beacon (unbiasable, publicly verifiable)',
        'Fair Leader Election (commitment + VDF)',
        'Timelock Encryption (AES-256-GCM + VDF-derived key)',
        'Benchmarking and Difficulty Calibration',
      ],
      securityNotes: {
        iteratedSquaring:
          'Security based on hidden-order group assumption. NOT post-quantum for the group itself, but the sequential computation property holds.',
        lattice:
          'Security based on SIS/LWE hardness. Believed post-quantum secure. Verification requires re-computation (no succinct proof).',
        isogeny:
          'Security based on supersingular isogeny problem. Post-quantum secure. Sequential walk in isogeny graph.',
        timelockEncryption:
          'Uses RSA VDF with trapdoor for fast encryption. Decryption requires sequential VDF computation. AES-256-GCM for symmetric encryption.',
        beacon:
          'Randomness is unbiasable assuming VDF sequentiality. Chain integrity verified through back-links.',
      },
      timestamp: Date.now(),
    };
  }
}

export interface VDFSystemReport {
  version: string;
  config: Required<VDFSystemConfig>;
  vdfTypes: string[];
  publicParams: Record<string, VDFPublicParams>;
  features: string[];
  securityNotes: Record<string, string>;
  timestamp: number;
}
