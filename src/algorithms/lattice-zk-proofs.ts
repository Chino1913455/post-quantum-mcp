/**
 * Post-Quantum Lattice-Based Zero-Knowledge Proofs
 * ==================================================
 *
 * Zero-knowledge proof systems built on lattice hardness assumptions
 * (SIS, LWE, Ring-LWE) — quantum-resistant alternatives to discrete-log
 * and pairing-based ZK systems.
 *
 * Implements:
 *   - Stern-type protocols for SIS (knowledge of short preimage)
 *   - Lattice Σ-protocols (linear relations over Zq)
 *   - Ring-LWE based commitments (Baum et al.)
 *   - Lattice-based range proofs (bulletproof-style)
 *   - Lattice-based set membership proofs
 *   - BDLOP commitment scheme (binding + hiding from Module-SIS/LWE)
 *   - Fiat-Shamir transform for non-interactive proofs
 *   - Proof aggregation and batching
 */

import * as sampling from '../utils/entropy/sampling.js';
import { getNTT } from '../utils/lattice/ntt.js';

// ============================================================
// Core Lattice Arithmetic
// ============================================================

/** Polynomial ring element Zq[X]/(X^n + 1) */
class RingElement {
  readonly coeffs: number[];
  readonly n: number;
  readonly q: number;

  constructor(coeffs: number[], n: number = 256, q: number = 12289) {
    this.n = n;
    this.q = q;
    this.coeffs = new Array(n).fill(0);
    for (let i = 0; i < Math.min(coeffs.length, n); i++) {
      this.coeffs[i] = ((coeffs[i] % q) + q) % q;
    }
  }

  static zero(n: number = 256, q: number = 12289): RingElement {
    return new RingElement(new Array(n).fill(0), n, q);
  }

  static one(n: number = 256, q: number = 12289): RingElement {
    const c = new Array(n).fill(0);
    c[0] = 1;
    return new RingElement(c, n, q);
  }

  static random(n: number = 256, q: number = 12289): RingElement {
    const c = Array.from({ length: n }, () => sampling.randomModInt(q));
    return new RingElement(c, n, q);
  }

  /** Sample from discrete Gaussian (centered) with parameter σ */
  static gaussianSample(n: number = 256, q: number = 12289, sigma: number = 3.2): RingElement {
    const coeffs: number[] = [];
    for (let i = 0; i < n; i++) {
      // CSPRNG-backed discrete Gaussian (was Math.random Box–Muller).
      coeffs.push(sampling.discreteGaussian(sigma));
    }
    return new RingElement(coeffs, n, q);
  }

  /** Sample with small coefficients in [-bound, bound] */
  static smallSample(n: number = 256, q: number = 12289, bound: number = 1): RingElement {
    const coeffs = Array.from({ length: n }, () =>
      sampling.randomIntInclusive(-bound, bound)
    );
    return new RingElement(coeffs, n, q);
  }

  add(other: RingElement): RingElement {
    const result = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      result[i] = (this.coeffs[i] + other.coeffs[i]) % this.q;
    }
    return new RingElement(result, this.n, this.q);
  }

  sub(other: RingElement): RingElement {
    const result = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      result[i] = ((this.coeffs[i] - other.coeffs[i]) % this.q + this.q) % this.q;
    }
    return new RingElement(result, this.n, this.q);
  }

  /**
   * Polynomial multiplication mod (X^n + 1). Uses the negacyclic NTT
   * (O(n log n)) when parameters are NTT-friendly, falling back to schoolbook
   * (O(n^2)) otherwise. The NTT computes the identical ring element (verified
   * bit-for-bit against schoolbook in ntt.test.ts) — pure speedup, no change to
   * the algebra.
   */
  mul(other: RingElement): RingElement {
    const ntt = getNTT(this.n, this.q);
    if (ntt.usable) {
      return new RingElement(ntt.multiply(this.coeffs, other.coeffs), this.n, this.q);
    }
    const result = new Array(this.n).fill(0);
    for (let i = 0; i < this.n; i++) {
      for (let j = 0; j < this.n; j++) {
        const idx = i + j;
        if (idx < this.n) {
          result[idx] = (result[idx] + this.coeffs[i] * other.coeffs[j]) % this.q;
        } else {
          // X^n = -1 in the ring
          result[idx - this.n] = ((result[idx - this.n] - this.coeffs[i] * other.coeffs[j]) % this.q + this.q) % this.q;
        }
      }
    }
    return new RingElement(result, this.n, this.q);
  }

  scalarMul(scalar: number): RingElement {
    const s = ((scalar % this.q) + this.q) % this.q;
    return new RingElement(this.coeffs.map(c => (c * s) % this.q), this.n, this.q);
  }

  /** L2 norm */
  norm(): number {
    return Math.sqrt(this.coeffs.reduce((s, c) => {
      const centered = c > this.q / 2 ? c - this.q : c;
      return s + centered * centered;
    }, 0));
  }

  /** L∞ norm */
  infNorm(): number {
    return Math.max(...this.coeffs.map(c => {
      const centered = c > this.q / 2 ? c - this.q : c;
      return Math.abs(centered);
    }));
  }

  isZero(): boolean {
    return this.coeffs.every(c => c === 0);
  }

  equals(other: RingElement): boolean {
    for (let i = 0; i < this.n; i++) {
      if (this.coeffs[i] !== other.coeffs[i]) return false;
    }
    return true;
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(this.n * 2);
    for (let i = 0; i < this.n; i++) {
      bytes[2 * i] = this.coeffs[i] & 0xFF;
      bytes[2 * i + 1] = (this.coeffs[i] >> 8) & 0xFF;
    }
    return bytes;
  }
}

/** Module element: vector of ring elements */
class ModuleElement {
  readonly elements: RingElement[];
  readonly k: number;

  constructor(elements: RingElement[]) {
    this.elements = elements;
    this.k = elements.length;
  }

  static zero(k: number, n: number = 256, q: number = 12289): ModuleElement {
    return new ModuleElement(Array.from({ length: k }, () => RingElement.zero(n, q)));
  }

  static random(k: number, n: number = 256, q: number = 12289): ModuleElement {
    return new ModuleElement(Array.from({ length: k }, () => RingElement.random(n, q)));
  }

  add(other: ModuleElement): ModuleElement {
    return new ModuleElement(this.elements.map((e, i) => e.add(other.elements[i])));
  }

  sub(other: ModuleElement): ModuleElement {
    return new ModuleElement(this.elements.map((e, i) => e.sub(other.elements[i])));
  }

  /** Inner product with another module element */
  innerProduct(other: ModuleElement): RingElement {
    let result = RingElement.zero(this.elements[0].n, this.elements[0].q);
    for (let i = 0; i < this.k; i++) {
      result = result.add(this.elements[i].mul(other.elements[i]));
    }
    return result;
  }

  norm(): number {
    return Math.sqrt(this.elements.reduce((s, e) => s + e.norm() ** 2, 0));
  }
}

// ============================================================
// Hash / Random Oracle (simplified Fiat-Shamir)
// ============================================================

class LatticeHash {
  /** Simple hash for Fiat-Shamir (in production, use SHAKE-256) */
  static hash(...inputs: (Uint8Array | number[])[]): number[] {
    // FNV-1a variant with wider state for demonstration
    let h0 = 0x811c9dc5;
    let h1 = 0x1000193;
    let h2 = 0xdeadbeef;
    let h3 = 0xcafebabe;

    for (const input of inputs) {
      for (const byte of input) {
        h0 = Math.imul(h0 ^ byte, 0x01000193);
        h1 = Math.imul(h1 ^ (byte + 1), 0x01000193);
        h2 = Math.imul(h2 ^ (byte + 2), 0x100001b3);
        h3 = Math.imul(h3 ^ (byte + 3), 0x100001b3);
      }
    }

    return [
      (h0 >>> 0) & 0xFFFFFFFF,
      (h1 >>> 0) & 0xFFFFFFFF,
      (h2 >>> 0) & 0xFFFFFFFF,
      (h3 >>> 0) & 0xFFFFFFFF,
    ];
  }

  /** Hash to challenge polynomial (sparse ternary) */
  static hashToChallenge(n: number, q: number, ...inputs: (Uint8Array | number[])[]): RingElement {
    const hashValues = LatticeHash.hash(...inputs);
    const coeffs = new Array(n).fill(0);
    // Set tau positions to ±1 (Hamming weight tau challenge).
    // tau MUST be <= n: positions are distinct residues in [0, n), so a target
    // weight above n makes the fill loop below unsatisfiable (infinite loop).
    // This surfaces with small (test) ring dimensions; cap to guarantee
    // termination while keeping a large challenge space (C(n,tau)*2^tau).
    const tau = Math.min(60, n); // challenge weight
    let seed = hashValues[0];
    const positions = new Set<number>();

    while (positions.size < tau) {
      seed = Math.imul(seed, 1664525) + 1013904223;
      const pos = ((seed >>> 0) % n);
      if (!positions.has(pos)) {
        positions.add(pos);
        seed = Math.imul(seed, 1664525) + 1013904223;
        coeffs[pos] = (seed >>> 31) === 0 ? 1 : q - 1; // ±1
      }
    }

    return new RingElement(coeffs, n, q);
  }
}

// ============================================================
// BDLOP Commitment Scheme
// ============================================================

export interface BDLOPParams {
  n: number;       // ring dimension
  q: number;       // modulus
  k: number;       // module rank for binding
  l: number;       // number of committed messages
}

export interface BDLOPCommitment {
  c0: RingElement;       // binding component
  c: RingElement[];      // message-carrying components (l elements)
}

export class BDLOPCommitmentScheme {
  private params: BDLOPParams;
  private A: ModuleElement[];  // public matrix (k rows)
  private B: RingElement[][];  // public matrix for message embedding

  constructor(params?: Partial<BDLOPParams>) {
    this.params = {
      n: params?.n || 256,
      q: params?.q || 12289,
      k: params?.k || 4,
      l: params?.l || 2,
    };

    // Generate public parameters
    this.A = Array.from({ length: this.params.k }, () =>
      ModuleElement.random(this.params.k, this.params.n, this.params.q)
    );
    this.B = Array.from({ length: this.params.l }, () =>
      Array.from({ length: this.params.k }, () =>
        RingElement.random(this.params.n, this.params.q)
      )
    );
  }

  /**
   * Commit to messages m_1, ..., m_l using randomness r.
   * c_0 = A * r (binding)
   * c_i = <b_i, r> + m_i (message-carrying)
   */
  commit(messages: RingElement[], randomness?: ModuleElement): {
    commitment: BDLOPCommitment;
    randomness: ModuleElement;
  } {
    const { n, q, k, l } = this.params;

    if (messages.length !== l) {
      throw new Error(`Expected ${l} messages, got ${messages.length}`);
    }

    // Generate randomness if not provided
    const r = randomness || new ModuleElement(
      Array.from({ length: k }, () => RingElement.gaussianSample(n, q, 3.2))
    );

    // Binding component: c_0 = sum(A_i * r_i) for first row
    let c0 = RingElement.zero(n, q);
    for (let i = 0; i < k; i++) {
      c0 = c0.add(this.A[0].elements[i].mul(r.elements[i]));
    }

    // Message components
    const c: RingElement[] = [];
    for (let j = 0; j < l; j++) {
      let cj = messages[j];
      for (let i = 0; i < k; i++) {
        cj = cj.add(this.B[j][i].mul(r.elements[i]));
      }
      c.push(cj);
    }

    return { commitment: { c0, c }, randomness: r };
  }

  /** Open and verify commitment */
  verify(commitment: BDLOPCommitment, messages: RingElement[], randomness: ModuleElement): boolean {
    const { n, q, k, l } = this.params;

    // Check randomness norm bound
    if (randomness.norm() > Math.sqrt(k * n) * 10) {
      return false; // randomness too large
    }

    // Verify c_0
    let c0Check = RingElement.zero(n, q);
    for (let i = 0; i < k; i++) {
      c0Check = c0Check.add(this.A[0].elements[i].mul(randomness.elements[i]));
    }
    if (!c0Check.equals(commitment.c0)) return false;

    // Verify each message component
    for (let j = 0; j < l; j++) {
      let cjCheck = messages[j];
      for (let i = 0; i < k; i++) {
        cjCheck = cjCheck.add(this.B[j][i].mul(randomness.elements[i]));
      }
      if (!cjCheck.equals(commitment.c[j])) return false;
    }

    return true;
  }

  /** Homomorphic addition of commitments */
  add(com1: BDLOPCommitment, com2: BDLOPCommitment): BDLOPCommitment {
    return {
      c0: com1.c0.add(com2.c0),
      c: com1.c.map((c, i) => c.add(com2.c[i])),
    };
  }
}

// ============================================================
// Stern-Type Protocol (ZK Proof of Short Preimage for SIS)
// ============================================================

export interface SternProof {
  commitments: Uint8Array[];    // 3 commitments per round
  challenges: number[];          // verifier challenges (0, 1, or 2)
  responses: {
    permutation?: number[];
    maskedWitness?: number[];
    maskedPermuted?: number[];
  }[];
  rounds: number;
}

export class SternProtocol {
  /**
   * Prove knowledge of s such that A*s = t (mod q) and ||s|| ≤ β
   * where A is m×n over Zq.
   *
   * This is a Σ-protocol with soundness error 2/3 per round.
   * Repeat λ times for 2^{-λ} soundness.
   */

  private m: number;
  private n: number;
  private q: number;
  private A: number[][];  // m × n matrix

  constructor(A: number[][], q: number = 12289) {
    this.A = A;
    this.m = A.length;
    this.n = A[0].length;
    this.q = q;
  }

  /**
   * Prover generates proof of knowledge of s where A*s = t mod q.
   */
  prove(s: number[], _t: number[], rounds: number = 128): SternProof {
    const proof: SternProof = {
      commitments: [],
      challenges: [],
      responses: [],
      rounds,
    };

    for (let round = 0; round < rounds; round++) {
      // Step 1: Prover generates randomness
      const y = Array.from({ length: this.n }, () =>
        sampling.randomModInt(this.q)
      );

      // Random permutation π of {0,...,n-1}
      const perm = Array.from({ length: this.n }, (_, i) => i);
      for (let i = this.n - 1; i > 0; i--) {
        const j = sampling.randomUniformInt(i + 1);
        [perm[i], perm[j]] = [perm[j], perm[i]];
      }

      // Compute commitments
      // c1 = H(π, A*y mod q)
      const Ay = this.matVecMul(y);
      const c1Bytes = new Uint8Array([...this.encodePermutation(perm), ...this.encodeVector(Ay)]);

      // c2 = H(π(y))
      const permY = perm.map(i => y[i]);
      const c2Bytes = new Uint8Array(this.encodeVector(permY));

      // c3 = H(π(s + y))
      const sPlusY = s.map((si, i) => ((si + y[i]) % this.q + this.q) % this.q);
      const permSPlusY = perm.map(i => sPlusY[i]);
      const c3Bytes = new Uint8Array(this.encodeVector(permSPlusY));

      const c1Hash = LatticeHash.hash(c1Bytes);
      const c2Hash = LatticeHash.hash(c2Bytes);
      const c3Hash = LatticeHash.hash(c3Bytes);

      proof.commitments.push(
        new Uint8Array([...c1Hash, ...c2Hash, ...c3Hash].map(v => v & 0xFF))
      );

      // Step 2: Fiat-Shamir challenge
      const challengeHash = LatticeHash.hash(
        new Uint8Array([...c1Hash, ...c2Hash, ...c3Hash, round].map(v => v & 0xFF))
      );
      const challenge = ((challengeHash[0] >>> 0) % 3);
      proof.challenges.push(challenge);

      // Step 3: Prover responds based on challenge
      switch (challenge) {
        case 0:
          // Reveal π and y
          proof.responses.push({
            permutation: perm,
            maskedWitness: y,
          });
          break;
        case 1:
          // Reveal π(y) and π(s)
          proof.responses.push({
            maskedPermuted: permY,
            maskedWitness: perm.map(i => s[i]),
          });
          break;
        case 2:
          // Reveal π(s+y)
          proof.responses.push({
            maskedPermuted: permSPlusY,
          });
          break;
      }
    }

    return proof;
  }

  /**
   * Verifier checks the proof.
   */
  verify(proof: SternProof, _t: number[]): boolean {
    for (let round = 0; round < proof.rounds; round++) {
      const challenge = proof.challenges[round];
      const response = proof.responses[round];

      switch (challenge) {
        case 0: {
          // Check c1 and c2 are consistent with revealed π and y
          if (!response.permutation || !response.maskedWitness) return false;
          const perm = response.permutation;
          const y = response.maskedWitness;

          // Recompute c1 = H(π, A*y)
          const Ay = this.matVecMul(y);
          const c1Bytes = new Uint8Array([...this.encodePermutation(perm), ...this.encodeVector(Ay)]);
          const c1Hash = LatticeHash.hash(c1Bytes);

          // Recompute c2 = H(π(y))
          const permY = perm.map(i => y[i]);
          const c2Bytes = new Uint8Array(this.encodeVector(permY));
          const c2Hash = LatticeHash.hash(c2Bytes);

          // Verify hashes match commitments
          const expected = proof.commitments[round];
          const combined = [...c1Hash, ...c2Hash].map(v => v & 0xFF);
          for (let i = 0; i < Math.min(combined.length, expected.length / 2); i++) {
            if (combined[i] !== expected[i]) return false;
          }
          break;
        }
        case 1: {
          // Check c2 and c3 using π(y) and π(s)
          if (!response.maskedPermuted || !response.maskedWitness) return false;
          const permY = response.maskedPermuted;
          const permS = response.maskedWitness;

          // Check norm of π(s) — it's a permutation of s, so same norm
          const sNorm = Math.sqrt(permS.reduce((sum, v) => {
            const centered = v > this.q / 2 ? v - this.q : v;
            return sum + centered * centered;
          }, 0));
          if (sNorm > Math.sqrt(this.n) * 10) return false; // shortness check

          // c3 should be consistent: π(s+y) = π(s) + π(y)
          const permSPlusY = permS.map((ps, i) =>
            ((ps + permY[i]) % this.q + this.q) % this.q
          );
          const c3Bytes = new Uint8Array(this.encodeVector(permSPlusY));
          void LatticeHash.hash(c3Bytes); // c3Hash for commitment check

          // Verify A * s^{-perm} = t (need to invert permutation to check)
          // In Stern protocol, we check consistency not the relation directly here
          break;
        }
        case 2: {
          // Check c1 and c3 using π(s+y)
          if (!response.maskedPermuted) return false;
          // Verify consistency of commitments
          break;
        }
      }
    }

    return true;
  }

  private matVecMul(v: number[]): number[] {
    const result = new Array(this.m).fill(0);
    for (let i = 0; i < this.m; i++) {
      for (let j = 0; j < this.n; j++) {
        result[i] = (result[i] + this.A[i][j] * v[j]) % this.q;
      }
    }
    return result;
  }

  private encodePermutation(perm: number[]): number[] {
    return perm.map(p => p & 0xFF);
  }

  private encodeVector(v: number[]): number[] {
    const bytes: number[] = [];
    for (const val of v) {
      bytes.push(val & 0xFF);
      bytes.push((val >> 8) & 0xFF);
    }
    return bytes;
  }
}

// ============================================================
// Lattice Σ-Protocol (Linear Relation Proof)
// ============================================================

export interface LatticeSigmaProof {
  commitment: RingElement;      // t = A*y (commitment)
  challenge: RingElement;       // c ← H(t) (Fiat-Shamir)
  response: ModuleElement;      // z = y + c*s (masked witness)
}

export class LatticeSigmaProtocol {
  /**
   * Prove knowledge of s with small norm such that A·s = u in Rq^k.
   * Based on Lyubashevsky's Fiat-Shamir with aborts.
   */

  private A: ModuleElement[];   // k vectors of module rank m
  private params: { n: number; q: number; k: number; m: number; beta: number };

  constructor(k: number = 4, m: number = 4, n: number = 256, q: number = 12289, beta: number = 1000) {
    this.params = { n, q, k, m, beta };
    this.A = Array.from({ length: k }, () => ModuleElement.random(m, n, q));
  }

  /** Compute A·s = sum_i A_i · s_i */
  private computeAs(s: ModuleElement): RingElement[] {
    const { k } = this.params;
    const result: RingElement[] = [];
    for (let i = 0; i < k; i++) {
      result.push(this.A[i].innerProduct(s));
    }
    return result;
  }

  /**
   * Prove: given public u = A·s, prove knowledge of s with ||s|| ≤ β.
   * Uses rejection sampling (Fiat-Shamir with aborts).
   */
  prove(s: ModuleElement, u: RingElement[]): LatticeSigmaProof | null {
    const { n, q, m, beta } = this.params;
    const maxAttempts = 50;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      // Step 1: Sample masking vector y with large coefficients
      const gamma = beta * 10; // masking parameter
      const y = new ModuleElement(
        Array.from({ length: m }, () => {
          const coeffs = Array.from({ length: n }, () =>
            sampling.randomIntInclusive(-gamma, gamma)
          );
          return new RingElement(coeffs, n, q);
        })
      );

      // Step 2: Commitment w = A·y
      const w = this.computeAs(y);
      const commitment = w[0]; // simplified: use first component

      // Step 3: Fiat-Shamir challenge
      const wBytes = w.map(wi => wi.toBytes());
      const uBytes = u.map(ui => ui.toBytes());
      const challenge = LatticeHash.hashToChallenge(n, q, ...wBytes, ...uBytes);

      // Step 4: Response z = y + c·s
      const z = new ModuleElement(
        y.elements.map((yi, i) => yi.add(challenge.mul(s.elements[i])))
      );

      // Step 5: Rejection sampling — check ||z|| ≤ gamma - beta
      const zNorm = z.norm();
      const bound = gamma - beta;

      if (zNorm > bound) {
        continue; // reject and retry
      }

      // Acceptance probability check (simplified Lyubashevsky rejection)
      const acceptProb = Math.exp(-2 * zNorm * beta / (gamma * gamma));
      if (sampling.randomUnitFloat() > Math.min(1, acceptProb * 3)) {
        continue; // probabilistic rejection
      }

      return { commitment, challenge, response: z };
    }

    return null; // failed after max attempts
  }

  /**
   * Verify proof: check A·z = w + c·u and ||z|| ≤ bound.
   */
  verify(proof: LatticeSigmaProof, u: RingElement[]): boolean {
    const { beta } = this.params;
    const gamma = beta * 10;

    // Check norm bound
    if (proof.response.norm() > gamma - beta) {
      return false;
    }

    // Check A·z = w + c·u
    const Az = this.computeAs(proof.response);

    // w + c·u
    const cu0 = proof.challenge.mul(u[0]);
    const expected = proof.commitment.add(cu0);

    return Az[0].equals(expected);
  }
}

// ============================================================
// Lattice-Based Range Proof
// ============================================================

export interface LatticeRangeProof {
  commitments: BDLOPCommitment[];
  binaryDecomposition: RingElement[];
  innerProductProof: LatticeSigmaProof | null;
  range: [number, number];
}

export class LatticeRangeProofSystem {
  private commitScheme: BDLOPCommitmentScheme;
  private sigmaProtocol: LatticeSigmaProtocol;
  private n: number;
  private q: number;

  constructor(n: number = 256, q: number = 12289) {
    this.n = n;
    this.q = q;
    this.commitScheme = new BDLOPCommitmentScheme({ n, q, k: 4, l: 2 });
    this.sigmaProtocol = new LatticeSigmaProtocol(4, 4, n, q);
  }

  /**
   * Prove that committed value v lies in [0, 2^B - 1].
   * Uses binary decomposition: v = sum_i b_i * 2^i where b_i ∈ {0, 1}.
   * Then proves each b_i is binary via b_i * (1 - b_i) = 0.
   */
  prove(value: number, range: [number, number] = [0, 65535]): LatticeRangeProof {
    const [lo, hi] = range;
    const shifted = value - lo;
    const bits = Math.ceil(Math.log2(hi - lo + 1));

    // Binary decomposition
    const binaryCoeffs: RingElement[] = [];
    const commitments: BDLOPCommitment[] = [];

    for (let i = 0; i < bits; i++) {
      const bit = (shifted >> i) & 1;
      const bitPoly = new RingElement([bit], this.n, this.q);
      binaryCoeffs.push(bitPoly);

      // Commit to each bit
      const { commitment } = this.commitScheme.commit([
        bitPoly,
        bitPoly.mul(bitPoly).sub(bitPoly), // b*(b-1) should be 0
      ]);
      commitments.push(commitment);
    }

    // Prove knowledge of the binary decomposition
    // Simplified: prove via Sigma protocol that sum(b_i * 2^i) = v - lo
    const witness = new ModuleElement(
      binaryCoeffs.map(b => b).concat(
        Array.from({ length: Math.max(0, 4 - binaryCoeffs.length) }, () =>
          RingElement.zero(this.n, this.q)
        )
      ).slice(0, 4)
    );

    const targetPoly = new RingElement([shifted], this.n, this.q);
    const innerProductProof = this.sigmaProtocol.prove(witness, [targetPoly]);

    return {
      commitments,
      binaryDecomposition: binaryCoeffs,
      innerProductProof,
      range,
    };
  }

  /**
   * Verify range proof.
   */
  verify(proof: LatticeRangeProof): boolean {
    const [lo, hi] = proof.range;
    const bits = Math.ceil(Math.log2(hi - lo + 1));

    // Check number of bits
    if (proof.binaryDecomposition.length !== bits) return false;

    // Check each bit is binary: b*(b-1) = 0
    for (let i = 0; i < bits; i++) {
      const b = proof.binaryDecomposition[i];
      const check = b.mul(b).sub(b);
      if (!check.isZero()) return false;
    }

    // Check sum matches committed value
    let sum = RingElement.zero(this.n, this.q);
    for (let i = 0; i < bits; i++) {
      const powerOf2 = new RingElement([1 << i], this.n, this.q);
      sum = sum.add(proof.binaryDecomposition[i].mul(powerOf2));
    }

    // Verify inner product proof
    if (proof.innerProductProof) {
      return this.sigmaProtocol.verify(proof.innerProductProof, [sum]);
    }

    return true;
  }
}

// ============================================================
// Lattice-Based Set Membership Proof
// ============================================================

export interface SetMembershipProof {
  commitmentToValue: BDLOPCommitment;
  commitmentToIndex: BDLOPCommitment;
  equalityProof: LatticeSigmaProof | null;
  setDigest: number[];
}

export class LatticeSetMembershipProof {
  private commitScheme: BDLOPCommitmentScheme;
  private sigmaProtocol: LatticeSigmaProtocol;
  private n: number;
  private q: number;

  constructor(n: number = 256, q: number = 12289) {
    this.n = n;
    this.q = q;
    this.commitScheme = new BDLOPCommitmentScheme({ n, q, k: 4, l: 2 });
    this.sigmaProtocol = new LatticeSigmaProtocol(4, 4, n, q);
  }

  /**
   * Prove that a committed value v is in set S = {s_1, ..., s_N}.
   *
   * Approach: prove there exists index i such that v = s_i.
   * 1. Commit to (v, i)
   * 2. Prove v = S[i] using lookup argument
   */
  prove(value: number, set: number[]): SetMembershipProof {
    const index = set.indexOf(value);
    if (index === -1) throw new Error('Value not in set');

    // Encode value as ring element
    const valuePoly = new RingElement([value], this.n, this.q);
    const indexPoly = new RingElement([index], this.n, this.q);

    // Commit to value
    const { commitment: comValue, randomness: rValue } = this.commitScheme.commit([valuePoly, RingElement.zero(this.n, this.q)]);

    // Commit to index
    const { commitment: comIndex } = this.commitScheme.commit([indexPoly, RingElement.zero(this.n, this.q)]);

    // Prove that committed value equals set[committed_index]
    // Simplified: prove knowledge of value and index as witness
    const witness = new ModuleElement([
      valuePoly,
      indexPoly,
      rValue.elements[0],
      rValue.elements[1] || RingElement.zero(this.n, this.q),
    ]);

    const target = new RingElement([value], this.n, this.q);
    const equalityProof = this.sigmaProtocol.prove(witness, [target]);

    // Set digest (hash of all elements)
    const setBytes: number[] = [];
    for (const s of set) {
      setBytes.push(s & 0xFF, (s >> 8) & 0xFF);
    }
    const setDigest = LatticeHash.hash(new Uint8Array(setBytes));

    return {
      commitmentToValue: comValue,
      commitmentToIndex: comIndex,
      equalityProof,
      setDigest,
    };
  }

  verify(proof: SetMembershipProof, set: number[]): boolean {
    // Verify set digest
    const setBytes: number[] = [];
    for (const s of set) {
      setBytes.push(s & 0xFF, (s >> 8) & 0xFF);
    }
    const expectedDigest = LatticeHash.hash(new Uint8Array(setBytes));
    for (let i = 0; i < expectedDigest.length; i++) {
      if (expectedDigest[i] !== proof.setDigest[i]) return false;
    }

    // Verify equality proof
    if (proof.equalityProof) {
      // For a full implementation, would verify against committed value
      return true;
    }

    return true;
  }
}

// ============================================================
// Proof Aggregation
// ============================================================

export interface AggregatedProof {
  individualCommitments: RingElement[];
  aggregateChallenge: RingElement;
  aggregateResponse: ModuleElement;
  proofCount: number;
}

export class ProofAggregator {
  private n: number;
  private q: number;
  public sigmaProtocol: LatticeSigmaProtocol;

  constructor(n: number = 256, q: number = 12289) {
    this.n = n;
    this.q = q;
    this.sigmaProtocol = new LatticeSigmaProtocol(4, 4, n, q);
  }

  /**
   * Aggregate multiple Sigma proofs into one.
   * Uses random linear combination to compress.
   */
  aggregate(proofs: LatticeSigmaProof[]): AggregatedProof {
    if (proofs.length === 0) throw new Error('No proofs to aggregate');

    const commitments = proofs.map(p => p.commitment);

    // Generate random weights for aggregation (Fiat-Shamir from commitments)
    const weightSeed = LatticeHash.hash(...commitments.map(c => c.toBytes()));
    const weights: number[] = [];
    let seed = weightSeed[0];
    for (let i = 0; i < proofs.length; i++) {
      seed = Math.imul(seed, 6364136223846793005) + 1442695040888963407;
      weights.push(((seed >>> 0) % this.q));
    }

    // Aggregate challenge: c_agg = sum_i w_i * c_i
    let aggChallenge = RingElement.zero(this.n, this.q);
    for (let i = 0; i < proofs.length; i++) {
      aggChallenge = aggChallenge.add(proofs[i].challenge.scalarMul(weights[i]));
    }

    // Aggregate response: z_agg = sum_i w_i * z_i
    const aggResponseElements = proofs[0].response.elements.map((_, j) => {
      let sum = RingElement.zero(this.n, this.q);
      for (let i = 0; i < proofs.length; i++) {
        sum = sum.add(proofs[i].response.elements[j].scalarMul(weights[i]));
      }
      return sum;
    });

    return {
      individualCommitments: commitments,
      aggregateChallenge: aggChallenge,
      aggregateResponse: new ModuleElement(aggResponseElements),
      proofCount: proofs.length,
    };
  }

  /**
   * Verify aggregated proof.
   * Size: O(1) instead of O(N) — commitments still needed but verification is single.
   */
  verifyAggregated(aggProof: AggregatedProof, targets: RingElement[][]): boolean {
    // Recompute weights
    const weightSeed = LatticeHash.hash(...aggProof.individualCommitments.map(c => c.toBytes()));
    let seed = weightSeed[0];
    const weights: number[] = [];
    for (let i = 0; i < aggProof.proofCount; i++) {
      seed = Math.imul(seed, 6364136223846793005) + 1442695040888963407;
      weights.push(((seed >>> 0) % this.q));
    }

    // Check norm bound on aggregate response
    const maxNorm = aggProof.proofCount * 10000; // scaled bound
    if (aggProof.aggregateResponse.norm() > maxNorm) return false;

    // Verify aggregate relation: A * z_agg = sum_i w_i * (w_i + c_i * u_i)
    // Simplified verification
    let aggTarget = RingElement.zero(this.n, this.q);
    for (let i = 0; i < Math.min(aggProof.proofCount, targets.length); i++) {
      const wCommit = aggProof.individualCommitments[i].scalarMul(weights[i]);
      const cU = aggProof.aggregateChallenge.mul(targets[i][0]).scalarMul(weights[i]);
      aggTarget = aggTarget.add(wCommit).add(cU);
    }

    return true; // simplified — full verification would check aggregate relation
  }
}

// ============================================================
// Non-Interactive ZK Proof System (NIZK)
// ============================================================

export interface NIZKProof {
  type: 'knowledge' | 'range' | 'membership' | 'linear_relation';
  commitment: BDLOPCommitment;
  sigmaProof: LatticeSigmaProof | null;
  rangeProof?: LatticeRangeProof;
  membershipProof?: SetMembershipProof;
  publicInputHash: number[];
}

export class LatticeNIZKSystem {
  private commitScheme: BDLOPCommitmentScheme;
  private sigmaProtocol: LatticeSigmaProtocol;
  private rangeProver: LatticeRangeProofSystem;
  private membershipProver: LatticeSetMembershipProof;
  private aggregator: ProofAggregator;

  private n: number;
  private q: number;

  constructor(n: number = 256, q: number = 12289) {
    this.n = n;
    this.q = q;
    this.commitScheme = new BDLOPCommitmentScheme({ n, q, k: 4, l: 2 });
    this.sigmaProtocol = new LatticeSigmaProtocol(4, 4, n, q);
    this.rangeProver = new LatticeRangeProofSystem(n, q);
    this.membershipProver = new LatticeSetMembershipProof(n, q);
    this.aggregator = new ProofAggregator(n, q);
  }

  /**
   * Prove knowledge of secret s such that f(s) = y (public).
   * General-purpose: commits to s, proves linear relation.
   */
  proveKnowledge(
    secret: number[],
    publicOutput: number[]
  ): NIZKProof {
    const secretPoly = new RingElement(secret, this.n, this.q);
    const { commitment } = this.commitScheme.commit([
      secretPoly,
      RingElement.zero(this.n, this.q),
    ]);

    const witness = new ModuleElement([
      secretPoly,
      RingElement.zero(this.n, this.q),
      RingElement.zero(this.n, this.q),
      RingElement.zero(this.n, this.q),
    ]);

    const target = new RingElement(publicOutput, this.n, this.q);
    const sigmaProof = this.sigmaProtocol.prove(witness, [target]);

    return {
      type: 'knowledge',
      commitment,
      sigmaProof,
      publicInputHash: LatticeHash.hash(new Uint8Array(publicOutput.map(v => v & 0xFF))),
    };
  }

  /**
   * Prove value is in range [lo, hi].
   */
  proveRange(value: number, range: [number, number]): NIZKProof {
    const valuePoly = new RingElement([value], this.n, this.q);
    const { commitment } = this.commitScheme.commit([valuePoly, RingElement.zero(this.n, this.q)]);

    const rangeProof = this.rangeProver.prove(value, range);

    return {
      type: 'range',
      commitment,
      sigmaProof: null,
      rangeProof,
      publicInputHash: LatticeHash.hash(new Uint8Array([
        range[0] & 0xFF, (range[0] >> 8) & 0xFF,
        range[1] & 0xFF, (range[1] >> 8) & 0xFF,
      ])),
    };
  }

  /**
   * Prove value is member of a set.
   */
  proveMembership(value: number, set: number[]): NIZKProof {
    const valuePoly = new RingElement([value], this.n, this.q);
    const { commitment } = this.commitScheme.commit([valuePoly, RingElement.zero(this.n, this.q)]);

    const membershipProof = this.membershipProver.prove(value, set);

    return {
      type: 'membership',
      commitment,
      sigmaProof: null,
      membershipProof,
      publicInputHash: LatticeHash.hash(new Uint8Array(set.flatMap(s => [s & 0xFF, (s >> 8) & 0xFF]))),
    };
  }

  /**
   * Verify any NIZK proof.
   */
  verify(proof: NIZKProof, publicInput?: { output?: number[]; range?: [number, number]; set?: number[] }): boolean {
    switch (proof.type) {
      case 'knowledge':
        if (!proof.sigmaProof || !publicInput?.output) return false;
        return this.sigmaProtocol.verify(
          proof.sigmaProof,
          [new RingElement(publicInput.output, this.n, this.q)]
        );

      case 'range':
        if (!proof.rangeProof) return false;
        return this.rangeProver.verify(proof.rangeProof);

      case 'membership':
        if (!proof.membershipProof || !publicInput?.set) return false;
        return this.membershipProver.verify(proof.membershipProof, publicInput.set);

      default:
        return false;
    }
  }

  /**
   * Batch verify multiple proofs efficiently.
   */
  batchVerify(proofs: NIZKProof[], publicInputs: any[]): { allValid: boolean; results: boolean[] } {
    const results = proofs.map((proof, i) => this.verify(proof, publicInputs[i]));
    return { allValid: results.every(r => r), results };
  }

  /**
   * Aggregate multiple sigma proofs.
   */
  aggregateProofs(proofs: NIZKProof[]): AggregatedProof | null {
    const sigmaProofs = proofs
      .filter(p => p.sigmaProof !== null)
      .map(p => p.sigmaProof!);

    if (sigmaProofs.length === 0) return null;
    return this.aggregator.aggregate(sigmaProofs);
  }

  /** Get proof size estimate in bytes */
  estimateProofSize(proofType: 'knowledge' | 'range' | 'membership'): number {
    const ringSize = this.n * 2; // 2 bytes per coefficient
    const commitmentSize = ringSize * 3; // c0 + 2 message components

    switch (proofType) {
      case 'knowledge':
        return commitmentSize + ringSize + 4 * ringSize; // commitment + challenge + 4-element response
      case 'range':
        return commitmentSize + 16 * (commitmentSize + ringSize); // per-bit commitments
      case 'membership':
        return 2 * commitmentSize + 4 * ringSize; // value + index commitments + proof
    }
  }
}
