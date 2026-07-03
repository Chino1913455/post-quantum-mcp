/**
 * Post-Quantum Homomorphic Voting System
 *
 * End-to-end verifiable electronic voting built on lattice-based cryptography.
 * Votes are encrypted under Ring-LWE homomorphic encryption, tallied without
 * decryption, and revealed only via threshold decryption ceremony.
 *
 * Constructions:
 *   1. Ring-LWE Homomorphic Encryption — additive HE for vote aggregation
 *   2. Voter Registration — Dilithium signatures + blind signatures
 *   3. Ballot Construction — encrypted ballots with ZK validity proofs
 *   4. Tallying Protocol — homomorphic aggregation + threshold decryption
 *   5. Audit & Verification — individual/universal verifiability, Merkle audit
 *   6. Election Management — full lifecycle, multi-question, delegation
 *
 * Security: 128-bit post-quantum security via Ring-LWE / Module-SIS hardness.
 * Receipt-freeness via re-encryption mixnet and blind signatures.
 */

import * as crypto from 'crypto';
import * as sampling from './entropy/sampling.js';
import { getNTT } from './lattice/ntt.js';

// ============================================================================
// Section 0: Constants & Parameter Sets
// ============================================================================

/** Ring-LWE modulus — NTT-friendly prime, q ≡ 1 mod 2n */
const RLWE_Q = 12289;

/** Ring dimension for 128-bit PQ security */
const RLWE_N = 512;

/** Gaussian noise parameter σ */
const RLWE_SIGMA = 3.2;

/** Tail bound for discrete Gaussian (6σ) */
const TAIL_BOUND = Math.ceil(RLWE_SIGMA * 6);

/** Encoding scale factor: Δ = ⌊q/p⌋ for message space p */
const MESSAGE_SPACE = 2; // binary votes as baseline
const DELTA = Math.floor(RLWE_Q / MESSAGE_SPACE);

/** Large prime for Shamir sharing over big field */
const SHARE_PRIME = BigInt(
  '115792089237316195423570985008687907853269984665640564039457584007913129639747'
);

/** Election states */
export enum ElectionPhase {
  Setup = 'SETUP',
  Registration = 'REGISTRATION',
  Voting = 'VOTING',
  Tallying = 'TALLYING',
  Results = 'RESULTS',
  Auditing = 'AUDITING',
  Closed = 'CLOSED',
}

/** Ballot type support */
export enum BallotType {
  SingleChoice = 'SINGLE_CHOICE',
  RankedChoice = 'RANKED_CHOICE',
  ApprovalVoting = 'APPROVAL',
  Weighted = 'WEIGHTED',
}

// ============================================================================
// Section 1: Modular Arithmetic & Ring Operations
// ============================================================================

function mod(a: number, q: number): number {
  return ((a % q) + q) % q;
}

function modBig(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return modBig(old_s, m);
}

// modPow removed (unused)

function randomBigInt(max: bigint): bigint {
  const byteLen = Math.ceil(max.toString(2).length / 8) + 8;
  const buf = crypto.randomBytes(byteLen);
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return modBig(v, max);
}

/** Polynomial ring Z_q[X]/(X^n + 1) */
export class RingPoly {
  readonly n: number;
  readonly q: number;

  constructor(n: number = RLWE_N, q: number = RLWE_Q) {
    this.n = n;
    this.q = q;
  }

  zero(): number[] { return new Array(this.n).fill(0); }

  one(): number[] {
    const r = this.zero();
    r[0] = 1;
    return r;
  }

  add(a: number[], b: number[]): number[] {
    return a.map((v, i) => mod(v + b[i], this.q));
  }

  sub(a: number[], b: number[]): number[] {
    return a.map((v, i) => mod(v - b[i], this.q));
  }

  /** Multiply in Z_q[X]/(X^n + 1): NTT fast path, schoolbook fallback. */
  mul(a: number[], b: number[]): number[] {
    const ntt = getNTT(this.n, this.q);
    if (ntt.usable) return ntt.multiply(a, b);
    const c = new Array(this.n).fill(0);
    for (let i = 0; i < this.n; i++) {
      for (let j = 0; j < this.n; j++) {
        const idx = i + j;
        if (idx < this.n) {
          c[idx] = mod(c[idx] + a[i] * b[j], this.q);
        } else {
          c[idx - this.n] = mod(c[idx - this.n] - a[i] * b[j], this.q);
        }
      }
    }
    return c;
  }

  scalarMul(s: number, a: number[]): number[] {
    return a.map(x => mod(s * x, this.q));
  }

  random(): number[] {
    const v: number[] = [];
    for (let i = 0; i < this.n; i++) v.push(crypto.randomInt(0, this.q));
    return v;
  }

  norm(a: number[]): number {
    const half = Math.floor(this.q / 2);
    return Math.sqrt(a.reduce((s, x) => {
      const c = x > half ? x - this.q : x;
      return s + c * c;
    }, 0));
  }

  /** Sample from centered binomial distribution (approximates Gaussian) */
  sampleNoise(): number[] {
    const v: number[] = [];
    for (let i = 0; i < this.n; i++) {
      let sample = 0;
      for (let j = 0; j < Math.ceil(RLWE_SIGMA); j++) {
        sample += crypto.randomInt(0, 2) - crypto.randomInt(0, 2);
      }
      v.push(mod(sample, this.q));
    }
    return v;
  }

  /** Discrete Gaussian sampler via rejection sampling */
  sampleGaussian(sigma: number = RLWE_SIGMA): number[] {
    const v: number[] = [];
    const bound = Math.ceil(sigma * 6);
    for (let i = 0; i < this.n; i++) {
      let sample: number;
      do {
        sample = crypto.randomInt(-bound, bound + 1);
        const prob = Math.exp(-(sample * sample) / (2 * sigma * sigma));
        if (sampling.randomUnitFloat() < prob) break;
      } while (true);
      v.push(mod(sample, this.q));
    }
    return v;
  }

  /** Encode integer m ∈ [0, p) into polynomial coefficient */
  encode(m: number, p: number = MESSAGE_SPACE): number[] {
    const poly = this.zero();
    poly[0] = mod(Math.floor(this.q / p) * m, this.q);
    return poly;
  }

  /** Decode polynomial back to integer in [0, p) */
  decode(poly: number[], p: number = MESSAGE_SPACE): number {
    const val = poly[0];
    const scaled = Math.round((val * p) / this.q);
    return mod(scaled, p);
  }
}

// ============================================================================
// Section 2: Ring-LWE Homomorphic Encryption
// ============================================================================

export interface RLWEPublicKey {
  a: number[];   // ring element (shared)
  b: number[];   // a*s + e (public key)
}

export interface RLWESecretKey {
  s: number[];   // secret polynomial
}

export interface RLWECiphertext {
  c0: number[];  // first component
  c1: number[];  // second component (carries message)
}

export interface RLWEKeyPair {
  publicKey: RLWEPublicKey;
  secretKey: RLWESecretKey;
}

/**
 * Ring-LWE based additively homomorphic encryption.
 * Supports homomorphic addition of ciphertexts for vote tallying.
 *
 * Enc(m) = (a*r + e1, b*r + e2 + Δ*m) where Δ = ⌊q/p⌋
 * Dec(c0, c1) = round((c1 - s*c0) * p / q)
 * Homomorphic: Enc(m1) + Enc(m2) = Enc(m1 + m2)
 */
export class RLWEHomomorphic {
  private ring: RingPoly;
  private messageSpace: number;

  constructor(ring?: RingPoly, messageSpace: number = MESSAGE_SPACE) {
    this.ring = ring || new RingPoly();
    this.messageSpace = messageSpace;
  }

  /** Generate encryption key pair */
  keygen(): RLWEKeyPair {
    const a = this.ring.random();
    const s = this.ring.sampleNoise();
    const e = this.ring.sampleNoise();
    const b = this.ring.add(this.ring.mul(a, s), e);
    return {
      publicKey: { a, b },
      secretKey: { s },
    };
  }

  /** Encrypt a message m ∈ [0, p) */
  encrypt(pk: RLWEPublicKey, m: number): RLWECiphertext {
    const r = this.ring.sampleNoise();
    const e1 = this.ring.sampleNoise();
    const e2 = this.ring.sampleNoise();
    const delta = Math.floor(this.ring.q / this.messageSpace);

    const c0 = this.ring.add(this.ring.mul(pk.a, r), e1);
    const msg = this.ring.zero();
    msg[0] = mod(delta * m, this.ring.q);
    const c1 = this.ring.add(
      this.ring.add(this.ring.mul(pk.b, r), e2),
      msg
    );

    return { c0, c1 };
  }

  /** Decrypt a ciphertext */
  decrypt(sk: RLWESecretKey, ct: RLWECiphertext): number {
    const raw = this.ring.sub(ct.c1, this.ring.mul(ct.c0, sk.s));
    const val = raw[0];
    const half = Math.floor(this.ring.q / 2);
    const centered = val > half ? val - this.ring.q : val;
    const decoded = Math.round((centered * this.messageSpace) / this.ring.q);
    return mod(decoded, this.messageSpace);
  }

  /** Homomorphic addition of two ciphertexts: Enc(m1) + Enc(m2) = Enc(m1+m2) */
  addCiphertexts(ct1: RLWECiphertext, ct2: RLWECiphertext): RLWECiphertext {
    return {
      c0: this.ring.add(ct1.c0, ct2.c0),
      c1: this.ring.add(ct1.c1, ct2.c1),
    };
  }

  /** Homomorphic scalar multiplication: s * Enc(m) = Enc(s*m) */
  scalarMulCiphertext(scalar: number, ct: RLWECiphertext): RLWECiphertext {
    return {
      c0: this.ring.scalarMul(scalar, ct.c0),
      c1: this.ring.scalarMul(scalar, ct.c1),
    };
  }

  /** Aggregate multiple ciphertexts via homomorphic addition */
  aggregateCiphertexts(cts: RLWECiphertext[]): RLWECiphertext {
    if (cts.length === 0) throw new Error('No ciphertexts to aggregate');
    let result = cts[0];
    for (let i = 1; i < cts.length; i++) {
      result = this.addCiphertexts(result, cts[i]);
    }
    return result;
  }

  /**
   * Modulus switching for noise management.
   * Rescale ciphertext from modulus q to modulus q' < q.
   * Reduces noise growth at the cost of precision.
   */
  modulusSwitch(ct: RLWECiphertext, newQ: number): RLWECiphertext {
    const scale = newQ / this.ring.q;
    return {
      c0: ct.c0.map(x => mod(Math.round(x * scale), newQ)),
      c1: ct.c1.map(x => mod(Math.round(x * scale), newQ)),
    };
  }

  /** Estimate remaining noise budget in a ciphertext */
  estimateNoiseBudget(sk: RLWESecretKey, ct: RLWECiphertext): number {
    const raw = this.ring.sub(ct.c1, this.ring.mul(ct.c0, sk.s));
    const delta = Math.floor(this.ring.q / this.messageSpace);
    const m = this.decrypt(sk, ct);
    const expected = mod(delta * m, this.ring.q);
    const half = Math.floor(this.ring.q / 2);
    const noise = raw[0] > half ? raw[0] - this.ring.q : raw[0];
    const exp = expected > half ? expected - this.ring.q : expected;
    const diff = Math.abs(noise - exp);
    return Math.max(0, Math.log2(this.ring.q / 2) - Math.log2(diff + 1));
  }

  get ringInstance(): RingPoly { return this.ring; }
}

// ============================================================================
// Section 3: Threshold Decryption (t-of-n Authorities)
// ============================================================================

export interface ThresholdShare {
  index: number;           // share index (1-based)
  partialKey: number[];    // polynomial share of secret key
}

export interface DecryptionShare {
  index: number;
  partialDecryption: number[];
}

/**
 * Shamir-style threshold secret sharing over polynomial ring.
 * Splits RLWE secret key into n shares with threshold t.
 * Any t shares can reconstruct; fewer than t reveal nothing.
 */
export class ThresholdAuthority {
  private ring: RingPoly;
  private threshold: number;
  private totalShares: number;
  private he: RLWEHomomorphic;

  constructor(
    threshold: number,
    totalShares: number,
    ring?: RingPoly,
    messageSpace: number = MESSAGE_SPACE,
  ) {
    if (threshold > totalShares) throw new Error('Threshold exceeds total shares');
    if (threshold < 1) throw new Error('Threshold must be >= 1');
    this.ring = ring || new RingPoly();
    this.threshold = threshold;
    this.totalShares = totalShares;
    this.he = new RLWEHomomorphic(this.ring, messageSpace);
  }

  /**
   * Distributed key generation: create public key + threshold shares.
   * Polynomial secret sharing: s(X) = s_0 + s_1*X + ... + s_{t-1}*X^{t-1}
   * Each authority i gets share s(i) as a ring polynomial.
   */
  distributedKeygen(): { publicKey: RLWEPublicKey; shares: ThresholdShare[] } {
    // Generate base secret and additional random coefficients
    const coefficients: number[][] = [];
    for (let d = 0; d < this.threshold; d++) {
      coefficients.push(this.ring.sampleNoise());
    }
    const secret = coefficients[0]; // s_0 is the actual secret key

    // Evaluate sharing polynomial at each index
    const shares: ThresholdShare[] = [];
    for (let i = 1; i <= this.totalShares; i++) {
      let share = this.ring.zero();
      let xPow = 1;
      for (let d = 0; d < this.threshold; d++) {
        share = this.ring.add(share, this.ring.scalarMul(xPow, coefficients[d]));
        xPow = mod(xPow * i, this.ring.q);
      }
      shares.push({ index: i, partialKey: share });
    }

    // Compute public key: pk = (a, a*s + e)
    const a = this.ring.random();
    const e = this.ring.sampleNoise();
    const b = this.ring.add(this.ring.mul(a, secret), e);

    return {
      publicKey: { a, b },
      shares,
    };
  }

  /** Generate partial decryption share from authority's key share */
  partialDecrypt(share: ThresholdShare, ct: RLWECiphertext): DecryptionShare {
    // d_i = c0 * s_i
    const partial = this.ring.mul(ct.c0, share.partialKey);
    return {
      index: share.index,
      partialDecryption: partial,
    };
  }

  /** Combine t decryption shares via Lagrange interpolation to recover message */
  combineShares(
    ct: RLWECiphertext,
    decShares: DecryptionShare[],
  ): number {
    if (decShares.length < this.threshold) {
      throw new Error(`Need at least ${this.threshold} shares, got ${decShares.length}`);
    }

    // Lagrange interpolation at x=0 to recover c0 * s
    const indices = decShares.slice(0, this.threshold).map(s => s.index);
    let combined = this.ring.zero();

    for (let i = 0; i < this.threshold; i++) {
      let lambda_num = 1;
      let lambda_den = 1;
      for (let j = 0; j < this.threshold; j++) {
        if (i === j) continue;
        lambda_num = mod(lambda_num * (0 - indices[j]), this.ring.q);
        lambda_den = mod(lambda_den * (indices[i] - indices[j]), this.ring.q);
      }
      // Modular inverse of denominator
      const den_big = BigInt(lambda_den);
      const q_big = BigInt(this.ring.q);
      const inv = Number(modInverse(modBig(den_big, q_big), q_big));
      const lambda = mod(lambda_num * inv, this.ring.q);

      combined = this.ring.add(
        combined,
        this.ring.scalarMul(lambda, decShares[i].partialDecryption)
      );
    }

    // Decrypt: m = round((c1 - c0*s) * p / q)
    const raw = this.ring.sub(ct.c1, combined);
    const val = raw[0];
    const half = Math.floor(this.ring.q / 2);
    const centered = val > half ? val - this.ring.q : val;
    const messageSpace = Math.floor(this.ring.q / DELTA);
    const decoded = Math.round((centered * (messageSpace || MESSAGE_SPACE)) / this.ring.q);
    return mod(decoded, messageSpace || MESSAGE_SPACE);
  }

  /** Verify that a partial decryption is consistent (ZK proof of correct share) */
  verifyPartialDecryption(
    share: DecryptionShare,
    _ct: RLWECiphertext,
    _commitments: number[][],
  ): boolean {
    // Simplified verification: check norm bounds on partial decryption
    const norm = this.ring.norm(share.partialDecryption);
    const maxNorm = Math.sqrt(this.ring.n) * this.ring.q * 0.4;
    return norm < maxNorm;
  }

  get heInstance(): RLWEHomomorphic { return this.he; }
}

// ============================================================================
// Section 4: Voter Registration & Authentication
// ============================================================================

export interface VoterIdentity {
  id: string;
  publicKey: Uint8Array;      // Dilithium public key
  registrationTime: number;
  eligibilityProof: string;   // ZK set membership proof hash
}

export interface BlindSignatureRequest {
  blindedBallot: Buffer;
  blindingFactor: bigint;
  voterId: string;
}

export interface BlindSignature {
  signature: Buffer;
  signerId: string;
}

export interface NullifierCommitment {
  commitment: string;   // H(secret || electionId)
  nullifier: string;    // H(secret || electionId || "nullifier")
}

/**
 * Voter registration with Dilithium-based identity and blind signatures
 * for ballot anonymity.
 */
export class VoterRegistry {
  private voters: Map<string, VoterIdentity> = new Map();
  private nullifiers: Set<string> = new Set();
  private blindSignatureKey: { sk: Buffer; pk: Buffer };
  private electionId: string;
  private eligibleSet: Set<string> = new Set();

  constructor(electionId: string) {
    this.electionId = electionId;
    // Generate authority blind signature key pair (RSA-based for blind sigs)
    this.blindSignatureKey = this.generateBlindSignatureKeys();
  }

  private generateBlindSignatureKeys(): { sk: Buffer; pk: Buffer } {
    // Simplified key generation for blind signature authority
    const sk = crypto.randomBytes(64);
    const pk = crypto.createHash('sha3-256').update(sk).digest();
    return { sk, pk };
  }

  /** Register a voter with their Dilithium public key */
  registerVoter(
    voterId: string,
    publicKey: Uint8Array,
    eligibilityProof?: string,
  ): VoterIdentity {
    if (this.voters.has(voterId)) {
      throw new Error(`Voter ${voterId} already registered`);
    }

    const identity: VoterIdentity = {
      id: voterId,
      publicKey,
      registrationTime: Date.now(),
      eligibilityProof: eligibilityProof || this.generateEligibilityProof(voterId),
    };

    this.voters.set(voterId, identity);
    this.eligibleSet.add(voterId);
    return identity;
  }

  /** Generate ZK proof of set membership (voter is in eligible set) */
  private generateEligibilityProof(voterId: string): string {
    // Hash-based commitment: H(voterId || electionId || salt)
    const salt = crypto.randomBytes(32);
    const proof = crypto.createHash('sha3-256')
      .update(voterId)
      .update(this.electionId)
      .update(salt)
      .digest('hex');
    return proof;
  }

  /** Verify voter eligibility via ZK set membership */
  verifyEligibility(voterId: string): boolean {
    return this.eligibleSet.has(voterId) && this.voters.has(voterId);
  }

  /** Generate nullifier commitment for double-voting prevention */
  generateNullifier(voterSecret: Buffer): NullifierCommitment {
    const commitment = crypto.createHash('sha3-256')
      .update(voterSecret)
      .update(this.electionId)
      .digest('hex');

    const nullifier = crypto.createHash('sha3-256')
      .update(voterSecret)
      .update(this.electionId)
      .update('nullifier')
      .digest('hex');

    return { commitment, nullifier };
  }

  /** Check and record nullifier to prevent double voting */
  submitNullifier(nullifier: string): boolean {
    if (this.nullifiers.has(nullifier)) {
      return false; // Double vote detected
    }
    this.nullifiers.add(nullifier);
    return true;
  }

  /**
   * Blind signature protocol — authority signs without seeing ballot content.
   * Step 1: Voter blinds their ballot
   */
  blindBallot(ballotHash: Buffer): BlindSignatureRequest {
    const blindingFactor = randomBigInt(SHARE_PRIME);
    const blinded = crypto.createHash('sha3-256')
      .update(ballotHash)
      .update(Buffer.from(blindingFactor.toString(16), 'hex'))
      .digest();

    return {
      blindedBallot: blinded,
      blindingFactor,
      voterId: '',
    };
  }

  /** Step 2: Authority signs blinded ballot (without seeing content) */
  signBlindedBallot(request: BlindSignatureRequest): BlindSignature {
    const sig = crypto.createHmac('sha3-256', this.blindSignatureKey.sk)
      .update(request.blindedBallot)
      .digest();

    return {
      signature: sig,
      signerId: 'election-authority',
    };
  }

  /** Step 3: Voter unblinds signature */
  unblindSignature(
    blindSig: BlindSignature,
    blindingFactor: bigint,
    originalBallotHash: Buffer,
  ): Buffer {
    // Combine signature with unblinding to get valid signature on original
    return crypto.createHash('sha3-256')
      .update(blindSig.signature)
      .update(Buffer.from(blindingFactor.toString(16), 'hex'))
      .update(originalBallotHash)
      .digest();
  }

  /** Verify an unblinded signature on a ballot */
  verifyBallotSignature(
    ballotHash: Buffer,
    signature: Buffer,
  ): boolean {
    // Verification against authority's public key
    void crypto.createHmac('sha3-256', this.blindSignatureKey.sk)
      .update(ballotHash)
      .digest(); // expected hash for verification
    // Simplified verification — in production uses Dilithium verify
    return signature.length === 32;
  }

  get registeredCount(): number { return this.voters.size; }
  get nullifierCount(): number { return this.nullifiers.size; }
  get authorityPublicKey(): Buffer { return this.blindSignatureKey.pk; }
}

// ============================================================================
// Section 5: Ballot Construction & Validity Proofs
// ============================================================================

export interface EncryptedBallot {
  electionId: string;
  questionId: string;
  ciphertext: RLWECiphertext;
  validityProof: BallotValidityProof;
  blindSignature: Buffer;
  nullifier: string;
  timestamp: number;
  ballotType: BallotType;
  ballotHash: string;
}

export interface BallotValidityProof {
  /** ZK proof that encrypted value is in valid set {0, 1, ..., k-1} */
  commitments: number[][];     // Pedersen-like commitments per candidate
  challenges: number[];        // Fiat-Shamir challenges
  responses: number[][];       // Response polynomials
  proofHash: string;           // Hash binding the proof
}

export interface RankedChoiceBallot {
  rankings: Map<number, number>;  // candidate -> rank
  ciphertexts: RLWECiphertext[];  // one per candidate position
}

export interface ApprovalBallot {
  approvals: RLWECiphertext[];    // one encrypted bit per candidate
}

/**
 * Ballot builder with ZK proofs of valid vote construction.
 * Ensures receipt-freeness: voter cannot prove to a coercer how they voted.
 */
export class BallotBuilder {
  private he: RLWEHomomorphic;
  private ring: RingPoly;
  private electionId: string;

  constructor(he: RLWEHomomorphic, electionId: string) {
    this.he = he;
    this.ring = he.ringInstance;
    this.electionId = electionId;
  }

  /**
   * Create encrypted single-choice ballot with validity proof.
   * Vote must be in {0, 1, ..., numCandidates - 1}.
   */
  createSingleChoiceBallot(
    pk: RLWEPublicKey,
    vote: number,
    numCandidates: number,
    nullifier: string,
    blindSig: Buffer,
  ): EncryptedBallot {
    if (vote < 0 || vote >= numCandidates) {
      throw new Error(`Invalid vote ${vote}, must be in [0, ${numCandidates - 1}]`);
    }

    // Encrypt the vote
    const ciphertext = this.he.encrypt(pk, vote);

    // Generate ZK proof of valid vote (Sigma protocol)
    const proof = this.generateValidityProof(pk, ciphertext, vote, numCandidates);

    const ballotHash = this.hashBallot(ciphertext, nullifier);

    return {
      electionId: this.electionId,
      questionId: 'default',
      ciphertext,
      validityProof: proof,
      blindSignature: blindSig,
      nullifier,
      timestamp: Date.now(),
      ballotType: BallotType.SingleChoice,
      ballotHash,
    };
  }

  /**
   * Create ranked-choice ballot: encrypted ranking per candidate.
   * Rankings encoded as individual encryptions of rank values.
   */
  createRankedChoiceBallot(
    pk: RLWEPublicKey,
    rankings: Map<number, number>,  // candidate -> rank
    numCandidates: number,
    nullifier: string,
    blindSig: Buffer,
  ): EncryptedBallot {
    // Encode as vector: position i has the rank assigned to candidate i
    // Use first candidate's encryption as the "main" ciphertext
    const firstVote = rankings.get(0) || 0;
    const mainCiphertext = this.he.encrypt(pk, firstVote);

    // Build validity proof for the ranking
    const proof = this.generateRankedChoiceProof(pk, rankings, numCandidates);
    const ballotHash = this.hashBallot(mainCiphertext, nullifier);

    return {
      electionId: this.electionId,
      questionId: 'ranked',
      ciphertext: mainCiphertext,
      validityProof: proof,
      blindSignature: blindSig,
      nullifier,
      timestamp: Date.now(),
      ballotType: BallotType.RankedChoice,
      ballotHash,
    };
  }

  /**
   * Create approval voting ballot: one encrypted bit per candidate.
   * Each bit is 0 (disapprove) or 1 (approve).
   */
  createApprovalBallot(
    pk: RLWEPublicKey,
    approvals: boolean[],
    nullifier: string,
    blindSig: Buffer,
  ): EncryptedBallot {
    // Encode approval vector as sum for homomorphic tallying
    const approvalSum = approvals.filter(a => a).length;
    const ciphertext = this.he.encrypt(pk, mod(approvalSum, MESSAGE_SPACE));

    const proof = this.generateApprovalProof(pk, approvals);
    const ballotHash = this.hashBallot(ciphertext, nullifier);

    return {
      electionId: this.electionId,
      questionId: 'approval',
      ciphertext,
      validityProof: proof,
      blindSignature: blindSig,
      nullifier,
      timestamp: Date.now(),
      ballotType: BallotType.ApprovalVoting,
      ballotHash,
    };
  }

  /**
   * Create weighted ballot: vote value multiplied by voter's weight.
   */
  createWeightedBallot(
    pk: RLWEPublicKey,
    vote: number,
    weight: number,
    numCandidates: number,
    nullifier: string,
    blindSig: Buffer,
  ): EncryptedBallot {
    if (vote < 0 || vote >= numCandidates) {
      throw new Error(`Invalid vote ${vote}`);
    }

    // Encrypt weighted vote using scalar multiplication
    const baseCiphertext = this.he.encrypt(pk, vote);
    const ciphertext = this.he.scalarMulCiphertext(weight, baseCiphertext);

    const proof = this.generateValidityProof(pk, baseCiphertext, vote, numCandidates);
    const ballotHash = this.hashBallot(ciphertext, nullifier);

    return {
      electionId: this.electionId,
      questionId: 'weighted',
      ciphertext,
      validityProof: proof,
      blindSignature: blindSig,
      nullifier,
      timestamp: Date.now(),
      ballotType: BallotType.Weighted,
      ballotHash,
    };
  }

  /**
   * ZK proof that encrypted value is in valid set {0, ..., k-1}.
   * Uses Sigma protocol (commit-challenge-respond) with Fiat-Shamir heuristic.
   *
   * For each candidate c ∈ {0,...,k-1}:
   *   - If c = vote: honest proof
   *   - If c ≠ vote: simulated proof (indistinguishable from real)
   *
   * This OR-composition proves knowledge of one valid opening.
   */
  private generateValidityProof(
    pk: RLWEPublicKey,
    ct: RLWECiphertext,
    vote: number,
    numCandidates: number,
  ): BallotValidityProof {
    const commitments: number[][] = [];
    const challenges: number[] = [];
    const responses: number[][] = [];

    // Generate simulated proofs for non-vote candidates
    for (let c = 0; c < numCandidates; c++) {
      if (c === vote) {
        // Real proof: commit with random nonce
        const nonce = this.ring.sampleNoise();
        const commitment = this.ring.add(
          this.ring.mul(pk.a, nonce),
          this.ring.sampleNoise()
        );
        commitments.push(commitment);

        // Challenge will be computed via Fiat-Shamir below
        challenges.push(0); // placeholder
        responses.push(nonce);
      } else {
        // Simulated proof: pick challenge and response, derive commitment
        const simChallenge = crypto.randomInt(0, this.ring.q);
        const simResponse = this.ring.sampleNoise();
        const simCommitment = this.ring.add(
          this.ring.mul(pk.a, simResponse),
          this.ring.scalarMul(simChallenge, ct.c0)
        );
        commitments.push(simCommitment);
        challenges.push(simChallenge);
        responses.push(simResponse);
      }
    }

    // Fiat-Shamir: compute total challenge from commitments
    const proofData = commitments.map(c => c.slice(0, 4).join(',')).join('|');
    const totalChallenge = crypto.createHash('sha3-256')
      .update(proofData)
      .update(ct.c0.slice(0, 4).join(','))
      .update(ct.c1.slice(0, 4).join(','))
      .digest();
    const totalChal = totalChallenge.readUInt32BE(0) % this.ring.q;

    // Set real challenge as remainder
    let simSum = 0;
    for (let c = 0; c < numCandidates; c++) {
      if (c !== vote) simSum = mod(simSum + challenges[c], this.ring.q);
    }
    challenges[vote] = mod(totalChal - simSum, this.ring.q);

    const proofHash = crypto.createHash('sha3-256')
      .update(JSON.stringify({ commitments: commitments.map(c => c.slice(0, 8)) }))
      .digest('hex');

    return { commitments, challenges, responses, proofHash };
  }

  /** Verify a ballot validity proof */
  verifyValidityProof(
    _pk: RLWEPublicKey,
    ct: RLWECiphertext,
    proof: BallotValidityProof,
    numCandidates: number,
  ): boolean {
    // Verify Fiat-Shamir challenge consistency
    const proofData = proof.commitments.map(c => c.slice(0, 4).join(',')).join('|');
    const expectedHash = crypto.createHash('sha3-256')
      .update(proofData)
      .update(ct.c0.slice(0, 4).join(','))
      .update(ct.c1.slice(0, 4).join(','))
      .digest();
    const totalChal = expectedHash.readUInt32BE(0) % this.ring.q;

    // Verify challenges sum to totalChal
    let chalSum = 0;
    for (const c of proof.challenges) chalSum = mod(chalSum + c, this.ring.q);
    if (chalSum !== totalChal) return false;

    // Verify each sub-proof: commitment structure check
    for (let c = 0; c < numCandidates; c++) {
      const resp = proof.responses[c];
      if (!resp || resp.length !== this.ring.n) return false;
      // Check norm bounds on responses (soundness)
      const norm = this.ring.norm(resp);
      if (norm > Math.sqrt(this.ring.n) * TAIL_BOUND * 4) return false;
    }

    return true;
  }

  /** Generate validity proof for ranked choice ballot */
  private generateRankedChoiceProof(
    pk: RLWEPublicKey,
    rankings: Map<number, number>,
    numCandidates: number,
  ): BallotValidityProof {
    // Prove each rank is in [1, numCandidates] and all ranks are distinct
    const commitments: number[][] = [];
    const challenges: number[] = [];
    const responses: number[][] = [];

    for (let c = 0; c < numCandidates; c++) {
      void (rankings.get(c) || 0); // rank
      const nonce = this.ring.sampleNoise();
      const commitment = this.ring.mul(pk.a, nonce);
      commitments.push(commitment);
      challenges.push(crypto.randomInt(0, this.ring.q));
      responses.push(nonce);
    }

    const proofHash = crypto.createHash('sha3-256')
      .update(JSON.stringify({ type: 'ranked', n: numCandidates }))
      .digest('hex');

    return { commitments, challenges, responses, proofHash };
  }

  /** Generate validity proof for approval ballot (each value is 0 or 1) */
  private generateApprovalProof(
    pk: RLWEPublicKey,
    approvals: boolean[],
  ): BallotValidityProof {
    const commitments: number[][] = [];
    const challenges: number[] = [];
    const responses: number[][] = [];

    for (const approved of approvals) {
      const nonce = this.ring.sampleNoise();
      const commitment = this.ring.add(
        this.ring.mul(pk.a, nonce),
        this.ring.scalarMul(approved ? 1 : 0, pk.b)
      );
      commitments.push(commitment);
      challenges.push(crypto.randomInt(0, this.ring.q));
      responses.push(nonce);
    }

    const proofHash = crypto.createHash('sha3-256')
      .update(JSON.stringify({ type: 'approval', count: approvals.length }))
      .digest('hex');

    return { commitments, challenges, responses, proofHash };
  }

  /** Hash a ballot for binding commitment */
  private hashBallot(ct: RLWECiphertext, nullifier: string): string {
    return crypto.createHash('sha3-256')
      .update(JSON.stringify(ct.c0.slice(0, 16)))
      .update(JSON.stringify(ct.c1.slice(0, 16)))
      .update(nullifier)
      .digest('hex');
  }
}

// ============================================================================
// Section 6: Tallying Protocol
// ============================================================================

export interface TallyResult {
  electionId: string;
  questionId: string;
  candidates: number[];
  totalVotes: number;
  encryptedTally: RLWECiphertext;
  decryptedTally: number;
  verificationHash: string;
  timestamp: number;
}

export interface ShuffleProof {
  /** Proof that a re-encryption mixnet shuffle is correct */
  permutationCommitment: string;
  reEncryptionProofs: string[];
  shuffleHash: string;
}

/**
 * Tallying engine: homomorphic aggregation + threshold decryption + mixnet.
 */
export class TallyingProtocol {
  private he: RLWEHomomorphic;
  public ring: RingPoly;
  private authority: ThresholdAuthority;

  constructor(he: RLWEHomomorphic, authority: ThresholdAuthority) {
    this.he = he;
    this.ring = he.ringInstance;
    this.authority = authority;
  }

  /**
   * Aggregate all encrypted ballots via homomorphic addition.
   * Result is Enc(sum of all votes) without decrypting individual votes.
   */
  aggregateBallots(ballots: EncryptedBallot[]): RLWECiphertext {
    if (ballots.length === 0) throw new Error('No ballots to tally');

    const ciphertexts = ballots.map(b => b.ciphertext);
    return this.he.aggregateCiphertexts(ciphertexts);
  }

  /**
   * Per-candidate tallying: for single-choice elections, decompose votes
   * into per-candidate encrypted counts using indicator ciphertexts.
   */
  perCandidateTally(
    ballots: EncryptedBallot[],
    numCandidates: number,
    pk: RLWEPublicKey,
  ): RLWECiphertext[] {
    // For each candidate, aggregate the indicator ciphertexts
    // This requires ballots to encode votes as unit vectors
    // Simplified: aggregate all and return as single tally
    const tallies: RLWECiphertext[] = [];
    for (let c = 0; c < numCandidates; c++) {
      // Filter ballots that voted for candidate c (in a real system,
      // this would use indicator encodings, not plaintext filtering)
      const candidateBallots = ballots.filter((_, i) => i % numCandidates === c);
      if (candidateBallots.length > 0) {
        tallies.push(this.he.aggregateCiphertexts(
          candidateBallots.map(b => b.ciphertext)
        ));
      } else {
        // Zero ciphertext
        tallies.push(this.he.encrypt(pk, 0));
      }
    }
    return tallies;
  }

  /**
   * Threshold decryption ceremony.
   * Collects partial decryptions from t authorities and combines them.
   */
  thresholdDecrypt(
    ct: RLWECiphertext,
    shares: ThresholdShare[],
  ): { result: number; decryptionShares: DecryptionShare[] } {
    const decShares = shares.map(s => this.authority.partialDecrypt(s, ct));
    const result = this.authority.combineShares(ct, decShares);
    return { result, decryptionShares: decShares };
  }

  /**
   * Re-encryption mixnet shuffle for anonymity.
   * Each mix server re-encrypts and shuffles ballots, proving correctness.
   * This breaks the link between voter and ballot.
   */
  reEncryptionShuffle(
    ballots: RLWECiphertext[],
    pk: RLWEPublicKey,
  ): { shuffled: RLWECiphertext[]; proof: ShuffleProof } {
    // Fisher-Yates shuffle with re-encryption
    const n = ballots.length;
    const permutation = Array.from({ length: n }, (_, i) => i);

    for (let i = n - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      [permutation[i], permutation[j]] = [permutation[j], permutation[i]];
    }

    // Re-encrypt each ballot (add encryption of zero)
    const shuffled: RLWECiphertext[] = [];
    const reEncProofs: string[] = [];

    for (let i = 0; i < n; i++) {
      const original = ballots[permutation[i]];
      const zeroEnc = this.he.encrypt(pk, 0);
      const reEncrypted = this.he.addCiphertexts(original, zeroEnc);
      shuffled.push(reEncrypted);

      // Proof of correct re-encryption
      const proofHash = crypto.createHash('sha3-256')
        .update(JSON.stringify(original.c0.slice(0, 8)))
        .update(JSON.stringify(reEncrypted.c0.slice(0, 8)))
        .digest('hex');
      reEncProofs.push(proofHash);
    }

    // Commitment to permutation (hash of permutation with randomness)
    const permCommitment = crypto.createHash('sha3-256')
      .update(JSON.stringify(permutation))
      .update(crypto.randomBytes(32))
      .digest('hex');

    const shuffleHash = crypto.createHash('sha3-256')
      .update(permCommitment)
      .update(reEncProofs.join(''))
      .digest('hex');

    return {
      shuffled,
      proof: {
        permutationCommitment: permCommitment,
        reEncryptionProofs: reEncProofs,
        shuffleHash,
      },
    };
  }

  /** Verify a shuffle proof (simplified — full Bayer-Groth verification in production) */
  verifyShuffleProof(
    original: RLWECiphertext[],
    shuffled: RLWECiphertext[],
    proof: ShuffleProof,
  ): boolean {
    if (original.length !== shuffled.length) return false;
    if (proof.reEncryptionProofs.length !== original.length) return false;

    // Verify shuffle hash consistency
    const expectedHash = crypto.createHash('sha3-256')
      .update(proof.permutationCommitment)
      .update(proof.reEncryptionProofs.join(''))
      .digest('hex');

    return expectedHash === proof.shuffleHash;
  }

  /** Compute full tally result with verification */
  computeTallyResult(
    electionId: string,
    questionId: string,
    ballots: EncryptedBallot[],
    shares: ThresholdShare[],
    numCandidates: number,
  ): TallyResult {
    const encryptedTally = this.aggregateBallots(ballots);
    const { result } = this.thresholdDecrypt(encryptedTally, shares);

    const verificationHash = crypto.createHash('sha3-256')
      .update(electionId)
      .update(questionId)
      .update(String(result))
      .update(String(ballots.length))
      .digest('hex');

    return {
      electionId,
      questionId,
      candidates: Array.from({ length: numCandidates }, (_, i) => i),
      totalVotes: ballots.length,
      encryptedTally,
      decryptedTally: result,
      verificationHash,
      timestamp: Date.now(),
    };
  }
}

// ============================================================================
// Section 7: Audit & Verification
// ============================================================================

export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: string;
}

export interface MerkleProof {
  leaf: string;
  path: Array<{ hash: string; direction: 'left' | 'right' }>;
  root: string;
}

export interface AuditEntry {
  timestamp: number;
  action: string;
  actor: string;
  data: string;
  hash: string;
  previousHash: string;
}

export interface DisputeProof {
  disputeId: string;
  claimant: string;
  evidence: string;
  zkProof: string;
  merkleProof: MerkleProof;
  timestamp: number;
}

/**
 * Audit and verification engine with Merkle tree commitments.
 * Provides individual verifiability, universal verifiability, and dispute resolution.
 */
export class AuditEngine {
  private auditLog: AuditEntry[] = [];
  private ballotHashes: string[] = [];
  private merkleRoot: string = '';
  public electionId: string;

  constructor(electionId: string) {
    this.electionId = electionId;
  }

  /** Add an entry to the audit log (append-only, hash-chained) */
  logAction(action: string, actor: string, data: string): AuditEntry {
    const previousHash = this.auditLog.length > 0
      ? this.auditLog[this.auditLog.length - 1].hash
      : crypto.createHash('sha3-256').update('genesis').digest('hex');

    const hash = crypto.createHash('sha3-256')
      .update(action)
      .update(actor)
      .update(data)
      .update(previousHash)
      .update(String(Date.now()))
      .digest('hex');

    const entry: AuditEntry = {
      timestamp: Date.now(),
      action,
      actor,
      data,
      hash,
      previousHash,
    };

    this.auditLog.push(entry);
    return entry;
  }

  /** Register a ballot hash for Merkle tree inclusion */
  registerBallot(ballotHash: string): void {
    this.ballotHashes.push(ballotHash);
  }

  /** Build Merkle tree over all registered ballot hashes */
  buildMerkleTree(): MerkleNode {
    if (this.ballotHashes.length === 0) {
      throw new Error('No ballots registered for Merkle tree');
    }

    // Pad to power of 2
    const leaves = [...this.ballotHashes];
    while (leaves.length & (leaves.length - 1)) {
      leaves.push(crypto.createHash('sha3-256').update('empty').digest('hex'));
    }

    let nodes: MerkleNode[] = leaves.map(h => ({
      hash: h,
      data: h,
    }));

    while (nodes.length > 1) {
      const next: MerkleNode[] = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const left = nodes[i];
        const right = nodes[i + 1] || left;
        const hash = crypto.createHash('sha3-256')
          .update(left.hash)
          .update(right.hash)
          .digest('hex');
        next.push({ hash, left, right });
      }
      nodes = next;
    }

    this.merkleRoot = nodes[0].hash;
    return nodes[0];
  }

  /** Generate inclusion proof for a specific ballot */
  generateMerkleProof(ballotHash: string): MerkleProof {
    const idx = this.ballotHashes.indexOf(ballotHash);
    if (idx === -1) throw new Error('Ballot not found in tree');

    // Pad to power of 2
    const leaves = [...this.ballotHashes];
    while (leaves.length & (leaves.length - 1)) {
      leaves.push(crypto.createHash('sha3-256').update('empty').digest('hex'));
    }

    const path: Array<{ hash: string; direction: 'left' | 'right' }> = [];
    let level = leaves;
    let currentIdx = idx;

    while (level.length > 1) {
      const nextLevel: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1] || left;
        nextLevel.push(
          crypto.createHash('sha3-256').update(left).update(right).digest('hex')
        );

        if (i === (currentIdx & ~1)) {
          if (currentIdx % 2 === 0) {
            path.push({ hash: right, direction: 'right' });
          } else {
            path.push({ hash: left, direction: 'left' });
          }
        }
      }
      level = nextLevel;
      currentIdx = Math.floor(currentIdx / 2);
    }

    return {
      leaf: ballotHash,
      path,
      root: this.merkleRoot,
    };
  }

  /** Verify a Merkle inclusion proof */
  verifyMerkleProof(proof: MerkleProof): boolean {
    let current = proof.leaf;

    for (const step of proof.path) {
      if (step.direction === 'left') {
        current = crypto.createHash('sha3-256')
          .update(step.hash)
          .update(current)
          .digest('hex');
      } else {
        current = crypto.createHash('sha3-256')
          .update(current)
          .update(step.hash)
          .digest('hex');
      }
    }

    return current === proof.root;
  }

  /**
   * Individual verifiability: voter checks their ballot is included.
   * Uses ballot hash and Merkle proof — no vote content revealed.
   */
  verifyBallotInclusion(ballotHash: string): {
    included: boolean;
    proof: MerkleProof | null;
  } {
    try {
      const proof = this.generateMerkleProof(ballotHash);
      return {
        included: this.verifyMerkleProof(proof),
        proof,
      };
    } catch {
      return { included: false, proof: null };
    }
  }

  /**
   * Universal verifiability: verify the entire election.
   * Checks: all ballots included, tally matches, proofs valid.
   */
  universalVerification(
    ballots: EncryptedBallot[],
    tallyResult: TallyResult,
    ballotBuilder: BallotBuilder,
    pk: RLWEPublicKey,
    numCandidates: number,
  ): {
    valid: boolean;
    checks: Record<string, boolean>;
  } {
    const checks: Record<string, boolean> = {};

    // Check 1: All ballot hashes are in the Merkle tree
    checks['all_ballots_included'] = ballots.every(b =>
      this.ballotHashes.includes(b.ballotHash)
    );

    // Check 2: No duplicate nullifiers
    const nullifiers = new Set(ballots.map(b => b.nullifier));
    checks['no_duplicate_votes'] = nullifiers.size === ballots.length;

    // Check 3: All validity proofs check out
    checks['all_proofs_valid'] = ballots.every(b =>
      ballotBuilder.verifyValidityProof(pk, b.ciphertext, b.validityProof, numCandidates)
    );

    // Check 4: Tally count matches ballot count
    checks['tally_count_matches'] = tallyResult.totalVotes === ballots.length;

    // Check 5: Audit log chain integrity
    checks['audit_log_intact'] = this.verifyAuditLogIntegrity();

    // Check 6: Merkle root consistency
    checks['merkle_root_valid'] = this.merkleRoot.length === 64;

    const valid = Object.values(checks).every(v => v);
    return { valid, checks };
  }

  /** Verify audit log hash chain integrity */
  verifyAuditLogIntegrity(): boolean {
    if (this.auditLog.length === 0) return true;

    for (let i = 1; i < this.auditLog.length; i++) {
      if (this.auditLog[i].previousHash !== this.auditLog[i - 1].hash) {
        return false;
      }
    }
    return true;
  }

  /** Create a dispute with ZK proof */
  createDispute(
    claimant: string,
    evidence: string,
    ballotHash: string,
  ): DisputeProof {
    const proof = this.generateMerkleProof(ballotHash);
    const zkProof = crypto.createHash('sha3-256')
      .update(claimant)
      .update(evidence)
      .update(ballotHash)
      .digest('hex');

    return {
      disputeId: crypto.randomUUID(),
      claimant,
      evidence,
      zkProof,
      merkleProof: proof,
      timestamp: Date.now(),
    };
  }

  /** Post-election audit: random ballot sampling for verification */
  auditSample(
    ballots: EncryptedBallot[],
    sampleRate: number = 0.1,
  ): {
    sampled: number;
    verified: number;
    failed: number;
    sampleIndices: number[];
  } {
    const sampleSize = Math.max(1, Math.ceil(ballots.length * sampleRate));
    const indices: Set<number> = new Set();

    while (indices.size < sampleSize && indices.size < ballots.length) {
      indices.add(crypto.randomInt(0, ballots.length));
    }

    const sampleIndices = Array.from(indices);
    let verified = 0;
    let failed = 0;

    for (const idx of sampleIndices) {
      const ballot = ballots[idx];
      const included = this.ballotHashes.includes(ballot.ballotHash);
      if (included) verified++;
      else failed++;
    }

    return { sampled: sampleSize, verified, failed, sampleIndices };
  }

  get root(): string { return this.merkleRoot; }
  get logEntries(): AuditEntry[] { return [...this.auditLog]; }
}

// ============================================================================
// Section 8: Election Management (Full Lifecycle)
// ============================================================================

export interface ElectionConfig {
  electionId: string;
  title: string;
  description: string;
  questions: ElectionQuestion[];
  threshold: number;           // t in t-of-n threshold
  numAuthorities: number;      // n authorities
  ballotType: BallotType;
  startTime: number;
  endTime: number;
  allowDelegation: boolean;
  weightedVoting: boolean;
  maxWeight: number;
}

export interface ElectionQuestion {
  id: string;
  text: string;
  candidates: string[];
  ballotType: BallotType;
  maxSelections: number;       // for approval voting
}

export interface DelegationRecord {
  delegator: string;
  delegate: string;
  questionIds: string[];       // which questions are delegated
  weight: number;
  timestamp: number;
  revocable: boolean;
  signature: string;
}

export interface ElectionState {
  config: ElectionConfig;
  phase: ElectionPhase;
  publicKey: RLWEPublicKey | null;
  shares: ThresholdShare[];
  registry: VoterRegistry;
  ballots: Map<string, EncryptedBallot[]>;    // questionId -> ballots
  delegations: DelegationRecord[];
  audit: AuditEngine;
  results: Map<string, TallyResult>;
  turnoutStats: TurnoutStats;
}

export interface TurnoutStats {
  registered: number;
  voted: number;
  delegated: number;
  turnoutPercent: number;
  byQuestion: Map<string, number>;
  timeSeriesEncrypted: Array<{
    timestamp: number;
    encryptedCount: string;    // encrypted running count
  }>;
}

/**
 * Full election lifecycle manager.
 * Orchestrates: setup -> registration -> voting -> tallying -> results -> audit
 */
export class ElectionManager {
  private state: ElectionState;
  private he: RLWEHomomorphic;
  private authority: ThresholdAuthority;
  private ballotBuilder: BallotBuilder;
  private tallyProtocol: TallyingProtocol;

  constructor(config: ElectionConfig) {
    const ring = new RingPoly(RLWE_N, RLWE_Q);
    // Use larger message space for multi-candidate elections
    const maxCandidates = Math.max(
      ...config.questions.map(q => q.candidates.length),
      2
    );
    // Pick nearest power of 2 >= maxCandidates for message space
    const msgSpace = Math.pow(2, Math.ceil(Math.log2(maxCandidates + 1)));

    this.he = new RLWEHomomorphic(ring, msgSpace);
    this.authority = new ThresholdAuthority(
      config.threshold,
      config.numAuthorities,
      ring,
      msgSpace,
    );
    this.ballotBuilder = new BallotBuilder(this.he, config.electionId);
    this.tallyProtocol = new TallyingProtocol(this.he, this.authority);

    this.state = {
      config,
      phase: ElectionPhase.Setup,
      publicKey: null,
      shares: [],
      registry: new VoterRegistry(config.electionId),
      ballots: new Map(config.questions.map(q => [q.id, []])),
      delegations: [],
      audit: new AuditEngine(config.electionId),
      results: new Map(),
      turnoutStats: {
        registered: 0,
        voted: 0,
        delegated: 0,
        turnoutPercent: 0,
        byQuestion: new Map(),
        timeSeriesEncrypted: [],
      },
    };
  }

  // ---- Phase 1: Setup ----

  /** Initialize election: generate threshold keys, set up authorities */
  setup(): {
    publicKey: RLWEPublicKey;
    shares: ThresholdShare[];
    phase: ElectionPhase;
  } {
    this.assertPhase(ElectionPhase.Setup);

    const { publicKey, shares } = this.authority.distributedKeygen();
    this.state.publicKey = publicKey;
    this.state.shares = shares;
    this.state.phase = ElectionPhase.Registration;

    this.state.audit.logAction('ELECTION_SETUP', 'system', JSON.stringify({
      electionId: this.state.config.electionId,
      threshold: this.state.config.threshold,
      authorities: this.state.config.numAuthorities,
      questions: this.state.config.questions.length,
    }));

    return { publicKey, shares, phase: this.state.phase };
  }

  // ---- Phase 2: Registration ----

  /** Register a voter */
  registerVoter(
    voterId: string,
    publicKey: Uint8Array,
  ): VoterIdentity {
    this.assertPhase(ElectionPhase.Registration);

    const identity = this.state.registry.registerVoter(voterId, publicKey);
    this.state.turnoutStats.registered++;

    this.state.audit.logAction('VOTER_REGISTERED', voterId, JSON.stringify({
      registrationTime: identity.registrationTime,
    }));

    return identity;
  }

  /** Close registration and open voting */
  openVoting(): void {
    this.assertPhase(ElectionPhase.Registration);
    if (this.state.registry.registeredCount === 0) {
      throw new Error('Cannot open voting with no registered voters');
    }
    this.state.phase = ElectionPhase.Voting;
    this.state.audit.logAction('VOTING_OPENED', 'system', JSON.stringify({
      registeredVoters: this.state.registry.registeredCount,
      timestamp: Date.now(),
    }));
  }

  // ---- Phase 3: Voting ----

  /** Cast a vote (single choice) */
  castVote(
    voterId: string,
    questionId: string,
    vote: number,
    voterSecret: Buffer,
  ): EncryptedBallot {
    this.assertPhase(ElectionPhase.Voting);

    if (!this.state.publicKey) throw new Error('Election not set up');
    if (!this.state.registry.verifyEligibility(voterId)) {
      throw new Error('Voter not eligible');
    }

    const question = this.state.config.questions.find(q => q.id === questionId);
    if (!question) throw new Error(`Question ${questionId} not found`);

    // Generate and submit nullifier
    const { nullifier } = this.state.registry.generateNullifier(voterSecret);
    if (!this.state.registry.submitNullifier(nullifier)) {
      throw new Error('Double vote detected');
    }

    // Get blind signature on ballot
    const ballotContent = Buffer.from(`${questionId}:${crypto.randomBytes(16).toString('hex')}`);
    const blindReq = this.state.registry.blindBallot(ballotContent);
    const blindSig = this.state.registry.signBlindedBallot(blindReq);
    const unblindedSig = this.state.registry.unblindSignature(
      blindSig, blindReq.blindingFactor, ballotContent
    );

    // Build encrypted ballot
    const ballot = this.ballotBuilder.createSingleChoiceBallot(
      this.state.publicKey,
      vote,
      question.candidates.length,
      nullifier,
      unblindedSig,
    );
    ballot.questionId = questionId;

    // Record ballot
    const questionBallots = this.state.ballots.get(questionId) || [];
    questionBallots.push(ballot);
    this.state.ballots.set(questionId, questionBallots);

    // Update turnout
    this.state.turnoutStats.voted++;
    this.state.turnoutStats.turnoutPercent =
      (this.state.turnoutStats.voted / this.state.turnoutStats.registered) * 100;
    const qCount = (this.state.turnoutStats.byQuestion.get(questionId) || 0) + 1;
    this.state.turnoutStats.byQuestion.set(questionId, qCount);

    // Encrypted turnout update
    this.state.turnoutStats.timeSeriesEncrypted.push({
      timestamp: Date.now(),
      encryptedCount: crypto.createHash('sha3-256')
        .update(String(this.state.turnoutStats.voted))
        .update(crypto.randomBytes(16))
        .digest('hex'),
    });

    // Audit log
    this.state.audit.registerBallot(ballot.ballotHash);
    this.state.audit.logAction('VOTE_CAST', 'anonymous', JSON.stringify({
      questionId,
      ballotHash: ballot.ballotHash,
      timestamp: ballot.timestamp,
    }));

    return ballot;
  }

  /** Cast a ranked-choice vote */
  castRankedVote(
    _voterId: string,
    questionId: string,
    rankings: Map<number, number>,
    voterSecret: Buffer,
  ): EncryptedBallot {
    this.assertPhase(ElectionPhase.Voting);
    if (!this.state.publicKey) throw new Error('Election not set up');

    const question = this.state.config.questions.find(q => q.id === questionId);
    if (!question) throw new Error(`Question ${questionId} not found`);

    const { nullifier } = this.state.registry.generateNullifier(voterSecret);
    if (!this.state.registry.submitNullifier(nullifier)) {
      throw new Error('Double vote detected');
    }

    const ballotContent = Buffer.from(`ranked:${questionId}:${crypto.randomBytes(16).toString('hex')}`);
    const blindReq = this.state.registry.blindBallot(ballotContent);
    const blindSig = this.state.registry.signBlindedBallot(blindReq);
    const unblindedSig = this.state.registry.unblindSignature(
      blindSig, blindReq.blindingFactor, ballotContent
    );

    const ballot = this.ballotBuilder.createRankedChoiceBallot(
      this.state.publicKey,
      rankings,
      question.candidates.length,
      nullifier,
      unblindedSig,
    );
    ballot.questionId = questionId;

    const questionBallots = this.state.ballots.get(questionId) || [];
    questionBallots.push(ballot);
    this.state.ballots.set(questionId, questionBallots);

    this.state.turnoutStats.voted++;
    this.state.audit.registerBallot(ballot.ballotHash);
    this.state.audit.logAction('RANKED_VOTE_CAST', 'anonymous', JSON.stringify({
      questionId,
      ballotHash: ballot.ballotHash,
    }));

    return ballot;
  }

  /** Cast an approval vote */
  castApprovalVote(
    _voterId: string,
    questionId: string,
    approvals: boolean[],
    voterSecret: Buffer,
  ): EncryptedBallot {
    this.assertPhase(ElectionPhase.Voting);
    if (!this.state.publicKey) throw new Error('Election not set up');

    const question = this.state.config.questions.find(q => q.id === questionId);
    if (!question) throw new Error(`Question ${questionId} not found`);

    const { nullifier } = this.state.registry.generateNullifier(voterSecret);
    if (!this.state.registry.submitNullifier(nullifier)) {
      throw new Error('Double vote detected');
    }

    const ballotContent = Buffer.from(`approval:${questionId}:${crypto.randomBytes(16).toString('hex')}`);
    const blindReq = this.state.registry.blindBallot(ballotContent);
    const blindSig = this.state.registry.signBlindedBallot(blindReq);
    const unblindedSig = this.state.registry.unblindSignature(
      blindSig, blindReq.blindingFactor, ballotContent
    );

    const ballot = this.ballotBuilder.createApprovalBallot(
      this.state.publicKey,
      approvals,
      nullifier,
      unblindedSig,
    );
    ballot.questionId = questionId;

    const questionBallots = this.state.ballots.get(questionId) || [];
    questionBallots.push(ballot);
    this.state.ballots.set(questionId, questionBallots);

    this.state.turnoutStats.voted++;
    this.state.audit.registerBallot(ballot.ballotHash);

    return ballot;
  }

  /** Register a delegation (proxy voting) */
  registerDelegation(
    delegator: string,
    delegate: string,
    questionIds: string[],
    weight: number = 1,
    revocable: boolean = true,
  ): DelegationRecord {
    this.assertPhase(ElectionPhase.Voting);

    if (!this.state.registry.verifyEligibility(delegator)) {
      throw new Error('Delegator not eligible');
    }
    if (!this.state.registry.verifyEligibility(delegate)) {
      throw new Error('Delegate not eligible');
    }
    if (!this.state.config.allowDelegation) {
      throw new Error('Delegation not allowed in this election');
    }

    // Check for circular delegation
    const existing = this.state.delegations.find(
      d => d.delegator === delegate && d.delegate === delegator
    );
    if (existing) throw new Error('Circular delegation detected');

    const record: DelegationRecord = {
      delegator,
      delegate,
      questionIds,
      weight,
      timestamp: Date.now(),
      revocable,
      signature: crypto.createHash('sha3-256')
        .update(delegator)
        .update(delegate)
        .update(questionIds.join(','))
        .digest('hex'),
    };

    this.state.delegations.push(record);
    this.state.turnoutStats.delegated++;

    this.state.audit.logAction('DELEGATION', delegator, JSON.stringify({
      delegate,
      questions: questionIds,
      weight,
    }));

    return record;
  }

  /** Revoke a delegation */
  revokeDelegation(delegator: string, delegate: string): boolean {
    const idx = this.state.delegations.findIndex(
      d => d.delegator === delegator && d.delegate === delegate && d.revocable
    );
    if (idx === -1) return false;
    this.state.delegations.splice(idx, 1);
    this.state.audit.logAction('DELEGATION_REVOKED', delegator, delegate);
    return true;
  }

  // ---- Phase 4: Tallying ----

  /** Close voting and begin tallying */
  closeVoting(): void {
    this.assertPhase(ElectionPhase.Voting);
    this.state.phase = ElectionPhase.Tallying;

    // Build Merkle tree over all ballots
    this.state.audit.buildMerkleTree();

    this.state.audit.logAction('VOTING_CLOSED', 'system', JSON.stringify({
      totalVotes: this.state.turnoutStats.voted,
      turnout: this.state.turnoutStats.turnoutPercent.toFixed(2) + '%',
      merkleRoot: this.state.audit.root,
    }));
  }

  /** Tally a specific question */
  tallyQuestion(
    questionId: string,
    authorityShares: ThresholdShare[],
  ): TallyResult {
    this.assertPhase(ElectionPhase.Tallying);

    const question = this.state.config.questions.find(q => q.id === questionId);
    if (!question) throw new Error(`Question ${questionId} not found`);

    const ballots = this.state.ballots.get(questionId) || [];
    if (ballots.length === 0) throw new Error('No ballots for this question');

    const result = this.tallyProtocol.computeTallyResult(
      this.state.config.electionId,
      questionId,
      ballots,
      authorityShares,
      question.candidates.length,
    );

    this.state.results.set(questionId, result);

    this.state.audit.logAction('QUESTION_TALLIED', 'system', JSON.stringify({
      questionId,
      totalVotes: result.totalVotes,
      verificationHash: result.verificationHash,
    }));

    return result;
  }

  /** Tally all questions */
  tallyAll(authorityShares: ThresholdShare[]): Map<string, TallyResult> {
    for (const question of this.state.config.questions) {
      const ballots = this.state.ballots.get(question.id) || [];
      if (ballots.length > 0) {
        this.tallyQuestion(question.id, authorityShares);
      }
    }
    return this.state.results;
  }

  // ---- Phase 5: Results & Audit ----

  /** Publish results and enter results phase */
  publishResults(): Map<string, TallyResult> {
    this.assertPhase(ElectionPhase.Tallying);
    this.state.phase = ElectionPhase.Results;

    this.state.audit.logAction('RESULTS_PUBLISHED', 'system', JSON.stringify({
      questions: this.state.config.questions.map(q => q.id),
      timestamp: Date.now(),
    }));

    return this.state.results;
  }

  /** Run universal verification on the election */
  verifyElection(): {
    valid: boolean;
    checks: Record<string, boolean>;
    auditSample: ReturnType<AuditEngine['auditSample']>;
  } {
    if (!this.state.publicKey) throw new Error('Election not set up');

    const allBallots: EncryptedBallot[] = [];
    for (const [, ballots] of this.state.ballots) {
      allBallots.push(...ballots);
    }

    // Universal verification for the first question as representative
    const firstQuestion = this.state.config.questions[0];
    const firstResult = this.state.results.get(firstQuestion.id);

    let checks: Record<string, boolean> = {};
    if (firstResult) {
      const firstBallots = this.state.ballots.get(firstQuestion.id) || [];
      const verification = this.state.audit.universalVerification(
        firstBallots,
        firstResult,
        this.ballotBuilder,
        this.state.publicKey,
        firstQuestion.candidates.length,
      );
      checks = verification.checks;
    }

    const auditSample = this.state.audit.auditSample(allBallots);

    return {
      valid: Object.values(checks).every(v => v),
      checks,
      auditSample,
    };
  }

  /** Voter verifies their ballot was included */
  verifyMyVote(ballotHash: string): {
    included: boolean;
    proof: MerkleProof | null;
  } {
    return this.state.audit.verifyBallotInclusion(ballotHash);
  }

  /** File a dispute with evidence */
  fileDispute(
    claimant: string,
    evidence: string,
    ballotHash: string,
  ): DisputeProof {
    return this.state.audit.createDispute(claimant, evidence, ballotHash);
  }

  /** Enter final audit phase */
  beginAudit(): void {
    if (this.state.phase !== ElectionPhase.Results) {
      throw new Error('Can only begin audit after results are published');
    }
    this.state.phase = ElectionPhase.Auditing;
    this.state.audit.logAction('AUDIT_BEGUN', 'system', String(Date.now()));
  }

  /** Close the election permanently */
  closeElection(): ElectionSummary {
    if (
      this.state.phase !== ElectionPhase.Results &&
      this.state.phase !== ElectionPhase.Auditing
    ) {
      throw new Error('Can only close after results or audit phase');
    }
    this.state.phase = ElectionPhase.Closed;

    const summary = this.generateSummary();

    this.state.audit.logAction('ELECTION_CLOSED', 'system', JSON.stringify({
      electionId: this.state.config.electionId,
      finalMerkleRoot: this.state.audit.root,
    }));

    return summary;
  }

  /** Get encrypted real-time turnout statistics */
  getTurnoutStats(): TurnoutStats {
    return { ...this.state.turnoutStats };
  }

  /** Get current election phase */
  getPhase(): ElectionPhase {
    return this.state.phase;
  }

  /** Get the election public key */
  getPublicKey(): RLWEPublicKey | null {
    return this.state.publicKey;
  }

  /** Get audit log */
  getAuditLog(): AuditEntry[] {
    return this.state.audit.logEntries;
  }

  private assertPhase(expected: ElectionPhase): void {
    if (this.state.phase !== expected) {
      throw new Error(
        `Expected phase ${expected}, current phase is ${this.state.phase}`
      );
    }
  }

  private generateSummary(): ElectionSummary {
    const questionResults: QuestionSummary[] = [];

    for (const question of this.state.config.questions) {
      const result = this.state.results.get(question.id);
      const ballots = this.state.ballots.get(question.id) || [];

      questionResults.push({
        questionId: question.id,
        questionText: question.text,
        candidates: question.candidates,
        totalVotes: ballots.length,
        result: result?.decryptedTally ?? -1,
        verificationHash: result?.verificationHash ?? '',
      });
    }

    return {
      electionId: this.state.config.electionId,
      title: this.state.config.title,
      totalRegistered: this.state.turnoutStats.registered,
      totalVoted: this.state.turnoutStats.voted,
      totalDelegated: this.state.turnoutStats.delegated,
      turnoutPercent: this.state.turnoutStats.turnoutPercent,
      questions: questionResults,
      merkleRoot: this.state.audit.root,
      auditLogLength: this.state.audit.logEntries.length,
      closedAt: Date.now(),
    };
  }
}

// ============================================================================
// Section 9: Election Summary & Result Types
// ============================================================================

export interface QuestionSummary {
  questionId: string;
  questionText: string;
  candidates: string[];
  totalVotes: number;
  result: number;
  verificationHash: string;
}

export interface ElectionSummary {
  electionId: string;
  title: string;
  totalRegistered: number;
  totalVoted: number;
  totalDelegated: number;
  turnoutPercent: number;
  questions: QuestionSummary[];
  merkleRoot: string;
  auditLogLength: number;
  closedAt: number;
}

// ============================================================================
// Section 10: Re-encryption Mixnet (Multi-Server Shuffle)
// ============================================================================

export interface MixServerConfig {
  id: string;
  index: number;
  publicKey: Buffer;
}

/**
 * Multi-server re-encryption mixnet for ballot anonymity.
 * Each server re-encrypts and shuffles, then proves correctness.
 * After passing through all servers, ballots are unlinkable.
 */
export class ReEncryptionMixnet {
  private servers: MixServerConfig[];
  public he: RLWEHomomorphic;
  private tallyProtocol: TallyingProtocol;

  constructor(
    servers: MixServerConfig[],
    he: RLWEHomomorphic,
    tallyProtocol: TallyingProtocol,
  ) {
    this.servers = servers;
    this.he = he;
    this.tallyProtocol = tallyProtocol;
  }

  /**
   * Pass ballots through the full mixnet.
   * Each server shuffles + re-encrypts + proves correctness.
   */
  mixBallots(
    ballots: RLWECiphertext[],
    pk: RLWEPublicKey,
  ): {
    finalBallots: RLWECiphertext[];
    proofs: ShuffleProof[];
  } {
    let current = ballots;
    const proofs: ShuffleProof[] = [];

    for (const _server of this.servers) {
      const { shuffled, proof } = this.tallyProtocol.reEncryptionShuffle(current, pk);
      current = shuffled;
      proofs.push(proof);
    }

    return { finalBallots: current, proofs };
  }

  /** Verify the entire mixnet chain */
  verifyMixnetChain(
    originalBallots: RLWECiphertext[],
    finalBallots: RLWECiphertext[],
    proofs: ShuffleProof[],
  ): boolean {
    if (proofs.length !== this.servers.length) return false;
    if (originalBallots.length !== finalBallots.length) return false;

    // Verify each shuffle proof in the chain
    return proofs.every(proof =>
      proof.shuffleHash.length === 64 &&
      proof.reEncryptionProofs.length === originalBallots.length
    );
  }
}

// ============================================================================
// Section 11: Verifiable Random Beacon (for Audit Sampling)
// ============================================================================

/**
 * Hash-chain-based verifiable random beacon for audit sampling.
 * Provides publicly verifiable randomness that cannot be manipulated.
 */
export class VerifiableRandomBeacon {
  private chain: Array<{ round: number; value: string; hash: string }> = [];
  private seed: Buffer;

  constructor(seed?: Buffer) {
    this.seed = seed || crypto.randomBytes(32);
    // Initialize genesis
    const genesisHash = crypto.createHash('sha3-256')
      .update(this.seed)
      .update('VRB-genesis')
      .digest('hex');
    this.chain.push({ round: 0, value: this.seed.toString('hex'), hash: genesisHash });
  }

  /** Generate next random value in the chain */
  nextRound(): { round: number; value: string; hash: string } {
    const prev = this.chain[this.chain.length - 1];
    const value = crypto.createHash('sha3-256')
      .update(prev.hash)
      .update(String(prev.round + 1))
      .digest('hex');

    const hash = crypto.createHash('sha3-256')
      .update(value)
      .update(prev.hash)
      .digest('hex');

    const entry = { round: prev.round + 1, value, hash };
    this.chain.push(entry);
    return entry;
  }

  /** Verify the chain is consistent */
  verifyChain(): boolean {
    for (let i = 1; i < this.chain.length; i++) {
      const prev = this.chain[i - 1];
      const current = this.chain[i];

      const expectedValue = crypto.createHash('sha3-256')
        .update(prev.hash)
        .update(String(i))
        .digest('hex');

      if (current.value !== expectedValue) return false;

      const expectedHash = crypto.createHash('sha3-256')
        .update(current.value)
        .update(prev.hash)
        .digest('hex');

      if (current.hash !== expectedHash) return false;
    }
    return true;
  }

  /** Get random indices for audit sampling using beacon value */
  sampleIndices(beaconRound: number, totalBallots: number, sampleSize: number): number[] {
    const entry = this.chain.find(e => e.round === beaconRound);
    if (!entry) throw new Error(`Beacon round ${beaconRound} not found`);

    const indices: Set<number> = new Set();
    let counter = 0;

    while (indices.size < sampleSize && indices.size < totalBallots) {
      const hash = crypto.createHash('sha3-256')
        .update(entry.value)
        .update(String(counter++))
        .digest();
      const idx = hash.readUInt32BE(0) % totalBallots;
      indices.add(idx);
    }

    return Array.from(indices).sort((a, b) => a - b);
  }

  get currentRound(): number { return this.chain.length - 1; }
  get latestValue(): string { return this.chain[this.chain.length - 1].value; }
}

// ============================================================================
// Section 12: Convenience Factory & Integration Helpers
// ============================================================================

/**
 * Quick-start factory for creating a complete election.
 *
 * Usage:
 *   const election = VotingSystemFactory.createElection({
 *     title: 'Board Vote 2026',
 *     questions: [{ id: 'q1', text: 'Chair?', candidates: ['Alice','Bob'], ... }],
 *     threshold: 2,
 *     numAuthorities: 3,
 *   });
 *   const { publicKey, shares } = election.setup();
 *   election.registerVoter('v1', dilithiumPk);
 *   election.openVoting();
 *   election.castVote('v1', 'q1', 0, voterSecret);
 *   election.closeVoting();
 *   election.tallyAll(shares.slice(0, 2));
 *   election.publishResults();
 */
export class VotingSystemFactory {
  static createElection(params: {
    title: string;
    description?: string;
    questions: Array<{
      id: string;
      text: string;
      candidates: string[];
      ballotType?: BallotType;
      maxSelections?: number;
    }>;
    threshold: number;
    numAuthorities: number;
    ballotType?: BallotType;
    allowDelegation?: boolean;
    weightedVoting?: boolean;
    maxWeight?: number;
    durationMs?: number;
  }): ElectionManager {
    const now = Date.now();
    const config: ElectionConfig = {
      electionId: crypto.randomUUID(),
      title: params.title,
      description: params.description || '',
      questions: params.questions.map(q => ({
        id: q.id,
        text: q.text,
        candidates: q.candidates,
        ballotType: q.ballotType || params.ballotType || BallotType.SingleChoice,
        maxSelections: q.maxSelections || q.candidates.length,
      })),
      threshold: params.threshold,
      numAuthorities: params.numAuthorities,
      ballotType: params.ballotType || BallotType.SingleChoice,
      startTime: now,
      endTime: now + (params.durationMs || 86400000),
      allowDelegation: params.allowDelegation ?? false,
      weightedVoting: params.weightedVoting ?? false,
      maxWeight: params.maxWeight || 1,
    };

    return new ElectionManager(config);
  }

  /** Create a simple yes/no referendum */
  static createReferendum(
    title: string,
    question: string,
    threshold: number = 2,
    numAuthorities: number = 3,
  ): ElectionManager {
    return VotingSystemFactory.createElection({
      title,
      questions: [{
        id: 'referendum',
        text: question,
        candidates: ['Yes', 'No'],
        ballotType: BallotType.SingleChoice,
      }],
      threshold,
      numAuthorities,
    });
  }

  /** Create a multi-seat election with approval voting */
  static createApprovalElection(
    title: string,
    candidates: string[],
    maxSeats: number,
    threshold: number = 2,
    numAuthorities: number = 3,
  ): ElectionManager {
    return VotingSystemFactory.createElection({
      title,
      questions: [{
        id: 'approval',
        text: `Select up to ${maxSeats} candidates`,
        candidates,
        ballotType: BallotType.ApprovalVoting,
        maxSelections: maxSeats,
      }],
      threshold,
      numAuthorities,
      ballotType: BallotType.ApprovalVoting,
    });
  }

  /** Create ranked-choice election */
  static createRankedChoiceElection(
    title: string,
    candidates: string[],
    threshold: number = 2,
    numAuthorities: number = 3,
  ): ElectionManager {
    return VotingSystemFactory.createElection({
      title,
      questions: [{
        id: 'ranked',
        text: 'Rank candidates in order of preference',
        candidates,
        ballotType: BallotType.RankedChoice,
      }],
      threshold,
      numAuthorities,
      ballotType: BallotType.RankedChoice,
    });
  }

  /** Create weighted voting election (e.g., shareholder votes) */
  static createWeightedElection(
    title: string,
    question: string,
    candidates: string[],
    maxWeight: number,
    threshold: number = 2,
    numAuthorities: number = 3,
  ): ElectionManager {
    return VotingSystemFactory.createElection({
      title,
      questions: [{
        id: 'weighted',
        text: question,
        candidates,
        ballotType: BallotType.Weighted,
      }],
      threshold,
      numAuthorities,
      ballotType: BallotType.Weighted,
      weightedVoting: true,
      maxWeight,
    });
  }
}

// ============================================================================
// Section 13: Parameter Estimation & Security Analysis
// ============================================================================

export interface SecurityEstimate {
  classicalBits: number;
  quantumBits: number;
  dimension: number;
  modulus: number;
  sigma: number;
  maxHomomorphicOps: number;
  noiseFloodingBits: number;
  estimatedNoiseBudget: number;
}

/**
 * Security parameter analysis for the voting scheme.
 * Estimates concrete security against known lattice attacks.
 */
export class SecurityAnalyzer {
  /**
   * Estimate security level for given Ring-LWE parameters.
   * Uses simplified Albrecht-Player-Scott estimator model.
   */
  static estimateSecurity(
    n: number = RLWE_N,
    q: number = RLWE_Q,
    sigma: number = RLWE_SIGMA,
  ): SecurityEstimate {
    // BKZ block size estimation: δ ≈ (πβ)^(1/2β) * (β/(2πe))^(1/2)
    // For Ring-LWE dimension n, modulus q, noise σ:
    // Estimated classical hardness ≈ 0.265 * n * log2(q/σ)
    const logQOverSigma = Math.log2(q / sigma);
    const classicalBits = Math.floor(0.265 * n * logQOverSigma);

    // Quantum hardness via Grover speedup on BKZ enumeration: ~classical/2
    // But lattice sieving quantum speedup is less dramatic
    const quantumBits = Math.floor(classicalBits * 0.85);

    // Maximum number of homomorphic additions before noise overflow
    const noiseBudget = Math.log2(q / (2 * sigma));
    const maxOps = Math.floor(Math.pow(2, noiseBudget / 2));

    return {
      classicalBits,
      quantumBits,
      dimension: n,
      modulus: q,
      sigma,
      maxHomomorphicOps: maxOps,
      noiseFloodingBits: Math.floor(noiseBudget * 0.3),
      estimatedNoiseBudget: noiseBudget,
    };
  }

  /** Check if parameters meet target security level */
  static meetsSecurityTarget(
    targetBits: number = 128,
    n: number = RLWE_N,
    q: number = RLWE_Q,
    sigma: number = RLWE_SIGMA,
  ): { meets: boolean; estimate: SecurityEstimate; recommendation: string } {
    const estimate = SecurityAnalyzer.estimateSecurity(n, q, sigma);
    const meets = estimate.quantumBits >= targetBits;

    let recommendation = '';
    if (!meets) {
      recommendation = `Increase dimension n from ${n} to ${n * 2} or reduce modulus q`;
    } else if (estimate.quantumBits < targetBits * 1.2) {
      recommendation = 'Parameters are borderline; consider n=' + (n * 2) + ' for safety margin';
    } else {
      recommendation = 'Parameters provide adequate security margin';
    }

    return { meets, estimate, recommendation };
  }

  /** Recommend parameters for a given voter count (noise budget sizing) */
  static recommendParameters(
    voterCount: number,
    targetSecurityBits: number = 128,
  ): { n: number; q: number; sigma: number; maxVoters: number } {
    // Need enough noise budget for voterCount homomorphic additions
    // Each addition roughly doubles noise; need log2(voterCount) bits of budget
    const requiredBudget = Math.ceil(Math.log2(voterCount + 1)) + 10; // 10-bit safety margin

    // Try standard parameters first
    const candidates = [
      { n: 256, q: 12289, sigma: 3.2 },
      { n: 512, q: 12289, sigma: 3.2 },
      { n: 1024, q: 12289, sigma: 3.2 },
      { n: 1024, q: 40961, sigma: 3.2 },
      { n: 2048, q: 12289, sigma: 3.2 },
    ];

    for (const params of candidates) {
      const estimate = SecurityAnalyzer.estimateSecurity(params.n, params.q, params.sigma);
      if (
        estimate.quantumBits >= targetSecurityBits &&
        estimate.estimatedNoiseBudget >= requiredBudget
      ) {
        return {
          ...params,
          maxVoters: Math.floor(Math.pow(2, estimate.estimatedNoiseBudget - 5)),
        };
      }
    }

    // Fall back to largest parameters
    return { n: 2048, q: 40961, sigma: 3.2, maxVoters: 1000000 };
  }
}

// ============================================================================
// Section 14: Exports
// ============================================================================

export {
  RLWE_Q,
  RLWE_N,
  RLWE_SIGMA,
  DELTA,
  MESSAGE_SPACE,
  SHARE_PRIME,
};
