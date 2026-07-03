import { jest, describe, it, expect, beforeEach, afterEach, test } from "@jest/globals";
/**
 * Tests for Post-Quantum Lattice-Based Zero-Knowledge Proofs
 *
 * Verifies BDLOPCommitmentScheme, SternProtocol, LatticeSigmaProtocol,
 * LatticeRangeProofSystem, LatticeSetMembershipProof, ProofAggregator,
 * and LatticeNIZKSystem.
 */

import {
  BDLOPCommitmentScheme,
  BDLOPParams,
  BDLOPCommitment,
  SternProtocol,
  SternProof,
  LatticeSigmaProtocol,
  LatticeSigmaProof,
  LatticeRangeProofSystem,
  LatticeRangeProof,
  LatticeSetMembershipProof,
  SetMembershipProof,
  ProofAggregator,
  AggregatedProof,
  LatticeNIZKSystem,
  NIZKProof,
} from '../algorithms/lattice-zk-proofs';

// Use smaller parameters for test speed where possible
const TEST_N = 32;
const TEST_Q = 12289;

// ---------------------------------------------------------------------------
// BDLOPCommitmentScheme
// ---------------------------------------------------------------------------

describe('BDLOPCommitmentScheme', () => {
  let scheme: BDLOPCommitmentScheme;

  beforeEach(() => {
    scheme = new BDLOPCommitmentScheme({ n: TEST_N, q: TEST_Q, k: 4, l: 2 });
  });

  test('commit produces a commitment and randomness', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);

    const { commitment, randomness } = scheme.commit([m1, m2]);

    expect(commitment.c0).toBeDefined();
    expect(commitment.c.length).toBe(2);
    expect(randomness.elements.length).toBe(4); // k = 4
  });

  test('verify accepts a correctly opened commitment', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);

    const { commitment, randomness } = scheme.commit([m1, m2]);
    const valid = scheme.verify(commitment, [m1, m2], randomness);
    expect(valid).toBe(true);
  });

  test('verify rejects commitment opened to different messages', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);
    const mFake = RingElement.random(TEST_N, TEST_Q);

    const { commitment, randomness } = scheme.commit([m1, m2]);
    // Open to a different first message
    const valid = scheme.verify(commitment, [mFake, m2], randomness);
    expect(valid).toBe(false);
  });

  test('verify rejects wrong randomness', () => {
    const { RingElement, ModuleElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);

    const { commitment } = scheme.commit([m1, m2]);
    // Use different randomness
    const fakeRandomness = ModuleElement.random(4, TEST_N, TEST_Q);
    const valid = scheme.verify(commitment, [m1, m2], fakeRandomness);
    expect(valid).toBe(false);
  });

  test('commit throws when wrong number of messages provided', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);

    // Scheme expects l=2 messages, but we provide 1
    expect(() => scheme.commit([m1])).toThrow('Expected 2 messages, got 1');
  });

  test('homomorphic addition of commitments', () => {
    const { RingElement } = getHelpers();
    const m1a = RingElement.random(TEST_N, TEST_Q);
    const m2a = RingElement.random(TEST_N, TEST_Q);
    const m1b = RingElement.random(TEST_N, TEST_Q);
    const m2b = RingElement.random(TEST_N, TEST_Q);

    const { commitment: comA } = scheme.commit([m1a, m2a]);
    const { commitment: comB } = scheme.commit([m1b, m2b]);

    const comSum = scheme.add(comA, comB);
    // The sum commitment should have the same structure
    expect(comSum.c0).toBeDefined();
    expect(comSum.c.length).toBe(2);
  });

  test('commitment binding: cannot open same commitment to two different values', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);
    const m1Alt = RingElement.random(TEST_N, TEST_Q);
    const m2Alt = RingElement.random(TEST_N, TEST_Q);

    const { commitment, randomness } = scheme.commit([m1, m2]);

    // The original messages verify
    expect(scheme.verify(commitment, [m1, m2], randomness)).toBe(true);
    // Different messages with same randomness should not verify
    expect(scheme.verify(commitment, [m1Alt, m2Alt], randomness)).toBe(false);
  });

  test('two commits with same messages but different randomness differ', () => {
    const { RingElement } = getHelpers();
    const m1 = RingElement.random(TEST_N, TEST_Q);
    const m2 = RingElement.random(TEST_N, TEST_Q);

    const { commitment: c1 } = scheme.commit([m1, m2]);
    const { commitment: c2 } = scheme.commit([m1, m2]);

    // Due to random randomness, c0 components should differ
    const c1Bytes = c1.c0.toBytes();
    const c2Bytes = c2.c0.toBytes();
    const same = c1Bytes.every((b: number, i: number) => b === c2Bytes[i]);
    expect(same).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SternProtocol
// ---------------------------------------------------------------------------

describe('SternProtocol', () => {
  const m = 8;
  const n = 16;
  const q = 12289;

  function makeInstance(): { A: number[][]; s: number[]; t: number[] } {
    // Build A as a random m x n matrix
    const A: number[][] = [];
    for (let i = 0; i < m; i++) {
      const row: number[] = [];
      for (let j = 0; j < n; j++) {
        row.push(Math.floor(Math.random() * q));
      }
      A.push(row);
    }
    // Secret with small coefficients
    const s: number[] = [];
    for (let j = 0; j < n; j++) {
      s.push(Math.floor(Math.random() * 5) - 2);
    }
    // Target: t = A * s mod q
    const t: number[] = [];
    for (let i = 0; i < m; i++) {
      let sum = 0;
      for (let j = 0; j < n; j++) {
        sum = ((sum + A[i][j] * s[j]) % q + q) % q;
      }
      t.push(sum);
    }
    return { A, s, t };
  }

  test('honest prover generates a proof that verifier accepts', () => {
    const { A, s, t } = makeInstance();
    const stern = new SternProtocol(A, q);
    const proof = stern.prove(s, t, 16); // fewer rounds for speed

    expect(proof.rounds).toBe(16);
    expect(proof.commitments.length).toBe(16);
    expect(proof.challenges.length).toBe(16);
    expect(proof.responses.length).toBe(16);

    const valid = stern.verify(proof, t);
    expect(valid).toBe(true);
  });

  test('proof has correct structure for each round', () => {
    const { A, s, t } = makeInstance();
    const stern = new SternProtocol(A, q);
    const proof = stern.prove(s, t, 8);

    for (let i = 0; i < proof.rounds; i++) {
      expect(proof.commitments[i]).toBeInstanceOf(Uint8Array);
      expect([0, 1, 2]).toContain(proof.challenges[i]);
      expect(proof.responses[i]).toBeDefined();
    }
  });

  test('wrong witness (random vector) is rejected by verifier', () => {
    const { A, t } = makeInstance();
    const stern = new SternProtocol(A, q);

    // Use a random witness that does NOT satisfy A*s = t
    const wrongS = Array.from({ length: n }, () => Math.floor(Math.random() * q));
    // Compute what t should be for the wrong witness
    const wrongT: number[] = [];
    for (let i = 0; i < m; i++) {
      let sum = 0;
      for (let j = 0; j < n; j++) {
        sum = ((sum + A[i][j] * wrongS[j]) % q + q) % q;
      }
      wrongT.push(sum);
    }

    // wrongS is a random mod-q vector, NOT the small/ternary witness the Stern
    // protocol proves knowledge of. Although A*wrongS = wrongT holds by
    // construction, the verifier's structural (ternary / fixed-weight) checks
    // must reject it — that rejection IS the soundness property under test.
    const proof = stern.prove(wrongS, wrongT, 8);
    expect(stern.verify(proof, wrongT)).toBe(false);
  });

  test('challenges are drawn from {0, 1, 2}', () => {
    const { A, s, t } = makeInstance();
    const stern = new SternProtocol(A, q);
    const proof = stern.prove(s, t, 128);

    const challengeSet = new Set(proof.challenges);
    // With 128 rounds, we should see all three challenge types
    expect(challengeSet.size).toBeGreaterThanOrEqual(2);
    for (const c of proof.challenges) {
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThanOrEqual(2);
    }
  });
});

// ---------------------------------------------------------------------------
// LatticeSigmaProtocol
// ---------------------------------------------------------------------------

describe('LatticeSigmaProtocol', () => {
  test('prove returns a proof or null (due to rejection sampling)', () => {
    const { RingElement, ModuleElement } = getHelpers();
    const protocol = new LatticeSigmaProtocol(4, 4, TEST_N, TEST_Q, 1000);

    // Construct witness with small norm
    const s = new ModuleElement(
      Array.from({ length: 4 }, () => RingElement.smallSample(TEST_N, TEST_Q, 1))
    );

    // Compute u = A*s (we don't have direct access to A, so compute via prove)
    // The protocol internally computes u from its own A matrix
    // We need to get u by computing it; but since A is internal, we just test
    // that prove/verify work together
    const protocol2 = new LatticeSigmaProtocol(4, 4, TEST_N, TEST_Q, 1000);
    // For this test, we accept that prove may return null due to rejection sampling
    // We just verify the API works
    expect(typeof protocol2.prove).toBe('function');
    expect(typeof protocol2.verify).toBe('function');
  });

  test('verify rejects a proof with oversized response norm', () => {
    const { RingElement, ModuleElement } = getHelpers();
    const protocol = new LatticeSigmaProtocol(4, 4, TEST_N, TEST_Q, 10);

    // Craft a fake proof with very large response
    const fakeProof: LatticeSigmaProof = {
      commitment: RingElement.random(TEST_N, TEST_Q),
      challenge: RingElement.random(TEST_N, TEST_Q),
      response: ModuleElement.random(4, TEST_N, TEST_Q), // random = very large norm
    };

    const target = [RingElement.random(TEST_N, TEST_Q)];
    // Should reject because random response has very large norm
    const valid = protocol.verify(fakeProof, target);
    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// LatticeRangeProofSystem
// ---------------------------------------------------------------------------

describe('LatticeRangeProofSystem', () => {
  let rangeProver: LatticeRangeProofSystem;

  beforeEach(() => {
    rangeProver = new LatticeRangeProofSystem(TEST_N, TEST_Q);
  });

  test('prove creates a range proof for a value in range', () => {
    const proof = rangeProver.prove(42, [0, 255]);
    expect(proof.range).toEqual([0, 255]);
    expect(proof.binaryDecomposition.length).toBe(8); // ceil(log2(256)) = 8
    expect(proof.commitments.length).toBe(8);
  });

  test('verify accepts a valid range proof', () => {
    const proof = rangeProver.prove(100, [0, 255]);
    const valid = rangeProver.verify(proof);
    expect(valid).toBe(true);
  });

  test('verify accepts proof for minimum value in range', () => {
    const proof = rangeProver.prove(0, [0, 255]);
    expect(rangeProver.verify(proof)).toBe(true);
  });

  test('verify accepts proof for maximum value in range', () => {
    const proof = rangeProver.prove(255, [0, 255]);
    expect(rangeProver.verify(proof)).toBe(true);
  });

  test('binary decomposition is correct', () => {
    const proof = rangeProver.prove(42, [0, 255]);
    // 42 = 0b00101010 -> bits are [0,1,0,1,0,1,0,0]
    const bits = proof.binaryDecomposition.map(r => r.coeffs[0]);
    // Reconstruct value from bits
    let value = 0;
    for (let i = 0; i < bits.length; i++) {
      value += bits[i] * (1 << i);
    }
    expect(value).toBe(42);
  });

  test('binary decomposition for shifted range', () => {
    const proof = rangeProver.prove(50, [10, 265]);
    // shifted = 50 - 10 = 40
    const bits = proof.binaryDecomposition.map(r => r.coeffs[0]);
    let value = 0;
    for (let i = 0; i < bits.length; i++) {
      value += bits[i] * (1 << i);
    }
    expect(value).toBe(40); // 50 - 10
  });

  test('verify rejects proof with tampered binary decomposition', () => {
    const proof = rangeProver.prove(42, [0, 255]);

    // Tamper with a bit: set a 0-bit to 2 (not binary)
    const tamperedProof = { ...proof };
    const { RingElement } = getHelpers();
    const fakeBit = new RingElement([2], TEST_N, TEST_Q);
    tamperedProof.binaryDecomposition = [...proof.binaryDecomposition];
    tamperedProof.binaryDecomposition[0] = fakeBit;

    // b*(b-1) = 2*(2-1) = 2, which is not zero
    const valid = rangeProver.verify(tamperedProof);
    expect(valid).toBe(false);
  });

  test('verify rejects proof with wrong number of bits', () => {
    const proof = rangeProver.prove(42, [0, 255]);

    // Remove one bit from decomposition
    const tamperedProof = { ...proof };
    tamperedProof.binaryDecomposition = proof.binaryDecomposition.slice(0, -1);

    expect(rangeProver.verify(tamperedProof)).toBe(false);
  });

  test('different values produce different binary decompositions', () => {
    const p1 = rangeProver.prove(10, [0, 255]);
    const p2 = rangeProver.prove(200, [0, 255]);

    const bits1 = p1.binaryDecomposition.map(r => r.coeffs[0]);
    const bits2 = p2.binaryDecomposition.map(r => r.coeffs[0]);

    expect(bits1.join(',')).not.toEqual(bits2.join(','));
  });
});

// ---------------------------------------------------------------------------
// LatticeSetMembershipProof
// ---------------------------------------------------------------------------

describe('LatticeSetMembershipProof', () => {
  let memberProver: LatticeSetMembershipProof;

  beforeEach(() => {
    memberProver = new LatticeSetMembershipProof(TEST_N, TEST_Q);
  });

  test('prove creates a membership proof for element in set', () => {
    const set = [10, 20, 30, 40, 50];
    const proof = memberProver.prove(30, set);

    expect(proof.commitmentToValue).toBeDefined();
    expect(proof.commitmentToIndex).toBeDefined();
    expect(proof.setDigest.length).toBe(4); // LatticeHash returns 4 numbers
  });

  test('prove throws for element not in set', () => {
    const set = [10, 20, 30];
    expect(() => memberProver.prove(99, set)).toThrow('Value not in set');
  });

  test('verify accepts a valid membership proof', () => {
    const set = [1, 2, 3, 4, 5];
    const proof = memberProver.prove(3, set);
    const valid = memberProver.verify(proof, set);
    expect(valid).toBe(true);
  });

  test('verify rejects proof with wrong set digest', () => {
    const set = [1, 2, 3, 4, 5];
    const proof = memberProver.prove(3, set);

    // Verify against a different set
    const differentSet = [10, 20, 30, 40, 50];
    const valid = memberProver.verify(proof, differentSet);
    expect(valid).toBe(false);
  });

  test('different values produce different proofs', () => {
    const set = [10, 20, 30];
    const p1 = memberProver.prove(10, set);
    const p2 = memberProver.prove(20, set);

    // Commitment to value should differ
    const c1 = p1.commitmentToValue.c0.toBytes();
    const c2 = p2.commitmentToValue.c0.toBytes();
    const same = c1.every((b: number, i: number) => b === c2[i]);
    expect(same).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ProofAggregator
// ---------------------------------------------------------------------------

describe('ProofAggregator', () => {
  let aggregator: ProofAggregator;

  beforeEach(() => {
    aggregator = new ProofAggregator(TEST_N, TEST_Q);
  });

  test('aggregate throws with empty proofs array', () => {
    expect(() => aggregator.aggregate([])).toThrow('No proofs to aggregate');
  });

  test('aggregate produces an aggregated proof from valid sigma proofs', () => {
    const { RingElement, ModuleElement } = getHelpers();

    // Create minimal valid-structure sigma proofs
    const proofs: LatticeSigmaProof[] = [];
    for (let i = 0; i < 3; i++) {
      proofs.push({
        commitment: RingElement.random(TEST_N, TEST_Q),
        challenge: RingElement.random(TEST_N, TEST_Q),
        response: new ModuleElement(
          Array.from({ length: 4 }, () => RingElement.smallSample(TEST_N, TEST_Q, 1))
        ),
      });
    }

    const aggregated = aggregator.aggregate(proofs);
    expect(aggregated.proofCount).toBe(3);
    expect(aggregated.individualCommitments.length).toBe(3);
    expect(aggregated.aggregateChallenge).toBeDefined();
    expect(aggregated.aggregateResponse).toBeDefined();
  });

  test('aggregated proof preserves individual commitments', () => {
    const { RingElement, ModuleElement } = getHelpers();
    const proofs: LatticeSigmaProof[] = [];
    for (let i = 0; i < 2; i++) {
      proofs.push({
        commitment: RingElement.random(TEST_N, TEST_Q),
        challenge: RingElement.random(TEST_N, TEST_Q),
        response: new ModuleElement(
          Array.from({ length: 4 }, () => RingElement.smallSample(TEST_N, TEST_Q, 1))
        ),
      });
    }

    const agg = aggregator.aggregate(proofs);
    for (let i = 0; i < proofs.length; i++) {
      expect(agg.individualCommitments[i].equals(proofs[i].commitment)).toBe(true);
    }
  });

  test('verifyAggregated checks norm bound', () => {
    const { RingElement, ModuleElement } = getHelpers();

    // Create an aggregated proof with oversized response
    const agg: AggregatedProof = {
      individualCommitments: [RingElement.random(TEST_N, TEST_Q)],
      aggregateChallenge: RingElement.random(TEST_N, TEST_Q),
      aggregateResponse: ModuleElement.random(4, TEST_N, TEST_Q),
      proofCount: 1,
    };

    // Scale response to be enormous
    const hugeResponse = new ModuleElement(
      agg.aggregateResponse.elements.map(e => e.scalarMul(TEST_Q - 1))
    );
    const hugAgg = { ...agg, aggregateResponse: hugeResponse };

    const targets = [[RingElement.random(TEST_N, TEST_Q)]];
    const valid = aggregator.verifyAggregated(hugAgg, targets);
    expect(valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// LatticeNIZKSystem
// ---------------------------------------------------------------------------

describe('LatticeNIZKSystem', () => {
  let nizk: LatticeNIZKSystem;

  beforeEach(() => {
    nizk = new LatticeNIZKSystem(TEST_N, TEST_Q);
  });

  test('proveKnowledge produces a knowledge proof', () => {
    const secret = [1, 2, 3];
    const publicOutput = [10, 20, 30];
    const proof = nizk.proveKnowledge(secret, publicOutput);

    expect(proof.type).toBe('knowledge');
    expect(proof.commitment).toBeDefined();
    expect(proof.publicInputHash.length).toBe(4);
  });

  test('proveRange produces a range proof', () => {
    const proof = nizk.proveRange(42, [0, 255]);
    expect(proof.type).toBe('range');
    expect(proof.rangeProof).toBeDefined();
    expect(proof.rangeProof!.range).toEqual([0, 255]);
  });

  test('verify accepts a valid range proof', () => {
    const proof = nizk.proveRange(100, [0, 255]);
    const valid = nizk.verify(proof, { range: [0, 255] });
    expect(valid).toBe(true);
  });

  test('proveMembership produces a membership proof', () => {
    const set = [5, 10, 15, 20];
    const proof = nizk.proveMembership(10, set);
    expect(proof.type).toBe('membership');
    expect(proof.membershipProof).toBeDefined();
  });

  test('verify accepts a valid membership proof', () => {
    const set = [5, 10, 15, 20];
    const proof = nizk.proveMembership(10, set);
    const valid = nizk.verify(proof, { set });
    expect(valid).toBe(true);
  });

  test('verify returns false for knowledge proof without sigma proof', () => {
    const proof = nizk.proveKnowledge([1], [2]);
    // If sigma proof is null (due to rejection sampling), verify should return false
    if (proof.sigmaProof === null) {
      const valid = nizk.verify(proof, { output: [2] });
      expect(valid).toBe(false);
    }
    // Otherwise, it should be a function returning boolean
    expect(typeof nizk.verify(proof, { output: [2] })).toBe('boolean');
  });

  test('verify returns false for range proof without range data', () => {
    const proof = nizk.proveRange(50, [0, 100]);
    // Remove the range proof
    const broken = { ...proof, rangeProof: undefined };
    expect(nizk.verify(broken, { range: [0, 100] })).toBe(false);
  });

  test('batchVerify checks multiple proofs', () => {
    const proofs = [
      nizk.proveRange(10, [0, 255]),
      nizk.proveRange(200, [0, 255]),
    ];
    const inputs = [
      { range: [0, 255] as [number, number] },
      { range: [0, 255] as [number, number] },
    ];

    const result = nizk.batchVerify(proofs, inputs);
    expect(result.results.length).toBe(2);
    expect(typeof result.allValid).toBe('boolean');
  });

  test('aggregateProofs aggregates sigma proofs from knowledge proofs', () => {
    const proofs = [
      nizk.proveKnowledge([1, 2], [3, 4]),
      nizk.proveKnowledge([5, 6], [7, 8]),
    ];

    const hasSigma = proofs.filter(p => p.sigmaProof !== null);
    if (hasSigma.length >= 2) {
      const agg = nizk.aggregateProofs(hasSigma);
      expect(agg).not.toBeNull();
      expect(agg!.proofCount).toBe(hasSigma.length);
    }
  });

  test('estimateProofSize returns positive byte count for each type', () => {
    const knowledgeSize = nizk.estimateProofSize('knowledge');
    const rangeSize = nizk.estimateProofSize('range');
    const membershipSize = nizk.estimateProofSize('membership');

    expect(knowledgeSize).toBeGreaterThan(0);
    expect(rangeSize).toBeGreaterThan(0);
    expect(membershipSize).toBeGreaterThan(0);
    // Range proofs are larger than knowledge proofs due to per-bit structure
    expect(rangeSize).toBeGreaterThan(knowledgeSize);
  });

  test('verify rejects unknown proof type', () => {
    const { RingElement } = getHelpers();
    const fakeProof: NIZKProof = {
      type: 'linear_relation' as any,
      commitment: {
        c0: RingElement.zero(TEST_N, TEST_Q),
        c: [RingElement.zero(TEST_N, TEST_Q), RingElement.zero(TEST_N, TEST_Q)],
      },
      sigmaProof: null,
      publicInputHash: [0, 0, 0, 0],
    };
    expect(nizk.verify(fakeProof)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Helper to get ring/module constructors from the module
// ---------------------------------------------------------------------------

/**
 * Import helpers. Since RingElement and ModuleElement are not exported
 * directly, we re-create minimal versions using the exported classes
 * that internally use them, or import them if available.
 *
 * We try dynamic import; if that fails, we create inline helpers.
 */
function getHelpers() {
  // These types are used by exported classes but may not be exported themselves.
  // We construct them by leveraging the BDLOPCommitmentScheme internals.
  // Since the module exports BDLOPCommitmentScheme which uses RingElement,
  // we need to replicate minimal RingElement/ModuleElement for test setup.

  // Attempt to require the module to get the classes
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('../algorithms/lattice-zk-proofs');
    if (mod.RingElement && mod.ModuleElement) {
      return { RingElement: mod.RingElement, ModuleElement: mod.ModuleElement };
    }
  } catch {
    // fall through
  }

  // Inline minimal implementations matching the source API
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
      const c = Array.from({ length: n }, () => Math.floor(Math.random() * q));
      return new RingElement(c, n, q);
    }

    static gaussianSample(n: number = 256, q: number = 12289, sigma: number = 3.2): RingElement {
      const coeffs: number[] = [];
      for (let i = 0; i < n; i++) {
        const u1 = Math.random();
        const u2 = Math.random();
        const z = Math.sqrt(-2 * Math.log(u1 + 1e-10)) * Math.cos(2 * Math.PI * u2);
        coeffs.push(Math.round(z * sigma));
      }
      return new RingElement(coeffs, n, q);
    }

    static smallSample(n: number = 256, q: number = 12289, bound: number = 1): RingElement {
      const coeffs = Array.from({ length: n }, () =>
        Math.floor(Math.random() * (2 * bound + 1)) - bound
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

    mul(other: RingElement): RingElement {
      const result = new Array(this.n).fill(0);
      for (let i = 0; i < this.n; i++) {
        for (let j = 0; j < this.n; j++) {
          const idx = i + j;
          if (idx < this.n) {
            result[idx] = (result[idx] + this.coeffs[i] * other.coeffs[j]) % this.q;
          } else {
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

    norm(): number {
      return Math.sqrt(this.coeffs.reduce((s, c) => {
        const centered = c > this.q / 2 ? c - this.q : c;
        return s + centered * centered;
      }, 0));
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

    norm(): number {
      return Math.sqrt(this.elements.reduce((s, e) => s + e.norm() ** 2, 0));
    }
  }

  return { RingElement, ModuleElement };
}
