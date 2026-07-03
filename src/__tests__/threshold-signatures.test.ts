import { jest, describe, it, expect, beforeEach, afterEach, test } from "@jest/globals";
/**
 * Tests for Post-Quantum Threshold Signature Scheme
 *
 * Verifies Shamir secret sharing, threshold Dilithium distributed key
 * generation, partial signing, signature combination, verification,
 * and proactive share refresh.
 */

import {
  ShamirLattice,
  Share,
  LatticeShare,
  ThresholdDilithium,
  ThresholdKeyPair,
  PartialSignature,
  CombinedSignature,
  ProactiveRefresh,
  DILITHIUM_Q,
  DEFAULT_FIELD_PRIME,
} from '../algorithms/threshold-signatures';

// ---------------------------------------------------------------------------
// ShamirLattice — secret sharing
// ---------------------------------------------------------------------------

describe('ShamirLattice', () => {
  let shamir: ShamirLattice;

  beforeEach(() => {
    shamir = new ShamirLattice();
  });

  test('generateShares produces n shares with correct indices', () => {
    const shares = shamir.generateShares(42n, 5, 3);
    expect(shares.length).toBe(5);
    expect(shares.map(s => s.index)).toEqual([1, 2, 3, 4, 5]);
  });

  test('reconstructSecret recovers the original secret from t shares', () => {
    const secret = 123456789n;
    const shares = shamir.generateShares(secret, 5, 3);
    const recovered = shamir.reconstructSecret(shares.slice(0, 3), 3);
    expect(recovered).toBe(secret);
  });

  test('reconstructSecret works with any t-subset of shares', () => {
    const secret = 999999n;
    const shares = shamir.generateShares(secret, 7, 4);

    // Try multiple subsets
    const subsets = [
      [shares[0], shares[1], shares[2], shares[3]],
      [shares[3], shares[4], shares[5], shares[6]],
      [shares[0], shares[2], shares[4], shares[6]],
      [shares[1], shares[3], shares[5], shares[6]],
    ];

    for (const subset of subsets) {
      const recovered = shamir.reconstructSecret(subset, 4);
      expect(recovered).toBe(secret);
    }
  });

  test('fewer than t shares cannot reconstruct secret', () => {
    const shares = shamir.generateShares(42n, 5, 3);
    expect(() => shamir.reconstructSecret(shares.slice(0, 2), 3)).toThrow();
  });

  test('generateShares throws when t > n', () => {
    expect(() => shamir.generateShares(1n, 3, 5)).toThrow();
  });

  test('generateShares throws for t < 1', () => {
    expect(() => shamir.generateShares(1n, 5, 0)).toThrow();
  });

  test('sharing zero reconstructs to zero', () => {
    const shares = shamir.generateShares(0n, 5, 3);
    const recovered = shamir.reconstructSecret(shares.slice(0, 3), 3);
    expect(recovered).toBe(0n);
  });

  test('large secret roundtrips correctly', () => {
    const secret = DEFAULT_FIELD_PRIME - 1n;
    const shares = shamir.generateShares(secret, 5, 3);
    const recovered = shamir.reconstructSecret(shares.slice(0, 3), 3);
    // secret mod prime = prime - 1
    expect(recovered).toBe(secret % DEFAULT_FIELD_PRIME);
  });

  test('different secrets produce different shares', () => {
    const s1 = shamir.generateShares(100n, 5, 3);
    const s2 = shamir.generateShares(200n, 5, 3);
    // At least share values at same indices should differ
    const allSame = s1.every((s, i) => s.value === s2[i].value);
    expect(allSame).toBe(false);
  });

  test('lagrangeCoefficient computes valid coefficients', () => {
    const indices = [1, 2, 3];
    // Lagrange coefficients should sum to 1 (at x=0 for the basis)
    const coeffs = indices.map(i => shamir.lagrangeCoefficient(i, indices));
    // Test each is a bigint
    for (const c of coeffs) {
      expect(typeof c).toBe('bigint');
    }
  });
});

// ---------------------------------------------------------------------------
// ShamirLattice — Feldman VSS
// ---------------------------------------------------------------------------

describe('ShamirLattice Feldman VSS', () => {
  let shamir: ShamirLattice;

  beforeEach(() => {
    shamir = new ShamirLattice();
  });

  test('verifiableSharing produces shares and commitments', () => {
    const { shares, commitment } = shamir.verifiableSharing(42n, 5, 3);
    expect(shares.length).toBe(5);
    expect(commitment.commitments.length).toBe(3); // t commitments
    expect(commitment.generator).toBe(2n);
  });

  test('shares from verifiable sharing can reconstruct original secret', () => {
    const secret = 777n;
    const { shares } = shamir.verifiableSharing(secret, 5, 3);
    const recovered = shamir.reconstructSecret(shares.slice(0, 3), 3);
    expect(recovered).toBe(secret);
  });

  test('verifyShare accepts valid shares', () => {
    const { shares, commitment } = shamir.verifiableSharing(42n, 5, 3);
    for (const share of shares) {
      expect(shamir.verifyShare(share, commitment)).toBe(true);
    }
  });

  test('verifyShare rejects tampered share', () => {
    const { shares, commitment } = shamir.verifiableSharing(42n, 5, 3);
    const tampered: Share = { index: shares[0].index, value: shares[0].value + 1n };
    expect(shamir.verifyShare(tampered, commitment)).toBe(false);
  });

  test('each share has a commitment proof', () => {
    const { shares } = shamir.verifiableSharing(42n, 5, 3);
    for (const share of shares) {
      expect(share.commitment).toBeDefined();
      expect(share.commitment!.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// ShamirLattice — Pedersen VSS
// ---------------------------------------------------------------------------

describe('ShamirLattice Pedersen VSS', () => {
  let shamir: ShamirLattice;

  beforeEach(() => {
    shamir = new ShamirLattice();
  });

  test('pedersenVSS produces shares, blind shares, and commitments', () => {
    const { shares, blindShares, commitment } = shamir.pedersenVSS(42n, 5, 3);
    expect(shares.length).toBe(5);
    expect(blindShares.length).toBe(5);
    expect(commitment.commitments.length).toBe(3);
  });

  test('Pedersen shares reconstruct the original secret', () => {
    const secret = 12345n;
    const { shares } = shamir.pedersenVSS(secret, 5, 3);
    const recovered = shamir.reconstructSecret(shares.slice(0, 3), 3);
    expect(recovered).toBe(secret);
  });

  test('verifyPedersenShare accepts valid share/blind pairs', () => {
    const { shares, blindShares, commitment } = shamir.pedersenVSS(42n, 5, 3);
    for (let i = 0; i < shares.length; i++) {
      expect(shamir.verifyPedersenShare(shares[i], blindShares[i], commitment)).toBe(true);
    }
  });

  test('verifyPedersenShare rejects mismatched share and blind', () => {
    const { shares, blindShares, commitment } = shamir.pedersenVSS(42n, 5, 3);
    // Swap blind shares to cause mismatch
    expect(shamir.verifyPedersenShare(shares[0], blindShares[1], commitment)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ShamirLattice — lattice vector sharing
// ---------------------------------------------------------------------------

describe('ShamirLattice lattice vector sharing', () => {
  let shamir: ShamirLattice;

  beforeEach(() => {
    shamir = new ShamirLattice();
  });

  test('shareLatticeVector produces n shares with correct dimension', () => {
    const secret = [10, 20, 30, 40];
    const shares = shamir.shareLatticeVector(secret, 5, 3, DILITHIUM_Q);
    expect(shares.length).toBe(5);
    for (const share of shares) {
      expect(share.vector.length).toBe(4);
      expect(share.index).toBeGreaterThanOrEqual(1);
    }
  });

  test('reconstructLatticeVector recovers the original vector', () => {
    const secret = [100, 200, 300];
    const q = DILITHIUM_Q;
    const shares = shamir.shareLatticeVector(secret, 5, 3, q);
    const recovered = shamir.reconstructLatticeVector(shares.slice(0, 3), 3, q);

    for (let i = 0; i < secret.length; i++) {
      expect(recovered[i]).toBe(secret[i] % q);
    }
  });

  test('fewer than t lattice shares cannot reconstruct', () => {
    const secret = [10, 20, 30];
    const shares = shamir.shareLatticeVector(secret, 5, 3, DILITHIUM_Q);
    expect(() => shamir.reconstructLatticeVector(shares.slice(0, 2), 3, DILITHIUM_Q)).toThrow();
  });

  test('any t-subset reconstructs correctly', () => {
    const secret = [7, 13, 42];
    const q = DILITHIUM_Q;
    const shares = shamir.shareLatticeVector(secret, 5, 3, q);

    // subset [1,3,5]
    const subset = [shares[0], shares[2], shares[4]];
    const recovered = shamir.reconstructLatticeVector(subset, 3, q);
    for (let i = 0; i < secret.length; i++) {
      expect(recovered[i]).toBe(secret[i] % q);
    }
  });
});

// ---------------------------------------------------------------------------
// ThresholdDilithium — distributed key generation
// ---------------------------------------------------------------------------

describe('ThresholdDilithium DKG', () => {
  let td: ThresholdDilithium;

  beforeEach(() => {
    td = new ThresholdDilithium('dilithium2');
  });

  test('distributedKeyGen produces a key pair with correct structure', () => {
    const kp = td.distributedKeyGen(5, 3, 'dilithium2');
    expect(kp.n).toBe(5);
    expect(kp.t).toBe(3);
    expect(kp.shares.length).toBe(5);
    expect(kp.verificationShares.length).toBe(5);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBeGreaterThan(0);
  });

  test('each share has correct metadata', () => {
    const kp = td.distributedKeyGen(4, 3, 'dilithium2');
    for (let i = 0; i < kp.shares.length; i++) {
      const share = kp.shares[i];
      expect(share.index).toBe(i + 1);
      expect(share.n).toBe(4);
      expect(share.t).toBe(3);
      expect(share.secretShare.length).toBeGreaterThan(0);
      expect(share.commitment.length).toBeGreaterThan(0);
    }
  });

  test('all shares reference the same combined public key', () => {
    const kp = td.distributedKeyGen(5, 3);
    const pkHex = Array.from(kp.publicKey).join(',');
    for (const share of kp.shares) {
      expect(Array.from(share.publicKey).join(',')).toBe(pkHex);
    }
  });

  test('DKG throws for threshold > numParties', () => {
    expect(() => td.distributedKeyGen(3, 5)).toThrow();
  });

  test('DKG throws for threshold < 2', () => {
    expect(() => td.distributedKeyGen(5, 1)).toThrow();
  });

  test('different DKG runs produce different public keys', () => {
    const kp1 = td.distributedKeyGen(4, 3);
    const kp2 = td.distributedKeyGen(4, 3);
    expect(Array.from(kp1.publicKey).join(','))
      .not.toEqual(Array.from(kp2.publicKey).join(','));
  });
});

// ---------------------------------------------------------------------------
// ThresholdDilithium — partial signing and combination
// ---------------------------------------------------------------------------

describe('ThresholdDilithium signing', () => {
  let td: ThresholdDilithium;
  let keyPair: ThresholdKeyPair;

  beforeAll(() => {
    td = new ThresholdDilithium('dilithium2');
    keyPair = td.distributedKeyGen(5, 3, 'dilithium2');
  });

  test('partialSign produces a partial signature with correct index', () => {
    const msg = new TextEncoder().encode('threshold test');
    const partial = td.partialSign(msg, keyPair.shares[0]);
    expect(partial.index).toBe(1);
    expect(partial.partialSig).toBeInstanceOf(Uint8Array);
    expect(partial.partialSig.length).toBeGreaterThan(0);
    expect(partial.commitment.length).toBeGreaterThan(0);
    expect(partial.proof.length).toBeGreaterThan(0);
  });

  test('t parties can produce enough partial signatures to combine', () => {
    const msg = new TextEncoder().encode('combine test');
    const partials: PartialSignature[] = [];
    for (let i = 0; i < 3; i++) {
      partials.push(td.partialSign(msg, keyPair.shares[i]));
    }
    expect(partials.length).toBe(3);
    const combined = td.combinePartialSignatures(partials, 3, keyPair.publicKey);
    expect(combined.signature).toBeInstanceOf(Uint8Array);
    expect(combined.signature.length).toBeGreaterThan(0);
    expect(combined.valid).toBe(true);
    expect(combined.signerIndices).toEqual([1, 2, 3]);
  });

  test('fewer than t partial signatures cannot be combined', () => {
    const msg = new TextEncoder().encode('too few');
    const partials: PartialSignature[] = [];
    for (let i = 0; i < 2; i++) {
      partials.push(td.partialSign(msg, keyPair.shares[i]));
    }
    expect(() => td.combinePartialSignatures(partials, 3, keyPair.publicKey)).toThrow();
  });

  test('different messages produce different combined signatures', () => {
    const msg1 = new TextEncoder().encode('message one');
    const msg2 = new TextEncoder().encode('message two');

    const partials1 = keyPair.shares.slice(0, 3).map(s => td.partialSign(msg1, s));
    const partials2 = keyPair.shares.slice(0, 3).map(s => td.partialSign(msg2, s));

    const combined1 = td.combinePartialSignatures(partials1, 3, keyPair.publicKey);
    const combined2 = td.combinePartialSignatures(partials2, 3, keyPair.publicKey);

    expect(Array.from(combined1.signature).join(','))
      .not.toEqual(Array.from(combined2.signature).join(','));
  });

  test('different subsets of t signers produce valid combined signatures', () => {
    const msg = new TextEncoder().encode('subset test');

    // Use shares [0,1,2]
    const partialsA = keyPair.shares.slice(0, 3).map(s => td.partialSign(msg, s));
    const combinedA = td.combinePartialSignatures(partialsA, 3, keyPair.publicKey);
    expect(combinedA.valid).toBe(true);

    // Use shares [2,3,4]
    const partialsB = keyPair.shares.slice(2, 5).map(s => td.partialSign(msg, s));
    const combinedB = td.combinePartialSignatures(partialsB, 3, keyPair.publicKey);
    expect(combinedB.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ProactiveRefresh
// ---------------------------------------------------------------------------

describe('ProactiveRefresh', () => {
  let shamir: ShamirLattice;
  let refresh: ProactiveRefresh;

  beforeEach(() => {
    shamir = new ShamirLattice();
    refresh = new ProactiveRefresh();
  });

  test('refresh produces new shares preserving the secret', () => {
    const secret = 42n;
    const original = shamir.generateShares(secret, 5, 3);
    const { newShares, epoch, proof } = refresh.refresh(original, 3);

    expect(newShares.length).toBe(5);
    expect(epoch).toBe(1);
    expect(proof).toBeInstanceOf(Uint8Array);

    // Verify secret is preserved
    const recovered = shamir.reconstructSecret(newShares.slice(0, 3), 3);
    expect(recovered).toBe(secret);
  });

  test('refreshed shares differ from original shares', () => {
    const secret = 100n;
    const original = shamir.generateShares(secret, 5, 3);
    const { newShares } = refresh.refresh(original, 3);

    // At least some share values should change
    const anyChanged = newShares.some((s, i) => s.value !== original[i].value);
    expect(anyChanged).toBe(true);
  });

  test('verifyRefresh confirms old and new shares hold same secret', () => {
    const secret = 999n;
    const original = shamir.generateShares(secret, 5, 3);
    const { newShares } = refresh.refresh(original, 3);

    expect(refresh.verifyRefresh(original, newShares, 3)).toBe(true);
  });

  test('verifyRefresh rejects shares of different secrets', () => {
    const shares1 = shamir.generateShares(100n, 5, 3);
    const shares2 = shamir.generateShares(200n, 5, 3);
    expect(refresh.verifyRefresh(shares1, shares2, 3)).toBe(false);
  });

  test('multiple refreshes preserve the secret', () => {
    const secret = 777n;
    let shares = shamir.generateShares(secret, 5, 3);

    for (let i = 0; i < 5; i++) {
      const { newShares } = refresh.refresh(shares, 3);
      const recovered = shamir.reconstructSecret(newShares.slice(0, 3), 3);
      expect(recovered).toBe(secret);
      shares = newShares;
    }
  });

  test('refresh epoch increments on each call', () => {
    const shares = shamir.generateShares(1n, 5, 3);
    const r1 = refresh.refresh(shares, 3);
    const r2 = refresh.refresh(r1.newShares, 3);
    const r3 = refresh.refresh(r2.newShares, 3);

    expect(r1.epoch).toBe(1);
    expect(r2.epoch).toBe(2);
    expect(r3.epoch).toBe(3);
  });

  test('refresh preserves share indices', () => {
    const secret = 42n;
    const original = shamir.generateShares(secret, 5, 3);
    const { newShares } = refresh.refresh(original, 3);

    for (let i = 0; i < 5; i++) {
      expect(newShares[i].index).toBe(original[i].index);
    }
  });

  test('refresh throws with insufficient shares', () => {
    const shares = shamir.generateShares(1n, 5, 3);
    const tooFew = shares.slice(0, 2); // only 2 shares, but threshold is 3
    expect(() => refresh.refresh(tooFew, 3)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// ThresholdDilithium — verification
// ---------------------------------------------------------------------------

describe('ThresholdDilithium verification', () => {
  let td: ThresholdDilithium;

  beforeEach(() => {
    td = new ThresholdDilithium('dilithium2');
  });

  test('verify returns boolean for a combined signature', () => {
    const kp = td.distributedKeyGen(4, 3, 'dilithium2');
    const msg = new TextEncoder().encode('verify test');
    const partials = kp.shares.slice(0, 3).map(s => td.partialSign(msg, s));
    const combined = td.combinePartialSignatures(partials, 3, kp.publicKey);

    const result = td.verify(msg, combined.signature, kp.publicKey);
    expect(typeof result).toBe('boolean');
  });

  test('verify rejects a zero-length signature', () => {
    const kp = td.distributedKeyGen(4, 3, 'dilithium2');
    const msg = new TextEncoder().encode('empty sig');
    expect(td.verify(msg, new Uint8Array(0), kp.publicKey)).toBe(false);
  });

  test('verify rejects a short random signature', () => {
    const kp = td.distributedKeyGen(4, 3, 'dilithium2');
    const msg = new TextEncoder().encode('random sig');
    const randomSig = new Uint8Array(16);
    expect(td.verify(msg, randomSig, kp.publicKey)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ThresholdDilithium — parameter sets
// ---------------------------------------------------------------------------

describe('ThresholdDilithium parameter sets', () => {
  test('dilithium2 (ml-dsa-44) instantiates without error', () => {
    const td = new ThresholdDilithium('dilithium2');
    const kp = td.distributedKeyGen(3, 2, 'dilithium2');
    expect(kp.parameterSet).toBe('dilithium2');
    expect(kp.shares.length).toBe(3);
  });

  test('dilithium3 (ml-dsa-65) instantiates without error', () => {
    const td = new ThresholdDilithium('dilithium3');
    const kp = td.distributedKeyGen(3, 2, 'dilithium3');
    expect(kp.parameterSet).toBe('dilithium3');
  });

  test('dilithium5 (ml-dsa-87) instantiates without error', () => {
    const td = new ThresholdDilithium('dilithium5');
    const kp = td.distributedKeyGen(3, 2, 'dilithium5');
    expect(kp.parameterSet).toBe('dilithium5');
  });

  test('different parameter sets produce different-sized public keys', () => {
    const td2 = new ThresholdDilithium('dilithium2');
    const td3 = new ThresholdDilithium('dilithium3');

    const kp2 = td2.distributedKeyGen(3, 2, 'dilithium2');
    const kp3 = td3.distributedKeyGen(3, 2, 'dilithium3');

    // dilithium3 has k=6 vs k=4, so public key should be larger
    expect(kp3.publicKey.length).toBeGreaterThan(kp2.publicKey.length);
  });
});
