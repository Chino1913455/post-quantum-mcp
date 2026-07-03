/**
 * Device-independent randomness (Probe 1) tests.
 *
 * Asserts the Pironio CHSH->min-entropy bound at its known endpoints and
 * monotonicity, that the DI ingest gate certifies/refuses correctly, that
 * public outcomes are tagged NOT secret-safe (a public beacon must never seed a
 * key), and that above-Tsirelson data is rejected as inconsistent.
 */
import { describe, it, expect } from '@jest/globals';
import * as crypto from 'crypto';

import {
  diMinEntropyFromCHSH,
  vonNeumannEntropyCHSH,
  ingestDeviceIndependent,
  publicBeaconSeed,
  finiteRateEAT,
  roundsForSeed,
  finiteRateSecondOrder,
  roundsForSeedSecondOrder,
  entropyVariance,
  LOCAL_BOUND,
  TSIRELSON_BOUND,
} from '../utils/entropy/di';

describe('diMinEntropyFromCHSH (Pironio 2010)', () => {
  it('certifies 0 bits at the local bound S=2', () => {
    const c = diMinEntropyFromCHSH(LOCAL_BOUND);
    expect(c.minEntropyPerBit).toBeCloseTo(0, 9);
    expect(c.certifiesRandomness).toBe(false);
  });

  it('certifies 1 bit at the Tsirelson bound S=2√2', () => {
    const c = diMinEntropyFromCHSH(TSIRELSON_BOUND);
    expect(c.minEntropyPerBit).toBeCloseTo(1, 9);
    expect(c.certifiesRandomness).toBe(true);
    expect(c.aboveTsirelson).toBe(false);
  });

  it('is monotonically increasing in S over (2, 2√2)', () => {
    const a = diMinEntropyFromCHSH(2.2).minEntropyPerBit;
    const b = diMinEntropyFromCHSH(2.5).minEntropyPerBit;
    const d = diMinEntropyFromCHSH(2.8).minEntropyPerBit;
    expect(a).toBeGreaterThan(0);
    expect(b).toBeGreaterThan(a);
    expect(d).toBeGreaterThan(b);
    expect(d).toBeLessThanOrEqual(1);
  });

  it('flags S below the local bound as no-randomness', () => {
    const c = diMinEntropyFromCHSH(1.5);
    expect(c.certifiesRandomness).toBe(false);
    expect(c.minEntropyPerBit).toBeCloseTo(0, 9);
  });

  it('flags S above Tsirelson as inconsistent (clamped)', () => {
    const c = diMinEntropyFromCHSH(2.95);
    expect(c.aboveTsirelson).toBe(true);
    expect(c.minEntropyPerBit).toBeCloseTo(1, 9);
  });
});

describe('ingestDeviceIndependent', () => {
  const outcomes = (n = 100_000) => new Uint8Array(crypto.randomBytes(n));

  it('accepts a strong violation (private) and returns a 512-bit secret-safe seed', () => {
    const r = ingestDeviceIndependent(outcomes(), { chsh: TSIRELSON_BOUND, visibility: 'private' });
    expect(r.accepted).toBe(true);
    expect(r.seed).not.toBeNull();
    expect(r.seed!.length).toBe(64);
    expect(r.secretSafe).toBe(true);
    expect(r.certificate!.fullEntropy).toBe(true);
  });

  it('accepts a public violation but tags it NOT secret-safe', () => {
    const r = ingestDeviceIndependent(outcomes(), { chsh: 2.6, visibility: 'public' });
    expect(r.accepted).toBe(true);
    expect(r.secretSafe).toBe(false);
    expect(r.reason).toMatch(/PUBLIC|not a secret/i);
  });

  it('rejects S at the local bound (no certified randomness)', () => {
    const r = ingestDeviceIndependent(outcomes(), { chsh: 2.0, visibility: 'private' });
    expect(r.accepted).toBe(false);
    expect(r.seed).toBeNull();
  });

  it('rejects above-Tsirelson data as inconsistent', () => {
    const r = ingestDeviceIndependent(outcomes(), { chsh: 2.95, visibility: 'private' });
    expect(r.accepted).toBe(false);
    expect(r.seed).toBeNull();
  });

  it('rejects when there is too little data for the certified rate', () => {
    // S just above 2 -> tiny per-bit rate -> needs far more than we supply.
    const r = ingestDeviceIndependent(outcomes(1000), { chsh: 2.01, visibility: 'private' });
    expect(r.accepted).toBe(false);
    expect(r.reason).toMatch(/need \d+ outcome bytes/);
  });
});

describe('publicBeaconSeed', () => {
  it('produces a public, NOT secret-safe seed deterministically', () => {
    const pulse = new Uint8Array(crypto.randomBytes(64));
    const a = publicBeaconSeed(pulse);
    const b = publicBeaconSeed(pulse);
    expect(a.secretSafe).toBe(false);
    expect(a.seed!.length).toBe(64);
    expect(Buffer.from(a.seed!).equals(Buffer.from(b.seed!))).toBe(true); // deterministic
  });
});

describe('finiteRateEAT (entropy accumulation)', () => {
  it('certifies less than the asymptotic ceiling for finite n', () => {
    const r = finiteRateEAT(2.7, 100_000);
    expect(r.netRatePerRound).toBeGreaterThan(0);
    expect(r.netRatePerRound).toBeLessThan(r.asymptoticRatePerRound);
  });

  it('approaches the asymptotic bound as n grows', () => {
    const small = finiteRateEAT(2.6, 10_000).netRatePerRound;
    const big = finiteRateEAT(2.6, 100_000_000).netRatePerRound;
    expect(big).toBeGreaterThan(small);
    const asymptoticAtObserved = vonNeumannEntropyCHSH(2.6);
    expect(big).toBeGreaterThan(asymptoticAtObserved - 0.02);
  });

  it('certifies more total bits with more rounds', () => {
    const a = finiteRateEAT(2.7, 50_000).totalCertifiedBits;
    const b = finiteRateEAT(2.7, 500_000).totalCertifiedBits;
    expect(b).toBeGreaterThan(a);
  });

  it('certifies ~zero at the local bound S=2', () => {
    const r = finiteRateEAT(2.0, 1_000_000);
    expect(r.netRatePerRound).toBe(0);
    expect(r.totalCertifiedBits).toBe(0);
  });
});

describe('roundsForSeed', () => {
  it('returns rounds that actually certify the seed (and is tight)', () => {
    const S = 2.7;
    const n = roundsForSeed(S, 512);
    expect(n).not.toBeNull();
    expect(finiteRateEAT(S, n!).totalCertifiedBits).toBeGreaterThanOrEqual(512);
    expect(finiteRateEAT(S, n! - 1).totalCertifiedBits).toBeLessThan(512);
  });

  it('returns null when the violation is too weak to ever certify', () => {
    expect(roundsForSeed(2.0, 512)).toBeNull();
  });
});

describe('vonNeumannEntropyCHSH (tight per-round rate)', () => {
  it('is 0 at S=2 and 1 at S=2√2', () => {
    expect(vonNeumannEntropyCHSH(LOCAL_BOUND)).toBeCloseTo(0, 9);
    expect(vonNeumannEntropyCHSH(TSIRELSON_BOUND)).toBeCloseTo(1, 9);
  });

  it('is strictly tighter than the guessing (min-entropy) bound for intermediate S', () => {
    for (const S of [2.2, 2.4, 2.6]) {
      expect(vonNeumannEntropyCHSH(S)).toBeGreaterThan(diMinEntropyFromCHSH(S).minEntropyPerBit);
    }
  });
});

describe('second-order tight rate (iid collective attacks)', () => {
  it('certifies more than the conservative EAT bound at the same n', () => {
    const tight = finiteRateSecondOrder(2.7, 10_000).netRatePerRound;
    const eat = finiteRateEAT(2.7, 10_000).netRatePerRound;
    expect(tight).toBeGreaterThan(eat);
  });

  it('needs fewer rounds than EAT for a 512-bit seed', () => {
    const tight = roundsForSeedSecondOrder(2.7, 512)!;
    const eat = roundsForSeed(2.7, 512)!;
    expect(tight).toBeLessThan(eat);
    expect(finiteRateSecondOrder(2.7, tight).totalCertifiedBits).toBeGreaterThanOrEqual(512);
  });

  it('entropy variance vanishes at the endpoints and is positive between', () => {
    expect(entropyVariance(LOCAL_BOUND)).toBeCloseTo(0, 9);
    expect(entropyVariance(TSIRELSON_BOUND)).toBeCloseTo(0, 9);
    expect(entropyVariance(2.5)).toBeGreaterThan(0);
  });
});
