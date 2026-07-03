/**
 * External-entropy ingest gate + HMAC_DRBG tests.
 *
 * Asserts real properties: the gate ACCEPTS a healthy source and REJECTS
 * stuck/biased ones (not merely passing good data), a 512-bit seed appears only
 * on accept, the SP 800-90A HMAC_DRBG seeded from it yields high-min-entropy
 * non-repeating output (and is deterministic for a fixed seed), and a validated
 * device registered on EntropyService becomes the source generate() draws from.
 */
import { describe, it, expect } from '@jest/globals';
import * as crypto from 'crypto';

import {
  minEntropyMCV,
  ingestExternalEntropy,
  verifyFullEntropy,
  registerValidatedSource,
  HmacDrbg,
} from '../utils/entropy/ingest';
import { EntropyService } from '../utils/entropy/sources';

function good(n = 200_000): Uint8Array {
  return new Uint8Array(crypto.randomBytes(n));
}
function stuck(n = 200_000): Uint8Array {
  return new Uint8Array(n); // all zeros -> RCT must fail
}
function biased(n = 200_000): Uint8Array {
  // bytes in {0,1}: ~1 bit/byte min-entropy -> below the floor
  const b = crypto.randomBytes(n);
  for (let i = 0; i < n; i++) b[i] &= 1;
  return new Uint8Array(b);
}

describe('minEntropyMCV', () => {
  it('rates a CSPRNG near full entropy', () => {
    expect(minEntropyMCV(good()).hMin).toBeGreaterThan(7.5);
  });
  it('rates a stuck source near zero', () => {
    expect(minEntropyMCV(stuck()).hMin).toBeLessThan(0.1);
  });
});

describe('ingestExternalEntropy gate', () => {
  it('ACCEPTS a healthy source and returns a 512-bit seed', () => {
    const r = ingestExternalEntropy(good());
    expect(r.accepted).toBe(true);
    expect(r.seed).not.toBeNull();
    expect(r.seed!.length).toBe(64);
    expect(r.measuredMinEntropyPerByte).toBeGreaterThan(7.5);
  });
  it('REJECTS a stuck source (RCT) with no seed', () => {
    const r = ingestExternalEntropy(stuck());
    expect(r.accepted).toBe(false);
    expect(r.seed).toBeNull();
    expect(r.reason).toMatch(/RCT|stuck/i);
  });
  it('REJECTS a biased source below the min-entropy floor', () => {
    const r = ingestExternalEntropy(biased());
    expect(r.accepted).toBe(false);
    expect(r.seed).toBeNull();
  });
});

describe('HmacDrbg', () => {
  it('produces high-min-entropy, non-repeating output from a validated seed', () => {
    const r = ingestExternalEntropy(good());
    const drbg = new HmacDrbg(r.seed!);
    const a = drbg.generate(100_000);
    const b = drbg.generate(100_000);
    expect(minEntropyMCV(a).hMin).toBeGreaterThan(7.5);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
  it('is deterministic for a fixed seed', () => {
    const seed = new Uint8Array(crypto.randomBytes(32));
    const x = new HmacDrbg(seed).generate(64);
    const y = new HmacDrbg(seed).generate(64);
    expect(Buffer.from(x).equals(Buffer.from(y))).toBe(true);
  });
});

describe('registerValidatedSource', () => {
  it('makes a validated device the source generate() uses', () => {
    const svc = new EntropyService();
    const r = registerValidatedSource(svc, good(), { sourceName: 'true-entropy-test' });
    expect(r.accepted).toBe(true);
    const out = svc.generate(32);
    expect(out.source).toBe('true-entropy-test');
    expect(out.conditioned).toBe(true);
    expect(out.bytes.length).toBe(32);
  });
  it('does NOT register a rejected source', () => {
    const svc = new EntropyService();
    expect(registerValidatedSource(svc, stuck()).accepted).toBe(false);
    expect(svc.generate(32).source).toBe('os-csprng');
  });
});

describe('full-entropy guarantee', () => {
  it('certifies the seed is full entropy (LHL, distance <= epsilon)', () => {
    const r = ingestExternalEntropy(good());
    expect(r.accepted).toBe(true);
    expect(r.certificate).not.toBeNull();
    expect(r.certificate!.fullEntropy).toBe(true);
    expect(r.certificate!.distanceFromUniform).toBeLessThanOrEqual(2 ** -32);
    expect(r.certificate!.securityMarginBits).toBeGreaterThanOrEqual(0);
  });

  it('the DRBG stream measures as full entropy (~8 bits/byte)', () => {
    const r = ingestExternalEntropy(good());
    const block = new HmacDrbg(r.seed!).generate(200_000);
    const v = verifyFullEntropy(block);
    expect(v.shannonPerByte).toBeGreaterThan(7.99);
    expect(v.nearUniform).toBe(true);
  });
});
