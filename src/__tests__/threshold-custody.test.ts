/**
 * Shamir t-of-n custody of post-quantum keys.
 *
 * The headline guarantee: a quorum reconstructs the key and produces a REAL,
 * standard FIPS-204 ML-DSA signature (verified by the unmodified @noble
 * verifier) — and any t-1 shares cannot reconstruct it.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ThresholdCustodyHandler } from '../utils/threshold-custody';

const log = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);
const body = (r: any) => JSON.parse(r.content[0].text);
let h: ThresholdCustodyHandler;
beforeEach(() => { h = new ThresholdCustodyHandler(log(), new NodeCache()); });

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

describe('Shamir GF(256) custody', () => {
  it('splits and reconstructs an exact secret (any t-subset)', async () => {
    const secret = b64(Buffer.from('a-32-byte-post-quantum-secret-ok'));
    const split = body(await h.splitKey({ secret, n: 5, threshold: 3 }));
    expect(split.shares.length).toBe(5);

    // Two different 3-share subsets must both reconstruct the original.
    for (const pick of [[0, 1, 2], [1, 3, 4]]) {
      const subset = pick.map((i) => split.shares[i]);
      const r = body(await h.reconstructKey({ shares: subset, threshold: 3, commitment: split.commitment }));
      expect(r.verified).toBe(true);
      expect(Buffer.from(r.secret, 'base64').toString()).toBe('a-32-byte-post-quantum-secret-ok');
    }
  });

  it('cannot reconstruct from t-1 shares', async () => {
    const split = body(await h.splitKey({ secret: b64(Buffer.from('secret-material-here')), n: 5, threshold: 3 }));
    await expect(h.reconstructKey({ shares: split.shares.slice(0, 2), threshold: 3 })).rejects.toThrow();
  });

  it('detects a tampered share via the commitment', async () => {
    const split = body(await h.splitKey({ secret: b64(Buffer.from('integrity-protected')), n: 4, threshold: 2 }));
    const tampered = JSON.parse(JSON.stringify(split.shares.slice(0, 2)));
    const v = Buffer.from(tampered[0].value, 'base64');
    v[0] ^= 0xff;
    tampered[0].value = v.toString('base64');
    await expect(h.reconstructKey({ shares: tampered, threshold: 2, commitment: split.commitment })).rejects.toThrow(/commitment/);
  });

  it('rejects invalid (t, n) parameters', async () => {
    await expect(h.splitKey({ secret: b64(Buffer.from('x')), n: 3, threshold: 5 })).rejects.toThrow();
    await expect(h.splitKey({ secret: b64(Buffer.from('x')), n: 300, threshold: 2 })).rejects.toThrow();
  });
});

describe('Quorum signing produces a REAL FIPS-204 signature', () => {
  it('a 3-of-5 quorum yields a signature the standard ML-DSA verifier accepts', async () => {
    const kp = ml_dsa65.keygen();
    const split = body(await h.splitKey({ secret: b64(kp.secretKey), n: 5, threshold: 3 }));

    const message = 'released by quorum';
    const sig = body(await h.thresholdSign({ shares: split.shares.slice(0, 3), threshold: 3, message, algorithm: 'dilithium3' }));

    // Verify with the UNMODIFIED noble verifier and the original public key.
    const ok = ml_dsa65.verify(
      new Uint8Array(Buffer.from(sig.signature, 'base64')),
      new Uint8Array(Buffer.from(message, 'utf8')),
      kp.publicKey,
    );
    expect(ok).toBe(true);
  });

  it('a different 3-subset of the same shares signs identically-verifiably', async () => {
    const kp = ml_dsa65.keygen();
    const split = body(await h.splitKey({ secret: b64(kp.secretKey), n: 5, threshold: 3 }));
    const message = 'second quorum';
    const sig = body(await h.thresholdSign({ shares: [split.shares[1], split.shares[3], split.shares[4]], threshold: 3, message }));
    const ok = ml_dsa65.verify(
      new Uint8Array(Buffer.from(sig.signature, 'base64')),
      new Uint8Array(Buffer.from(message, 'utf8')),
      kp.publicKey,
    );
    expect(ok).toBe(true);
  });
});
