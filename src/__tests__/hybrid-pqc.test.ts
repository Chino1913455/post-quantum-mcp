/**
 * Hybrid (classical + post-quantum) primitives.
 *
 * Asserts the defining property of a hybrid scheme: it is correct when both
 * components agree, and it FAILS if EITHER component is wrong — that AND-logic
 * is the whole point (security survives a break of either half).
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { HybridPQCHandler } from '../utils/hybrid-pqc';

const log = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);
const body = (r: any) => JSON.parse(r.content[0].text);
let h: HybridPQCHandler;
beforeEach(() => { h = new HybridPQCHandler(log(), new NodeCache()); });

describe('Hybrid KEM (X-Wing: X25519 + ML-KEM-768)', () => {
  it('encapsulate -> decapsulate recovers the same shared secret', async () => {
    const kp = body(await h.kemKeygen({ format: 'base64' }));
    const enc = body(await h.kemEncapsulate({ publicKey: kp.publicKey }));
    const dec = body(await h.kemDecapsulate({ privateKey: kp.privateKey, ciphertext: enc.ciphertext }));
    expect(dec.sharedSecret).toBe(enc.sharedSecret);
    expect(enc.sharedSecretSize).toBe(32);
  });

  it('a different key does not recover the secret', async () => {
    const a = body(await h.kemKeygen({}));
    const b = body(await h.kemKeygen({}));
    const enc = body(await h.kemEncapsulate({ publicKey: a.publicKey }));
    const dec = body(await h.kemDecapsulate({ privateKey: b.privateKey, ciphertext: enc.ciphertext }));
    expect(dec.sharedSecret).not.toBe(enc.sharedSecret);
  });

  it('tampering with the X25519 half of the ciphertext changes the secret', async () => {
    const kp = body(await h.kemKeygen({}));
    const enc = body(await h.kemEncapsulate({ publicKey: kp.publicKey }));
    const ct = Buffer.from(enc.ciphertext, 'base64');
    ct[ct.length - 1] ^= 0xff; // last byte is in the X25519 ct
    const dec = body(await h.kemDecapsulate({ privateKey: kp.privateKey, ciphertext: ct.toString('base64') }));
    expect(dec.sharedSecret).not.toBe(enc.sharedSecret);
  });
});

describe('Hybrid signatures (Ed25519 + ML-DSA-65)', () => {
  it('sign then verify is valid (both components pass)', async () => {
    const kp = body(await h.signKeygen({}));
    const sig = body(await h.sign({ privateKey: kp.privateKey, message: 'release v1.0.0' }));
    const v = body(await h.verify({ publicKey: kp.publicKey, message: 'release v1.0.0', signature: sig.signature }));
    expect(v.valid).toBe(true);
    expect(v.components.ed25519).toBe(true);
    expect(v.components['ml-dsa-65']).toBe(true);
  });

  it('rejects an altered message', async () => {
    const kp = body(await h.signKeygen({}));
    const sig = body(await h.sign({ privateKey: kp.privateKey, message: 'original' }));
    const v = body(await h.verify({ publicKey: kp.publicKey, message: 'tampered', signature: sig.signature }));
    expect(v.valid).toBe(false);
  });

  it('FAILS if only the classical (Ed25519) component is corrupted', async () => {
    const kp = body(await h.signKeygen({}));
    const sig = body(await h.sign({ privateKey: kp.privateKey, message: 'msg' }));
    const s = Buffer.from(sig.signature, 'base64');
    s[10] ^= 0xff; // within the first 64 bytes = Ed25519 signature
    const v = body(await h.verify({ publicKey: kp.publicKey, message: 'msg', signature: s.toString('base64') }));
    expect(v.valid).toBe(false);
    expect(v.components.ed25519).toBe(false);
    expect(v.components['ml-dsa-65']).toBe(true); // PQ half still valid — but hybrid still fails
  });

  it('FAILS if only the post-quantum (ML-DSA) component is corrupted', async () => {
    const kp = body(await h.signKeygen({}));
    const sig = body(await h.sign({ privateKey: kp.privateKey, message: 'msg' }));
    const s = Buffer.from(sig.signature, 'base64');
    s[200] ^= 0xff; // past byte 64 = within the ML-DSA signature
    const v = body(await h.verify({ publicKey: kp.publicKey, message: 'msg', signature: s.toString('base64') }));
    expect(v.valid).toBe(false);
    expect(v.components.ed25519).toBe(true);
    expect(v.components['ml-dsa-65']).toBe(false);
  });

  it('verify is total: malformed signature returns valid:false, does not throw', async () => {
    const kp = body(await h.signKeygen({}));
    const v = body(await h.verify({ publicKey: kp.publicKey, message: 'msg', signature: 'AAAA' }));
    expect(v.valid).toBe(false);
  });
});
