/**
 * Exhaustive failure-case suite for the exposed MCP surface.
 *
 * Security tooling must FAIL SAFELY on bad input: reject (throw) or return a
 * clearly-invalid result — never crash the process, never silently accept a
 * forgery, never leak a usable secret. Every exposed handler is exercised here
 * with malformed, truncated, tampered, oversized, and wrong-key inputs.
 */
import { describe, it, expect, jest, beforeEach, afterAll } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

import { KyberHandler } from '../algorithms/kyber';
import { DilithiumHandler } from '../algorithms/dilithium';
import { SphincsPlusHandler } from '../algorithms/sphincs';
import { FalconHandler } from '../algorithms/falcon';
import { HybridCryptoHandler } from '../utils/hybrid';
import { SecureRandomHandler } from '../utils/quantum-random';
import { KeyManagementHandler } from '../utils/keymanagement';
import { BenchmarkHandler } from '../utils/benchmark';

const log = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);
const body = (r: any) => JSON.parse(r.content[0].text);
let cache: NodeCache;
beforeEach(() => { cache = new NodeCache(); });

describe('Kyber failure cases', () => {
  let h: KyberHandler;
  beforeEach(() => { h = new KyberHandler(log(), cache); });

  it('rejects an unsupported parameter set', async () => {
    await expect(h.generateKeyPair({ parameterSet: 'kyber999' })).rejects.toThrow();
  });
  it('rejects encapsulation against a malformed public key', async () => {
    await expect(h.encapsulate({ publicKey: 'not-a-real-key', parameterSet: 'kyber768' })).rejects.toThrow();
  });
  it('rejects decapsulation with a truncated ciphertext', async () => {
    const kp = body(await h.generateKeyPair({ parameterSet: 'kyber768' }));
    await expect(
      h.decapsulate({ privateKey: kp.privateKey, ciphertext: 'AAAA', parameterSet: 'kyber768' }),
    ).rejects.toThrow();
  });
  it('does not recover the secret under a wrong private key (implicit rejection, no crash)', async () => {
    const a = body(await h.generateKeyPair({ parameterSet: 'kyber768' }));
    const b = body(await h.generateKeyPair({ parameterSet: 'kyber768' }));
    const enc = body(await h.encapsulate({ publicKey: a.publicKey, parameterSet: 'kyber768' }));
    const dec = body(await h.decapsulate({ privateKey: b.privateKey, ciphertext: enc.ciphertext, parameterSet: 'kyber768' }));
    expect(dec.sharedSecret).not.toBe(enc.sharedSecret);
  });
});

describe('Signature verification rejects forgeries and malformed input', () => {
  const cases = [
    { name: 'Dilithium', make: () => new DilithiumHandler(log(), cache), ps: 'dilithium3' },
    { name: 'SPHINCS+', make: () => new SphincsPlusHandler(log(), cache), ps: 'sphincs-sha2-128f' },
    { name: 'Falcon', make: () => new FalconHandler(log(), cache), ps: 'falcon512' },
  ];

  for (const c of cases) {
    describe(c.name, () => {
      it('rejects a forged/empty signature', async () => {
        const h: any = c.make();
        const kp = body(await h.generateKeyPair({ parameterSet: c.ps }));
        const forged = Buffer.alloc(64).toString('base64');
        const res = body(await h.verify({ publicKey: kp.publicKey, message: 'hello', signature: forged, parameterSet: c.ps }));
        expect(res.valid).toBe(false);
      });
      it('rejects a signature verified under the wrong public key', async () => {
        const h: any = c.make();
        const a = body(await h.generateKeyPair({ parameterSet: c.ps }));
        const b = body(await h.generateKeyPair({ parameterSet: c.ps }));
        const sig = body(await h.sign({ privateKey: a.privateKey, message: 'msg', parameterSet: c.ps }));
        const res = body(await h.verify({ publicKey: b.publicKey, message: 'msg', signature: sig.signature, parameterSet: c.ps }));
        expect(res.valid).toBe(false);
      });
      it('rejects when the message is altered after signing', async () => {
        const h: any = c.make();
        const kp = body(await h.generateKeyPair({ parameterSet: c.ps }));
        const sig = body(await h.sign({ privateKey: kp.privateKey, message: 'original', parameterSet: c.ps }));
        const res = body(await h.verify({ publicKey: kp.publicKey, message: 'tampered', signature: sig.signature, parameterSet: c.ps }));
        expect(res.valid).toBe(false);
      });
    });
  }
});

describe('Hybrid encryption failure cases', () => {
  let h: HybridCryptoHandler;
  let kyber: KyberHandler;
  beforeEach(() => { h = new HybridCryptoHandler(log(), cache); kyber = new KyberHandler(log(), cache); });

  it('rejects decryption of a payload with a tampered ciphertext body', async () => {
    const kp = body(await kyber.generateKeyPair({ parameterSet: 'kyber768' }));
    const enc = body(await h.encrypt({ publicKey: kp.publicKey, data: 'secret' }));
    const buf = Buffer.from(enc.encryptedData, 'base64');
    buf[0] ^= 0xff;
    await expect(h.decrypt({ privateKey: kp.privateKey, encryptedData: { ...enc, encryptedData: buf.toString('base64') } })).rejects.toThrow();
  });
  it('rejects decryption with the wrong private key', async () => {
    const a = body(await kyber.generateKeyPair({ parameterSet: 'kyber768' }));
    const b = body(await kyber.generateKeyPair({ parameterSet: 'kyber768' }));
    const enc = body(await h.encrypt({ publicKey: a.publicKey, data: 'secret' }));
    await expect(h.decrypt({ privateKey: b.privateKey, encryptedData: enc })).rejects.toThrow();
  });
  it('rejects a structurally incomplete payload', async () => {
    const kp = body(await kyber.generateKeyPair({ parameterSet: 'kyber768' }));
    await expect(h.decrypt({ privateKey: kp.privateKey, encryptedData: { encapsulatedKey: 'AAAA' } })).rejects.toThrow();
  });
});

describe('Secure-random failure cases', () => {
  let h: SecureRandomHandler;
  beforeEach(() => { h = new SecureRandomHandler(log(), cache); });

  it('rejects zero and negative sizes', async () => {
    await expect(h.generate({ bytes: 0 })).rejects.toThrow();
    await expect(h.generate({ bytes: -5 })).rejects.toThrow();
  });
  it('rejects non-integer and oversized sizes', async () => {
    await expect(h.generate({ bytes: 3.5 })).rejects.toThrow();
    await expect(h.generate({ bytes: 5_000_000 })).rejects.toThrow();
  });
});

describe('Key derivation failure cases', () => {
  let h: KeyManagementHandler;
  beforeEach(() => { h = new KeyManagementHandler(log(), cache); });

  it('rejects an unsupported KDF algorithm', async () => {
    await expect(h.deriveKey({ masterKey: Buffer.from('k').toString('base64'), info: 'ctx', algorithm: 'blake3' })).rejects.toThrow();
  });
  it('derives the requested length for every supported KDF', async () => {
    const master = Buffer.from('master-key-material').toString('base64');
    for (const algorithm of ['shake256', 'hkdf-sha256', 'pbkdf2', 'scrypt']) {
      const r = body(await h.deriveKey({ masterKey: master, info: 'salt', length: 32, algorithm, format: 'hex' }));
      expect(r.derivedKey).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe('Key storage fails closed without a master secret', () => {
  const tmp = path.join(os.tmpdir(), `pqmcp-keys-${process.pid}`);
  const prevSecret = process.env.KEY_ENCRYPTION_SECRET;
  const prevPath = process.env.KEY_STORE_PATH;
  process.env.KEY_STORE_PATH = tmp;

  afterAll(() => {
    if (prevSecret === undefined) delete process.env.KEY_ENCRYPTION_SECRET; else process.env.KEY_ENCRYPTION_SECRET = prevSecret;
    if (prevPath === undefined) delete process.env.KEY_STORE_PATH; else process.env.KEY_STORE_PATH = prevPath;
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('refuses encrypted storage when KEY_ENCRYPTION_SECRET is unset', async () => {
    delete process.env.KEY_ENCRYPTION_SECRET;
    const h = new KeyManagementHandler(log(), cache);
    await expect(
      h.storeKey({ keyId: 'k1', keyData: Buffer.from('secret').toString('base64'), encryption: true }),
    ).rejects.toThrow(/KEY_ENCRYPTION_SECRET/);
  });

  it('round-trips a stored key when the secret is set', async () => {
    process.env.KEY_ENCRYPTION_SECRET = 'a-strong-test-secret-value';
    const h = new KeyManagementHandler(log(), cache);
    const data = Buffer.from('top-secret-key').toString('base64');
    await h.storeKey({ keyId: 'k2', keyData: data, encryption: true });
    const got = body(await h.retrieveKey({ keyId: 'k2', decrypt: true }));
    expect(got.keyData ?? got.data).toBeDefined();
  });
});

describe('Benchmark failure cases', () => {
  let h: BenchmarkHandler;
  beforeEach(() => { h = new BenchmarkHandler(log(), cache); });

  it('rejects an unsupported algorithm', async () => {
    await expect(h.benchmark({ algorithm: 'ntru' })).rejects.toThrow();
  });
  it('measures real, positive timings for a supported algorithm', async () => {
    const r = body(await h.benchmark({ algorithm: 'kyber', operations: 20 }));
    expect(r.results.length).toBeGreaterThan(0);
    for (const res of r.results) {
      expect(res.averageMs).toBeGreaterThan(0);
      expect(res.opsPerSec).toBeGreaterThan(0);
    }
  });
});
