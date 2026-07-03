/**
 * Core surface conformance suite.
 *
 * Exercises EVERY tool the MCP server actually exposes (see index.ts dispatch):
 * Kyber/ML-KEM, Dilithium/ML-DSA, SPHINCS+/SLH-DSA, Falcon, hybrid encryption,
 * and the quantum/secure-random generator.
 *
 * Unlike the legacy tests, this suite asserts real cryptographic invariants:
 *   - KEM: encapsulate -> decapsulate recovers the SAME shared secret.
 *   - Signatures: valid sig verifies true; tampered message/sig verifies false.
 *   - Hybrid: encrypt -> decrypt recovers plaintext; tampering breaks AEAD.
 * These are the guarantees a buyer relies on; happy-path "is defined" is not enough.
 */
import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';

import { KyberHandler } from '../algorithms/kyber';
import { DilithiumHandler } from '../algorithms/dilithium';
import { SphincsPlusHandler } from '../algorithms/sphincs';
import { FalconHandler } from '../algorithms/falcon';
import { HybridCryptoHandler } from '../utils/hybrid';
import { QuantumRandomHandler } from '../utils/quantum-random';

const mockLogger = (): Logger =>
  ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);

/** Unwrap an MCP tool response into its parsed JSON payload. */
function payload(result: any): any {
  expect(result?.content?.[0]?.type).toBe('text');
  return JSON.parse(result.content[0].text);
}

/** Flip one byte in the middle of a base64 blob to simulate tampering. */
function tamperB64(b64: string): string {
  const buf = Buffer.from(b64, 'base64');
  const i = Math.floor(buf.length / 2);
  buf[i] = buf[i] ^ 0xff;
  return buf.toString('base64');
}

let logger: Logger;
let cache: NodeCache;
beforeEach(() => {
  logger = mockLogger();
  cache = new NodeCache();
});

describe('Kyber / ML-KEM (FIPS 203)', () => {
  let h: KyberHandler;
  beforeEach(() => { h = new KyberHandler(logger, cache); });

  for (const parameterSet of ['kyber512', 'kyber768', 'kyber1024']) {
    it(`${parameterSet}: encapsulate -> decapsulate recovers the same shared secret`, async () => {
      const kp = payload(await h.generateKeyPair({ parameterSet, format: 'base64' }));
      expect(kp.publicKeySize).toBeGreaterThan(0);
      expect(kp.privateKeySize).toBeGreaterThan(0);

      const enc = payload(await h.encapsulate({ publicKey: kp.publicKey, parameterSet, format: 'base64' }));
      expect(enc.sharedSecret).toBeDefined();
      expect(enc.ciphertext).toBeDefined();

      const dec = payload(await h.decapsulate({
        privateKey: kp.privateKey, ciphertext: enc.ciphertext, parameterSet, format: 'base64',
      }));

      // The core KEM correctness guarantee.
      expect(dec.sharedSecret).toBe(enc.sharedSecret);
    });
  }

  it('decapsulation with a different key does NOT recover the shared secret', async () => {
    const ps = 'kyber768';
    const a = payload(await h.generateKeyPair({ parameterSet: ps, format: 'base64' }));
    const b = payload(await h.generateKeyPair({ parameterSet: ps, format: 'base64' }));
    const enc = payload(await h.encapsulate({ publicKey: a.publicKey, parameterSet: ps, format: 'base64' }));
    // ML-KEM is designed to NOT fail loudly on wrong key (implicit rejection):
    // it returns a pseudo-random secret instead. Assert it simply differs.
    const wrong = payload(await h.decapsulate({
      privateKey: b.privateKey, ciphertext: enc.ciphertext, parameterSet: ps, format: 'base64',
    }));
    expect(wrong.sharedSecret).not.toBe(enc.sharedSecret);
  });

  it('rejects an unsupported parameter set', async () => {
    await expect(h.generateKeyPair({ parameterSet: 'kyber999', format: 'base64' }))
      .rejects.toThrow(/Unsupported parameter set/);
  });
});

describe('Dilithium / ML-DSA (FIPS 204)', () => {
  let h: DilithiumHandler;
  beforeEach(() => { h = new DilithiumHandler(logger, cache); });

  for (const parameterSet of ['dilithium2', 'dilithium3', 'dilithium5']) {
    it(`${parameterSet}: sign then verify is valid; tampering is rejected`, async () => {
      const kp = payload(await h.generateKeyPair({ parameterSet, format: 'base64' }));
      const message = `payload-${parameterSet}-${'x'.repeat(40)}`;

      const sig = payload(await h.sign({ privateKey: kp.privateKey, message, format: 'base64' }));
      expect(sig.signatureSize).toBeGreaterThan(0);

      const ok = payload(await h.verify({ publicKey: kp.publicKey, message, signature: sig.signature, format: 'base64' }));
      expect(ok.valid).toBe(true);

      const wrongMsg = payload(await h.verify({ publicKey: kp.publicKey, message: message + '!', signature: sig.signature, format: 'base64' }));
      expect(wrongMsg.valid).toBe(false);

      const wrongSig = payload(await h.verify({ publicKey: kp.publicKey, message, signature: tamperB64(sig.signature), format: 'base64' }));
      expect(wrongSig.valid).toBe(false);
    });
  }
});

describe('SPHINCS+ / SLH-DSA (FIPS 205)', () => {
  let h: SphincsPlusHandler;
  beforeEach(() => { h = new SphincsPlusHandler(logger, cache); });

  // Use the fast ("f") 128-bit variant to keep the suite quick; the slow ("s")
  // and larger variants share the same code path through @noble.
  const parameterSet = 'sphincs-sha2-128f';

  it('sign then verify is valid; tampered message is rejected', async () => {
    const kp = payload(await h.generateKeyPair({ parameterSet, format: 'base64' }));
    const message = 'hash-based signatures are stateless and conservative';

    const sig = payload(await h.sign({ privateKey: kp.privateKey, message, parameterSet, format: 'base64' }));
    const ok = payload(await h.verify({ publicKey: kp.publicKey, message, signature: sig.signature, parameterSet, format: 'base64' }));
    expect(ok.valid).toBe(true);

    const bad = payload(await h.verify({ publicKey: kp.publicKey, message: message + ' (edited)', signature: sig.signature, parameterSet, format: 'base64' }));
    expect(bad.valid).toBe(false);
  });
});

describe('Falcon / FN-DSA', () => {
  let h: FalconHandler;
  beforeEach(() => { h = new FalconHandler(logger, cache); });

  const parameterSet = 'falcon512';

  it('sign then verify is valid; tampered signature is rejected', async () => {
    const kp = payload(await h.generateKeyPair({ parameterSet, format: 'base64' }));
    const message = 'compact NTRU lattice signature';

    const sig = payload(await h.sign({ privateKey: kp.privateKey, message, parameterSet, format: 'base64' }));
    const ok = payload(await h.verify({ publicKey: kp.publicKey, message, signature: sig.signature, parameterSet, format: 'base64' }));
    expect(ok.valid).toBe(true);

    const bad = payload(await h.verify({ publicKey: kp.publicKey, message, signature: tamperB64(sig.signature), parameterSet, format: 'base64' }));
    expect(bad.valid).toBe(false);
  });
});

describe('Hybrid encryption (ML-KEM-768 + AES-256-GCM)', () => {
  let h: HybridCryptoHandler;
  let kyber: KyberHandler;
  beforeEach(() => { h = new HybridCryptoHandler(logger, cache); kyber = new KyberHandler(logger, cache); });

  it('encrypt then decrypt round-trips the plaintext', async () => {
    const kp = payload(await kyber.generateKeyPair({ parameterSet: 'kyber768', format: 'base64' }));
    const data = 'attack at dawn — but quantum-safely';

    const enc = payload(await h.encrypt({ publicKey: kp.publicKey, data, format: 'base64' }));
    const dec = payload(await h.decrypt({ privateKey: kp.privateKey, encryptedData: enc, format: 'base64' }));

    expect(dec.success).toBe(true);
    expect(dec.decryptedData).toBe(data);
  });

  it('tampering with the auth tag breaks decryption (AEAD integrity)', async () => {
    const kp = payload(await kyber.generateKeyPair({ parameterSet: 'kyber768', format: 'base64' }));
    const enc = payload(await h.encrypt({ publicKey: kp.publicKey, data: 'integrity matters', format: 'base64' }));

    const forged = { ...enc, authTag: tamperB64(enc.authTag) };
    await expect(h.decrypt({ privateKey: kp.privateKey, encryptedData: forged, format: 'base64' }))
      .rejects.toThrow();
  });
});

describe('Secure random generator', () => {
  let h: QuantumRandomHandler;
  beforeEach(() => { h = new QuantumRandomHandler(logger, cache); });

  it('produces the requested number of bytes in hex', async () => {
    const out = payload(await h.generate({ bytes: 32, format: 'hex' }));
    expect(out.bytes).toBe(32);
    expect(out.random).toMatch(/^[0-9a-f]{64}$/);
  });

  it('two successive draws differ (non-deterministic)', async () => {
    const a = payload(await h.generate({ bytes: 32, format: 'hex' }));
    const b = payload(await h.generate({ bytes: 32, format: 'hex' }));
    expect(a.random).not.toBe(b.random);
  });

  it('rejects out-of-range sizes', async () => {
    await expect(h.generate({ bytes: 0 })).rejects.toThrow();
    await expect(h.generate({ bytes: 2_000_000 })).rejects.toThrow(); // > 1 MiB cap
  });
});
