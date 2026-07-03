/**
 * Application-layer tests: PQ-JWT (auth tokens), multi-recipient document
 * encryption, and PQ PKI/certificates — happy paths and failure cases.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Logger } from 'winston';
import NodeCache from 'node-cache';
import { PQJwtHandler } from '../utils/pq-jwt';
import { PQEncryptHandler } from '../utils/pq-encrypt';
import { PQCertificateHandler } from '../utils/pq-certificate';
import { hybridSignKeypair, hybridKemKeypair } from '../utils/hybrid-pqc';
import { b64 } from '../utils/canonical';

const log = (): Logger => ({ info: jest.fn(), error: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any);
const body = (r: any) => JSON.parse(r.content[0].text);
let cache: NodeCache;
beforeEach(() => { cache = new NodeCache(); });

const signKeys = () => { const k = hybridSignKeypair(); return { pub: b64(k.publicKey), priv: b64(k.secretKey) }; };
const kemKeys = () => { const k = hybridKemKeypair(); return { pub: b64(k.publicKey), priv: b64(k.secretKey) }; };

describe('PQ-JWT (quantum-safe tokens)', () => {
  let h: PQJwtHandler;
  beforeEach(() => { h = new PQJwtHandler(log(), cache); });

  it('signs and verifies a token', async () => {
    const k = signKeys();
    const t = body(await h.sign({ privateKey: k.priv, claims: { sub: 'agent-7', scope: 'pay' }, expiresInSeconds: 3600 }));
    const v = body(await h.verify({ publicKey: k.pub, token: t.token }));
    expect(v.valid).toBe(true);
    expect(v.claims.sub).toBe('agent-7');
  });

  it('rejects an expired token', async () => {
    const k = signKeys();
    const t = body(await h.sign({ privateKey: k.priv, claims: { sub: 'x' }, expiresInSeconds: -10 }));
    const v = body(await h.verify({ publicKey: k.pub, token: t.token }));
    expect(v.valid).toBe(false);
    expect(v.expired).toBe(true);
  });

  it('rejects a tampered payload and a wrong key', async () => {
    const k = signKeys();
    const t = body(await h.sign({ privateKey: k.priv, claims: { admin: false } }));
    const [hd, , sg] = t.token.split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ admin: true }), 'utf8').toString('base64url');
    const forged = `${hd}.${forgedPayload}.${sg}`;
    expect(body(await h.verify({ publicKey: k.pub, token: forged })).valid).toBe(false);
    expect(body(await h.verify({ publicKey: signKeys().pub, token: t.token })).valid).toBe(false);
  });
});

describe('Multi-recipient document encryption', () => {
  let h: PQEncryptHandler;
  beforeEach(() => { h = new PQEncryptHandler(log(), cache); });

  it('any recipient decrypts; a non-recipient cannot', async () => {
    const a = kemKeys();
    const b = kemKeys();
    const outsider = kemKeys();
    const data = Buffer.from('confidential payload').toString('base64');
    const env = body(await h.encryptDocument({ recipients: [a.pub, b.pub], data }));
    expect(env.recipientCount).toBe(2);

    for (const who of [a, b]) {
      const dec = body(await h.decryptDocument({ privateKey: who.priv, envelope: env }));
      expect(Buffer.from(dec.data, 'base64').toString()).toBe('confidential payload');
    }
    await expect(h.decryptDocument({ privateKey: outsider.priv, envelope: env })).rejects.toThrow(/Not a recipient/);
  });

  it('detects tampering of the ciphertext', async () => {
    const a = kemKeys();
    const env = body(await h.encryptDocument({ recipients: [a.pub], data: Buffer.from('x').toString('base64') }));
    const ct = Buffer.from(env.ciphertext, 'base64');
    ct[0] ^= 0xff;
    await expect(h.decryptDocument({ privateKey: a.priv, envelope: { ...env, ciphertext: ct.toString('base64') } })).rejects.toThrow();
  });
});

describe('PQ PKI / certificates', () => {
  let h: PQCertificateHandler;
  beforeEach(() => { h = new PQCertificateHandler(log(), cache); });

  it('issues and verifies a self-signed certificate', async () => {
    const k = signKeys();
    const c = body(await h.issue({ subject: 'agent-1', subjectPublicKey: k.pub, issuerPrivateKey: k.priv }));
    expect(c.selfSigned).toBe(true);
    const v = body(await h.verify({ certificate: c.certificate, signature: c.signature }));
    expect(v.valid).toBe(true);
  });

  it('verifies a CA-issued certificate and its one-level chain', async () => {
    const ca = signKeys();
    const caCert = body(await h.issue({ subject: 'Veris Root CA', subjectPublicKey: ca.pub, issuerPrivateKey: ca.priv, isCA: true }));

    const leaf = signKeys();
    const leafCert = body(await h.issue({ subject: 'svc-payments', subjectPublicKey: leaf.pub, issuer: 'Veris Root CA', issuerPublicKey: ca.pub, issuerPrivateKey: ca.priv }));

    const v = body(await h.verify({ certificate: leafCert.certificate, signature: leafCert.signature, caCertificate: caCert.certificate }));
    expect(v.valid).toBe(true);
    expect(v.chainValid).toBe(true);
  });

  it('rejects a tampered certificate and an expired one', async () => {
    const k = signKeys();
    const c = body(await h.issue({ subject: 'agent-1', subjectPublicKey: k.pub, issuerPrivateKey: k.priv }));
    const tampered = { ...c.certificate, subject: 'attacker' };
    expect(body(await h.verify({ certificate: tampered, signature: c.signature })).valid).toBe(false);

    const expired = body(await h.issue({ subject: 'old', subjectPublicKey: k.pub, issuerPrivateKey: k.priv, validityDays: -1 }));
    const ev = body(await h.verify({ certificate: expired.certificate, signature: expired.signature }));
    expect(ev.valid).toBe(false);
    expect(ev.expired).toBe(true);
  });
});
